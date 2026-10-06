# Buzz as a native hcom integration

Status: design, for review. Owner: BuzzHcomNative lane. Date: 2026-10-06.

## Bottom line

hcom grows a Buzz connector: `hcom buzz serve`, a long-lived process inside the
hcom binary that runs on exactly one host (mbai). It makes every Buzz human in a
bridged channel an hcom participant (`michael`, `seanfitz`) and every hcom agent
a Buzz identity humans can pick in the mention popup. Agents on any device talk
to humans with plain `hcom send @michael`; the existing hcom relay carries the
message to mbai, where the connector posts it to Buzz as that agent. Human
replies (mentions, plain thread replies, DM messages) come back as ordinary hcom
messages from `michael`. Humans never install anything. Adding a person means
adding them to a bridged Buzz channel. The Python `zagcom-bridge` is retired;
warehouse Q&A survives as a small hcom participant on the new transport.

## Requirements (from the operator)

1. Buzz people are hcom-addressable both ways, with hcom delivery, receipts and
   offline semantics. Plain thread replies under an agent's message reach that
   agent.
2. hcom agents are Buzz identities humans can pick in the mention popup.
3. Buzz say/read on every hcom device through hcom and its relay. No per-device
   client.
4. The connector is a proper long-lived hcom participant host. No listen-timeout
   tricks.
5. Warehouse Q&A semantics preserved (verbatim operator-signed answers, bead
   notes, one open question, withdraw rules).
6. Rate limits respected, per-channel fault isolation, backoff on 429/5xx, no
   exit on relay errors.
7. Humans never install hcom. Only agent machines run it.
8. The release must be wire-compatible with 0.7.52 peers during the mixed
   period, cutover included (operator, 2026-10-06).

Non-goals: patching Buzz; Buzz-to-hcom broadcast (`!hcom-all`, operator still
deciding, don't build); bridging the `@infra` buzz-acp agent; macOS/Windows
release targets (hcom already compiles there; the connector code is portable,
but only mbai runs `serve`).

## Facts this design rests on

Verified at the deployed tags (relay-v0.2.1, desktop-v0.5.26) and in hcom
origin/main (0.7.52). Evidence lives in the lane's verifier reports; the ones
that shaped the design:

- **One WebSocket is one identity.** After NIP-42 AUTH as A, every EVENT must be
  authored by A; a second AUTH is refused (`handlers/event.rs:659-667`,
  `handlers/auth.rs:49-55`). HTTP `POST /events` likewise requires the NIP-98
  signer to be the event author (`ingest.rs:1995-1998`).
- **NIP-OA delegation admits derived keys.** The relay is closed
  (`requireRelayMembership`, `allowNipOaAuth` true). A non-member key is admitted
  when it carries exactly one valid `["auth", owner, "", sig]` tag from a member
  owner: inside the AUTH event on WS, or in the `x-auth-tag` header on HTTP
  (`api/mod.rs:62-108`, `bridge.rs:803`). Conditions must be empty or desktop
  won't treat the key as an owned agent.
- **Rate limits are per signing pubkey,** shared across relay pods: HTTP 300/min;
  WS 50 frames per fixed 5 s (EVENT+REQ+COUNT); WS EVENTs 120/min for a
  delegated agent, 60/min otherwise. A rate-limited WS EVENT gets a `NOTICE
  rate-limited: … retry in Ns`, not an `OK false`. HTTP gives `429
  {"error":"rate-limited: quota exceeded; retry in Ns"}`.
- **Live subscriptions are per channel.** Only a REQ whose filters all carry one
  identical `#h` receives channel events live; anything else is global and gets
  none. A single-`#h` sub does receive h-less kind 5 deletions and kind 7
  reactions for that channel (`filter.rs:79-89`, `subscription.rs:447-449`).
  Historical global `#e` queries return deletions; live global ones never do.
- **Thread replies don't tag the parent author.** A direct reply to a root
  carries only `["e", root, "", "reply"]`; deeper replies carry `root` + `reply`
  markers. Routing by thread ancestry is the only way to catch them.
- **Mention popup eligibility** for agent X owned by omp, seen by human H: X's
  kind 0 with the NIP-OA tag; omp's kind 30177 with `d` = X and
  `respond_to: "anyone"`; X in a stream/forum channel H belongs to, added by kind
  9000 with role `bot`. Kind 10100 is optional (presence only). DMs only offer
  the viewer's own agents.
- **DMs:** kind 41010 with a `p` per other participant (1–8) opens or reuses a
  DM (idempotent on the participant set); any admitted key, agents included, may
  open one; the channel id comes back in the OK `response`. Desktop DM messages
  p-tag the other participants.
- **Private channels:** only owner/admin add members. omp is admin of `#infra`
  and `#warehouse`.
- **buzz-pg switchovers** give ~40 s of relay 5xx. The connector must ride them.
- **hcom:** a participant is an `instances` row. `SenderKind::Instance` gets real
  routing; `External`/`System` senders broadcast. Messages from other devices
  arrive through the relay as local `events` rows with the receiving device's
  suffix stripped from `mentions`, `delivered_to` and `exact_targets`, and
  `reply_to` untouched, so a row hosted on mbai is addressable from every device
  as `@michael` (resolving to `michael:XXXX` remotely, case-insensitively). Relay
  state carries any `tool` string verbatim. Base names are `[a-z0-9_]+`. A row
  is deliverable unless `stopped`, `launch_failed` or `inactive` + `exit:*`;
  rows are reaped only by the daemon sweep on positive evidence that their
  process died. A quiet `hcom listen` timeout no longer marks a row `exit:`.

## Design

### Where the code lives

| Piece | Location | Why |
|---|---|---|
| Nostr primitives: keys, HKDF derivation, BIP-340, NIP-01 ids, NIP-OA, NIP-42, NIP-98 | `src/buzz/nostr.rs` | Pure functions, unit-tested against pinned vectors. |
| Relay client: WS session (AUTH, REQ, EVENT, CLOSE, NOTICE), HTTP publish | `src/buzz/relay.rs` | Std threads + blocking sockets, matching the rest of hcom (no async runtime). |
| Connector state DB | `src/buzz/store.rs`, file `~/.hcom/buzz/state.db` | Connector-only state stays out of `hcom.db`: no schema bump, so old and new hcom processes share `hcom.db` safely in the mixed period, and `hcom reset` can't wipe identity maps. |
| Routing (Buzz event → hcom message, hcom event → Buzz post) | `src/buzz/route.rs` | Pure decision functions over typed inputs; the heart of the tests. |
| Service loop | `src/buzz/serve.rs` | Composition root: config, keys, sessions, workers. |
| CLI | `src/commands/buzz.rs` (`serve`, `status`, `read`, `event`, `say`) | One command family. |
| Core hcom changes | `proctruth.rs`, `instance_binding.rs`, `relay/control.rs` | Hosted participants and two read RPCs. Kept small; listed below. |

A separate binary or service was rejected: the connector has to own hcom rows,
read the events table, and write deliver receipts. Doing that from outside is
exactly the CLI-shelling and listen-timeout workaround the bridge needed.

New crates, all pure Rust so Windows and macOS CI keep compiling: `k256`
(schnorr), `hkdf`, `tungstenite` (rustls), `ureq` (rustls). `sha2`, `rustls`,
`webpki-roots`, `base64`, `rand` are already in the tree.

### Identities and key custody

Everything secret stays on mbai, read in-process by the connector, never logged,
never on argv, never in the environment of a child.

- **Seed**: the existing 32-byte `hcom-buzz-seed` (ubuntu-admin
  `secrets/hosts/mbai/`). Path in config.
- **Owner**: the `omp` identity (`7e996ef3…`). Its key is parsed in-process from
  `buzz-omp.env` (`BUZZ_PRIVATE_KEY`, hex or nsec), same rules as the bridge's
  `load_owner_key`.
- **Agent key** for hcom name N on device label D:
  `HKDF-SHA256(ikm=seed, salt=none, info="zagcom/hcom-identity/v1:" + N + "@" + D, len=32)`,
  reduced into `[1, n-1]`. Byte-identical to the bridge (pinned by a cross-test
  vector generated from the Python implementation), so every agent identity the
  bridge already enrolled in `#infra` keeps its pubkey across cutover.
- **Device label**: mbai's own rows use the configured `device_label` (default:
  hostname, `mbai`), matching the bridge. Rows from other devices use the
  lowercased hcom relay short id (`luna:BOXE` → `luna@boxe`). It changes only on
  `hcom reset all` of that device, and then the agent simply gets a fresh Buzz
  identity. This needs nothing from 0.7.52 peers.
- **Connector reader**: derived identity `buzz@mbai`, the one key that holds
  long-lived subscriptions on bridged channels. omp adds it to each bridged
  channel.
- **Profile**: every derived key publishes a kind 0 with `display_name` = hcom
  name (plus ` (DEV)` for remote devices), `about` =
  `zagcom/hcom-identity/v1:<N>@<D>` (the bridge's marker, kept so existing tools
  still parse it), and the NIP-OA tag with empty conditions.

Derived private keys live in memory only, keyed by canonical name.

### Who is who in hcom

| Buzz thing | hcom participant | Name |
|---|---|---|
| A human member of any bridged channel (not omp, not a derived key, not role `bot`) | hosted row, `tool = "buzz"` | slug of kind 0 `name`/`display_name`, `[a-z0-9_]`, stable once assigned (stored by pubkey), overridable in config |
| A bridged channel | hosted row, `tool = "buzz"` | `ch_<slug>` (`ch_infra`, `ch_warehouse`) |

A name collision with a non-buzz row gets a `_bz` suffix. Person rows appear the
first time the roster (kind 39002) shows them in a bridged channel, and are
removed 24 h after they leave every bridged channel. That's the whole onboarding
story for coworkers.

### Hosted participants (the core hcom change)

hcom today has no "one process hosts many rows" notion. Rows are held or
reaped by the daemon's `sweep_vanished_instances` (run by the relay worker
watchdog every 30 s) on positive evidence that a row's process died; inactive
status alone deletes nothing, and the send predicate
(`fleet_names::LIVE_ROW_PREDICATE`) only refuses `stopped`, `launch_failed` and
`inactive`+`exit:*`. So a hosted row needs three things, and only the second is
new behaviour:

1. **Connector-owned registration** (`instance_binding.rs`): create the row with
   `tool = "buzz"`, no session or process binding, status `listening`, context
   `buzz:online` (never `new`, so placeholder cleanup ignores it); on restart,
   upsert in place and **never** reset an existing row's `last_event_id` (the
   ordinary initializer jumps a new row's cursor to the current max, which is
   right for agents and wrong here). Fleet name-collision checks apply as for
   any registration.
2. **Explicit reaper exemption** (`proctruth::sweep_vanished_instances`):
   `tool = "buzz"` rows are skipped. Today they would already be held for lack
   of PID evidence, but that is an accident, not a contract.
3. **Liveness from the connector's heartbeat**: one localhost notify endpoint
   (kind `listen`, one port shared by every hosted row; `wake_all` already
   dedupes by port) and one `UPDATE … SET last_stop` over all hosted rows per
   loop. Computed status then reads `listening` while the connector runs and
   `stale:listening` within 35 s of it dying. On graceful stop the connector
   writes `inactive` / `buzz:offline`. Every one of those states is deliverable,
   so messages sent while the connector is down queue on the row's cursor and
   drain on restart.

Plus two relay RPC handlers, `buzz_read` and `buzz_event` (one table entry
each in `REMOTE_RPC_HANDLERS`, advertised automatically), so `hcom buzz read`
and `hcom buzz event` work from any device.

No `Tool` enum variant: the column is a free string, relay and TUI already carry
unknown tools verbatim, and a variant would add ten exhaustive match arms for
launch/resume/hook plumbing a connector never uses. No schema change.

The connector consumes each hosted row with the same calls `hcom listen` uses
(`get_unread_messages`, then advance `last_event_id` and log the delivery
status like `commit_delivery_ack`), so hcom's cursor is the single source of
truth for what a Buzz person has been handed, and the TUI's read waterline
shows it.

### Buzz → hcom (inbound)

One WS session as `buzz@mbai`. Per bridged channel: one REQ with that channel's
`#h` for the live kinds `{9, 40002, 45001, 45003, 40003, 5, 9005, 39002}`,
opened staggered (WS budget is 50 frames / 5 s). On (re)connect each channel
backfills from its durable `created_at` cursor (minus a 960 s window, since the
relay admits 900 s of backdating), deduplicated by event id. DM channels opened
for agents are read through that agent's session (see outbound).

For each event E from author H, verified signature first:

- **Skip** if H is a derived key (our own posts) or omp.
- **Targets** = derived agents p-tagged in E ∪ the derived author of any
  ancestor in E's thread (walk `e` tags to the root; this is what catches plain
  thread replies) ∪ the agent participant of a DM channel. Minus H.
- No targets → nothing is sent to hcom; the event is still cached for `read`.
- Otherwise the connector sends one hcom message **as H's hosted row**
  (`SenderKind::Instance`, via the in-process send path, not the CLI) with
  `@mentions` = target names, text = E's content with `nostr:npub…` mentions
  rendered as `@name`, thread = `buzz_<channel>_<root8>`, and `reply_to` = the
  hcom event that produced the Buzz message being answered, when there is one.
- **Edits (40003)** of a delivered message → a new hcom message to the same
  targets, `reply_to` the original, text prefixed `(edited) `. **Deletions** →
  `(deleted)` notice the same way. The original is never rewritten.
- Exactly-once into hcom: the map row is committed `pending` in `state.db`
  before the in-process send and marked done with the hcom event id after. On
  restart a `pending` row is resolved by looking for that sender's message with
  the same text in `events` since the pending time; found means done, missing
  means send. Only then does the channel's Buzz cursor move.

### hcom → Buzz (outbound)

On every wake (and a 5 s tick as a backstop) the connector reads each hosted
row's unread messages. It forwards message M only when the row is an explicit
target (`exact_targets`/`mentions` after relay import), or M replies
(`reply_to`) to a message that row sent. Broadcasts, thread-member fan-out and
anything sent by a hosted row are skipped and acknowledged. One M addressed to
several hosted rows (`@michael @ch_infra`) becomes one Buzz post: the outbox is
keyed by hcom event id. This filter lives in the connector, not the sender, so
0.7.52 senders get identical behaviour.

Sender: M's `from` (`luna` local or `luna:BOXE` remote) gives the agent key.
External (`ext_`) and system (`sys_`) senders are not posted; the connector
logs and drops them.

Destination, first match wins:

1. M is a reply into a Buzz thread (by `reply_to` or `buzz_*` thread name) →
   reply in that thread, `e` tags per NIP-10, p-tag every mentioned person and
   the parent author.
2. M mentions `ch_<x>` rows → one top-level post per channel, p-tagging the
   mentioned people.
3. M mentions only people → a DM from the agent to those people (41010,
   idempotent, ≤8 others). **Operator decision D1.**

Before the first post into a channel, the agent is enrolled: kind 0 (agent
key), kind 30177 `{"name", "respond_to": "anyone", "parallelism": 1}` with
`d` = agent pubkey (omp key), kind 9000 add with role `bot` (omp, channel
admin). Enrollment is cached in `state.db` and re-checked against the 39002
roster.

Publishing: every post is signed locally, so its event id is known before it is
sent. The outbox row (hcom event id → signed Buzz event JSON) is committed in
`state.db` first, idempotent on the hcom event id, and only then are the hosted
rows' cursors advanced, so a crash between the two re-reads the message and the
insert is a no-op. Then `POST /events` with NIP-98 + `x-auth-tag`, signed by the
agent key. Re-sending the same signed event after a lost ack is a duplicate at
the relay, not a second post. An outbox entry still unacknowledged when its
`created_at` nears the relay's 900 s admission window is looked up by id first
and only re-signed if the relay never stored it. On success the connector logs
the delivery status for each hosted recipient.

DMs need a live read path for the agent side, because a WS session reads only
as its own identity: the connector keeps a session per agent that has an open
DM (single `#h` sub per DM), closes it after 24 h of DM silence, and reopens it
with a cursor backfill when needed. There is no per-IP connection cap at
relay-v0.2.1, so a few dozen sessions from mbai are fine.

### Popup enrollment

Agents become pickable before they ever post: every deliverable hcom agent row
(local or remote, excluding hosted rows, `sys_`/`_` names and subagents) is
enrolled into each bridged channel whose config says `agents = true`. Agents
whose hcom row has been gone 24 h are removed (kind 9001 by omp); this keeps the
popup to agents that can actually answer. Operator decision D2 covers which
channels.

### Say and read from every device

- **Say** is plain hcom: `hcom send @ch_infra -- text` (post in `#infra`),
  `hcom send @michael -- text` (DM), `hcom send @michael --reply-to <id> -- …`
  (thread reply). Works from 0.7.52 today because it is just a message to a
  remote row. `hcom buzz say <channel> -- text` is a thin alias that builds the
  same message.
- **Read**: `hcom buzz read <channel> [--thread <root>] [--limit N] [--json]`
  answers from the connector's cache on mbai, and from any other device through
  the `buzz_read` relay RPC to the device advertising it. `hcom buzz event
  <buzz-id|hcom-id> --json` returns the raw signed Buzz event the same way.
  Neither needs a key off mbai. Both need the new CLI on the calling device;
  0.7.52 CLIs don't have the command, which is the only mixed-period gap.

### Faults, budgets, backoff

- Per signing pubkey token buckets sized under the relay: HTTP writes 240/min,
  WS frames 40 per 5 s, WS EVENTs 100/min. omp's bucket is shared by every
  enrollment write, so enrollment is queued and paced.
- 429 / `NOTICE rate-limited` → honor `retry in Ns` (floor 1 s, jitter) for that
  pubkey only. 5xx, transport errors, socket drops → exponential backoff 1 s →
  60 s, per channel subscription and per identity outbox. `CLOSED` on one
  channel (removed, archived, private) parks that channel and alerts; the others
  keep running.
- Nothing returns an error out of `serve`. Only config/key load failures at
  startup exit nonzero. A ~40 s buzz-pg switchover is a backoff and a backfill,
  nothing more; that's a required test.
- A single-instance lock (`~/.hcom/buzz/serve.lock`) plus a startup check that no
  other relay device advertises `buzz_read` keeps two connectors from
  double-posting.
- systemd user unit on mbai (`hcom-buzz.service`, `Restart=always`) supervises
  it, because a restart is still the backstop for panics.

### Warehouse Q&A

Kept as a thin layer, not ported into hcom. The numbering (git ref headings),
JSONL ledger, `ffc-bd` bead notes and withdraw rules are FFC workflow, and they
already carry ~350 tests of hard-won behaviour. Putting `ffc-bd` and a git-ref
parser inside a general messaging tool is the wrong layer.

What changes is the transport. The recorder becomes an ordinary hcom participant
named `qa` on mbai (the `zagcom` package minus its Buzz client, identity,
budget, read workers and hcom shims). It consumes with a plain `hcom listen
--name qa --json` loop: since a quiet listen timeout no longer marks the row
`exit:`, the row stays deliverable between calls, so there's no long-timeout
keepalive child.

- Agents ask with `hcom send @qa --intent request -- bead=<id> <question>` from
  any device. `qa` enforces one open question and the numbering, then posts
  `Q<n>` with `hcom send @ch_warehouse @michael`. The connector posts it as
  `qa@mbai`, a single stable asker, which is what the Q&A v2 notes asked for.
- Michael's reply in that thread reaches `qa` through thread routing. `qa`
  fetches the signed event with `hcom buzz event <hcom-id> --json`, checks it is
  operator-signed, records it verbatim (ledger, then bead note), and forwards the
  answer to the asking agent.
- Edits and deletions arrive as `(edited)`/`(deleted)` messages with the signed
  event behind them, which is what the withdraw and amendment rules consume.
  `!withdraw Q<n>` is just answer text, unchanged.

Until that port lands, `#warehouse` stays on the interim bridge. One channel is
never bridged by both.

### Mixed-version behaviour (0.7.52 peers)

No schema change, so old and new processes share `hcom.db`. Concretely:

| Situation | Behaviour |
|---|---|
| 0.7.52 device, `hcom send @michael` | Resolves to `michael:XXXX` (synced via relay state) and is relayed to mbai; delivered. |
| 0.7.52 device lists rows | Hosted rows show as `michael:XXXX` with tool `buzz`; relay pull and the TUI keep unknown tool strings verbatim. |
| 0.7.52 device broadcasts | Its scope can include hosted rows; the connector forwards only explicit targets, so nothing reaches Buzz. |
| Receipts | The TUI read check is the recipient row's `last_event_id` waterline, which is local to mbai; remote read waterlines aren't relayed by any version today. The connector advances the cursor only after the Buzz post succeeds. |
| 0.7.52 CLI, `hcom buzz read` | Command doesn't exist until that device updates its binary. `hcom update` swaps the binary, so CLI calls from not-yet-restarted sessions get it immediately. |
| 0.7.52 daemon sweep on mbai while the connector is down | Hosted rows have no process binding, so the old sweep holds them (`no-pid-evidence`); the new sweep skips them explicitly. Queued messages survive. |
| mbai relay silent > 90 s | Peers drop all mbai mirrors (existing behaviour); `hcom send @michael` from a peer fails loudly at the sender until mbai is back. Never silent loss. |
| Connector host (mbai) itself | Must run the new binary and a restarted relay worker (the RPC handlers run there). That's part of cutover. |

### Migration from zagcom-bridge

Same seed, same derivation, same owner, so every agent identity the bridge
enrolled in `#infra` is the same pubkey after cutover. The bridge's per-channel
`buzz_since:<channel>` cursor is imported once into `state.db` so nothing in the
switch window is missed or replayed beyond the dedupe window.

### Rollout

1. PR: this design doc.
2. PR: Nostr primitives + relay client + in-process fake relay test harness.
3. PR: core hosted participants (tool `buzz`, cleanup exemption) + RPC handlers.
4. PR: connector (routing, enrollment, outbox, budgets, `hcom buzz` CLI).
5. Live end-to-end on a private test channel `#hcom-test` (created by omp) with
   a test human key generated for the purpose, never Michael's: mention, plain
   thread reply, DM, edit, delete, popup listing (checked from the relay
   directory data the desktop reads), a remote-device send through the relay,
   a forced 5xx window and a 429.
6. Report ready. With the operator's go (relayed by nami): release hcom (CDN +
   `latest.json`), then cut `#infra` over: stop `zagcom-bridge`, import cursor,
   start `hcom-buzz.service`, verify, keep the bridge unit installed but disabled
   for rollback.
7. Q&A port, then `#warehouse` cutover the same way.

Rollback at any step: stop `hcom-buzz`, start `zagcom-bridge`. Identities are
shared, so nothing in Buzz has to change.

## Decisions for the operator

- **D1. Where `hcom send @michael` lands with no channel or thread context.**
  Recommend a DM from that agent: private, a phone notification, and replies in
  the DM route back to the right agent without guessing. The alternative is
  posting in a default bridged channel with an `@michael` mention, simpler but
  public to everyone in that channel.
- **D2. Which channels list agents in the mention popup.** Recommend `#infra`,
  `#warehouse` and `#hcom-test`, with every live hcom agent enrolled and pruned
  24 h after its session ends. The alternative is enrolling only agents that
  have posted, which keeps the list short but hides agents you'd want to ping
  first.
- **D3. Who may message agents.** Recommend: any member of a bridged channel,
  with every message labelled by its human sender, consistent with "being in the
  channel is the authority". That means coworkers like SeanFitz can instruct
  agents. The alternative is an allowlist of humans in the connector config.
- **D4. Human names in hcom.** Recommend slugs of the Buzz profile name
  (`michael`, `seanfitz`), fixed at first sight, with a config override.
- **D5. Q&A.** Recommend the thin layer above. `#warehouse` keeps the interim
  bridge until the `qa` participant is proven.
