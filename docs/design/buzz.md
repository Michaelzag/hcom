# Buzz as a native hcom integration

Status: design, for review. Owner: BuzzHcomNative lane. Date: 2026-10-06.

## Bottom line

hcom grows a Buzz connector: `hcom buzz serve`, a long-lived process inside the
hcom binary that runs on exactly one host (mbai). It makes every Buzz human in a
bridged channel an hcom participant (`michael`, `seanfitz`) and every hcom agent
a Buzz identity humans can pick in the mention popup. Agents on any device talk
to humans with plain `hcom send @michael`; the existing hcom relay carries the
message to mbai, where the connector posts it to Buzz as that agent. Human
replies (mentions and plain thread replies) come back as ordinary hcom
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
  9000 with role `bot`. Kind 10100 is optional (presence only).
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
| Relay client: WS session (AUTH, REQ, CLOSE, inbound EVENT/EOSE/CLOSED/NOTICE), HTTP `/events` + `/query` | `src/buzz/relay.rs` | Std threads + blocking sockets, matching the rest of hcom (no async runtime). All publishing is HTTP: one WS session can only ever speak as one key. |
| Connector state DB | `src/buzz/store.rs`, file `~/.hcom/buzz/state.db` | Connector state stays out of the core schema, and the pubkey ↔ name maps survive `hcom reset`. Every hcom event id stored here is scoped by the hcom DB epoch (below). |
| Routing (Buzz event → hcom message, hcom message → Buzz post) | `src/buzz/route.rs` | Pure decision functions over typed inputs; the heart of the tests. |
| Service loop | `src/buzz/serve.rs` | Composition root: config, keys, sessions, workers. |
| CLI | `src/commands/buzz.rs`: `serve`, `status`, `read`, `down`, plus mbai-local `query`, `prepare`, `publish` for the Q&A layer | One command family. |
| Core hcom changes | `hosted.rs` (new), `proctruth.rs`, `commands/stop.rs`, `commands/send.rs` + `messages.rs` (addressing), `relay/control.rs` | Hosted participants, the addressing forms, one read RPC. |

A separate binary or service was rejected: the connector has to own hcom rows,
read their unread messages, send as them and advance their cursors. Doing that
from outside is the CLI-shelling and listen-timeout workaround the bridge
needed.

New crates, all pure Rust so Windows and macOS CI keep compiling: `k256`
(schnorr), HKDF, `tungstenite` (rustls), `ureq` (rustls), `bech32`.

### Identities and key custody

Everything secret stays on mbai, read in-process, never logged, never on argv,
never in a child's environment.

- **Seed**: the existing 32-byte `hcom-buzz-seed` (ubuntu-admin
  `secrets/hosts/mbai/`). Path in config.
- **Owner**: the `omp` identity (`7e996ef3…`). Its key is parsed in-process from
  `buzz-omp.env` (`BUZZ_PRIVATE_KEY`, hex or nsec), same rules as the bridge's
  `load_owner_key`.
- **Agent key** for hcom name N on device label D:
  `HKDF-SHA256(ikm=seed, salt=none, info="zagcom/hcom-identity/v1:" + N + "@" + D, len=32)`,
  reduced into `[1, n-1]`, byte-identical to the bridge (pinned by vectors
  generated from the Python implementation).
- **Device label**: mbai's own rows use the configured `device_label` (`mbai`),
  so every mbai agent identity the bridge enrolled keeps its pubkey. Rows from
  other devices use the lowercased hcom relay short id (`luna:BOXE` →
  `luna@boxe`); it changes only on `hcom reset all` of that device, and then
  that agent gets a fresh Buzz identity. The bridge bound remote devices by a
  claimed name instead, but its remote client never ran (STATUS.md:79-90), so
  no remote-device identities exist to preserve. This needs nothing from 0.7.52
  peers.
- **Connector reader**: its own info string,
  `hcom-buzz/connector/v1:reader@<device_label>`, so no hcom agent name can
  collide with it. It holds the channel subscriptions; omp adds it to each
  bridged channel.
- **Profile**: every derived agent key publishes a kind 0 with `display_name` =
  hcom name (plus ` (DEV)` for remote devices), `about` =
  `zagcom/hcom-identity/v1:<N>@<D>` (the bridge's marker), and the NIP-OA tag
  with empty conditions. The marker is how the connector maps any author back to
  an hcom name, including authors of posts made before cutover: re-derive from
  the claimed name and accept only if the pubkey matches.

### The hcom DB epoch

`hcom reset` archives `hcom.db` and restarts event ids at 1. Every hcom event id
the connector remembers is stored with an epoch: the `hcom.db` inode plus kv
`relay_local_reset_ts`, the same rule the bridge uses (`hcom.py:475-500`). On an
epoch change the connector drops its id-keyed lookups and re-registers its rows.
Unposted outbox rows are kept and sent until acknowledged: each holds a complete
signed event and needs no hcom id to go out. Everything keyed by pubkey or Buzz
event id carries over.

### Who is who in hcom

| Buzz thing | hcom participant | Name |
|---|---|---|
| A human member of any bridged channel (not omp, not a derived key, not role `bot`) | hosted row, `tool = "buzz"` | slug of kind 0 `name`/`display_name`, `[a-z0-9_]`, stable once assigned (stored by pubkey), overridable in config |
| A bridged channel | hosted row, `tool = "buzz"` | `ch_<slug>` (`ch_infra`, `ch_warehouse`) |

A name collision with a non-buzz row gets a `_bz` suffix. Person rows appear the
first time the roster (kind 39002) shows them in a bridged channel, and are
stopped 24 h after they leave every bridged channel. That's the whole
onboarding story for coworkers. hcom `@` resolution is case-insensitive, so
`@SeanFitz` works.

### Hosted participants (the core hcom change)

hcom has no "one process hosts many rows" notion. Rows are reaped by the daemon
sweep (`sweep_vanished_instances`, every 30 s from the relay worker) on positive
evidence that their process died, and deleted by `hcom stop` / `hcom reset`.
Inactive status alone deletes nothing, and the send predicate
(`fleet_names::LIVE_ROW_PREDICATE`) refuses only `stopped`, `launch_failed` and
`inactive` + `exit:*`. Core changes, each with a fail-before/pass-after test:

1. **Connector-owned registration** (`instance_binding.rs`): create the row with
   `tool = "buzz"`, no session or process binding, `tcp_mode = 1`, status
   `listening`, context `buzz:online` (never `new`, so placeholder cleanup
   ignores it). On restart, upsert in place and never reset an existing row's
   `last_event_id`; the ordinary initializer jumps a new row's cursor to the
   current max, right for agents and wrong here. Fleet name-collision checks
   apply as for any registration.
2. **Reaper and `stop all` exemption**: `proctruth::sweep_vanished_instances`
   and `hcom stop all` skip `tool = "buzz"` rows. Today the sweep would hold
   them for lack of PID evidence, but that's an accident, not a contract. An
   explicit `hcom stop michael` still stops that row; if `michael` is still in
   the connector's active roster, the connector re-registers it within one loop
   and logs that loudly. Rows the connector itself retired (people who left,
   `down`) are never re-registered. `hcom reset` is handled by the epoch rule.
3. **Liveness from the connector's heartbeat**: one localhost notify endpoint
   (kind `listen`, one port shared by every hosted row; `wake_all` already
   dedupes by port) and one `UPDATE … SET last_stop` over all hosted rows per
   loop. On mbai the computed status reads `listening` while the connector runs
   and goes stale within 35 s of it dying; peers see the stored status, so
   liveness is visible from mbai only. On graceful stop the connector writes
   `inactive` / `buzz:offline`. All of these are deliverable, so messages sent
   while the connector is down queue on the row's cursor and drain on restart.
4. **One relay RPC handler, `buzz_read`** (one entry in `REMOTE_RPC_HANDLERS`).
   Every upgraded device advertises it, so callers don't pick the target by
   capability: they send it to the origin short id of the `ch_*` mirror rows,
   which only the connector host publishes. A device without connector state
   answers with an explicit error.

No `Tool` enum variant: the column is a free string, relay and TUI already carry
unknown tools verbatim, and a variant would add ten exhaustive match arms for
launch/resume/hook plumbing a connector never uses. No schema change.

The connector consumes each hosted row the way `hcom listen` does
(`get_unread_messages`, advance `last_event_id`, log the delivery status), so
hcom's cursor is the single record of what a Buzz person has been handed. The
TUI read check on mbai therefore means "queued for Buzz"; the logged delivery
status after the relay accepts the post means "posted".

### Buzz → hcom (inbound)

One WS session as the reader. Per bridged channel: one REQ with that channel's
`#h` for kinds `{9, 40002, 45001, 45003, 40003, 5, 9005, 39002}`, opened
staggered (WS budget is 50 frames / 5 s). On (re)connect each channel backfills
from its durable `created_at` cursor minus 960 s (the relay admits 900 s of
backdating), deduplicated by Buzz event id. DMs are not bridged (operator
ruling on D1).

For each event E from author H, signature verified first:

- **Skip** if H is a derived key (our own posts), omp or the reader.
- **Targets** = agents p-tagged in E ∪ the agent author of any ancestor in E's
  thread (walk `e` tags to the root; this is what catches plain thread
  replies), minus H. An ancestor missing from the cache is
  fetched by id from the relay, and its author resolved through the profile
  marker, so replies under posts older than cutover still route.
- Agent pubkey → hcom name: label `mbai` → bare name; otherwise
  `name:SHORTID`. Names are resolved at send time against live rows.
- No targets → nothing goes to hcom; the event is still cached for `read`.
- Otherwise one hcom message **as H's hosted row** (`SenderKind::Instance`,
  in-process `send_message`), explicit targets = target names, text = E's
  content with `nostr:npub…` rendered as `@name`, thread =
  `buzz_<channel>_<root12>`. No `reply_to`: hcom event ids are per device and the
  relay doesn't translate them, so the thread name is the correlation that
  survives the hop.
- **Edits (40003)** and **deletions (5, 9005)** of an event that was delivered →
  a new message to the same targets in the same thread, prefixed `(edited) ` or
  `(deleted)`. The original message is never rewritten. The Q&A layer doesn't
  depend on these; it reads signed events itself.
- **Unresolvable target** (agent session ended, or its device's mirror expired):
  that target is parked per event and retried with backoff for 15 min. The
  channel cursor moves on regardless, so one sleeping laptop can't stall a
  channel. If it still can't be delivered, the connector says so in Buzz:
  "luna isn't running — not delivered", as omp in that thread.
- Delivery is at least once. The Buzz event id is recorded as delivered right
  after the send; a crash between the two can repeat that one message, and
  nothing is dropped.

### hcom → Buzz (outbound)

On every wake (and a 5 s tick as a backstop) the connector reads each hosted
row's unread messages. It forwards message M when either:

- the row is in M's `exact_targets` (explicitly addressed), or
- M's thread is a `buzz_<channel>_<root12>` thread. Those threads only exist
  because a Buzz conversation created them, so thread fan-out there is a reply
  in that Buzz thread. This is what makes `hcom send --reply-to <id> -- answer`
  work without an explicit `@michael`: hcom inherits the thread and resolves
  the recipients from its members, leaving `exact_targets` empty.

Everything else (broadcasts, fan-out in ordinary hcom threads, messages sent by
hosted rows) is acknowledged and dropped. `mentions` alone is never the test,
because it also carries ordinary thread fan-out. 0.7.52 senders write the same
fields, so this holds in the mixed period.

Sender: M's `from` (`luna` local or `luna:BOXE` remote) gives the agent key.
External (`ext_`) and system (`sys_`) senders are not posted; they're logged
and dropped.

Destinations, first rule that matches:

1. M's thread is `buzz_<channel>_<root12>` → one reply in that Buzz thread
   (NIP-10 `e` tags), p-tagging every addressed person and the parent author.
2. M targets `ch_<x>` rows → one top-level post per channel, p-tagging the
   addressed people.
3. Otherwise (people only) → a top-level post in each addressed person's
   **home channel**, @mentioning them. A home channel is a private bridged
   channel per human (`#michael`), created by omp like `#warehouse`, so the
   human can invite observers; the connector config maps human → home channel.
   A person with no home channel configured gets nothing posted: the connector
   sends the agent an hcom notice from that person's row ("seanfitz has no home
   channel; address a channel row such as @ch_warehouse"). Two people with
   different home channels get one post each. Agents keep a conversation in its
   Buzz thread by answering with `--reply-to`; the hcom agent-messaging skill
   says so. (Operator ruling D1, 2026-10-06: a channel per human, not DMs.)

Before the first post into a channel the agent is enrolled: kind 0 (agent key),
kind 30177 `{"name", "respond_to": "anyone", "parallelism": 1}` with `d` = agent
pubkey (omp key), kind 9000 add with role `bot` (omp, channel admin). Enrollment
is cached in `state.db` and re-checked against the 39002 roster.

Publishing: each post is signed locally, so its Buzz id is known before it's
sent. The outbox is keyed by (epoch, hcom event id, destination), so a message
to two channels is two independent rows and one failing doesn't hold the other.
Outbox rows commit before the hosted cursors advance; a crash between re-reads
M and the inserts are no-ops. Then `POST /events` with a freshly signed NIP-98
header and `x-auth-tag`, as the agent key. A resend after a lost ack is a relay
duplicate (`duplicate:`), not a second post. A 401 is a bug, not a retry case
(NIP-98 headers are never reused). An entry still unacknowledged as its
`created_at` nears the 900 s admission window is looked up by id and re-signed
only if the relay never stored it.

### Popup enrollment

Agents become pickable before they ever post: every deliverable hcom agent row
(local or remote; not hosted rows, `sys_`/`_` names or subagents) is enrolled
into every bridged stream/forum channel. When an agent's row has been gone for
an hour, omp removes it from those channels (kind 9001), the same trigger that
closes its session, so the popup lists agents that can answer.

### Addressing

Buzz targets live inside hcom's existing target grammar (`src/messages.rs`
`match_target`, `src/commands/send.rs` positional handling), shaped like the
`name:DEVICE` form agents already use (`nina:MABE`): a person, optionally at a
place.

| Address | Means | Buzz result |
|---|---|---|
| `michael` | the person | top-level post in Michael's home channel (`#michael`), @mentioning him |
| `michael:infra` | the person, in a channel | top-level post in `#infra`, @mentioning him |
| `ch_infra` | the channel | top-level post in `#infra`, no mention |
| any of the above + `--reply-to <id>` of a Buzz-originated message | that conversation | reply in that Buzz thread |

How it resolves, on the sender's device, before anything goes on the wire:
`michael:infra` is a colon target whose suffix is not a device id (not four
uppercase letters or digits matching a known device) and whose base is a
`tool = "buzz"` person row; it expands to the two ordinary targets `michael`
and `ch_infra` (`michael:MBAI` and `ch_infra:MBAI` on other devices). Nothing
new travels in the event, so the connector's rule 2 handles it as a channel post
addressed to Michael. A device id wins over a channel slug if both could match.
Today a lowercase colon target only prefix-matches row names and fails as
unmatched, so this takes no existing meaning away.

**No `@` needed.** In PowerShell a bare `@michael` is splatting: it's swallowed
before hcom sees it (tested on KILA, pwsh 7.5: `@michael`, `@michael:infra` and
`@ch_infra` arrive as no argument; `@michael.infra` is a parse error). So
`hcom send` accepts targets without `@` whenever the message is separated with
`--` (or comes from `--stdin`/`--file`/`--base64`): every positional before the
message is a target, so there's no ambiguity. Today that form errors with
"Targets require @" (`send.rs:1048-1066`). The no-`--` compatibility form
(`hcom send hello` = message text) is unchanged. This applies to all targets,
not just Buzz ones, and all docs and agent instructions use the no-`@` form:

```
hcom send michael -- text
hcom send michael:infra -- text
hcom send ch_infra -- text
hcom send michael --reply-to 4521 -- text
```

These are single plain tokens (letters, digits, `_`, `:`, `-`) with no `/ \ #
$` or backtick, and pass unchanged as bare arguments in bash and zsh (run
locally) and in pwsh 7.5 and cmd.exe (run on KILA). [`--` passthrough on
KILA's pwsh is being re-run; result goes in this table before merge.]

**A swallowed `@target` is not reliably caught today.** In pwsh,
`hcom send @michael -- text` arrives as `hcom send -- text`, which is a
broadcast. The broadcast preview only blocks it when the sender is inside an AI
tool, without `--go`, and the broadcast would reach more than three rows
(`send.rs:1162-1169`). Decision D6 below.

### Say and read from every device

- **Say** is plain hcom with the addresses above. All of it works from 0.7.52
  in the `@` form, since it's a message to a remote row; `michael:infra` and the
  no-`@` form need the new CLI on the sending device.
- **Read**: `hcom buzz read <channel> [--thread <root>] [--limit N] [--json]`
  answers from the connector's cache on mbai, and from any other device via the
  `buzz_read` RPC to the `ch_*` rows' origin device. Responses are capped at
  98,304 bytes like the existing events RPC; `--before <buzz-id>` continues. It
  needs the new CLI on the calling device.

### Faults, budgets, backoff

- Per-pubkey token buckets under the relay limits: HTTP 240/min per signing key,
  WS frames 40 per 5 s per session. omp's bucket carries every enrollment write,
  so enrollment is queued and paced; 429 handling covers omp's other users.
- 429 → honor `retry in Ns` (floor 1 s, jitter) for that key only. 5xx,
  transport errors and socket drops → exponential backoff 1 s → 60 s, per
  channel subscription and per outbox destination. `CLOSED` on one channel
  parks it and alerts; the rest keep running.
- Nothing returns an error out of `serve` once it's up. Only config and key load
  failures at startup exit nonzero. A 40 s buzz-pg switchover is backoff plus
  backfill; that's a required test.
- One connector: a lock file on mbai. mbai is the only host configured to run
  it.
- systemd user unit on mbai (`hcom-buzz.service`, `Restart=always`) as the
  backstop for panics.

### Warehouse Q&A

Kept as a thin layer, not ported into hcom. Numbering from git-ref headings,
the JSONL ledger, `ffc-bd` bead notes, the one-open-question lock and the three
withdraw paths are FFC workflow with ~350 tests behind them. `ffc-bd` and a
git-ref parser don't belong in a general messaging tool.

The transport is what changes. `QaWorkflow` already talks to Buzz through a
seven-method transport (`qa_workflow.py:108-129`: identity, query, query_all,
members, prepare_question, publish_question, publish_question_enrolled). The
thin layer replaces its implementation, Python crypto + `buzz` CLI + raw HTTP,
with calls to mbai-local `hcom buzz` subcommands that do the signing in-process:

- `hcom buzz query --json` and `hcom buzz members <channel> --json`: signed
  `/query` reads as `qa@mbai`.
- `hcom buzz prepare --channel ch_warehouse --p <operator> --created-at <ts>
  --json`: returns the signed kind 9 without sending it, using the
  reservation's own `created_at`, so `qa` stores the exact question and its
  root id, as today.
- `hcom buzz publish --json` with that event on stdin: enrolls if needed, posts
  that exact event, confirms by id. Idempotent. An abandoned or withdrawn
  question is never published, so the publication-truth rules in
  `qa_workflow.py:663-727` hold unchanged.

These sign only as identities listed in the connector config's
`local_signers` (just `qa`), so no other process on mbai can sign as an
arbitrary agent.

Everything else stays as it is: answers are still ingested by `qa`'s own
signed-ancestry scan of `#warehouse`, so verbatim content, signatures, edits,
root deletions and tombstones are read from signed events, not from rendered
hcom text.

What goes away is the remote-client and request-thread machinery. `qa` becomes
an hcom participant on mbai: agents anywhere ask with
`hcom send @qa --intent request -- title=<t> bead=<id> <question>`, and `qa`
answers and forwards recorded answers with `hcom send`. Its row is registered
with `hcom start --name qa` on service start and consumed with a plain
`hcom listen --name qa --json` loop; a quiet listen timeout no longer marks a
row `exit:`, so there's no keepalive child. If the service is down long enough
for the sweep to reap the row, sends to `@qa` fail loudly until it restarts.
Thread replies under `qa@mbai`'s questions also reach the `qa` row through
ordinary routing; `qa` acknowledges and ignores those, since its scan is the
record.

That Python change lives in the `zagcom` repo, which the interim-bridge lane
owns right now; it starts after that lane lands, coordinated through nami. Until
then `#warehouse` stays on the interim bridge, and no channel is ever bridged by
both.

### Mixed-version behaviour (0.7.52 peers)

| Situation | Behaviour |
|---|---|
| 0.7.52 device, `hcom send @michael` / `@ch_infra` | Resolves to the `…:XXXX` mirror and is relayed to mbai; delivered. |
| 0.7.52 device lists rows | Hosted rows show as `michael:XXXX` with tool `buzz`; relay pull and the TUI keep unknown tool strings verbatim. |
| 0.7.52 device broadcasts or posts to a thread | Not in `exact_targets`, so nothing reaches Buzz. |
| 0.7.52 agent replies with `--reply-to` | Its CLI copies the `buzz_*` thread name, so the reply lands in the Buzz thread. |
| Receipts | The TUI read check is the recipient row's cursor, local to mbai; no hcom version relays remote read waterlines. |
| 0.7.52 CLI, `hcom buzz read`, `michael:infra`, no-`@` targets | Need the new binary on the sending device. On 0.7.52, `michael:infra` fails as an unmatched target and a no-`@` target fails with "Targets require @"; both are loud. `hcom update` swaps the binary, so even not-yet-restarted sessions get the new forms on their next CLI call. |
| 0.7.52 daemon sweep on mbai while the connector is down | Hosted rows have no process binding, so the old sweep holds them (`no-pid-evidence`); the new one skips them explicitly. |
| mbai relay silent > 90 s | Peers drop all mbai mirrors (existing behaviour); sends to `@michael` from a peer fail loudly until mbai is back. |
| Connector host (mbai) | Runs the new binary and a restarted relay worker (the RPC handler runs there). Part of cutover. |

### Migration from zagcom-bridge

Same seed, derivation, owner and mbai label, so mbai agents keep their Buzz
identities. The bridge's per-channel `buzz_since:<channel>` cursor is imported
once into `state.db`. Threads under old bridge posts route through the profile
marker. Bridge state that doesn't carry over: its pending owner-DM alerts and
request receipts. Cutover stops the bridge only after `zagcom status` shows
those empty.

### Rollout

1. PR: this design doc.
2. PR: Nostr primitives + relay client + in-process fake relay.
3. PR: core hosted participants.
4. PR: connector (routing, enrollment, outbox, budgets, `buzz_read` RPC,
   `hcom buzz` CLI incl. the Q&A subcommands).
5. Live end-to-end on a private test channel `#hcom-test` (created by omp) with
   a throwaway test-human key, never Michael's: mention, plain thread reply,
   reply under a pre-cutover-style post, a home-channel post, edit, delete,
   popup eligibility (checked against the directory data desktop reads), a send
   from a second relay device, a forced 5xx window and a 429.
6. Report ready. With the operator's go via nami: release hcom (CDN +
   `latest.json`), then cut `#infra` over: drain and stop `zagcom-bridge`,
   import its cursor, start `hcom-buzz.service`, verify, keep the bridge unit
   installed but disabled.
7. Q&A transport swap in `zagcom`, then `#warehouse` cutover the same way.

Rollback: `hcom buzz down` first waits for the outbox to drain (bounded, and it
prints anything still unposted with its destination), then stops the service,
then marks every hosted row `stopped`, so senders get a clear refusal instead
of queueing into nothing. Then start `zagcom-bridge`. Identities are shared, so
nothing in Buzz changes.

## Decisions for the operator

- **D1. Decided (operator, 2026-10-06):** `hcom send @michael` with no Buzz
  thread posts in that human's private home channel (`#michael`), @mentioning
  him, so observers can be invited. No DMs.
- **D2. Popup.** Recommend enrolling every live hcom agent into every bridged
  stream channel (`#infra`, home channels, `#hcom-test`, later `#warehouse`). Alternative:
  only agents that have posted, a shorter list that hides agents you'd want to
  ping first.
- **D3. Who may message agents.** Recommend any member of a bridged channel,
  each message labelled with its human sender: being in the channel is the
  authority. So coworkers like SeanFitz can instruct agents, and hcom delivery
  roles (reroutes to role holders) apply to them like any sender. Alternative:
  a human allowlist in config.
- **D4. Human names in hcom.** Recommend slugs of the Buzz profile name
  (`michael`, `seanfitz`), fixed at first sight, with a config override.
- **D5. Q&A.** Recommend the thin layer: keep zagcom's Q&A logic, swap its
  transport for `hcom buzz` subcommands, make `qa` an hcom participant.
  `#warehouse` stays on the interim bridge until that's proven.
- **D6. Target-less sends after `--`.** A swallowed pwsh `@target` silently
  becomes a broadcast unless the narrow preview gate fires. Recommend: a send
  that uses `--` (or `--stdin`/`--file`/`--base64`) with zero targets is
  refused unless `--go` is given, everywhere, not only inside AI tools with
  more than three recipients. That makes an accidental broadcast impossible to
  send by mistake from any shell; deliberate broadcasts add `--go`.
  Alternative: leave broadcast as is and rely on the no-`@` docs.
