## Unreleased

`hcom send` stays successful after delivery when a notification thread can't
start (for example, under a low systemd `TasksMax`). Wakeups fall back to
inline connections with the same per-endpoint timeout. Failed fallback
connections are logged without inviting a retry of an already-stored message.

Codex no longer warns about unrecognized hcom keys. hcom's Codex hook trust
bookkeeping moved out of Codex's `config.toml` into a sidecar at
`$HCOM_DIR/codex-hook-trust.json`, keyed by canonical Codex home and then
`hooks.state` id. Codex 0.165 rejected the two private keys hcom used to
write there and warned about them on every launch. Codex's own `trusted_hash`
and `enabled` values stay in TOML.

**Upgrade behavior:** the next `hcom codex` launch strips the legacy
`hcom_codex_cli_version` and `hcom_hook_definition_hash` keys from every
`hooks.state` table, including foreign and inline tables, and leaves your own
settings untouched. A missing or stale sidecar fails verification instead of
falling back to the legacy TOML keys, so trust is recorded again on the next
launch. Concurrent writers across Codex homes are serialized by a stable
`codex-hook-trust.json.lock` sibling.

Hook tests now clear inherited tool-home overrides, so a fixture can't write
into the operator's real Codex, Claude, Gemini, or Cursor configuration.

Kill now retries a busy database while finalizing the stopped snapshot and
releasing the row. The retry window is 30 seconds plus at most one final
5-second SQLite wait. If it still can't write, the error distinguishes the
dead process from the unfinalized row and gives `hcom kill <name>` as recovery.

Resume's empty-carrier recovery requires a recorded, positively dead pid.
It respects the daemon sweep's activity grace, live shell bindings, and
seat-owned or undetermined notify endpoints. Those holds and the captured
incarnation are checked again under the write transaction before releasing
the row or any child. Pid-less and unprovable empty-carrier rows stay held.

Local busy/stale rows and invalid snapshots no longer turn into an off-host
identity hint. Resume suggests kill-then-resume only for database contention
on a verified dead-pid row whose entire tree passes the recovery checks. Ownership
refusals, read failures, and pid-less rows keep their real error without
prescribing a destructive or unusable retry.

A successful terminal spawn stays a successful launch if later database
bookkeeping fails. Those failures are warnings, not a false `0/1 launched`
report or a reason to launch the same seat again.

Terminal cleanup now requires a receipt from the instance's own launch.
Manually started agents can't close another seat by inheriting its pane or
systemd unit id.

**Upgrade behavior:** instances launched by v0.7.58 or earlier have no receipt.
Kill or resume leaves their terminal panes open until they're relaunched.
This includes the gnomeseat and zagtmux seats already running on mbai. The
upgrade doesn't retroactively certify their captured terminal ids.

Run-here tool launches still close their own identified pane in tmux,
wezterm, kitty, zellij, herdr and waveterm. The launcher records ownership
before exec using that pane's environment id. Window, workspace and unit
ids don't grant run-here ownership: an inherited `GNOME_SEAT_UNIT` or
`gnome-terminal-seat-*` value never permits closing the whole seat.

Session adoption transfers receipt ownership to the canonical instance
alongside its pid and launch context. After ownership is proven, the close
id order stays `pane_id` (from `pane_id_env`), then `terminal_id`, then the
opener's captured id. The per-seat unit-name guard applies to the chosen id.

## 0.7.62

Oh My Pi seats now prove their owner instead of trusting the environment they
inherit (#101). Every omp lifecycle call — `omp-start`, `omp-status`,
`omp-read`, `omp-beforetool`, `omp-stop`, `omp-role` — is authorized against
the one real `omp` process on the caller's path to its launch anchor, matched
by pid and by the native process incarnation (boot id and start time). Two
omp processes on that path, an unreadable one, an omp worker, a vanished owner
or a reused pid refuses, and an ancestor above the anchor can neither supply
nor invalidate the owner. A refusal is terminal: it never mints a
replacement identity and never invites a retry.

The owning seat keeps working. A session switch or branch rebinds the row,
moves the runtime state and the notify endpoints and releases the displaced
row in one transaction, and the same owner may repair its own row's poisoned
session metadata. A second minted id for the same live omp counts as that
same holder, not as another live process, so the switch migrates the row
instead of leaving the old one bound (#126); a late failure inside that
migration rolls the whole switch back.

The omp plugin now recovers a failed bind on its own (#124). The 1800 ms hook
cap is unchanged. A bind that timed out or reported a transient error is
retried from the plugin's own reconcile timer with bounded backoff — 5 s, then
10 s, 20 s and 30 s, five attempts at most — reusing the same process id and
the same notify endpoint, so a start that committed before the timeout
recovers that row instead of creating a second identity. Ownership refusals,
an intentional stop and other terminal answers are never retried, and a retry
belongs to the session generation that asked for it.

A seat's own stop stays the seat's own. `omp-stop --soft` keeps the row and
the process binding, which is what `/restart` needs when it execs the same pid
and rebinds; a hard stop releases the row on Linux, and off Linux the row is
soft-stopped instead, because nothing there can see the session's other
carriers. The exiting session's own process tree is excluded from the stop's
signals, while every other carrier (tool subprocesses, MCP/LSP servers) is
still reaped and a survivor still blocks the release. A nested extension
inside the same omp process — an omp task subagent loads a fresh extension
instance in the parent process — never binds and never stops, so it cannot
take the parent's seat. A throwaway omp process (a print or RPC run, or one
with no session file) stays inert: it binds nothing, stops nothing and opens
no notify server.

**Upgrade behavior:** plain seats registered by v0.7.61 recorded no pid at
all. Those rows migrate under a proven owner: the owner is pinned on the
existing row in place, so the old plugin's read, ack, status, stop and
restart keep working and no second identity is minted. A row with another
owner, another live holder or a reused pid is refused and left untouched.
Plain (non-hcom-launched) omp sessions join only with the `plain_sessions`
opt-in, and the plugin starts no recovery of its own while that opt-in is off.

The plugin and the binary ship together. Refresh the installed plugin with
the new binary — `hcom hooks add omp` (`install` is an alias) — using the
environment the seat actually runs in. The destination is resolved, not
fixed: `$PI_CODING_AGENT_DIR/extensions/hcom.ts` when that is set, otherwise
`~/.omp/agent/extensions/hcom.ts`, or `<root>/.omp/extensions/hcom.ts` for a
non-home root. The installer byte-compares the embedded plugin, rewrites an
hcom-owned stale `hcom.ts`, and refuses a foreign `hcom.ts` instead of
overwriting it. The refresh is disk-only: a running omp keeps the plugin it
already loaded until it is restarted, so roll the binary and the plugin to a
seat and restart that seat before relying on the new behaviour.

Known limits: omp-core #369 (shared worker environment inheritance) is not
fixed here, and this release does not clean warm helper environments.
