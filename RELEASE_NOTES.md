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
