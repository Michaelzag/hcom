## Unreleased

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

OMP ownership now follows the nearest actual OMP process. A nested or sibling
OMP that inherits a seat's process id, instance name, or anchor pid no longer
binds to that seat, reads its mail, or changes its state. Every OMP hook needs
the actual owner, including `omp-read --check` and `--format`: even a read can
consume governed mail, forward a message, or mark a thread tip.

An OMP seat launched by 0.7.60 or earlier works on its first hook or read. A
normal launcher or gnomeseat seat, a canonical resume, a headless seat, a
PTY-only seat and a same-owner stop keep working, and a missing owner pin or
launch receipt alone does not block the bind, so no relaunch and no database
repair are needed. (The terminal-receipt note above still governs pane closing
after kill or resume.) OMP started through npm's Bun package on Linux or macOS
is recognized by its real `bun.exe` basename, a Bun-specific alias rather than
a general `.exe` strip on Unix.

Refusals leave state unchanged: a rare pre-guard row bound to a shared generic
wrapper with no recorded OMP owner pid; a plain OMP that inherited an unproven
launcher UUID, which is never adopted, even under `plain_sessions` (with the
UUID and its session unbound, it mints a fresh identity instead); and a hook
call from a caller that cannot prove it is the seat's owner. A dead owner's
canonical session can still be adopted, a released identity can be reclaimed
when its last owner is the caller or is positively dead (an observed zombie
counts as dead), and a soft-stopped seat resumes normally for its owner. An
owner whose liveness or incarnation cannot be read refuses. This covers
accidental identity inheritance, not a process that can edit the same user's
database, environment or argv.

Separately from the terminal-receipt change above, OMP self-stop with caller
exclusions on Windows and macOS remains an effective soft stop: the row goes
inactive, its own process binding is kept, and the canonical session binding
and notify endpoints are cleared, so the same owner resumes normally. Linux
keeps the full release. There is no native reaper port.
