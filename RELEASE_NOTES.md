## Unreleased

`hcom kill` no longer signals an unrelated process that reused a crashed
seat's PID (#106). Every target form, including multiple names, tags, all,
and stopped-process targets, now requires positive owner proof before pane,
process-group, or Windows tree teardown. The same `omp_launch_pid` receipt
now records the native birth identity atomically with every PID update,
including the hook's interpreter re-pin. A mismatched or unreadable identity
refuses with the PID, reason, nonzero exit and `hcom stop N` recovery pointer;
gone and zombie owners get signal-free bookkeeping cleanup. Bulk kills
continue handling verified owners while reporting refusals.

Legacy rows on Linux, macOS and Windows can prove ownership through the live
process's bound `HCOM_PROCESS_ID`, read through the native process API. This
keeps a pre-upgrade or hung owner killable without waiting for another hook.
The next successful `omp-start` writes the native owner receipt. Missing,
unreadable, malformed or mismatched evidence refuses without signalling;
`hcom stop N` only clears bookkeeping.
Windows tree termination checks the captured creation time through the same
handle it terminates and will not follow a reused parent's numeric PID.

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

A resume that launched an OMP which exited or crashed before its first hook no
longer locks the seat. The next `hcom r N` replaces a launch pin whose process
is gone, is a zombie, or whose pid now belongs to a different process: the
receipt records the launch process's native start identity next to the pid. A
launch still running before its first hook is left alone, and so is a pin whose
process can't be read or that predates this release and is still live.

A held reservation refuses the resume and names the recovery. `hcom stop N`
releases an inactive reservation that never bound a session; it only clears
hcom's bookkeeping, never signals the recorded pid (that pid may belong to an
unrelated process after reuse), and prints that no process was signaled:
`Released reservation for <name>; no process was signaled (recorded pid <pid>).`
`hcom r N` then works. A launch that is really still running is yours to stop —
close its terminal; hcom won't. The released identity carries no owner
evidence, so `hcom r N` is the way back: `hcom start --as N` and a plain OMP
re-adopting that session refuse it.

The hook path now applies the same owner-or-positively-dead rule as
`hcom start --as` when an `omp-start` recreates a released name: a different or
descendant OMP can't claim it while the name's last owner is still running. The
owner itself, a dead or zombie owner's successor, `hcom r N`, and a canonical
resume after a normal stop still bind on the first hook.

The receipt rides in the existing `launch_context` JSON as the `omp_launch_pid`
key, which `hcom list --json` shows; there is no schema change. An older binary
reads the unknown key and ignores it, and its hook-time context rewrite may drop
it, which leaves that pin on the legacy rules — held while its process is live,
with `hcom stop N` available.

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

Two more refusals ship with their own fix: a held unhooked reservation wants
`hcom stop N` and then `hcom r N`; and a released name whose last owner is
still running refuses another OMP's `omp-start` claim, so run from the owning
OMP, wait for it to exit, or `hcom r N`.

Separately from the terminal-receipt change above, OMP self-stop with caller
exclusions on Windows and macOS remains an effective soft stop: the row goes
inactive, its own process binding is kept, and the canonical session binding
and notify endpoints are cleared, so the same owner resumes normally. Linux
keeps the full release. There is no native reaper port.

The `still active or its ownership is undetermined` resume refusal now names
`hcom stop <name>` followed by `hcom r <name>`, even when the recorded pid is
gone or missing. The conservative refusal and its no-mutation behavior are
unchanged.

Delivery publishes PTY wake and inject endpoints atomically under the current
row incarnation. Late refreshes cannot recreate endpoints after the row is
removed or overwrite another owner's replacement. Binding-verified name changes
and same-name re-registration still work.
