//! Process truth: the live process table as the lifecycle gate.
//!
//! The DB row says what hcom *believes*; `/proc` says what is *true*. Two
//! incidents (2026-09-20/21) showed the belief drifting from truth:
//!
//! - `hcom r` spawned a new harness over a still-running prior subtree
//!   (orphan puma pushed a tag under a dead name), and
//! - systemd-oomd killed a whole session cgroup, so the in-cgroup writer of
//!   the `stopped` event died with the session and the row stayed active.
//!
//! This module owns the three mechanisms that close those gaps:
//!
//! - [`processes_for_instance`]: enumerate live processes holding an
//!   instance — `HCOM_INSTANCE_NAME=<name>` OR `HCOM_PROCESS_ID=<binding>`
//!   (exact entry match; only those two variables' values are ever read —
//!   other environ values are never printed).
//! - [`reap_instance_tree_for`]: SIGTERM the whole carrier set (oldest first,
//!   so the pty wrapper goes before its children), wait up to 5 s, SIGKILL
//!   survivors.
//! - [`check_spawn_allowed`]: refuse to spawn under `<name>` over a live
//!   holder or an orphan (started before the newest binding).
//! - [`sweep_vanished_instances`]: daemon-side periodic check that notices
//!   rows whose harness is gone without a `stopped` event.
//!
//! Unix only: `/proc` enumeration is compiled out on other platforms, where
//! every query reports empty (verified-no-holders) and reap is a no-op.

use crate::db::HcomDb;

/// One live process carrying an instance name.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcMatch {
    /// OS pid.
    pub pid: u32,
    /// Value of that process's `HCOM_PROCESS_ID` entry (empty if absent).
    pub process_id: String,
    /// Process start time as unix epoch seconds (field 22 of /proc stat +
    /// system btime). Used to tell orphans (started before the newest
    /// binding) from current-subtree processes (started after).
    pub start_epoch: f64,
}

/// Refusal reason when spawning under `<name>` is blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HolderKind {
    /// A process carrying the newest binding's own process_id is alive.
    LiveHolder,
    /// A process carrying the name with an older process_id, started before
    /// the newest binding (minus grace), is alive.
    Orphan,
}

/// A refused spawn: which pids hold `<name>` and why.
#[derive(Debug, Clone)]
pub struct SpawnRefusal {
    pub name: String,
    pub kind: HolderKind,
    pub pids: Vec<u32>,
}

impl std::fmt::Display for SpawnRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.kind {
            HolderKind::LiveHolder => "live holder",
            HolderKind::Orphan => "orphan",
        };
        write!(
            f,
            "refusing to spawn under '{}': {} process(es) {} still alive: {} — run hcom kill {} first",
            self.name,
            self.pids.len(),
            what,
            self.pids
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            self.name,
        )
    }
}

/// Grace between a binding's `updated_at` and a process start before the
/// process counts as pre-dating the binding (orphan). Covers clock skew
/// between the DB timestamp and /proc starttime arithmetic.
const ORPHAN_GRACE_SECS: f64 = 30.0;

/// How long reap waits after SIGTERM before escalating to SIGKILL.
#[cfg(unix)]
const TERM_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// Poll step while waiting for exits.
#[cfg(unix)]
const POLL_STEP: std::time::Duration = std::time::Duration::from_millis(100);
/// How long reap waits after SIGKILL before declaring survivors.
#[cfg(unix)]
const KILL_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Enumerate live processes holding an instance: environ contains exactly
/// `HCOM_INSTANCE_NAME=<name>` as one NUL-delimited entry, or exactly
/// `HCOM_PROCESS_ID=<id>` for one of the instance's binding ids.
///
/// The second arm is the self-bound rule: self-bound sessions (bound at the
/// first hook from `HCOM_PROCESS_ID=omp-<pid>-…`, never carrying
/// `HCOM_INSTANCE_NAME`) are held by their process id, not their name.
///
/// Only the `HCOM_INSTANCE_NAME` and `HCOM_PROCESS_ID` entries are ever
/// inspected; no other environ values are read or reported. The calling
/// process itself is always excluded (a CLI running inside the session
/// inherits the name but never owns it).
pub fn processes_for_instance(name: &str, binding_ids: &[String]) -> Vec<ProcMatch> {
    #[cfg(unix)]
    {
        enumerate_unix(name, binding_ids)
    }
    #[cfg(not(unix))]
    {
        let _ = name;
        let _ = binding_ids;
        Vec::new()
    }
}

/// Decode the two identity facts from a raw /proc environ block: whether it
/// carries exactly `want` (`HCOM_INSTANCE_NAME=<name>`) as one NUL-delimited
/// entry, and its `HCOM_PROCESS_ID` value (empty when absent). Only these two
/// entries are ever decoded; everything else stays unread bytes.
#[cfg(unix)]
fn identity_facts(env: &[u8], want: &[u8]) -> (bool, String) {
    let mut carries_name = false;
    let mut process_id = String::new();
    for var in env.split(|b| *b == 0) {
        if var == want {
            carries_name = true;
        } else if let Some(rest) = var.strip_prefix(b"HCOM_PROCESS_ID=") {
            process_id = String::from_utf8_lossy(rest).into_owned();
        }
        if carries_name && !process_id.is_empty() {
            // Both facts known; remaining entries cannot change them.
            // (A second HCOM_PROCESS_ID entry would be pathological;
            // first wins.)
            break;
        }
    }
    (carries_name, process_id)
}

/// True when a decoded `HCOM_PROCESS_ID` value names one of the instance's
/// bindings. Empty never matches, so an absent entry (or an empty binding
/// id) can never hold an instance.
#[cfg(unix)]
fn is_bound_process_id(process_id: &str, binding_ids: &[String]) -> bool {
    !process_id.is_empty() && binding_ids.iter().any(|id| id == process_id)
}

#[cfg(unix)]
fn enumerate_unix(name: &str, binding_ids: &[String]) -> Vec<ProcMatch> {
    let want = format!("HCOM_INSTANCE_NAME={name}");
    let self_pid = std::process::id();
    let btime = system_btime();
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in dir.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        // An unreadable environ (exited, or foreign-owned — a different UID)
        // reads as absent. Cross-UID carriers are therefore invisible here;
        // all hcom sessions run as the same user, so that blind spot is a
        // documented limitation, not a live case.
        let Ok(env) = std::fs::read(format!("/proc/{pid}/environ")) else {
            continue;
        };
        let (carries_name, process_id) = identity_facts(&env, want.as_bytes());
        // Self-bound arm: the process carries one of the instance's binding
        // ids even though it never carried the name. Empty binding ids never
        // match (an absent HCOM_PROCESS_ID reads as empty).
        if !carries_name && !is_bound_process_id(&process_id, binding_ids) {
            continue;
        }
        // A second pass is unnecessary: process_id defaults to empty when
        // the entry is absent, which simply never matches a binding.
        let start_epoch = process_start_epoch(pid, btime).unwrap_or(0.0);
        out.push(ProcMatch {
            pid,
            process_id,
            start_epoch,
        });
    }
    out
}

/// System boot time (unix epoch seconds) from the `btime` line of /proc/stat.
#[cfg(unix)]
fn system_btime() -> f64 {
    std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|stat| {
            stat.lines().find_map(|line| {
                line.strip_prefix("btime ")
                    .and_then(|rest| rest.trim().parse::<f64>().ok())
            })
        })
        .unwrap_or(0.0)
}

/// Start time of `pid` as unix epoch seconds: btime + starttime/HZ, where
/// starttime is field 22 of /proc/<pid>/stat.
#[cfg(unix)]
fn process_start_epoch(pid: u32, btime: f64) -> Option<f64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm (field 2) is parenthesized and may contain spaces/parens; fields
    // after it start past the last ')'.
    let after_comm = stat.rsplit_once(')')?.1;
    let starttime_ticks: f64 = after_comm.split_whitespace().nth(19)?.parse().ok()?;
    let hz = clock_ticks_per_sec();
    if hz <= 0.0 {
        return None;
    }
    Some(btime + starttime_ticks / hz)
}

#[cfg(unix)]
fn clock_ticks_per_sec() -> f64 {
    // _SC_CLK_TCK is 100 on every Linux we run; sysconf is authoritative.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 { 100.0 } else { ticks as f64 }
}
/// True when `pid` is gone for lifecycle purposes: no such process, or a
/// zombie (dead but unreaped — `kill(pid, 0)` still succeeds on it, so a
/// bare liveness check would block a release on an already-dead process
/// until its parent reaps it).
fn process_gone(pid: u32) -> bool {
    if !crate::sys::process::is_alive(pid) {
        return true;
    }
    #[cfg(unix)]
    {
        is_zombie(pid)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn is_zombie(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(')')
        .map(|(_, rest)| rest.trim_start().starts_with('Z'))
        .unwrap_or(false)
}
/// The calling process's own pid plus its /proc ppid-ancestor chain.
///
/// Exists so lifecycle signalling can exclude the caller's own session tree:
/// a CLI running inside the instance it operates on inherits the name but
/// must never be signalled for it. Ancestors are read from field 4 (ppid) of
/// `/proc/<pid>/stat` — the token after the closing `)` of comm, so a comm
/// containing spaces or parens cannot shift the parse — walking up until pid
/// 1 (bonded iteration cap guards against a corrupted chain).
///
/// Unix only; elsewhere this is just the caller's own pid.
pub fn caller_ancestor_pids() -> Vec<u32> {
    #[cfg(not(unix))]
    {
        return vec![std::process::id()];
    }
    #[cfg(unix)]
    {
        let mut out = vec![std::process::id()];
        let mut pid = std::process::id();
        while let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            let Some(end) = stat.rfind(')') else {
                break;
            };
            let mut fields = stat[end + 1..].split_whitespace();
            let _state = fields.next();
            let Some(ppid_str) = fields.next() else {
                break;
            };
            let Ok(ppid) = ppid_str.parse::<u32>() else {
                break;
            };
            if ppid == 0 || ppid == pid {
                break;
            }
            out.push(ppid);
            if ppid == 1 || out.len() > 1024 {
                break;
            }
            pid = ppid;
        }
        out
    }
}

/// Reap every live process holding the instance: carriers of
/// `HCOM_INSTANCE_NAME=<name>` plus carriers of any of the instance's
/// binding process ids (the self-bound tree never carries the name).
///
/// Oldest first (the pty wrapper predates its children), SIGTERM, wait up to
/// 5 s, SIGKILL survivors, verify. Verification is by carrier set, not by pid
/// snapshot: after each wait the tree is re-enumerated for carriers, so a
/// child forked between the first enumerate and SIGTERM is still signalled
/// (in the KILL round) and still blocks success while it lives; conversely a
/// snapshot pid recycled by an unrelated process no longer carries the name
/// and is neither signalled nor counted (an EPERM on such a pid is not
/// survival). Returns the surviving pids on failure — callers must not
/// report success or release the row while any survive.
///
/// The calling process is never signalled (see [`processes_for_instance`]).
/// Zombies are excluded from verification: a SIGKILLed carrier stays visible
/// in /proc (environ intact) until its parent reaps it, but it is gone for
/// lifecycle purposes (see [`process_gone`]) — blocking a release on it
/// would wedge every stop behind an unreaped child.
///
/// Unix only; elsewhere this is a no-op success.
pub fn reap_instance_tree_for(name: &str, binding_ids: &[String]) -> Result<(), Vec<u32>> {
    reap_instance_tree_for_excluding(name, binding_ids, &[])
}

/// [`reap_instance_tree_for`] with an exclusion set: carriers in `exclude`
/// are never signalled and never count as survivors, at any enumeration
/// round (initial, KILL re-enumeration, verification).
///
/// The kill self-path uses this with [`caller_ancestor_pids`]: the caller
/// runs inside the instance it is killing, so its own session tree must be
/// spared while every other carrier is still reaped and still blocks success
/// while it lives. An empty `exclude` is exactly [`reap_instance_tree_for`].
///
/// Unix only; elsewhere this is a no-op success.
pub fn reap_instance_tree_for_excluding(
    name: &str,
    binding_ids: &[String],
    exclude: &[u32],
) -> Result<(), Vec<u32>> {
    #[cfg(not(unix))]
    {
        let _ = name;
        let _ = binding_ids;
        let _ = exclude;
        Ok(())
    }
    #[cfg(unix)]
    {
        let mut matches = live_carriers_for(name, binding_ids, exclude);
        if matches.is_empty() {
            return Ok(());
        }
        // Oldest first: pty wrapper before children.
        matches.sort_by(|a, b| {
            a.start_epoch
                .partial_cmp(&b.start_epoch)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for m in &matches {
            // Pid-reuse guard: only signal a snapshot pid that still holds
            // the instance; a recycled pid belongs to someone else now.
            if pid_carries_instance(m.pid, name, binding_ids) {
                signal(m.pid, libc::SIGTERM);
            }
        }
        wait_for_exit_pids(
            &matches.iter().map(|m| m.pid).collect::<Vec<_>>(),
            TERM_WAIT,
        );
        // Re-enumerate by carrier set: newly seen carriers (forked after the
        // first snapshot, so never TERMED) join the KILL round directly —
        // the TERM round already elapsed, so escalation is immediate.
        let mut current = live_carriers_for(name, binding_ids, exclude);
        if current.is_empty() {
            return Ok(());
        }
        current.sort_by(|a, b| {
            a.start_epoch
                .partial_cmp(&b.start_epoch)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for m in &current {
            if pid_carries_instance(m.pid, name, binding_ids) {
                signal(m.pid, libc::SIGKILL);
            }
        }
        wait_for_exit_pids(
            &current.iter().map(|m| m.pid).collect::<Vec<_>>(),
            KILL_WAIT,
        );
        let still: Vec<u32> = live_carriers_for(name, binding_ids, exclude)
            .into_iter()
            .map(|m| m.pid)
            .collect();
        if still.is_empty() { Ok(()) } else { Err(still) }
    }
}

/// Shell pid behind a self-bound process id: `omp-<pid>-…` → `<pid>`.
/// Anything else (UUID bindings, empty, malformed) → None.
fn shell_pid_from_process_id(process_id: &str) -> Option<u32> {
    process_id
        .strip_prefix("omp-")
        .and_then(|rest| rest.split('-').next())
        .filter(|head| !head.is_empty())
        .and_then(|head| head.parse::<u32>().ok())
}

/// Live carriers for reap verification: carrier enumeration minus zombies
/// minus the exclusion set (the caller's own session tree in the kill
/// self-path — never signalled, never a survivor).
#[cfg(unix)]
fn live_carriers_for(name: &str, binding_ids: &[String], exclude: &[u32]) -> Vec<ProcMatch> {
    processes_for_instance(name, binding_ids)
        .into_iter()
        .filter(|m| !is_zombie(m.pid) && !exclude.contains(&m.pid))
        .collect()
}

/// Pid-reuse guard: true when `pid` still holds the instance — exactly
/// `HCOM_INSTANCE_NAME=<name>` or exactly `HCOM_PROCESS_ID=<id>` for one of
/// the binding ids — in its environ. No other environ values are read. An
/// unreadable environ (exited, or foreign-owned) reads as absent.
#[cfg(unix)]
fn pid_carries_instance(pid: u32, name: &str, binding_ids: &[String]) -> bool {
    let want = format!("HCOM_INSTANCE_NAME={name}");
    std::fs::read(format!("/proc/{pid}/environ")).is_ok_and(|env| {
        let (carries_name, process_id) = identity_facts(&env, want.as_bytes());
        carries_name || is_bound_process_id(&process_id, binding_ids)
    })
}

#[cfg(unix)]
fn signal(pid: u32, sig: libc::c_int) {
    unsafe {
        libc::kill(pid as libc::pid_t, sig);
    }
    // Best-effort: ESRCH (already gone) and EPERM (foreign) both just mean
    // this pid is not ours to reap; the name re-enumeration sorts it out —
    // a pid that no longer carries the name is never a survivor.
}

#[cfg(unix)]
fn wait_for_exit_pids(pids: &[u32], budget: std::time::Duration) {
    let steps = budget.as_millis() / POLL_STEP.as_millis().max(1);
    for _ in 0..steps {
        if pids.iter().all(|pid| process_gone(*pid)) {
            return;
        }
        std::thread::sleep(POLL_STEP);
    }
}

/// Refuse to spawn under `<name>` over a live holder or an orphan.
///
/// Carriers match by name OR by any of the instance's binding process ids,
/// so a live self-bound holder (process id only, no name in env) refuses
/// exactly like a live hcom-launched holder:
///
/// - Newest binding's own process_id still carried by a live process → live
///   holder, refuse.
/// - Any other process_id carrying the name, started before the newest
///   binding's `updated_at` minus grace → orphan, refuse.
/// - A same-name process with an old process_id started *after* the binding
///   (subagent shape: children inherit the parent's process id and outlive
///   the rebind) is not an orphan → proceed.
/// - Nothing alive → proceed (a DB-active row is the DB layer's business:
///   resume keeps its existing "still active" message for that case).
/// - No binding at all but live name carriers → live holders, refuse. (A
///   process carrying only an unknown process_id is unattributable without
///   bindings, so it never blocks — this keeps `start --as` recovery working
///   after a row plus its bindings were deleted.)
pub fn check_spawn_allowed(db: &HcomDb, name: &str) -> Result<(), SpawnRefusal> {
    let binding_ids = db.process_binding_ids(name).unwrap_or_default();
    let holders = processes_for_instance(name, &binding_ids);
    if holders.is_empty() {
        return Ok(());
    }
    let newest = db.newest_process_binding(name).unwrap_or(None);
    classify_holders(name, &holders, newest)
}

/// Pure spawn-gate decision over an enumerated carrier set: the part of
/// [`check_spawn_allowed`] that is testable without live processes.
fn classify_holders(
    name: &str,
    holders: &[ProcMatch],
    newest: Option<(String, f64)>,
) -> Result<(), SpawnRefusal> {
    match newest {
        None => Err(SpawnRefusal {
            name: name.to_string(),
            kind: HolderKind::LiveHolder,
            pids: holders.iter().map(|h| h.pid).collect(),
        }),
        Some((bound_process_id, updated_at)) => {
            let live: Vec<u32> = holders
                .iter()
                .filter(|h| !h.process_id.is_empty() && h.process_id == bound_process_id)
                .map(|h| h.pid)
                .collect();
            if !live.is_empty() {
                return Err(SpawnRefusal {
                    name: name.to_string(),
                    kind: HolderKind::LiveHolder,
                    pids: live,
                });
            }
            // An unstat-able carrier (unknown start) fails toward holder:
            // refuse, never read it as orphan-free. It may be a holder whose
            // stat raced its exit, or a fresh process we could not time.
            let unknown: Vec<u32> = holders
                .iter()
                .filter(|h| h.process_id != bound_process_id && h.start_epoch <= 0.0)
                .map(|h| h.pid)
                .collect();
            if !unknown.is_empty() {
                return Err(SpawnRefusal {
                    name: name.to_string(),
                    kind: HolderKind::LiveHolder,
                    pids: unknown,
                });
            }
            let orphans: Vec<u32> = holders
                .iter()
                .filter(|h| {
                    h.process_id != bound_process_id && is_orphan_carrier(h.start_epoch, updated_at)
                })
                .map(|h| h.pid)
                .collect();
            if orphans.is_empty() {
                Ok(())
            } else {
                Err(SpawnRefusal {
                    name: name.to_string(),
                    kind: HolderKind::Orphan,
                    pids: orphans,
                })
            }
        }
    }
}

/// True when a same-name carrier with a foreign process_id predates the newest
/// binding (minus grace): an orphan. An unknown start (`<= 0.0`, unstat-able)
/// is NEVER an orphan — callers fail that toward holder instead.
fn is_orphan_carrier(start_epoch: f64, binding_updated_at: f64) -> bool {
    start_epoch > 0.0 && start_epoch < binding_updated_at - ORPHAN_GRACE_SECS
}

/// Grace after `last_seen` during which the daemon sweep leaves a row alone.
/// Covers the wrapper-exit race: the wrapper deletes the row synchronously,
/// but a sweep tick landing mid-exit must not write `vanished` first.
const SWEEP_FRESH_GRACE_SECS: i64 = 60;

/// Daemon-side periodic check (runs on the relay worker's watchdog tick, so
/// in a different process — and typically a different cgroup — from any
/// session): for every active local instance, test whether its harness is
/// gone.
///
/// Fail-safe inversion: a row is vanished ONLY on positive evidence of death —
/// every attributable pid is dead AND no live carrier holds the instance. Any
/// doubt holds the row and logs why at debug:
///
/// - no attributable pid at all (empty recorded pid, no parseable shell pid
///   in the bindings) → HELD. This is the self-bound incident shape: the
///   snapshot pid is empty and the binding is `omp-<shell pid>-…`.
/// - any attributable pid alive (recorded snapshot pid, or the shell pid
///   parsed from a shell-shaped binding) → HELD.
/// - any live carrier by name (`HCOM_INSTANCE_NAME`) or by binding process id
///   (`HCOM_PROCESS_ID`) → HELD.
/// - an unparseable binding process id contributes no pid evidence and never
///   counts toward death → HELD unless other evidence proves death.
///
/// A vanished row gets `stopped by=daemon reason=vanished` with the instance
/// snapshot, then the row is released — the notice systemd-oomd kills
/// currently never produce.
///
/// Skips rows already released (they are simply not returned by the live
/// query, so a normal exit's wrapper-written `stopped` never double-fires),
/// remote mirrors, placeholders, inactive resume rows, and recently-seen rows.
/// Returns swept names.
pub fn sweep_vanished_instances(db: &HcomDb) -> Vec<String> {
    let instances = match db.iter_instances_full() {
        Ok(rows) => rows,
        Err(_) => return Vec::new(),
    };
    let now = crate::shared::time::now_epoch_f64() as i64;
    let mut swept = Vec::new();
    for inst in &instances {
        // An empty-string origin is local (same convention as start rebind
        // and stop display): only a non-empty device id marks a remote row.
        if inst
            .origin_device_id
            .as_deref()
            .is_some_and(|d| !d.is_empty())
        {
            continue;
        }
        if matches!(inst.status.as_str(), "stopped" | "dead") {
            continue;
        }
        if inst.status == crate::instance_names::PLACEHOLDER_STATUS {
            continue;
        }
        // Inactive rows are resume handles, not live sessions: soft-stop
        // (OMP --soft, agy Stop synthesis) deliberately keeps the row, its
        // pid, and its process bindings for a later `hcom r`. They live out
        // cleanup_stale_instances' retention tiers — the sweep must never
        // release them.
        if inst.status == crate::shared::ST_INACTIVE {
            continue;
        }
        if inst.last_seen > 0 && now - inst.last_seen < SWEEP_FRESH_GRACE_SECS {
            continue;
        }
        let newest = db.newest_process_binding(&inst.name).unwrap_or(None);
        let binding_ids = db.process_binding_ids(&inst.name).unwrap_or_default();
        // Positive-evidence pids: the recorded snapshot pid plus every shell
        // pid parsed from a shell-shaped binding. Unparseable bindings (UUID
        // harness ids, empty, malformed) contribute nothing — they are not
        // evidence of life OR death.
        let mut evidence_pids: Vec<u32> = inst
            .pid
            .filter(|pid| *pid > 0)
            .map(|pid| pid as u32)
            .into_iter()
            .collect();
        evidence_pids.extend(
            binding_ids
                .iter()
                .filter_map(|id| shell_pid_from_process_id(id)),
        );
        if evidence_pids.is_empty() {
            crate::log::log(
                "DEBUG",
                "daemon",
                "sweep.held",
                &format!("name={} reason=no-pid-evidence", inst.name),
            );
            continue;
        }
        if evidence_pids.iter().any(|pid| !process_gone(*pid)) {
            crate::log::log(
                "DEBUG",
                "daemon",
                "sweep.held",
                &format!("name={} reason=pid-alive", inst.name),
            );
            continue;
        }
        // Every attributable pid is dead. Still held while any live carrier
        // holds the instance by name or by binding process id. Zombies don't
        // count: a SIGKILLed carrier keeps its environ until its parent
        // reaps it, but it is gone for lifecycle purposes — same rule as
        // reap verification (live_carriers_for).
        if processes_for_instance(&inst.name, &binding_ids)
            .into_iter()
            .any(|m| !is_zombie(m.pid))
        {
            crate::log::log(
                "DEBUG",
                "daemon",
                "sweep.held",
                &format!("name={} reason=live-carrier", inst.name),
            );
            continue;
        }
        // Vanished: snapshot, stopped by=daemon, release.
        let snapshot = db.get_instance_snapshot(&inst.name).unwrap_or(None);
        let process_id = newest.as_ref().map(|(p, _)| p.as_str());
        let data = serde_json::json!({
            "action": "stopped",
            "by": "daemon",
            "reason": "vanished",
            "process_id": process_id,
            "snapshot": snapshot,
        });
        match db.finalize_instance_stop(
            &inst.name,
            inst.created_at,
            inst.session_id.as_deref(),
            inst.agent_id.as_deref(),
            &data,
            process_id,
        ) {
            Ok(true) => {
                crate::log::log_info(
                    "daemon",
                    "sweep.vanished",
                    &format!("name={} pid={:?}", inst.name, inst.pid),
                );
                swept.push(inst.name.clone());
            }
            Ok(false) => {
                // Lost a teardown race (someone else released or rebound it).
                // Row state is authoritative; leave it.
            }
            Err(e) => {
                crate::log::log_warn(
                    "daemon",
                    "sweep.vanished_failed",
                    &format!("name={} err={}", inst.name, e),
                );
            }
        }
    }
    swept
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: these tests spawn real `sleep` processes carrying fake instance
    // names. Names embed the test-runner pid so parallel tests (and any real
    // session on this host) can never collide with them.

    #[cfg(unix)]
    fn unique_name(tag: &str) -> String {
        format!(
            "hcom-proctruth-{}-{}-{}",
            std::process::id(),
            tag,
            rand_suffix()
        )
    }

    #[cfg(unix)]
    fn rand_suffix() -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut h);
        std::thread::current().id().hash(&mut h);
        (h.finish() % 900000) as u32 + 100000
    }

    #[cfg(unix)]
    fn spawn_named_sleeper(name: &str, process_id: &str) -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("300")
            .env("HCOM_INSTANCE_NAME", name)
            .env("HCOM_PROCESS_ID", process_id)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep")
    }

    #[cfg(unix)]
    fn wait_for_enumerated(name: &str, binding_ids: &[String], pid: u32) -> Vec<ProcMatch> {
        for _ in 0..50 {
            let found = processes_for_instance(name, binding_ids);
            if found.iter().any(|m| m.pid == pid) {
                return found;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        processes_for_instance(name, binding_ids)
    }

    #[test]
    #[cfg(unix)]
    fn enumerate_finds_named_sleeper_with_process_id() {
        let name = unique_name("enum");
        let mut child = spawn_named_sleeper(&name, "proc-enum-1");
        let pid = child.id();
        let found = wait_for_enumerated(&name, &[], pid);
        let hit = found
            .iter()
            .find(|m| m.pid == pid)
            .expect("sleeper enumerated");
        assert_eq!(hit.process_id, "proc-enum-1");
        assert!(
            hit.start_epoch > 1_700_000_000.0,
            "start_epoch sane: {}",
            hit.start_epoch
        );
        child.kill().ok();
        child.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn enumerate_ignores_different_name() {
        let name = unique_name("other");
        let mut child = spawn_named_sleeper("hcom-proctruth-unrelated", "proc-x");
        std::thread::sleep(std::time::Duration::from_millis(200));
        let found = processes_for_instance(&name, &[]);
        assert!(found.is_empty(), "unexpected matches: {found:?}");
        child.kill().ok();
        child.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn reap_kills_whole_tree_and_reports_survivors_shape() {
        let name = unique_name("reap");
        let mut a = spawn_named_sleeper(&name, "proc-reap");
        let mut b = spawn_named_sleeper(&name, "proc-reap");
        let (pa, pb) = (a.id(), b.id());
        wait_for_enumerated(&name, &[], pa);
        wait_for_enumerated(&name, &[], pb);
        assert!(reap_instance_tree_for(&name, &[]).is_ok());
        // Reap the (zombie) children so bare kill-0 liveness observes them.
        a.wait().ok();
        b.wait().ok();
        assert!(!crate::sys::process::is_alive(pa), "sleeper A reaped");
        assert!(!crate::sys::process::is_alive(pb), "sleeper B reaped");
    }

    #[test]
    #[cfg(unix)]
    fn reap_empty_name_is_noop_ok() {
        assert!(reap_instance_tree_for(&unique_name("empty"), &[]).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn caller_ancestors_start_at_self_and_end_at_init() {
        let chain = caller_ancestor_pids();
        assert!(!chain.is_empty(), "chain always holds at least self");
        assert_eq!(chain[0], std::process::id(), "chain starts at the caller");
        assert!(
            chain.iter().all(|p| *p > 0),
            "no null pids in chain: {chain:?}"
        );
        assert_eq!(*chain.last().unwrap(), 1, "chain walks to init: {chain:?}");
        if chain.len() > 1 {
            let parent = unsafe { libc::getppid() } as u32;
            assert_eq!(chain[1], parent, "second link is the real parent");
        }
    }

    #[test]
    #[cfg(unix)]
    fn reap_excluding_spares_excluded_carrier() {
        let name = unique_name("exclude");
        let mut spared = spawn_named_sleeper(&name, "proc-exclude-spared");
        let mut reaped = spawn_named_sleeper(&name, "proc-exclude-reaped");
        let (spared_pid, reaped_pid) = (spared.id(), reaped.id());
        wait_for_enumerated(&name, &[], spared_pid);
        wait_for_enumerated(&name, &[], reaped_pid);
        assert!(
            reap_instance_tree_for_excluding(&name, &[], std::slice::from_ref(&spared_pid)).is_ok(),
            "excluded carrier must not count as a survivor"
        );
        reaped.wait().ok();
        assert!(
            !crate::sys::process::is_alive(reaped_pid),
            "non-excluded carrier is reaped"
        );
        assert!(
            crate::sys::process::is_alive(spared_pid),
            "excluded carrier is never signalled"
        );
        spared.kill().ok();
        spared.wait().ok();
    }

    // -- Spawn-gate (B) and release/sweep (C) tests need a DB ---------------

    fn test_db() -> crate::db::HcomDb {
        let db = crate::db::HcomDb::open_raw(std::path::Path::new(":memory:")).unwrap();
        db.init_db().unwrap();
        db
    }

    fn insert_row(db: &crate::db::HcomDb, name: &str, status: &str, pid: Option<i64>) {
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) VALUES (?1, ?2, ?3, 'codex', ?4)",
                rusqlite::params![name, status, now, pid],
            )
            .unwrap();
    }

    #[cfg(unix)]
    fn backdate_binding(db: &crate::db::HcomDb, process_id: &str, updated_at: f64) {
        db.conn()
            .execute(
                "UPDATE process_bindings SET updated_at = ?1 WHERE process_id = ?2",
                rusqlite::params![updated_at, process_id],
            )
            .unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn spawn_refused_over_orphan_naming_pid() {
        let db = test_db();
        let name = unique_name("orphan");
        let mut sleeper = spawn_named_sleeper(&name, "proc-old");
        let pid = sleeper.id();
        wait_for_enumerated(&name, &[], pid);
        let start = processes_for_instance(&name, &[])
            .into_iter()
            .find(|m| m.pid == pid)
            .expect("sleeper enumerated")
            .start_epoch;
        // New harness bound AFTER the sleeper started: the sleeper predates it.
        db.set_process_binding("proc-new", "sess", &name).unwrap();
        backdate_binding(&db, "proc-new", start + 3600.0);
        let err = check_spawn_allowed(&db, &name).expect_err("orphan must refuse");
        assert_eq!(err.kind, HolderKind::Orphan);
        assert!(err.pids.contains(&pid), "refusal names the pid: {err}");
        assert!(err.to_string().contains(&format!("hcom kill {name}")));
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn spawn_proceeds_for_subagent_shape_started_after_binding() {
        let db = test_db();
        let name = unique_name("subagent");
        // Old process_id, but started AFTER the newest binding: a current
        // subtree child (subagents inherit the parent process id), not an
        // orphan.
        let mut sleeper = spawn_named_sleeper(&name, "proc-old");
        let pid = sleeper.id();
        wait_for_enumerated(&name, &[], pid);
        db.set_process_binding("proc-new", "sess", &name).unwrap();
        assert!(
            check_spawn_allowed(&db, &name).is_ok(),
            "post-binding same-name process must not block"
        );
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn spawn_refused_over_live_holder_of_newest_binding() {
        let db = test_db();
        let name = unique_name("holder");
        let mut sleeper = spawn_named_sleeper(&name, "proc-cur");
        let pid = sleeper.id();
        wait_for_enumerated(&name, &[], pid);
        db.set_process_binding("proc-cur", "sess", &name).unwrap();
        let err = check_spawn_allowed(&db, &name).expect_err("live holder must refuse");
        assert_eq!(err.kind, HolderKind::LiveHolder);
        assert!(err.pids.contains(&pid));
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn spawn_proceeds_with_nothing_alive() {
        let db = test_db();
        let name = unique_name("quiet");
        // DB-only row (binding, no processes): the DB-status message owns
        // this case; the process gate proceeds.
        db.set_process_binding("proc-gone", "sess", &name).unwrap();
        assert!(check_spawn_allowed(&db, &name).is_ok());
        assert!(check_spawn_allowed(&db, &unique_name("free")).is_ok());
    }

    #[test]
    fn finalize_rejects_stale_process_id_and_keeps_row() {
        let db = test_db();
        insert_row(&db, "stale-row", "active", None);
        let created = db
            .get_instance_full("stale-row")
            .unwrap()
            .expect("row")
            .created_at;
        db.set_process_binding("proc-current", "sess", "stale-row")
            .unwrap();
        let data = serde_json::json!({
            "action": "stopped", "by": "pty", "reason": "closed",
            "process_id": "proc-old", "snapshot": null,
        });
        let won = db
            .finalize_instance_stop("stale-row", created, None, None, &data, Some("proc-old"))
            .unwrap();
        assert!(!won, "stale process_id must not win the release");
        assert!(
            db.get_instance_full("stale-row").unwrap().is_some(),
            "row untouched by stale stopped"
        );
        let event: String = db
            .conn()
            .query_row(
                "SELECT data FROM events WHERE type='life' AND instance='stale-row' ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let event: serde_json::Value = serde_json::from_str(&event).unwrap();
        assert_eq!(
            event.get("action").and_then(|v| v.as_str()),
            Some("stopped")
        );
        assert_eq!(
            event.get("reason").and_then(|v| v.as_str()),
            Some("stale-harness-exit")
        );
    }

    #[test]
    fn finalize_releases_for_current_process_id() {
        let db = test_db();
        insert_row(&db, "cur-row", "active", None);
        let created = db
            .get_instance_full("cur-row")
            .unwrap()
            .expect("row")
            .created_at;
        db.set_process_binding("proc-current", "sess", "cur-row")
            .unwrap();
        let data = serde_json::json!({
            "action": "stopped", "by": "pty", "reason": "closed",
            "process_id": "proc-current", "snapshot": null,
        });
        let won = db
            .finalize_instance_stop("cur-row", created, None, None, &data, Some("proc-current"))
            .unwrap();
        assert!(won, "current process_id releases the row");
        assert!(db.get_instance_full("cur-row").unwrap().is_none());
    }

    #[cfg(unix)]
    fn dead_pid() -> i64 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid as i64
    }

    #[test]
    #[cfg(unix)]
    fn sweep_releases_vanished_row_with_daemon_stopped() {
        let db = test_db();
        insert_row(&db, "gone-row", "active", Some(dead_pid()));
        let swept = sweep_vanished_instances(&db);
        assert!(
            swept.contains(&"gone-row".to_string()),
            "vanished swept: {swept:?}"
        );
        assert!(db.get_instance_full("gone-row").unwrap().is_none());
        let event: String = db
            .conn()
            .query_row(
                "SELECT data FROM events WHERE type='life' AND instance='gone-row' ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let event: serde_json::Value = serde_json::from_str(&event).unwrap();
        assert_eq!(event.get("by").and_then(|v| v.as_str()), Some("daemon"));
        assert_eq!(
            event.get("reason").and_then(|v| v.as_str()),
            Some("vanished")
        );
    }

    #[test]
    #[cfg(unix)]
    fn sweep_leaves_live_pid_row_alone() {
        let db = test_db();
        insert_row(&db, "live-row", "active", Some(std::process::id() as i64));
        let swept = sweep_vanished_instances(&db);
        assert!(!swept.contains(&"live-row".to_string()));
        assert!(db.get_instance_full("live-row").unwrap().is_some());
    }

    #[test]
    #[cfg(unix)]
    fn sweep_leaves_name_held_row_alone() {
        let db = test_db();
        // Dead recorded pid, but a live process still carries the name
        // (binding-less): the harness is around in some form; not vanished.
        let name = unique_name("held");
        insert_row(&db, &name, "active", Some(dead_pid()));
        let mut sleeper = spawn_named_sleeper(&name, "proc-held");
        wait_for_enumerated(&name, &[], sleeper.id());
        let swept = sweep_vanished_instances(&db);
        assert!(!swept.iter().any(|n| n == &name));
        assert!(db.get_instance_full(&name).unwrap().is_some());
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn sweep_skips_inactive_resume_row() {
        let db = test_db();
        // Soft-stop resume handle: inactive, dead pid, kept binding. The
        // sweep must leave it for cleanup_stale_instances' retention tiers.
        let name = unique_name("inactive");
        insert_row(&db, &name, "inactive", Some(dead_pid()));
        db.set_process_binding("proc-kept", "sess", &name).unwrap();
        let swept = sweep_vanished_instances(&db);
        assert!(
            !swept.iter().any(|n| n == &name),
            "inactive swept: {swept:?}"
        );
        assert!(db.get_instance_full(&name).unwrap().is_some());
    }

    #[test]
    #[cfg(unix)]
    fn sweep_leaves_post_binding_different_id_carrier() {
        let db = test_db();
        // Dead recorded pid, but a live carrier with a different non-empty
        // process_id started AFTER the binding (subagent shape): a holder,
        // not a vanished harness.
        let name = unique_name("subholder");
        insert_row(&db, &name, "active", Some(dead_pid()));
        db.set_process_binding("proc-new", "sess", &name).unwrap();
        let mut sleeper = spawn_named_sleeper(&name, "proc-old");
        wait_for_enumerated(&name, &[], sleeper.id());
        let swept = sweep_vanished_instances(&db);
        assert!(
            !swept.iter().any(|n| n == &name),
            "held row swept: {swept:?}"
        );
        assert!(db.get_instance_full(&name).unwrap().is_some());
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn sweep_treats_empty_origin_as_local() {
        let db = test_db();
        // Some("") origin is local per the tree convention: a vanished row
        // carrying it is swept, not skipped as a remote mirror.
        insert_row(&db, "empty-origin-row", "active", Some(dead_pid()));
        db.conn()
            .execute(
                "UPDATE instances SET origin_device_id = '' WHERE name = 'empty-origin-row'",
                [],
            )
            .unwrap();
        let swept = sweep_vanished_instances(&db);
        assert!(
            swept.contains(&"empty-origin-row".to_string()),
            "local row not swept: {swept:?}"
        );
        assert!(db.get_instance_full("empty-origin-row").unwrap().is_none());
    }

    #[test]
    #[cfg(unix)]
    fn reap_kills_child_forked_after_enumerate() {
        let name = unique_name("latefork");
        let mut first = spawn_named_sleeper(&name, "proc-late");
        let first_pid = first.id();
        wait_for_enumerated(&name, &[], first_pid);
        // Fork a second carrier mid-reap: it lands after the first snapshot
        // (reap spends 5 s in TERM-wait) and must still be reaped — the old
        // pid-snapshot verification would have missed it and returned Ok
        // under a live holder.
        let late_name = name.clone();
        let late = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let mut child = spawn_named_sleeper(&late_name, "proc-late");
            let pid = child.id();
            // Wait until reap kills it (or time out and clean up ourselves so
            // the test can never hang).
            for _ in 0..150 {
                if !crate::sys::process::is_alive(pid) || is_zombie(pid) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            child.kill().ok();
            child.wait().ok();
            pid
        });
        assert!(
            reap_instance_tree_for(&name, &[]).is_ok(),
            "late-forked child must be reaped"
        );
        let late_pid = late.join().expect("late-fork thread");
        first.wait().ok();
        assert!(
            processes_for_instance(&name, &[])
                .iter()
                .all(|m| m.pid != late_pid),
            "late carrier {late_pid} still enumerated"
        );
    }

    #[test]
    fn unknown_start_never_reads_as_orphan() {
        // Unstat-able carrier: the predicate alone must not call it an orphan
        // (old code read start_epoch 0.0 as pre-binding).
        let now = crate::shared::time::now_epoch_f64();
        assert!(!is_orphan_carrier(0.0, now));
        assert!(!is_orphan_carrier(-1.0, now));
        assert!(is_orphan_carrier(now - 3600.0, now));
        assert!(!is_orphan_carrier(now, now));
    }

    #[test]
    fn classify_holders_refuses_unknown_start_as_holder() {
        // End-to-end decision: an unstat-able foreign-id carrier fails toward
        // holder (refuse to spawn), never toward orphan-free.
        let now = crate::shared::time::now_epoch_f64();
        let holders = vec![ProcMatch {
            pid: 424242,
            process_id: "proc-old".to_string(),
            start_epoch: 0.0,
        }];
        let err = classify_holders("unstatable", &holders, Some(("proc-new".to_string(), now)))
            .expect_err("unstat-able carrier must refuse");
        assert_eq!(err.kind, HolderKind::LiveHolder);
        assert!(err.pids.contains(&424242));
    }
    // -- Self-bound sessions (D-68/D-69): no HCOM_INSTANCE_NAME in env ----

    #[test]
    fn shell_pid_parses_omp_shape_only() {
        assert_eq!(shell_pid_from_process_id("omp-123-4-5"), Some(123));
        assert_eq!(shell_pid_from_process_id("omp-7"), Some(7));
        assert_eq!(
            shell_pid_from_process_id("550e8400-e29b-41d4-a716-446655440000"),
            None
        );
        assert_eq!(shell_pid_from_process_id(""), None);
        assert_eq!(shell_pid_from_process_id("omp-"), None);
        assert_eq!(shell_pid_from_process_id("omp-abc-1"), None);
        assert_eq!(shell_pid_from_process_id("omp--1"), None);
    }

    #[cfg(unix)]
    fn spawn_pid_only_sleeper(process_id: &str) -> std::process::Child {
        // Self-bound shape: carries HCOM_PROCESS_ID but never
        // HCOM_INSTANCE_NAME.
        std::process::Command::new("sleep")
            .arg("300")
            .env_remove("HCOM_INSTANCE_NAME")
            .env("HCOM_PROCESS_ID", process_id)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep")
    }

    #[test]
    #[cfg(unix)]
    fn sweep_keeps_self_bound_incident_shape() {
        // The incident shape: empty snapshot pid, shell-shaped binding whose
        // shell (here: the test runner itself, unquestionably alive) is up,
        // no env carriers at all. The old sweep deleted this row.
        let db = test_db();
        let name = unique_name("selfbound");
        insert_row(&db, &name, "active", None);
        let binding = format!("omp-{}-1-1", std::process::id());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        let swept = sweep_vanished_instances(&db);
        assert!(
            !swept.iter().any(|n| n == &name),
            "live self-bound row swept: {swept:?}"
        );
        assert!(db.get_instance_full(&name).unwrap().is_some());
    }

    #[test]
    #[cfg(unix)]
    fn sweep_releases_self_bound_when_shell_dead() {
        // Same shape, but the shell behind the binding is dead and no
        // carrier holds the instance: positive evidence of death → swept.
        let db = test_db();
        let name = unique_name("selfdead");
        insert_row(&db, &name, "active", None);
        let binding = format!("omp-{}-1-1", dead_pid());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        let swept = sweep_vanished_instances(&db);
        assert!(swept.contains(&name), "dead self-bound row kept: {swept:?}");
        assert!(db.get_instance_full(&name).unwrap().is_none());
    }

    #[test]
    #[cfg(unix)]
    fn sweep_keeps_uuid_binding_pid_only_carrier() {
        // UUID binding, dead recorded pid, one live process carrying ONLY
        // the binding process id (no name in env): held, not vanished.
        let db = test_db();
        let name = unique_name("pidonly");
        insert_row(&db, &name, "active", Some(dead_pid()));
        let binding = format!("proc-pidonly-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        let mut sleeper = spawn_pid_only_sleeper(&binding);
        let pid = sleeper.id();
        wait_for_enumerated(&name, std::slice::from_ref(&binding), pid);
        let swept = sweep_vanished_instances(&db);
        assert!(
            !swept.iter().any(|n| n == &name),
            "pid-held row swept: {swept:?}"
        );
        assert!(db.get_instance_full(&name).unwrap().is_some());
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn spawn_refuses_pid_only_carrier_of_newest_binding() {
        // Spawn gate: a live process carrying HCOM_PROCESS_ID=<newest
        // binding> but no name is a live holder → refusal naming the pid.
        let db = test_db();
        let name = unique_name("gatepid");
        let binding = format!("proc-gate-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        let mut sleeper = spawn_pid_only_sleeper(&binding);
        let pid = sleeper.id();
        wait_for_enumerated(&name, &[binding], pid);
        let err = check_spawn_allowed(&db, &name).expect_err("pid-only holder must refuse");
        assert_eq!(err.kind, HolderKind::LiveHolder);
        assert!(err.pids.contains(&pid), "refusal names the pid: {err}");
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn reap_kills_pid_only_carrier_by_binding() {
        // Reap: a sleeper carrying only HCOM_PROCESS_ID=<binding> is the
        // self-bound tree and must die with the instance.
        let name = unique_name("reappid");
        let binding = format!("proc-reap-{}", rand_suffix());
        let mut sleeper = spawn_pid_only_sleeper(&binding);
        let pid = sleeper.id();
        wait_for_enumerated(&name, std::slice::from_ref(&binding), pid);
        assert!(reap_instance_tree_for(&name, &[binding]).is_ok());
        sleeper.wait().ok();
        assert!(
            !crate::sys::process::is_alive(pid),
            "pid-only sleeper reaped"
        );
    }

    #[test]
    #[cfg(unix)]
    fn sweep_releases_row_whose_only_carrier_is_zombie() {
        // Dead recorded pid, dead binding shell, one carrier that is a
        // zombie (SIGKILLed, parent not yet reaped): gone for lifecycle
        // purposes, so the row is vanished — same rule as reap
        // verification, which also ignores zombies.
        let db = test_db();
        let name = unique_name("zombie");
        insert_row(&db, &name, "active", Some(dead_pid()));
        let binding = format!("proc-zombie-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        let mut sleeper = spawn_named_sleeper(&name, &binding);
        let pid = sleeper.id();
        wait_for_enumerated(&name, &[], pid);
        sleeper.kill().ok();
        for _ in 0..50 {
            if is_zombie(pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(is_zombie(pid), "sleeper never reached zombie state");
        let swept = sweep_vanished_instances(&db);
        assert!(swept.contains(&name), "zombie-held row kept: {swept:?}");
        assert!(db.get_instance_full(&name).unwrap().is_none());
        sleeper.wait().ok();
    }
}
