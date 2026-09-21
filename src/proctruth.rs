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
//! - [`processes_with_instance_name`]: enumerate live processes carrying
//!   `HCOM_INSTANCE_NAME=<name>` (exact entry match; only that variable's
//!   value is ever read — other environ values are never printed).
//! - [`reap_instance_tree`]: SIGTERM the whole set (oldest first, so the pty
//!   wrapper goes before its children), wait up to 5 s, SIGKILL survivors.
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

/// Enumerate live processes whose environ contains exactly
/// `HCOM_INSTANCE_NAME=<name>` as one NUL-delimited entry.
///
/// Only the `HCOM_INSTANCE_NAME` and `HCOM_PROCESS_ID` entries are ever
/// inspected; no other environ values are read or reported. The calling
/// process itself is always excluded (a CLI running inside the session
/// inherits the name but never owns it).
pub fn processes_with_instance_name(name: &str) -> Vec<ProcMatch> {
    #[cfg(unix)]
    {
        enumerate_unix(name)
    }
    #[cfg(not(unix))]
    {
        let _ = name;
        Vec::new()
    }
}

#[cfg(unix)]
fn enumerate_unix(name: &str) -> Vec<ProcMatch> {
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
        let Ok(env) = std::fs::read(format!("/proc/{pid}/environ")) else {
            continue;
        };
        let mut carries_name = false;
        let mut process_id = String::new();
        for var in env.split(|b| *b == 0) {
            if var == want.as_bytes() {
                carries_name = true;
            } else if let Some(rest) = var.strip_prefix(b"HCOM_PROCESS_ID=") {
                // Only this variable's value is ever decoded; everything
                // else in the environ block stays unread bytes.
                process_id = String::from_utf8_lossy(rest).into_owned();
            }
            if carries_name && !process_id.is_empty() {
                // Both facts known; remaining entries cannot change them.
                // (A second HCOM_PROCESS_ID entry would be pathological;
                // first wins.)
                break;
            }
        }
        if !carries_name {
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
/// Reap every live process carrying `HCOM_INSTANCE_NAME=<name>`.
///
/// Oldest first (the pty wrapper predates its children), SIGTERM, wait up to
/// 5 s, SIGKILL survivors, verify. Returns the surviving pids on failure —
/// callers must not report success or release the row while any survive.
/// The calling process is never signalled (see [`processes_with_instance_name`]).
///
/// Unix only; elsewhere this is a no-op success.
pub fn reap_instance_tree(name: &str) -> Result<(), Vec<u32>> {
    #[cfg(not(unix))]
    {
        let _ = name;
        return Ok(());
    }
    #[cfg(unix)]
    {
        let mut matches = processes_with_instance_name(name);
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
            signal(m.pid, libc::SIGTERM);
        }
        wait_for_exit(&matches, TERM_WAIT);
        let survivors: Vec<u32> = matches
            .iter()
            .map(|m| m.pid)
            .filter(|pid| !process_gone(*pid))
            .collect();
        if survivors.is_empty() {
            return Ok(());
        }
        for pid in &survivors {
            signal(*pid, libc::SIGKILL);
        }
        wait_for_exit_pids(&survivors, KILL_WAIT);
        let still: Vec<u32> = survivors
            .into_iter()
            .filter(|pid| !process_gone(*pid))
            .collect();
        if still.is_empty() { Ok(()) } else { Err(still) }
    }
}

#[cfg(unix)]
fn signal(pid: u32, sig: libc::c_int) {
    unsafe {
        libc::kill(pid as libc::pid_t, sig);
    }
    // Best-effort: ESRCH (already gone) and EPERM (foreign) both just mean
    // this pid is not ours to reap; the survivor check sorts it out.
}

#[cfg(unix)]
fn wait_for_exit(matches: &[ProcMatch], budget: std::time::Duration) {
    wait_for_exit_pids(&matches.iter().map(|m| m.pid).collect::<Vec<_>>(), budget);
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
/// - Newest binding's own process_id still carried by a live process → live
///   holder, refuse.
/// - Any other process_id carrying the name, started before the newest
///   binding's `updated_at` minus grace → orphan, refuse.
/// - A same-name process with an old process_id started *after* the binding
///   (subagent shape: children inherit the parent's process id and outlive
///   the rebind) is not an orphan → proceed.
/// - Nothing alive → proceed (a DB-active row is the DB layer's business:
///   resume keeps its existing "still active" message for that case).
/// - No binding at all but live carriers → live holders, refuse.
pub fn check_spawn_allowed(db: &HcomDb, name: &str) -> Result<(), SpawnRefusal> {
    let holders = processes_with_instance_name(name);
    if holders.is_empty() {
        return Ok(());
    }
    let newest = db.newest_process_binding(name).unwrap_or(None);
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
            let orphans: Vec<u32> = holders
                .iter()
                .filter(|h| {
                    h.process_id != bound_process_id
                        && h.start_epoch < updated_at - ORPHAN_GRACE_SECS
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

/// Grace after `last_seen` during which the daemon sweep leaves a row alone.
/// Covers the wrapper-exit race: the wrapper deletes the row synchronously,
/// but a sweep tick landing mid-exit must not write `vanished` first.
const SWEEP_FRESH_GRACE_SECS: i64 = 60;

/// Daemon-side periodic check (runs on the relay worker's watchdog tick, so
/// in a different process — and typically a different cgroup — from any
/// session): for every active local instance, test whether its harness is
/// gone.
///
/// Vanished = recorded pid dead (or absent) AND no live process carries
/// `name` (+ newest process_id when a binding exists). A vanished row gets
/// `stopped by=daemon reason=vanished` with the instance snapshot, then the
/// row is released — the notice systemd-oomd kills currently never produce.
///
/// Skips rows already released (they are simply not returned by the live
/// query, so a normal exit's wrapper-written `stopped` never double-fires),
/// remote mirrors, placeholders, and recently-seen rows. Returns swept names.
pub fn sweep_vanished_instances(db: &HcomDb) -> Vec<String> {
    let instances = match db.iter_instances_full() {
        Ok(rows) => rows,
        Err(_) => return Vec::new(),
    };
    let now = crate::shared::time::now_epoch_f64() as i64;
    let mut swept = Vec::new();
    for inst in &instances {
        if inst.origin_device_id.is_some() {
            continue;
        }
        if matches!(inst.status.as_str(), "stopped" | "dead") {
            continue;
        }
        if inst.status == crate::instance_names::PLACEHOLDER_STATUS {
            continue;
        }
        if inst.last_seen > 0 && now - inst.last_seen < SWEEP_FRESH_GRACE_SECS {
            continue;
        }
        let newest = db.newest_process_binding(&inst.name).unwrap_or(None);
        if inst.pid.is_none() && newest.is_none() {
            // Nothing to judge liveness by — neither a recorded pid nor a
            // binding. Leave the row; deleting blind risks reservation rows.
            continue;
        }
        let pid_alive = inst
            .pid
            .is_some_and(|pid| pid > 0 && !process_gone(pid as u32));
        if pid_alive {
            continue;
        }
        let holders = processes_with_instance_name(&inst.name);
        let held = match &newest {
            Some((bound_process_id, _)) => holders
                .iter()
                .any(|h| h.process_id == *bound_process_id || h.process_id.is_empty()),
            None => !holders.is_empty(),
        };
        if held {
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

    fn unique_name(tag: &str) -> String {
        format!("hcom-proctruth-{}-{}-{}", std::process::id(), tag, rand_suffix())
    }

    fn rand_suffix() -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        std::time::SystemTime::now()
            .hash(&mut h);
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
    fn wait_for_enumerated(name: &str, pid: u32) -> Vec<ProcMatch> {
        for _ in 0..50 {
            let found = processes_with_instance_name(name);
            if found.iter().any(|m| m.pid == pid) {
                return found;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        processes_with_instance_name(name)
    }

    #[test]
    #[cfg(unix)]
    fn enumerate_finds_named_sleeper_with_process_id() {
        let name = unique_name("enum");
        let mut child = spawn_named_sleeper(&name, "proc-enum-1");
        let pid = child.id();
        let found = wait_for_enumerated(&name, pid);
        let hit = found.iter().find(|m| m.pid == pid).expect("sleeper enumerated");
        assert_eq!(hit.process_id, "proc-enum-1");
        assert!(hit.start_epoch > 1_700_000_000.0, "start_epoch sane: {}", hit.start_epoch);
        child.kill().ok();
        child.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn enumerate_ignores_different_name() {
        let name = unique_name("other");
        let mut child = spawn_named_sleeper("hcom-proctruth-unrelated", "proc-x");
        std::thread::sleep(std::time::Duration::from_millis(200));
        let found = processes_with_instance_name(&name);
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
        wait_for_enumerated(&name, pa);
        wait_for_enumerated(&name, pb);
        assert!(reap_instance_tree(&name).is_ok());
        // Reap the (zombie) children so bare kill-0 liveness observes them.
        a.wait().ok();
        b.wait().ok();
        assert!(!crate::sys::process::is_alive(pa), "sleeper A reaped");
        assert!(!crate::sys::process::is_alive(pb), "sleeper B reaped");
    }

    #[test]
    #[cfg(unix)]
    fn reap_empty_name_is_noop_ok() {
        assert!(reap_instance_tree(&unique_name("empty")).is_ok());
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
        wait_for_enumerated(&name, pid);
        let start = processes_with_instance_name(&name)
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
        wait_for_enumerated(&name, pid);
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
        wait_for_enumerated(&name, pid);
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
        assert_eq!(event.get("action").and_then(|v| v.as_str()), Some("stopped"));
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
        assert!(swept.contains(&"gone-row".to_string()), "vanished swept: {swept:?}");
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
        assert_eq!(event.get("reason").and_then(|v| v.as_str()), Some("vanished"));
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
        wait_for_enumerated(&name, sleeper.id());
        let swept = sweep_vanished_instances(&db);
        assert!(!swept.iter().any(|n| n == &name));
        assert!(db.get_instance_full(&name).unwrap().is_some());
        sleeper.kill().ok();
        sleeper.wait().ok();
    }
}
