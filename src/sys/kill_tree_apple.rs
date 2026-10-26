//! Terminate one verified macOS owner and its descendants, never its process group.
//!
//! Parent PIDs alone aren't ownership: a child older than its reported parent
//! belongs to an earlier incarnation of that PID. Plan the complete tree before
//! sending anything, and recheck each process's creation time before its signal.

use std::collections::HashSet;

#[cfg(target_os = "macos")]
use super::process::{GroupSignal, process_info_apple};

type StartTime = (u64, u64);

const MAX_SNAPSHOT_PROCESSES: usize = 65_536;
const MAX_TREE_PROCESSES: usize = 4_096;
const MAX_TREE_DEPTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcFact {
    pid: u32,
    ppid: u32,
    // Seconds and microseconds, without floating-point rounding or overflow.
    start_time: StartTime,
}

#[derive(Debug)]
struct Target<'a> {
    fact: &'a ProcFact,
    depth: usize,
}

/// Authenticate the root and every parent edge before returning a deepest-first
/// plan. Missing facts never authenticate a path through an unreadable process.
fn kill_tree(
    snapshot: &[ProcFact],
    root: u32,
    expected_start: StartTime,
) -> Result<Vec<Target<'_>>, &'static str> {
    if root <= 1 {
        return Err("refusing to terminate a reserved process ID");
    }
    if snapshot.len() > MAX_SNAPSHOT_PROCESSES {
        return Err("process snapshot exceeds the safety limit");
    }

    let mut seen = HashSet::with_capacity(snapshot.len());
    let mut by_parent = Vec::with_capacity(snapshot.len());
    let mut root_fact = None;
    for fact in snapshot {
        if !seen.insert(fact.pid) {
            return Err("process snapshot contains a duplicate PID");
        }
        if fact.pid == root {
            root_fact = Some(fact);
        }
        by_parent.push(fact);
    }
    let root_fact = root_fact.ok_or("verified owner is missing from the process snapshot")?;
    if root_fact.start_time != expected_start {
        return Err("owner identity changed before the process snapshot");
    }
    by_parent.sort_unstable_by_key(|fact| (fact.ppid, fact.pid));

    // Reuse the duplicate-check allocation for cycle detection. An explicit
    // stack bounds traversal independently of the Rust thread's stack size.
    seen.clear();
    let mut pending = vec![Target {
        fact: root_fact,
        depth: 0,
    }];
    let mut targets = Vec::new();
    while let Some(target) = pending.pop() {
        if !seen.insert(target.fact.pid) {
            return Err("cycle in the verified owner's process tree");
        }
        let first_child = by_parent.partition_point(|fact| fact.ppid < target.fact.pid);
        for child in by_parent[first_child..]
            .iter()
            .take_while(|fact| fact.ppid == target.fact.pid)
        {
            if child.pid <= 1 || child.start_time < target.fact.start_time {
                continue;
            }
            let depth = target.depth + 1;
            if depth > MAX_TREE_DEPTH {
                return Err("verified owner's process tree exceeds the depth limit");
            }
            if targets.len() + pending.len() + 1 >= MAX_TREE_PROCESSES {
                return Err("verified owner's process tree exceeds the size limit");
            }
            pending.push(Target { fact: child, depth });
        }
        targets.push(target);
    }
    targets.sort_unstable_by(|left, right| {
        right
            .depth
            .cmp(&left.depth)
            .then_with(|| left.fact.pid.cmp(&right.fact.pid))
    });
    Ok(targets)
}

/// `expected` is the native `apple:seconds:microseconds` ownership identity.
/// The outcome describes the owner's signal, as with the other GroupSignal
/// primitives; inaccessible or exited descendants don't authorize other PIDs.
#[cfg(target_os = "macos")]
pub(crate) fn terminate(root: u32, expected: &str) -> Result<GroupSignal, &'static str> {
    let (seconds, micros) = expected
        .strip_prefix("apple:")
        .and_then(|identity| identity.split_once(':'))
        .ok_or("recorded Apple process creation time is unreadable")?;
    let expected_start = (
        seconds
            .parse::<u64>()
            .map_err(|_| "recorded Apple process creation time is unreadable")?,
        micros
            .parse::<u64>()
            .ok()
            .filter(|micros| *micros < 1_000_000)
            .ok_or("recorded Apple process creation time is unreadable")?,
    );
    let snapshot = snapshot()?;
    let targets = kill_tree(&snapshot, root, expected_start)?;

    // This gate runs before *any* signal, not just before the root's (last)
    // signal. A reused or unreadable owner invalidates the entire plan.
    if process_fact(root).map(|fact| fact.start_time) != Some(expected_start) {
        return Err("owner identity changed or became unreadable before tree termination");
    }
    for target in targets {
        let pid = target.fact.pid;
        if process_fact(pid).map(|fact| fact.start_time) != Some(target.fact.start_time) {
            if pid == root {
                // Earlier descendants may already have received SIGTERM, but
                // never signal a new incarnation of the owner itself.
                return Err("owner identity changed or became unreadable during tree termination");
            }
            continue;
        }
        // process_fact rejects reserved and unrepresentable PIDs, so this is
        // always one positive PID, never kill(0), kill(-1), or a group signal.
        // SAFETY: kill receives a checked process ID and a valid signal.
        let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if pid == root {
            return Ok(if result == 0 {
                GroupSignal::Sent
            } else {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::ESRCH) => GroupSignal::NotFound,
                    Some(libc::EPERM) => GroupSignal::PermissionDenied,
                    _ => GroupSignal::Other,
                }
            });
        }
    }
    Err("verified owner is missing from the termination plan")
}

#[cfg(target_os = "macos")]
fn process_fact(pid: u32) -> Option<ProcFact> {
    if pid <= 1 || pid > libc::pid_t::MAX as u32 {
        return None;
    }
    let info = process_info_apple(pid)?;
    if info.pbi_pid != pid || info.pbi_start_tvusec >= 1_000_000 {
        return None;
    }
    Some(ProcFact {
        pid,
        ppid: info.pbi_ppid,
        start_time: (info.pbi_start_tvsec, info.pbi_start_tvusec),
    })
}

#[cfg(target_os = "macos")]
fn snapshot() -> Result<Vec<ProcFact>, &'static str> {
    // SAFETY: a null buffer with zero size requests only the process count.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 || count as usize > MAX_SNAPSHOT_PROCESSES {
        return Err("could not size a bounded Apple process snapshot");
    }
    let capacity = (count as usize + 64).min(MAX_SNAPSHOT_PROCESSES);
    let mut pids: Vec<libc::pid_t> = vec![0; capacity];
    // The process table can grow between calls. A full buffer is ambiguous:
    // retry with more space, and fail closed rather than use a truncated tree.
    for attempt in 0..4 {
        let bytes = (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
        // SAFETY: pids has exactly `bytes` writable, aligned storage.
        let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if count <= 0 {
            return Err("could not read the Apple process snapshot");
        }
        if (count as usize) < pids.len() {
            let mut facts = Vec::with_capacity(count as usize);
            for &pid in &pids[..count as usize] {
                if pid > 1
                    && let Some(fact) = process_fact(pid as u32)
                {
                    facts.push(fact);
                }
            }
            return Ok(facts);
        }
        if pids.len() == MAX_SNAPSHOT_PROCESSES {
            return Err("Apple process snapshot exceeds the safety limit");
        }
        if attempt == 3 {
            break;
        }
        pids.resize((pids.len() * 2).min(MAX_SNAPSHOT_PROCESSES), 0);
    }
    Err("Apple process snapshot kept growing during enumeration")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(pid: u32, ppid: u32, micros: u64) -> ProcFact {
        ProcFact {
            pid,
            ppid,
            start_time: (100, micros),
        }
    }

    fn planned_pids(snapshot: &[ProcFact], root: ProcFact) -> Vec<u32> {
        kill_tree(snapshot, root.pid, root.start_time)
            .unwrap()
            .iter()
            .map(|target| target.fact.pid)
            .collect()
    }

    #[test]
    fn kill_tree_orders_a_simple_chain_children_first() {
        let root = fact(10, 5, 1);
        let snapshot = [root, fact(11, 10, 2), fact(12, 11, 3), fact(13, 12, 4)];
        assert_eq!(planned_pids(&snapshot, root), [13, 12, 11, 10]);
    }

    #[test]
    fn kill_tree_orders_all_branches_by_depth() {
        let root = fact(10, 5, 1);
        let snapshot = [
            fact(12, 10, 3),
            fact(14, 12, 5),
            root,
            fact(15, 13, 6),
            fact(11, 10, 2),
            fact(13, 11, 4),
        ];
        assert_eq!(planned_pids(&snapshot, root), [15, 13, 14, 11, 12, 10]);
    }

    #[test]
    fn kill_tree_excludes_reused_parent_links_and_their_subtrees() {
        let root = fact(10, 5, 10);
        let snapshot = [
            root,
            fact(11, 10, 9),
            fact(12, 11, 11),
            fact(13, 10, 10),
            fact(14, 99, 20),
            fact(15, 14, 21),
        ];
        // Equal timestamps are possible at the native clock's resolution.
        // Missing ancestry (PID 99) is no more authoritative than a stale link.
        assert_eq!(planned_pids(&snapshot, root), [13, 10]);
    }

    #[test]
    fn kill_tree_compares_full_second_and_microsecond_timestamps() {
        let root = ProcFact {
            start_time: (100, 999_999),
            ..fact(10, 5, 0)
        };
        let snapshot = [
            root,
            ProcFact {
                start_time: (101, 0),
                ..fact(11, 10, 0)
            },
            ProcFact {
                start_time: (100, 999_998),
                ..fact(12, 10, 0)
            },
        ];
        assert_eq!(planned_pids(&snapshot, root), [11, 10]);
    }

    #[test]
    fn kill_tree_excludes_ancestors_siblings_and_reserved_pids() {
        let root = fact(10, 5, 10);
        let snapshot = [
            root,
            fact(5, 2, 5),
            fact(2, 1, 2),
            fact(11, 5, 11),
            fact(12, 10, 12),
            fact(0, 10, 20),
            fact(1, 10, 20),
        ];
        assert_eq!(planned_pids(&snapshot, root), [12, 10]);
    }

    #[test]
    fn kill_tree_rejects_a_cycle_without_a_partial_plan() {
        let root = fact(10, 12, 10);
        let snapshot = [root, fact(11, 10, 10), fact(12, 11, 10)];
        assert_eq!(
            kill_tree(&snapshot, root.pid, root.start_time).unwrap_err(),
            "cycle in the verified owner's process tree"
        );
        let self_parent = fact(10, 10, 10);
        assert!(kill_tree(&[self_parent], 10, self_parent.start_time).is_err());
    }

    #[test]
    fn kill_tree_enforces_the_depth_boundary() {
        let root = fact(10, 5, 0);
        let mut snapshot = vec![root];
        for depth in 1..=MAX_TREE_DEPTH {
            snapshot.push(fact(10 + depth as u32, 9 + depth as u32, depth as u64));
        }
        let plan = kill_tree(&snapshot, root.pid, root.start_time).unwrap();
        assert_eq!(plan.first().unwrap().depth, MAX_TREE_DEPTH);
        assert_eq!(plan.last().unwrap().fact, &root);

        let depth = MAX_TREE_DEPTH + 1;
        snapshot.push(fact(10 + depth as u32, 9 + depth as u32, depth as u64));
        assert_eq!(
            kill_tree(&snapshot, root.pid, root.start_time).unwrap_err(),
            "verified owner's process tree exceeds the depth limit"
        );
    }

    #[test]
    fn kill_tree_enforces_the_size_boundary() {
        let root = fact(10, 5, 0);
        let mut snapshot = vec![root];
        for index in 1..MAX_TREE_PROCESSES {
            snapshot.push(fact(10 + index as u32, 10, index as u64));
        }
        let plan = kill_tree(&snapshot, root.pid, root.start_time).unwrap();
        assert_eq!(plan.len(), MAX_TREE_PROCESSES);
        assert_eq!(plan.last().unwrap().fact, &root);

        snapshot.push(fact(10 + MAX_TREE_PROCESSES as u32, 10, 9_000));
        assert_eq!(
            kill_tree(&snapshot, root.pid, root.start_time).unwrap_err(),
            "verified owner's process tree exceeds the size limit"
        );
    }

    #[test]
    fn kill_tree_keeps_a_lone_root() {
        let root = fact(10, 5, 1);
        assert_eq!(planned_pids(&[root], root), [10]);
    }

    #[test]
    fn kill_tree_requires_the_expected_root_incarnation() {
        let root = fact(10, 5, 10);
        assert_eq!(
            kill_tree(&[root], 10, (100, 9)).unwrap_err(),
            "owner identity changed before the process snapshot"
        );
        assert_eq!(
            kill_tree(&[root], 11, root.start_time).unwrap_err(),
            "verified owner is missing from the process snapshot"
        );
        for reserved in [0, 1] {
            assert_eq!(
                kill_tree(&[fact(reserved, 0, 10)], reserved, root.start_time).unwrap_err(),
                "refusing to terminate a reserved process ID"
            );
        }
    }

    #[test]
    fn kill_tree_rejects_duplicate_snapshot_pids() {
        let root = fact(10, 5, 10);
        assert_eq!(
            kill_tree(&[root, fact(10, 11, 10)], 10, root.start_time).unwrap_err(),
            "process snapshot contains a duplicate PID"
        );
    }

    #[test]
    fn kill_tree_bounds_the_snapshot_before_walking_it() {
        let root = fact(10, 5, 10);
        let snapshot = vec![root; MAX_SNAPSHOT_PROCESSES + 1];
        assert_eq!(
            kill_tree(&snapshot, root.pid, root.start_time).unwrap_err(),
            "process snapshot exceeds the safety limit"
        );
    }
}
