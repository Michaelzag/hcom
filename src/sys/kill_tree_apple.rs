//! Terminate a verified macOS seat root and confirm its captured processes exit.
//!
//! A verified group leader owns its group; other roots authorize only their
//! creation-time-verified descendants. Capture before signaling, reject reused
//! parent links, and never escalate against a different PID incarnation.

use std::collections::{HashMap, HashSet};

#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use super::{
    kill_group,
    process::{GroupSignal, KILL_WAIT, POLL_STEP, TERM_WAIT, is_definitely_dead, process_info_apple},
};

type StartTime = (u64, u64);

const MAX_SNAPSHOT_PROCESSES: usize = 65_536;
const MAX_TREE_PROCESSES: usize = 4_096;
const MAX_TREE_DEPTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcFact {
    pid: u32,
    ppid: u32,
    pgid: u32,
    // Seconds and microseconds, without floating-point rounding or overflow.
    start_time: StartTime,
}

#[derive(Debug)]
struct Target<'a> {
    fact: &'a ProcFact,
    depth: usize,
    in_group: bool,
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
        in_group: false,
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
            pending.push(Target {
                fact: child,
                depth,
                in_group: false,
            });
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

/// Add every authenticated live group member when the root owns that group.
/// Group members need not remain descendants: shells can reparent them, and
/// descendants can leave the group. Neither observation invalidates capture.
fn capture_members<'a>(
    snapshot: &'a [ProcFact],
    root: u32,
    expected_start: StartTime,
    root_group: u32,
    group_members: &'a [ProcFact],
) -> Result<Vec<Target<'a>>, &'static str> {
    let mut targets = kill_tree(snapshot, root, expected_start)?;
    if targets.last().is_none_or(|target| target.fact.pgid != root_group) {
        return Err("owner process group changed during capture");
    }
    if root_group != root {
        // A member of the user's shell group doesn't own its parent/siblings.
        return Ok(targets);
    }
    if group_members.len() > MAX_SNAPSHOT_PROCESSES {
        return Err("process group snapshot exceeds the safety limit");
    }
    let mut by_pid = HashMap::with_capacity(targets.len());
    for (index, target) in targets.iter_mut().enumerate() {
        target.in_group = target.fact.pgid == root;
        by_pid.insert(target.fact.pid, index);
    }
    for member in group_members {
        if member.pid <= 1 {
            continue;
        }
        if member.pgid != root {
            return Err("captured group member changed process groups");
        }
        if let Some(&index) = by_pid.get(&member.pid) {
            let target = &mut targets[index];
            if target.fact.start_time != member.start_time {
                return Err("captured PID identity changed between process snapshots");
            }
            target.fact = member;
            target.in_group = true;
            continue;
        }
        if targets.len() == MAX_TREE_PROCESSES {
            return Err("captured process set exceeds the size limit");
        }
        by_pid.insert(member.pid, targets.len());
        targets.push(Target {
            fact: member,
            depth: 1,
            in_group: true,
        });
    }
    targets.sort_unstable_by(|left, right| {
        right
            .depth
            .cmp(&left.depth)
            .then_with(|| left.fact.pid.cmp(&right.fact.pid))
    });
    Ok(targets)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observation {
    Gone,
    Present(StartTime),
    Unknown,
}

/// Query failures are survivors, not evidence of exit. A different creation
/// time proves the captured incarnation has gone without authorizing its PID.
fn survivors(
    captured: &[Target<'_>],
    mut observe: impl FnMut(u32) -> Observation,
) -> Vec<u32> {
    let mut pids = Vec::new();
    for target in captured {
        match observe(target.fact.pid) {
            Observation::Gone => {}
            Observation::Present(start) if start != target.fact.start_time => {}
            Observation::Present(_) | Observation::Unknown => pids.push(target.fact.pid),
        }
    }
    pids.sort_unstable();
    pids
}

/// `expected` is the native `apple:seconds:microseconds` seat-root identity.
/// Return success only after every captured incarnation has exited or its PID
/// has been reused. Unknown state remains a survivor through both deadlines.
#[cfg(target_os = "macos")]
pub(crate) fn terminate(root: u32, expected: &str) -> Result<GroupSignal, String> {
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
    // Authenticate before any enumeration or signal, not just at the last
    // moment. A stale receipt never authorizes capture from a recycled root.
    let verified_root = process_fact(root)
        .filter(|fact| fact.start_time == expected_start)
        .ok_or("owner identity changed or became unreadable before tree capture")?;
    let snapshot = snapshot()?;
    let group_members = if verified_root.pgid == root {
        group_snapshot(root)?
    } else {
        Vec::new()
    };
    let targets = capture_members(
        &snapshot,
        root,
        expected_start,
        verified_root.pgid,
        &group_members,
    )?;
    let leader = verified_root.pgid == root;
    let current_root = process_fact(root)
        .filter(|fact| fact.start_time == expected_start && (!leader || fact.pgid == root))
        .ok_or("owner identity or process group changed before tree termination")?;

    let mut outcome = GroupSignal::NotFound;
    if leader {
        // SAFETY: current_root has a positive representable PID, matching
        // creation time, and PGID == PID. This is never a shared parent group.
        outcome = signal_result(unsafe { libc::killpg(current_root.pid as libc::pid_t, libc::SIGTERM) });
    }
    for target in &targets {
        if leader && target.in_group {
            continue;
        }
        if let Some(result) = signal_one(target, libc::SIGTERM)
            && target.fact.pid == root
        {
            outcome = result;
        }
    }
    let remaining = wait_for_exit(&targets, TERM_WAIT);
    if remaining.is_empty() {
        return Ok(outcome);
    }
    // Only captured, still-matching incarnations authorize escalation. The
    // root may already have exited, so never repeat a bare process-group kill.
    for target in &targets {
        if remaining.binary_search(&target.fact.pid).is_ok() {
            let _ = signal_one(target, libc::SIGKILL);
        }
    }
    let remaining = wait_for_exit(&targets, KILL_WAIT);
    if remaining.is_empty() {
        Ok(outcome)
    } else {
        Err(format!("captured processes survived termination: {remaining:?}"))
    }
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
        pgid: info.pbi_pgid,
        start_time: (info.pbi_start_tvsec, info.pbi_start_tvusec),
    })
}

#[cfg(target_os = "macos")]
fn group_snapshot(root: u32) -> Result<Vec<ProcFact>, String> {
    let pids = kill_group::live_members(root)?;
    let mut facts = Vec::with_capacity(pids.len());
    for pid in pids {
        match process_fact(pid) {
            // Preserve group departures for the pure capture check. Silently
            // omitting one could claim success while a real member survives.
            Some(fact) => facts.push(fact),
            None if is_definitely_dead(pid) => {}
            None => return Err(format!("could not authenticate process-group member {pid}")),
        }
    }
    Ok(facts)
}

#[cfg(target_os = "macos")]
fn observe(pid: u32) -> Observation {
    if is_definitely_dead(pid) {
        Observation::Gone
    } else if let Some(fact) = process_fact(pid) {
        Observation::Present(fact.start_time)
    } else {
        Observation::Unknown
    }
}

#[cfg(target_os = "macos")]
fn signal_one(target: &Target<'_>, signal: libc::c_int) -> Option<GroupSignal> {
    if observe(target.fact.pid) != Observation::Present(target.fact.start_time) {
        return None;
    }
    // SAFETY: observe authenticated one positive, representable PID's exact
    // incarnation. The caller supplies only SIGTERM or SIGKILL.
    Some(signal_result(unsafe {
        libc::kill(target.fact.pid as libc::pid_t, signal)
    }))
}

#[cfg(target_os = "macos")]
fn signal_result(result: libc::c_int) -> GroupSignal {
    if result == 0 {
        GroupSignal::Sent
    } else {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => GroupSignal::NotFound,
            Some(libc::EPERM) => GroupSignal::PermissionDenied,
            _ => GroupSignal::Other,
        }
    }
}

#[cfg(target_os = "macos")]
fn wait_for_exit(captured: &[Target<'_>], grace: Duration) -> Vec<u32> {
    let deadline = Instant::now() + grace;
    loop {
        let remaining = survivors(captured, observe);
        let now = Instant::now();
        if remaining.is_empty() || now >= deadline {
            return remaining;
        }
        std::thread::sleep(POLL_STEP.min(deadline.saturating_duration_since(now)));
    }
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
            pgid: 5,
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

    #[test]
    fn kill_tree_capture_includes_the_owned_group_and_escaped_descendants() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 5, 10)
        };
        let escaped = ProcFact {
            pgid: 99,
            ..fact(11, 10, 11)
        };
        let child = ProcFact {
            pgid: 10,
            ..fact(12, 10, 12)
        };
        let reparented = ProcFact {
            pgid: 10,
            ..fact(20, 1, 9)
        };
        let snapshot = [root, escaped, child, fact(5, 2, 1), fact(6, 5, 2)];
        let members = [
            root,
            child,
            reparented,
            ProcFact {
                pgid: 10,
                ..fact(1, 10, 11)
            },
        ];
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &members).unwrap();
        let mut pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        pids.sort_unstable();
        assert_eq!(pids, [10, 11, 12, 20]);
        for target in &captured {
            assert_eq!(target.in_group, target.fact.pid != 11);
        }
        assert_eq!(captured.last().unwrap().fact.pid, 10);
    }

    #[test]
    fn kill_tree_capture_never_adopts_a_nonleaders_shared_group() {
        let root = fact(10, 5, 10);
        let parent = fact(5, 2, 1);
        let sibling = fact(6, 5, 2);
        let child = fact(11, 10, 11);
        let snapshot = [root, parent, sibling, child];
        let members = [root, parent, sibling, child];
        let captured = capture_members(&snapshot, 10, root.start_time, 5, &members).unwrap();
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [11, 10]);
        assert!(captured.iter().all(|target| !target.in_group));
    }

    #[test]
    fn kill_tree_capture_rejects_an_identity_change_between_snapshots() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 5, 10)
        };
        let child = ProcFact {
            pgid: 10,
            ..fact(11, 10, 11)
        };
        let replacement = ProcFact {
            start_time: (100, 12),
            ..child
        };
        assert_eq!(
            capture_members(&[root, child], 10, root.start_time, 10, &[replacement])
                .unwrap_err(),
            "captured PID identity changed between process snapshots"
        );
    }

    #[test]
    fn kill_tree_capture_rejects_a_changed_root_group() {
        let root = fact(10, 5, 10);
        assert_eq!(
            capture_members(&[root], 10, root.start_time, 10, &[]).unwrap_err(),
            "owner process group changed during capture"
        );
    }

    #[test]
    fn kill_tree_capture_bounds_additional_group_members() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 5, 0)
        };
        let snapshot = [root];
        let mut members: Vec<_> = (0..MAX_TREE_PROCESSES - 1)
            .map(|index| ProcFact {
                pgid: 10,
                ..fact(20 + index as u32, 1, index as u64)
            })
            .collect();
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &members).unwrap();
        assert_eq!(captured.len(), MAX_TREE_PROCESSES);
        assert_eq!(captured.last().unwrap().fact.pid, 10);
        members.push(ProcFact {
            pgid: 10,
            ..fact(20 + MAX_TREE_PROCESSES as u32, 1, 9_000)
        });
        assert_eq!(
            capture_members(&snapshot, 10, root.start_time, 10, &members).unwrap_err(),
            "captured process set exceeds the size limit"
        );
    }

    #[test]
    fn kill_tree_survivors_require_positive_exit_or_reuse_evidence() {
        let root = fact(10, 5, 10);
        let snapshot = [
            root,
            fact(11, 10, 11),
            fact(12, 10, 12),
            fact(13, 10, 13),
        ];
        let captured = capture_members(&snapshot, 10, root.start_time, 5, &[]).unwrap();
        let remaining = survivors(&captured, |pid| match pid {
            10 => Observation::Present(root.start_time),
            11 => Observation::Gone,
            12 => Observation::Present((100, 14)),
            13 => Observation::Unknown,
            _ => panic!("unexpected captured PID"),
        });
        assert_eq!(remaining, [10, 13]);
    }

    #[test]
    fn kill_tree_survivors_accept_gone_or_reused_roots_and_children() {
        let root = fact(10, 5, 10);
        let snapshot = [root, fact(11, 10, 11)];
        let captured = capture_members(&snapshot, 10, root.start_time, 5, &[]).unwrap();
        assert_eq!(
            survivors(&captured, |pid| {
                if pid == 10 {
                    Observation::Present((101, 0))
                } else {
                    Observation::Gone
                }
            }),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn kill_tree_capture_refuses_ambiguous_group_departure() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 5, 10)
        };
        // The PID-only group scan saw this member, but its identity query now
        // reports another group. It might have escaped, not exited/reused.
        let departed = fact(20, 1, 20);
        assert_eq!(
            capture_members(&[root], 10, root.start_time, 10, &[departed]).unwrap_err(),
            "captured group member changed process groups"
        );
    }
}
