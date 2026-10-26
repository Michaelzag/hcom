//! Terminate one verified Linux seat root's process tree and confirm it is gone.
//!
//! Parent PIDs alone aren't ownership: a child older than its reported parent
//! belongs to an earlier incarnation of that PID. Capture the complete member
//! set before sending anything, recheck each process's start time before its
//! signal, and treat a reused PID as gone rather than as a survivor.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use super::kill_group::live_members;
use super::process::{
    GroupSignal, KILL_WAIT, POLL_STEP, TERM_WAIT, has_identity, proc_stat_group_id,
    proc_stat_is_dead,
};

const MAX_SNAPSHOT_PROCESSES: usize = 65_536;
const MAX_STAT_BYTES: usize = 8_192;
const MAX_TREE_PROCESSES: usize = 4_096;
const MAX_TREE_DEPTH: usize = 128;

/// One live (neither zombie nor dead) process from `/proc/<pid>/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcFact {
    pid: u32,
    ppid: u32,
    pgrp: u32,
    /// Boot-relative start time in clock ticks (stat field 22).
    start: u64,
}

/// What one fresh `/proc/<pid>/stat` read proves about a PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// Absent, zombie, or dead: the process has exited.
    Gone,
    Live(ProcFact),
    /// Unreadable or malformed: proves neither exit nor identity.
    Unknown,
}

/// A captured process and the start time that names its incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Member {
    pid: u32,
    start: u64,
    depth: usize,
    /// Reached by the leader's killpg; otherwise it needs its own signal.
    in_group: bool,
}

/// Capture the seat root's members from one snapshot. A root that leads its
/// process group owns every live member of that group; any root owns its
/// descendants, reached only through edges whose child is no older than its
/// parent. Returned deepest first, root last; nothing here signals anything.
fn capture(
    snapshot: &[ProcFact],
    root: u32,
    expected_start: u64,
) -> Result<Vec<Member>, &'static str> {
    if root <= 1 {
        return Err("refusing to terminate a reserved process ID");
    }
    if snapshot.len() > MAX_SNAPSHOT_PROCESSES {
        return Err("process snapshot exceeds the safety limit");
    }

    let mut seen = HashSet::with_capacity(snapshot.len());
    let mut root_fact = None;
    for fact in snapshot {
        if !seen.insert(fact.pid) {
            return Err("process snapshot contains a duplicate PID");
        }
        if fact.pid == root {
            root_fact = Some(fact);
        }
    }
    let root_fact = root_fact.ok_or("seat root is missing from the process snapshot")?;
    if root_fact.start != expected_start {
        return Err("seat root identity changed before the process snapshot");
    }
    let leader = root_fact.pgrp == root;

    let mut by_parent: Vec<&ProcFact> = snapshot.iter().collect();
    by_parent.sort_unstable_by_key(|fact| (fact.ppid, fact.pid));

    // Reuse the duplicate-check allocation as the captured set. An explicit
    // stack bounds traversal independently of the Rust thread's stack size.
    seen.clear();
    let mut members = Vec::new();
    let mut pending = vec![(root_fact, 0usize)];
    while let Some((fact, depth)) = pending.pop() {
        if !seen.insert(fact.pid) {
            return Err("cycle in the seat root's process tree");
        }
        let first_child = by_parent.partition_point(|child| child.ppid < fact.pid);
        for child in by_parent[first_child..]
            .iter()
            .take_while(|child| child.ppid == fact.pid)
        {
            if child.pid <= 1 || child.start < fact.start {
                continue;
            }
            if depth + 1 > MAX_TREE_DEPTH {
                return Err("seat root's process tree exceeds the depth limit");
            }
            if members.len() + pending.len() + 1 >= MAX_TREE_PROCESSES {
                return Err("seat root's process tree exceeds the size limit");
            }
            pending.push((child, depth + 1));
        }
        members.push(Member {
            pid: fact.pid,
            start: fact.start,
            depth,
            in_group: leader && fact.pgrp == root,
        });
    }
    if leader {
        // Group members whose ancestry left the tree (reparented to a
        // subreaper or init) are still the leader's.
        for fact in snapshot {
            if fact.pgrp != root || fact.pid <= 1 || !seen.insert(fact.pid) {
                continue;
            }
            if members.len() >= MAX_TREE_PROCESSES {
                return Err("seat root's process group exceeds the size limit");
            }
            members.push(Member {
                pid: fact.pid,
                start: fact.start,
                depth: 1,
                in_group: true,
            });
        }
    }
    members.sort_unstable_by(|left, right| {
        (left.pid == root)
            .cmp(&(right.pid == root))
            .then_with(|| right.depth.cmp(&left.depth))
            .then_with(|| left.pid.cmp(&right.pid))
    });
    Ok(members)
}

/// Captured members still running as the captured incarnation. A gone PID
/// and a PID reused by a different start time both count as gone; an
/// unreadable PID proves nothing, so it stays a survivor.
fn survivors(members: &[Member], mut observe: impl FnMut(u32) -> Seen) -> Vec<u32> {
    members
        .iter()
        .filter(|member| match observe(member.pid) {
            Seen::Gone => false,
            Seen::Live(fact) => fact.start == member.start,
            Seen::Unknown => true,
        })
        .map(|member| member.pid)
        .collect()
}

/// Decide one PID the group scan reported, from a fresh read. A captured PID
/// must still be its captured incarnation, and still in the group if killpg
/// is what reaches it; a new PID must still be in the group. A PID that can't
/// be bound to one incarnation refuses the whole capture, before any signal.
fn group_member(
    root: u32,
    pid: u32,
    captured: Option<&Member>,
    seen: Seen,
) -> Result<Option<Member>, &'static str> {
    match (seen, captured) {
        (Seen::Gone, _) => Ok(None),
        (Seen::Unknown, _) => Err("seat root's process group has an unreadable member"),
        (Seen::Live(fact), Some(member)) if fact.start != member.start => {
            Err("a process group PID was reused during capture")
        }
        (Seen::Live(fact), Some(member)) if member.in_group && fact.pgrp != root => {
            Err("a process group member left the group during capture")
        }
        (Seen::Live(_), Some(_)) => Ok(None),
        (Seen::Live(fact), None) if fact.pgrp == root => Ok(Some(Member {
            pid,
            start: fact.start,
            depth: 1,
            in_group: true,
        })),
        (Seen::Live(_), None) => Err("a process group member left the group during capture"),
    }
}

/// A leader owns its exact group: every PID the group scan reports must be
/// captured already, captured now, or proven gone before killpg reaches it.
fn verify_group(proc_root: &Path, root: u32, members: &mut Vec<Member>) -> Result<(), String> {
    let captured: HashMap<u32, Member> =
        members.iter().map(|member| (member.pid, *member)).collect();
    for pid in live_members(root)? {
        let seen = observe(proc_root, pid);
        if let Some(member) = group_member(root, pid, captured.get(&pid), seen)? {
            if members.len() >= MAX_TREE_PROCESSES {
                return Err("seat root's process group exceeds the size limit".into());
            }
            members.push(member);
        }
    }
    Ok(())
}

/// Poll until every member is gone or `budget` runs out; the survivors.
fn wait_gone(proc_root: &Path, members: &[Member], budget: Duration) -> Vec<u32> {
    let end = Instant::now() + budget;
    loop {
        let left = survivors(members, |pid| observe(proc_root, pid));
        if left.is_empty() || Instant::now() >= end {
            return left;
        }
        std::thread::sleep(POLL_STEP);
    }
}

/// Whether `member` is freshly readable as its captured incarnation.
fn still_captured(proc_root: &Path, member: &Member) -> bool {
    matches!(observe(proc_root, member.pid), Seen::Live(fact) if fact.start == member.start)
}

/// `expected` is the native `linux:<boot_id>:<start_ticks>` identity of the
/// verified seat root. Ok carries the root's own signal outcome, as with the
/// other GroupSignal primitives, once every captured member is confirmed
/// gone; survivors at the deadline are an error naming their PIDs.
pub(crate) fn terminate(root: u32, expected: &str) -> Result<GroupSignal, String> {
    let expected_start = expected
        .strip_prefix("linux:")
        .and_then(|identity| identity.rsplit_once(':'))
        .and_then(|(_, ticks)| ticks.parse::<u64>().ok())
        .ok_or("recorded Linux process identity is unreadable")?;
    let proc_root = Path::new("/proc");
    if !has_identity(root, expected) {
        return Err("seat root identity changed or became unreadable before tree capture".into());
    }
    let mut members = capture(&snapshot(proc_root)?, root, expected_start)?;
    let leader = members
        .iter()
        .any(|member| member.pid == root && member.in_group);
    if leader {
        verify_group(proc_root, root, &mut members)?;
    }

    let mut root_signal = None;
    for member in &members {
        if member.pid == root {
            // The boot id half of the identity is checked here too: this gate
            // runs immediately before the root's (or group's) signal.
            if !has_identity(root, expected) {
                return Err(
                    "seat root identity changed or became unreadable before its signal".into(),
                );
            }
            root_signal = Some(if leader {
                // SAFETY: killpg receives the verified leader's positive PGID.
                signal_result(unsafe { libc::killpg(root as libc::pid_t, libc::SIGTERM) })
            } else {
                // SAFETY: kill receives one verified positive PID.
                signal_result(unsafe { libc::kill(root as libc::pid_t, libc::SIGTERM) })
            });
            continue;
        }
        if leader && member.in_group {
            continue;
        }
        if !still_captured(proc_root, member) {
            continue;
        }
        // SAFETY: capture rejects reserved PIDs, so this is one positive PID,
        // never kill(0), kill(-1), or a group signal. ESRCH means it is gone.
        unsafe { libc::kill(member.pid as libc::pid_t, libc::SIGTERM) };
    }
    let root_signal = root_signal.ok_or("seat root is missing from the termination plan")?;

    if wait_gone(proc_root, &members, TERM_WAIT).is_empty() {
        return Ok(root_signal);
    }
    // Escalate per PID, never by group: the leader may have exited, and only
    // a freshly re-proven captured incarnation is signaled, never a reuse.
    for member in &members {
        if still_captured(proc_root, member) {
            // SAFETY: one positive captured PID whose start time was just
            // rechecked; ESRCH means it exited in between.
            unsafe { libc::kill(member.pid as libc::pid_t, libc::SIGKILL) };
        }
    }
    let left = wait_gone(proc_root, &members, KILL_WAIT);
    if left.is_empty() {
        return Ok(root_signal);
    }
    let pids: Vec<String> = left.iter().map(u32::to_string).collect();
    Err(format!("survivors: {}", pids.join(" ")))
}

fn signal_result(result: libc::c_int) -> GroupSignal {
    if result == 0 {
        return GroupSignal::Sent;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => GroupSignal::NotFound,
        Some(libc::EPERM) => GroupSignal::PermissionDenied,
        _ => GroupSignal::Other,
    }
}

/// Parse one process from its stat line; None for a malformed line or one
/// naming a different PID. The caller decides what a dead state means.
fn parse_stat(pid: u32, stat: &str) -> Option<ProcFact> {
    let pgrp = proc_stat_group_id(stat)?;
    let (head, fields) = stat.rsplit_once(") ")?;
    if head.split_once(" (")?.0.parse::<u32>().ok()? != pid {
        return None;
    }
    // Fields after the final `) ` begin at field 3 (`state`): ppid is index 1
    // and the start time (field 22) index 19.
    let mut fields = fields.split_whitespace();
    let ppid = fields.nth(1)?.parse().ok()?;
    let start = fields.nth(17)?.parse().ok()?;
    Some(ProcFact {
        pid,
        ppid,
        pgrp,
        start,
    })
}

/// Read one stat file. Err only when it exceeds the hard cap.
fn read_seen(path: &Path, pid: u32, buffer: &mut Vec<u8>) -> Result<Seen, &'static str> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Seen::Gone),
        Err(_) => return Ok(Seen::Unknown),
    };
    buffer.clear();
    if let Err(error) = file.take((MAX_STAT_BYTES + 1) as u64).read_to_end(buffer) {
        // A process reaped after the open reads back ESRCH.
        return Ok(if error.raw_os_error() == Some(libc::ESRCH) {
            Seen::Gone
        } else {
            Seen::Unknown
        });
    }
    if buffer.len() > MAX_STAT_BYTES {
        return Err("process stat exceeds the safety limit");
    }
    // comm can contain non-UTF-8 bytes. Replacing those bytes preserves the
    // ASCII fields parsed after its final closing parenthesis.
    let stat = String::from_utf8_lossy(buffer);
    if proc_stat_is_dead(&stat) {
        return Ok(Seen::Gone);
    }
    Ok(parse_stat(pid, &stat).map_or(Seen::Unknown, Seen::Live))
}

fn observe(proc_root: &Path, pid: u32) -> Seen {
    let mut buffer = Vec::with_capacity(512);
    let path = proc_root.join(pid.to_string()).join("stat");
    read_seen(&path, pid, &mut buffer).unwrap_or(Seen::Unknown)
}

/// One bounded pass over procfs. Exits race the scan and unreadable entries
/// are skipped; neither authorizes a PID absent from the snapshot.
fn snapshot(proc_root: &Path) -> Result<Vec<ProcFact>, &'static str> {
    let entries = std::fs::read_dir(proc_root).map_err(|_| "could not read process directory")?;
    let mut facts = Vec::new();
    let mut buffer = Vec::with_capacity(512);
    let mut stat_path = proc_root.to_path_buf();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_SNAPSHOT_PROCESSES {
            return Err("process directory exceeds the safety limit");
        }
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        stat_path.clear();
        stat_path.push(proc_root);
        stat_path.push(name);
        stat_path.push("stat");
        if let Seen::Live(fact) = read_seen(&stat_path, pid, &mut buffer)? {
            facts.push(fact);
        }
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    use super::super::process::identity;
    use super::*;

    fn fact(pid: u32, ppid: u32, pgrp: u32, start: u64) -> ProcFact {
        ProcFact {
            pid,
            ppid,
            pgrp,
            start,
        }
    }

    fn pids(members: &[Member]) -> Vec<u32> {
        members.iter().map(|member| member.pid).collect()
    }

    #[test]
    fn stat_parse_reads_parent_group_and_start_past_a_hostile_comm() {
        let stat = "42 (we ) ird) S 7 40 40 0 -1 4194304 1 2 3 4 5 6 7 8 20 0 1 0 98765 1 2";
        assert_eq!(parse_stat(42, stat), Some(fact(42, 7, 40, 98765)));
        assert_eq!(parse_stat(43, stat), None, "a line for another PID");
        assert_eq!(parse_stat(42, "42 (short) S 7 40 40"), None);
    }

    #[test]
    fn stat_read_separates_exit_from_unreadable() {
        let root = tempfile::tempdir().unwrap();
        let tail = "0 -1 4194304 1 2 3 4 5 6 7 8 20 0 1 0 98765";
        for (pid, state) in [("40", "S"), ("41", "Z"), ("42", "X")] {
            std::fs::create_dir(root.path().join(pid)).unwrap();
            std::fs::write(
                root.path().join(pid).join("stat"),
                format!("{pid} (p) {state} 7 40 40 {tail}"),
            )
            .unwrap();
        }
        std::fs::create_dir(root.path().join("43")).unwrap();
        std::fs::write(root.path().join("43/stat"), "43 (p) S 7 nope").unwrap();
        // A directory where stat should be: open succeeds, reads fail.
        std::fs::create_dir_all(root.path().join("44/stat")).unwrap();

        assert_eq!(observe(root.path(), 40), Seen::Live(fact(40, 7, 40, 98765)));
        assert_eq!(observe(root.path(), 41), Seen::Gone, "zombie");
        assert_eq!(observe(root.path(), 42), Seen::Gone, "dead");
        assert_eq!(observe(root.path(), 45), Seen::Gone, "absent");
        assert_eq!(observe(root.path(), 43), Seen::Unknown, "malformed");
        assert_eq!(observe(root.path(), 44), Seen::Unknown, "unreadable");
    }

    #[test]
    fn non_leader_capture_walks_only_verified_descendants_deepest_first() {
        let snapshot = [
            fact(10, 1, 5, 100),
            fact(20, 10, 5, 110),
            fact(30, 20, 5, 120),
            // Older than its claimed parent: an earlier incarnation's child.
            fact(21, 10, 5, 90),
            // Same group, not a descendant: a non-leader root never owns it.
            fact(40, 5, 5, 100),
            fact(5, 1, 5, 50),
        ];
        let members = capture(&snapshot, 10, 100).unwrap();
        assert_eq!(pids(&members), vec![30, 20, 10]);
        assert!(members.iter().all(|member| !member.in_group));
    }

    #[test]
    fn leader_capture_adds_group_members_and_escaped_descendants() {
        let snapshot = [
            fact(10, 1, 10, 100),
            fact(20, 10, 10, 110),
            // Group member reparented to init: still the leader's.
            fact(25, 1, 10, 115),
            // Descendant that left the group: captured, signaled on its own.
            fact(30, 20, 30, 120),
            // Unrelated process in another group.
            fact(50, 1, 50, 100),
        ];
        let members = capture(&snapshot, 10, 100).unwrap();
        assert_eq!(pids(&members), vec![30, 20, 25, 10]);
        let in_group: HashMap<u32, bool> = members.iter().map(|m| (m.pid, m.in_group)).collect();
        assert!(in_group[&10] && in_group[&20] && in_group[&25]);
        assert!(!in_group[&30]);
    }

    #[test]
    fn capture_fails_closed_before_any_signal() {
        let snapshot = [fact(10, 1, 10, 100), fact(20, 10, 10, 110)];
        assert!(
            capture(&snapshot, 10, 101).is_err(),
            "root identity mismatch"
        );
        assert!(capture(&snapshot, 11, 100).is_err(), "root missing");
        assert!(capture(&snapshot, 1, 100).is_err(), "reserved root");
        assert!(capture(&[fact(10, 1, 10, 100), fact(10, 1, 10, 100)], 10, 100).is_err());

        let mut wide = vec![fact(10, 1, 10, 100)];
        wide.extend((0..MAX_TREE_PROCESSES as u32).map(|pid| fact(1_000 + pid, 10, 7, 100)));
        assert!(capture(&wide, 10, 100).is_err(), "tree size cap");
        let mut group = vec![fact(10, 1, 10, 100)];
        group.extend((0..MAX_TREE_PROCESSES as u32).map(|pid| fact(1_000 + pid, 1, 10, 100)));
        assert!(capture(&group, 10, 100).is_err(), "group size cap");
        let mut deep = vec![fact(10, 1, 10, 100)];
        deep.extend((0..=MAX_TREE_DEPTH as u32).map(|depth| {
            fact(
                1_000 + depth,
                if depth == 0 { 10 } else { 999 + depth },
                7,
                100,
            )
        }));
        assert!(capture(&deep, 10, 100).is_err(), "depth cap");
    }

    #[test]
    fn survivors_are_members_still_running_as_their_captured_incarnation_or_unreadable() {
        let member = |pid, start| Member {
            pid,
            start,
            depth: 0,
            in_group: false,
        };
        let members = [
            member(10, 100),
            member(20, 110),
            member(30, 120),
            member(40, 130),
        ];
        let now = HashMap::from([
            (10, Seen::Live(fact(10, 1, 10, 100))),
            (30, Seen::Live(fact(30, 1, 30, 999))),
            (40, Seen::Unknown),
        ]);
        // 10 still matches; 20 is gone; 30's PID now names a newer process;
        // 40 can't be read, which proves neither exit nor reuse.
        let observe = |pid| now.get(&pid).copied().unwrap_or(Seen::Gone);
        assert_eq!(survivors(&members, observe), vec![10, 40]);
        assert!(survivors(&members, |_| Seen::Gone).is_empty());
    }

    #[test]
    fn group_member_refuses_any_pid_it_cannot_bind_to_one_incarnation() {
        let grouped = Member {
            pid: 20,
            start: 110,
            depth: 1,
            in_group: true,
        };
        let escaped = Member {
            in_group: false,
            ..grouped
        };
        let live = |pgrp, start| Seen::Live(fact(20, 1, pgrp, start));
        assert_eq!(group_member(10, 20, Some(&grouped), Seen::Gone), Ok(None));
        assert_eq!(group_member(10, 20, None, Seen::Gone), Ok(None));
        assert_eq!(
            group_member(10, 20, Some(&grouped), live(10, 110)),
            Ok(None)
        );
        assert_eq!(
            group_member(10, 20, Some(&escaped), live(30, 110)),
            Ok(None)
        );
        assert_eq!(
            group_member(10, 20, None, live(10, 120)),
            Ok(Some(Member {
                start: 120,
                ..grouped
            }))
        );
        // Reused, escaped after capture, escaped before capture, unreadable.
        assert!(group_member(10, 20, Some(&grouped), live(10, 111)).is_err());
        assert!(group_member(10, 20, Some(&grouped), live(30, 110)).is_err());
        assert!(group_member(10, 20, None, live(30, 120)).is_err());
        assert!(group_member(10, 20, None, Seen::Unknown).is_err());
    }

    /// Owns this test's fixture processes and their process group. Drop
    /// SIGKILLs the fixture group (created by the test itself) and reaps.
    struct Fixture {
        group: u32,
        children: Vec<Child>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // SAFETY: `group` is a process group this test created with
            // process_group(0); nothing else ever joins it.
            unsafe { libc::killpg(self.group as libc::pid_t, libc::SIGKILL) };
            for child in &mut self.children {
                let _ = child.kill();
                let deadline = Instant::now() + Duration::from_secs(5);
                while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn spawn(script: &str, group: u32) -> Child {
        Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(group as i32)
            .spawn()
            .expect("spawn own fixture")
    }

    /// Wait until `root` has captured at least `count` members.
    fn captured(root: u32, count: usize) -> Vec<Member> {
        let start = start_of(root).expect("fixture root");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let members = capture(&snapshot(Path::new("/proc")).unwrap(), root, start).unwrap();
            if members.len() >= count {
                return members;
            }
            assert!(Instant::now() < deadline, "fixture tree never formed");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn start_of(pid: u32) -> Option<u64> {
        match observe(Path::new("/proc"), pid) {
            Seen::Live(fact) => Some(fact.start),
            Seen::Gone | Seen::Unknown => None,
        }
    }

    fn running(member: &Member) -> bool {
        start_of(member.pid) == Some(member.start)
    }

    #[test]
    fn leader_group_with_two_children_is_terminated_and_confirmed_gone() {
        let leader = spawn("sleep 30 & sleep 30 & wait", 0);
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        let members = captured(root, 3);
        assert!(members.iter().all(|member| member.in_group));

        let result = terminate(root, &identity(root).unwrap());
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert!(members.iter().all(|member| !running(member)));
        drop(fixture);
    }

    #[test]
    fn non_leader_root_and_its_child_go_while_a_sibling_survives() {
        // A test-owned group whose leader is not the seat root.
        let anchor = spawn("exec sleep 30", 0);
        let group = anchor.id();
        let mut fixture = Fixture {
            group,
            children: vec![anchor],
        };
        let root_child = spawn("sleep 30 & wait", group);
        let root = root_child.id();
        fixture.children.push(root_child);
        let sibling = spawn("exec sleep 30", group);
        let sibling_pid = sibling.id();
        fixture.children.push(sibling);

        let members = captured(root, 2);
        assert_eq!(members.len(), 2, "root plus its one child");
        let sibling_start = start_of(sibling_pid).unwrap();
        let anchor_start = start_of(group).unwrap();

        let result = terminate(root, &identity(root).unwrap());
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert!(members.iter().all(|member| !running(member)));
        assert_eq!(start_of(sibling_pid), Some(sibling_start));
        assert_eq!(start_of(group), Some(anchor_start));
        drop(fixture);
    }

    #[test]
    fn root_identity_mismatch_signals_nothing() {
        let leader = spawn("sleep 30 & wait", 0);
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        let members = captured(root, 2);
        let (boot, ticks) = identity(root)
            .unwrap()
            .strip_prefix("linux:")
            .and_then(|rest| rest.rsplit_once(':'))
            .map(|(boot, ticks)| (boot.to_string(), ticks.parse::<u64>().unwrap()))
            .unwrap();

        assert!(terminate(root, &format!("linux:{boot}:{}", ticks + 1)).is_err());
        assert!(terminate(root, &format!("linux:not-this-boot:{ticks}")).is_err());
        assert!(terminate(root, "linux:unreadable").is_err());
        // A signal would already have landed; give it time to show anyway.
        std::thread::sleep(Duration::from_millis(100));
        assert!(members.iter().all(running));
        drop(fixture);
    }
}
