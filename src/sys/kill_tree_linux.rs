//! Terminate one verified Linux seat root's process tree and confirm it is gone.
//!
//! Parent PIDs alone aren't ownership: a child older than its reported parent
//! belongs to an earlier incarnation of that PID. Capture the complete member
//! set before sending anything, recheck each process's start time before its
//! signal, and treat a reused PID as gone rather than as a survivor. The same
//! set holds the seat's restricted carriers: processes that escaped the tree
//! but still carry one of the row's bound ids.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use super::kill_group::live_members;
use super::process::{
    GroupSignal, KILL_WAIT, KillError, POLL_STEP, TERM_WAIT, has_identity, proc_stat_group_id,
    proc_stat_is_dead,
};
use super::process_args::EnvRead;

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
    /// Outside the tree: its bound id and eligibility are re-proven too.
    carrier: bool,
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
            carrier: false,
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
                carrier: false,
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
            carrier: false,
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

/// Whether a fresh read shows `member` still as its captured incarnation.
/// Only this authorizes a per-PID signal: gone, reused and unreadable PIDs
/// never get one, though an unreadable PID still counts as a survivor.
fn is_captured(member: &Member, seen: Seen) -> bool {
    matches!(seen, Seen::Live(fact) if fact.start == member.start)
}

/// The members escalation may SIGKILL, proven lazily: each member's fresh
/// proof runs on `next`, immediately before the caller signals that PID.
fn escalation_targets<'a>(
    members: &'a [Member],
    mut proven: impl FnMut(&Member) -> bool + 'a,
) -> impl Iterator<Item = u32> + 'a {
    members
        .iter()
        .filter(move |member| proven(member))
        .map(|member| member.pid)
}

fn has_bound_id(process_id: EnvRead, bound_ids: &[String]) -> bool {
    matches!(process_id, EnvRead::Present(id) if !id.is_empty() && bound_ids.contains(&id))
}

/// Whether `member` may get a per-PID signal now. Tree and group members
/// need only their native incarnation; a carrier must also still carry a
/// bound id and stay eligible. Lost proof leaves it an unsignaled survivor.
fn signal_proof(
    member: &Member,
    seen: Seen,
    bound_ids: &[String],
    process_id: impl FnOnce() -> EnvRead,
    eligible: impl FnOnce() -> bool,
) -> bool {
    is_captured(member, seen)
        && (!member.carrier || (has_bound_id(process_id(), bound_ids) && eligible()))
}

/// `pid`'s ancestors in the snapshot, and whether the chain was read all the
/// way to the top (a parent of 0 or 1) rather than broken by a missing link.
fn ancestry(by_pid: &HashMap<u32, &ProcFact>, pid: u32) -> (HashSet<u32>, bool) {
    let mut chain = HashSet::new();
    let mut current = pid;
    for _ in 0..MAX_TREE_DEPTH {
        let Some(fact) = by_pid.get(&current) else {
            return (chain, false);
        };
        if fact.ppid <= 1 {
            chain.insert(fact.ppid);
            return (chain, true);
        }
        if !chain.insert(fact.ppid) {
            return (chain, false);
        }
        current = fact.ppid;
    }
    (chain, false)
}

/// The root's ancestry as read at capture, plus the caller's excluded chain
/// and the subtrees the `eligible` predicate fenced off. Rescans keep this
/// view, since the root may already be gone when they run.
struct Lineage<'a> {
    ancestors: HashSet<u32>,
    /// The chain read all the way to the top.
    complete: bool,
    /// PIDs the caller spares: traversal anchors, never signaled, never
    /// survivors, never carriers.
    excluded: &'a [u32],
    /// Ineligible processes and their whole subtrees: never captured,
    /// walked through, or signaled.
    fenced: HashSet<u32>,
}

impl<'a> Lineage<'a> {
    fn of(snapshot: &[ProcFact], root: u32) -> Self {
        let by_pid: HashMap<u32, &ProcFact> =
            snapshot.iter().map(|fact| (fact.pid, fact)).collect();
        let (ancestors, complete) = ancestry(&by_pid, root);
        Lineage {
            ancestors,
            complete,
            excluded: &[],
            fenced: HashSet::new(),
        }
    }

    fn excluding(self, excluded: &'a [u32]) -> Self {
        Lineage { excluded, ..self }
    }

    fn spares(&self, pid: u32) -> bool {
        self.excluded.contains(&pid)
    }
}

/// Fence `pid` and its whole subtree as `by_parent` (a snapshot sorted by
/// parent) shows it, whatever the start times: over-fencing only spares.
fn fence_subtree(by_parent: &[&ProcFact], pid: u32, fenced: &mut HashSet<u32>) {
    let mut visited = HashSet::new();
    let mut pending = vec![pid];
    while let Some(pid) = pending.pop() {
        if !visited.insert(pid) {
            continue;
        }
        fenced.insert(pid);
        let first_child = by_parent.partition_point(|child| child.ppid < pid);
        pending.extend(
            by_parent[first_child..]
                .iter()
                .take_while(|child| child.ppid == pid)
                .map(|child| child.pid),
        );
    }
}

/// Whether `pid` or any ancestor the snapshot shows is fenced.
fn under_fence(by_pid: &HashMap<u32, &ProcFact>, pid: u32, fenced: &HashSet<u32>) -> bool {
    let mut current = pid;
    for _ in 0..MAX_TREE_DEPTH {
        if fenced.contains(&current) {
            return true;
        }
        match by_pid.get(&current) {
            Some(fact) if fact.ppid > 1 => current = fact.ppid,
            _ => return false,
        }
    }
    false
}

fn sorted_by_parent(snapshot: &[ProcFact]) -> Vec<&ProcFact> {
    let mut by_parent: Vec<&ProcFact> = snapshot.iter().collect();
    by_parent.sort_unstable_by_key(|fact| (fact.ppid, fact.pid));
    by_parent
}

/// Drop every captured member the `eligible` predicate rejects, together
/// with its whole subtree, and fence them for every later rescan. The root
/// is the authenticated target, not a candidate, so it is never fenced.
fn fence_ineligible(
    snapshot: &[ProcFact],
    root: u32,
    members: &mut Vec<Member>,
    fenced: &mut HashSet<u32>,
    mut eligible: impl FnMut(u32) -> bool,
) {
    let by_parent = sorted_by_parent(snapshot);
    for member in members.iter() {
        if member.pid != root && !fenced.contains(&member.pid) && !eligible(member.pid) {
            fence_subtree(&by_parent, member.pid, fenced);
        }
    }
    members.retain(|member| member.pid == root || !fenced.contains(&member.pid));
}

/// From one snapshot, the processes the capture hasn't seen yet:
/// - descendants of a tree member still running as its captured incarnation,
///   through edges whose child is no older than its parent;
/// - restricted carriers: live processes outside the tree and the root's
///   ancestry that carry one of `bound_ids` and pass `eligible`. None predates
///   the root. A same-tick one is admitted only when both its ancestry and the
///   root's read to the top: a same-tick ancestor above a broken link is
///   otherwise indistinguishable from a carrier.
///
/// Every candidate must pass `eligible`; a rejected one is fenced with its
/// whole subtree, and nothing under a fence is ever admitted. Rescans run
/// this again, so forks made while the kill runs join the set.
fn absorb(
    snapshot: &[ProcFact],
    root_start: u64,
    lineage: &mut Lineage,
    members: &[Member],
    bound_ids: &[String],
    mut process_id_of: impl FnMut(u32) -> EnvRead,
    mut eligible: impl FnMut(u32) -> bool,
) -> Result<Vec<Member>, &'static str> {
    let captured: HashMap<u32, &Member> =
        members.iter().map(|member| (member.pid, member)).collect();
    let by_parent = sorted_by_parent(snapshot);
    // Only tree members found here; a carrier's own forks must carry the id.
    let mut pending: Vec<(u32, u64, usize)> = snapshot
        .iter()
        .filter_map(|fact| {
            let member = captured.get(&fact.pid)?;
            (!member.carrier && member.start == fact.start).then_some((
                fact.pid,
                fact.start,
                member.depth,
            ))
        })
        .collect();
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    while let Some((pid, start, depth)) = pending.pop() {
        let first_child = by_parent.partition_point(|child| child.ppid < pid);
        for child in by_parent[first_child..]
            .iter()
            .take_while(|child| child.ppid == pid)
        {
            if child.pid <= 1
                || child.start < start
                || captured.contains_key(&child.pid)
                || lineage.ancestors.contains(&child.pid)
                || lineage.fenced.contains(&child.pid)
                || !seen.insert(child.pid)
            {
                continue;
            }
            if !eligible(child.pid) {
                fence_subtree(&by_parent, child.pid, &mut lineage.fenced);
                continue;
            }
            if members.len() + found.len() >= MAX_TREE_PROCESSES {
                return Err("seat's captured processes exceed the size limit");
            }
            found.push(Member {
                pid: child.pid,
                start: child.start,
                depth: depth + 1,
                in_group: false,
                carrier: false,
            });
            pending.push((child.pid, child.start, depth + 1));
        }
    }
    if bound_ids.is_empty() {
        return Ok(found);
    }
    let by_pid: HashMap<u32, &ProcFact> = snapshot.iter().map(|fact| (fact.pid, fact)).collect();
    for fact in snapshot {
        if fact.pid <= 1
            || fact.start < root_start
            || captured.contains_key(&fact.pid)
            || seen.contains(&fact.pid)
            || lineage.ancestors.contains(&fact.pid)
            || lineage.spares(fact.pid)
            || under_fence(&by_pid, fact.pid, &lineage.fenced)
        {
            continue;
        }
        if fact.start == root_start && !(lineage.complete && ancestry(&by_pid, fact.pid).1) {
            continue;
        }
        if !has_bound_id(process_id_of(fact.pid), bound_ids) || !eligible(fact.pid) {
            continue;
        }
        if members.len() + found.len() >= MAX_TREE_PROCESSES {
            return Err("seat's captured processes exceed the size limit");
        }
        found.push(Member {
            pid: fact.pid,
            start: fact.start,
            depth: 0,
            in_group: false,
            carrier: true,
        });
    }
    Ok(found)
}

/// The capture-time facts and injected proofs a kill reuses for every
/// per-PID signal and every rescan.
struct Sweep<'a, P, E, A> {
    proc_root: &'a Path,
    root_start: u64,
    lineage: Lineage<'a>,
    bound_ids: &'a [String],
    process_id_of: P,
    eligible: E,
    authorize: A,
    /// Late members `authorize` refused: never signaled, still confirmed.
    refused: HashSet<u32>,
    /// The first late refusal, reported if any member is left running.
    refusal: Option<KillError>,
}

impl<P, E, A> Sweep<'_, P, E, A>
where
    P: FnMut(u32) -> EnvRead,
    E: FnMut(u32) -> bool,
    A: FnMut(u32) -> Result<(), KillError>,
{
    fn absorb(
        &mut self,
        snapshot: &[ProcFact],
        members: &[Member],
    ) -> Result<Vec<Member>, &'static str> {
        absorb(
            snapshot,
            self.root_start,
            &mut self.lineage,
            members,
            self.bound_ids,
            &mut self.process_id_of,
            &mut self.eligible,
        )
    }

    /// Authorize every member the kill would signal, before the first
    /// signal; one refusal refuses the whole capture.
    fn authorize_all(&mut self, members: &[Member]) -> Result<(), KillError> {
        for member in members {
            if !self.lineage.spares(member.pid) {
                (self.authorize)(member.pid)?;
            }
        }
        Ok(())
    }

    /// Whether `member` may get a per-PID signal now. An excluded or
    /// refused PID never does, whatever else it proves.
    fn proven(&mut self, member: &Member) -> bool {
        let pid = member.pid;
        !self.lineage.spares(pid)
            && !self.refused.contains(&pid)
            && signal_proof(
                member,
                observe(self.proc_root, pid),
                self.bound_ids,
                || (self.process_id_of)(pid),
                || (self.eligible)(pid),
            )
    }

    /// Captured members still running as their captured incarnation. An
    /// excluded PID stays in the set as a traversal anchor but is never
    /// confirmed, so it never counts as a survivor.
    fn survivors(&self, members: &[Member]) -> Vec<u32> {
        survivors(members, |pid| {
            if self.lineage.spares(pid) {
                Seen::Gone
            } else {
                observe(self.proc_root, pid)
            }
        })
    }

    /// Poll until every member is gone or `budget` runs out, returning the
    /// survivors. Each round first rescans and sends `signal` to proven new
    /// members, so success needs a round that found nothing new. Rounds are
    /// bounded by the deadline; a snapshot failure or a breach of the size
    /// cap ends the kill with the survivors named.
    fn settle(
        &mut self,
        members: &mut Vec<Member>,
        budget: Duration,
        signal: libc::c_int,
    ) -> Result<Vec<u32>, KillError> {
        let end = Instant::now() + budget;
        loop {
            let fresh = match snapshot(self.proc_root)
                .and_then(|snapshot| self.absorb(&snapshot, members))
            {
                Ok(fresh) => fresh,
                Err(reason) => {
                    return Err(KillError::Unconfirmed {
                        reason: reason.to_string(),
                        survivors: self.survivors(members),
                    });
                }
            };
            for member in &fresh {
                if self.lineage.spares(member.pid) {
                    continue;
                }
                if let Err(refusal) = (self.authorize)(member.pid) {
                    self.refused.insert(member.pid);
                    self.refusal.get_or_insert(refusal);
                    continue;
                }
                if self.proven(member) {
                    // SAFETY: one positive PID absorbed from this round's
                    // snapshot, authorized and just re-proven; never a
                    // group signal.
                    unsafe { libc::kill(member.pid as libc::pid_t, signal) };
                }
            }
            members.extend(fresh);
            let left = self.survivors(members);
            if left.is_empty() || Instant::now() >= end {
                return Ok(left);
            }
            std::thread::sleep(POLL_STEP);
        }
    }
}

/// Whether the leader's killpg may run: only when it can reach nothing the
/// kill must spare. An ancestor, excluded or fenced (ineligible) PID in the
/// root's group (the root itself included), or an ancestry too broken to
/// rule an ancestor out, sends every captured member its own signal
/// instead; nothing is refused.
fn group_signal_allowed(
    snapshot: &[ProcFact],
    root: u32,
    leader: bool,
    lineage: &Lineage,
    members: &[Member],
) -> bool {
    let spared = |pid: u32| {
        lineage.ancestors.contains(&pid) || lineage.spares(pid) || lineage.fenced.contains(&pid)
    };
    leader
        && lineage.complete
        && !snapshot
            .iter()
            .any(|fact| fact.pgrp == root && spared(fact.pid))
        && !members
            .iter()
            .any(|member| member.in_group && spared(member.pid))
}

/// `expected` is the native `linux:<boot_id>:<start_ticks>` identity of the
/// verified seat root. `bound_ids` and `process_id_of` admit the restricted
/// carriers; `eligible` must pass for every capture candidate but the root,
/// and a rejected one is spared with its whole subtree. `excluded` is the
/// caller's own chain: those PIDs anchor capture and rescans but are never
/// signaled or confirmed. Any ancestor, excluded or ineligible PID in the
/// root's group turns the group signal into per-PID signals. `authorize`
/// runs on every member to be signaled before the first signal (one refusal
/// refuses the kill) and on each late member before its signal (a refused
/// one stays unsignaled and unconfirmed). Ok carries the root's own signal
/// outcome, as with the other GroupSignal primitives, once every captured
/// member is confirmed gone; an excluded root is never signaled and reports
/// NotFound. Members left at the deadline are an error naming their PIDs.
pub(crate) fn terminate(
    root: u32,
    expected: &str,
    bound_ids: &[String],
    excluded: &[u32],
    process_id_of: impl FnMut(u32) -> EnvRead,
    mut eligible: impl FnMut(u32) -> bool,
    authorize: impl FnMut(u32) -> Result<(), KillError>,
) -> Result<GroupSignal, KillError> {
    let expected_start = expected
        .strip_prefix("linux:")
        .and_then(|identity| identity.rsplit_once(':'))
        .and_then(|(_, ticks)| ticks.parse::<u64>().ok())
        .ok_or("recorded Linux process identity is unreadable")?;
    let proc_root = Path::new("/proc");
    if !has_identity(root, expected) {
        return Err("seat root identity changed or became unreadable before tree capture".into());
    }
    let snapshot = snapshot(proc_root)?;
    let mut members = capture(&snapshot, root, expected_start)?;
    let leader = members
        .iter()
        .any(|member| member.pid == root && member.in_group);
    if leader {
        verify_group(proc_root, root, &mut members)?;
    }
    let mut lineage = Lineage::of(&snapshot, root).excluding(excluded);
    fence_ineligible(
        &snapshot,
        root,
        &mut members,
        &mut lineage.fenced,
        &mut eligible,
    );
    let group_signal = group_signal_allowed(&snapshot, root, leader, &lineage, &members);
    // The root's ancestors (its launch wrapper and everything above) are
    // never signaled, confirmed or walked through, even when they share its
    // group; excluded PIDs stay as anchors and are skipped at each signal.
    members.retain(|member| !lineage.ancestors.contains(&member.pid));
    let mut sweep = Sweep {
        proc_root,
        root_start: expected_start,
        lineage,
        bound_ids,
        process_id_of,
        eligible,
        authorize,
        refused: HashSet::new(),
        refusal: None,
    };
    let found = sweep.absorb(&snapshot, &members)?;
    members.splice(0..0, found);
    sweep.authorize_all(&members)?;

    let mut root_signal = None;
    for member in &members {
        if member.pid == root {
            if sweep.lineage.spares(root) {
                root_signal = Some(GroupSignal::NotFound);
                continue;
            }
            // The boot id half of the identity is checked here too: this gate
            // runs immediately before the root's (or group's) signal.
            if !has_identity(root, expected) {
                // A root that waited on the descendants just signaled can
                // exit, and be reaped, on its own. That is the outcome asked
                // for; only a live mismatch or an unreadable root refuses.
                if observe(proc_root, root) != Seen::Gone {
                    return Err(
                        "seat root identity changed or became unreadable before its signal".into(),
                    );
                }
                root_signal = Some(GroupSignal::NotFound);
                if group_signal {
                    // Its group outlives it but gets no killpg from here, so
                    // the members the loop skipped get their own signals.
                    for grouped in members.iter().filter(|m| m.in_group && m.pid != root) {
                        if sweep.proven(grouped) {
                            // SAFETY: one positive captured PID, just re-proven.
                            unsafe { libc::kill(grouped.pid as libc::pid_t, libc::SIGTERM) };
                        }
                    }
                }
                continue;
            }
            root_signal = Some(if group_signal {
                // SAFETY: killpg receives the verified leader's positive PGID.
                signal_result(unsafe { libc::killpg(root as libc::pid_t, libc::SIGTERM) })
            } else {
                // SAFETY: kill receives one verified positive PID.
                signal_result(unsafe { libc::kill(root as libc::pid_t, libc::SIGTERM) })
            });
            continue;
        }
        if group_signal && member.in_group {
            continue;
        }
        if !sweep.proven(member) {
            continue;
        }
        // SAFETY: capture rejects reserved PIDs, so this is one positive PID,
        // never kill(0), kill(-1), or a group signal. ESRCH means it is gone.
        unsafe { libc::kill(member.pid as libc::pid_t, libc::SIGTERM) };
    }
    let root_signal = root_signal.ok_or("seat root is missing from the termination plan")?;

    if sweep
        .settle(&mut members, TERM_WAIT, libc::SIGTERM)?
        .is_empty()
    {
        return Ok(root_signal);
    }
    // Escalate per PID, never by group: the leader may have exited, and only
    // a freshly re-proven captured incarnation is signaled, never a reuse.
    for pid in escalation_targets(&members, |member| sweep.proven(member)) {
        // SAFETY: one positive captured PID whose start time was just
        // rechecked; ESRCH means it exited in between.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
    let left = sweep.settle(&mut members, KILL_WAIT, libc::SIGKILL)?;
    if left.is_empty() {
        return Ok(root_signal);
    }
    Err(match sweep.refusal.take() {
        // A refused late member was never signaled; say why it may be left.
        Some(refusal) => KillError::Unconfirmed {
            reason: refusal.to_string(),
            survivors: left,
        },
        None => KillError::Survivors(left),
    })
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
            carrier: false,
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
    fn escalation_never_kills_a_reused_gone_or_unreadable_pid_and_reads_each_just_in_time() {
        let member = |pid, start| Member {
            pid,
            start,
            depth: 0,
            in_group: true,
            carrier: false,
        };
        let members = [
            member(10, 100),
            member(20, 110),
            member(30, 120),
            member(40, 130),
            member(50, 140),
        ];
        let now = HashMap::from([
            (10, Seen::Live(fact(10, 1, 10, 100))),
            // Its start changed between the TERM and the KILL: a new process.
            (20, Seen::Live(fact(20, 1, 10, 111))),
            (30, Seen::Gone),
            (40, Seen::Unknown),
            (50, Seen::Live(fact(50, 1, 99, 140))),
        ]);
        let log = std::cell::RefCell::new(Vec::new());
        let proven = |member: &Member| {
            log.borrow_mut().push(format!("read {}", member.pid));
            is_captured(member, now[&member.pid])
        };
        for pid in escalation_targets(&members, proven) {
            log.borrow_mut().push(format!("kill {pid}"));
        }
        // Each kill follows its own fresh read, never a batch read earlier.
        assert_eq!(
            log.into_inner(),
            [
                "read 10", "kill 10", "read 20", "read 30", "read 40", "read 50", "kill 50"
            ]
        );
    }

    #[test]
    fn group_member_refuses_any_pid_it_cannot_bind_to_one_incarnation() {
        let grouped = Member {
            pid: 20,
            start: 110,
            depth: 1,
            in_group: true,
            carrier: false,
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

    const SEAT: &str = "seat-id";

    fn seat_env(pid: u32) -> EnvRead {
        match pid {
            41 => EnvRead::Unreadable,
            42 => EnvRead::Absent,
            43 => EnvRead::Present("another-seat".into()),
            46 => EnvRead::Present(String::new()),
            _ => EnvRead::Present(SEAT.into()),
        }
    }

    /// Root 10 (ticks 100) under 5 (same ticks) under 3, under init. Every
    /// process carries the seat id unless `seat_env` says otherwise.
    fn carrier_snapshot() -> Vec<ProcFact> {
        vec![
            fact(1, 0, 1, 1),
            // Ancestors: one older, one from the root's own tick.
            fact(3, 1, 3, 50),
            fact(5, 3, 3, 100),
            fact(10, 5, 10, 100),
            // Tree member: captured once, as tree, not again as a carrier.
            fact(20, 10, 10, 110),
            // Reparented to init after the root started: a carrier.
            fact(30, 1, 30, 120),
            // Predates the root, so it can't be the seat's.
            fact(31, 1, 31, 99),
            // Same tick as the root, ancestry read to the top: a carrier.
            fact(40, 1, 40, 100),
            // Unreadable, absent, foreign and empty ids never qualify.
            fact(41, 1, 41, 130),
            fact(42, 1, 42, 130),
            fact(43, 1, 43, 130),
            fact(46, 1, 46, 130),
            // Same tick, its parent missing from the snapshot: skipped.
            fact(44, 77, 44, 100),
            // Bound id, but not eligible.
            fact(45, 1, 45, 130),
        ]
    }

    fn absorbed(
        snapshot: &[ProcFact],
        lineage: &mut Lineage,
        members: &[Member],
        bound: &[String],
    ) -> Result<Vec<Member>, &'static str> {
        absorb(snapshot, 100, lineage, members, bound, seat_env, |pid| {
            pid != 45
        })
    }

    fn carrier_pids(snapshot: &[ProcFact], bound: &[String]) -> Vec<u32> {
        let members = capture(snapshot, 10, 100).unwrap();
        pids(&absorbed(snapshot, &mut Lineage::of(snapshot, 10), &members, bound).unwrap())
    }

    #[test]
    fn carriers_are_bound_eligible_post_root_processes_outside_tree_and_ancestry() {
        let bound = [String::from("other"), SEAT.to_string()];
        assert_eq!(carrier_pids(&carrier_snapshot(), &bound), vec![30, 40]);

        let snapshot = carrier_snapshot();
        let members = capture(&snapshot, 10, 100).unwrap();
        let found = absorbed(&snapshot, &mut Lineage::of(&snapshot, 10), &members, &bound);
        assert!(
            found
                .unwrap()
                .iter()
                .all(|member| member.carrier && !member.in_group)
        );
    }

    #[test]
    fn a_broken_root_ancestry_admits_no_same_tick_carrier() {
        // Without 3, the root's chain stops at 5: a same-tick process could be
        // an ancestor above the gap, so only strictly later carriers remain.
        let snapshot: Vec<ProcFact> = carrier_snapshot()
            .into_iter()
            .filter(|fact| fact.pid != 3)
            .collect();
        assert_eq!(carrier_pids(&snapshot, &[SEAT.to_string()]), vec![30]);
    }

    #[test]
    fn no_bound_ids_reads_no_process_id() {
        let snapshot = carrier_snapshot();
        let members = capture(&snapshot, 10, 100).unwrap();
        let found = absorb(
            &snapshot,
            100,
            &mut Lineage::of(&snapshot, 10),
            &members,
            &[],
            |_| panic!("no carrier arm without bound ids"),
            |_| panic!("no carrier arm without bound ids"),
        );
        assert_eq!(found, Ok(Vec::new()));
    }

    #[test]
    fn a_rescan_absorbs_late_forks_and_orphans_but_keeps_the_capture_lineage() {
        let initial = carrier_snapshot();
        let mut lineage = Lineage::of(&initial, 10);
        let bound = [SEAT.to_string()];
        let mut members = capture(&initial, 10, 100).unwrap();
        members.extend(absorbed(&initial, &mut lineage, &members, &bound).unwrap());

        // The root has exited. Its tree forked 60 -> 61 meanwhile; an orphan
        // of the root (95) was adopted by init. 70 claims tree member 20 as
        // parent but predates it; 80 is a carrier's child without the id.
        let later: Vec<ProcFact> = initial
            .iter()
            .copied()
            .filter(|fact| fact.pid != 10)
            .chain([
                fact(60, 20, 10, 150),
                fact(61, 60, 10, 160),
                fact(70, 20, 70, 105),
                fact(80, 30, 30, 170),
                fact(95, 1, 95, 180),
            ])
            .collect();
        let env = |pid| match pid {
            70 | 80 => EnvRead::Absent,
            _ => seat_env(pid),
        };
        let found = absorb(&later, 100, &mut lineage, &members, &bound, env, |pid| {
            pid != 45
        })
        .unwrap();
        let tree: Vec<u32> = found.iter().filter(|m| !m.carrier).map(|m| m.pid).collect();
        let carriers: Vec<u32> = found.iter().filter(|m| m.carrier).map(|m| m.pid).collect();
        assert_eq!(tree, vec![60, 61]);
        // The ancestors 3 and 5 still carry the id and are still excluded.
        assert_eq!(carriers, vec![95]);

        members.extend(found);
        assert_eq!(
            absorb(&later, 100, &mut lineage, &members, &bound, env, |_| true).map(|f| pids(&f)),
            Ok(vec![45])
        );
    }

    #[test]
    fn a_group_signal_runs_only_when_it_can_reach_nothing_spared() {
        let snapshot = carrier_snapshot();
        let lineage = Lineage::of(&snapshot, 10);
        let members = capture(&snapshot, 10, 100).unwrap();
        assert!(group_signal_allowed(
            &snapshot, 10, true, &lineage, &members
        ));
        assert!(!group_signal_allowed(
            &snapshot, 10, false, &lineage, &members
        ));

        // Ancestor 3 moved into the root's group: killpg would reach it.
        let joined: Vec<ProcFact> = snapshot
            .iter()
            .map(|f| if f.pid == 3 { fact(3, 1, 10, 50) } else { *f })
            .collect();
        assert!(!group_signal_allowed(&joined, 10, true, &lineage, &members));

        // An excluded group member, or an excluded root.
        for spared in [[20], [10]] {
            let excluding = Lineage::of(&snapshot, 10).excluding(&spared);
            assert!(!group_signal_allowed(
                &snapshot, 10, true, &excluding, &members
            ));
        }
        // An excluded PID outside the group doesn't matter to killpg.
        let outside = Lineage::of(&snapshot, 10).excluding(&[30]);
        assert!(group_signal_allowed(
            &snapshot, 10, true, &outside, &members
        ));

        // A broken ancestry can't rule out an ancestor in the group.
        let broken: Vec<ProcFact> = snapshot.iter().copied().filter(|f| f.pid != 3).collect();
        let broken_lineage = Lineage::of(&broken, 10);
        assert!(!group_signal_allowed(
            &broken,
            10,
            true,
            &broken_lineage,
            &members
        ));
    }

    #[test]
    fn a_rescan_never_walks_into_a_root_ancestor() {
        // A pathological edge: ancestor 5 reported as a child of tree member
        // 20 with no older start. The walk still refuses to absorb it.
        let initial = carrier_snapshot();
        let mut lineage = Lineage::of(&initial, 10);
        let members = capture(&initial, 10, 100).unwrap();
        let later: Vec<ProcFact> = initial
            .iter()
            .map(|f| if f.pid == 5 { fact(5, 20, 3, 110) } else { *f })
            .collect();
        let found = absorbed(&later, &mut lineage, &members, &[]).unwrap();
        assert!(found.iter().all(|member| member.pid != 5));
    }

    #[test]
    fn a_rescan_fences_an_ineligible_late_fork_with_its_whole_subtree() {
        let initial = carrier_snapshot();
        let mut lineage = Lineage::of(&initial, 10);
        let bound = [SEAT.to_string()];
        let mut members = capture(&initial, 10, 100).unwrap();
        members.extend(absorbed(&initial, &mut lineage, &members, &bound).unwrap());

        // Tree member 20 forked a broker-like 60 (ineligible, carrying the
        // seat id) with children 61 -> 62, and an ordinary sleeper 70.
        let later: Vec<ProcFact> = initial
            .iter()
            .copied()
            .chain([
                fact(60, 20, 60, 150),
                fact(61, 60, 60, 160),
                fact(62, 61, 60, 170),
                fact(70, 20, 10, 150),
            ])
            .collect();
        let eligible = |pid| pid != 60 && pid != 45;
        let found = absorb(
            &later,
            100,
            &mut lineage,
            &members,
            &bound,
            seat_env,
            eligible,
        );
        assert_eq!(found.map(|f| pids(&f)), Ok(vec![70]));
        assert!([60, 61, 62].iter().all(|pid| lineage.fenced.contains(pid)));
        members.push(Member {
            pid: 70,
            start: 150,
            depth: 2,
            in_group: false,
            carrier: false,
        });

        // A still later fork under the fence carries the id and passes the
        // predicate itself; it stays out with the rest of the subtree.
        let latest: Vec<ProcFact> = later
            .iter()
            .copied()
            .chain([fact(63, 62, 60, 180)])
            .collect();
        let found = absorb(
            &latest,
            100,
            &mut lineage,
            &members,
            &bound,
            seat_env,
            eligible,
        );
        assert_eq!(found, Ok(Vec::new()));
    }

    #[test]
    fn an_ineligible_member_is_fenced_with_its_subtree_but_never_the_root() {
        let snapshot: Vec<ProcFact> = carrier_snapshot()
            .into_iter()
            .chain([fact(21, 20, 10, 115), fact(22, 21, 10, 120)])
            .collect();
        let mut members = capture(&snapshot, 10, 100).unwrap();
        let mut fenced = HashSet::new();
        fence_ineligible(&snapshot, 10, &mut members, &mut fenced, |pid| {
            pid != 20 && pid != 10
        });
        assert_eq!(pids(&members), vec![10]);
        assert_eq!(fenced, HashSet::from([20, 21, 22]));
        // The ineligible members were in the root's group: no killpg.
        let mut lineage = Lineage::of(&snapshot, 10);
        lineage.fenced = fenced;
        assert!(!group_signal_allowed(
            &snapshot, 10, true, &lineage, &members
        ));
    }

    #[test]
    fn a_rescan_past_the_size_cap_is_an_error() {
        let initial = vec![fact(10, 1, 10, 100)];
        let mut lineage = Lineage::of(&initial, 10);
        let members = capture(&initial, 10, 100).unwrap();
        let mut later = initial.clone();
        later.extend((0..MAX_TREE_PROCESSES as u32).map(|pid| fact(1_000 + pid, 10, 10, 110)));
        assert!(absorbed(&later, &mut lineage, &members, &[]).is_err());
    }

    #[test]
    fn only_a_still_bound_eligible_carrier_may_be_signaled() {
        let member = Member {
            pid: 30,
            start: 120,
            depth: 0,
            in_group: false,
            carrier: true,
        };
        let tree_member = Member {
            carrier: false,
            ..member
        };
        let bound = [SEAT.to_string()];
        let live = Seen::Live(fact(30, 1, 30, 120));
        let reused = Seen::Live(fact(30, 1, 30, 121));
        let seat = || EnvRead::Present(SEAT.into());
        assert!(signal_proof(&member, live, &bound, seat, || true));
        assert!(!signal_proof(
            &member,
            live,
            &bound,
            || EnvRead::Unreadable,
            || true
        ));
        assert!(!signal_proof(&member, live, &bound, seat, || false));
        assert!(!signal_proof(
            &member,
            reused,
            &bound,
            || panic!("reused PID read"),
            || true
        ));
        // Tree members keep their native proof alone.
        assert!(signal_proof(
            &tree_member,
            live,
            &bound,
            || panic!("env read"),
            || panic!("eligibility read")
        ));
        // Unsignaled, a carrier that lost its proof still counts against success.
        assert_eq!(survivors(&[member], |_| live), vec![30]);
    }

    fn terminate_tree(root: u32, expected: &str) -> Result<GroupSignal, KillError> {
        terminate(
            root,
            expected,
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |_| Ok(()),
        )
    }

    /// Wait until `pid` has exec'd `sleep`, so its incarnation is final.
    fn wait_for_sleep(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .as_deref()
            != Some("sleep\n")
        {
            assert!(
                Instant::now() < deadline,
                "fixture {pid} never exec'd sleep"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// SIGKILLs one test-spawned process that left every fixture group, only
    /// while it is still the incarnation the test recorded.
    struct Stray {
        pid: u32,
        start: u64,
    }

    impl Drop for Stray {
        fn drop(&mut self) {
            if start_of(self.pid) == Some(self.start) {
                // SAFETY: one positive PID this test spawned, just rechecked.
                unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGKILL) };
            }
        }
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

        let result = terminate_tree(root, &identity(root).unwrap());
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

        let result = terminate_tree(root, &identity(root).unwrap());
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

        assert!(terminate_tree(root, &format!("linux:{boot}:{}", ticks + 1)).is_err());
        assert!(terminate_tree(root, &format!("linux:not-this-boot:{ticks}")).is_err());
        assert!(terminate_tree(root, "linux:unreadable").is_err());
        // A signal would already have landed; give it time to show anyway.
        std::thread::sleep(Duration::from_millis(100));
        assert!(members.iter().all(running));
        drop(fixture);
    }

    #[test]
    fn a_term_ignoring_child_is_escalated_to_sigkill_and_confirmed_gone() {
        // SIG_IGN survives exec, so sleep itself ignores SIGTERM.
        let leader = spawn("trap '' TERM; exec sleep 30", 0);
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        // Wait for the exec, so the captured incarnation is sleep's.
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read_to_string(format!("/proc/{root}/comm"))
            .ok()
            .as_deref()
            != Some("sleep\n")
        {
            assert!(Instant::now() < deadline, "fixture never exec'd sleep");
            std::thread::sleep(Duration::from_millis(10));
        }
        let members = captured(root, 1);

        let began = Instant::now();
        let result = terminate_tree(root, &identity(root).unwrap());
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert!(members.iter().all(|member| !running(member)));
        // It outlived the SIGTERM budget, so only the SIGKILL ended it.
        assert!(began.elapsed() >= TERM_WAIT, "{:?}", began.elapsed());
        drop(fixture);
    }

    #[test]
    fn a_reparented_carrier_with_a_bound_id_is_captured_and_terminated() {
        let leader = spawn("exec sleep 30", 0);
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        wait_for_sleep(root);
        let id = format!("kill-tree-linux-carrier-{}-{root}", std::process::id());
        // The intermediate shell exits at once; its background sleep is
        // adopted by init or a subreaper, outside the root's tree.
        let output = Command::new("sh")
            .args([
                "-c",
                "HCOM_PROCESS_ID=\"$1\" sleep 30 </dev/null >/dev/null 2>&1 & echo $!",
                "sh",
                &id,
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .expect("spawn own carrier");
        let carrier: u32 = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        wait_for_sleep(carrier);
        let stray = Stray {
            pid: carrier,
            start: start_of(carrier).expect("carrier start"),
        };
        let tree = captured(root, 1);
        assert!(tree.iter().all(|member| member.pid != carrier));

        let result = terminate(
            root,
            &identity(root).unwrap(),
            std::slice::from_ref(&id),
            &[],
            crate::proctruth::process_id_of,
            |_| true,
            |_| Ok(()),
        );
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert_ne!(start_of(carrier), Some(stray.start), "carrier survived");
        assert!(tree.iter().all(|member| !running(member)));
        drop(stray);
        drop(fixture);
    }

    #[test]
    fn an_ancestor_carrying_the_id_is_never_signaled() {
        // Anchor -> root shell -> sleep. After its wait the anchor execs sleep,
        // keeping its start time, so it stays observable unless signaled.
        let anchor = spawn("sh -c 'sleep 30 & wait' & wait; exec sleep 30", 0);
        let group = anchor.id();
        let fixture = Fixture {
            group,
            children: vec![anchor],
        };
        let tree = captured(group, 3);
        let root = tree
            .iter()
            .find(|member| member.depth == 1)
            .expect("root shell")
            .pid;
        let anchor_start = start_of(group).unwrap();
        assert!(anchor_start <= start_of(root).unwrap());

        // Every fixture process reads as carrying the id, nothing else does,
        // so the anchor is the only carrier candidate outside the root tree.
        let fixture_pids: Vec<u32> = tree.iter().map(|member| member.pid).collect();
        let result = terminate(
            root,
            &identity(root).unwrap(),
            &[SEAT.to_string()],
            &[],
            |pid| {
                if fixture_pids.contains(&pid) {
                    EnvRead::Present(SEAT.into())
                } else {
                    EnvRead::Absent
                }
            },
            |_| true,
            |_| Ok(()),
        );
        assert_eq!(result, Ok(GroupSignal::Sent));
        let root_tree: Vec<&Member> = tree.iter().filter(|member| member.pid != group).collect();
        assert!(root_tree.iter().all(|member| !running(member)));
        assert_eq!(start_of(group), Some(anchor_start), "ancestor was signaled");
        drop(fixture);
    }

    #[test]
    fn a_root_that_exits_and_is_reaped_once_its_tree_is_signaled_is_success() {
        // The root shell exits as soon as its sleeper dies, and its own
        // parent reaps it at once: the root can vanish between its child's
        // signal and its own. Repeat to make that narrow window likely.
        for _ in 0..40 {
            let anchor = spawn("sh -c 'sleep 30 & wait' & wait", 0);
            let group = anchor.id();
            let fixture = Fixture {
                group,
                children: vec![anchor],
            };
            let tree = captured(group, 3);
            let root = tree
                .iter()
                .find(|member| member.depth == 1)
                .expect("root shell")
                .pid;
            let result = terminate_tree(root, &identity(root).unwrap());
            assert!(
                matches!(result, Ok(GroupSignal::Sent | GroupSignal::NotFound)),
                "{result:?}"
            );
            drop(fixture);
        }
    }

    #[test]
    fn forks_made_during_the_kill_are_absorbed_and_confirmed_gone() {
        // A test-owned group whose leader is not the seat root.
        let anchor = spawn("exec sleep 30", 0);
        let group = anchor.id();
        let mut fixture = Fixture {
            group,
            children: vec![anchor],
        };
        wait_for_sleep(group);
        let id = format!("kill-tree-linux-forker-{}-{group}", std::process::id());
        // The root and its sleepers ignore SIGTERM, so the root keeps forking
        // a sleeper every 50ms through the whole TERM budget, long after the
        // initial capture; one forked just before its SIGKILL is orphaned.
        let root_child = Command::new("sh")
            .args([
                "-c",
                "trap '' TERM; while :; do sleep 30 & sleep 0.05; done",
            ])
            .env("HCOM_PROCESS_ID", &id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(group as i32)
            .spawn()
            .expect("spawn own forking root");
        let root = root_child.id();
        fixture.children.push(root_child);
        let first = captured(root, 3);

        let result = terminate(
            root,
            &identity(root).unwrap(),
            std::slice::from_ref(&id),
            &[],
            crate::proctruth::process_id_of,
            |_| true,
            |_| Ok(()),
        );
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert!(first.iter().all(|member| !running(member)));
        // Every sleeper, late or orphaned, is gone; only the anchor is left.
        assert_eq!(live_members(group), Ok(vec![group]));
        drop(fixture);
    }

    #[test]
    fn an_excluded_group_member_survives_while_the_rest_of_the_group_goes() {
        let leader = spawn("sleep 30 & sleep 30 & wait", 0);
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        let tree = captured(root, 3);
        let spared = tree
            .iter()
            .filter(|member| member.depth == 1)
            .map(|member| member.pid)
            .min()
            .expect("a sleeper");
        let spared_start = start_of(spared).unwrap();

        // The excluded sleeper shares the root's group, so no killpg may run.
        let result = terminate(
            root,
            &identity(root).unwrap(),
            &[],
            &[spared],
            |_| EnvRead::Absent,
            |_| true,
            |_| Ok(()),
        );
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert!(
            tree.iter()
                .filter(|member| member.pid != spared)
                .all(|member| !running(member))
        );
        assert_eq!(
            start_of(spared),
            Some(spared_start),
            "excluded PID was signaled"
        );
        drop(fixture);
    }

    #[test]
    fn an_excluded_root_anchors_its_tree_but_is_never_signaled() {
        // After its wait the root execs sleep, keeping its start time.
        let leader = spawn("sleep 30 & wait; exec sleep 30", 0);
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        let tree = captured(root, 2);
        let root_start = start_of(root).unwrap();

        let result = terminate(
            root,
            &identity(root).unwrap(),
            &[],
            &[root],
            |_| EnvRead::Absent,
            |_| true,
            |_| Ok(()),
        );
        assert_eq!(result, Ok(GroupSignal::NotFound));
        assert!(
            tree.iter()
                .filter(|member| member.pid != root)
                .all(|member| !running(member))
        );
        assert_eq!(
            start_of(root),
            Some(root_start),
            "excluded root was signaled"
        );
        drop(fixture);
    }

    /// SIGKILLs and reaps one process this test forked.
    struct Forked(libc::pid_t);

    impl Drop for Forked {
        fn drop(&mut self) {
            // SAFETY: our own forked child; waitpid reaps it after the kill.
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                libc::waitpid(self.0, std::ptr::null_mut(), 0);
            }
        }
    }

    #[test]
    fn a_leader_root_sharing_its_group_with_its_parent_spares_the_parent() {
        let sleep = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .find(|path| Path::new(path).exists())
            .expect("a sleep binary");
        let path = std::ffi::CString::new(sleep).unwrap();
        let (arg0, arg1) = (c"sleep", c"30");
        let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
        // The parent forks the root, makes it lead its own group, then joins
        // that group itself: a leader root whose group holds its ancestor.
        // SAFETY: between fork and exec the children call only fork, setpgid,
        // execv and _exit, all async-signal-safe; argv was built beforehand.
        let parent = unsafe { libc::fork() };
        assert!(parent >= 0, "fork failed");
        if parent == 0 {
            unsafe {
                let root = libc::fork();
                if root == 0 {
                    libc::setpgid(0, 0);
                    libc::execv(path.as_ptr(), argv.as_ptr());
                    libc::_exit(127);
                }
                if root > 0 {
                    libc::setpgid(root, root);
                    libc::setpgid(0, root);
                    libc::execv(path.as_ptr(), argv.as_ptr());
                }
                libc::_exit(127);
            }
        }
        let parent_guard = Forked(parent);
        let parent = parent as u32;

        let deadline = Instant::now() + Duration::from_secs(5);
        let root = loop {
            let snapshot = snapshot(Path::new("/proc")).unwrap();
            let child = snapshot.iter().find(|fact| fact.ppid == parent).copied();
            let parent_fact = snapshot.iter().find(|fact| fact.pid == parent).copied();
            if let (Some(child), Some(parent_fact)) = (child, parent_fact)
                && child.pgrp == child.pid
                && parent_fact.pgrp == child.pid
            {
                break child.pid;
            }
            assert!(Instant::now() < deadline, "fixture group never formed");
            std::thread::sleep(Duration::from_millis(10));
        };
        wait_for_sleep(root);
        wait_for_sleep(parent);
        let root_stray = Stray {
            pid: root,
            start: start_of(root).unwrap(),
        };
        let parent_start = start_of(parent).unwrap();

        let result = terminate_tree(root, &identity(root).unwrap());
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert_ne!(start_of(root), Some(root_stray.start), "root survived");
        assert_eq!(start_of(parent), Some(parent_start), "parent was signaled");
        drop(root_stray);
        drop(parent_guard);
    }

    #[test]
    fn an_ineligible_child_carrying_the_seat_id_survives_with_its_subtree() {
        let id = format!("kill-tree-linux-broker-{}", std::process::id());
        // Root -> A (the "broker": ineligible, carries the seat id) -> B,
        // plus an ordinary sleeper S that must go with the root.
        let leader = Command::new("sh")
            .args(["-c", "sh -c 'sleep 30 & wait' & sleep 30 & wait"])
            .env("HCOM_PROCESS_ID", &id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn own root");
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        let tree = captured(root, 4);
        let snapshot = snapshot(Path::new("/proc")).unwrap();
        let broker = snapshot
            .iter()
            .find(|fact| fact.ppid == root && snapshot.iter().any(|c| c.ppid == fact.pid))
            .expect("broker shell")
            .pid;
        let grandchild = snapshot
            .iter()
            .find(|fact| fact.ppid == broker)
            .expect("broker child")
            .pid;
        let spared = [
            (broker, start_of(broker).unwrap()),
            (grandchild, start_of(grandchild).unwrap()),
        ];

        let result = terminate(
            root,
            &identity(root).unwrap(),
            std::slice::from_ref(&id),
            &[],
            crate::proctruth::process_id_of,
            |pid| pid != broker,
            |_| Ok(()),
        );
        assert_eq!(result, Ok(GroupSignal::Sent));
        for (pid, start) in spared {
            assert_eq!(start_of(pid), Some(start), "spared {pid} was signaled");
        }
        assert!(
            tree.iter()
                .filter(|member| member.pid != broker && member.pid != grandchild)
                .all(|member| !running(member))
        );
        drop(fixture);
    }

    #[test]
    fn an_unauthorized_member_refuses_the_kill_before_any_signal() {
        let leader = spawn("sleep 30 & sleep 30 & wait", 0);
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        let tree = captured(root, 3);
        let foreign = tree.iter().find(|member| member.pid != root).unwrap().pid;
        let result = terminate(
            root,
            &identity(root).unwrap(),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                if pid == foreign {
                    Err(KillError::Refused("owned by another row".into()))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(
            result,
            Err(KillError::Refused("owned by another row".into()))
        );
        std::thread::sleep(Duration::from_millis(100));
        assert!(tree.iter().all(running), "a member was signaled");
        drop(fixture);
    }

    #[test]
    fn an_unauthorized_late_fork_is_never_signaled_and_reported_unconfirmed() {
        let anchor = spawn("exec sleep 30", 0);
        let group = anchor.id();
        let mut fixture = Fixture {
            group,
            children: vec![anchor],
        };
        wait_for_sleep(group);
        // The root ignores SIGTERM and keeps forking; only the processes
        // present at the start are authorized, so later forks stay unsignaled.
        let root_child = Command::new("sh")
            .args([
                "-c",
                "trap '' TERM; while :; do sleep 30 & sleep 0.05; done",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(group as i32)
            .spawn()
            .expect("spawn own forking root");
        let root = root_child.id();
        fixture.children.push(root_child);
        captured(root, 3);
        // Authorization is fixed at its first call, which comes after the
        // capture and before any signal: anything started later is foreign.
        let cutoff = std::cell::Cell::new(None::<u64>);
        let now_ticks = || {
            let uptime = std::fs::read_to_string("/proc/uptime").unwrap();
            let seconds: f64 = uptime.split_whitespace().next().unwrap().parse().unwrap();
            // SAFETY: sysconf reads a constant system value.
            let hertz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
            (seconds * hertz) as u64
        };

        let result = terminate(
            root,
            &identity(root).unwrap(),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                let limit = cutoff.get().unwrap_or_else(now_ticks);
                cutoff.set(Some(limit));
                match start_of(pid) {
                    Some(start) if start > limit => {
                        Err(KillError::Refused(format!("{pid} is foreign")))
                    }
                    _ => Ok(()),
                }
            },
        );
        let Err(KillError::Unconfirmed { reason, survivors }) = result else {
            panic!("expected an unconfirmed kill, got {result:?}");
        };
        assert!(reason.ends_with("is foreign"), "{reason}");
        assert!(!survivors.is_empty());
        let limit = cutoff.get().unwrap();
        // Every survivor is a refused late fork, still running unsignaled.
        assert!(
            survivors
                .iter()
                .all(|pid| start_of(*pid).is_some_and(|start| start > limit))
        );
        drop(fixture);
    }
}
