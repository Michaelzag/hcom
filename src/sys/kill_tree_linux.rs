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
    proc_stat_is_dead, proc_stat_is_zombie,
};
use super::process_args::EnvRead;

const MAX_SNAPSHOT_PROCESSES: usize = 65_536;
const MAX_STAT_BYTES: usize = 8_192;
const MAX_TREE_PROCESSES: usize = 4_096;
const MAX_TREE_DEPTH: usize = 128;
const MAX_THREADS: usize = 65_536;
/// `PF_EXITING` (include/linux/sched.h): the thread is in do_exit and can
/// never return to user space.
const PF_EXITING: u64 = 0x4;

/// One process from `/proc/<pid>/stat`: its leader's parent, group and start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcFact {
    pid: u32,
    ppid: u32,
    pgrp: u32,
    /// Boot-relative start time in clock ticks (stat field 22).
    start: u64,
}

/// What one fresh read of a PID's whole thread set proves about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// Absent, or every thread a zombie or dead: the process has exited.
    Gone,
    /// Every thread is dead or in do_exit: it can never run user code
    /// again, but it has not finished exiting.
    Exiting(ProcFact),
    /// At least one thread is running and not exiting.
    Live(ProcFact),
    /// Unreadable, malformed, or the thread set changed while read: proves
    /// neither exit nor identity.
    Unknown,
}

/// A Linux process's state from its whole thread set; see [`linux_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcState {
    /// Absent, every thread a zombie or dead, or (with an expected start) a
    /// different incarnation of the PID.
    Gone,
    /// Every thread is dead or exiting; it will never run user code again.
    Exiting,
    /// At least one thread runs and is not exiting, even behind a zombie
    /// leader thread.
    Live,
    /// Unreadable or changing while read: fail closed, never Gone.
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
            Seen::Live(fact) | Seen::Exiting(fact) => fact.start == member.start,
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
    // An exiting member is still a member until it is gone.
    let fact = match seen {
        Seen::Gone => return Ok(None),
        Seen::Unknown => return Err("seat root's process group has an unreadable member"),
        Seen::Live(fact) | Seen::Exiting(fact) => fact,
    };
    match captured {
        Some(member) if fact.start != member.start => {
            Err("a process group PID was reused during capture")
        }
        Some(member) if member.in_group && fact.pgrp != root => {
            Err("a process group member left the group during capture")
        }
        Some(_) => Ok(None),
        None if fact.pgrp == root => Ok(Some(Member {
            pid,
            start: fact.start,
            depth: 1,
            in_group: true,
            carrier: false,
        })),
        None => Err("a process group member left the group during capture"),
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

/// Whether a fresh read shows `member` still as its captured incarnation and
/// able to run. Only this authorizes a per-PID signal: gone, reused, exiting
/// and unreadable PIDs never get one, though exiting and unreadable PIDs
/// still count as survivors.
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
    /// Late members refused by `authorize`, and everything below them:
    /// never signaled, still confirmed.
    refused: HashSet<u32>,
    /// The first late refusal, reported if the kill ends with survivors.
    refusal: Option<KillError>,
}

/// Whether a fresh read makes a refusal moot: the captured incarnation is
/// over (exited, a zombie, or its PID reused) or exiting, so it can never
/// run user code again. An unreadable PID proves nothing; the refusal stands.
fn refusal_moot(member: &Member, seen: Seen) -> bool {
    match seen {
        Seen::Gone | Seen::Exiting(_) => true,
        Seen::Live(fact) => fact.start != member.start,
        Seen::Unknown => false,
    }
}

/// The bare reason a refusal carries, without any survivor list.
fn refusal_reason(refusal: KillError) -> String {
    match refusal {
        KillError::Refused(reason) | KillError::Unconfirmed { reason, .. } => reason,
        survivors @ KillError::Survivors(_) => survivors.to_string(),
    }
}

/// The error for members left at the deadline: why they may be left (a late
/// refusal, members still exiting), or plain survivors.
fn verdict(refusal: Option<KillError>, exiting: &[u32], left: Vec<u32>) -> KillError {
    let mut reasons: Vec<String> = refusal.into_iter().map(refusal_reason).collect();
    if !exiting.is_empty() {
        let pids: Vec<String> = exiting.iter().map(u32::to_string).collect();
        reasons.push(format!("exiting: {}", pids.join(" ")));
    }
    if reasons.is_empty() {
        KillError::Survivors(left)
    } else {
        KillError::Unconfirmed {
            reason: reasons.join("; "),
            survivors: left,
        }
    }
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

    /// Authorize the initial members before the first signal. A refusal
    /// stands unless a fresh read makes it moot, as when a short-lived child
    /// exits between the listing and the check; a standing one refuses the
    /// whole kill. Returns the members whose refusal was moot.
    fn preflight(&mut self, members: &[Member]) -> Result<HashSet<u32>, KillError> {
        let mut mooted = HashSet::new();
        for member in members {
            if self.lineage.spares(member.pid) {
                continue;
            }
            if let Err(refusal) = (self.authorize)(member.pid) {
                if !refusal_moot(member, observe(self.proc_root, member.pid)) {
                    return Err(refusal);
                }
                mooted.insert(member.pid);
            }
        }
        Ok(mooted)
    }

    /// Authorize a round's new members, all before any of them is signaled.
    /// A standing refusal fences that member and everything below it: never
    /// signaled, still confirmed, and reported once the kill ends.
    fn authorize_late(&mut self, snapshot: &[ProcFact], fresh: &[Member]) {
        let by_pid: HashMap<u32, &ProcFact> =
            snapshot.iter().map(|fact| (fact.pid, fact)).collect();
        for member in fresh {
            if self.lineage.spares(member.pid) {
                continue;
            }
            if under_fence(&by_pid, member.pid, &self.refused) {
                self.refused.insert(member.pid);
                continue;
            }
            if let Err(refusal) = (self.authorize)(member.pid)
                && !refusal_moot(member, observe(self.proc_root, member.pid))
            {
                self.refused.insert(member.pid);
                self.refusal.get_or_insert(refusal);
            }
        }
    }

    /// Whether `member` may get a per-PID signal now. An excluded or refused
    /// PID never does, whatever else it proves.
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

    /// The error for `left` at the deadline, naming members still exiting.
    fn verdict(&mut self, members: &[Member], left: Vec<u32>) -> KillError {
        let exiting: Vec<u32> = members
            .iter()
            .filter(|member| left.contains(&member.pid))
            .filter(|member| {
                matches!(observe(self.proc_root, member.pid),
                    Seen::Exiting(fact) if fact.start == member.start)
            })
            .map(|member| member.pid)
            .collect();
        verdict(self.refusal.take(), &exiting, left)
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
            let snapshot = match snapshot(self.proc_root) {
                Ok(snapshot) => snapshot,
                Err(reason) => {
                    return Err(KillError::Unconfirmed {
                        reason: reason.to_string(),
                        survivors: self.survivors(members),
                    });
                }
            };
            let fresh = match self.absorb(&snapshot, members) {
                Ok(fresh) => fresh,
                Err(reason) => {
                    return Err(KillError::Unconfirmed {
                        reason: reason.to_string(),
                        survivors: self.survivors(members),
                    });
                }
            };
            self.authorize_late(&snapshot, &fresh);
            for member in &fresh {
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
/// runs on every member before the first signal, and on each round's new
/// members before any of them is signaled. A refusal is moot when a fresh
/// read shows that member gone, reused or exiting; otherwise it refuses the
/// kill (initially) or fences that member and its subtree, unsignaled, and
/// the kill ends Unconfirmed with its reason (late). Exiting members are
/// never signaled and are confirmed only once gone. Ok carries the root's
/// own signal outcome, as with the other GroupSignal primitives, once every
/// captured member is confirmed gone; an excluded or exiting root is never
/// signaled and reports NotFound. Members left at the deadline are an error
/// naming their PIDs, with the reason when they were refused or exiting.
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
    let mut group_signal = group_signal_allowed(&snapshot, root, leader, &lineage, &members);
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
    let mooted = sweep.preflight(&members)?;
    // killpg can't skip a group member whose refusal a fresh read made moot,
    // nor one already exiting: then every member gets its own signal, and
    // those get none.
    group_signal &= !members.iter().any(|member| {
        member.in_group
            && member.pid != root
            && (mooted.contains(&member.pid)
                || matches!(observe(proc_root, member.pid), Seen::Exiting(_)))
    });

    let mut root_signal = None;
    for member in &members {
        if member.pid == root {
            if sweep.lineage.spares(root) {
                root_signal = Some(GroupSignal::NotFound);
                continue;
            }
            // The boot id half of the identity is checked here too: this gate
            // runs immediately before the root's (or group's) signal.
            let root_runs = if has_identity(root, expected) {
                !matches!(observe(proc_root, root), Seen::Exiting(_))
            } else if observe(proc_root, root) == Seen::Gone {
                // A root that waited on the descendants just signaled can
                // exit, and be reaped, on its own: the outcome asked for.
                false
            } else {
                // Only a live mismatch or an unreadable root refuses.
                return Err(
                    "seat root identity changed or became unreadable before its signal".into(),
                );
            };
            if !root_runs {
                // Gone or exiting: the root itself gets no signal.
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
    Err(sweep.verdict(&members, left))
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

/// What one stat read returned.
enum Raw {
    Missing,
    Unreadable,
    Read,
}

/// Read one stat file into `buffer`. Err only when it exceeds the hard cap.
fn read_raw(path: &Path, buffer: &mut Vec<u8>) -> Result<Raw, &'static str> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Raw::Missing),
        Err(_) => return Ok(Raw::Unreadable),
    };
    buffer.clear();
    if let Err(error) = file.take((MAX_STAT_BYTES + 1) as u64).read_to_end(buffer) {
        // A task released after the open reads back ESRCH.
        return Ok(if error.raw_os_error() == Some(libc::ESRCH) {
            Raw::Missing
        } else {
            Raw::Unreadable
        });
    }
    if buffer.len() > MAX_STAT_BYTES {
        return Err("process stat exceeds the safety limit");
    }
    Ok(Raw::Read)
}

/// One thread's state from its stat line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Thread {
    /// Zombie or dead.
    Dead,
    /// `PF_EXITING`: in do_exit, never to run user code again.
    Exiting,
    Running,
}

fn thread_of(stat: &str) -> Option<Thread> {
    if proc_stat_is_dead(stat) {
        return Some(Thread::Dead);
    }
    // Fields after the final `) ` begin at field 3 (`state`); the flags
    // (field 9) are index 6. A malformed line has no state either.
    let flags: u64 = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(6)?
        .parse()
        .ok()?;
    Some(if flags & PF_EXITING != 0 {
        Thread::Exiting
    } else {
        Thread::Running
    })
}

enum Tids {
    Gone,
    Unreadable,
    Listed(Vec<u32>),
}

fn list_tids(task: &Path) -> Tids {
    let entries = match std::fs::read_dir(task) {
        Ok(entries) => entries,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            return Tids::Gone;
        }
        Err(_) => return Tids::Unreadable,
    };
    let mut tids = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_THREADS {
            return Tids::Unreadable;
        }
        let Ok(entry) = entry else {
            return Tids::Unreadable;
        };
        if let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        {
            tids.push(tid);
        }
    }
    tids.sort_unstable();
    Tids::Listed(tids)
}

/// Classify a process whose leader thread is dead or exiting from its whole
/// thread set: list `task/`, read every thread, list again. Any running
/// thread proves it Live (a zombie leader can front live threads); all dead
/// is Gone; dead or exiting is Exiting; listings that differ are Unknown.
fn thread_set(task: &Path, fact: ProcFact) -> Result<Seen, &'static str> {
    let first = match list_tids(task) {
        Tids::Gone => return Ok(Seen::Gone),
        Tids::Unreadable => return Ok(Seen::Unknown),
        Tids::Listed(tids) => tids,
    };
    let mut buffer = Vec::with_capacity(512);
    let mut path = task.to_path_buf();
    let mut exiting = false;
    for tid in &first {
        path.clear();
        path.push(task);
        path.push(tid.to_string());
        path.push("stat");
        match read_raw(&path, &mut buffer)? {
            // Released between the listings; the second listing settles it.
            Raw::Missing => continue,
            Raw::Unreadable => return Ok(Seen::Unknown),
            Raw::Read => {}
        }
        match thread_of(&String::from_utf8_lossy(&buffer)) {
            Some(Thread::Running) => return Ok(Seen::Live(fact)),
            Some(Thread::Exiting) => exiting = true,
            Some(Thread::Dead) => {}
            None => return Ok(Seen::Unknown),
        }
    }
    Ok(match list_tids(task) {
        Tids::Gone => Seen::Gone,
        Tids::Listed(second) if second == first => {
            if exiting {
                Seen::Exiting(fact)
            } else {
                Seen::Gone
            }
        }
        Tids::Listed(_) | Tids::Unreadable => Seen::Unknown,
    })
}

/// Classify `pid` from its leader's stat line: a running leader is Live at
/// once, otherwise the thread set decides.
fn classify_stat(proc_root: &Path, pid: u32, stat: &str) -> Result<Seen, &'static str> {
    let leader = thread_of(stat);
    let Some(fact) = parse_stat(pid, stat) else {
        // A released leader can lose its group before its entry goes; only
        // its dead state settles it.
        return Ok(if leader == Some(Thread::Dead) {
            Seen::Gone
        } else {
            Seen::Unknown
        });
    };
    match leader {
        None => Ok(Seen::Unknown),
        Some(Thread::Running) => Ok(Seen::Live(fact)),
        Some(Thread::Dead | Thread::Exiting) => {
            thread_set(&proc_root.join(pid.to_string()).join("task"), fact)
        }
    }
}

fn observe(proc_root: &Path, pid: u32) -> Seen {
    let mut buffer = Vec::with_capacity(512);
    let path = proc_root.join(pid.to_string()).join("stat");
    match read_raw(&path, &mut buffer) {
        Ok(Raw::Missing) => Seen::Gone,
        Ok(Raw::Read) => {
            // comm can contain non-UTF-8 bytes. Replacing those bytes keeps
            // the ASCII fields parsed after its final closing parenthesis.
            classify_stat(proc_root, pid, &String::from_utf8_lossy(&buffer))
                .unwrap_or(Seen::Unknown)
        }
        Ok(Raw::Unreadable) | Err(_) => Seen::Unknown,
    }
}

/// `pid`'s state from its whole thread set. With `expected_start`, a PID now
/// naming a different incarnation is Gone. Unknown is never Gone: callers
/// fail closed on it.
pub(crate) fn linux_state(pid: u32, expected_start: Option<u64>) -> ProcState {
    state_of(observe(Path::new("/proc"), pid), expected_start)
}

/// Whether `pid` is an unreaped zombie: its leader reads Z and every thread
/// in two matching listings is dead. False for a zombie leader fronting a
/// live or exiting thread, for a released or absent PID, and for anything
/// unreadable.
pub(crate) fn linux_is_zombie(pid: u32) -> bool {
    is_zombie_at(Path::new("/proc"), pid)
}

fn is_zombie_at(proc_root: &Path, pid: u32) -> bool {
    let dir = proc_root.join(pid.to_string());
    let mut buffer = Vec::with_capacity(512);
    if !matches!(read_raw(&dir.join("stat"), &mut buffer), Ok(Raw::Read))
        || !proc_stat_is_zombie(&String::from_utf8_lossy(&buffer))
    {
        return false;
    }
    let task = dir.join("task");
    let Tids::Listed(first) = list_tids(&task) else {
        return false;
    };
    let mut path = task.clone();
    let all_dead = !first.is_empty()
        && first.iter().all(|tid| {
            path.clear();
            path.push(&task);
            path.push(tid.to_string());
            path.push("stat");
            matches!(read_raw(&path, &mut buffer), Ok(Raw::Read))
                && thread_of(&String::from_utf8_lossy(&buffer)) == Some(Thread::Dead)
        });
    all_dead && matches!(list_tids(&task), Tids::Listed(second) if second == first)
}

fn state_of(seen: Seen, expected_start: Option<u64>) -> ProcState {
    match seen {
        Seen::Gone => ProcState::Gone,
        Seen::Unknown => ProcState::Unknown,
        Seen::Live(fact) | Seen::Exiting(fact)
            if expected_start.is_some_and(|start| start != fact.start) =>
        {
            ProcState::Gone
        }
        Seen::Live(_) => ProcState::Live,
        Seen::Exiting(_) => ProcState::Exiting,
    }
}

/// One bounded pass over procfs. Exits race the scan and unreadable entries
/// are skipped; neither authorizes a PID absent from the snapshot. A dead
/// leader stays in the snapshot unless its thread set proves it gone.
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
        if !matches!(read_raw(&stat_path, &mut buffer)?, Raw::Read) {
            continue;
        }
        let stat = String::from_utf8_lossy(&buffer);
        match classify_stat(proc_root, pid, &stat)? {
            Seen::Live(fact) | Seen::Exiting(fact) => facts.push(fact),
            // Fail closed: an unreadable thread set may hide live threads.
            Seen::Unknown => facts.extend(parse_stat(pid, &stat)),
            Seen::Gone => {}
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

    /// A fake `/proc/<pid>` whose leader and threads have the given state
    /// letters and flags.
    fn fake_process(root: &Path, pid: u32, leader: (&str, u64), threads: &[(u32, &str, u64)]) {
        let line = |tid: u32, (state, flags): (&str, u64)| {
            format!("{tid} (p) {state} 7 40 40 0 -1 {flags} 1 2 3 4 5 6 7 8 20 0 1 0 98765")
        };
        let dir = root.join(pid.to_string());
        std::fs::create_dir_all(dir.join("task")).unwrap();
        std::fs::write(dir.join("stat"), line(pid, leader)).unwrap();
        for &(tid, state, flags) in threads {
            let thread = dir.join("task").join(tid.to_string());
            std::fs::create_dir_all(&thread).unwrap();
            std::fs::write(thread.join("stat"), line(tid, (state, flags))).unwrap();
        }
    }

    #[test]
    fn the_thread_set_decides_live_exiting_gone_and_unknown() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let exiting = PF_EXITING | 0x40;
        // A zombie leader fronting a sleeping thread is alive.
        fake_process(
            root,
            50,
            ("Z", exiting),
            &[(50, "Z", exiting), (51, "S", 0x40)],
        );
        // Every thread dead or in do_exit: exiting, not yet gone.
        fake_process(
            root,
            60,
            ("R", exiting),
            &[(60, "R", exiting), (61, "D", exiting)],
        );
        fake_process(
            root,
            62,
            ("Z", exiting),
            &[(62, "Z", exiting), (63, "R", exiting)],
        );
        // Every thread dead: gone. An empty or missing thread set: gone.
        fake_process(root, 70, ("Z", exiting), &[(70, "Z", exiting)]);
        fake_process(root, 71, ("Z", exiting), &[]);
        fake_process(root, 72, ("X", exiting), &[]);
        std::fs::remove_dir(root.join("72/task")).unwrap();
        // A thread whose stat can't be read, or reads malformed: unknown.
        fake_process(root, 80, ("Z", exiting), &[(80, "Z", exiting)]);
        std::fs::create_dir_all(root.join("80/task/81/stat")).unwrap();
        fake_process(root, 82, ("R", exiting), &[(82, "R", exiting)]);
        std::fs::create_dir_all(root.join("82/task/83")).unwrap();
        std::fs::write(root.join("82/task/83/stat"), "83 (p) S 7 nope").unwrap();
        // A running leader is live without reading its threads.
        fake_process(root, 90, ("S", 0x40), &[]);
        std::fs::create_dir_all(root.join("90/task/91/stat")).unwrap();

        let fact = |pid| fact(pid, 7, 40, 98765);
        assert_eq!(observe(root, 50), Seen::Live(fact(50)));
        assert_eq!(observe(root, 60), Seen::Exiting(fact(60)));
        assert_eq!(observe(root, 62), Seen::Exiting(fact(62)));
        assert_eq!(observe(root, 70), Seen::Gone);
        assert_eq!(observe(root, 71), Seen::Gone);
        assert_eq!(observe(root, 72), Seen::Gone);
        assert_eq!(observe(root, 80), Seen::Unknown);
        assert_eq!(observe(root, 82), Seen::Unknown);
        assert_eq!(observe(root, 90), Seen::Live(fact(90)));

        // The exported view, with and without the identity gate.
        assert_eq!(state_of(Seen::Live(fact(50)), Some(98765)), ProcState::Live);
        assert_eq!(state_of(Seen::Live(fact(50)), Some(1)), ProcState::Gone);
        assert_eq!(state_of(Seen::Exiting(fact(60)), None), ProcState::Exiting);
        assert_eq!(state_of(Seen::Exiting(fact(60)), Some(1)), ProcState::Gone);
        assert_eq!(state_of(Seen::Unknown, Some(98765)), ProcState::Unknown);
        assert_eq!(state_of(Seen::Gone, None), ProcState::Gone);

        // A zombie is positively a dead thread set behind a Z leader: not a
        // Z leader with live or exiting threads, not absent, not unreadable.
        assert!(is_zombie_at(root, 70));
        assert!(!is_zombie_at(root, 50), "live thread behind Z");
        assert!(!is_zombie_at(root, 62), "exiting thread behind Z");
        assert!(!is_zombie_at(root, 71), "empty thread set: released");
        assert!(!is_zombie_at(root, 72), "X, not Z");
        assert!(!is_zombie_at(root, 80), "unreadable thread");
        assert!(!is_zombie_at(root, 99), "absent");
        assert!(!is_zombie_at(root, 60), "running leader");
    }

    #[test]
    fn an_exiting_member_is_never_signaled_but_survives_until_gone() {
        let member = Member {
            pid: 60,
            start: 98765,
            depth: 1,
            in_group: false,
            carrier: false,
        };
        let exiting = Seen::Exiting(fact(60, 7, 40, 98765));
        assert!(!is_captured(&member, exiting));
        assert!(!signal_proof(
            &member,
            exiting,
            &[],
            || EnvRead::Absent,
            || true
        ));
        assert_eq!(survivors(&[member], |_| exiting), vec![60]);
        assert!(survivors(&[member], |_| Seen::Gone).is_empty());
        let reused = Seen::Exiting(fact(60, 7, 40, 1));
        assert!(survivors(&[member], |_| reused).is_empty());
    }

    #[test]
    fn a_verdict_names_refusals_and_members_still_exiting() {
        let refusal = Some(KillError::Refused("61 is foreign".into()));
        assert_eq!(verdict(None, &[], vec![60]), KillError::Survivors(vec![60]));
        assert_eq!(
            verdict(None, &[60], vec![60, 61]),
            KillError::Unconfirmed {
                reason: "exiting: 60".into(),
                survivors: vec![60, 61],
            }
        );
        assert_eq!(
            verdict(refusal, &[60], vec![60, 61]),
            KillError::Unconfirmed {
                reason: "61 is foreign; exiting: 60".into(),
                survivors: vec![60, 61],
            }
        );
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

    /// The captured incarnation's start while it is still present, running
    /// or exiting.
    fn start_of(pid: u32) -> Option<u64> {
        match observe(Path::new("/proc"), pid) {
            Seen::Live(fact) | Seen::Exiting(fact) => Some(fact.start),
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
    fn a_root_that_exits_and_is_reaped_before_its_own_signal_is_success() {
        // Anchor -> root shell -> sleeper. The anchor reaps the root at once.
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
        // `authorize` runs after the capture and before any signal: end and
        // reap the root there, the way a root that waited on its signaled
        // descendants exits on its own, so it is gone at its own signal.
        let mut ended = false;
        let result = terminate(
            root,
            &identity(root).unwrap(),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                if pid == root && !ended {
                    ended = true;
                    // SAFETY: the root shell this test spawned, still live.
                    unsafe { libc::kill(root as libc::pid_t, libc::SIGKILL) };
                    let deadline = Instant::now() + Duration::from_secs(5);
                    // Reaped, not merely a zombie: a zombie keeps its
                    // identity and can still take a signal.
                    while Path::new(&format!("/proc/{root}")).exists() {
                        assert!(Instant::now() < deadline, "root was never reaped");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                Ok(())
            },
        );
        assert_eq!(result, Ok(GroupSignal::NotFound));
        assert!(
            tree.iter()
                .filter(|member| member.pid != group)
                .all(|member| !running(member))
        );
        drop(fixture);
    }

    #[test]
    fn a_leader_root_reaped_before_its_signal_still_gets_its_group_signaled() {
        // Anchor -> root (setsid: its own session and group) -> sleeper in
        // the root's group. The anchor reaps the root at once.
        let anchor = spawn("setsid sh -c 'sleep 30 & wait' & wait; exec sleep 30", 0);
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
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(observe(Path::new("/proc"), root), Seen::Live(fact) if fact.pgrp == root) {
            assert!(Instant::now() < deadline, "root never led its own group");
            std::thread::sleep(Duration::from_millis(5));
        }
        // The sleeper left the anchor's group with the root, so the fixture
        // can't reach it; this kills it only while it is that incarnation.
        let sleeper = tree
            .iter()
            .find(|member| member.depth == 2)
            .expect("sleeper");
        let stray = Stray {
            pid: sleeper.pid,
            start: sleeper.start,
        };

        let mut ended = false;
        let began = Instant::now();
        let result = terminate(
            root,
            &identity(root).unwrap(),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                if pid == root && !ended {
                    ended = true;
                    // SAFETY: the root shell this test spawned, still live.
                    unsafe { libc::kill(root as libc::pid_t, libc::SIGKILL) };
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while Path::new(&format!("/proc/{root}")).exists() {
                        assert!(Instant::now() < deadline, "root was never reaped");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                Ok(())
            },
        );
        assert_eq!(result, Ok(GroupSignal::NotFound));
        assert!(!running(sleeper));
        // The group got per-PID SIGTERMs at once, not SIGKILL after the
        // whole TERM budget.
        assert!(began.elapsed() < TERM_WAIT, "{:?}", began.elapsed());
        drop(stray);
        drop(fixture);
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
        assert!(
            reason.starts_with(char::is_numeric) && reason.contains("is foreign"),
            "{reason}"
        );
        let refused: u32 = reason.split(' ').next().unwrap().parse().unwrap();
        let limit = cutoff.get().unwrap();
        // Every survivor is a refused late fork, still running unsignaled;
        // everything authorized is gone.
        assert!(survivors.contains(&refused), "{survivors:?}");
        assert!(
            survivors
                .iter()
                .all(|pid| start_of(*pid).is_some_and(|start| start > limit)),
            "{survivors:?}"
        );
        drop(fixture);
    }

    #[test]
    fn a_refusal_is_moot_only_for_a_gone_reused_or_exiting_member() {
        let member = Member {
            pid: 20,
            start: 110,
            depth: 1,
            in_group: false,
            carrier: false,
        };
        assert!(refusal_moot(&member, Seen::Gone), "exited or zombie");
        assert!(
            refusal_moot(&member, Seen::Live(fact(20, 1, 20, 111))),
            "reused"
        );
        assert!(
            refusal_moot(&member, Seen::Exiting(fact(20, 1, 20, 110))),
            "exiting"
        );
        assert!(
            !refusal_moot(&member, Seen::Live(fact(20, 1, 20, 110))),
            "live"
        );
        assert!(!refusal_moot(&member, Seen::Unknown), "unreadable");
    }

    /// Kill a test-owned leader root whose `authorize` refuses `victim`'s
    /// PID after ending it: SIGKILL, then wait until a fresh read shows it
    /// gone (reaped by a shell parent, or a zombie under an exec'd one).
    fn kill_refusing_an_ended_member(
        script: &str,
    ) -> (Result<GroupSignal, KillError>, Vec<Member>) {
        let leader = spawn(script, 0);
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        let tree = captured(root, 2);
        let victim = tree.iter().find(|member| member.pid != root).unwrap().pid;
        let result = terminate(
            root,
            &identity(root).unwrap(),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                if pid != victim {
                    return Ok(());
                }
                // SAFETY: the test's own sleeper, still live.
                unsafe { libc::kill(victim as libc::pid_t, libc::SIGKILL) };
                let deadline = Instant::now() + Duration::from_secs(5);
                while observe(Path::new("/proc"), victim) != Seen::Gone {
                    assert!(Instant::now() < deadline, "victim never ended");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(KillError::Unconfirmed {
                    reason: "not signaled: identity unreadable".into(),
                    survivors: vec![victim],
                })
            },
        );
        drop(fixture);
        (result, tree)
    }

    #[test]
    fn a_member_that_exits_before_its_refusal_is_rechecked_is_gone() {
        // The root execs sleep after its child dies and is reaped.
        let (result, tree) = kill_refusing_an_ended_member("sleep 30 & wait; exec sleep 30");
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert!(tree.iter().all(|member| !running(member)));
    }

    #[test]
    fn a_zombie_member_behind_a_refusal_is_gone() {
        // The exec'd root never reaps, so the killed child stays a zombie.
        let (result, tree) = kill_refusing_an_ended_member("sleep 30 & exec sleep 30");
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert!(tree.iter().all(|member| !running(member)));
    }

    /// PF_EXITING on a live (not zombie or dead) leader, read straight from
    /// procfs, independent of the classifier under test.
    fn exiting_now(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                let fields: Vec<&str> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
                let dead = matches!(fields.first()?.as_bytes(), [b'Z' | b'X' | b'x']);
                Some(!dead && fields.get(6)?.parse::<u64>().ok()? & 0x4 != 0)
            })
            .unwrap_or(false)
    }

    #[test]
    fn a_refusal_on_an_exiting_member_is_dropped_and_it_is_confirmed_once_gone() {
        // ~1 GiB of touched memory keeps the child in do_exit for ~150 ms
        // after its SIGKILL: long enough to recheck it while it exits.
        let leader = spawn(
            "python3 -c 'import time; b = bytearray(1 << 30); \
             b[::4096] = bytes([1]) * (1 << 18); time.sleep(30)' & wait",
            0,
        );
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        let tree = captured(root, 2);
        let child = tree.iter().find(|member| member.pid != root).unwrap().pid;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let rss_kib = std::fs::read_to_string(format!("/proc/{child}/status"))
                .ok()
                .and_then(|status| {
                    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
                    line.split_whitespace().nth(1)?.parse::<u64>().ok()
                });
            if rss_kib.is_some_and(|kib| kib >= 1 << 20) {
                break;
            }
            assert!(Instant::now() < deadline, "child never touched its memory");
            std::thread::sleep(Duration::from_millis(20));
        }
        let child_start = start_of(child).unwrap();

        // Its argv reads empty once its memory is released, so authorize
        // refuses it while it exits: the frontend's flake (b).
        let mut caught = false;
        let result = terminate(
            root,
            &identity(root).unwrap(),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                if pid != child {
                    return Ok(());
                }
                // SAFETY: this test's own child, still live.
                unsafe { libc::kill(child as libc::pid_t, libc::SIGKILL) };
                let deadline = Instant::now() + Duration::from_secs(2);
                while !exiting_now(child) && Instant::now() < deadline {
                    std::hint::spin_loop();
                }
                caught = exiting_now(child);
                Err(KillError::Unconfirmed {
                    reason: "not signaled: identity unreadable".into(),
                    survivors: vec![child],
                })
            },
        );
        assert!(caught, "the child was never seen exiting");
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert_ne!(
            start_of(child),
            Some(child_start),
            "child never confirmed gone"
        );
        drop(fixture);
    }

    #[test]
    fn preflight_drops_a_refusal_only_on_an_exiting_or_gone_member() {
        let root = tempfile::tempdir().unwrap();
        let exiting = PF_EXITING | 0x40;
        fake_process(root.path(), 60, ("R", exiting), &[(60, "R", exiting)]);
        fake_process(root.path(), 61, ("S", 0x40), &[]);
        let member = |pid| Member {
            pid,
            start: 98765,
            depth: 1,
            in_group: false,
            carrier: false,
        };
        let preflight = |members: &[Member]| {
            let mut sweep = Sweep {
                proc_root: root.path(),
                root_start: 1,
                lineage: Lineage::of(&[], 10),
                bound_ids: &[],
                process_id_of: |_| EnvRead::Absent,
                eligible: |_| true,
                authorize: |pid| Err(KillError::Refused(format!("{pid} unreadable"))),
                refused: HashSet::new(),
                refusal: None,
            };
            sweep.preflight(members)
        };
        // 60 is exiting and 62 is gone: both refusals are moot.
        assert_eq!(
            preflight(&[member(60), member(62)]),
            Ok(HashSet::from([60, 62]))
        );
        // 61 is live: its refusal stands.
        assert_eq!(
            preflight(&[member(60), member(61)]),
            Err(KillError::Refused("61 unreadable".into()))
        );
    }

    #[test]
    fn a_late_refusal_reports_the_final_survivors_not_an_instant_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("trapped");
        // T delays its exit a second after its SIGTERM; the root itself
        // ignores TERM and forks a sleeper every 50ms.
        let script = format!(
            "trap '' TERM; python3 -c 'import os, signal, sys, time; \
             signal.signal(signal.SIGTERM, lambda *_: (time.sleep(1), sys.exit(0))); \
             open(\"{}\", \"w\").write(str(os.getpid())); time.sleep(30)' & \
             while :; do sleep 30 & sleep 0.05; done",
            pidfile.display()
        );
        let leader = spawn(&script, 0);
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let trapped: u32 = loop {
            if let Some(pid) = std::fs::read_to_string(&pidfile)
                .ok()
                .and_then(|text| text.trim().parse().ok())
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "trapped child never started");
            std::thread::sleep(Duration::from_millis(10));
        };
        let trapped_start = start_of(trapped).unwrap();
        captured(root, 3);
        // Authorization is fixed at its first call: anything started after
        // it is foreign, so the first late fork is refused.
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
        assert!(reason.contains("is foreign"), "{reason}");
        // T was still exiting when the refusal came; the report is taken at
        // the deadline, when T is long gone.
        assert!(!survivors.contains(&trapped), "{survivors:?}");
        assert_ne!(start_of(trapped), Some(trapped_start), "T survived");
        drop(fixture);
    }

    #[test]
    fn a_zombie_leader_fronting_a_live_thread_is_captured_and_signaled() {
        // The child's main thread exits alone (SYS_exit, not exit_group)
        // while a second thread sleeps: its leader reads Z, it is alive. It
        // runs in its own session, so only a per-PID signal reaches it.
        let leader = spawn(
            "setsid python3 -c 'import ctypes, threading, time; \
             threading.Thread(target=time.sleep, args=(30,), daemon=True).start(); \
             time.sleep(0.1); ctypes.CDLL(None).syscall(60, 0)' & wait",
            0,
        );
        let root = leader.id();
        let fixture = Fixture {
            group: root,
            children: vec![leader],
        };
        let tree = captured(root, 2);
        let child = tree.iter().find(|member| member.pid != root).unwrap();
        let stray = Stray {
            pid: child.pid,
            start: child.start,
        };
        let child = child.pid;
        let deadline = Instant::now() + Duration::from_secs(10);
        let thread = loop {
            let leader_state = std::fs::read_to_string(format!("/proc/{child}/stat"))
                .ok()
                .and_then(|stat| stat.rsplit_once(") ")?.1.as_bytes().first().copied());
            let others: Vec<u32> = std::fs::read_dir(format!("/proc/{child}/task"))
                .map(|entries| {
                    entries
                        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
                        .filter(|tid| *tid != child)
                        .collect()
                })
                .unwrap_or_default();
            if leader_state == Some(b'Z') && others.len() == 1 {
                break others[0];
            }
            assert!(
                Instant::now() < deadline,
                "the leader thread never exited alone"
            );
            std::thread::sleep(Duration::from_millis(10));
        };

        let result = terminate_tree(root, &identity(root).unwrap());
        assert_eq!(result, Ok(GroupSignal::Sent));
        // Independent of the classifier: the live thread itself goes away
        // (allow it a moment to be released after it is confirmed dead).
        let thread_dir = format!("/proc/{child}/task/{thread}");
        let deadline = Instant::now() + Duration::from_secs(1);
        while Path::new(&thread_dir).exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!Path::new(&thread_dir).exists(), "the live thread survived");
        drop(stray);
        drop(fixture);
    }
}
