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

use super::kill_group::capture_members;
use super::process::{
    GroupSignal, KILL_WAIT, KillError, POLL_STEP, TERM_WAIT, UNSIGNALED_CARRIER_LIMIT,
    UnsignaledCarrier, UnsignaledCarriers, has_identity, proc_stat_group_id, proc_stat_is_dead,
    proc_stat_is_zombie, signal_group, signal_pid,
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

/// A leader's killpg must reach exactly what was captured. The shared group
/// enumeration (live and exiting members) is checked against the capture:
/// every PID it reports is captured already, captured now, or proven gone.
/// Returns whether killpg may still run: not when the group holds any member
/// the capture didn't have, exiting ones included; those join the set and
/// everything is signaled per PID instead.
fn verify_group(proc_root: &Path, root: u32, members: &mut Vec<Member>) -> Result<bool, String> {
    let scanned: Vec<u32> = capture_members(root)?
        .into_iter()
        .map(|member| member.pid)
        .collect();
    reconcile_group(root, members, &scanned, |pid| observe(proc_root, pid))
}

/// [`verify_group`]'s decision over a group scan and fresh reads.
fn reconcile_group(
    root: u32,
    members: &mut Vec<Member>,
    scanned: &[u32],
    mut observe: impl FnMut(u32) -> Seen,
) -> Result<bool, String> {
    let captured: HashMap<u32, Member> =
        members.iter().map(|member| (member.pid, *member)).collect();
    let mut complete = true;
    for &pid in scanned {
        if let Some(member) = group_member(root, pid, captured.get(&pid), observe(pid))? {
            if members.len() >= MAX_TREE_PROCESSES {
                return Err("seat root's process group exceeds the size limit".into());
            }
            complete = false;
            members.push(member);
        }
    }
    Ok(complete)
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
    /// New carrier births rejected during this kill stay out of scope even
    /// if they later reparent. Captured members never enter this set.
    rejected_carriers: HashMap<(u32, u64), ProcFact>,
    /// Only the first ten unique rejections need names for their notices.
    pending_notices: Vec<(ProcFact, ProcFact)>,
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
            rejected_carriers: HashMap::new(),
            pending_notices: Vec::new(),
        }
    }

    fn excluding(self, excluded: &'a [u32]) -> Self {
        Lineage { excluded, ..self }
    }

    fn spares(&self, pid: u32) -> bool {
        self.excluded.contains(&pid)
    }

    fn reject_carrier(&mut self, candidate: ProcFact, launcher: ProcFact) {
        if self
            .rejected_carriers
            .insert((candidate.pid, candidate.start), launcher)
            .is_none()
            && self.rejected_carriers.len() <= UNSIGNALED_CARRIER_LIMIT
        {
            self.pending_notices.push((candidate, launcher));
        }
    }
}

/// A new carrier may have been adopted by a non-seat process. Stop at that
/// boundary (or init); below a same-id excluded ancestor, ownership is not
/// proven. Return that ancestor for an unsignaled notice. Missing/invalid
/// facts or an unreadable parent id prove neither adoption nor ownership.
fn carrier_ancestry(
    by_pid: &HashMap<u32, &ProcFact>,
    candidate: &ProcFact,
    lineage: &Lineage,
    bound_ids: &[String],
    process_id_of: &mut impl FnMut(u32) -> EnvRead,
) -> Result<Option<ProcFact>, &'static str> {
    let mut current = candidate;
    for _ in 0..MAX_TREE_DEPTH {
        if current.ppid <= 1 {
            return Ok(None);
        }
        let Some(parent) = by_pid.get(&current.ppid).copied() else {
            #[cfg(test)]
            eprintln!(
                "HCOM106_ANCESTRY_DIAGNOSTIC reason=missing_snapshot_parent candidate={candidate:?} current={current:?} parent_pid={} fresh_parent_stat={:?} fresh_current_stat={:?}",
                current.ppid,
                std::fs::read_to_string(format!("/proc/{}/stat", current.ppid))
                    .map(|stat| parse_stat(current.ppid, &stat)),
                std::fs::read_to_string(format!("/proc/{}/stat", current.pid))
                    .map(|stat| parse_stat(current.pid, &stat))
            );
            return Err("carrier ancestry is unreadable or invalid");
        };
        if parent.start > current.start {
            #[cfg(test)]
            eprintln!(
                "HCOM106_ANCESTRY_DIAGNOSTIC reason=parent_birth_after_child candidate={candidate:?} current={current:?} parent={parent:?}"
            );
            return Err("carrier ancestry is unreadable or invalid");
        }
        if let Some(launcher) = lineage.rejected_carriers.get(&(parent.pid, parent.start)) {
            return Ok(Some(*launcher));
        }
        // A child born below a rejected carrier and orphaned entirely
        // between scans was never observed there. Its own current chain
        // and seat id decide admission; no historical edge is invented.
        match process_id_of(parent.pid) {
            EnvRead::Unreadable => {
                #[cfg(test)]
                eprintln!(
                    "HCOM106_ANCESTRY_DIAGNOSTIC reason=parent_env_unreadable candidate={candidate:?} current={current:?} parent={parent:?} fresh_parent_stat={:?} fresh_current_stat={:?}",
                    std::fs::read_to_string(format!("/proc/{}/stat", parent.pid))
                        .map(|stat| parse_stat(parent.pid, &stat)),
                    std::fs::read_to_string(format!("/proc/{}/stat", current.pid))
                        .map(|stat| parse_stat(current.pid, &stat))
                );
                return Err("carrier ancestry is unreadable or invalid");
            }
            EnvRead::Absent => return Ok(None),
            EnvRead::Present(id) if id.is_empty() || !bound_ids.contains(&id) => return Ok(None),
            EnvRead::Present(_) => {}
        }
        // hcom never sets PR_SET_CHILD_SUBREAPER on its id-carrying
        // launchers/runners. Non-hcom id-carrying ancestors can adopt too,
        // so report this branch rather than silently treating it as owned.
        // If hcom ever sets that bit, revisit this admission rule.
        if lineage.ancestors.contains(&parent.pid) || lineage.spares(parent.pid) {
            return Ok(Some(*parent));
        }
        current = parent;
    }
    #[cfg(test)]
    eprintln!(
        "HCOM106_ANCESTRY_DIAGNOSTIC reason=depth_exhausted candidate={candidate:?} current={current:?} MAX_TREE_DEPTH={MAX_TREE_DEPTH}"
    );
    Err("carrier ancestry is unreadable or invalid")
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

#[derive(Debug, Default, PartialEq, Eq)]
struct Absorbed {
    found: Vec<Member>,
    unconfirmed: Vec<Member>,
}

/// From one snapshot, the processes the capture hasn't seen yet:
/// - descendants of a tree member still running as its captured incarnation,
///   through edges whose child is no older than its parent;
/// - restricted carriers: live processes outside the tree and the root's
///   ancestry that carry one of `bound_ids` and pass `eligible`. None predates
///   the root; a same-tick one needs the root's complete capture lineage.
///   Its parent chain must reach init or a non-bound-id adoption boundary
///   before any same-id excluded ancestor. An unreadable/invalid chain is
///   Unconfirmed, never authority to signal.
///
/// Valid discoveries and uncertain native births are returned together;
/// initial capture and late settlement apply their different refusal policy.
///
/// Ineligible tree candidates are fenced with their whole subtree; nothing
/// under a fence is admitted. Rejected carrier births stay out of scope for
/// this kill, even after reparenting. Captured members retain their native
/// identity proof regardless of later ancestry. Rescans reuse these rules.
fn absorb(
    snapshot: &[ProcFact],
    root_start: u64,
    lineage: &mut Lineage,
    members: &[Member],
    bound_ids: &[String],
    mut process_id_of: impl FnMut(u32) -> EnvRead,
    mut eligible: impl FnMut(u32) -> bool,
) -> Result<Absorbed, KillError> {
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
                || lineage
                    .rejected_carriers
                    .contains_key(&(child.pid, child.start))
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
                return Err("seat's captured processes exceed the size limit".into());
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
        return Ok(Absorbed {
            found,
            unconfirmed: Vec::new(),
        });
    }
    let by_pid: HashMap<u32, &ProcFact> = snapshot.iter().map(|fact| (fact.pid, fact)).collect();
    let mut unconfirmed = Vec::new();
    for fact in snapshot {
        if fact.pid <= 1
            || fact.start < root_start
            || captured.contains_key(&fact.pid)
            || seen.contains(&fact.pid)
            || lineage
                .rejected_carriers
                .contains_key(&(fact.pid, fact.start))
            || lineage.ancestors.contains(&fact.pid)
            || lineage.spares(fact.pid)
            || under_fence(&by_pid, fact.pid, &lineage.fenced)
        {
            continue;
        }
        if fact.start == root_start && !lineage.complete {
            continue;
        }
        if !has_bound_id(process_id_of(fact.pid), bound_ids) || !eligible(fact.pid) {
            continue;
        }
        match carrier_ancestry(&by_pid, fact, lineage, bound_ids, &mut process_id_of) {
            Ok(Some(launcher)) => {
                lineage.reject_carrier(*fact, launcher);
                continue;
            }
            Err(_) => {
                if members.len() + found.len() + unconfirmed.len() >= MAX_TREE_PROCESSES {
                    return Err("seat's captured processes exceed the size limit".into());
                }
                unconfirmed.push(Member {
                    pid: fact.pid,
                    start: fact.start,
                    depth: 0,
                    in_group: false,
                    carrier: true,
                });
                continue;
            }
            Ok(None) => {}
        }
        if members.len() + found.len() + unconfirmed.len() >= MAX_TREE_PROCESSES {
            return Err("seat's captured processes exceed the size limit".into());
        }
        found.push(Member {
            pid: fact.pid,
            start: fact.start,
            depth: 0,
            in_group: false,
            carrier: true,
        });
    }
    Ok(Absorbed { found, unconfirmed })
}

/// Best-effort diagnostic text only; a name never authorizes a signal.
fn notice_comm(proc_root: &Path, pid: u32) -> String {
    let Ok(mut comm) = std::fs::read_to_string(proc_root.join(format!("{pid}/comm"))) else {
        return "<unknown>".into();
    };
    comm.truncate(comm.trim_end_matches('\n').len());
    if comm.is_empty() {
        "<unknown>".into()
    } else {
        comm
    }
}

/// The capture-time facts and injected proofs a kill reuses for every
/// per-PID signal and every rescan.
struct Sweep<'a, P, E, A> {
    proc_root: &'a Path,
    root_start: u64,
    lineage: Lineage<'a>,
    bound_ids: &'a [String],
    not_signaled: &'a mut UnsignaledCarriers,
    signal_sent: &'a std::cell::Cell<bool>,
    process_id_of: P,
    eligible: E,
    authorize: A,
    /// Late members refused by `authorize`, and everything below them:
    /// never signaled, still confirmed.
    /// PID reuse can conservatively retain a refusal/false survivor, never authorize a signal.
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
    fn absorb(&mut self, snapshot: &[ProcFact], members: &[Member]) -> Result<Absorbed, KillError> {
        let rejected_before = self.lineage.rejected_carriers.len();
        let result = absorb(
            snapshot,
            self.root_start,
            &mut self.lineage,
            members,
            self.bound_ids,
            &mut self.process_id_of,
            &mut self.eligible,
        );
        self.not_signaled.total += self.lineage.rejected_carriers.len() - rejected_before;
        for (candidate, launcher) in self.lineage.pending_notices.drain(..) {
            if self.not_signaled.entries.len() >= UNSIGNALED_CARRIER_LIMIT {
                break;
            }
            self.not_signaled.entries.push(UnsignaledCarrier {
                launcher_pid: launcher.pid,
                launcher_comm: notice_comm(self.proc_root, launcher.pid),
                pid: candidate.pid,
                comm: notice_comm(self.proc_root, candidate.pid),
            });
        }
        result
    }

    /// Late uncertainty is a refusal to signal this birth and its subtree,
    /// not a reason to abandon other owned members before escalation.
    fn fence_uncertain(&mut self, snapshot: &[ProcFact], unconfirmed: &[Member]) {
        let by_parent = sorted_by_parent(snapshot);
        for member in unconfirmed {
            if refusal_moot(member, observe(self.proc_root, member.pid)) {
                continue;
            }
            fence_subtree(&by_parent, member.pid, &mut self.refused);
            self.refusal.get_or_insert_with(|| KillError::Unconfirmed {
                reason: "carrier ancestry is unreadable or invalid".into(),
                survivors: Vec::new(),
            });
        }
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
            let batch = match self.absorb(&snapshot, members) {
                Ok(batch) => batch,
                Err(error) => {
                    return Err(KillError::Unconfirmed {
                        reason: refusal_reason(error),
                        survivors: self.survivors(members),
                    });
                }
            };
            let fresh_start = members.len();
            members.extend(batch.found);
            let fresh_end = members.len();
            self.fence_uncertain(&snapshot, &batch.unconfirmed);
            members.extend(batch.unconfirmed);
            self.authorize_late(&snapshot, &members[fresh_start..fresh_end]);
            for member in &members[fresh_start..fresh_end] {
                // One PID absorbed from this round, authorized and just
                // re-proven; never a group signal.
                if self.proven(member)
                    && matches!(signal_pid(member.pid, signal), Ok(GroupSignal::Sent))
                {
                    self.signal_sent.set(true);
                }
            }
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

fn signal_phase_error(error: KillError, signal_sent: bool, not_signaled: &[u32]) -> KillError {
    if signal_sent {
        return error;
    }
    let (reason, mut pids) = match error {
        KillError::Refused(reason) => (reason, Vec::new()),
        KillError::Unconfirmed { reason, survivors } => (reason, survivors),
        KillError::Survivors(pids) => ("termination was not confirmed".into(), pids),
    };
    pids.extend_from_slice(not_signaled);
    pids.sort_unstable();
    pids.dedup();
    let mut reason = format!("no signal sent: {reason}");
    if !pids.is_empty() {
        use std::fmt::Write;
        reason.push_str("; not signaled:");
        for pid in pids {
            write!(reason, " {pid}").expect("formatting into a String cannot fail");
        }
    }
    KillError::Refused(reason)
}

fn terminate_body(
    (root, expected): (u32, &str),
    bound_ids: &[String],
    excluded: &[u32],
    process_id_of: impl FnMut(u32) -> EnvRead,
    mut eligible: impl FnMut(u32) -> bool,
    authorize: impl FnMut(u32) -> Result<(), KillError>,
    (not_signaled, sent, members): (
        &mut UnsignaledCarriers,
        &std::cell::Cell<bool>,
        &mut Vec<Member>,
    ),
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
    *members = capture(&snapshot, root, expected_start)?;
    let leader = members
        .iter()
        .any(|member| member.pid == root && member.in_group);
    // A group the capture didn't fully cover gets per-PID signals only.
    let group_complete = !leader || verify_group(proc_root, root, members)?;
    let mut lineage = Lineage::of(&snapshot, root).excluding(excluded);
    fence_ineligible(&snapshot, root, members, &mut lineage.fenced, &mut eligible);
    let mut group_signal =
        group_complete && group_signal_allowed(&snapshot, root, leader, &lineage, members);
    // The root's ancestors (its launch wrapper and everything above) are
    // never signaled, confirmed or walked through, even when they share its
    // group; excluded PIDs stay as anchors and are skipped at each signal.
    members.retain(|member| !lineage.ancestors.contains(&member.pid));
    let mut sweep = Sweep {
        proc_root,
        root_start: expected_start,
        lineage,
        bound_ids,
        not_signaled,
        signal_sent: sent,
        process_id_of,
        eligible,
        authorize,
        refused: HashSet::new(),
        refusal: None,
    };
    let batch = sweep.absorb(&snapshot, members)?;
    members.splice(0..0, batch.found);
    if !batch.unconfirmed.is_empty() {
        members.extend(batch.unconfirmed);
        return Err(KillError::Unconfirmed {
            reason: "carrier ancestry is unreadable or invalid".into(),
            survivors: sweep.survivors(members),
        });
    }
    let mooted = sweep.preflight(members)?;
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
    for member in members.iter() {
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
                        if sweep.proven(grouped)
                            && matches!(
                                signal_pid(grouped.pid, libc::SIGTERM),
                                Ok(GroupSignal::Sent)
                            )
                        {
                            sweep.signal_sent.set(true);
                        }
                    }
                }
                continue;
            }
            let outcome = if group_signal {
                // The verified leader's own group.
                signal_group(root, libc::SIGTERM)?
            } else {
                signal_pid(root, libc::SIGTERM)?
            };
            if outcome == GroupSignal::Sent {
                sweep.signal_sent.set(true);
            }
            root_signal = Some(outcome);
            continue;
        }
        if group_signal && member.in_group {
            continue;
        }
        if !sweep.proven(member) {
            continue;
        }
        // Capture never admits a reserved PID, and signal_pid refuses one
        // anyway. ESRCH means it is gone.
        if matches!(signal_pid(member.pid, libc::SIGTERM), Ok(GroupSignal::Sent)) {
            sweep.signal_sent.set(true);
        }
    }
    let root_signal = root_signal.ok_or("seat root is missing from the termination plan")?;

    if sweep.settle(members, TERM_WAIT, libc::SIGTERM)?.is_empty() {
        return Ok(root_signal);
    }
    // Escalate per PID, never by group: the leader may have exited, and only
    // a freshly re-proven captured incarnation is signaled, never a reuse.
    let signal_sent = sweep.signal_sent;
    for pid in escalation_targets(members, |member| sweep.proven(member)) {
        // A captured PID whose start time was just rechecked; ESRCH means it
        // exited in between.
        if matches!(signal_pid(pid, libc::SIGKILL), Ok(GroupSignal::Sent)) {
            signal_sent.set(true);
        }
    }
    let left = sweep.settle(members, KILL_WAIT, libc::SIGKILL)?;
    if left.is_empty() {
        return Ok(root_signal);
    }
    Err(sweep.verdict(members, left))
}

/// `expected` is the native `linux:<boot_id>:<start_ticks>` identity of the
/// verified seat root. `bound_ids` and `process_id_of` admit the restricted
/// carriers. A new carrier's parent chain must reach a non-bound-id process
/// or init before a same-id excluded ancestor. Unreadable ancestry before
/// the first signal refuses the whole kill with every live captured PID.
/// Late uncertainty fences that birth and subtree without signaling them;
/// other owned members still settle and escalate. Final live/unknown births
/// are reported as Unconfirmed at the deadline, with their native identities
/// retained for confirmation.
/// Rejected new carrier births are not survivors: `not_signaled` records
/// their total and first ten launcher/process names, on success or failure.
/// That rejection is sticky for this kill's `(pid, start)`; already-captured
/// members remain tracked by identity after any reparenting.
/// `eligible` must pass for every capture candidate but the root, and a
/// rejected one is spared with its whole subtree. `excluded` is the
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
/// Before any accepted signal, errors say "no signal sent" and label live
/// PIDs "not signaled". After accepted actuation, existing error variants
/// and survivor details are retained.
pub(crate) fn terminate(
    (root, expected): (u32, &str),
    bound_ids: &[String],
    excluded: &[u32],
    process_id_of: impl FnMut(u32) -> EnvRead,
    eligible: impl FnMut(u32) -> bool,
    authorize: impl FnMut(u32) -> Result<(), KillError>,
    not_signaled: &mut UnsignaledCarriers,
) -> Result<GroupSignal, KillError> {
    let sent = std::cell::Cell::new(false);
    let mut members = Vec::new();
    let result = terminate_body(
        (root, expected),
        bound_ids,
        excluded,
        process_id_of,
        eligible,
        authorize,
        (not_signaled, &sent, &mut members),
    );
    result.map_err(|error| {
        let accepted = sent.get();
        let mut pids = if accepted {
            Vec::new()
        } else {
            survivors(&members, |pid| {
                if excluded.contains(&pid) {
                    Seen::Gone
                } else {
                    observe(Path::new("/proc"), pid)
                }
            })
        };
        if !accepted
            && pids.is_empty()
            && root > 1
            && !excluded.contains(&root)
            && !matches!(observe(Path::new("/proc"), root), Seen::Gone)
        {
            pids.push(root);
        }
        signal_phase_error(error, accepted, &pids)
    })
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
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
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
    fn errors_before_any_accepted_signal_name_unsignaled_pids_not_survivors() {
        for error in [
            KillError::Refused("preflight validation refused".into()),
            KillError::Unconfirmed {
                reason: "ancestry unreadable".into(),
                survivors: vec![20],
            },
            KillError::Survivors(vec![20]),
        ] {
            let formatted = signal_phase_error(error, false, &[10, 20]);
            let KillError::Refused(reason) = formatted else {
                panic!("pre-signal error kept a post-actuation variant");
            };
            assert!(reason.starts_with("no signal sent:"));
            assert!(reason.contains("not signaled: 10 20"));
            assert!(!reason.contains("survivors"));
        }
    }

    #[test]
    fn errors_after_an_accepted_signal_keep_their_typed_survivor_details() {
        let error = KillError::Unconfirmed {
            reason: "ancestry unreadable".into(),
            survivors: vec![30],
        };
        assert_eq!(
            signal_phase_error(error, true, &[10, 20]),
            KillError::Unconfirmed {
                reason: "ancestry unreadable".into(),
                survivors: vec![30],
            }
        );
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
    fn an_uncaptured_group_member_even_exiting_turns_off_the_group_signal() {
        let snapshot = [fact(10, 1, 10, 100), fact(20, 10, 10, 110)];
        let captured = capture(&snapshot, 10, 100).unwrap();
        let seen = |pid| match pid {
            10 => Seen::Live(fact(10, 1, 10, 100)),
            20 => Seen::Live(fact(20, 10, 10, 110)),
            // Late, already exiting, reparented to init, still in the group.
            30 => Seen::Exiting(fact(30, 1, 10, 120)),
            31 => Seen::Live(fact(31, 1, 10, 121)),
            _ => Seen::Gone,
        };

        // Exactly the capture, plus a PID gone by now: killpg may run.
        let mut members = captured.clone();
        assert_eq!(
            reconcile_group(10, &mut members, &[10, 20, 99], seen),
            Ok(true)
        );
        assert_eq!(pids(&members), pids(&captured));

        // A late member, already exiting or live: no killpg, and it joins
        // the set so it is confirmed (and, only if live, signaled per PID).
        for late in [30, 31] {
            let mut members = captured.clone();
            assert_eq!(
                reconcile_group(10, &mut members, &[10, 20, late], seen),
                Ok(false)
            );
            assert!(members.iter().any(|m| m.pid == late && m.in_group));
        }

        // An unreadable scanned member still refuses before any signal.
        let mut members = captured.clone();
        assert!(
            reconcile_group(10, &mut members, &[10, 77], |pid| {
                if pid == 77 { Seen::Unknown } else { seen(pid) }
            })
            .is_err()
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
            // Bound id, but not eligible.
            fact(45, 1, 45, 130),
        ]
    }

    fn absorbed(
        snapshot: &[ProcFact],
        lineage: &mut Lineage,
        members: &[Member],
        bound: &[String],
    ) -> Result<Vec<Member>, KillError> {
        absorb(snapshot, 100, lineage, members, bound, seat_env, |pid| {
            pid != 45
        })
        .map(|batch| {
            assert!(batch.unconfirmed.is_empty(), "unexpected uncertain carrier");
            batch.found
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
    fn fresh_children_of_a_spared_terminal_are_not_escaped_seat_carriers() {
        let initial = [
            fact(5, 1, 5, 50),
            fact(10, 5, 10, 100),
            fact(20, 10, 10, 110),
        ];
        let members = capture(&initial, 10, 100).unwrap();
        let mut lineage = Lineage::of(&initial, 10).excluding(&[]);
        let bound = [SEAT.to_string()];
        // The root is gone. Its terminal's fresh child carries the same id,
        // but only the detached process belongs to the carrier candidate set.
        let later = [fact(5, 1, 5, 50), fact(30, 5, 5, 120), fact(40, 1, 40, 120)];
        let mut admitted = pids(
            &absorb(
                &later,
                100,
                &mut lineage,
                &members,
                &bound,
                |_| EnvRead::Present(SEAT.into()),
                |_| true,
            )
            .map(|batch| {
                assert!(batch.unconfirmed.is_empty());
                batch.found
            })
            .unwrap(),
        );
        admitted.sort_unstable();
        assert_eq!(admitted, vec![40]);
    }

    #[test]
    fn a_non_bound_id_ancestor_is_a_carrier_adoption_boundary() {
        let snapshot = [
            fact(5, 1, 5, 50),
            fact(10, 5, 10, 100),
            fact(30, 5, 30, 120),
        ];
        let members = capture(&snapshot, 10, 100).unwrap();
        let excluded = [5];
        let mut lineage = Lineage::of(&snapshot, 10).excluding(&excluded);
        let found = absorb(
            &snapshot,
            100,
            &mut lineage,
            &members,
            &[SEAT.to_string()],
            |pid| {
                if pid == 5 {
                    EnvRead::Absent
                } else {
                    EnvRead::Present(SEAT.into())
                }
            },
            |_| true,
        )
        .unwrap();
        assert!(found.unconfirmed.is_empty());
        assert_eq!(pids(&found.found), vec![30]);
    }

    #[test]
    fn a_same_id_chain_to_an_excluded_caller_is_not_a_carrier() {
        let initial = [fact(5, 1, 5, 50), fact(7, 1, 7, 50), fact(10, 5, 10, 100)];
        let members = capture(&initial, 10, 100).unwrap();
        let excluded = [7];
        let mut lineage = Lineage::of(&initial, 10).excluding(&excluded);
        let later = [
            fact(5, 1, 5, 50),
            fact(7, 1, 7, 50),
            fact(30, 7, 30, 120),
            fact(31, 30, 30, 130),
            fact(40, 1, 40, 120),
        ];
        let found = absorb(
            &later,
            100,
            &mut lineage,
            &members,
            &[SEAT.to_string()],
            |_| EnvRead::Present(SEAT.into()),
            |_| true,
        )
        .unwrap();
        assert!(found.unconfirmed.is_empty());
        assert_eq!(pids(&found.found), vec![40]);
    }

    #[test]
    fn a_rejected_birth_stays_out_of_scope_after_adoption_but_a_reused_pid_is_new() {
        let initial = [
            fact(5, 1, 5, 50),
            fact(10, 5, 10, 100),
            fact(20, 10, 10, 110),
        ];
        let members = capture(&initial, 10, 100).unwrap();
        let mut lineage = Lineage::of(&initial, 10);
        let bound = [SEAT.to_string()];
        let first = [
            fact(5, 1, 5, 50),
            fact(20, 1, 10, 110),
            fact(30, 5, 30, 120),
        ];
        assert_eq!(
            absorb(
                &first,
                100,
                &mut lineage,
                &members,
                &bound,
                |_| EnvRead::Present(SEAT.into()),
                |_| true,
            ),
            Ok(Absorbed::default())
        );
        // The rejected birth is now directly beneath a captured member.
        // Neither the tree arm nor the carrier arm may admit it.
        let adopted = [
            fact(20, 1, 10, 110),
            fact(30, 20, 30, 120),
            fact(40, 1, 40, 130),
        ];
        let found = absorb(
            &adopted,
            100,
            &mut lineage,
            &members,
            &bound,
            |_| EnvRead::Present(SEAT.into()),
            |_| true,
        )
        .unwrap();
        assert!(found.unconfirmed.is_empty());
        assert_eq!(pids(&found.found), vec![40]);
        // A different birth using the same numeric PID is evaluated anew.
        let reused = [fact(20, 1, 10, 110), fact(30, 20, 30, 121)];
        let found = absorb(
            &reused,
            100,
            &mut lineage,
            &members,
            &bound,
            |_| EnvRead::Present(SEAT.into()),
            |_| true,
        )
        .unwrap();
        assert!(found.unconfirmed.is_empty());
        assert_eq!(pids(&found.found), vec![30]);
        assert_eq!(lineage.rejected_carriers.len(), 1);
    }

    #[test]
    fn a_child_observed_below_a_rejected_birth_is_rejected_before_any_adoption_boundary() {
        let initial = [fact(5, 1, 5, 50), fact(10, 5, 10, 100)];
        let members = capture(&initial, 10, 100).unwrap();
        let mut lineage = Lineage::of(&initial, 10);
        let bound = [SEAT.to_string()];
        let first = [fact(5, 1, 5, 50), fact(30, 5, 30, 120)];
        assert_eq!(
            absorb(
                &first,
                100,
                &mut lineage,
                &members,
                &bound,
                seat_env,
                |_| true
            ),
            Ok(Absorbed::default())
        );
        // The rejected parent is now adopted and has lost its seat id.
        // Seeing its child below that same birth is still positive rejection.
        let adopted = [fact(30, 1, 30, 120), fact(31, 30, 31, 130)];
        let env = |pid| {
            if pid == 30 {
                EnvRead::Absent
            } else {
                EnvRead::Present(SEAT.into())
            }
        };
        assert_eq!(
            absorb(&adopted, 100, &mut lineage, &members, &bound, env, |_| true),
            Ok(Absorbed::default())
        );
        assert_eq!(lineage.rejected_carriers[&(31, 130)].pid, 5);
        let orphaned = [fact(31, 1, 31, 130)];
        assert_eq!(
            absorb(
                &orphaned,
                100,
                &mut lineage,
                &members,
                &bound,
                seat_env,
                |_| true
            ),
            Ok(Absorbed::default())
        );
        // Neither the parent's nor the child's old rejection binds a new birth.
        let reused = [fact(30, 1, 30, 121), fact(31, 30, 31, 131)];
        let batch = absorb(&reused, 100, &mut lineage, &members, &bound, env, |_| true).unwrap();
        assert!(batch.unconfirmed.is_empty());
        assert_eq!(pids(&batch.found), vec![31]);
    }

    #[test]
    fn a_captured_child_keeps_its_birth_proof_after_adoption_by_a_spared_ancestor() {
        let initial = [
            fact(5, 1, 5, 50),
            fact(10, 5, 10, 100),
            fact(20, 10, 10, 110),
        ];
        let members = capture(&initial, 10, 100).unwrap();
        let excluded = [5];
        let mut lineage = Lineage::of(&initial, 10).excluding(&excluded);
        let later = [fact(5, 1, 5, 50), fact(20, 5, 10, 110)];
        assert_eq!(
            absorb(
                &later,
                100,
                &mut lineage,
                &members,
                &[SEAT.to_string()],
                |_| EnvRead::Present(SEAT.into()),
                |_| true,
            ),
            Ok(Absorbed::default())
        );
        assert!(!lineage.rejected_carriers.contains_key(&(20, 110)));
        let child = members.iter().find(|member| member.pid == 20).unwrap();
        assert!(signal_proof(
            child,
            Seen::Live(later[1]),
            &[],
            || panic!("a captured child needs no carrier id"),
            || panic!("a captured child keeps its native birth proof"),
        ));
    }

    #[test]
    fn a_same_tick_carrier_with_a_missing_parent_is_unconfirmed() {
        let snapshot = [fact(10, 1, 10, 100), fact(44, 77, 44, 100)];
        let members = capture(&snapshot, 10, 100).unwrap();
        let result = absorb(
            &snapshot,
            100,
            &mut Lineage::of(&snapshot, 10),
            &members,
            &[SEAT.to_string()],
            |_| EnvRead::Present(SEAT.into()),
            |_| true,
        );
        let batch = result.unwrap();
        assert_eq!(pids(&batch.unconfirmed), vec![44]);
        assert_eq!(batch.unconfirmed[0].start, 100);
        assert!(batch.found.is_empty());
    }

    #[test]
    fn an_unreadable_parent_id_cannot_prove_a_carrier_adoption_boundary() {
        let snapshot = [
            fact(5, 1, 5, 50),
            fact(10, 1, 10, 100),
            fact(30, 5, 30, 120),
        ];
        let members = capture(&snapshot, 10, 100).unwrap();
        let result = absorb(
            &snapshot,
            100,
            &mut Lineage::of(&snapshot, 10),
            &members,
            &[SEAT.to_string()],
            |pid| {
                if pid == 5 {
                    EnvRead::Unreadable
                } else {
                    EnvRead::Present(SEAT.into())
                }
            },
            |_| true,
        );
        let batch = result.unwrap();
        assert_eq!(pids(&batch.unconfirmed), vec![30]);
        assert!(batch.found.is_empty());
    }

    #[test]
    fn invalid_parent_births_and_cycles_do_not_admit_carriers() {
        for branch in [
            [fact(30, 31, 30, 120), fact(31, 1, 31, 121)],
            [fact(30, 31, 30, 120), fact(31, 30, 31, 120)],
        ] {
            let snapshot = [fact(10, 1, 10, 100), branch[0], branch[1]];
            let members = capture(&snapshot, 10, 100).unwrap();
            let result = absorb(
                &snapshot,
                100,
                &mut Lineage::of(&snapshot, 10),
                &members,
                &[SEAT.to_string()],
                |_| EnvRead::Present(SEAT.into()),
                |_| true,
            );
            let batch = result.unwrap();
            assert!(batch.unconfirmed.iter().any(|member| member.pid == 30));
            assert!(!batch.found.iter().any(|member| member.pid == 30));
        }
    }

    #[test]
    fn unreadable_carrier_ancestry_unions_its_pid_with_captured_survivors() {
        let proc_root = tempfile::tempdir().unwrap();
        fake_process(proc_root.path(), 10, ("S", 0x40), &[]);
        fake_process(proc_root.path(), 30, ("S", 0x40), &[]);
        let snapshot = [fact(10, 1, 10, 98765), fact(30, 77, 30, 98765)];
        let members = capture(&snapshot, 10, 98765).unwrap();
        let bound = [SEAT.to_string()];
        let mut not_signaled = UnsignaledCarriers::default();
        let signal_sent = std::cell::Cell::new(false);
        let mut sweep = Sweep {
            proc_root: proc_root.path(),
            root_start: 98765,
            lineage: Lineage::of(&snapshot, 10),
            bound_ids: &bound,
            not_signaled: &mut not_signaled,
            signal_sent: &signal_sent,
            process_id_of: |_| EnvRead::Present(SEAT.into()),
            eligible: |_| true,
            authorize: |_| Ok(()),
            refused: HashSet::new(),
            refusal: None,
        };
        let batch = sweep.absorb(&snapshot, &members).unwrap();
        let mut tracked = members;
        tracked.extend(batch.found);
        sweep.fence_uncertain(&snapshot, &batch.unconfirmed);
        tracked.extend(batch.unconfirmed);
        let uncertain = tracked.iter().find(|member| member.pid == 30).unwrap();
        assert!(sweep.refused.contains(&30));
        assert!(!sweep.proven(uncertain));
        let left = sweep.survivors(&tracked);
        let result = sweep.verdict(&tracked, left);
        assert!(matches!(
            result,
            KillError::Unconfirmed { survivors, .. } if survivors == [10, 30]
        ));
    }

    #[test]
    fn an_unconfirmed_carrier_preserves_valid_forks_and_carriers_from_the_same_scan() {
        let initial = [fact(10, 1, 10, 100)];
        let members = capture(&initial, 10, 100).unwrap();
        let later = [
            fact(10, 1, 10, 100),
            fact(20, 10, 10, 110),
            fact(30, 77, 30, 120),
            fact(40, 1, 40, 130),
        ];
        let batch = absorb(
            &later,
            100,
            &mut Lineage::of(&initial, 10),
            &members,
            &[SEAT.to_string()],
            seat_env,
            |_| true,
        )
        .unwrap();
        assert_eq!(pids(&batch.found), vec![20, 40]);
        assert_eq!(pids(&batch.unconfirmed), vec![30]);
        assert_eq!(batch.unconfirmed[0].start, 120);
    }

    #[test]
    fn unsignaled_carrier_notices_are_capped_deduplicated_and_preserved_on_error() {
        let proc_root = tempfile::tempdir().unwrap();
        fake_process(proc_root.path(), 10, ("S", 0x40), &[]);
        let mut snapshot = vec![fact(5, 1, 5, 90000), fact(10, 5, 10, 98765)];
        snapshot.extend((30..43).map(|pid| fact(pid, 5, pid, 98766)));
        let members = capture(&snapshot, 10, 98765).unwrap();
        let bound = [SEAT.to_string()];
        let mut not_signaled = UnsignaledCarriers::default();
        let signal_sent = std::cell::Cell::new(false);
        let mut sweep = Sweep {
            proc_root: proc_root.path(),
            root_start: 98765,
            lineage: Lineage::of(&snapshot, 10),
            bound_ids: &bound,
            not_signaled: &mut not_signaled,
            signal_sent: &signal_sent,
            process_id_of: |_| EnvRead::Present(SEAT.into()),
            eligible: |_| true,
            authorize: |_| Ok(()),
            refused: HashSet::new(),
            refusal: None,
        };
        assert_eq!(sweep.absorb(&snapshot, &members), Ok(Absorbed::default()));
        assert_eq!(sweep.not_signaled.total, 13);
        assert_eq!(sweep.not_signaled.entries.len(), UNSIGNALED_CARRIER_LIMIT);
        assert_eq!(
            sweep
                .not_signaled
                .entries
                .iter()
                .map(|entry| entry.pid)
                .collect::<Vec<_>>(),
            (30..40).collect::<Vec<_>>()
        );
        assert!(
            sweep
                .not_signaled
                .entries
                .iter()
                .all(|entry| entry.launcher_pid == 5)
        );

        assert_eq!(sweep.absorb(&snapshot, &members), Ok(Absorbed::default()));
        assert_eq!(
            sweep.not_signaled.total, 13,
            "a rescan counted the same births twice"
        );
        snapshot
            .iter_mut()
            .find(|fact| fact.pid == 30)
            .unwrap()
            .start += 1;
        assert_eq!(sweep.absorb(&snapshot, &members), Ok(Absorbed::default()));
        assert_eq!(sweep.not_signaled.total, 14, "a new birth was not counted");

        snapshot.push(fact(61, 5, 61, 98767));
        snapshot.push(fact(60, 77, 60, 98765));
        fake_process(proc_root.path(), 60, ("S", 0x40), &[]);
        let batch = sweep.absorb(&snapshot, &members).unwrap();
        let mut tracked = members;
        tracked.extend(batch.found);
        sweep.fence_uncertain(&snapshot, &batch.unconfirmed);
        tracked.extend(batch.unconfirmed);
        let left = sweep.survivors(&tracked);
        let result = sweep.verdict(&tracked, left);
        assert!(matches!(
            result,
            KillError::Unconfirmed { survivors, .. } if survivors == [10, 60]
        ));
        assert_eq!(
            sweep.not_signaled.total, 15,
            "an error discarded a new notice"
        );
        assert_eq!(sweep.not_signaled.entries.len(), UNSIGNALED_CARRIER_LIMIT);
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
        assert_eq!(found, Ok(Absorbed::default()));
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
        assert!(found.unconfirmed.is_empty());
        let tree: Vec<u32> = found
            .found
            .iter()
            .filter(|m| !m.carrier)
            .map(|m| m.pid)
            .collect();
        let carriers: Vec<u32> = found
            .found
            .iter()
            .filter(|m| m.carrier)
            .map(|m| m.pid)
            .collect();
        assert_eq!(tree, vec![60, 61]);
        // The ancestors 3 and 5 still carry the id and are still excluded.
        assert_eq!(carriers, vec![95]);

        members.extend(found.found);
        assert_eq!(
            absorb(&later, 100, &mut lineage, &members, &bound, env, |_| true).map(|batch| {
                assert!(batch.unconfirmed.is_empty());
                pids(&batch.found)
            }),
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
        assert_eq!(
            found.map(|batch| {
                assert!(batch.unconfirmed.is_empty());
                pids(&batch.found)
            }),
            Ok(vec![70])
        );
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
        assert_eq!(found, Ok(Absorbed::default()));
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
            (root, expected),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |_| Ok(()),
            &mut UnsignaledCarriers::default(),
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

    /// The marker a test's fixtures carry: HCOM_PROCESS_ID set to a token
    /// unique to that test and this test binary.
    fn marker(test: &str) -> String {
        format!("kill-tree-linux-{test}-{}", std::process::id())
    }

    /// A fixture descendant the test holds no `Child` for, pinned with a
    /// pidfd and proven the fixture's. After pinning it still has the start
    /// recorded at capture and carries the test's marker, and it is still
    /// alive afterwards, so no PID reuse can slip between those reads.
    /// Signals go only through the pidfd, which can never reach a different
    /// process: once the pinned one exits, they fail with ESRCH.
    struct Pinned {
        pidfd: OwnedFd,
    }

    impl Pinned {
        fn pin(pid: u32, start: u64, token: &str) -> Self {
            let raw = libc::pid_t::try_from(pid).expect("representable fixture PID");
            // SAFETY: pidfd_open takes a PID and zero flags and returns a new
            // descriptor or -1; it signals nothing.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, raw, 0) };
            assert!(
                fd >= 0,
                "pidfd_open({pid}): {}",
                std::io::Error::last_os_error()
            );
            let fd = libc::c_int::try_from(fd).expect("descriptor fits a c_int");
            // SAFETY: a fresh descriptor that nothing else owns.
            let pinned = Pinned {
                pidfd: unsafe { OwnedFd::from_raw_fd(fd) },
            };
            assert_eq!(start_of(pid), Some(start), "{pid} is not the captured one");
            assert!(
                matches!(
                    crate::proctruth::process_id_of(pid),
                    EnvRead::Present(id) if id == token
                ),
                "{pid} lacks the fixture marker"
            );
            assert!(pinned.signal(0), "{pid} exited while it was proven");
            pinned
        }

        /// Send `sig` to the pinned process; false once it has exited.
        fn signal(&self, sig: libc::c_int) -> bool {
            // SAFETY: a pidfd this struct owns, no siginfo and no flags.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    sig,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                ) == 0
            }
        }
    }

    /// SIGKILLs a pinned fixture process that left every fixture group, on
    /// drop; one that already exited gets nothing.
    struct Stray(Pinned);

    impl Drop for Stray {
        fn drop(&mut self) {
            self.0.signal(libc::SIGKILL);
        }
    }

    /// Owns this test's fixture processes and their process group. The
    /// leader's birth is captured while its Child is still unreaped.
    struct Fixture {
        group: u32,
        birth: Option<String>,
        children: Vec<Child>,
    }

    impl Fixture {
        fn new(leader: Child) -> Self {
            let group = leader.id();
            let birth = identity(group);
            Self {
                group,
                birth,
                children: vec![leader],
            }
        }
    }

    /// WNOWAIT proves this is still our unreaped child without consuming
    /// its exit status. ECHILD or an unreadable/changed birth fails closed.
    fn still_owned(child: &Child, birth: Option<&str>) -> bool {
        let Some(birth) = birth else {
            return false;
        };
        // SAFETY: siginfo_t is a plain C result buffer; waitid only reads
        // our positive child PID and writes this buffer, without reaping.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let owned = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            ) == 0
        };
        owned && has_identity(child.id(), birth)
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // The unreaped leader pins this exact group number. No wait
            // may reap it before its birth and group are rechecked.
            if let Some(leader) = self.children.first()
                && leader.id() == self.group
                && let Ok(raw) = libc::pid_t::try_from(leader.id())
                && still_owned(leader, self.birth.as_deref())
                // SAFETY: reads the group of this positive, owned child.
                && unsafe { libc::getpgid(raw) } == raw
            {
                let _ = signal_group(self.group, libc::SIGKILL);
            }
            for child in &mut self.children {
                let _ = child.kill();
                let deadline = Instant::now() + Duration::from_secs(5);
                while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn command(script: &str, group: u32) -> Command {
        let mut command = Command::new("sh");
        command
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(group as i32);
        command
    }

    fn spawn(script: &str, group: u32) -> Child {
        command(script, group).spawn().expect("spawn own fixture")
    }

    /// [`spawn`], with every process in the fixture carrying `token`.
    fn spawn_marked(script: &str, group: u32, token: &str) -> Child {
        command(script, group)
            .env("HCOM_PROCESS_ID", token)
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
        let fixture = Fixture::new(leader);
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
        let mut fixture = Fixture::new(anchor);
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
        let fixture = Fixture::new(leader);
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
        let fixture = Fixture::new(leader);
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
        let dir = tempfile::Builder::new()
            .prefix("hcom-reparented-carrier-")
            .tempdir()
            .unwrap();
        let home = dir.path().join("home");
        let state = dir.path().join("hcom");
        let tmp = dir.path().join("tmp");
        for path in [&home, &state, &tmp] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(state.join("config.toml"), "[relay]\nenabled = false\n").unwrap();
        let root_file = dir.path().join("root");
        let carrier_file = dir.path().join("carrier");
        let stop = dir.path().join("stop");
        let program = dir.path().join("subreaper.py");
        std::fs::write(
            &program,
            format!(
                r#"import ctypes, os, subprocess, sys, time
root_file, carrier_file, stop, token = sys.argv[1:]
if ctypes.CDLL(None).prctl({}, 1, 0, 0, 0) != 0:
    raise RuntimeError("fixture could not become a subreaper")
marked = os.environ.copy()
marked["HCOM_PROCESS_ID"] = token
root = subprocess.Popen(["/bin/sleep", "30"], env=marked, start_new_session=True)
with open(root_file, "w") as output:
    output.write(str(root.pid))
carrier = int(subprocess.check_output(
    ["/bin/sh", "-c", "/bin/sleep 30 </dev/null >/dev/null 2>&1 & echo $!"],
    env=marked,
))
with open(carrier_file, "w") as output:
    output.write(str(carrier))
while not os.path.exists(stop):
    time.sleep(0.01)
root.wait()
os.waitpid(carrier, 0)
"#,
                libc::PR_SET_CHILD_SUBREAPER,
            ),
        )
        .unwrap();
        let id = marker("reparented-carrier");
        let subreaper = Command::new("python3")
            .arg(&program)
            .args([&root_file, &carrier_file, &stop])
            .arg(&id)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("HCOM_DIR", &state)
            .env("TMPDIR", &tmp)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn own non-id subreaper");
        let subreaper_pid = subreaper.id();
        let subreaper_start = start_of(subreaper_pid).expect("fixture subreaper start");
        let fixture = Fixture::new(subreaper);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (root, carrier) = loop {
            let read_pid = |path| {
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|pid| pid.parse::<u32>().ok())
            };
            if let (Some(root), Some(carrier)) = (read_pid(&root_file), read_pid(&carrier_file))
                && matches!(
                    observe(Path::new("/proc"), carrier),
                    Seen::Live(fact) if fact.ppid == subreaper_pid
                )
            {
                break (root, carrier);
            }
            assert!(
                Instant::now() < deadline,
                "fixture carrier was never adopted"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        wait_for_sleep(root);
        wait_for_sleep(carrier);
        let root_start = start_of(root).expect("fixture root start");
        let carrier_start = start_of(carrier).expect("carrier start");
        let root_guard = Stray(Pinned::pin(root, root_start, &id));
        let stray = Stray(Pinned::pin(carrier, carrier_start, &id));
        assert!(carrier_start >= root_start);
        assert_eq!(start_of(subreaper_pid), Some(subreaper_start));
        assert!(matches!(
            crate::proctruth::process_id_of(subreaper_pid),
            EnvRead::Absent
        ));
        let tree = captured(root, 1);
        assert!(tree.iter().all(|member| member.pid != carrier));

        let result = terminate(
            (root, &identity(root).unwrap()),
            std::slice::from_ref(&id),
            &[subreaper_pid],
            crate::proctruth::process_id_of,
            |_| true,
            |_| Ok(()),
            &mut UnsignaledCarriers::default(),
        );
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert_ne!(start_of(carrier), Some(carrier_start), "carrier survived");
        assert!(tree.iter().all(|member| !running(member)));
        assert_eq!(
            start_of(subreaper_pid),
            Some(subreaper_start),
            "non-id subreaper was signaled"
        );
        std::fs::write(&stop, b"").unwrap();
        drop(stray);
        drop(root_guard);
        drop(fixture);
    }

    #[test]
    fn an_ancestor_carrying_the_id_is_never_signaled() {
        // Anchor -> root shell -> sleep. After its wait the anchor execs sleep,
        // keeping its start time, so it stays observable unless signaled.
        let anchor = spawn("sh -c 'sleep 30 & wait' & wait; exec sleep 30", 0);
        let group = anchor.id();
        let fixture = Fixture::new(anchor);
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
            (root, &identity(root).unwrap()),
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
            &mut UnsignaledCarriers::default(),
        );
        assert_eq!(result, Ok(GroupSignal::Sent));
        let root_tree: Vec<&Member> = tree.iter().filter(|member| member.pid != group).collect();
        assert!(root_tree.iter().all(|member| !running(member)));
        assert_eq!(start_of(group), Some(anchor_start), "ancestor was signaled");
        drop(fixture);
    }

    #[test]
    fn an_excluded_ancestor_spawning_bound_id_siblings_does_not_refill_the_seat() {
        let dir = tempfile::Builder::new()
            .prefix("hcom-off-seat-carriers-")
            .tempdir()
            .unwrap();
        let home = dir.path().join("home");
        let state = dir.path().join("hcom");
        let tmp = dir.path().join("tmp");
        for path in [&home, &state, &tmp] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(state.join("config.toml"), "[relay]\nenabled = false\n").unwrap();
        let root_file = dir.path().join("root");
        let sibling_file = dir.path().join("siblings");
        let child_file = dir.path().join("seat-child");
        let release_root = dir.path().join("release-root");
        let begin = dir.path().join("begin");
        let stop = dir.path().join("stop");
        let program = dir.path().join("ancestor.py");
        std::fs::write(
            &program,
            format!(
                r#"import ctypes, os, subprocess, sys, time
root_file, sibling_file, begin, stop, child_file, release_root = sys.argv[1:]
if ctypes.CDLL(None).prctl({}, 1, 0, 0, 0) != 0:
    raise RuntimeError("fixture could not become a subreaper")
root = subprocess.Popen(
    [sys.executable, "-c",
     "import os, subprocess, sys, time\n"
     "child = subprocess.Popen(['/bin/sh', '-c', \"trap '' TERM; exec /bin/sleep 30\"])\n"
     "with open(sys.argv[1], 'w') as output: output.write(str(child.pid))\n"
     "while not os.path.exists(sys.argv[2]): time.sleep(0.01)\n"
     "os._exit(0)\n",
     child_file, release_root],
    start_new_session=True,
)
with open(root_file, "w") as output:
    output.write(str(root.pid))
while not os.path.exists(begin) and not os.path.exists(stop):
    time.sleep(0.01)
siblings = []
while not os.path.exists(stop):
    child = subprocess.Popen(["/bin/sleep", "30"])
    siblings.append(child)
    with open(sibling_file, "a") as output:
        output.write(str(child.pid) + "\n")
    root.poll()
    time.sleep(0.02)
root.wait()
for child in siblings:
    child.wait()
"#,
                libc::PR_SET_CHILD_SUBREAPER,
            ),
        )
        .unwrap();
        let token = marker("off-seat-siblings");
        let ancestor = Command::new("python3")
            .arg(&program)
            .args([
                &root_file,
                &sibling_file,
                &begin,
                &stop,
                &child_file,
                &release_root,
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("HCOM_DIR", &state)
            .env("TMPDIR", &tmp)
            .env("HCOM_PROCESS_ID", &token)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn own excluded ancestor");
        let ancestor_pid = ancestor.id();
        let fixture = Fixture::new(ancestor);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (root, seat_child) = loop {
            let read_pid = |path: &Path| {
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|pid| pid.parse::<u32>().ok())
            };
            if let (Some(root), Some(child)) = (read_pid(&root_file), read_pid(&child_file)) {
                break (root, child);
            }
            assert!(
                Instant::now() < deadline,
                "ancestor never spawned its seat tree"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let root_start = start_of(root).expect("fixture root start");
        let root_guard = Stray(Pinned::pin(root, root_start, &token));
        wait_for_sleep(seat_child);
        let child_start = start_of(seat_child).expect("fixture seat child start");
        let child_guard = Stray(Pinned::pin(seat_child, child_start, &token));
        std::fs::write(&begin, b"").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let siblings = loop {
            let pids: Vec<u32> = std::fs::read_to_string(&sibling_file)
                .unwrap_or_default()
                .lines()
                .filter_map(|pid| pid.parse().ok())
                .take(3)
                .collect();
            if pids.len() == 3 {
                break pids;
            }
            assert!(Instant::now() < deadline, "ancestor never spawned siblings");
            std::thread::sleep(Duration::from_millis(10));
        };
        let siblings: Vec<_> = siblings
            .into_iter()
            .map(|pid| {
                let start = start_of(pid).expect("fixture sibling start");
                assert!(start >= root_start);
                (pid, start, Stray(Pinned::pin(pid, start, &token)))
            })
            .collect();

        let mut not_signaled = UnsignaledCarriers::default();
        let root_identity = identity(root).unwrap();
        let mut root_released = false;
        let result = terminate(
            (root, &root_identity),
            std::slice::from_ref(&token),
            &[ancestor_pid],
            crate::proctruth::process_id_of,
            |_| true,
            |pid| {
                if pid == seat_child && !root_released {
                    root_released = true;
                    std::fs::write(&release_root, b"").unwrap();
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while has_identity(root, &root_identity)
                        || !matches!(
                            observe(Path::new("/proc"), seat_child),
                            Seen::Live(fact) if fact.start == child_start && fact.ppid == ancestor_pid
                        )
                    {
                        assert!(
                            Instant::now() < deadline,
                            "captured child was never adopted"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                Ok(())
            },
            &mut not_signaled,
        );
        std::fs::write(&stop, b"").unwrap();
        assert_eq!(result, Ok(GroupSignal::NotFound));
        assert_ne!(start_of(root), Some(root_start), "seat root survived");
        assert_ne!(
            start_of(seat_child),
            Some(child_start),
            "captured adopted child survived"
        );
        assert!(not_signaled.total >= siblings.len());
        assert_eq!(
            not_signaled.entries.len(),
            not_signaled.total.min(UNSIGNALED_CARRIER_LIMIT)
        );
        assert!(not_signaled.entries.iter().all(|entry| {
            entry.launcher_pid == ancestor_pid && entry.pid != seat_child && entry.pid != root
        }));
        for (pid, start, guard) in &siblings {
            assert_eq!(
                start_of(*pid),
                Some(*start),
                "off-seat sibling was signaled"
            );
            assert!(guard.0.signal(0), "off-seat sibling exited");
        }
        drop(siblings);
        drop(child_guard);
        drop(root_guard);
        drop(fixture);
    }

    #[test]
    fn a_carrier_adopted_by_a_non_id_subreaper_is_still_terminated() {
        let dir = tempfile::Builder::new()
            .prefix("hcom-adopted-carrier-")
            .tempdir()
            .unwrap();
        let home = dir.path().join("home");
        let state = dir.path().join("hcom");
        let tmp = dir.path().join("tmp");
        for path in [&home, &state, &tmp] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(state.join("config.toml"), "[relay]\nenabled = false\n").unwrap();
        let root_file = dir.path().join("root");
        let carrier_file = dir.path().join("carrier");
        let stop = dir.path().join("stop");
        let program = dir.path().join("subreaper.py");
        std::fs::write(
            &program,
            format!(
                r#"import ctypes, os, subprocess, sys, time
root_file, carrier_file, stop, token = sys.argv[1:]
if ctypes.CDLL(None).prctl({}, 1, 0, 0, 0) != 0:
    raise RuntimeError("fixture could not become a subreaper")
marked = os.environ.copy()
marked["HCOM_PROCESS_ID"] = token
root = subprocess.Popen(["/bin/sleep", "30"], env=marked, start_new_session=True)
with open(root_file, "w") as output:
    output.write(str(root.pid))
carrier = int(subprocess.check_output(
    ["/bin/sh", "-c", "/bin/sleep 30 </dev/null >/dev/null 2>&1 & echo $!"],
    env=marked,
))
with open(carrier_file, "w") as output:
    output.write(str(carrier))
while not os.path.exists(stop):
    time.sleep(0.01)
root.wait()
os.waitpid(carrier, 0)
"#,
                libc::PR_SET_CHILD_SUBREAPER,
            ),
        )
        .unwrap();
        let token = marker("adopted-carrier");
        let subreaper = Command::new("python3")
            .arg(&program)
            .args([&root_file, &carrier_file, &stop])
            .arg(&token)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("HCOM_DIR", &state)
            .env("TMPDIR", &tmp)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn own non-id subreaper");
        let subreaper_pid = subreaper.id();
        let subreaper_start = start_of(subreaper_pid).expect("fixture subreaper start");
        let fixture = Fixture::new(subreaper);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (root, carrier) = loop {
            let read_pid = |path| {
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|pid| pid.parse::<u32>().ok())
            };
            if let (Some(root), Some(carrier)) = (read_pid(&root_file), read_pid(&carrier_file))
                && matches!(
                    observe(Path::new("/proc"), carrier),
                    Seen::Live(fact) if fact.ppid == subreaper_pid
                )
            {
                break (root, carrier);
            }
            assert!(
                Instant::now() < deadline,
                "fixture carrier was never adopted"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        wait_for_sleep(root);
        wait_for_sleep(carrier);
        let root_start = start_of(root).expect("fixture root start");
        let carrier_start = start_of(carrier).expect("fixture carrier start");
        let root_guard = Stray(Pinned::pin(root, root_start, &token));
        let carrier_guard = Stray(Pinned::pin(carrier, carrier_start, &token));
        assert!(carrier_start >= root_start);
        assert!(matches!(
            crate::proctruth::process_id_of(subreaper_pid),
            EnvRead::Absent
        ));

        let mut not_signaled = UnsignaledCarriers::default();
        let result = terminate(
            (root, &identity(root).unwrap()),
            std::slice::from_ref(&token),
            &[subreaper_pid],
            crate::proctruth::process_id_of,
            |_| true,
            |_| Ok(()),
            &mut not_signaled,
        );
        std::fs::write(&stop, b"").unwrap();
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert_eq!(not_signaled.total, 0, "an adopted carrier was excluded");
        assert_ne!(start_of(root), Some(root_start), "seat root survived");
        assert_ne!(
            start_of(carrier),
            Some(carrier_start),
            "adopted carrier survived"
        );
        assert_eq!(
            start_of(subreaper_pid),
            Some(subreaper_start),
            "non-id subreaper was signaled"
        );
        drop(carrier_guard);
        drop(root_guard);
        drop(fixture);
    }

    #[test]
    fn late_uncertain_ancestry_never_abandons_other_owned_members_before_sigkill() {
        let dir = tempfile::Builder::new()
            .prefix("hcom-late-uncertain-")
            .tempdir()
            .unwrap();
        let home = dir.path().join("home");
        let state = dir.path().join("hcom");
        let tmp = dir.path().join("tmp");
        for path in [&home, &state, &tmp] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(state.join("config.toml"), "[relay]\nenabled = false\n").unwrap();
        let ready = dir.path().join("ready");
        let begin = dir.path().join("begin");
        let child_file = dir.path().join("child");
        let program = dir.path().join("root.py");
        std::fs::write(
            &program,
            r#"import os, signal, subprocess, sys, time
ready, begin, child_file = sys.argv[1:]
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open(ready, "w") as output:
    output.write("ready")
while not os.path.exists(begin):
    time.sleep(0.01)
child = subprocess.Popen(["/bin/sleep", "30"])
with open(child_file, "w") as output:
    output.write(str(child.pid))
time.sleep(30)
"#,
        )
        .unwrap();
        let token = marker("late-uncertain");
        let leader = Command::new("python3")
            .arg(&program)
            .args([&ready, &begin, &child_file])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("HCOM_DIR", &state)
            .env("TMPDIR", &tmp)
            .env("HCOM_PROCESS_ID", &token)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn own TERM-ignoring root");
        let root = leader.id();
        let fixture = Fixture::new(leader);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "root never installed SIG_IGN");
            std::thread::sleep(Duration::from_millis(10));
        }
        let root_identity = identity(root).unwrap();
        let root_start = start_of(root).unwrap();
        let me = std::process::id();
        let mut valid_child = None::<(u32, u64, Stray)>;
        let mut uncertain = None::<(Fixture, u32, u64, Stray)>;
        let mut not_signaled = UnsignaledCarriers::default();
        let result = terminate(
            (root, &root_identity),
            std::slice::from_ref(&token),
            &[me],
            |pid| {
                if pid == me {
                    EnvRead::Unreadable
                } else {
                    crate::proctruth::process_id_of(pid)
                }
            },
            |_| true,
            |pid| {
                if pid == root && uncertain.is_none() {
                    std::fs::write(&begin, b"").unwrap();
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let child = loop {
                        if let Some(child) = std::fs::read_to_string(&child_file)
                            .ok()
                            .and_then(|pid| pid.parse::<u32>().ok())
                        {
                            break child;
                        }
                        assert!(Instant::now() < deadline, "root never made its late fork");
                        std::thread::sleep(Duration::from_millis(5));
                    };
                    wait_for_sleep(child);
                    let start = start_of(child).unwrap();
                    valid_child = Some((child, start, Stray(Pinned::pin(child, start, &token))));

                    let child = command("exec /bin/sleep 30", 0)
                        .env_clear()
                        .env("PATH", "/usr/bin:/bin")
                        .env("HOME", &home)
                        .env("HCOM_DIR", &state)
                        .env("TMPDIR", &tmp)
                        .env("HCOM_PROCESS_ID", &token)
                        .spawn()
                        .expect("spawn own uncertain carrier");
                    let pid = child.id();
                    let fixture = Fixture::new(child);
                    wait_for_sleep(pid);
                    let start = start_of(pid).unwrap();
                    uncertain = Some((fixture, pid, start, Stray(Pinned::pin(pid, start, &token))));
                }
                Ok(())
            },
            &mut not_signaled,
        );
        let (_, pid, start, guard) = uncertain.as_ref().expect("late uncertain carrier");
        assert!(matches!(
            result,
            Err(KillError::Unconfirmed { reason, survivors })
                if reason.contains("ancestry") && survivors == [*pid]
        ));
        assert_ne!(
            start_of(root),
            Some(root_start),
            "TERM-ignoring root escaped escalation"
        );
        // Peek at our own unreaped root's status without forfeiting the
        // fixture's group-cleanup authority. It died by SIGKILL, not timeout.
        // SAFETY: siginfo_t is a C result buffer with a valid zero value.
        let mut exit: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: a writable result buffer and our positive, unreaped Child.
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    root as libc::id_t,
                    &mut exit,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            0
        );
        assert_eq!(exit.si_code, libc::CLD_KILLED);
        // SAFETY: waitid succeeded and filled this SIGCHLD result buffer.
        assert_eq!(unsafe { exit.si_pid() }, root as libc::pid_t);
        // SAFETY: the checked result is CLD_KILLED for this root.
        assert_eq!(unsafe { exit.si_status() }, libc::SIGKILL);
        let (child, child_start, _) = valid_child.as_ref().expect("validated same-pass fork");
        assert_ne!(
            start_of(*child),
            Some(*child_start),
            "same-pass validated fork was lost"
        );
        assert_eq!(
            start_of(*pid),
            Some(*start),
            "uncertain carrier was signaled"
        );
        assert!(guard.0.signal(0), "uncertain carrier exited");
        assert_eq!(
            not_signaled.total, 0,
            "uncertainty became an informational rejection"
        );
        drop(valid_child);
        drop(uncertain);
        drop(fixture);
    }

    #[test]
    fn a_root_that_exits_and_is_reaped_before_its_own_signal_is_success() {
        // Anchor -> root shell -> sleeper. The anchor reaps the root at once.
        let token = marker("root-reaped");
        let anchor = spawn_marked("sh -c 'sleep 30 & wait' & wait; exec sleep 30", 0, &token);
        let group = anchor.id();
        let fixture = Fixture::new(anchor);
        let tree = captured(group, 3);
        let root_member = tree
            .iter()
            .find(|member| member.depth == 1)
            .expect("root shell");
        let root = root_member.pid;
        let pinned_root = Pinned::pin(root, root_member.start, &token);
        // `authorize` runs after the capture and before any signal: end and
        // reap the root there, the way a root that waited on its signaled
        // descendants exits on its own, so it is gone at its own signal.
        let mut ended = false;
        let result = terminate(
            (root, &identity(root).unwrap()),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                if pid == root && !ended {
                    ended = true;
                    // The pinned root shell, never anything else.
                    pinned_root.signal(libc::SIGKILL);
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
            &mut UnsignaledCarriers::default(),
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
        let token = marker("leader-root-reaped");
        let anchor = spawn_marked(
            "setsid sh -c 'sleep 30 & wait' & wait; exec sleep 30",
            0,
            &token,
        );
        let group = anchor.id();
        let fixture = Fixture::new(anchor);
        let tree = captured(group, 3);
        let root_member = tree
            .iter()
            .find(|member| member.depth == 1)
            .expect("root shell");
        let root = root_member.pid;
        let pinned_root = Pinned::pin(root, root_member.start, &token);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(observe(Path::new("/proc"), root), Seen::Live(fact) if fact.pgrp == root) {
            assert!(Instant::now() < deadline, "root never led its own group");
            std::thread::sleep(Duration::from_millis(5));
        }
        // The sleeper left the anchor's group with the root, so the fixture
        // can't reach it; it is pinned and killed only through its pidfd.
        let sleeper = tree
            .iter()
            .find(|member| member.depth == 2)
            .expect("sleeper");
        let stray = Stray(Pinned::pin(sleeper.pid, sleeper.start, &token));

        let mut ended = false;
        let began = Instant::now();
        let result = terminate(
            (root, &identity(root).unwrap()),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                if pid == root && !ended {
                    ended = true;
                    // The pinned root shell, never anything else.
                    pinned_root.signal(libc::SIGKILL);
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while Path::new(&format!("/proc/{root}")).exists() {
                        assert!(Instant::now() < deadline, "root was never reaped");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                Ok(())
            },
            &mut UnsignaledCarriers::default(),
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
        let dir = tempfile::Builder::new()
            .prefix("hcom-forking-carrier-")
            .tempdir()
            .unwrap();
        let home = dir.path().join("home");
        let state = dir.path().join("hcom");
        let tmp = dir.path().join("tmp");
        for path in [&home, &state, &tmp] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(state.join("config.toml"), "[relay]\nenabled = false\n").unwrap();
        // A test-owned group whose leader is not the seat root.
        let anchor = command("exec sleep 30", 0)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("HCOM_DIR", &state)
            .env("TMPDIR", &tmp)
            .spawn()
            .expect("spawn own anchor");
        let group = anchor.id();
        let fixture = Fixture::new(anchor);
        wait_for_sleep(group);
        let id = marker("forking-carrier");
        let root_file = dir.path().join("root");
        let stop = dir.path().join("stop");
        let program = dir.path().join("subreaper.py");
        // The root and its sleepers ignore SIGTERM, so the root keeps forking
        // a sleeper every 50ms through the whole TERM budget, long after the
        // initial capture; one forked just before its SIGKILL is orphaned.
        // The subreaper stays outside that group and adopts those late forks.
        std::fs::write(
            &program,
            format!(
                r#"import ctypes, os, subprocess, sys, time
root_file, stop, token, group = sys.argv[1:]
if ctypes.CDLL(None).prctl({}, 1, 0, 0, 0) != 0:
    raise RuntimeError("fixture could not become a subreaper")
marked = os.environ.copy()
marked["HCOM_PROCESS_ID"] = token
root = subprocess.Popen(
    ["/bin/sh", "-c", "trap '' TERM; while :; do sleep 30 & sleep 0.05; done"],
    env=marked,
    preexec_fn=lambda: os.setpgid(0, int(group)),
)
with open(root_file, "w") as output:
    output.write(str(root.pid))
while not os.path.exists(stop):
    time.sleep(0.01)
root.wait()
while True:
    try:
        os.waitpid(-1, 0)
    except ChildProcessError:
        break
"#,
                libc::PR_SET_CHILD_SUBREAPER,
            ),
        )
        .unwrap();
        let subreaper = Command::new("python3")
            .arg(&program)
            .args([&root_file, &stop])
            .arg(&id)
            .arg(group.to_string())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("HCOM_DIR", &state)
            .env("TMPDIR", &tmp)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn own non-id subreaper");
        let subreaper_pid = subreaper.id();
        let subreaper_start = start_of(subreaper_pid).expect("fixture subreaper start");
        let adopter_fixture = Fixture::new(subreaper);
        let deadline = Instant::now() + Duration::from_secs(5);
        let root = loop {
            if let Some(root) = std::fs::read_to_string(&root_file)
                .ok()
                .and_then(|pid| pid.parse::<u32>().ok())
                && matches!(
                    observe(Path::new("/proc"), root),
                    Seen::Live(fact) if fact.ppid == subreaper_pid
                )
            {
                break root;
            }
            assert!(
                Instant::now() < deadline,
                "fixture forking root was never ready"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(start_of(subreaper_pid), Some(subreaper_start));
        assert!(matches!(
            crate::proctruth::process_id_of(subreaper_pid),
            EnvRead::Absent
        ));
        let first = captured(root, 3);

        let result = terminate(
            (root, &identity(root).unwrap()),
            std::slice::from_ref(&id),
            &[subreaper_pid],
            crate::proctruth::process_id_of,
            |_| true,
            |_| Ok(()),
            &mut UnsignaledCarriers::default(),
        );
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert!(first.iter().all(|member| !running(member)));
        // Every sleeper, late or orphaned, is gone; only the anchor is left.
        assert_eq!(
            super::super::kill_group::live_members(group),
            Ok(vec![group])
        );
        assert_eq!(
            start_of(subreaper_pid),
            Some(subreaper_start),
            "non-id subreaper was signaled"
        );
        std::fs::write(&stop, b"").unwrap();
        drop(adopter_fixture);
        drop(fixture);
    }

    #[test]
    fn an_excluded_group_member_survives_while_the_rest_of_the_group_goes() {
        let leader = spawn("sleep 30 & sleep 30 & wait", 0);
        let root = leader.id();
        let fixture = Fixture::new(leader);
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
            (root, &identity(root).unwrap()),
            &[],
            &[spared],
            |_| EnvRead::Absent,
            |_| true,
            |_| Ok(()),
            &mut UnsignaledCarriers::default(),
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
        let fixture = Fixture::new(leader);
        let tree = captured(root, 2);
        let root_start = start_of(root).unwrap();

        let result = terminate(
            (root, &identity(root).unwrap()),
            &[],
            &[root],
            |_| EnvRead::Absent,
            |_| true,
            |_| Ok(()),
            &mut UnsignaledCarriers::default(),
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

    /// SIGKILLs only a pinned fixture process and reaps our own fork.
    struct Forked {
        pid: libc::pid_t,
        pinned: Option<Pinned>,
    }

    impl Drop for Forked {
        fn drop(&mut self) {
            if let Some(pinned) = &self.pinned {
                pinned.signal(libc::SIGKILL);
            }
            // SAFETY: waits for our own positive fork PID; no status is read.
            unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) };
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
        let token = marker("leader-shares-parent-group");
        let dir = tempfile::Builder::new()
            .prefix("hcom-kill-tree-linux-")
            .tempdir()
            .unwrap();
        let home = dir.path().join("home");
        let state = dir.path().join("hcom");
        let tmp = dir.path().join("tmp");
        for path in [&home, &state, &tmp] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(state.join("config.toml"), "[relay]\nenabled = false\n").unwrap();
        // execve inherits nothing: only private roots and this test's
        // deliberate positive marker reach either fixture process.
        let env = [
            std::ffi::CString::new(format!("HOME={}", home.display())).unwrap(),
            std::ffi::CString::new(format!("HCOM_DIR={}", state.display())).unwrap(),
            std::ffi::CString::new(format!("TMPDIR={}", tmp.display())).unwrap(),
            std::ffi::CString::new(format!("HCOM_PROCESS_ID={token}")).unwrap(),
        ];
        let envp = [
            env[0].as_ptr(),
            env[1].as_ptr(),
            env[2].as_ptr(),
            env[3].as_ptr(),
            std::ptr::null(),
        ];
        // The parent forks the root, makes it lead its own group, then joins
        // that group itself: a leader root whose group holds its ancestor.
        // SAFETY: between fork and exec the children call only fork, setpgid,
        // execve and _exit, all async-signal-safe; argv and envp were built
        // beforehand.
        let parent = unsafe { libc::fork() };
        assert!(parent >= 0, "fork failed");
        if parent == 0 {
            unsafe {
                let root = libc::fork();
                if root == 0 {
                    libc::setpgid(0, 0);
                    libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                    libc::_exit(127);
                }
                if root > 0 {
                    libc::setpgid(root, root);
                    libc::setpgid(0, root);
                    libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                }
                libc::_exit(127);
            }
        }
        let mut parent_guard = Forked {
            pid: parent,
            pinned: None,
        };
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
        parent_guard.pinned = Some(Pinned::pin(
            parent,
            start_of(parent).expect("own fork start"),
            &token,
        ));
        let root_start = start_of(root).unwrap();
        let root_stray = Stray(Pinned::pin(root, root_start, &token));
        let parent_start = start_of(parent).unwrap();

        let result = terminate_tree(root, &identity(root).unwrap());
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert_ne!(start_of(root), Some(root_start), "root survived");
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
        let fixture = Fixture::new(leader);
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
            (root, &identity(root).unwrap()),
            std::slice::from_ref(&id),
            &[],
            crate::proctruth::process_id_of,
            |pid| pid != broker,
            |_| Ok(()),
            &mut UnsignaledCarriers::default(),
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
        let fixture = Fixture::new(leader);
        let tree = captured(root, 3);
        let foreign = tree.iter().find(|member| member.pid != root).unwrap().pid;
        let result = terminate(
            (root, &identity(root).unwrap()),
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
            &mut UnsignaledCarriers::default(),
        );
        assert!(matches!(
            result,
            Err(KillError::Refused(reason))
                if reason.contains("no signal sent")
                    && reason.contains("owned by another row")
                    && reason.contains("not signaled:")
                    && reason.contains(&root.to_string())
                    && reason.contains(&foreign.to_string())
                    && !reason.contains("survivors:")
        ));
        std::thread::sleep(Duration::from_millis(100));
        assert!(tree.iter().all(running), "a member was signaled");
        drop(fixture);
    }

    #[test]
    fn an_unauthorized_late_fork_is_never_signaled_and_reported_unconfirmed() {
        let anchor = spawn("exec sleep 30", 0);
        let group = anchor.id();
        let mut fixture = Fixture::new(anchor);
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
            (root, &identity(root).unwrap()),
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
            &mut UnsignaledCarriers::default(),
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
        name: &str,
        script: &str,
    ) -> (Result<GroupSignal, KillError>, Vec<Member>) {
        let token = marker(name);
        let leader = spawn_marked(script, 0, &token);
        let root = leader.id();
        let fixture = Fixture::new(leader);
        let tree = captured(root, 2);
        let victim_member = tree.iter().find(|member| member.pid != root).unwrap();
        let victim = victim_member.pid;
        let pinned_victim = Pinned::pin(victim, victim_member.start, &token);
        let result = terminate(
            (root, &identity(root).unwrap()),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                if pid != victim {
                    return Ok(());
                }
                // The pinned sleeper, never anything else.
                pinned_victim.signal(libc::SIGKILL);
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
            &mut UnsignaledCarriers::default(),
        );
        drop(fixture);
        (result, tree)
    }

    #[test]
    fn a_member_that_exits_before_its_refusal_is_rechecked_is_gone() {
        // The root execs sleep after its child dies and is reaped.
        let (result, tree) =
            kill_refusing_an_ended_member("refused-reaped", "sleep 30 & wait; exec sleep 30");
        assert_eq!(result, Ok(GroupSignal::Sent));
        assert!(tree.iter().all(|member| !running(member)));
    }

    #[test]
    fn a_zombie_member_behind_a_refusal_is_gone() {
        // The exec'd root never reaps, so the killed child stays a zombie.
        let (result, tree) =
            kill_refusing_an_ended_member("refused-zombie", "sleep 30 & exec sleep 30");
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
        let token = marker("exiting-refusal");
        let leader = spawn_marked(
            "python3 -c 'import time; b = bytearray(1 << 30); \
             b[::4096] = bytes([1]) * (1 << 18); time.sleep(30)' & wait",
            0,
            &token,
        );
        let root = leader.id();
        let fixture = Fixture::new(leader);
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
        let pinned_child = Pinned::pin(child, child_start, &token);

        // Its argv reads empty once its memory is released, so authorize
        // refuses it while it exits: the frontend's flake (b).
        let mut caught = false;
        let result = terminate(
            (root, &identity(root).unwrap()),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                if pid != child {
                    return Ok(());
                }
                // The pinned child, never anything else.
                pinned_child.signal(libc::SIGKILL);
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
            &mut UnsignaledCarriers::default(),
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
            let mut not_signaled = UnsignaledCarriers::default();
            let signal_sent = std::cell::Cell::new(false);
            let mut sweep = Sweep {
                proc_root: root.path(),
                root_start: 1,
                lineage: Lineage::of(&[], 10),
                bound_ids: &[],
                not_signaled: &mut not_signaled,
                signal_sent: &signal_sent,
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
        let gate = dir.path().join("gate");
        let program = dir.path().join("trapped.py");
        // T traps SIGTERM and then waits for the gate before it exits, so it
        // is certainly alive when the refusal comes and certainly gone after
        // the test opens the gate. The root ignores TERM and keeps forking.
        std::fs::write(
            &program,
            "import os, signal, sys, time\n\
             gate, pidfile = sys.argv[1], sys.argv[2]\n\
             def on_term(*_):\n\
             \x20   while not os.path.exists(gate):\n\
             \x20       time.sleep(0.01)\n\
             \x20   sys.exit(0)\n\
             signal.signal(signal.SIGTERM, on_term)\n\
             open(pidfile, 'w').write(str(os.getpid()))\n\
             time.sleep(30)\n",
        )
        .unwrap();
        let script = format!(
            "trap '' TERM; python3 '{}' '{}' '{}' & \
             while :; do sleep 30 & sleep 0.05; done",
            program.display(),
            gate.display(),
            pidfile.display()
        );
        let leader = spawn(&script, 0);
        let root = leader.id();
        let fixture = Fixture::new(leader);
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
            (root, &identity(root).unwrap()),
            &[],
            &[],
            |_| EnvRead::Absent,
            |_| true,
            |pid| {
                let limit = cutoff.get().unwrap_or_else(now_ticks);
                cutoff.set(Some(limit));
                match start_of(pid) {
                    Some(start) if start > limit => {
                        // Only now may T finish exiting: it outlives the
                        // refusal, and is gone long before the deadline.
                        std::fs::write(&gate, b"").unwrap();
                        Err(KillError::Refused(format!("{pid} is foreign")))
                    }
                    _ => Ok(()),
                }
            },
            &mut UnsignaledCarriers::default(),
        );
        let Err(KillError::Unconfirmed { reason, survivors }) = result else {
            panic!("expected an unconfirmed kill, got {result:?}");
        };
        assert!(reason.contains("is foreign"), "{reason}");
        // T was alive when the refusal came (it waited on the gate the
        // refusal opened); the report is taken at the deadline, when T is gone.
        assert!(!survivors.contains(&trapped), "{survivors:?}");
        assert_ne!(start_of(trapped), Some(trapped_start), "T survived");
        drop(fixture);
    }

    #[test]
    fn a_zombie_leader_fronting_a_live_thread_is_captured_and_signaled() {
        // The child's main thread exits alone (SYS_exit, not exit_group)
        // while a second thread sleeps: its leader reads Z, it is alive. It
        // runs in its own session, so only a per-PID signal reaches it.
        // The leader thread waits on a gate the test opens only once the
        // process is pinned and proven: a leader that has exited has
        // released its memory, and with it its readable marker.
        let dir = tempfile::tempdir().unwrap();
        let gate = dir.path().join("gate");
        let token = marker("zombie-leader");
        let leader = spawn_marked(
            &format!(
                "setsid python3 -c 'import ctypes, os, threading, time; \
                 threading.Thread(target=time.sleep, args=(30,), daemon=True).start(); \
                 [time.sleep(0.01) for _ in iter(lambda: os.path.exists(\"{}\"), True)]; \
                 ctypes.CDLL(None).syscall({}, 0)' & wait",
                gate.display(),
                libc::SYS_exit
            ),
            0,
            &token,
        );
        let root = leader.id();
        let fixture = Fixture::new(leader);
        let tree = captured(root, 2);
        let child = tree.iter().find(|member| member.pid != root).unwrap();
        let stray = Stray(Pinned::pin(child.pid, child.start, &token));
        let child = child.pid;
        std::fs::write(&gate, b"").unwrap();
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
