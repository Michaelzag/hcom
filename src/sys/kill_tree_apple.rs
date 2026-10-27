//! Terminate a verified macOS seat root and confirm its captured processes exit.
//!
//! A verified group leader owns its group; other roots authorize only their
//! creation-time-verified descendants. Capture before signaling, reject reused
//! parent links, and never escalate against a different PID incarnation.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::time::Duration;

#[cfg(target_os = "macos")]
use std::time::Instant;

#[cfg(target_os = "macos")]
use super::{
    kill_group,
    process::{
        GroupSignal, KILL_WAIT, KillError, KillState, POLL_STEP, TERM_WAIT, kill_state,
        process_info_apple,
    },
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

#[derive(Debug)]
struct Capture<'a> {
    targets: Vec<Target<'a>>,
    facts: HashMap<u32, &'a ProcFact>,
}

#[derive(Debug, Default)]
struct Refusals {
    roots: HashSet<u32>,
    paths: HashMap<u32, bool>,
    reason: Option<String>,
}

impl Refusals {
    fn record(&mut self, pid: u32, reason: String) {
        if self.roots.insert(pid) {
            self.paths.clear();
        }
        self.reason.get_or_insert(reason);
    }

    fn blocks(
        &mut self,
        candidate: &ProcFact,
        root: u32,
        ancestors: &HashSet<u32>,
        facts: &HashMap<u32, &ProcFact>,
    ) -> bool {
        if self.roots.is_empty() {
            return false;
        }
        if self.roots.contains(&root) {
            return true;
        }
        let roots = &self.roots;
        !eligible_path(
            candidate,
            root,
            ancestors,
            facts,
            &mut self.paths,
            &mut |pid| !roots.contains(&pid),
        )
    }

    fn track(
        &mut self,
        candidate: &ProcFact,
        root: u32,
        ancestors: &HashSet<u32>,
        facts: &HashMap<u32, &ProcFact>,
        mut eligible: impl FnMut(&ProcFact) -> bool,
    ) -> bool {
        self.blocks(candidate, root, ancestors, facts) || eligible(candidate)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Confirmation {
    survivors: Vec<u32>,
    exiting: Vec<u32>,
}

/// Authenticate the root and every parent edge before returning a deepest-first
/// plan. Missing facts never authenticate a path through an unreadable process.
fn kill_tree(
    snapshot: &[ProcFact],
    root: u32,
    expected_start: StartTime,
    mut eligible: impl FnMut(&ProcFact) -> bool,
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
    if !eligible(root_fact) {
        return Ok(Vec::new());
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
            if child.pid <= 1 || child.start_time < target.fact.start_time || !eligible(child) {
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

/// A complete root lineage protects ancestors in every signaling mode. Both
/// capture and the final native preflight use the same bounded proof.
fn ancestry(
    root: ProcFact,
    mut read: impl FnMut(u32) -> Option<ProcFact>,
) -> Result<HashSet<u32>, &'static str> {
    let mut ancestors = HashSet::new();
    let mut child = root;
    while child.ppid > 1 {
        if ancestors.len() == MAX_TREE_DEPTH {
            return Err("root ancestry exceeds the depth limit");
        }
        let parent = read(child.ppid)
            .filter(|parent| parent.pid == child.ppid)
            .ok_or("root ancestry is unreadable")?;
        if parent.pid == root.pid || !ancestors.insert(parent.pid) {
            return Err("cycle in the root ancestry");
        }
        if parent.start_time > child.start_time {
            return Err("root ancestor identity changed during capture");
        }
        child = parent;
    }
    Ok(ancestors)
}

/// Prove a candidate has no ineligible ancestor inside the capture boundary.
/// Memoized paths prevent group capture from reintroducing a pruned subtree.
fn eligible_path(
    candidate: &ProcFact,
    root: u32,
    ancestors: &HashSet<u32>,
    facts: &HashMap<u32, &ProcFact>,
    paths: &mut HashMap<u32, bool>,
    eligible: &mut impl FnMut(u32) -> bool,
) -> bool {
    let mut path = [0; MAX_TREE_DEPTH + 1];
    let mut length = 0;
    let mut child = candidate;
    let allowed = loop {
        if let Some(allowed) = paths.get(&child.pid) {
            break *allowed;
        }
        if length == path.len() {
            break false;
        }
        path[length] = child.pid;
        length += 1;
        if !eligible(child.pid) {
            break false;
        }
        if child.pid == root || child.ppid <= 1 || ancestors.contains(&child.ppid) {
            break true;
        }
        let Some(parent) = facts.get(&child.ppid) else {
            break false;
        };
        if parent.start_time > child.start_time {
            break false;
        }
        child = parent;
    };
    for pid in &path[..length] {
        paths.insert(*pid, allowed);
    }
    allowed
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
    mut eligible: impl FnMut(u32) -> bool,
) -> Result<Capture<'a>, &'static str> {
    let mut decisions = HashMap::new();
    let mut is_eligible = |pid| *decisions.entry(pid).or_insert_with(|| eligible(pid));
    let mut paths = HashMap::new();
    let mut targets = kill_tree(snapshot, root, expected_start, |fact| {
        let allowed = is_eligible(fact.pid);
        if !allowed {
            paths.insert(fact.pid, false);
        }
        allowed
    })?;
    let root_fact = targets
        .last()
        .ok_or("verified owner is ineligible for termination")?
        .fact;
    let mut facts_by_pid: HashMap<_, _> = snapshot.iter().map(|fact| (fact.pid, fact)).collect();
    let ancestors = ancestry(*root_fact, |pid| facts_by_pid.get(&pid).map(|fact| **fact))?;
    let leader = root_group == root && root_fact.pgid == root;
    if leader && group_members.len() > MAX_SNAPSHOT_PROCESSES {
        return Err("process group snapshot exceeds the safety limit");
    }
    if leader {
        for member in group_members {
            if member.pid > 1 && !ancestors.contains(&member.pid) {
                facts_by_pid.insert(member.pid, member);
                if !is_eligible(member.pid) {
                    paths.insert(member.pid, false);
                }
            }
        }
    }
    targets.retain(|target| {
        !ancestors.contains(&target.fact.pid)
            && eligible_path(
                target.fact,
                root,
                &ancestors,
                &facts_by_pid,
                &mut paths,
                &mut is_eligible,
            )
    });
    if !leader {
        // Sharing an ancestor's group doesn't authorize that group. The root
        // and its eligible descendants remain valid individual targets.
        return Ok(Capture {
            targets,
            facts: facts_by_pid,
        });
    }
    let mut by_pid = HashMap::with_capacity(targets.len());
    for (index, target) in targets.iter_mut().enumerate() {
        target.in_group = target.fact.pgid == root;
        by_pid.insert(target.fact.pid, index);
    }
    for member in group_members {
        if member.pid <= 1
            || ancestors.contains(&member.pid)
            || member.pgid != root
            || !eligible_path(
                member,
                root,
                &ancestors,
                &facts_by_pid,
                &mut paths,
                &mut is_eligible,
            )
        {
            continue;
        }
        if let Some(&index) = by_pid.get(&member.pid) {
            let target = &mut targets[index];
            if target.fact.start_time != member.start_time {
                // A fresh incarnation never replaces a captured one. Group
                // eligibility will reject it; per-PID rechecks skip reuse.
                continue;
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
    Ok(Capture {
        targets,
        facts: facts_by_pid,
    })
}

/// Apply self-exclusion only after traversal, so an excluded root or intermediate
/// parent still authenticates descendants. Any excluded group member forbids
/// killpg; the remaining members must then be signaled individually.
fn apply_exclusions(captured: &mut Vec<Target<'_>>, excluded: &[u32]) -> bool {
    let excluded: HashSet<_> = excluded.iter().copied().collect();
    let mut blocks_group = false;
    captured.retain(|target| {
        if excluded.contains(&target.fact.pid) {
            blocks_group |= target.in_group;
            false
        } else {
            true
        }
    });
    blocks_group
}

/// A group signal may reach only captured, still-matching incarnations. Any
/// ancestor, excluded caller, new/unreadable member, or reused PID selects the
/// per-PID path instead of rejecting an otherwise authenticated kill.
fn group_signal_allowed<'p>(
    root: u32,
    root_group: u32,
    captured: &[Target<'_>],
    members: impl IntoIterator<Item = &'p u32>,
    mut current: impl FnMut(u32) -> Option<ProcFact>,
) -> bool {
    if root_group != root || !captured.iter().any(|target| target.fact.pid == root) {
        return false;
    }
    let by_pid: HashMap<_, _> = captured
        .iter()
        .map(|target| (target.fact.pid, target.fact))
        .collect();
    members.into_iter().all(|pid| {
        by_pid.get(pid).is_some_and(|captured| {
            current(*pid).is_some_and(|fact| {
                fact.pid == *pid && fact.pgid == root && fact.start_time == captured.start_time
            })
        })
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observation {
    Gone,
    Exiting(StartTime),
    Present(StartTime),
    Unknown,
}

/// Positive death or PID reuse ends a captured incarnation. Unknown state
/// cannot erase a survivor or an authorization failure for that incarnation.
fn may_survive(expected: StartTime, observed: Observation) -> bool {
    match observed {
        Observation::Gone => false,
        Observation::Present(start) | Observation::Exiting(start) => start == expected,
        Observation::Unknown => true,
    }
}

fn is_signalable(expected: StartTime, observed: Observation) -> bool {
    observed == Observation::Present(expected)
}

fn refusal_stands(expected: StartTime, observed: Observation) -> bool {
    !matches!(observed, Observation::Exiting(_)) && may_survive(expected, observed)
}

/// Refresh a captured lineage before signaling or confirmation. An exited or
/// reused ancestor is still a historical ownership anchor, not a new process
/// whose current eligibility could authorize or block its former children.
fn eligible_now(
    candidate: &ProcFact,
    root: u32,
    ancestors: &HashSet<u32>,
    facts: &HashMap<u32, &ProcFact>,
    paths: &mut HashMap<u32, bool>,
    eligible: &mut impl FnMut(u32) -> bool,
    mut observe: impl FnMut(u32) -> Observation,
) -> bool {
    paths.clear();
    eligible_path(candidate, root, ancestors, facts, paths, &mut |pid| {
        let Some(captured) = facts.get(&pid) else {
            return false;
        };
        match observe(pid) {
            Observation::Gone | Observation::Exiting(_) => true,
            Observation::Present(start) if start != captured.start_time => true,
            Observation::Present(_) | Observation::Unknown => eligible(pid),
        }
    })
}

/// Query failures are survivors, not evidence of exit. A different creation
/// time proves the captured incarnation has gone without authorizing its PID.
fn confirmation(
    captured: &[Target<'_>],
    mut observe: impl FnMut(u32) -> Observation,
) -> Confirmation {
    let mut status = Confirmation::default();
    for target in captured {
        let observed = observe(target.fact.pid);
        if may_survive(target.fact.start_time, observed) {
            status.survivors.push(target.fact.pid);
            if matches!(observed, Observation::Exiting(_)) {
                status.exiting.push(target.fact.pid);
            }
        }
    }
    status.survivors.sort_unstable();
    status.exiting.sort_unstable();
    status
}

fn verdict_reason(first_refusal: Option<String>, exiting: &[u32]) -> Option<String> {
    if exiting.is_empty() {
        return first_refusal;
    }
    let mut reason = first_refusal.unwrap_or_default();
    if !reason.is_empty() {
        reason.push_str("; ");
    }
    write!(&mut reason, "exiting: {exiting:?}").expect("writing to String cannot fail");
    Some(reason)
}

/// The native wrapper supplies elapsed time and sleep; tests supply a pure
/// deterministic clock. Refused members remain observable until this settles.
fn confirm_until(
    captured: &mut Vec<Target<'_>>,
    grace: Duration,
    poll_step: Duration,
    mut retain: impl FnMut(&ProcFact) -> bool,
    mut observe: impl FnMut(u32) -> Observation,
    mut now: impl FnMut() -> Duration,
    mut pause: impl FnMut(Duration),
) -> Confirmation {
    let deadline = now().saturating_add(grace);
    loop {
        captured.retain(|target| retain(target.fact));
        let status = confirmation(captured, &mut observe);
        let current = now();
        if status.survivors.is_empty() || current >= deadline {
            return status;
        }
        pause(poll_step.min(deadline.saturating_sub(current)));
    }
}

#[cfg(target_os = "macos")]
fn apple_start(identity: &str) -> Result<StartTime, &'static str> {
    let (seconds, micros) = identity
        .strip_prefix("apple:")
        .and_then(|identity| identity.split_once(':'))
        .ok_or("recorded Apple process creation time is unreadable")?;
    Ok((
        seconds
            .parse::<u64>()
            .map_err(|_| "recorded Apple process creation time is unreadable")?,
        micros
            .parse::<u64>()
            .ok()
            .filter(|micros| *micros < 1_000_000)
            .ok_or("recorded Apple process creation time is unreadable")?,
    ))
}

/// `expected` is the native `apple:seconds:microseconds` seat-root identity.
/// Return success after every remaining eligible, non-excluded incarnation
/// exits or its PID is reused. A protected/excluded root is never claimed dead;
/// only explicit self-exclusion permits its original incarnation to remain.
#[cfg(target_os = "macos")]
pub(crate) fn terminate(
    root: u32,
    expected: &str,
    excluded: &[u32],
    mut eligible: impl FnMut(u32) -> bool,
    mut authorize: impl FnMut(u32) -> Result<(), KillError>,
) -> Result<GroupSignal, KillError> {
    let expected_start = apple_start(expected)?;
    // Authenticate before any enumeration or signal, not just at the last
    // moment. A stale receipt never authorizes capture from a recycled root.
    let verified_root = process_fact(root)
        .filter(|fact| fact.start_time == expected_start)
        .ok_or("owner identity changed or became unreadable before tree capture")?;
    let snapshot = snapshot()?;
    let group_members = if verified_root.pgid == root {
        group_snapshot(root, &snapshot)?
    } else {
        Vec::new()
    };
    let Capture { mut targets, facts } = capture_members(
        &snapshot,
        root,
        expected_start,
        verified_root.pgid,
        &group_members,
        &mut eligible,
    )?;
    let current_root = process_fact(root)
        .filter(|fact| fact.start_time == expected_start)
        .ok_or("owner identity changed before tree termination")?;
    let current_ancestors = ancestry(current_root, process_fact)?;
    let mut paths = HashMap::new();
    targets.retain(|target| {
        !current_ancestors.contains(&target.fact.pid)
            && eligible_now(
                target.fact,
                root,
                &current_ancestors,
                &facts,
                &mut paths,
                &mut eligible,
                observe,
            )
    });
    let blocks_group = apply_exclusions(&mut targets, excluded);
    let initial_group_ok = authorize_initial(&targets, &mut authorize)?;
    let mut refused = Refusals::default();
    let mut signal_group = false;
    let mut outcome = GroupSignal::NotFound;
    // If the group cannot be re-proven, the captured PID targets remain safe.
    if current_root.pgid == root
        && !blocks_group
        && initial_group_ok
        && is_signalable(expected_start, observe(root))
        && let Ok(members) = kill_group::capture_members(root)
        && members.iter().all(|member| member.state == KillState::Live)
    {
        signal_group = group_signal_allowed(
            root,
            current_root.pgid,
            &targets,
            members.iter().map(|member| &member.pid),
            signalable_fact,
        );
        if signal_group {
            for member in &members {
                let pid = member.pid;
                let captured = facts
                    .get(&pid)
                    .ok_or("captured group member lost its process facts")?;
                if refused.blocks(captured, root, &current_ancestors, &facts)
                    || !eligible_now(
                        captured,
                        root,
                        &current_ancestors,
                        &facts,
                        &mut paths,
                        &mut eligible,
                        observe,
                    )
                {
                    signal_group = false;
                    break;
                }
                if let Err(error) = authorize(pid)
                    && targets
                        .iter()
                        .find(|target| target.fact.pid == pid)
                        .is_none_or(|target| refusal_stands(target.fact.start_time, observe(pid)))
                {
                    record_refusal(&mut refused, captured, error);
                    signal_group = false;
                    break;
                }
            }
            // Ownership checks can query other state. Any membership change
            // during those checks selects the per-PID path, never a blind
            // signal to newly joined or otherwise uncaptured processes.
            if signal_group {
                signal_group = kill_group::capture_members(root)
                    .ok()
                    .filter(|current| current == &members)
                    .is_some_and(|current| {
                        group_signal_allowed(
                            root,
                            current_root.pgid,
                            &targets,
                            current.iter().map(|member| &member.pid),
                            signalable_fact,
                        ) && current.iter().all(|member| {
                            facts.get(&member.pid).is_some_and(|fact| {
                                eligible_now(
                                    fact,
                                    root,
                                    &current_ancestors,
                                    &facts,
                                    &mut paths,
                                    &mut eligible,
                                    observe,
                                )
                            })
                        })
                    });
            }
        }
        if signal_group {
            let checked_root = signalable_fact(root)
                .filter(|fact| {
                    fact.start_time == expected_start
                        && fact.pgid == root
                        && fact.ppid == current_root.ppid
                })
                .ok_or("owner identity or ancestry changed before the group signal")?;
            // SAFETY: the root's identity and ancestry were rechecked, and
            // every fresh group member is a captured matching incarnation.
            // Ancestors and excluded callers are absent from that set.
            outcome = signal_result(unsafe {
                libc::killpg(checked_root.pid as libc::pid_t, libc::SIGTERM)
            });
        }
    }
    for target in &targets {
        if signal_group && target.in_group {
            continue;
        }
        if refused.blocks(target.fact, root, &current_ancestors, &facts) {
            continue;
        }
        if !eligible_now(
            target.fact,
            root,
            &current_ancestors,
            &facts,
            &mut paths,
            &mut eligible,
            observe,
        ) {
            continue;
        }
        match signal_one(target, libc::SIGTERM, &mut authorize, |fact| {
            eligible_now(
                fact,
                root,
                &current_ancestors,
                &facts,
                &mut paths,
                &mut eligible,
                observe,
            )
        }) {
            Ok(Some(result)) if result == GroupSignal::Sent || outcome != GroupSignal::Sent => {
                outcome = result;
            }
            Ok(_) => {}
            Err(error) => {
                record_refusal(&mut refused, target.fact, error);
            }
        }
    }
    let remaining = wait_for_exit(&mut targets, TERM_WAIT, |fact| {
        refused.track(fact, root, &current_ancestors, &facts, |fact| {
            eligible_now(
                fact,
                root,
                &current_ancestors,
                &facts,
                &mut paths,
                &mut eligible,
                observe,
            )
        })
    });
    if remaining.survivors.is_empty() {
        return finish(
            root,
            expected_start,
            excluded,
            &targets,
            outcome,
            remaining,
            refused.reason,
        );
    }
    // Reauthorize the complete late batch before any escalation can signal a
    // descendant of a newly unreadable or differently bound process.
    targets.retain(|target| {
        refused.track(target.fact, root, &current_ancestors, &facts, |fact| {
            eligible_now(
                fact,
                root,
                &current_ancestors,
                &facts,
                &mut paths,
                &mut eligible,
                observe,
            )
        })
    });
    authorize_late(
        &targets,
        root,
        &current_ancestors,
        &facts,
        &mut refused,
        &mut authorize,
    );
    // The root may already have exited; escalation never repeats killpg.
    for target in &targets {
        if refused.blocks(target.fact, root, &current_ancestors, &facts) {
            continue;
        }
        if !eligible_now(
            target.fact,
            root,
            &current_ancestors,
            &facts,
            &mut paths,
            &mut eligible,
            observe,
        ) {
            continue;
        }
        if remaining.survivors.binary_search(&target.fact.pid).is_ok() {
            match signal_one(target, libc::SIGKILL, &mut authorize, |fact| {
                eligible_now(
                    fact,
                    root,
                    &current_ancestors,
                    &facts,
                    &mut paths,
                    &mut eligible,
                    observe,
                )
            }) {
                Ok(Some(result)) if result == GroupSignal::Sent || outcome != GroupSignal::Sent => {
                    outcome = result;
                }
                Ok(_) => {}
                Err(error) => {
                    record_refusal(&mut refused, target.fact, error);
                }
            }
        }
    }
    let remaining = wait_for_exit(&mut targets, KILL_WAIT, |fact| {
        refused.track(fact, root, &current_ancestors, &facts, |fact| {
            eligible_now(
                fact,
                root,
                &current_ancestors,
                &facts,
                &mut paths,
                &mut eligible,
                observe,
            )
        })
    });
    finish(
        root,
        expected_start,
        excluded,
        &targets,
        outcome,
        remaining,
        refused.reason,
    )
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
fn group_snapshot(root: u32, snapshot: &[ProcFact]) -> Result<Vec<ProcFact>, String> {
    let members = kill_group::capture_members(root)?;
    let mut facts = Vec::with_capacity(members.len());
    for member in members {
        let start = apple_start(&member.identity)?;
        match process_fact(member.pid) {
            Some(fact) if fact.start_time != start => continue,
            Some(mut fact) => {
                // The stamped group snapshot authorizes this membership even
                // if the same incarnation left the group before its info read.
                fact.pgid = root;
                facts.push(fact);
            }
            None if kill_state(member.pid) == KillState::Gone => {}
            None => {
                // Exiting can race a second info query. A matching fact from
                // the full snapshot keeps its ancestry and captured identity.
                let mut fact = snapshot
                    .iter()
                    .find(|fact| fact.pid == member.pid && fact.start_time == start)
                    .copied()
                    .ok_or_else(|| format!("group member {} ancestry is unreadable", member.pid))?;
                fact.pgid = root;
                facts.push(fact);
            }
        }
    }
    Ok(facts)
}

#[cfg(target_os = "macos")]
fn observe(pid: u32) -> Observation {
    let state = kill_state(pid);
    if state == KillState::Gone {
        return Observation::Gone;
    }
    if state == KillState::Unknown {
        return Observation::Unknown;
    }
    let Some(fact) = process_fact(pid) else {
        return Observation::Unknown;
    };
    match state {
        KillState::Live => Observation::Present(fact.start_time),
        KillState::Exiting => Observation::Exiting(fact.start_time),
        KillState::Gone | KillState::Unknown => unreachable!(),
    }
}

#[cfg(target_os = "macos")]
fn signalable_fact(pid: u32) -> Option<ProcFact> {
    let fact = process_fact(pid)?;
    is_signalable(fact.start_time, observe(pid)).then_some(fact)
}

#[cfg(target_os = "macos")]
fn signal_one(
    target: &Target<'_>,
    signal: libc::c_int,
    authorize: &mut impl FnMut(u32) -> Result<(), KillError>,
    mut eligible: impl FnMut(&ProcFact) -> bool,
) -> Result<Option<GroupSignal>, KillError> {
    if !is_signalable(target.fact.start_time, observe(target.fact.pid)) {
        return Ok(None);
    }
    if let Err(error) = authorize(target.fact.pid) {
        return if refusal_stands(target.fact.start_time, observe(target.fact.pid)) {
            Err(error)
        } else {
            Ok(None)
        };
    }
    if !eligible(target.fact) || !is_signalable(target.fact.start_time, observe(target.fact.pid)) {
        return Ok(None);
    }
    // SAFETY: the current incarnation was authorized and rechecked as one
    // positive PID. The caller supplies only SIGTERM or SIGKILL.
    Ok(Some(signal_result(unsafe {
        libc::kill(target.fact.pid as libc::pid_t, signal)
    })))
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
fn wait_for_exit(
    captured: &mut Vec<Target<'_>>,
    grace: Duration,
    retain: impl FnMut(&ProcFact) -> bool,
) -> Confirmation {
    let started = Instant::now();
    confirm_until(
        captured,
        grace,
        POLL_STEP,
        retain,
        observe,
        || started.elapsed(),
        std::thread::sleep,
    )
}

#[cfg(target_os = "macos")]
fn authorize_initial(
    captured: &[Target<'_>],
    authorize: &mut impl FnMut(u32) -> Result<(), KillError>,
) -> Result<bool, KillError> {
    let mut group_ok = true;
    for target in captured {
        if let Err(error) = authorize(target.fact.pid) {
            if refusal_stands(target.fact.start_time, observe(target.fact.pid)) {
                return Err(error);
            }
            group_ok = false;
        }
    }
    Ok(group_ok)
}

#[cfg(target_os = "macos")]
fn record_refusal(refused: &mut Refusals, captured: &ProcFact, error: KillError) {
    if refusal_stands(captured.start_time, observe(captured.pid)) {
        let reason = match error {
            KillError::Refused(reason) | KillError::Unconfirmed { reason, .. } => reason,
            other => other.reason().to_owned(),
        };
        refused.record(captured.pid, reason);
    }
}

#[cfg(target_os = "macos")]
fn authorize_late(
    captured: &[Target<'_>],
    root: u32,
    ancestors: &HashSet<u32>,
    facts: &HashMap<u32, &ProcFact>,
    refused: &mut Refusals,
    authorize: &mut impl FnMut(u32) -> Result<(), KillError>,
) {
    for target in captured {
        if !refused.blocks(target.fact, root, ancestors, facts)
            && let Err(error) = authorize(target.fact.pid)
        {
            record_refusal(refused, target.fact, error);
        }
    }
}

#[cfg(target_os = "macos")]
fn finish(
    root: u32,
    expected_start: StartTime,
    excluded: &[u32],
    captured: &[Target<'_>],
    outcome: GroupSignal,
    mut status: Confirmation,
    first_refusal: Option<String>,
) -> Result<GroupSignal, KillError> {
    // Never re-probe an already confirmed root: a later PID reuse must not
    // resurrect its captured incarnation. A pruned protected root still needs
    // positive death evidence unless the caller explicitly excluded it.
    if !excluded.contains(&root) && !captured.iter().any(|target| target.fact.pid == root) {
        let observed = observe(root);
        if may_survive(expected_start, observed) {
            status.survivors.push(root);
            status.survivors.sort_unstable();
            if matches!(observed, Observation::Exiting(_)) {
                status.exiting.push(root);
                status.exiting.sort_unstable();
            }
        }
    }
    if status.survivors.is_empty() {
        Ok(outcome)
    } else if let Some(reason) = verdict_reason(first_refusal, &status.exiting) {
        Err(KillError::Unconfirmed {
            reason,
            survivors: status.survivors,
        })
    } else {
        Err(KillError::Survivors(status.survivors))
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
        kill_tree(snapshot, root.pid, root.start_time, |_| true)
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
            kill_tree(&snapshot, root.pid, root.start_time, |_| true).unwrap_err(),
            "cycle in the verified owner's process tree"
        );
        let self_parent = fact(10, 10, 10);
        assert!(kill_tree(&[self_parent], 10, self_parent.start_time, |_| true).is_err());
    }

    #[test]
    fn kill_tree_enforces_the_depth_boundary() {
        let root = fact(10, 5, 0);
        let mut snapshot = vec![root];
        for depth in 1..=MAX_TREE_DEPTH {
            snapshot.push(fact(10 + depth as u32, 9 + depth as u32, depth as u64));
        }
        let plan = kill_tree(&snapshot, root.pid, root.start_time, |_| true).unwrap();
        assert_eq!(plan.first().unwrap().depth, MAX_TREE_DEPTH);
        assert_eq!(plan.last().unwrap().fact, &root);

        let depth = MAX_TREE_DEPTH + 1;
        snapshot.push(fact(10 + depth as u32, 9 + depth as u32, depth as u64));
        assert_eq!(
            kill_tree(&snapshot, root.pid, root.start_time, |_| true).unwrap_err(),
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
        let plan = kill_tree(&snapshot, root.pid, root.start_time, |_| true).unwrap();
        assert_eq!(plan.len(), MAX_TREE_PROCESSES);
        assert_eq!(plan.last().unwrap().fact, &root);

        snapshot.push(fact(10 + MAX_TREE_PROCESSES as u32, 10, 9_000));
        assert_eq!(
            kill_tree(&snapshot, root.pid, root.start_time, |_| true).unwrap_err(),
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
            kill_tree(&[root], 10, (100, 9), |_| true).unwrap_err(),
            "owner identity changed before the process snapshot"
        );
        assert_eq!(
            kill_tree(&[root], 11, root.start_time, |_| true).unwrap_err(),
            "verified owner is missing from the process snapshot"
        );
        for reserved in [0, 1] {
            assert_eq!(
                kill_tree(&[fact(reserved, 0, 10)], reserved, root.start_time, |_| {
                    true
                })
                .unwrap_err(),
                "refusing to terminate a reserved process ID"
            );
        }
    }

    #[test]
    fn kill_tree_rejects_duplicate_snapshot_pids() {
        let root = fact(10, 5, 10);
        assert_eq!(
            kill_tree(&[root, fact(10, 11, 10)], 10, root.start_time, |_| true).unwrap_err(),
            "process snapshot contains a duplicate PID"
        );
    }

    #[test]
    fn kill_tree_bounds_the_snapshot_before_walking_it() {
        let root = fact(10, 5, 10);
        let snapshot = vec![root; MAX_SNAPSHOT_PROCESSES + 1];
        assert_eq!(
            kill_tree(&snapshot, root.pid, root.start_time, |_| true).unwrap_err(),
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
        let snapshot = [
            root,
            escaped,
            child,
            fact(5, 2, 1),
            fact(6, 5, 2),
            fact(2, 1, 0),
        ];
        let members = [
            root,
            child,
            reparented,
            ProcFact {
                pgid: 10,
                ..fact(1, 10, 11)
            },
        ];
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &members, |_| true)
            .unwrap()
            .targets;
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
        let snapshot = [root, parent, sibling, child, fact(2, 1, 0)];
        let members = [root, parent, sibling, child];
        let captured = capture_members(&snapshot, 10, root.start_time, 5, &members, |_| true)
            .unwrap()
            .targets;
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [11, 10]);
        assert!(captured.iter().all(|target| !target.in_group));
        let member_pids: Vec<_> = members.iter().map(|fact| fact.pid).collect();
        assert!(!group_signal_allowed(
            10,
            5,
            &captured,
            &member_pids,
            |pid| { members.iter().find(|fact| fact.pid == pid).copied() }
        ));
    }

    #[test]
    fn kill_tree_capture_preserves_the_original_incarnation_on_reuse() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 1, 10)
        };
        let child = ProcFact {
            pgid: 10,
            ..fact(11, 10, 11)
        };
        let replacement = ProcFact {
            start_time: (100, 12),
            ..child
        };
        let snapshot = [root, child];
        let members = [root, replacement];
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &members, |_| true)
            .unwrap()
            .targets;
        assert!(!group_signal_allowed(10, 10, &captured, &[10, 11], |pid| {
            members.iter().find(|fact| fact.pid == pid).copied()
        }));
        assert_eq!(
            confirmation(&captured, |pid| {
                Observation::Present(if pid == 10 {
                    root.start_time
                } else {
                    replacement.start_time
                })
            })
            .survivors,
            [10]
        );
    }

    #[test]
    fn kill_tree_capture_uses_pids_after_a_root_group_change() {
        let root = fact(10, 1, 10);
        let snapshot = [root, fact(11, 10, 11)];
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &[], |_| true)
            .unwrap()
            .targets;
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [11, 10]);
        assert!(!group_signal_allowed(10, 5, &captured, &[10, 11], |pid| {
            snapshot.iter().find(|fact| fact.pid == pid).copied()
        }));
    }

    #[test]
    fn kill_tree_capture_bounds_additional_group_members() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 1, 0)
        };
        let snapshot = [root];
        let mut members: Vec<_> = (0..MAX_TREE_PROCESSES - 1)
            .map(|index| ProcFact {
                pgid: 10,
                ..fact(20 + index as u32, 1, index as u64)
            })
            .collect();
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &members, |_| true)
            .unwrap()
            .targets;
        assert_eq!(captured.len(), MAX_TREE_PROCESSES);
        assert_eq!(captured.last().unwrap().fact.pid, 10);
        members.push(ProcFact {
            pgid: 10,
            ..fact(20 + MAX_TREE_PROCESSES as u32, 1, 9_000)
        });
        assert_eq!(
            capture_members(&snapshot, 10, root.start_time, 10, &members, |_| true).unwrap_err(),
            "captured process set exceeds the size limit"
        );
    }

    #[test]
    fn kill_tree_survivors_require_positive_exit_or_reuse_evidence() {
        let root = fact(10, 1, 10);
        let snapshot = [root, fact(11, 10, 11), fact(12, 10, 12), fact(13, 10, 13)];
        let captured = capture_members(&snapshot, 10, root.start_time, 5, &[], |_| true)
            .unwrap()
            .targets;
        let remaining = confirmation(&captured, |pid| match pid {
            10 => Observation::Present(root.start_time),
            11 => Observation::Gone,
            12 => Observation::Present((100, 14)),
            13 => Observation::Unknown,
            _ => panic!("unexpected captured PID"),
        });
        assert_eq!(remaining.survivors, [10, 13]);
    }

    #[test]
    fn kill_tree_survivors_accept_gone_or_reused_roots_and_children() {
        let root = fact(10, 1, 10);
        let snapshot = [root, fact(11, 10, 11)];
        let captured = capture_members(&snapshot, 10, root.start_time, 5, &[], |_| true)
            .unwrap()
            .targets;
        assert_eq!(
            confirmation(&captured, |pid| {
                if pid == 10 {
                    Observation::Present((101, 0))
                } else {
                    Observation::Gone
                }
            })
            .survivors,
            Vec::<u32>::new()
        );
    }

    #[test]
    fn kill_tree_capture_uses_pids_for_an_unconfirmed_group_departure() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 1, 10)
        };
        // The PID-only group scan saw this member, but its identity query now
        // reports another group. It might have escaped, not exited/reused.
        let departed = fact(20, 1, 20);
        let snapshot = [root];
        let members = [root, departed];
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &members, |_| true)
            .unwrap()
            .targets;
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [10]);
        assert!(!group_signal_allowed(10, 10, &captured, &[10, 20], |pid| {
            members.iter().find(|fact| fact.pid == pid).copied()
        }));
    }

    #[test]
    fn kill_tree_capture_excludes_an_ancestor_and_uses_pids() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 5, 10)
        };
        let parent = ProcFact {
            pgid: 10,
            ..fact(5, 1, 5)
        };
        let snapshot = [root, parent, fact(11, 10, 11)];
        let members = [root, parent];
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &members, |_| true)
            .unwrap()
            .targets;
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [11, 10]);
        assert!(!group_signal_allowed(10, 10, &captured, &[10, 5], |pid| {
            members.iter().find(|fact| fact.pid == pid).copied()
        }));
    }

    #[test]
    fn kill_tree_capture_excludes_a_grandparent_and_uses_pids() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 5, 10)
        };
        let parent = fact(5, 2, 5);
        let grandparent = ProcFact {
            pgid: 10,
            ..fact(2, 1, 2)
        };
        let snapshot = [root, parent, grandparent];
        let members = [root, grandparent];
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &members, |_| true)
            .unwrap()
            .targets;
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [10]);
        assert!(!group_signal_allowed(10, 10, &captured, &[10, 2], |pid| {
            members.iter().find(|fact| fact.pid == pid).copied()
        }));
    }

    #[test]
    fn kill_tree_capture_excludes_an_ancestor_that_joined_after_the_snapshot() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 5, 10)
        };
        let parent = fact(5, 1, 5);
        let joined = ProcFact { pgid: 10, ..parent };
        let snapshot = [root, parent];
        let members = [root, joined];
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &members, |_| true)
            .unwrap()
            .targets;
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [10]);
        assert!(!group_signal_allowed(10, 10, &captured, &[10, 5], |pid| {
            members.iter().find(|fact| fact.pid == pid).copied()
        }));
    }

    #[test]
    fn kill_tree_capture_requires_complete_ancestry() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 5, 10)
        };
        assert_eq!(
            capture_members(&[root], 10, root.start_time, 10, &[root], |_| true).unwrap_err(),
            "root ancestry is unreadable"
        );
        let nonleader = ProcFact { pgid: 5, ..root };
        let snapshot = [nonleader, fact(11, 10, 11)];
        assert_eq!(
            capture_members(&snapshot, 10, root.start_time, 5, &[], |_| true).unwrap_err(),
            "root ancestry is unreadable"
        );
    }

    #[test]
    fn kill_tree_ancestry_rejects_cycles_and_reused_parent_ids() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 5, 10)
        };
        let cycle = [fact(5, 2, 10), fact(2, 5, 10)];
        assert_eq!(
            ancestry(root, |pid| cycle
                .iter()
                .find(|fact| fact.pid == pid)
                .copied())
            .unwrap_err(),
            "cycle in the root ancestry"
        );
        assert_eq!(
            ancestry(root, |_| Some(fact(5, 1, 11))).unwrap_err(),
            "root ancestor identity changed during capture"
        );
    }

    #[test]
    fn kill_tree_ancestry_enforces_the_depth_boundary() {
        let root = ProcFact {
            pgid: 1_000,
            ..fact(1_000, 999, 1_000)
        };
        let mut snapshot: Vec<_> = (0..MAX_TREE_DEPTH)
            .map(|index| {
                let pid = 999 - index as u32;
                let ppid = if index + 1 == MAX_TREE_DEPTH {
                    1
                } else {
                    pid - 1
                };
                fact(pid, ppid, pid as u64)
            })
            .collect();
        let ancestors = ancestry(root, |pid| {
            snapshot.iter().find(|fact| fact.pid == pid).copied()
        })
        .unwrap();
        assert_eq!(ancestors.len(), MAX_TREE_DEPTH);
        let next = snapshot.last().unwrap().pid - 1;
        snapshot.last_mut().unwrap().ppid = next;
        snapshot.push(fact(next, 1, next as u64));
        assert_eq!(
            ancestry(root, |pid| {
                snapshot.iter().find(|fact| fact.pid == pid).copied()
            })
            .unwrap_err(),
            "root ancestry exceeds the depth limit"
        );
    }

    #[test]
    fn kill_tree_exclusions_keep_nonleader_anchors_but_never_require_their_exit() {
        let root = fact(10, 1, 10);
        let snapshot = [root, fact(11, 10, 11), fact(12, 11, 12), fact(13, 10, 13)];
        let mut captured = capture_members(&snapshot, 10, root.start_time, 5, &[], |_| true)
            .unwrap()
            .targets;
        assert!(!apply_exclusions(&mut captured, &[10, 11]));
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [12, 13]);
        assert_eq!(
            confirmation(&captured, |pid| {
                match pid {
                    12 => Observation::Present((100, 12)),
                    13 => Observation::Present((100, 13)),
                    _ => panic!("excluded caller chain must never be observed"),
                }
            })
            .survivors,
            [12, 13]
        );
    }

    #[test]
    fn kill_tree_excluded_group_member_forces_remaining_members_to_use_pids() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 1, 10)
        };
        let child = ProcFact {
            pgid: 10,
            ..fact(11, 10, 11)
        };
        let escaped = ProcFact {
            pgid: 99,
            ..fact(12, 11, 12)
        };
        let excluded = ProcFact {
            pgid: 10,
            ..fact(20, 1, 20)
        };
        let snapshot = [root, child, escaped];
        let members = [root, child, excluded];
        let mut captured = capture_members(&snapshot, 10, root.start_time, 10, &members, |_| true)
            .unwrap()
            .targets;
        assert!(apply_exclusions(&mut captured, &[20]));
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [12, 11, 10]);
    }

    #[test]
    fn kill_tree_excluded_leader_still_authenticates_nonexcluded_descendants() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 1, 10)
        };
        let child = ProcFact {
            pgid: 10,
            ..fact(11, 10, 11)
        };
        let leaf = ProcFact {
            pgid: 10,
            ..fact(12, 11, 12)
        };
        let snapshot = [root, child, leaf];
        let mut captured = capture_members(&snapshot, 10, root.start_time, 10, &snapshot, |_| true)
            .unwrap()
            .targets;
        assert!(apply_exclusions(&mut captured, &[10, 11]));
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [12]);
        assert_eq!(
            confirmation(&captured, |pid| {
                assert_eq!(pid, 12, "excluded roots are not survivor probes");
                Observation::Gone
            })
            .survivors,
            Vec::<u32>::new()
        );
    }

    #[test]
    fn kill_tree_excluding_an_escaped_member_does_not_block_the_owned_group() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 1, 10)
        };
        let escaped = fact(11, 10, 11);
        let snapshot = [root, escaped];
        let members = [root];
        let mut captured = capture_members(&snapshot, 10, root.start_time, 10, &members, |_| true)
            .unwrap()
            .targets;
        assert!(!apply_exclusions(&mut captured, &[11]));
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [10]);
    }

    #[test]
    fn kill_tree_group_signal_requires_every_member_to_be_captured_and_readable() {
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 1, 10)
        };
        let child = ProcFact {
            pgid: 10,
            ..fact(11, 10, 11)
        };
        let snapshot = [root, child];
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &snapshot, |_| true)
            .unwrap()
            .targets;
        assert!(group_signal_allowed(10, 10, &captured, &[10, 11], |pid| {
            snapshot.iter().find(|fact| fact.pid == pid).copied()
        }));
        assert!(!group_signal_allowed(
            10,
            10,
            &captured,
            &[10, 11, 20],
            |pid| { snapshot.iter().find(|fact| fact.pid == pid).copied() }
        ));
        assert!(!group_signal_allowed(10, 10, &captured, &[10, 11], |pid| {
            (pid == 10).then_some(root)
        }));
    }

    #[test]
    fn kill_tree_ineligible_bound_broker_prunes_its_entire_nonleader_subtree() {
        let bound_id = "seat-bound-id";
        let processes = [
            (fact(10, 1, 10), bound_id, true),
            (fact(11, 10, 11), bound_id, false),
            (fact(12, 11, 12), bound_id, true),
            (fact(13, 10, 13), bound_id, true),
        ];
        let snapshot: Vec<_> = processes.iter().map(|(fact, _, _)| *fact).collect();
        let captured = capture_members(&snapshot, 10, (100, 10), 5, &[], |pid| {
            let (_, binding, allowed) = processes
                .iter()
                .find(|(fact, _, _)| fact.pid == pid)
                .unwrap();
            // Matching the seat's ID never overrides the injected decision.
            assert_eq!(*binding, bound_id);
            *allowed
        })
        .unwrap()
        .targets;
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [13, 10]);
    }

    #[test]
    fn kill_tree_bound_broker_cannot_reenter_through_group_capture() {
        let bound_id = "seat-bound-id";
        let root = ProcFact {
            pgid: 10,
            ..fact(10, 1, 10)
        };
        let broker = ProcFact {
            pgid: 10,
            ..fact(11, 10, 11)
        };
        let worker = ProcFact {
            pgid: 10,
            ..fact(12, 11, 12)
        };
        let sibling = ProcFact {
            pgid: 10,
            ..fact(13, 10, 13)
        };
        let processes = [
            (root, bound_id, true),
            (broker, bound_id, false),
            (worker, bound_id, true),
            (sibling, bound_id, true),
        ];
        let snapshot: Vec<_> = processes.iter().map(|(fact, _, _)| *fact).collect();
        // Encountering the worker before the broker must not bypass pruning.
        let members = [worker, broker, sibling, root];
        let captured = capture_members(&snapshot, 10, root.start_time, 10, &members, |pid| {
            let (_, binding, allowed) = processes
                .iter()
                .find(|(fact, _, _)| fact.pid == pid)
                .unwrap();
            assert_eq!(*binding, bound_id);
            *allowed
        })
        .unwrap()
        .targets;
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [13, 10]);
        assert!(!group_signal_allowed(
            10,
            10,
            &captured,
            &[10, 11, 12, 13],
            |pid| { snapshot.iter().find(|fact| fact.pid == pid).copied() }
        ));
    }

    #[test]
    fn kill_tree_prunes_a_bound_broker_before_its_subtree_can_hit_the_depth_cap() {
        let bound_id = "seat-bound-id";
        let root = fact(10, 1, 10);
        let mut snapshot = vec![root, fact(11, 10, 11), fact(13, 10, 13)];
        for index in 0..=MAX_TREE_DEPTH + 1 {
            let pid = 20 + index as u32;
            let ppid = if index == 0 { 11 } else { pid - 1 };
            snapshot.push(fact(pid, ppid, pid as u64));
        }
        let bindings: HashMap<_, _> = snapshot.iter().map(|fact| (fact.pid, bound_id)).collect();
        let captured = capture_members(&snapshot, 10, root.start_time, 5, &[], |pid| {
            assert_eq!(bindings.get(&pid), Some(&bound_id));
            pid != 11
        })
        .unwrap()
        .targets;
        let pids: Vec<_> = captured.iter().map(|target| target.fact.pid).collect();
        assert_eq!(pids, [13, 10]);
    }

    #[test]
    fn kill_tree_dynamic_eligibility_protects_broker_children_and_keeps_gone_anchors() {
        let bound_id = "seat-bound-id";
        let root = fact(10, 1, 10);
        let broker = fact(11, 10, 11);
        let worker = fact(12, 11, 12);
        let snapshot = [root, broker, worker];
        let bindings: HashMap<_, _> = snapshot.iter().map(|fact| (fact.pid, bound_id)).collect();
        let capture = capture_members(&snapshot, 10, root.start_time, 5, &[], |_| true).unwrap();
        let ancestors = HashSet::new();
        let mut paths = HashMap::new();
        let observe = |pid| {
            if pid == 10 {
                Observation::Gone
            } else {
                Observation::Present(capture.facts[&pid].start_time)
            }
        };
        let mut broker_policy = |pid| {
            assert_eq!(bindings.get(&pid), Some(&bound_id));
            pid != 11
        };
        assert!(!eligible_now(
            &worker,
            10,
            &ancestors,
            &capture.facts,
            &mut paths,
            &mut broker_policy,
            observe,
        ));
        // Root termination cannot strand owned children during escalation.
        // The dead root's current inability to pass argv checks is irrelevant.
        assert!(eligible_now(
            &worker,
            10,
            &ancestors,
            &capture.facts,
            &mut paths,
            &mut |pid| pid != 10,
            observe,
        ));
        assert!(eligible_now(
            &worker,
            10,
            &ancestors,
            &capture.facts,
            &mut paths,
            &mut |pid| pid != 10,
            |pid| {
                Observation::Present(if pid == 10 {
                    (101, 0)
                } else {
                    capture.facts[&pid].start_time
                })
            },
        ));
    }

    #[test]
    fn kill_tree_exiting_member_is_unsignalable_until_confirmed_gone() {
        let root = fact(10, 1, 10);
        let child = fact(11, 10, 11);
        let snapshot = [root, child];
        let mut captured = capture_members(&snapshot, 10, root.start_time, 5, &[], |_| true)
            .unwrap()
            .targets;
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let transition = Duration::from_millis(100);
        let grace = Duration::from_millis(300);
        let status = confirm_until(
            &mut captured,
            grace,
            transition,
            |_| true,
            |pid| {
                let observed = if pid == root.pid || elapsed.get() >= transition {
                    Observation::Gone
                } else {
                    Observation::Exiting(child.start_time)
                };
                assert!(!is_signalable(child.start_time, observed));
                assert!(!refusal_stands(child.start_time, observed));
                observed
            },
            || elapsed.get(),
            |step| elapsed.set(elapsed.get() + step),
        );
        assert_eq!(status, Confirmation::default());
        assert!(elapsed.get() >= transition && elapsed.get() < grace);
    }

    #[test]
    fn kill_tree_exiting_member_at_the_deadline_remains_a_survivor() {
        let root = fact(10, 1, 10);
        let child = fact(11, 10, 11);
        let snapshot = [root, child];
        let mut captured = capture_members(&snapshot, 10, root.start_time, 5, &[], |_| true)
            .unwrap()
            .targets;
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let grace = Duration::from_millis(250);
        let status = confirm_until(
            &mut captured,
            grace,
            Duration::from_millis(100),
            |_| true,
            |pid| {
                if pid == root.pid {
                    Observation::Gone
                } else {
                    let observed = Observation::Exiting(child.start_time);
                    assert!(!is_signalable(child.start_time, observed));
                    assert!(!refusal_stands(child.start_time, observed));
                    observed
                }
            },
            || elapsed.get(),
            |step| elapsed.set(elapsed.get() + step),
        );
        assert_eq!(elapsed.get(), grace);
        assert_eq!(status.survivors, [11]);
        assert_eq!(status.exiting, [11]);
        assert!(
            verdict_reason(None, &status.exiting)
                .unwrap()
                .contains("exiting")
        );
    }

    #[test]
    fn kill_tree_unknown_lifecycle_is_neither_exiting_nor_gone() {
        let root = fact(10, 1, 10);
        let snapshot = [root];
        let mut captured = capture_members(&snapshot, 10, root.start_time, 5, &[], |_| true)
            .unwrap()
            .targets;
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let grace = Duration::from_millis(100);
        let status = confirm_until(
            &mut captured,
            grace,
            grace,
            |_| true,
            |_| {
                assert!(!is_signalable(root.start_time, Observation::Unknown));
                assert!(refusal_stands(root.start_time, Observation::Unknown));
                Observation::Unknown
            },
            || elapsed.get(),
            |step| elapsed.set(elapsed.get() + step),
        );
        assert_eq!(elapsed.get(), grace);
        assert_eq!(status.survivors, [10]);
        assert!(status.exiting.is_empty());
    }

    #[test]
    fn kill_tree_late_refusal_fences_subtrees_and_reports_deadline_survivors() {
        let root = fact(10, 1, 10);
        let refused_parent = fact(11, 10, 11);
        let child = fact(12, 11, 12);
        let sibling = fact(13, 10, 13);
        let first_refused = fact(14, 10, 14);
        let snapshot = [root, refused_parent, child, sibling, first_refused];
        let Capture { mut targets, facts } =
            capture_members(&snapshot, 10, root.start_time, 5, &[], |_| true).unwrap();
        let ancestors = HashSet::new();
        let mut refused = Refusals::default();
        refused.record(first_refused.pid, "first refusal".to_owned());
        // A later refusal must invalidate previously allowed ancestry paths.
        assert!(!refused.blocks(&child, 10, &ancestors, &facts));
        refused.record(refused_parent.pid, "later refusal".to_owned());
        assert!(refused.blocks(&refused_parent, 10, &ancestors, &facts));
        assert!(refused.blocks(&child, 10, &ancestors, &facts));
        assert!(!refused.blocks(&sibling, 10, &ancestors, &facts));
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let grace = Duration::from_millis(250);
        let status = confirm_until(
            &mut targets,
            grace,
            Duration::from_millis(100),
            |fact| {
                refused.track(fact, 10, &ancestors, &facts, |fact| {
                    fact.pid != 11 && fact.pid != 12 && fact.pid != 14
                })
            },
            |pid| {
                let settled = match pid {
                    10 | 14 => elapsed.get() >= Duration::from_millis(100),
                    12 | 13 => elapsed.get() >= Duration::from_millis(200),
                    11 => false,
                    _ => panic!("unexpected captured PID"),
                };
                if settled {
                    Observation::Gone
                } else {
                    Observation::Present(facts[&pid].start_time)
                }
            },
            || elapsed.get(),
            |step| elapsed.set(elapsed.get() + step),
        );
        assert_eq!(elapsed.get(), grace);
        assert_eq!(status.survivors, [11]);
        assert!(status.exiting.is_empty());
        assert_eq!(
            verdict_reason(refused.reason, &status.exiting).as_deref(),
            Some("first refusal")
        );
    }
}
