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
//!   Linux also excludes shared broker daemons unless a nested `omp` owns the
//!   candidate subtree.
//! - [`reap_instance_tree_for`]: SIGTERM the whole carrier set (oldest first,
//!   so the pty wrapper goes before its children), wait up to 5 s, SIGKILL
//!   survivors — fail-closed: success is only reported once no in-scope
//!   carrier lives. A late carrier is signalled unless its non-empty
//!   `HCOM_PROCESS_ID` is registered among the name's CURRENT binding ids
//!   read fresh in that round, minus the call-start ids (see
//!   [`carrier_in_reap_scope`]): a brand-new registration started mid-reap
//!   is spared, a name-only late fork — or a late child carrying a stale id
//!   of the dying tree — is not. Every round captures its carrier set first
//!   and reads the binding registry second (read-after-capture, plus a
//!   pre-signal re-read in the KILL round) — the ordering that makes "read
//!   fresh" trustworthy (see [`reap_instance_tree_for_excluding`]).
//! - [`check_spawn_allowed`]: refuse to spawn under `<name>` over a live
//!   holder or an orphan (started before the newest binding) — the one
//!   uniform spawn gate, after removing the caller's own identity tree from
//!   the carrier set (a session re-registering its own name is never blocked
//!   by its own processes).
//! - [`sweep_vanished_instances`]: daemon-side periodic check that notices
//!   rows whose harness is gone without a `stopped` event.
//!
//! Unix only: `/proc` enumeration is compiled out on other platforms, where
//! every query reports empty (verified-no-holders) and reap is a no-op.

#[cfg(unix)]
use std::collections::{HashMap, HashSet};

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
/// On Linux a broker (`/proc/<pid>/comm` exactly `omp daemon brok`) is never
/// a carrier. Its descendants need a nested `omp` between them and their
/// nearest broker, including the candidate itself.
///
/// A third arm covers the owner of a minted `omp-<pid>-...` binding: the omp
/// plugin sets that id in omp's runtime env, which /proc environ (exec-time
/// only) never shows, so the owner is proven from the binding instead — see
/// [`OmpOwnerBinding`].
///
/// Only the `HCOM_INSTANCE_NAME` and `HCOM_PROCESS_ID` entries are ever
/// inspected; no other environ values are read or reported. The calling
/// process itself is always excluded (a CLI running inside the session
/// inherits the name but never owns it).
pub fn processes_for_instance(
    name: &str,
    binding_ids: &[String],
    owners: &[OmpOwnerBinding],
) -> Vec<ProcMatch> {
    #[cfg(unix)]
    {
        enumerate_unix(name, binding_ids, owners, None)
    }
    #[cfg(not(unix))]
    {
        let _ = (name, binding_ids, owners);
        Vec::new()
    }
}

/// Whether any live (non-zombie) carrier holds the instance by name or by
/// one of its binding ids. The placeholder janitor's hold rule: a stale
/// placeholder whose launch is still running is held, never released or
/// signalled.
pub(crate) fn has_live_carriers(
    name: &str,
    binding_ids: &[String],
    owners: &[OmpOwnerBinding],
) -> bool {
    processes_for_instance(name, binding_ids, owners)
        .iter()
        .any(|m| !process_gone(m.pid))
}

/// A minted `omp-<pid>-...` binding and when it was registered. `<pid>` holds
/// the instance while it is alive, its `/proc/<pid>/comm` is exactly `omp`
/// (the reap-root proof), and it started no later than the registration —
/// a process that started after the binding existed reused the pid.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields are read only by the Linux/Android owner proof
pub struct OmpOwnerBinding {
    pid: u32,
    process_id: String,
    registered_at: f64,
}

/// The instance's minted omp bindings with their registration times. A DB
/// error reads as none: the owner arm only ever adds carriers.
pub fn omp_owner_bindings(db: &HcomDb, name: &str) -> Vec<OmpOwnerBinding> {
    db.process_bindings_registered(name)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(process_id, registered_at)| {
            Some(OmpOwnerBinding {
                pid: omp_minted_pid(&process_id)?,
                process_id,
                registered_at,
            })
        })
        .collect()
}

/// /proc start times derive from whole-second `btime`, so a start epoch can
/// read up to a second late against a DB timestamp.
#[cfg(any(target_os = "linux", target_os = "android"))]
const START_EPOCH_SLACK_SECS: f64 = 1.0;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn proven_omp_owner(owner: &OmpOwnerBinding, btime: f64) -> bool {
    !process_gone(owner.pid)
        && std::fs::read_to_string(format!("/proc/{}/comm", owner.pid))
            .is_ok_and(|comm| comm.trim_end_matches('\n') == "omp")
        && process_start_epoch(owner.pid, btime)
            .is_some_and(|start| start <= owner.registered_at + START_EPOCH_SLACK_SECS)
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

/// The two identity facts of `pid` (see [`identity_facts`]) as the spawn
/// gate reads them. The calling process's own facts come from its LIVE
/// environment — what it actually carries and passes to its children, the
/// same source `HcomContext` resolves identity from. Every other pid is
/// read from `/proc/<pid>/environ`; None when that is unreadable (exited,
/// or foreign-owned).
fn identity_facts_of(pid: u32, name: &str) -> Option<(bool, String)> {
    if pid == std::process::id() {
        return Some((
            std::env::var("HCOM_INSTANCE_NAME").is_ok_and(|v| v == name),
            std::env::var("HCOM_PROCESS_ID").unwrap_or_default(),
        ));
    }
    #[cfg(unix)]
    {
        let want = format!("HCOM_INSTANCE_NAME={name}");
        std::fs::read(format!("/proc/{pid}/environ"))
            .ok()
            .map(|env| identity_facts(&env, want.as_bytes()))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// True when a decoded `HCOM_PROCESS_ID` value names one of the instance's
/// bindings. Empty never matches, so an absent entry (or an empty binding
/// id) can never hold an instance.
fn is_bound_process_id(process_id: &str, binding_ids: &[String]) -> bool {
    !process_id.is_empty() && binding_ids.iter().any(|id| id == process_id)
}

/// Broker-owned daemons inherit the first session's identity but do not belong
/// to it. Only a nested `omp` below the nearest broker starts a new carrier
/// subtree. Off Linux and Android there is no `/proc/<pid>/comm` to distinguish
/// them, so keep the existing identity-only rule.
#[cfg(unix)]
pub(crate) fn carrier_eligible(pid: u32) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        carrier_eligible_with(
            pid,
            |pid| std::fs::read_to_string(format!("/proc/{pid}/comm")).ok(),
            parent_pid,
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = pid;
        true
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn carrier_eligible_with(
    pid: u32,
    comm_of: impl Fn(u32) -> Option<String>,
    parent_of: impl Fn(u32) -> Option<u32>,
) -> bool {
    let mut current = pid;
    let mut passed_omp = false;
    // A missing link cannot establish broker ancestry. Bound the walk like
    // ancestor_or_self_pids in case /proc changes under us.
    for _ in 0..1024 {
        let comm = comm_of(current);
        let comm = comm
            .as_deref()
            .map(|value| value.strip_suffix('\n').unwrap_or(value));
        if comm == Some("omp daemon brok") {
            return passed_omp;
        }
        if comm == Some("omp") {
            passed_omp = true;
        }
        let Some(parent) = parent_of(current) else {
            return true;
        };
        if parent == current {
            return true;
        }
        current = parent;
    }
    true
}

/// Roots and the original PID incarnations are captured before the first
/// signal of a teardown. A descendant stays in scope if an earlier signal
/// kills its parent and the kernel reparents it; a reused pid does not.
#[cfg(unix)]
struct CarrierTreeScope {
    roots: Vec<u32>,
    caller_ancestors: Vec<u32>,
    known: HashMap<u32, (ProcMatch, String)>,
    /// Identity carriers seen live outside the proven scope. Only the ones
    /// still alive at the release decision can block it.
    dropped_live: std::cell::RefCell<Vec<u32>>,
    admitted: std::cell::Cell<usize>,
    excluded: Vec<u32>,
    /// Captured with the roots: every round of this teardown proves binding
    /// owners against the same registrations.
    owners: Vec<OmpOwnerBinding>,
}

#[cfg(unix)]
impl CarrierTreeScope {
    fn drop_unproven(&self, pid: u32) {
        let mut dropped = self.dropped_live.borrow_mut();
        if !dropped.contains(&pid) {
            dropped.push(pid);
        }
    }
}

/// The row a capture was taken against. A stop that threads the capture may
/// release this incarnation and no other: a `start --as` rebind between the
/// capture and the release is a different row, whatever its name.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CapturedIncarnation {
    pub(crate) created_at: f64,
    pub(crate) pid: Option<i64>,
    pub(crate) session_id: Option<String>,
    pub(crate) agent_id: Option<String>,
    pub(crate) binding_ids: Vec<String>,
}

/// The owning roots and carrier set from before the operation's first signal.
/// Live carriers whose identity is unreadable stay in the set but cannot be
/// signalled. Callers with a headless group signal capture before that step;
/// callers with no pre-step capture at reap entry.
pub(crate) struct ReapCapture {
    #[cfg(unix)]
    scope: CarrierTreeScope,
    #[cfg(unix)]
    carriers: Vec<ProcMatch>,
    /// `None` when no row existed at capture time, or when the capture is
    /// reap-only and deliberately binds no incarnation.
    incarnation: Option<CapturedIncarnation>,
}

impl ReapCapture {
    pub(crate) fn incarnation(&self) -> Option<&CapturedIncarnation> {
        self.incarnation.as_ref()
    }
}

#[cfg(unix)]
fn carrier_tree_scope(
    row_pid: Option<i64>,
    binding_ids: &[String],
    owners: &[OmpOwnerBinding],
) -> CarrierTreeScope {
    let mut roots = vec![std::process::id()];
    if let Some(pid) = row_pid.and_then(|pid| u32::try_from(pid).ok())
        && pid != 0
        && !roots.contains(&pid)
    {
        roots.push(pid);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    for id in binding_ids {
        // Only the minted omp-<pid>-... shape identifies an owner. A live
        // process with another comm must not become a root on the strength of
        // a borrowed or stale binding id.
        if let Some(pid) = minted_root_pid(id)
            && !process_gone(pid)
            && std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .is_ok_and(|comm| comm.trim_end_matches('\n') == "omp")
            && !roots.contains(&pid)
        {
            roots.push(pid);
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = binding_ids;
    CarrierTreeScope {
        roots,
        caller_ancestors: caller_ancestor_pids(),
        known: HashMap::new(),
        excluded: Vec::new(),
        dropped_live: std::cell::RefCell::new(Vec::new()),
        admitted: std::cell::Cell::new(0),
        owners: owners.to_vec(),
    }
}

/// A capture with NO bound incarnation: the row contributes only its
/// recorded-pid root. The reap conveniences pair that fresh row read with
/// the caller's call-start binding ids — two reads, never one snapshot — so
/// their capture must not carry a [`CapturedIncarnation`] a stop could
/// release against. The reap consumes only scope and carriers.
fn capture_reap_carriers_unbound(
    db: &HcomDb,
    name: &str,
    row_pid: Option<i64>,
    binding_ids: &[String],
    owners: &[OmpOwnerBinding],
    exclude: &[u32],
) -> Result<ReapCapture, ReapError> {
    #[cfg(unix)]
    {
        let mut scope = carrier_tree_scope(row_pid, binding_ids, owners);
        let carriers = snapshot_reap_carriers(name, binding_ids, exclude, &mut scope);
        // The root set is final and the carriers are captured: the last point
        // before the caller's first signal, so this is where a foreign live
        // owner is refused.
        refuse_foreign_live_owner(db, name, &scope, &carriers)?;
        Ok(ReapCapture {
            scope,
            carriers,
            incarnation: None,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (db, name, row_pid, binding_ids, owners, exclude);
        Ok(ReapCapture { incarnation: None })
    }
}

/// The pid a minted binding id names, parsed exactly as [`carrier_tree_scope`]
/// parses it to admit a root: the loose `omp-<head>-…` head plus the
/// mandatory trailing `-`. "A minted pid" therefore means the same thing in
/// the root admission and in the foreign-owner guard.
#[cfg(unix)]
fn minted_root_pid(id: &str) -> Option<u32> {
    let pid = shell_pid_from_process_id(id)?;
    id.strip_prefix("omp-")
        .is_some_and(|rest| rest.contains('-'))
        .then_some(pid)
}

/// minted pid → the live rows whose bindings name it. One pid can back
/// several minted ids (the plugin re-mints inside the same omp process), so
/// the map keeps every owner, not just the first.
#[cfg(unix)]
fn minted_pid_owners(db: &HcomDb) -> Result<HashMap<u32, Vec<String>>, ReapError> {
    let bindings = db
        .live_process_bindings()
        .map_err(|e| ReapError::BindingRegistryUnreadable(e.to_string()))?;
    let mut owners: HashMap<u32, Vec<String>> = HashMap::new();
    for (id, owner) in bindings {
        if let Some(pid) = minted_root_pid(&id) {
            let entry = owners.entry(pid).or_default();
            if !entry.contains(&owner) {
                entry.push(owner);
            }
        }
    }
    Ok(owners)
}

/// Who, if anyone, holds `pid` under a live row other than `name`, and by
/// which proof. Both arms are deliberately id-based: an `HCOM_INSTANCE_NAME`
/// conflict and a row-pid collision are NOT this guard's business, because
/// both are sticky across legitimate session switches and would refuse
/// legitimate stops.
#[cfg(unix)]
fn foreign_live_owner(
    db: &HcomDb,
    minted: &HashMap<u32, Vec<String>>,
    name: &str,
    pid: u32,
) -> Result<Option<(String, &'static str)>, ReapError> {
    // One read of the identity this process actually carries, reused by both
    // of its arms: the exact id, and the minted pid that id names.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let process_id = identity_facts_of(pid, name)
        .map(|(_, process_id)| process_id)
        .unwrap_or_default();
    // No /proc to read: only the candidate-pid arm below can run off-Linux.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let process_id = String::new();

    // The carried id itself, then the minted pid behind it.
    if !process_id.is_empty() {
        let owner = db
            .live_process_binding_owner(&process_id)
            .map_err(|e| ReapError::BindingRegistryUnreadable(e.to_string()))?;
        if let Some(owner) = owner
            && owner != name
        {
            return Ok(Some((owner, "binding")));
        }
        if let Some(minted_pid) = minted_root_pid(&process_id)
            && let Some(owners) = minted.get(&minted_pid)
            && let Some(owner) = owners.iter().find(|owner| owner.as_str() != name)
        {
            return Ok(Some((owner.clone(), "minted_pid")));
        }
    }

    // The candidate pid itself, whatever it was admitted for.
    if let Some(owners) = minted.get(&pid)
        && let Some(owner) = owners.iter().find(|owner| owner.as_str() != name)
    {
        return Ok(Some((owner.clone(), "minted_pid")));
    }
    Ok(None)
}

/// No teardown may signal a process another live row holds. It is checked in
/// two places, and the coverage is exactly:
///
/// - every admitted root except this command's own pid (`roots[0]`, which
///   inherits the caller's identity and is never a target), plus every
///   first-capture carrier — a descendant of a foreign-owned root is
///   signalable too, so roots and carriers together are the whole candidate
///   set. A conflict here refuses the teardown at capture time, before the
///   caller's first signal, pane close, or reap.
/// - every carrier first seen by the KILL round's own capture, which never
///   went through the check above: a conflict there SKIPS the KILL (see the
///   call site) and the carrier surfaces as a survivor.
/// - NOT covered: co-members of a recorded process group reached only by the
///   headless or kill group signal, which never pass through either set. And
///   a candidate whose `/proc/<pid>/environ` is unreadable runs only the
///   candidate-pid arm, since there is no carried id to resolve.
/// - When two live rows both hold minted ids for the same pid, BOTH rows'
///   teardowns refuse: the conflict is symmetric, so the stale binding has to
///   be removed before either side can be stopped. That is the fail-closed
///   choice, and it is the one that cannot signal the wrong owner.
///
/// An unreadable registry fails closed: the teardown returns an error and
/// sends nothing.
#[cfg(unix)]
fn refuse_foreign_live_owner(
    db: &HcomDb,
    name: &str,
    scope: &CarrierTreeScope,
    carriers: &[ProcMatch],
) -> Result<(), ReapError> {
    let minted = minted_pid_owners(db)?;
    let candidates = scope
        .roots
        .iter()
        .skip(1)
        .copied()
        .chain(carriers.iter().map(|carrier| carrier.pid));
    for pid in candidates {
        let Some((owner, via)) = foreign_live_owner(db, &minted, name, pid)? else {
            continue;
        };
        crate::log::log_info(
            "proctruth",
            "reap_refused_foreign_owner",
            &format!("instance={name} pid={pid} owner={owner} via={via}"),
        );
        return Err(ReapError::ForeignLiveOwner { pid, owner });
    }
    Ok(())
}

/// `row` and `binding_ids` must be ONE snapshot of the instance
/// ([`HcomDb::get_instance_with_bindings`] or
/// [`HcomDb::iter_instances_with_bindings`]): they become the captured
/// incarnation. A row paired with another incarnation's binding epoch lets
/// a stop bound to it release a row nobody resolved.
///
/// The capture is a gate, not only a snapshot: `Err` means the teardown must
/// send no signal at all, which is why every production caller handles it
/// before its first group signal, pane close, or reap.
pub(crate) fn capture_reap_carriers(
    db: &HcomDb,
    name: &str,
    row: Option<&crate::db::InstanceRow>,
    binding_ids: &[String],
    owners: &[OmpOwnerBinding],
    exclude: &[u32],
) -> Result<ReapCapture, ReapError> {
    let mut capture = capture_reap_carriers_unbound(
        db,
        name,
        row.and_then(|row| row.pid),
        binding_ids,
        owners,
        exclude,
    )?;
    // The snapshot's row feeds the bound incarnation as well as the roots.
    capture.incarnation = row.map(|row| CapturedIncarnation {
        created_at: row.created_at,
        pid: row.pid,
        session_id: row.session_id.clone(),
        agent_id: row.agent_id.clone(),
        binding_ids: binding_ids.to_vec(),
    });
    Ok(capture)
}

#[cfg(unix)]
fn carrier_identity(pid: u32) -> Option<String> {
    #[cfg(test)]
    if MISSING_CARRIER_IDENTITY.with(|missing| missing.get() == Some(pid)) {
        return None;
    }
    crate::sys::process::identity(pid)
}

/// Build a round's live carrier set. Proven members from an earlier snapshot
/// survive reparenting only with the same OS process identity; new carriers
/// must pass ancestry and the broker rule at their first snapshot.
/// An unreadable identity is not death: keep a live carrier in the round
/// without granting it a signalable identity in `scope.known`.
#[cfg(unix)]
fn snapshot_reap_carriers(
    name: &str,
    binding_ids: &[String],
    exclude: &[u32],
    scope: &mut CarrierTreeScope,
) -> Vec<ProcMatch> {
    scope.excluded.clear();
    scope.excluded.extend_from_slice(exclude);
    let owners = scope.owners.clone();
    let mut matches = live_carriers_for(name, binding_ids, &owners, exclude, Some(scope));
    matches.retain(|m| {
        let Some(identity) = carrier_identity(m.pid) else {
            let alive = crate::sys::process::is_alive(m.pid);
            if alive {
                crate::log::log_info(
                    "proctruth",
                    "carrier_identity_unavailable",
                    &format!("pid={} instance={name}", m.pid),
                );
            }
            return alive;
        };
        match scope.known.get(&m.pid) {
            Some((_, original)) => {
                if original != &identity {
                    log_carrier_out_of_scope(m.pid, name, scope);
                    return false;
                }
                true
            }
            None => {
                scope.known.insert(m.pid, (m.clone(), identity));
                true
            }
        }
    });
    matches
}

/// An identity holder is signalable only when its parent chain reaches one
/// of the captured roots. An unreadable or changing chain never proves
/// ownership. A root itself counts, except if it is a caller ancestor.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn carrier_in_owner_tree_with(
    pid: u32,
    scope: &CarrierTreeScope,
    parent_of: impl Fn(u32) -> Option<u32>,
) -> bool {
    if scope.caller_ancestors.last() != Some(&1) {
        return false;
    }
    if scope.caller_ancestors.contains(&pid) {
        return false;
    }
    let mut current = pid;
    for _ in 0..1024 {
        if scope.roots.contains(&current) {
            return true;
        }
        let Some(parent) = parent_of(current) else {
            return false;
        };
        if parent == current {
            return false;
        }
        current = parent;
    }
    false
}

#[cfg(unix)]
fn log_carrier_out_of_scope(pid: u32, name: &str, scope: &CarrierTreeScope) {
    crate::log::log_info(
        "proctruth",
        "carrier_out_of_scope",
        &format!("pid={pid} instance={name} roots={:?}", scope.roots),
    );
}

#[cfg(unix)]
fn carrier_in_signal_scope(pid: u32, name: &str, scope: &CarrierTreeScope) -> bool {
    if scope
        .known
        .get(&pid)
        .is_some_and(|(_, identity)| carrier_identity(pid).as_ref() == Some(identity))
    {
        return true;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if carrier_in_owner_tree_with(pid, scope, parent_pid) {
        return true;
    }
    log_carrier_out_of_scope(pid, name, scope);
    false
}

#[cfg(unix)]
fn enumerate_unix(
    name: &str,
    binding_ids: &[String],
    owners: &[OmpOwnerBinding],
    scope: Option<&CarrierTreeScope>,
) -> Vec<ProcMatch> {
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
        let (carries_name, mut process_id) = identity_facts(&env, want.as_bytes());
        // Self-bound arm: the process carries one of the instance's binding
        // ids even though it never carried the name. Empty binding ids never
        // match (an absent HCOM_PROCESS_ID reads as empty).
        if !carries_name && !is_bound_process_id(&process_id, binding_ids) {
            // Binding-owner arm: the process minted the binding in its
            // runtime env, which its environ never shows.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let owned = owners
                .iter()
                .find(|owner| owner.pid == pid && proven_omp_owner(owner, btime));
            // No comm/start-time proof off Linux: the arm never admits there.
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let owned: Option<&OmpOwnerBinding> = {
                let _ = owners;
                None
            };
            let Some(owner) = owned else {
                continue;
            };
            process_id = owner.process_id.clone();
        }
        let frozen = scope.and_then(|scope| scope.known.get(&pid));
        if let Some((original, identity)) = frozen {
            match carrier_identity(pid) {
                Some(current) if current != *identity => {
                    if let Some(scope) = scope {
                        log_carrier_out_of_scope(pid, name, scope);
                    }
                    continue;
                }
                None => {
                    // A proven carrier may have lost its parent already.
                    // Missing identity cannot authorize a signal, but a live
                    // pid still blocks release even without an ancestry path.
                    if crate::sys::process::is_alive(pid) {
                        out.push(ProcMatch {
                            pid,
                            process_id,
                            start_epoch: original.start_epoch,
                        });
                    }
                    continue;
                }
                Some(_) => {}
            }
        }
        // A previously scoped descendant may have been reparented by an
        // earlier signal. Keep its broker decision, but never signal a pid
        // that has itself become the shared broker.
        if frozen.is_some() {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if std::fs::read_to_string(format!("/proc/{pid}/comm")).map_or(true, |comm| {
                comm.trim_end_matches('\n') == "omp daemon brok"
            }) {
                if let Some(scope) = scope {
                    log_carrier_out_of_scope(pid, name, scope);
                }
                continue;
            }
        } else if !carrier_eligible(pid) {
            // The broker rule's rejects are not carriers (ffc-vpjpg): shared
            // daemons inheriting the identity are residue, never unproven
            // ownership. An excluded one still counts as admitted (b58539b).
            if let Some(scope) = scope {
                if scope.excluded.contains(&pid) {
                    scope.admitted.set(scope.admitted.get() + 1);
                }
                log_carrier_out_of_scope(pid, name, scope);
            }
            continue;
        }
        if scope.is_some_and(|scope| {
            if !carrier_in_signal_scope(pid, name, scope) {
                if scope.excluded.contains(&pid) {
                    scope.admitted.set(scope.admitted.get() + 1);
                } else {
                    scope.drop_unproven(pid);
                }
                true
            } else {
                scope.admitted.set(scope.admitted.get() + 1);
                false
            }
        }) {
            continue;
        }
        if let Some(scope) = scope {
            scope.admitted.set(scope.admitted.get() + 1);
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
pub(crate) fn process_gone(pid: u32) -> bool {
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
/// Field 4 (ppid) of `/proc/<pid>/stat` — the token after the closing `)` of
/// comm, so a comm containing spaces or parens cannot shift the parse. None
/// when the process is gone, unparseable, or has no parent (ppid 0).
fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    let mut fields = after_comm.split_whitespace();
    let _state = fields.next()?;
    let ppid: u32 = fields.next()?.parse().ok()?;
    (ppid != 0).then_some(ppid)
}

/// Field 5 (pgrp) of `/proc/<pid>/stat`, parsed after the closing `)` of
/// comm like [`parent_pid`]. None when the process is gone or unparseable.
#[cfg(target_os = "linux")]
fn process_group_id(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let _state = fields.next()?;
    let _ppid = fields.next()?;
    fields.next()?.parse().ok()
}

/// `pid` plus its /proc ppid-ancestor chain, youngest first, ending at init
/// (a bonded iteration cap guards against a corrupted chain).
fn ancestor_or_self_pids(pid: u32) -> Vec<u32> {
    let mut out = vec![pid];
    let mut cur = pid;
    while let Some(ppid) = parent_pid(cur) {
        if ppid == cur {
            break;
        }
        out.push(ppid);
        if ppid == 1 || out.len() > 1024 {
            break;
        }
        cur = ppid;
    }
    out
}

/// The calling process's pid plus its ancestor chain. Linux/Android use
/// `/proc/<pid>/stat`; Windows uses ToolHelp and macOS uses proc_pidinfo.
/// Both reject stale parent links by process creation time.
pub fn caller_ancestor_pids() -> Vec<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        ancestor_or_self_pids(std::process::id())
    }
    #[cfg(windows)]
    {
        let self_pid = std::process::id();
        let snapshot = crate::sys::process::snapshot_parents(false);
        walk_ancestor_links(
            self_pid,
            |pid| snapshot.as_ref()?.get(&pid).map(|entry| entry.parent_pid),
            crate::sys::process::creation_ticks_win,
        )
    }
    #[cfg(target_os = "macos")]
    {
        mac_ancestor_pids(&MacProcessLookup::default())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        windows,
        target_os = "macos"
    )))]
    {
        vec![std::process::id()]
    }
}

/// Self-inclusive ancestry from injected parent and creation-time lookups.
/// An older child cannot belong to a younger, PID-reused parent. Cycles and
/// a bounded walk cannot promote arbitrary processes into the chain.
#[cfg(any(windows, target_os = "macos", test))]
fn walk_ancestor_links(
    self_pid: u32,
    parent_of: impl Fn(u32) -> Option<u32>,
    ticks_of: impl Fn(u32) -> Option<u64>,
) -> Vec<u32> {
    let mut ancestors = vec![self_pid];
    let mut child = self_pid;
    let mut child_ticks = ticks_of(child);
    while ancestors.len() < 1024 {
        let Some(parent) = parent_of(child) else {
            break;
        };
        if parent <= 4 || ancestors.contains(&parent) {
            break;
        }
        let parent_ticks = ticks_of(parent);
        if !crate::sys::process::child_link_is_plausible(parent_ticks, child_ticks) {
            break;
        }
        ancestors.push(parent);
        child = parent;
        child_ticks = parent_ticks;
    }
    ancestors
}

/// Shell pid behind a self-bound process id: `omp-<pid>-…` → `<pid>`.
/// Unlike [`omp_minted_pid`], this also accepts the legacy bare `omp-<pid>`
/// shape used as sweep death evidence.
fn shell_pid_from_process_id(process_id: &str) -> Option<u32> {
    process_id
        .strip_prefix("omp-")
        .and_then(|rest| rest.split('-').next())
        .filter(|head| !head.is_empty())
        .and_then(|head| head.parse::<u32>().ok())
}

/// A reap cannot release ownership while carriers survive or its scope is unproven.
#[derive(Debug, PartialEq, Eq)]
pub enum ReapError {
    // The non-Unix reap is a no-op success and never constructs this variant.
    #[cfg_attr(not(unix), allow(dead_code))]
    Survivors(Vec<u32>),
    #[cfg(unix)]
    UnprovenOwnership,
    /// A candidate pid belongs to another instance whose row is still live.
    /// The teardown is refused before its first signal: the row and every
    /// binding stay exactly as they were.
    #[cfg(unix)]
    ForeignLiveOwner { pid: u32, owner: String },
    /// The binding registry could not be read, so no foreign owner can be
    /// ruled out. Refused like the conflict itself: fail closed, signal
    /// nothing.
    #[cfg(unix)]
    BindingRegistryUnreadable(String),
}

impl std::fmt::Display for ReapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Survivors(pids) => {
                f.write_str("process(es) still alive after SIGKILL: ")?;
                for (index, pid) in pids.iter().enumerate() {
                    if index != 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{pid}")?;
                }
                Ok(())
            }
            #[cfg(unix)]
            Self::UnprovenOwnership => {
                f.write_str("cannot prove process ownership on this host; row left intact")
            }
            #[cfg(unix)]
            Self::ForeignLiveOwner { pid, owner } => write!(
                f,
                "refusing to signal pid {pid}: it belongs to live instance '{owner}'; nothing was signalled"
            ),
            #[cfg(unix)]
            Self::BindingRegistryUnreadable(error) => write!(
                f,
                "cannot read the process binding registry: {error}; nothing was signalled"
            ),
        }
    }
}

/// The Apple process facts needed for both ancestry and OMP executable proof.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct MacProcessFacts {
    parent_pid: u32,
    start_micros: u64,
    comm: [u8; libc::MAXCOMLEN],
}

/// Reuse the Apple proc_pidinfo reader used by stable process identity.
#[cfg(target_os = "macos")]
fn mac_process_facts(pid: u32) -> Option<MacProcessFacts> {
    let _ = libc::c_int::try_from(pid).ok()?;
    let info = crate::sys::process::process_info_apple(pid)?;
    if info.pbi_pid != pid {
        return None;
    }
    Some(MacProcessFacts {
        parent_pid: info.pbi_ppid,
        start_micros: mac_start_micros(info.pbi_start_tvsec, info.pbi_start_tvusec)?,
        comm: std::array::from_fn(|i| info.pbi_comm[i] as u8),
    })
}

#[cfg(any(target_os = "macos", test))]
fn mac_start_micros(seconds: u64, micros: u64) -> Option<u64> {
    if micros >= 1_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000)?.checked_add(micros)
}

/// Each ancestor's parent, start time, and comm come from one per-pid
/// proc_pidinfo call; both walker lookups and the kind check share its result.
#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacProcessLookup(
    std::cell::RefCell<std::collections::HashMap<u32, Option<MacProcessFacts>>>,
);

#[cfg(target_os = "macos")]
impl MacProcessLookup {
    fn get(&self, pid: u32) -> Option<MacProcessFacts> {
        if let Some(cached) = self.0.borrow().get(&pid).copied() {
            return cached;
        }
        let facts = mac_process_facts(pid);
        self.0.borrow_mut().insert(pid, facts);
        facts
    }
}

#[cfg(target_os = "macos")]
fn mac_ancestor_pids(lookup: &MacProcessLookup) -> Vec<u32> {
    walk_ancestor_links(
        std::process::id(),
        |pid| lookup.get(pid).map(|facts| facts.parent_pid),
        |pid| lookup.get(pid).map(|facts| facts.start_micros),
    )
}
/// Which program an ancestor pid is running, as far as the platform will say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AncestorProcess {
    /// Linux/Android `/proc/<pid>/comm` is `omp`, macOS `pbi_comm` is
    /// `omp`, or Windows ToolHelp `szExeFile` is `omp.exe`.
    Omp,
    /// A readable process name that does not name OMP.
    #[cfg_attr(
        not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            windows
        )),
        allow(dead_code)
    )]
    Other,
    /// Unreadable process name. Never satisfies the `Omp` clause.
    Unknown,
}

/// `omp-<pid>-<rest>` → Some(pid), where `<rest>` must be non-empty. Agent-minted
/// ids only (plugin / D-69 shape); launcher ids are UUIDs and parse to None.
/// Anything else (empty, malformed, a bare `omp-<pid>`) → None.
///
/// The shape is deliberately the same one the plugin applies when it decides
/// whether to keep an inherited id (`OMP_ID_PATTERN` in
/// `src/omp_plugin/hcom.ts`), so minter and verifier cannot disagree about which
/// ids are agent-minted.
pub(crate) fn omp_minted_pid(id: &str) -> Option<u32> {
    let (head, rest) = id.strip_prefix("omp-")?.split_once('-')?;
    if rest.is_empty() || head.is_empty() {
        return None;
    }
    head.parse::<u32>().ok()
}

/// What `pid` is running: `Omp` only when `/proc/<pid>/comm` is `omp`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn ancestor_process_kind(pid: u32) -> AncestorProcess {
    match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        Ok(comm) => {
            if comm.trim() == "omp" {
                AncestorProcess::Omp
            } else {
                AncestorProcess::Other
            }
        }
        Err(_) => AncestorProcess::Unknown,
    }
}

/// Windows ToolHelp executable names identify OMP even when the installed
/// binary's path differs. Verified by windows-build compile only: there is no
/// Windows OMP real-tool job.
#[cfg(any(windows, test))]
fn ancestor_process_kind_from_name(name: Option<&str>) -> AncestorProcess {
    match name {
        Some(name) if name.eq_ignore_ascii_case("omp.exe") => AncestorProcess::Omp,
        Some(_) => AncestorProcess::Other,
        None => AncestorProcess::Unknown,
    }
}

#[cfg(windows)]
fn ancestor_process_kind(
    pid: u32,
    snapshot: &std::collections::HashMap<u32, crate::sys::process::ProcessSnapshot>,
) -> AncestorProcess {
    ancestor_process_kind_from_name(
        snapshot
            .get(&pid)
            .and_then(|entry| entry.exe_name.as_deref()),
    )
}

/// The macOS BSD comm is MAXCOMLEN bytes including its NUL terminator.
#[cfg(any(target_os = "macos", test))]
fn ancestor_process_kind_from_comm(comm: Option<&[u8]>) -> AncestorProcess {
    let Some(comm) = comm else {
        return AncestorProcess::Unknown;
    };
    let end = comm
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(comm.len());
    if comm[..end].trim_ascii() == b"omp" {
        AncestorProcess::Omp
    } else {
        AncestorProcess::Other
    }
}

/// True when `pid` carries exactly `HCOM_PROCESS_ID=<id>` in its environ —
/// the non-OMP synthetic-id carriage fallback. The calling
/// process's own facts come from its LIVE environment (same source
/// `HcomContext` resolves identity from); every other pid is read from
/// `/proc/<pid>/environ`, reusing [`identity_facts`]'s decoding via
/// [`identity_facts_of`] (only the `HCOM_PROCESS_ID` fact is used here). An
/// unreadable environ reads as absent. Empty `id` never matches.
pub(crate) fn carries_process_id(pid: u32, id: &str) -> bool {
    !id.is_empty()
        && identity_facts_of(pid, "") // name fact unused; only the process id matters
            .is_some_and(|(_, process_id)| process_id == id)
}

/// True for the launcher's own id shape ([`launcher::generate_process_id`]):
/// five lowercase-hex groups sized 8-4-4-4-12.
pub(crate) fn is_launcher_process_id(id: &str) -> bool {
    let mut sizes = [0usize; 5];
    let mut groups = 0usize;
    for part in id.split('-') {
        if groups == sizes.len() {
            return false;
        }
        let bytes = part.as_bytes();
        if bytes.is_empty()
            || !bytes
                .iter()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return false;
        }
        sizes[groups] = bytes.len();
        groups += 1;
    }
    groups == sizes.len() && sizes == [8, 4, 4, 4, 12]
}

/// Stamp a `life.stopped` snapshot with the incarnation of its anchor `pid`:
/// `pid_start_time` (boot-relative clock ticks) and `boot_id`. A later
/// reclaim ([`verify_reclaim_anchor`]) uses them to prove a live ancestor is
/// that same process, not a reused pid. Nothing is added when the snapshot
/// records no pid or the pid's procfs identity is unreadable (gone, or a
/// target without procfs).
pub(crate) fn record_anchor_identity(snapshot: &mut serde_json::Value) {
    let Some(pid) = snapshot
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
    else {
        return;
    };
    let Some((start_time, boot_id)) = crate::sys::process::procfs_start_identity(pid) else {
        return;
    };
    if let Some(fields) = snapshot.as_object_mut() {
        fields.insert("pid_start_time".into(), serde_json::json!(start_time));
        fields.insert("boot_id".into(), serde_json::json!(boot_id));
    }
}

/// Decide whether a reclaim may restore the anchor pid recorded in the
/// target's own newest `life.stopped` snapshot. Returns the pid, or why not.
///
/// All three must hold: the snapshot carries `pid` + `pid_start_time` +
/// `boot_id`; that pid is in `ancestors` (self-inclusive, as the trust gate
/// reads it); and `live_identity(pid)` reports the same start time on the
/// same boot. History plus ancestry plus process identity, never env
/// carriage: a reused pid on the caller's chain differs in start time, and a
/// reboot differs in boot id.
pub(crate) fn verify_reclaim_anchor(
    snapshot: &serde_json::Value,
    ancestors: &[u32],
    live_identity: &dyn Fn(u32) -> Option<(u64, String)>,
) -> Result<u32, &'static str> {
    let Some(pid) = snapshot
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
    else {
        return Err("snapshot records no anchor pid");
    };
    let (Some(start_time), Some(boot_id)) = (
        snapshot
            .get("pid_start_time")
            .and_then(serde_json::Value::as_u64),
        snapshot.get("boot_id").and_then(serde_json::Value::as_str),
    ) else {
        return Err("snapshot predates anchor start time and boot id");
    };
    if !ancestors.contains(&pid) {
        return Err("anchor pid is not a live ancestor of this process");
    }
    let Some((live_start_time, live_boot_id)) = live_identity(pid) else {
        return Err("anchor pid identity unreadable");
    };
    if live_boot_id != boot_id {
        return Err("boot id differs from the snapshot");
    }
    if live_start_time != start_time {
        return Err("anchor pid start time differs from the snapshot");
    }
    Ok(pid)
}

/// Pure decision core for process-identity trust — NO io. `ancestors` is
/// self-inclusive ([`caller_ancestor_pids`]); `binding_row_pid` is `None`
/// for no binding row and `Some(None)` for a row whose bound instance
/// records no pid. The trust table, in order:
///
/// - empty id → refused;
/// - `omp-<pid>-…` → trusted iff `<pid>` is in `ancestors` AND that
///   ancestor runs OMP ([`AncestorProcess::Omp`]); a shell ancestor
///   carrying a leaked id is not proof;
/// - launcher UUID → trusted iff a binding row records an ancestor pid.
///   A missing row OR a row with NULL pid is refused even when an ancestor
///   carries the id. The PTY wrapper records its own pid on entry before
///   spawning the tool, then replaces that anchor with the tool pid;
/// - other id shapes → a recorded row pid must be an ancestor; without a
///   recorded pid, non-OMP hooks retain carriage trust for synthetic,
///   relay and adhoc ids. OMP hooks reject these shapes outright, even
///   with `HCOM_LAUNCHED=1`.
///
/// READ BEFORE TRUSTING THE NON-OMP CARRIAGE ARM: `ancestor_carries_id` is
/// carriage, not proof. `ancestors` is self-inclusive and the caller's live
/// environ holds the presented `HCOM_PROCESS_ID`, so it cannot authenticate
/// an inherited synthetic id. Non-OMP tools keep the pre-0.7.30 basis;
/// OMP only trusts proven launcher UUIDs or proven OMP-minted ids.
///
/// Linux/Android prove `/proc` ancestry, Windows uses ToolHelp plus creation
/// ticks, and macOS uses proc_pidinfo BSD parent/start/comm facts. Other
/// unshipped targets fail closed until they have an ancestry mechanism.
/// [`AncestorProcess::Unknown`] never satisfies the OMP clause.
pub(crate) fn process_id_trusted(
    id: &str,
    ancestors: &[u32],
    ancestor_kind: &dyn Fn(u32) -> AncestorProcess,
    binding_row_pid: Option<Option<u32>>,
    ancestor_carries_id: &dyn Fn(&str) -> bool,
) -> bool {
    process_id_trusted_for_presenter(
        id,
        ancestors,
        ancestor_kind,
        binding_row_pid,
        ancestor_carries_id,
        false,
    )
}

fn process_id_trusted_for_presenter(
    id: &str,
    ancestors: &[u32],
    ancestor_kind: &dyn Fn(u32) -> AncestorProcess,
    binding_row_pid: Option<Option<u32>>,
    ancestor_carries_id: &dyn Fn(&str) -> bool,
    presenter_is_omp: bool,
) -> bool {
    if id.is_empty() {
        return false;
    }
    if let Some(pid) = omp_minted_pid(id) {
        return ancestors.contains(&pid) && ancestor_kind(pid) == AncestorProcess::Omp;
    }
    let launcher_id = is_launcher_process_id(id);
    if presenter_is_omp && !launcher_id {
        return false;
    }
    match binding_row_pid {
        None => !launcher_id && ancestor_carries_id(id),
        Some(Some(pid)) => ancestors.contains(&pid),
        // A launcher promises both a pre-registered row and a recorded anchor.
        Some(None) => !launcher_id && ancestor_carries_id(id),
    }
}

pub(crate) fn process_id_trusted_for_omp(
    id: &str,
    ancestors: &[u32],
    ancestor_kind: &dyn Fn(u32) -> AncestorProcess,
    binding_row_pid: Option<Option<u32>>,
    ancestor_carries_id: &dyn Fn(&str) -> bool,
) -> bool {
    process_id_trusted_for_presenter(
        id,
        ancestors,
        ancestor_kind,
        binding_row_pid,
        ancestor_carries_id,
        true,
    )
}

/// IO wrapper for [`process_id_trusted`]: reads caller ancestry and the
/// binding row (`get_process_binding` → `get_instance_full`). A DB read error,
/// dangling binding or invalid recorded pid reads as "no row" (fail closed).
pub fn trusted_process_id(db: &HcomDb, id: &str) -> bool {
    trusted_process_id_for_presenter(db, id, false)
}

/// OMP hooks accept only a proven launcher UUID or a proven OMP-minted id.
pub(crate) fn trusted_process_id_for_omp(db: &HcomDb, id: &str) -> bool {
    trusted_process_id_for_presenter(db, id, true)
}

fn trusted_process_id_for_presenter(db: &HcomDb, id: &str, presenter_is_omp: bool) -> bool {
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        windows
    )))]
    {
        // Unshipped targets get no inherited-id trust without ancestry proof.
        let _ = (db, id, presenter_is_omp);
        return false;
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        windows
    ))]
    {
        if id.is_empty() {
            return false;
        }
        let binding_row_pid = match db.get_process_binding(id) {
            Ok(Some(instance_name)) => match db.get_instance_full(&instance_name) {
                Ok(Some(row)) => Some(row.pid.and_then(|p| u32::try_from(p).ok())),
                _ => None,
            },
            _ => None,
        };
        let decide = if presenter_is_omp {
            process_id_trusted_for_omp
        } else {
            process_id_trusted
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let ancestors = caller_ancestor_pids();
            decide(
                id,
                &ancestors,
                &ancestor_process_kind,
                binding_row_pid,
                &|want| ancestors.iter().any(|&pid| carries_process_id(pid, want)),
            )
        }
        #[cfg(windows)]
        {
            // One ToolHelp snapshot supplies both parent links and exe names.
            let snapshot = crate::sys::process::snapshot_parents(true);
            let ancestors = walk_ancestor_links(
                std::process::id(),
                |pid| snapshot.as_ref()?.get(&pid).map(|entry| entry.parent_pid),
                crate::sys::process::creation_ticks_win,
            );
            decide(
                id,
                &ancestors,
                &|pid| {
                    snapshot
                        .as_ref()
                        .map_or(AncestorProcess::Unknown, |entries| {
                            ancestor_process_kind(pid, entries)
                        })
                },
                binding_row_pid,
                &|want| ancestors.iter().any(|&pid| carries_process_id(pid, want)),
            )
        }
        #[cfg(target_os = "macos")]
        {
            let lookup = MacProcessLookup::default();
            let ancestors = mac_ancestor_pids(&lookup);
            decide(
                id,
                &ancestors,
                &|pid| {
                    let facts = lookup.get(pid);
                    ancestor_process_kind_from_comm(
                        facts.as_ref().map(|facts| facts.comm.as_slice()),
                    )
                },
                binding_row_pid,
                // Self-carriage retains the non-OMP synthetic-id basis;
                // Darwin has no shipped reader for other pids' environ.
                &|want| ancestors.iter().any(|&pid| carries_process_id(pid, want)),
            )
        }
    }
}

/// Reap every proven in-scope process holding the instance: descendants of
/// an owning root carrying `HCOM_INSTANCE_NAME=<name>` or one of its binding
/// process ids (the self-bound tree never carries the name).
///
/// Oldest first (the pty wrapper predates its children), SIGTERM, wait up to
/// 5 s, SIGKILL survivors, verify. Verification re-enumerates carriers while
/// retaining earlier proven PID incarnations after reparenting. A late
/// carrier is signalable only when newly proven in scope (see
/// [`carrier_in_reap_scope`]): a mid-reap fork carrying one of the call-start
/// binding ids, one carrying a stale id no current binding claims, or one
/// with no process id at all (the name-only late fork) is still signalled
/// (in the KILL round) and still blocks success while it lives, while a
/// carrier whose `HCOM_PROCESS_ID` is registered among the name's fresh
/// binding epoch (a brand-new registration of a newer epoch) is spared and
/// never blocks; conversely a snapshot pid recycled by an unrelated process
/// no longer carries the name and is neither signalled nor counted (an EPERM
/// on such a pid is not survival). Returns an error when carriers survive or
/// the caller's ownership chain cannot be proven: the reap must reach `Ok(())`
/// before any `stopped` write or binding release.
///
/// The calling process is never signalled (see [`processes_for_instance`]).
/// Zombies are excluded from verification: a SIGKILLed carrier stays visible
/// in /proc (environ intact) until its parent reaps it, but it is gone for
/// lifecycle purposes (see [`process_gone`]) — blocking a release on it
/// would wedge every stop behind an unreaped child.
///
/// Unix only; elsewhere this is a no-op success.
#[allow(dead_code)] // test-facing: the reap conveniences used by the unix
// tests; production threads its own pre-signal capture.
pub fn reap_instance_tree_for(
    db: &HcomDb,
    name: &str,
    binding_ids: &[String],
) -> Result<(), ReapError> {
    reap_instance_tree_for_excluding(db, name, binding_ids, &[])
}

/// [`reap_instance_tree_for`] with an exclusion set: carriers in `exclude`
/// are never signalled and never count as survivors, at any enumeration
/// round (initial, KILL re-enumeration, verification).
///
/// In every round a carrier must also be a descendant of the recorded pid,
/// caller pid, or live minted `omp-<pid>-...` binding owner with comm exactly
/// `omp`. Roots are fixed at entry; the same roots gate pre-signal rechecks.
/// Caller ancestors are never signalled, even if also recorded roots. Other
/// Unix systems cannot prove /proc ancestry and signal no carriers here.
///
/// The kill self-path uses this with [`caller_ancestor_pids`]: the caller
/// runs inside the instance it is killing, so its own session ancestors
/// are spared while other eligible carriers are reaped. Ordering is
/// fail-closed: the kill runs this reap to
/// `Ok(())` BEFORE writing `stopped` or releasing the row/bindings — a
/// survivor returns `Err` and leaves ownership state untouched, so a failed
/// reap can never be converted into a successful exit after the row is
/// discarded (a kill never reports stopped or releases the row/bindings
/// while an in-scope instance process may still be alive). An empty `exclude` is
/// exactly [`reap_instance_tree_for`].
///
/// Reap scope (the re-enumeration / KILL and verification rounds): a carrier
/// first seen after the reap began is signalled unless its `HCOM_PROCESS_ID`
/// is non-empty and registered among the name's CURRENT binding ids read
/// fresh in that round, MINUS the ids passed at call start (see
/// [`carrier_in_reap_scope`]) — the epoch rule. The kill tears down exactly
/// one binding epoch: a fresh registration admitted mid-kill is a newer
/// epoch (its id is registered but outside the call-start set), its
/// processes are spared — never signalled, never a survivor — so a
/// same-identity start/resume admitted mid-kill never has its fresh process
/// reaped by the old kill's re-enumeration. Everything else name-matches the
/// dying epoch and is in scope: a late carrier with no process id (a
/// name-only fork of the dying tree), one carrying a call-start binding id
/// (a genuine mid-reap fork inherits the old env), and one carrying a stale
/// non-empty id that no current binding claims (a late child of the old
/// instance inheriting an older era's id) — signalled, and while alive a
/// survivor (fail-closed), provided its ancestry still reaches an owning
/// root.
///
/// Round ordering — the read-after-capture rule: every classification round
/// (the KILL re-enumeration and the final verification alike) CAPTURES its
/// carrier set first ([`live_carriers_for`]) and only THEN reads the binding
/// registry ([`fresh_epoch_ids`]), classifying exactly the captured set
/// against that read. This is what makes "read fresh" trustworthy: the
/// launcher registers a fresh binding BEFORE spawning its process
/// (`db.set_process_binding` runs in the pre-register block, before the tool
/// spawn — launcher.rs:2005), so every process a capture sees already has
/// its binding committed, and a registry read taken after the capture
/// cannot miss it. The reverse order (read, then capture) left a window: a
/// concurrent launch committing its binding after the read and spawning
/// before the capture was classified against a registry without its id and
/// killed as part of the dying epoch.
///
/// The KILL round revalidates once more immediately before its signal
/// round: it re-reads the registry and re-classifies the captured in-scope
/// set against the newer read, dropping every carrier that now matches a
/// fresh-epoch id from the signal set into `spared` (first-snapshot pids
/// stay in scope by fiat — this reap's own business, already TERMed; the
/// per-signal [`pid_carries_instance`] pid-reuse re-check is unchanged). A
/// spare decision is captured once per carrier: a carrier spared in one
/// round or by that revalidation stays spared, never reclassified into
/// scope by later registry changes.
///
/// Residual: a fresh registration whose binding lands only AFTER the round's
/// registry read is in scope for that round (the spawn-to-bind window) —
/// empty for launched instances, whose binding is written at launch
/// registration before the process spawns (launcher.rs:2005); only the
/// first-hook binding paths (instance_binding recovery), whose binding lands
/// after their process spawns, leave a window — and even that is bounded by
/// the KILL round's pre-signal re-read: a first-hook binding landing before
/// the re-read spares its process, one landing after it is signalled and,
/// while alive, a survivor (fail-closed).
/// The row itself is torn down only while the incarnation the kill resolved
/// against is still the row's (the kill command's teardown CAS).
/// If every live identity carrier seen is outside the proven scope and no carrier was admitted, release fails closed with the row intact.
///
/// `db` supplies the per-round binding registry read behind the epoch rule.
/// Unix only; elsewhere this is a no-op success.
#[allow(dead_code)] // test-facing: the reap conveniences used by the unix
// tests; production threads its own pre-signal capture.
pub fn reap_instance_tree_for_excluding(
    db: &HcomDb,
    name: &str,
    binding_ids: &[String],
    exclude: &[u32],
) -> Result<(), ReapError> {
    // The caller's ids are the call-start epoch this convenience reaps; the
    // row only supplies the recorded-pid root. The two are not one snapshot,
    // so the capture binds NO incarnation: the reap consumes only scope and
    // carriers, and nothing releases against it.
    let row = db.get_instance_full(name).ok().flatten();
    let owners = omp_owner_bindings(db, name);
    let capture = capture_reap_carriers_unbound(
        db,
        name,
        row.and_then(|row| row.pid),
        binding_ids,
        &owners,
        exclude,
    )?;
    reap_instance_tree_for_excluding_captured(db, name, binding_ids, exclude, capture)
}

pub(crate) fn reap_instance_tree_for_excluding_captured(
    db: &HcomDb,
    name: &str,
    binding_ids: &[String],
    exclude: &[u32],
    capture: ReapCapture,
) -> Result<(), ReapError> {
    #[cfg(not(unix))]
    {
        let _ = (db, name, binding_ids, exclude, capture);
        Ok(())
    }
    #[cfg(unix)]
    {
        let mut scope = capture.scope;
        // On /proc platforms, an unanchored caller cannot authorize release.
        // Other Unix hosts retain the baseline empty-reap success.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if scope.caller_ancestors.last() != Some(&1) {
            return Err(ReapError::UnprovenOwnership);
        }
        // The first round uses the pre-signal capture itself. Re-enumerating
        // here would wrongly TERM a carrier that arrived after that capture
        // (and, on headless paths, after the group signal). An empty first
        // capture still runs the KILL capture and epoch classification below:
        // an excluded owner may have forked a carrier since stop entry.
        let mut matches = capture.carriers;
        // Only identified first-snapshot carriers belong to this epoch by
        // fiat. Unidentified carriers still need the fresh-epoch check if
        // their identity becomes readable in a later round.
        let started: Vec<u32> = scope.known.keys().copied().collect();
        let mut spared: HashSet<u32> = HashSet::new();
        // Oldest first: pty wrapper before children.
        matches.sort_by(|a, b| {
            a.start_epoch
                .partial_cmp(&b.start_epoch)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for m in &matches {
            // Pid-reuse guard: only signal a snapshot pid that still holds
            // the instance; a recycled pid belongs to someone else now.
            if pid_carries_instance(m.pid, name, binding_ids, &scope) {
                signal(m.pid, libc::SIGTERM);
            }
        }
        wait_for_exit_pids(
            &matches.iter().map(|m| m.pid).collect::<Vec<_>>(),
            TERM_WAIT,
        );
        // Re-enumerate by carrier set: newly seen carriers (forked after the
        // first snapshot, so never TERMed) join the KILL round directly —
        // the TERM round already elapsed, so escalation is immediate — but
        // only in reap scope (predicate v3 against the registry read fresh
        // for this round). A genuine mid-reap fork carries the old binding
        // id (or no process id at all) and is caught here; a brand-new
        // registration (an id in the fresh epoch) started mid-reap is spared
        // (never signalled, never a survivor).
        //
        // Round ordering — the read-after-capture rule: the carrier set is
        // CAPTURED FIRST and the registry is read SECOND, so the read that
        // classifies a captured carrier cannot miss that carrier's
        // pre-spawn-registered binding (see the round-ordering note on
        // [`reap_instance_tree_for_excluding`]). A fresh process spawned
        // after the capture is outside the captured set entirely — never
        // classified here at all.
        let captured: Vec<ProcMatch> =
            snapshot_reap_carriers(name, binding_ids, exclude, &mut scope);
        #[cfg(test)]
        fire_round_seam(RoundPoint::Captured);
        let fresh_epoch = fresh_epoch_ids(db, name, binding_ids);
        let mut current: Vec<ProcMatch> = captured
            .into_iter()
            .filter(|m| {
                started.contains(&m.pid) || carrier_in_reap_scope(m, &fresh_epoch, &mut spared)
            })
            .collect();
        if current.is_empty() {
            // Ownership is unproven only while a dropped carrier still lives:
            // one seen only before the signal, and dead since, owns nothing.
            if scope.admitted.get() == 0
                && scope
                    .dropped_live
                    .borrow()
                    .iter()
                    .any(|&pid| !process_gone(pid))
            {
                return Err(ReapError::UnprovenOwnership);
            }
            return Ok(());
        }
        current.sort_by(|a, b| {
            a.start_epoch
                .partial_cmp(&b.start_epoch)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        // Pre-signal revalidation: immediately before the signal round,
        // re-read the registry and re-classify the captured in-scope set
        // against the newer read. A carrier that NOW matches a fresh-epoch
        // id (its registration landed between classification and the signal
        // round — the first-hook spawn-to-bind shape) is dropped from the
        // signal set and joins the spared set, where it stays. First-snapshot
        // pids stay in scope by fiat (this reap's own business, already
        // TERMed); the per-signal pid-reuse re-check below is unchanged.
        #[cfg(test)]
        fire_round_seam(RoundPoint::Classified);
        let fresh_epoch = fresh_epoch_ids(db, name, binding_ids);
        current.retain(|m| {
            started.contains(&m.pid) || carrier_in_reap_scope(m, &fresh_epoch, &mut spared)
        });

        // A carrier first seen in THIS capture never went through the
        // pre-signal guard, so it is re-proved here — the last point before a
        // KILL goes out. A late carrier another live row holds is not
        // signalled: it is logged once and left to the survivor check below,
        // which fails the release closed while it lives. A registry the
        // guard cannot read signals no late carrier at all. First-capture
        // carriers were refused at capture time and keep today's behaviour.
        let minted = if current.iter().any(|m| !started.contains(&m.pid)) {
            minted_pid_owners(db).ok()
        } else {
            None
        };
        current.retain(|m| {
            if started.contains(&m.pid) {
                return true;
            }
            match minted.as_ref() {
                // No registry read: an unproven late carrier is never signalled.
                None => false,
                Some(minted) => match foreign_live_owner(db, minted, name, m.pid) {
                    Ok(None) => true,
                    Ok(Some((owner, via))) => {
                        crate::log::log_info(
                            "proctruth",
                            "reap_skipped_foreign_owner",
                            &format!("instance={name} pid={} owner={owner} via={via}", m.pid),
                        );
                        false
                    }
                    // Fail closed: a registry that cannot answer is not a
                    // clean bill of health for this carrier.
                    Err(_) => false,
                },
            }
        });
        for m in &current {
            if pid_carries_instance(m.pid, name, binding_ids, &scope) {
                signal(m.pid, libc::SIGKILL);
            }
        }
        wait_for_exit_pids(
            &current.iter().map(|m| m.pid).collect::<Vec<_>>(),
            KILL_WAIT,
        );
        // Verification is scoped exactly like the KILL round (same order:
        // capture the carrier set first, registry read second, classify the
        // captured set against that read; same captured spare set): an
        // in-scope carrier still alive blocks success (fail-closed), while a
        // spared fresh registration never does — a spared carrier is never
        // counted as a survivor.
        let captured: Vec<ProcMatch> =
            snapshot_reap_carriers(name, binding_ids, exclude, &mut scope);
        let fresh_epoch = fresh_epoch_ids(db, name, binding_ids);
        let still: Vec<u32> = captured
            .into_iter()
            .filter(|m| {
                started.contains(&m.pid) || carrier_in_reap_scope(m, &fresh_epoch, &mut spared)
            })
            .map(|m| m.pid)
            .collect();
        if still.is_empty() {
            Ok(())
        } else {
            Err(ReapError::Survivors(still))
        }
    }
}

/// The name's fresh binding epoch for one reap round: its CURRENT process
/// binding ids read from the DB now, MINUS the ids passed at call start. A
/// binding registered during this kill shows up here — evidence of a newer
/// epoch (see [`carrier_in_reap_scope`]). Each round reads it AFTER
/// capturing its carrier set (the read-after-capture rule, see
/// [`reap_instance_tree_for_excluding`]); the KILL round reads it again
/// right before signalling (the pre-signal revalidation). A failed read
/// yields an empty epoch (fail-closed toward scope: nothing gets an unearned
/// spare).
#[cfg(unix)]
fn fresh_epoch_ids(db: &HcomDb, name: &str, call_start_ids: &[String]) -> Vec<String> {
    db.process_binding_ids(name)
        .unwrap_or_default()
        .into_iter()
        .filter(|id| !call_start_ids.contains(id))
        .collect()
}

/// Reap scope for a carrier first seen after the reap began (carriers of the
/// reap's first snapshot are always in scope) — predicate v3, the epoch
/// rule: IN SCOPE unless the carrier's `HCOM_PROCESS_ID` is
/// non-empty and registered among `fresh_epoch_ids`, the name's CURRENT
/// binding ids read fresh in this round — after the round's carrier capture
/// — MINUS the call-start ids. Instance identity keys to
/// binding epochs (process bindings are the incarnation token), so a
/// registered id outside the call-start set is a NEWER epoch and is spared —
/// never signalled, never a survivor. Everything else name-matches the
/// dying epoch and is this reap's business: a name-only late carrier (empty
/// process id — a fork of the dying tree, or an old process that became a
/// carrier mid-reap), a carrier carrying one of the call-start binding ids
/// (a genuine mid-reap fork inherits the old env), and a carrier whose
/// non-empty id no current binding claims (a stale id inherited from an
/// older era) are signalled and, while alive, block success (fail-closed).
/// The spare decision is captured once per carrier in `spared`: a carrier
/// spared in one round or by the KILL round's pre-signal revalidation stays
/// spared — later registry changes never reclassify it into scope.
#[cfg(unix)]
fn carrier_in_reap_scope(
    m: &ProcMatch,
    fresh_epoch_ids: &[String],
    spared: &mut HashSet<u32>,
) -> bool {
    if spared.contains(&m.pid) {
        return false;
    }
    if is_bound_process_id(&m.process_id, fresh_epoch_ids) {
        spared.insert(m.pid);
        return false;
    }
    true
}

/// Test-only round seam: a per-thread hook fired at the two boundaries the
/// round-ordering contract pins in the KILL round — right after its carrier
/// capture ([`RoundPoint::Captured`]) and right after its classification of
/// that captured set ([`RoundPoint::Classified`]). A test arms it from its
/// own reaper thread to land a concurrent registration or spawn at one exact
/// instruction boundary of the round instead of racing the clock. Unarmed,
/// firing is a no-op; never compiled outside `cfg(test)`.
#[cfg(all(test, unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoundPoint {
    /// The KILL round has captured its carrier set; its registry read is next.
    Captured,
    /// The KILL round has classified the captured set; the pre-signal
    /// revalidation and signal loop are next.
    Classified,
}

/// The round seam's per-thread slot: an optional hook, armed by the tests
/// via `arm_round_seam` and fired by [`fire_round_seam`].
#[cfg(all(test, unix))]
type RoundSeamSlot = std::cell::RefCell<Option<Box<dyn FnMut(RoundPoint)>>>;

#[cfg(all(test, unix))]
thread_local! {
    static ROUND_SEAM: RoundSeamSlot = std::cell::RefCell::new(None);
    static MISSING_CARRIER_IDENTITY: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(test, unix))]
fn fire_round_seam(point: RoundPoint) {
    ROUND_SEAM.with(|seam| {
        if let Some(hook) = seam.borrow_mut().as_mut() {
            hook(point);
        }
    });
}

/// Arm this thread's reap round seam at an exact round boundary.
#[cfg(all(test, unix))]
pub(crate) fn arm_round_seam(hook: impl FnMut(RoundPoint) + 'static) {
    ROUND_SEAM.with(|seam| *seam.borrow_mut() = Some(Box::new(hook)));
}

/// Live carriers for reap verification: carrier enumeration minus zombies
/// minus the exclusion set (the caller's own session tree in the kill
/// self-path — never signalled, never a survivor).
#[cfg(unix)]
fn live_carriers_for(
    name: &str,
    binding_ids: &[String],
    owners: &[OmpOwnerBinding],
    exclude: &[u32],
    scope: Option<&CarrierTreeScope>,
) -> Vec<ProcMatch> {
    enumerate_unix(name, binding_ids, owners, scope)
        .into_iter()
        .filter(|m| !is_zombie(m.pid) && !exclude.contains(&m.pid))
        .collect()
}

/// Pid-reuse guard for a recorded group leader: true when at least one live,
/// non-zombie identity carrier of the instance (the reap's enumeration) is in
/// process group `pgid`. A headless launch records the launch-script bash,
/// which leads the group but never carries the identity itself; `hcom pty`
/// below it does. An unrelated process that reused the pid has none of the
/// instance's carriers in its group.
#[cfg(target_os = "linux")]
pub(crate) fn group_holds_instance_carrier(
    pgid: u32,
    name: &str,
    binding_ids: &[String],
    owners: &[OmpOwnerBinding],
) -> bool {
    live_carriers_for(name, binding_ids, owners, &[], None)
        .iter()
        .any(|m| process_group_id(m.pid) == Some(pgid))
}

/// Whether every pid in `pids` is provably outside process group `pgid`:
/// none is `pgid` itself, and each one's /proc pgrp names another group. A
/// gone pid is in no group; a live pid whose pgrp cannot be read proves
/// nothing, so it counts as inside.
#[cfg(target_os = "linux")]
pub(crate) fn pids_outside_group(pgid: u32, pids: &[u32]) -> bool {
    pids.iter().all(|&pid| {
        pid != pgid
            && match process_group_id(pid) {
                Some(group) => group != pgid,
                None => process_gone(pid),
            }
    })
}

/// Recheck identity and the captured process incarnation before signalling.
/// Captured carriers keep their scope after their parents die. A live carrier
/// without a captured OS identity blocks release but is never signalled.
#[cfg(unix)]
fn pid_carries_instance(
    pid: u32,
    name: &str,
    binding_ids: &[String],
    scope: &CarrierTreeScope,
) -> bool {
    let want = format!("HCOM_INSTANCE_NAME={name}");
    let carries = std::fs::read(format!("/proc/{pid}/environ")).is_ok_and(|env| {
        let (carries_name, process_id) = identity_facts(&env, want.as_bytes());
        carries_name || is_bound_process_id(&process_id, binding_ids)
    });
    // A binding owner never shows its id in environ; the same proof that
    // admitted it (see `enumerate_unix`) still has to hold now.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let carries = carries
        || scope
            .owners
            .iter()
            .any(|owner| owner.pid == pid && proven_omp_owner(owner, system_btime()));
    if !carries {
        return false;
    }
    let Some((_, identity)) = scope.known.get(&pid) else {
        return false;
    };
    if carrier_identity(pid).as_ref() != Some(identity) {
        log_carrier_out_of_scope(pid, name, scope);
        return false;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if std::fs::read_to_string(format!("/proc/{pid}/comm")).map_or(true, |comm| {
        comm.trim_end_matches('\n') == "omp daemon brok"
    }) {
        log_carrier_out_of_scope(pid, name, scope);
        return false;
    }
    carrier_in_signal_scope(pid, name, scope)
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

/// The caller's own identity tree: the slice of the live process table that
/// is the caller's own session, never a foreign name holder.
///
/// Root: the OLDEST ancestor-or-self of `caller_pid` that is itself a
/// carrier (carries `HCOM_INSTANCE_NAME=<name>` or one of the instance's
/// binding process ids) AND shares the caller's identity facts — the same
/// non-empty `HCOM_PROCESS_ID` value, or both carrying the target name. The
/// tree is that root plus every process whose ppid-ancestor chain passes
/// through it: a session's carriers sit above and beside the CLI running the
/// gate, all under one session root.
///
/// Topology alone never finds a root: a child of a holder's tree whose env
/// was stripped of identity must not have that tree treated as its own — it
/// is a foreign claimant, and the identity match at the root is what says
/// so. A caller carrying no identity facts therefore finds no root; its tree
/// is just its own pid (already excluded from [`processes_for_instance`])
/// and the gate runs full, exactly as before this rule existed.
///
/// Returns the tree as far as the gate needs it: the caller's own pid, the
/// root, and every enumerated carrier inside it — exactly the pids
/// [`check_spawn_allowed`] removes from the carrier set.
///
/// `caller_pid` is [`std::process::id()`] in production; it is a parameter
/// so tests can model a caller inside an arbitrary tree.
fn caller_identity_tree(
    name: &str,
    binding_ids: &[String],
    holders: &[ProcMatch],
    caller_pid: u32,
) -> Vec<u32> {
    let Some((caller_carries_name, caller_process_id)) = identity_facts_of(caller_pid, name) else {
        return vec![caller_pid];
    };
    if !caller_carries_name && caller_process_id.is_empty() {
        return vec![caller_pid];
    }
    let root = ancestor_or_self_pids(caller_pid)
        .into_iter()
        .rev()
        .find(|pid| {
            let Some((carries_name, process_id)) = identity_facts_of(*pid, name) else {
                return false;
            };
            let carrier = carries_name || is_bound_process_id(&process_id, binding_ids);
            let shares = (carries_name && caller_carries_name)
                || (!caller_process_id.is_empty() && process_id == caller_process_id);
            carrier && shares
        });
    let Some(root) = root else {
        return vec![caller_pid];
    };
    let mut tree = vec![caller_pid];
    if root != caller_pid {
        tree.push(root);
    }
    for h in holders {
        if !tree.contains(&h.pid) && ancestor_or_self_pids(h.pid).contains(&root) {
            tree.push(h.pid);
        }
    }
    tree
}

/// Refuse to spawn under `<name>` over a live holder or an orphan — the one
/// uniform spawn gate (`start --as`, resume, and explicit-name launch all
/// share this rule).
///
/// Carriers match by name OR by any of the instance's binding process ids,
/// so a live self-bound holder (process id only, no name in env) refuses
/// exactly like a live hcom-launched holder. The caller's own identity tree
/// ([`caller_identity_tree`]) is removed from the carrier set first: a
/// session re-registering its own name is never blocked by its own
/// processes. What remains is classified:
///
/// - Newest binding's own process_id still carried by a live process → live
///   holder, refuse.
/// - Any other process_id carrying the name, started before the newest
///   binding's `updated_at` minus grace → orphan, refuse.
/// - A same-name process with an old process_id started *after* the binding
///   (subagent shape: children inherit the parent's process id and outlive
///   the rebind) is not an orphan → proceed.
/// - Nothing left alive → proceed (a DB-active row is the DB layer's business:
///   resume keeps its existing "still active" message for that case).
/// - No binding at all but live name carriers → live holders, refuse. (A
///   process carrying only an unknown process_id is unattributable without
///   bindings, so it never blocks — this keeps `start --as` recovery working
///   after a row plus its bindings were deleted.)
///
/// Residual: name-carrying impostors with NO process id that sit in the
/// caller's identity tree are indistinguishable from the caller's own
/// processes and are excluded with it — accepted because identity leaks into
/// descendant env are being removed separately (see the post-exit shell fix
/// already in this base).
pub fn check_spawn_allowed(db: &HcomDb, name: &str) -> Result<(), SpawnRefusal> {
    let binding_ids = db.process_binding_ids(name).unwrap_or_default();
    // No binding-owner arm here: the self-tree exclusion below finds the
    // caller's session root by environ identity, which a binding owner never
    // shows, so admitting owners would refuse a session re-registering its
    // own name.
    let holders = processes_for_instance(name, &binding_ids, &[]);
    if holders.is_empty() {
        return Ok(());
    }
    let self_tree = caller_identity_tree(name, &binding_ids, &holders, std::process::id());
    let remainder: Vec<ProcMatch> = holders
        .into_iter()
        .filter(|h| !self_tree.contains(&h.pid))
        .collect();
    // Only carriers outside the caller's own identity tree can refuse the
    // spawn; with the tree gone the gate is open.
    if remainder.is_empty() {
        return Ok(());
    }
    let newest = db.newest_process_binding(name).unwrap_or(None);
    classify_holders(name, &remainder, newest)
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

// Test seam: runs between the sweep's snapshot read and the release it
// authorizes, so a test can land a rebind or replacement in that gap.
#[cfg(test)]
thread_local! {
    static SWEEP_RELEASE_GAP_HOOK: crate::db::GapHook = const { std::cell::Cell::new(None) };
}

/// Daemon-side periodic check (runs on the relay worker's watchdog tick, so
/// in a different process — and typically a different cgroup — from any
/// session): for every local instance, test whether its harness is gone.
/// Inactive rows are checked on Linux only.
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
/// - a registered notify endpoint (kind other than `inject`) that still accepts
///   a TCP connect AND whose listener is proven to be the seat's (its owner or
///   the owner's child has the row's session transcript open; for a
///   session-less row, an omp/hcom owner no other live row is bound to) →
///   HELD: the seat process serves it, which `/proc` cannot otherwise see when
///   no carrier carries an HCOM marker. An accept whose owner cannot be
///   determined also holds; an accept from an unrelated owner is no evidence.
///   See `held_by_live_notify_endpoint`.
///
/// A vanished row gets `stopped by=daemon reason=vanished` with the instance
/// snapshot, then the row is released — the notice systemd-oomd kills
/// currently never produce. The release is bound to the incarnation the
/// sweep read (row identity plus binding epoch, one snapshot): a rebind or
/// `start --as` replacement landing after that read keeps its row and
/// bindings.
///
/// Skips rows already released (they are simply not returned by the live
/// query, so a normal exit's wrapper-written `stopped` never double-fires),
/// remote mirrors, placeholders, recently-seen rows, and off Linux, inactive
/// rows.
/// Returns swept names.
pub fn sweep_vanished_instances(db: &HcomDb) -> Vec<String> {
    // Row and its whole binding epoch come from ONE read transaction: a
    // `start --as` replacement deletes and recreates row and bindings in
    // separate commits, so separate reads can pair one incarnation's row
    // with another's bindings.
    let instances = match db.iter_instances_with_bindings() {
        Ok(rows) => rows,
        Err(_) => return Vec::new(),
    };
    let now = crate::shared::time::now_epoch_f64() as i64;
    let mut swept = Vec::new();
    for (inst, binding_ids) in &instances {
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
        // pid, and its process bindings for a later `hcom r`. On Linux they
        // get no pass: they are released once their process is provably
        // gone, and a resume handle survives release because `hcom r` reads
        // the stopped snapshot. Off Linux nothing sees their carriers (no
        // /proc), so a dead pid alone never releases one: the sweep leaves
        // them alone.
        #[cfg(not(target_os = "linux"))]
        if inst.status == crate::shared::ST_INACTIVE {
            continue;
        }
        if inst.last_seen > 0 && now - inst.last_seen < SWEEP_FRESH_GRACE_SECS {
            continue;
        }
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
        // No binding owners: every minted owner pid is in `evidence_pids`,
        // all of which are gone by here.
        if processes_for_instance(&inst.name, binding_ids, &[])
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
        // /proc sees nothing for a seat with no HCOM-marked carrier, but its
        // own notify endpoint is served by the seat process: a listener proven
        // to be the seat's is positive evidence of life the pid table cannot
        // supply (the valo 16:03 false stop). Last hold, so rows already held
        // by a cheap /proc check never pay for a connect.
        if held_by_live_notify_endpoint(db, &inst.name, inst.session_id.as_deref()) {
            continue;
        }
        #[cfg(test)]
        if let Some(hook) = SWEEP_RELEASE_GAP_HOOK.with(std::cell::Cell::take) {
            hook(db, &inst.name);
        }
        // Vanished: snapshot, stopped by=daemon, release. The exact bit
        // pattern rides beside created_at so a later reader can match the
        // incarnation without a lossy float decode.
        let snapshot = db.get_instance_snapshot(&inst.name).unwrap_or(None);
        let snapshot = snapshot.map(|mut snapshot| {
            if let Some(created_at) = snapshot
                .get("created_at")
                .and_then(serde_json::Value::as_f64)
                && let Some(object) = snapshot.as_object_mut()
            {
                object.insert(
                    "created_at_bits".to_string(),
                    serde_json::json!(created_at.to_bits()),
                );
            }
            snapshot
        });
        // Newest binding from the captured set: it is ordered newest-first
        // (process_bindings.updated_at DESC), the same ordering the old
        // `newest_process_binding` query used, so no second read.
        let process_id = binding_ids.first().map(String::as_str);
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
            inst.pid,
            inst.session_id.as_deref(),
            inst.agent_id.as_deref(),
            &data,
            process_id,
            Some(binding_ids.as_slice()),
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

/// Endpoint liveness probe for the sweep's last hold: is any of the row's
/// registered endpoints still served by the row's own seat? Cheap first: a
/// refused connect on loopback is a dead endpoint and costs no /proc scan.
/// An accept only proves that somebody holds the port, so the listener's
/// owner must then be proven to be the seat ([`endpoint_owner`]): a proven
/// owner holds the row, an unrelated owner is no evidence (another service
/// may have bound the port after the seat's listener died), and an owner
/// that cannot be determined holds the row on the accept alone, since the
/// sweep fails toward keeping.
///
/// Every wake kind answers a bare connect-and-close by design (the omp
/// plugin runs one idempotent `deliverPending` pass and closes), so the
/// accept is a wake, not a protocol exchange. `inject` is skipped: it is a
/// request/response RPC whose empty connection feeds an empty payload to the
/// PTY writer and runs the injected-approval check, so probing it is not a
/// no-op. Logs the branch taken for every accepting endpoint and returns
/// whether the row is held — a failed endpoint query holds the row too.
fn held_by_live_notify_endpoint(db: &HcomDb, name: &str, session_id: Option<&str>) -> bool {
    let endpoints = match db.notify_endpoint_ports(name) {
        Ok(endpoints) => endpoints,
        Err(e) => {
            crate::log::log(
                "DEBUG",
                "daemon",
                "sweep.held",
                &format!("name={} reason=endpoint-query-failed err={}", name, e),
            );
            return true;
        }
    };
    for (kind, port) in endpoints {
        if kind == "inject" {
            continue;
        }
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(250))
            .is_err()
        {
            continue;
        }
        match endpoint_owner(db, name, session_id, port) {
            EndpointOwner::Owned { pid, via } => {
                crate::log::log(
                    "DEBUG",
                    "daemon",
                    "sweep.held",
                    &format!(
                        "name={name} reason=notify-endpoint-owned kind={kind} port={port} owner_pid={pid} via={via}"
                    ),
                );
                return true;
            }
            EndpointOwner::Undeterminable(why) => {
                crate::log::log(
                    "DEBUG",
                    "daemon",
                    "sweep.held",
                    &format!(
                        "name={name} reason=notify-endpoint-accepts-owner-undeterminable kind={kind} port={port} why={why}"
                    ),
                );
                return true;
            }
            EndpointOwner::Unrelated { pid, why } => {
                crate::log::log_info(
                    "daemon",
                    "sweep.endpoint_not_owned",
                    &format!(
                        "name={name} kind={kind} port={port} owner_pid={pid} why={why}: no evidence"
                    ),
                );
            }
        }
    }
    false
}

/// What the process behind an accepting endpoint port proves about a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Only the Linux /proc probe proves or refutes an owner.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum EndpointOwner {
    /// The listener is the row's own seat; `via` names the proof.
    Owned { pid: u32, via: &'static str },
    /// Another process holds the port: no evidence for the row.
    Unrelated { pid: u32, why: &'static str },
    /// Neither could be proven (`why`), so the accept alone holds the row.
    Undeterminable(&'static str),
}

/// Who serves the loopback listener on `port`, judged against the row.
///
/// The LISTEN socket is found in `/proc/net/tcp{,6}` and its inode mapped to
/// the pids whose `/proc/<pid>/fd` link to it. A row with a session is owned
/// only when a holder, or a holder's direct child (the pty listener lives in
/// the hcom wrapper, whose child is the tool), has that session's transcript
/// (`<session_id>.jsonl`) open: proof tied to this row, not just to some
/// seat. A row with no session is owned when a holder or its direct parent
/// is an omp/hcom process that no other live row is bound to. Anything else
/// is unrelated. A socket or holder that cannot be found (another user's
/// process, another network namespace, a race with the close) is
/// undeterminable.
#[cfg(target_os = "linux")]
fn endpoint_owner(db: &HcomDb, name: &str, session_id: Option<&str>, port: u16) -> EndpointOwner {
    let inodes = loopback_listener_inodes(port);
    if inodes.is_empty() {
        return EndpointOwner::Undeterminable("listener-not-in-proc-net");
    }
    let holders = socket_holder_pids(&inodes);
    let Some(&first) = holders.first() else {
        return EndpointOwner::Undeterminable("listener-holder-not-found");
    };
    if let Some(session_id) = session_id.filter(|sid| !sid.is_empty()) {
        let transcript = format!("{session_id}.jsonl");
        if let Some(&pid) = holders
            .iter()
            .find(|&&pid| holds_session_transcript(pid, &transcript))
        {
            return EndpointOwner::Owned {
                pid,
                via: "session-fd",
            };
        }
        if let Some((pid, _child)) = direct_children(&holders)
            .into_iter()
            .find(|&(_, child)| holds_session_transcript(child, &transcript))
        {
            return EndpointOwner::Owned {
                pid,
                via: "session-fd-child",
            };
        }
        return EndpointOwner::Unrelated {
            pid: first,
            why: "session-transcript-not-open",
        };
    }
    let minted = match minted_pid_owners(db) {
        Ok(minted) => minted,
        Err(_) => return EndpointOwner::Undeterminable("binding-registry-unreadable"),
    };
    let mut verdict = EndpointOwner::Unrelated {
        pid: first,
        why: "not-omp-or-hcom",
    };
    'holders: for &pid in &holders {
        let lineage: Vec<u32> = std::iter::once(pid).chain(parent_pid(pid)).collect();
        for &candidate in &lineage {
            match foreign_live_owner(db, &minted, name, candidate) {
                Ok(None) => {}
                Ok(Some(_)) => {
                    verdict = EndpointOwner::Unrelated {
                        pid,
                        why: "bound-to-another-row",
                    };
                    continue 'holders;
                }
                Err(_) => return EndpointOwner::Undeterminable("binding-registry-unreadable"),
            }
        }
        if lineage
            .iter()
            .any(|&candidate| is_omp_or_hcom_process(candidate))
        {
            return EndpointOwner::Owned {
                pid,
                via: "omp-process",
            };
        }
    }
    verdict
}

/// No /proc to map a socket to its owner: the accept alone holds the row.
#[cfg(not(target_os = "linux"))]
fn endpoint_owner(db: &HcomDb, name: &str, session_id: Option<&str>, port: u16) -> EndpointOwner {
    let _ = (db, name, session_id, port);
    EndpointOwner::Undeterminable("no-proc")
}

/// Inodes of the LISTEN sockets on `port` that accept a connect to
/// 127.0.0.1: bound to 127.0.0.1, to the IPv4 wildcard, to the IPv6
/// wildcard, or to the v4-mapped loopback/wildcard. Addresses in
/// `/proc/net/tcp{,6}` are the in-memory (network order) words printed as
/// native-endian hex, the port is plain hex, and state `0A` is LISTEN.
#[cfg(target_os = "linux")]
fn loopback_listener_inodes(port: u16) -> Vec<u64> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn address_bytes<const N: usize>(hex: &str) -> Option<[u8; N]> {
        if hex.len() != N * 2 {
            return None;
        }
        let mut bytes = [0u8; N];
        for (word, chunk) in bytes.chunks_mut(4).enumerate() {
            let value = u32::from_str_radix(hex.get(word * 8..word * 8 + 8)?, 16).ok()?;
            chunk.copy_from_slice(&value.to_ne_bytes());
        }
        Some(bytes)
    }
    fn accepts_loopback_v4(addr: Ipv4Addr) -> bool {
        addr == Ipv4Addr::LOCALHOST || addr.is_unspecified()
    }

    let mut inodes = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in text.lines().skip(1) {
            // sl, local_address, rem_address, st, tx:rx, tr:when, retrnsmt,
            // uid, timeout, inode.
            let mut fields = line.split_whitespace();
            let (Some(local), Some(state), Some(inode)) =
                (fields.nth(1), fields.nth(1), fields.nth(5))
            else {
                continue;
            };
            let Some((addr_hex, port_hex)) = local.split_once(':') else {
                continue;
            };
            if state != "0A" || u16::from_str_radix(port_hex, 16) != Ok(port) {
                continue;
            }
            let accepts = match addr_hex.len() {
                8 => address_bytes::<4>(addr_hex).is_some_and(|b| accepts_loopback_v4(b.into())),
                32 => address_bytes::<16>(addr_hex).is_some_and(|b| {
                    let addr = Ipv6Addr::from(b);
                    addr.is_unspecified() || addr.to_ipv4_mapped().is_some_and(accepts_loopback_v4)
                }),
                _ => false,
            };
            if accepts
                && let Ok(inode) = inode.parse::<u64>()
                && inode != 0
            {
                inodes.push(inode);
            }
        }
    }
    inodes
}

/// Pids with an fd open on one of the socket `inodes`. A process whose fd
/// table cannot be read (another user's, or exited) is skipped, so an empty
/// result means "not found", never "nobody".
#[cfg(target_os = "linux")]
fn socket_holder_pids(inodes: &[u64]) -> Vec<u32> {
    let targets: Vec<String> = inodes
        .iter()
        .map(|inode| format!("socket:[{inode}]"))
        .collect();
    let mut holders = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return holders;
    };
    for entry in dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        let holds = fds.flatten().any(|fd| {
            std::fs::read_link(fd.path()).is_ok_and(|link| {
                targets
                    .iter()
                    .any(|target| link.as_os_str() == target.as_str())
            })
        });
        if holds {
            holders.push(pid);
        }
    }
    holders
}

/// `(parent, child)` for every live process whose parent is in `parents`.
#[cfg(target_os = "linux")]
fn direct_children(parents: &[u32]) -> Vec<(u32, u32)> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| {
            let parent = parent_pid(pid)?;
            parents.contains(&parent).then_some((parent, pid))
        })
        .collect()
}

/// Whether `pid` has a file open whose path ends in `transcript`
/// (`<session_id>.jsonl`) right after a path separator or a non-alphanumeric
/// prefix (`<ts>_<session_id>.jsonl`), so a longer id never matches a shorter
/// one. A transcript deleted while open still counts.
#[cfg(target_os = "linux")]
fn holds_session_transcript(pid: u32, transcript: &str) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    fds.flatten().any(|fd| {
        std::fs::read_link(fd.path()).is_ok_and(|link| {
            let path = link.as_os_str().as_bytes();
            let path = path.strip_suffix(b" (deleted)").unwrap_or(path);
            path.strip_suffix(transcript.as_bytes())
                .is_some_and(|head| head.last().is_none_or(|b| !b.is_ascii_alphanumeric()))
        })
    })
}

/// An omp or hcom process: `/proc/<pid>/comm`, or the basename of argv[0],
/// is exactly `omp` or `hcom`.
#[cfg(target_os = "linux")]
fn is_omp_or_hcom_process(pid: u32) -> bool {
    const NAMES: [&str; 2] = ["omp", "hcom"];
    let comm_matches = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .is_ok_and(|comm| NAMES.contains(&comm.trim_end_matches('\n')));
    comm_matches
        || std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| {
            let argv0 = cmdline.split(|b| *b == 0).next().unwrap_or_default();
            let base = argv0.rsplit(|b| *b == b'/').next().unwrap_or_default();
            NAMES.iter().any(|name| name.as_bytes() == base)
        })
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

    #[test]
    #[cfg(target_os = "linux")]
    fn broker_carrier_eligibility_decision_table() {
        let facts = [
            (10, "omp", 1),
            (20, "omp daemon brok\n", 10),
            (21, "chromium", 20),
            (22, "omp", 20),
            (23, "sh", 22),
            (24, "omp daemon brok", 22),
            (25, "sh", 24),
            (26, "sh", 10),
            (27, "omp daemon broker", 10),
            (28, "omp", 24),
            (29, "omp daemon bro", 10),
            (30, "chromium", 9999),
        ];
        for (pid, eligible) in [
            (10, true),  // Owner above the broker.
            (20, false), // Broker itself, even below an omp.
            (21, false), // Shared daemon immediately below broker.
            (22, true),  // Nested omp itself counts.
            (23, true),  // Nested omp's tool shell.
            (24, false), // Nearest broker wins over an outer nested omp.
            (25, false), // Inner broker's daemon.
            (26, true),  // Ordinary owner child, no broker.
            (27, true),  // Exact comm match, not prefix match.
            (28, true),  // A new omp below the inner broker.
            (29, true),  // Shorter lookalike is not a broker.
            (30, true),  // Unknown ancestry preserves the existing rule.
        ] {
            assert_eq!(
                carrier_eligible_with(
                    pid,
                    |id| facts
                        .iter()
                        .find(|(p, _, _)| *p == id)
                        .map(|(_, c, _)| c.to_string()),
                    |id| facts
                        .iter()
                        .find(|(p, _, _)| *p == id)
                        .map(|(_, _, parent)| *parent)
                ),
                eligible,
                "pid {pid}"
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn carrier_tree_scope_requires_descendance_and_never_signals_ancestors() {
        let scope = CarrierTreeScope {
            // Caller, recorded instance pid, verified minted omp owner.
            roots: vec![10, 20, 30],
            caller_ancestors: vec![10, 2, 1],
            known: HashMap::new(),
            excluded: Vec::new(),
            dropped_live: std::cell::RefCell::new(Vec::new()),
            admitted: std::cell::Cell::new(0),
            owners: Vec::new(),
        };
        let parents = [
            (10, 2),
            (20, 1),
            (21, 20),
            (22, 21),
            (30, 1),
            (31, 30),
            (40, 1),
            (41, 40),
            (50, 50),
            (2, 1),
        ];
        for (pid, eligible) in [
            (10, false), // Caller root is never signalled.
            (2, false),  // Nor an ancestor, even if it carried the identity.
            (20, true),  // Recorded root itself.
            (21, true),  // Recorded root descendant.
            (22, true),  // Grandchild.
            (30, true),  // Verified minted-omp root itself.
            (31, true),  // Verified minted-omp root descendant.
            (40, false), // Unrelated process beside the owner.
            (41, false), // Descendant of that unrelated process.
            (50, false), // Malformed cyclic ancestry.
            (60, false), // Missing /proc link.
        ] {
            assert_eq!(
                carrier_in_owner_tree_with(pid, &scope, |current| {
                    parents
                        .iter()
                        .find(|(id, _)| *id == current)
                        .map(|(_, parent)| *parent)
                }),
                eligible,
                "pid {pid}"
            );
        }
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

    #[cfg(target_os = "linux")]
    fn insert_null_pid_row(db: &HcomDb, name: &str, process_id: &str) {
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, session_id) \
                 VALUES (?1, 'active', ?2, 'codex', 'sess-carrier')",
                rusqlite::params![name, now],
            )
            .unwrap();
        db.set_process_binding(process_id, "sess-carrier", name)
            .unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn kill_releases_never_succeed_while_an_unsignalled_identity_carrier_lives() {
        let db = test_db();
        let name = unique_name("unproven-release");
        let process_id = format!("proc-{}", rand_suffix());
        insert_null_pid_row(&db, &name, &process_id);
        let carrier = spawn_detached_named_sleeper(&name, &process_id);
        wait_for_enumerated(&name, std::slice::from_ref(&process_id), carrier);
        let outcome = crate::hooks::common::stop_instance(&db, &name, "test", "stopped");
        assert!(matches!(
            outcome,
            crate::hooks::common::StopOutcome::RetryableError(_)
        ));
        assert!(db.get_instance_full(&name).unwrap().is_some());
        assert_eq!(db.process_binding_ids(&name).unwrap(), vec![process_id]);
        assert!(!process_gone(carrier));
        unsafe { libc::kill(carrier as libc::pid_t, libc::SIGKILL) };
    }

    /// A live process exec'd through a symlink named `comm` (so
    /// /proc/<pid>/comm reads `comm`) with no hcom identity in its environ:
    /// an omp whose plugin minted its id into the runtime env only. The loop
    /// keeps any orphaned `sleep` to at most a second once it dies.
    #[cfg(target_os = "linux")]
    fn spawn_comm_process(dir: &std::path::Path, comm: &str) -> std::process::Child {
        let link = dir.join(comm);
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        std::process::Command::new(&link)
            .args(["-c", "while :; do sleep 1; done"])
            .env_remove("HCOM_INSTANCE_NAME")
            .env_remove("HCOM_PROCESS_ID")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn comm process")
    }

    #[cfg(target_os = "linux")]
    fn owner_binding(pid: u32, registered_at: f64) -> OmpOwnerBinding {
        OmpOwnerBinding {
            pid,
            process_id: format!("omp-{pid}-{}-1", rand_suffix()),
            registered_at,
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn binding_owner_without_the_id_in_its_environ_is_a_carrier() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = spawn_comm_process(dir.path(), "omp");
        let binding = owner_binding(owner.id(), crate::shared::time::now_epoch_f64());
        let found = processes_for_instance(
            &unique_name("binding-owner"),
            std::slice::from_ref(&binding.process_id),
            std::slice::from_ref(&binding),
        );
        owner.kill().ok();
        owner.wait().ok();
        let owned = found.iter().find(|m| m.pid == binding.pid);
        assert!(owned.is_some(), "binding owner not enumerated: {found:?}");
        assert_eq!(owned.unwrap().process_id, binding.process_id);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn binding_owner_needs_omp_comm_and_a_start_before_registration() {
        let dir = tempfile::tempdir().unwrap();
        let mut other = spawn_comm_process(dir.path(), "notomp");
        let mut late = spawn_comm_process(dir.path(), "omp");
        let now = crate::shared::time::now_epoch_f64();
        // Named by a binding but not an omp process.
        let not_omp = owner_binding(other.id(), now);
        // An omp that started after the binding was registered: pid reuse.
        let reused = owner_binding(late.id(), now - 60.0);
        let found = processes_for_instance(
            &unique_name("binding-owner-refused"),
            &[not_omp.process_id.clone(), reused.process_id.clone()],
            &[not_omp, reused],
        );
        for child in [&mut other, &mut late] {
            child.kill().ok();
            child.wait().ok();
        }
        assert!(found.is_empty(), "unproven owners enumerated: {found:?}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn stop_never_releases_while_its_binding_owner_runs() {
        // The plain-omp shape: row pid NULL, one minted binding, and the only
        // live evidence is the omp that minted it, whose environ lacks the id.
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        let mut owner = spawn_comm_process(dir.path(), "omp");
        let name = unique_name("binding-owner-stop");
        let process_id = format!("omp-{}-{}-1", owner.id(), rand_suffix());
        insert_null_pid_row(&db, &name, &process_id);
        let outcome = crate::hooks::common::stop_instance(&db, &name, "test", "stopped");
        let released = db.get_instance_full(&name).unwrap().is_none();
        let owner_alive = owner.try_wait().unwrap().is_none();
        owner.kill().ok();
        owner.wait().ok();
        assert!(
            !(released && owner_alive),
            "row released while its binding owner ran: {outcome:?}"
        );
        // The owner is a proven root and carrier, so the existing rules reap
        // it before the release.
        assert_eq!(outcome, crate::hooks::common::StopOutcome::Stopped);
        assert!(released && !owner_alive);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn bulk_kill_scope_is_captured_before_the_first_signal() {
        let db = test_db();
        let name = unique_name("bulk-pre-signal");
        let process_id = format!("proc-{}", rand_suffix());
        insert_null_pid_row(&db, &name, &process_id);
        let carrier = spawn_detached_named_sleeper(&name, &process_id);
        wait_for_enumerated(&name, std::slice::from_ref(&process_id), carrier);
        let (row, bindings) = db.get_instance_with_bindings(&name).unwrap();
        let capture = capture_reap_carriers(&db, &name, row.as_ref(), &bindings, &[], &[]).unwrap();
        let result = reap_instance_tree_for_excluding_captured(&db, &name, &bindings, &[], capture);
        assert!(result.is_err());
        assert!(!process_gone(carrier));
        unsafe { libc::kill(carrier as libc::pid_t, libc::SIGKILL) };
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn empty_reap_still_releases_a_vanished_instance() {
        let db = test_db();
        let name = unique_name("empty-release");
        insert_null_pid_row(&db, &name, &format!("proc-{}", rand_suffix()));
        let outcome = crate::hooks::common::stop_instance(&db, &name, "test", "stopped");
        assert_eq!(outcome, crate::hooks::common::StopOutcome::Stopped);
        assert!(db.get_instance_full(&name).unwrap().is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn rooted_tree_release_skips_unrootable_identity_carriers() {
        let db = test_db();
        let name = unique_name("rooted-release");
        let token = format!("proc-{}", rand_suffix());
        insert_null_pid_row(&db, &name, &token);
        let mut rooted = spawn_named_sleeper(&name, &token);
        let detached = spawn_detached_named_sleeper(&name, &token);
        let bindings = db.process_binding_ids(&name).unwrap();
        wait_for_enumerated(&name, &bindings, rooted.id());
        wait_for_enumerated(&name, &bindings, detached);
        let result = reap_instance_tree_for_excluding(&db, &name, &bindings, &[]);
        assert!(result.is_ok());
        rooted.wait().ok();
        assert!(!process_gone(detached));
        unsafe { libc::kill(detached as libc::pid_t, libc::SIGKILL) };
    }

    /// Bulk kill against a `start --as` rebind landing between the pre-signal
    /// capture and the release: the capture binds incarnation A, so B's row,
    /// bindings, and live process are not its to touch, and the site reports
    /// the name skipped rather than stopped.
    #[test]
    #[cfg(target_os = "linux")]
    fn stop_with_capture_refuses_release_when_the_incarnation_rebound() {
        let db = test_db();
        let name = unique_name("rebound");
        let token_a = format!("proc-{}", rand_suffix());
        insert_null_pid_row(&db, &name, &token_a);
        // A's own carrier sits in the test's tree, so the capture admits it.
        let mut carrier_a = spawn_named_sleeper(&name, &token_a);
        let (row_a, bindings_a) = db.get_instance_with_bindings(&name).unwrap();
        wait_for_enumerated(&name, &bindings_a, carrier_a.id());
        let capture =
            capture_reap_carriers(&db, &name, row_a.as_ref(), &bindings_a, &[], &[]).unwrap();
        // The kill's group signal takes A down.
        carrier_a.kill().ok();
        carrier_a.wait().ok();

        // `start --as` replaces the row and its bindings with incarnation B.
        let token_b = format!("proc-{}", rand_suffix());
        db.conn()
            .execute(
                "DELETE FROM process_bindings WHERE instance_name = ?1",
                rusqlite::params![name],
            )
            .unwrap();
        db.conn()
            .execute(
                "DELETE FROM instances WHERE name = ?1",
                rusqlite::params![name],
            )
            .unwrap();
        let created_b = crate::shared::time::now_epoch_f64() + 1.0;
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, session_id) \
                 VALUES (?1, 'active', ?2, 'codex', 'sess-rebound')",
                rusqlite::params![name, created_b],
            )
            .unwrap();
        db.set_process_binding(&token_b, "sess-rebound", &name)
            .unwrap();
        let carrier_b = spawn_detached_named_sleeper(&name, &token_b);
        wait_for_enumerated(&name, std::slice::from_ref(&token_b), carrier_b);

        let outcome =
            crate::hooks::common::stop_instance_with_capture(&db, &name, "test", "killed", capture);
        let row = db.get_instance_full(&name).unwrap();
        let b_alive = !process_gone(carrier_b);
        unsafe { libc::kill(carrier_b as libc::pid_t, libc::SIGKILL) };

        assert!(
            row.is_some_and(|row| row.created_at.to_bits() == created_b.to_bits()),
            "B's row must survive a release bound to A's capture"
        );
        assert_eq!(db.process_binding_ids(&name).unwrap(), vec![token_b]);
        assert!(b_alive, "B's process must be unharmed");
        assert!(outcome.is_re_registered(), "{outcome:?}");
        let line = crate::hooks::common::skipped_stop_line(&name);
        assert_eq!(
            line,
            format!("{name} skipped: row re-registered during stop")
        );
        assert!(!line.contains("Stopped"), "{line}");
    }

    /// A `start --as` rebind landing after a bulk kill read the name. The
    /// kill resolved A, row and bindings in one snapshot; the replacement B
    /// was just created, so it has no bindings yet and no carrier of its
    /// own. Nothing but the incarnation guard stands between the stop and
    /// B's live row: B must survive, reported skipped.
    #[test]
    #[cfg(target_os = "linux")]
    fn bulk_stop_does_not_release_a_replacement_row_with_no_bindings() {
        let db = test_db();
        let name = unique_name("rebind-unbound");
        let token_a = format!("proc-{}", rand_suffix());
        insert_null_pid_row(&db, &name, &token_a);

        // The bulk kill's one snapshot: A's row with A's binding epoch.
        let (row_a, bindings_a) = db
            .iter_instances_with_bindings()
            .unwrap()
            .into_iter()
            .find(|(row, _)| row.name == name)
            .expect("A in the snapshot");

        // `start --as` by A's own session: row and bindings are deleted and
        // the row recreated in separate commits, same session, no bindings.
        db.conn()
            .execute(
                "DELETE FROM instances WHERE name = ?1",
                rusqlite::params![name],
            )
            .unwrap();
        db.conn()
            .execute(
                "DELETE FROM process_bindings WHERE instance_name = ?1",
                rusqlite::params![name],
            )
            .unwrap();
        let created_b = crate::shared::time::now_epoch_f64() + 1.0;
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, session_id) \
                 VALUES (?1, 'active', ?2, 'codex', 'sess-carrier')",
                rusqlite::params![name, created_b],
            )
            .unwrap();

        // The pre-signal capture, built from that snapshot alone.
        let capture =
            capture_reap_carriers(&db, &name, Some(&row_a), &bindings_a, &[], &[]).unwrap();
        let outcome =
            crate::hooks::common::stop_instance_with_capture(&db, &name, "test", "killed", capture);

        let row = db.get_instance_full(&name).unwrap();
        assert!(
            row.is_some_and(|row| row.created_at.to_bits() == created_b.to_bits()),
            "the live replacement row must survive the stop: {outcome:?}"
        );
        assert!(outcome.is_re_registered(), "{outcome:?}");
    }

    /// The binding epoch only ever adds refusals to the row identity, and an
    /// emptied set adds none: the same row (created_at bits, session_id,
    /// agent_id) whose every captured binding its own session released — an
    /// Antigravity soft stop does exactly that and keeps the row — is still
    /// the captured incarnation, and the bulk stop releases it. An unbound
    /// replacement is another created_at and is still refused
    /// (`bulk_stop_does_not_release_a_replacement_row_with_no_bindings`).
    #[test]
    #[cfg(target_os = "linux")]
    fn bulk_stop_releases_a_captured_epoch_emptied_under_the_same_row() {
        let db = test_db();
        let name = unique_name("epoch-emptied");
        insert_null_pid_row(&db, &name, &format!("proc-{}", rand_suffix()));
        let (row, bindings) = db.get_instance_with_bindings(&name).unwrap();
        let capture = capture_reap_carriers(&db, &name, row.as_ref(), &bindings, &[], &[]).unwrap();
        db.conn()
            .execute(
                "DELETE FROM process_bindings WHERE instance_name = ?1",
                rusqlite::params![name],
            )
            .unwrap();

        let outcome =
            crate::hooks::common::stop_instance_with_capture(&db, &name, "test", "killed", capture);
        assert_eq!(outcome, crate::hooks::common::StopOutcome::Stopped);
        assert!(
            db.get_instance_full(&name).unwrap().is_none(),
            "row released"
        );
    }

    /// A session that shrank its own epoch to a non-empty subset is still the
    /// captured incarnation too, and releases.
    #[test]
    #[cfg(target_os = "linux")]
    fn bulk_stop_releases_a_captured_epoch_its_session_shrank() {
        let db = test_db();
        let name = unique_name("epoch-shrunk");
        let kept = format!("proc-{}-kept", rand_suffix());
        let released = format!("proc-{}-released", rand_suffix());
        insert_null_pid_row(&db, &name, &kept);
        db.set_process_binding(&released, "sess-carrier", &name)
            .unwrap();
        let (row, bindings) = db.get_instance_with_bindings(&name).unwrap();
        assert_eq!(bindings.len(), 2);
        let capture = capture_reap_carriers(&db, &name, row.as_ref(), &bindings, &[], &[]).unwrap();
        db.conn()
            .execute(
                "DELETE FROM process_bindings WHERE process_id = ?1",
                rusqlite::params![released],
            )
            .unwrap();

        let outcome =
            crate::hooks::common::stop_instance_with_capture(&db, &name, "test", "killed", capture);
        assert_eq!(outcome, crate::hooks::common::StopOutcome::Stopped);
        assert!(
            db.get_instance_full(&name).unwrap().is_none(),
            "row released"
        );
    }

    /// A name-carrying sleeper that leads its own session and process group,
    /// outside the test's tree (the `sh` parent exits). Returns its pid, which
    /// is also its group id.
    #[cfg(target_os = "linux")]
    fn spawn_detached_group_leader(name: &str) -> u32 {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg("setsid sleep 300 >/dev/null 2>&1 & echo $!")
            .env("HCOM_INSTANCE_NAME", name)
            .env_remove("HCOM_PROCESS_ID")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .expect("spawn group leader");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("group leader pid")
    }

    /// The orphan arm captures before its group signal. A row-less orphan
    /// has no row root, so its live group is dropped unproven; once the
    /// signal kills it nothing lives, and the reap must not refuse on a
    /// carrier that existed only in the pre-signal snapshot.
    #[test]
    #[cfg(target_os = "linux")]
    fn unproven_refusal_requires_a_live_carrier_at_decision() {
        let db = test_db();
        let name = unique_name("orphan-group");
        let leader = spawn_detached_group_leader(&name);
        wait_for_enumerated(&name, &[], leader);
        let capture = capture_reap_carriers(&db, &name, None, &[], &[], &[]).unwrap();
        // The orphan arm's group signal.
        unsafe { libc::kill(-(leader as libc::pid_t), libc::SIGKILL) };
        for _ in 0..100 {
            if process_gone(leader) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(process_gone(leader), "group signal must kill the leader");
        let result = reap_instance_tree_for_excluding_captured(&db, &name, &[], &[], capture);
        assert!(result.is_ok(), "{result:?}");
    }

    /// A stale row whose owners are gone while the shared broker still
    /// carries the identity it inherited from the first session. Broker
    /// residue is not a carrier (ffc-vpjpg), so it cannot hold the release.
    #[test]
    #[cfg(target_os = "linux")]
    fn stale_row_releases_when_only_broker_identity_residue_remains() {
        let db = test_db();
        let name = unique_name("broker-residue");
        insert_null_pid_row(&db, &name, &format!("proc-{}", rand_suffix()));
        // The kernel names a process after the file it was exec'd through.
        // bash, unlike multicall coreutils, runs under any name; its builtin
        // `read` blocks on the held pipe without forking.
        let dir = tempfile::tempdir().unwrap();
        let broker_exe = dir.path().join("omp daemon brok");
        let bash = ["/usr/bin/bash", "/bin/bash"]
            .into_iter()
            .find(|path| std::path::Path::new(path).exists())
            .expect("bash binary");
        std::os::unix::fs::symlink(bash, &broker_exe).unwrap();
        let mut broker = std::process::Command::new(&broker_exe)
            .args(["-c", "read -r -t 300 _"])
            .env("HCOM_INSTANCE_NAME", &name)
            .env_remove("HCOM_PROCESS_ID")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn broker stand-in");
        // The broker rule hides it from `processes_for_instance`, so wait for
        // the exec itself: comm and environ switch together.
        let comm_path = format!("/proc/{}/comm", broker.id());
        let mut comm = String::new();
        for _ in 0..100 {
            comm = std::fs::read_to_string(&comm_path).unwrap_or_default();
            if comm.trim_end() == "omp daemon brok" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        let outcome = crate::hooks::common::stop_instance(&db, &name, "test", "stopped");
        let broker_alive = !process_gone(broker.id());
        broker.kill().ok();
        broker.wait().ok();

        assert_eq!(comm.trim_end(), "omp daemon brok");
        assert_eq!(outcome, crate::hooks::common::StopOutcome::Stopped);
        assert!(db.get_instance_full(&name).unwrap().is_none());
        assert!(broker_alive, "the broker is never signalled");
    }

    /// The round seam as a rendezvous: the reaper blocks at `point` until
    /// the returned sender is fired, and the returned receiver yields when
    /// the boundary is reached — so the test's registration/spawn lands at
    /// one exact instruction boundary of the round.
    #[cfg(unix)]
    fn rendezvous_at(
        point: RoundPoint,
    ) -> (
        impl FnMut(RoundPoint) + Send + 'static,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (hit_tx, hit_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let hook = move |p: RoundPoint| {
            if p == point {
                hit_tx.send(()).ok();
                release_rx.recv().ok();
            }
        };
        (hook, hit_rx, release_tx)
    }

    #[cfg(unix)]
    fn wait_for_enumerated(name: &str, binding_ids: &[String], pid: u32) -> Vec<ProcMatch> {
        for _ in 0..50 {
            let found = processes_for_instance(name, binding_ids, &[]);
            if found.iter().any(|m| m.pid == pid) {
                return found;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        processes_for_instance(name, binding_ids, &[])
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
        let found = processes_for_instance(&name, &[], &[]);
        assert!(found.is_empty(), "unexpected matches: {found:?}");
        child.kill().ok();
        child.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn reap_kills_whole_tree_and_reports_survivors_shape() {
        let db = test_db();
        let name = unique_name("reap");
        let mut a = spawn_named_sleeper(&name, "proc-reap");
        let mut b = spawn_named_sleeper(&name, "proc-reap");
        let (pa, pb) = (a.id(), b.id());
        wait_for_enumerated(&name, &[], pa);
        wait_for_enumerated(&name, &[], pb);
        assert!(reap_instance_tree_for(&db, &name, &[]).is_ok());
        // Reap the (zombie) children so bare kill-0 liveness observes them.
        a.wait().ok();
        b.wait().ok();
        assert!(!crate::sys::process::is_alive(pa), "sleeper A reaped");
        assert!(!crate::sys::process::is_alive(pb), "sleeper B reaped");
    }

    #[test]
    #[cfg(unix)]
    fn reap_empty_name_is_noop_ok() {
        let db = test_db();
        assert!(reap_instance_tree_for(&db, &unique_name("empty"), &[]).is_ok());
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn reap_refuses_unanchored_caller_scope() {
        let db = test_db();
        let capture = ReapCapture {
            scope: CarrierTreeScope {
                roots: vec![std::process::id()],
                caller_ancestors: vec![std::process::id()],
                known: HashMap::new(),
                excluded: Vec::new(),
                dropped_live: std::cell::RefCell::new(Vec::new()),
                admitted: std::cell::Cell::new(0),
                owners: Vec::new(),
            },
            carriers: Vec::new(),
            incarnation: None,
        };
        assert!(
            reap_instance_tree_for_excluding_captured(
                &db,
                &unique_name("unanchored"),
                &[],
                &[],
                capture,
            )
            .is_err(),
            "an unproven owner chain must never authorize release",
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn reap_keeps_live_unidentified_carriers_as_unsignalable_survivors() {
        for previously_identified in [false, true] {
            let db = test_db();
            let name = unique_name("missing-identity");
            let mut child = spawn_named_sleeper(&name, "");
            let pid = child.id();
            wait_for_enumerated(&name, &[], pid);
            if !previously_identified {
                MISSING_CARRIER_IDENTITY.with(|missing| missing.set(Some(pid)));
            }
            let capture = capture_reap_carriers(&db, &name, None, &[], &[], &[]).unwrap();
            MISSING_CARRIER_IDENTITY.with(|missing| missing.set(Some(pid)));
            let result = reap_instance_tree_for_excluding_captured(&db, &name, &[], &[], capture);
            MISSING_CARRIER_IDENTITY.with(|missing| missing.set(None));
            let alive = !process_gone(pid);
            child.kill().ok();
            child.wait().ok();
            assert!(alive, "an unidentified carrier must not be signalled");
            assert_eq!(result, Err(ReapError::Survivors(vec![pid])));
        }
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
    fn windows_ancestor_walk_follows_valid_chain() {
        let parents = [(40, 30), (30, 20), (20, 10), (10, 4)];
        let chain = walk_ancestor_links(
            40,
            |pid| parents.iter().find(|(child, _)| *child == pid).map(|p| p.1),
            |pid| Some(pid as u64),
        );
        assert_eq!(chain, vec![40, 30, 20, 10]);
    }

    #[test]
    fn windows_ancestor_walk_truncates_stale_pid_reuse_link() {
        let chain = walk_ancestor_links(
            40,
            |pid| match pid {
                40 => Some(30),
                30 => Some(20),
                _ => None,
            },
            |pid| Some(if pid == 20 { 50 } else { pid as u64 }),
        );
        assert_eq!(chain, vec![40, 30]);
    }

    #[test]
    fn windows_ancestor_walk_truncates_missing_parent() {
        assert_eq!(
            walk_ancestor_links(40, |pid| (pid == 40).then_some(30), |_| Some(10),),
            vec![40, 30]
        );
    }

    #[test]
    fn windows_ancestor_walk_bounds_cycles_and_hops() {
        assert_eq!(
            walk_ancestor_links(
                10,
                |pid| Some(if pid == 10 { 11 } else { 10 }),
                |_| Some(10),
            ),
            vec![10, 11]
        );
        let chain = walk_ancestor_links(10, |pid| Some(pid + 1), |_| Some(10));
        assert_eq!(chain.len(), 1024);
        assert_eq!(chain[0], 10);
        assert_eq!(chain[1023], 1033);
    }

    #[test]
    fn windows_ancestor_kind_uses_executable_name() {
        assert_eq!(
            ancestor_process_kind_from_name(Some("OMP.EXE")),
            AncestorProcess::Omp
        );
        assert_eq!(
            ancestor_process_kind_from_name(Some("omp.exe")),
            AncestorProcess::Omp
        );
        assert_eq!(
            ancestor_process_kind_from_name(Some("cmd.exe")),
            AncestorProcess::Other
        );
        assert_eq!(
            ancestor_process_kind_from_name(None),
            AncestorProcess::Unknown
        );
    }

    #[test]
    fn mac_ancestor_walk_rejects_reused_parent_by_microsecond_starttime() {
        let chain = walk_ancestor_links(
            40,
            |pid| match pid {
                40 => Some(30),
                30 => Some(20),
                _ => None,
            },
            |pid| match pid {
                40 => mac_start_micros(100, 200),
                30 => mac_start_micros(100, 100),
                20 => mac_start_micros(101, 0),
                _ => None,
            },
        );
        assert_eq!(chain, vec![40, 30]);
    }

    #[test]
    fn mac_start_micros_rejects_invalid_or_overflowed_timeval() {
        assert_eq!(mac_start_micros(1, 999_999), Some(1_999_999));
        assert_eq!(mac_start_micros(2, 0), Some(2_000_000));
        assert_eq!(mac_start_micros(1, 1_000_000), None);
        assert_eq!(mac_start_micros(u64::MAX, 1), None);
    }

    #[test]
    fn mac_ancestor_kind_requires_exact_trimmed_comm() {
        assert_eq!(
            ancestor_process_kind_from_comm(Some(b" omp \0ignored")),
            AncestorProcess::Omp
        );
        assert_eq!(
            ancestor_process_kind_from_comm(Some(b"OMP\0")),
            AncestorProcess::Other
        );
        assert_eq!(
            ancestor_process_kind_from_comm(Some(b"bash\0")),
            AncestorProcess::Other
        );
        assert_eq!(
            ancestor_process_kind_from_comm(None),
            AncestorProcess::Unknown
        );
    }

    #[test]
    #[cfg(unix)]
    fn reap_excluding_spares_excluded_carrier() {
        let db = test_db();
        let name = unique_name("exclude");
        let mut spared = spawn_named_sleeper(&name, "proc-exclude-spared");
        let mut reaped = spawn_named_sleeper(&name, "proc-exclude-reaped");
        let (spared_pid, reaped_pid) = (spared.id(), reaped.id());
        wait_for_enumerated(&name, &[], spared_pid);
        wait_for_enumerated(&name, &[], reaped_pid);
        assert!(
            reap_instance_tree_for_excluding(&db, &name, &[], std::slice::from_ref(&spared_pid))
                .is_ok(),
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

    /// A file-backed test DB two connections can share: for tests that write
    /// bindings from the main thread while a reap thread reads them on its
    /// own connection.
    #[cfg(unix)]
    fn file_test_db() -> (tempfile::TempDir, crate::db::HcomDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();
        (dir, db)
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
        let mut sleeper = spawn_named_sleeper(&name, &format!("proc-old-{}", rand_suffix()));
        let pid = sleeper.id();
        wait_for_enumerated(&name, &[], pid);
        let start = processes_for_instance(&name, &[], &[])
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
        let mut sleeper = spawn_named_sleeper(&name, &format!("proc-old-{}", rand_suffix()));
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
            .finalize_instance_stop(
                "stale-row",
                created,
                None,
                None,
                None,
                &data,
                Some("proc-old"),
                None,
            )
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
            .finalize_instance_stop(
                "cur-row",
                created,
                None,
                None,
                None,
                &data,
                Some("proc-current"),
                None,
            )
            .unwrap();
        assert!(won, "current process_id releases the row");
        assert!(db.get_instance_full("cur-row").unwrap().is_none());
    }

    fn dead_pid() -> i64 {
        #[cfg(unix)]
        let mut child = std::process::Command::new("true").spawn().unwrap();
        #[cfg(windows)]
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .unwrap();
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

    /// A rebind landing between the sweep's one-snapshot read and its
    /// release: a new process binds under the same row, whose identity
    /// (created_at, session, agent) is unchanged, so only the captured
    /// binding epoch shows the newer registration. The row and every
    /// binding survive, and the sweep writes no stopped record.
    #[test]
    #[cfg(unix)]
    fn sweep_spares_a_rebind_landing_after_its_read() {
        let db = test_db();
        let name = unique_name("rebind");
        insert_row(&db, &name, "active", Some(dead_pid()));
        // Ids derive from the unique row name so no sibling test's live
        // carrier can share them (the hook is a plain fn and cannot capture).
        let old_id = format!("proc-old-{name}");
        db.set_process_binding(&old_id, "sess-old", &name).unwrap();
        fn rebind(db: &HcomDb, name: &str) {
            db.set_process_binding(&format!("proc-new-{name}"), "sess-new", name)
                .unwrap();
        }
        SWEEP_RELEASE_GAP_HOOK.with(|hook| hook.set(Some(rebind)));
        let swept = sweep_vanished_instances(&db);
        SWEEP_RELEASE_GAP_HOOK.with(|hook| hook.set(None));

        assert!(!swept.contains(&name), "{swept:?}");
        assert!(
            db.get_instance_full(&name).unwrap().is_some(),
            "the rebound row survives"
        );
        let mut bindings = db.process_binding_ids(&name).unwrap();
        bindings.sort();
        assert_eq!(bindings, vec![format!("proc-new-{name}"), old_id]);
        let stopped: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = ?1",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stopped, 0, "no stopped record for the rebound row");
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

    /// A valo-shaped row: no recorded pid, a dead minted-omp binding plus a
    /// launcher UUID binding, and no process carrying an HCOM marker, so every
    /// /proc signal says gone. Its `plugin` endpoint is `port`.
    #[cfg(unix)]
    fn insert_valo_row(db: &crate::db::HcomDb, name: &str, session_id: Option<&str>, port: u16) {
        let dead = dead_pid();
        insert_row(db, name, "active", None);
        db.conn()
            .execute(
                "UPDATE instances SET session_id = ?1 WHERE name = ?2",
                rusqlite::params![session_id, name],
            )
            .unwrap();
        db.set_process_binding(&format!("omp-{}-a4a1-1174", dead), "sess-a", name)
            .unwrap();
        db.set_process_binding("3f1c8a52-0b7d-4e2a-9c31-6d0f5b7a1e42", "sess-b", name)
            .unwrap();
        age_row(db, name);
        db.upsert_notify_endpoint(name, "plugin", port).unwrap();
    }

    #[cfg(unix)]
    fn life_events(db: &crate::db::HcomDb, name: &str) -> i64 {
        db.conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = ?1",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// Open a transcript named the way omp names it (`<ts>_<session>.jsonl`)
    /// in a fresh directory; the process holds it while the handle lives.
    #[cfg(unix)]
    fn open_transcript(session_id: &str) -> (tempfile::TempDir, std::fs::File) {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(
            dir.path()
                .join(format!("2026-09-25T16-03-17-000Z_{session_id}.jsonl")),
        )
        .unwrap();
        (dir, file)
    }

    /// The valo 16:03 row: every /proc signal says gone, but the process
    /// serving its endpoint has the row's own session transcript open. That
    /// is proof the listener is this seat: the row survives with its
    /// bindings, and no `stopped` life event is written.
    #[test]
    #[cfg(target_os = "linux")]
    fn sweep_holds_a_row_whose_endpoint_owner_has_its_session_open() {
        let db = test_db();
        let name = unique_name("valo");
        let session_id = format!("{name}-session");
        let _transcript = open_transcript(&session_id);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        insert_valo_row(
            &db,
            &name,
            Some(&session_id),
            listener.local_addr().unwrap().port(),
        );

        let swept = sweep_vanished_instances(&db);

        assert!(!swept.contains(&name), "{swept:?}");
        assert!(
            db.get_instance_full(&name).unwrap().is_some(),
            "the seat's own endpoint holds the row"
        );
        assert_eq!(
            db.process_binding_ids(&name).unwrap().len(),
            2,
            "bindings survive the hold"
        );
        assert_eq!(
            life_events(&db, &name),
            0,
            "no stopped record for a held row"
        );
    }

    /// The port now answers for a process holding ANOTHER session's
    /// transcript: the accept proves somebody owns the port, not that this
    /// seat still does, so the row is released.
    #[test]
    #[cfg(target_os = "linux")]
    fn sweep_releases_a_row_whose_endpoint_owner_holds_another_session() {
        let db = test_db();
        let name = unique_name("valo-other");
        let _other = open_transcript(&format!("{name}-other-session"));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        insert_valo_row(
            &db,
            &name,
            Some(&format!("{name}-session")),
            listener.local_addr().unwrap().port(),
        );

        let swept = sweep_vanished_instances(&db);

        assert!(swept.contains(&name), "{swept:?}");
        assert!(db.get_instance_full(&name).unwrap().is_none());
    }

    /// A session-less row whose port was taken by an unrelated local service
    /// (a child `sleep` that inherited the listener, nothing omp or hcom
    /// about it) is released: an unrelated owner is no evidence.
    #[test]
    #[cfg(target_os = "linux")]
    fn sweep_releases_a_row_whose_port_an_unrelated_process_holds() {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;

        let db = test_db();
        let name = unique_name("valo-reused");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let fd = listener.as_raw_fd();
        let mut command = std::process::Command::new("sleep");
        command.arg("300");
        // SAFETY: fcntl is async-signal-safe. It clears close-on-exec on the
        // listener in the forked child only, so `sleep` inherits the socket.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut holder = command.spawn().unwrap();
        drop(listener);
        insert_valo_row(&db, &name, None, port);

        let swept = sweep_vanished_instances(&db);
        holder.kill().ok();
        holder.wait().ok();

        assert!(swept.contains(&name), "{swept:?}");
        assert!(db.get_instance_full(&name).unwrap().is_none());
    }

    /// A listener that accepts but whose owner /proc cannot name (here the
    /// socket rides in an unreceived SCM_RIGHTS message, as unreadable as one
    /// held by another user's process): ownership is undeterminable, so the
    /// accept alone holds the row.
    #[test]
    #[cfg(target_os = "linux")]
    fn sweep_holds_a_row_whose_accepting_listener_has_no_findable_owner() {
        use std::os::fd::AsRawFd;

        let db = test_db();
        let name = unique_name("valo-unknown");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd_len = std::mem::size_of::<std::os::fd::RawFd>() as u32;
        // SAFETY: every pointer handed to sendmsg points into a buffer that
        // outlives the call; the u64 control buffer is aligned for cmsghdr
        // and larger than CMSG_SPACE for one fd.
        unsafe {
            let mut byte = [0u8; 1];
            let mut iov = libc::iovec {
                iov_base: byte.as_mut_ptr().cast(),
                iov_len: byte.len(),
            };
            let mut control = [0u64; 8];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(fd_len) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fd_len) as _;
            std::ptr::write_unaligned(
                libc::CMSG_DATA(cmsg).cast::<std::os::fd::RawFd>(),
                listener.as_raw_fd(),
            );
            assert_eq!(libc::sendmsg(tx.as_raw_fd(), &msg, 0), 1);
        }
        drop(listener);
        insert_valo_row(&db, &name, Some(&format!("{name}-session")), port);

        let swept = sweep_vanished_instances(&db);
        drop((tx, rx));

        assert!(!swept.contains(&name), "{swept:?}");
        assert!(db.get_instance_full(&name).unwrap().is_some());
        assert_eq!(life_events(&db, &name), 0);
    }

    /// The hold is liveness, not a blanket exemption: once the seat's
    /// endpoint is closed the next sweep releases the row.
    #[test]
    #[cfg(unix)]
    fn sweep_releases_a_row_once_its_notify_endpoint_is_closed() {
        let db = test_db();
        let name = unique_name("valo-gone");
        let session_id = format!("{name}-session");
        let _transcript = open_transcript(&session_id);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        insert_valo_row(
            &db,
            &name,
            Some(&session_id),
            listener.local_addr().unwrap().port(),
        );
        assert!(!sweep_vanished_instances(&db).contains(&name));

        drop(listener);
        let swept = sweep_vanished_instances(&db);

        assert!(swept.contains(&name), "a closed endpoint releases the row");
        assert!(db.get_instance_full(&name).unwrap().is_none());
    }

    /// Push a row's `last_seen` outside the sweep's fresh grace.
    fn age_row(db: &crate::db::HcomDb, name: &str) {
        let stale = crate::shared::time::now_epoch_f64() as i64 - SWEEP_FRESH_GRACE_SECS - 60;
        db.conn()
            .execute(
                "UPDATE instances SET last_seen = ?1 WHERE name = ?2",
                rusqlite::params![stale, name],
            )
            .unwrap();
    }

    /// Off Linux the sweep sees no carriers, so a dead pid never releases an
    /// inactive row (a soft-stop resume handle). The active row with the same
    /// dead pid is released, which proves the pid reads as dead here.
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn sweep_keeps_dead_inactive_row_off_linux() {
        let db = test_db();
        let pid = dead_pid();
        insert_row(&db, "inactive-dead-row", "inactive", Some(pid));
        insert_row(&db, "active-dead-row", "active", Some(pid));
        age_row(&db, "inactive-dead-row");
        age_row(&db, "active-dead-row");
        let swept = sweep_vanished_instances(&db);
        assert!(
            swept.contains(&"active-dead-row".to_string()),
            "active row with the dead pid kept: {swept:?}"
        );
        assert!(
            !swept.contains(&"inactive-dead-row".to_string()),
            "inactive row swept off Linux: {swept:?}"
        );
        let row = db
            .get_instance_full("inactive-dead-row")
            .unwrap()
            .expect("inactive row released off Linux");
        assert_eq!(row.status, crate::shared::ST_INACTIVE);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sweep_releases_dead_inactive_row() {
        let db = test_db();
        // Soft-stopped row whose process is provably gone: dead recorded
        // pid, UUID binding, no carrier, seen long ago → released.
        let name = unique_name("inactdead");
        insert_row(&db, &name, "inactive", Some(dead_pid()));
        let binding = format!("proc-inactdead-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        age_row(&db, &name);
        let swept = sweep_vanished_instances(&db);
        assert!(swept.contains(&name), "dead inactive row kept: {swept:?}");
        assert!(db.get_instance_full(&name).unwrap().is_none());
        let event: String = db
            .conn()
            .query_row(
                "SELECT data FROM events WHERE type='life' AND instance=?1 ORDER BY id DESC LIMIT 1",
                [&name],
                |row| row.get(0),
            )
            .unwrap();
        let event: serde_json::Value = serde_json::from_str(&event).unwrap();
        assert_eq!(
            event.get("action").and_then(|v| v.as_str()),
            Some("stopped")
        );
        assert_eq!(event.get("by").and_then(|v| v.as_str()), Some("daemon"));
        assert_eq!(
            event.get("reason").and_then(|v| v.as_str()),
            Some("vanished")
        );
        assert!(
            event.get("snapshot").is_some_and(|s| s.is_object()),
            "stopped event carries a snapshot: {event}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn sweep_holds_inactive_row_with_live_carrier() {
        let db = test_db();
        // Dead recorded pid, but a live process still carries the name and
        // the bound process id: the harness is around; not vanished.
        let name = unique_name("inactcarrier");
        insert_row(&db, &name, "inactive", Some(dead_pid()));
        let binding = format!("proc-inactcarrier-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        age_row(&db, &name);
        let mut sleeper = spawn_named_sleeper(&name, &binding);
        wait_for_enumerated(&name, &[], sleeper.id());
        let swept = sweep_vanished_instances(&db);
        assert!(
            !swept.iter().any(|n| n == &name),
            "carrier-held inactive row swept: {swept:?}"
        );
        assert!(db.get_instance_full(&name).unwrap().is_some());
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    #[test]
    #[cfg(unix)]
    fn sweep_holds_inactive_row_with_live_pid() {
        let db = test_db();
        // Soft-stop with a kept binding and a live recorded pid: the
        // /restart shape, where the same pid comes back into the session.
        let name = unique_name("inactlive");
        insert_row(&db, &name, "inactive", Some(std::process::id() as i64));
        let binding = format!("proc-inactlive-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        age_row(&db, &name);
        let swept = sweep_vanished_instances(&db);
        assert!(
            !swept.iter().any(|n| n == &name),
            "live-pid inactive row swept: {swept:?}"
        );
        assert!(db.get_instance_full(&name).unwrap().is_some());
    }

    #[test]
    #[cfg(unix)]
    fn sweep_holds_inactive_row_without_pid_evidence() {
        let db = test_db();
        // No recorded pid and only a UUID-style binding: nothing proves
        // death, so the row is held.
        let name = unique_name("inactnopid");
        insert_row(&db, &name, "inactive", None);
        let binding = format!("proc-inactnopid-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        age_row(&db, &name);
        let swept = sweep_vanished_instances(&db);
        assert!(
            !swept.iter().any(|n| n == &name),
            "evidence-free inactive row swept: {swept:?}"
        );
        assert!(db.get_instance_full(&name).unwrap().is_some());
    }

    #[test]
    #[cfg(unix)]
    fn sweep_keeps_inactive_row_inside_fresh_grace() {
        let db = test_db();
        let name = unique_name("inactfresh");
        insert_row(&db, &name, "inactive", Some(dead_pid()));
        let now = crate::shared::time::now_epoch_f64() as i64;
        db.conn()
            .execute(
                "UPDATE instances SET last_seen = ?1 WHERE name = ?2",
                rusqlite::params![now, name],
            )
            .unwrap();
        let swept = sweep_vanished_instances(&db);
        assert!(
            !swept.iter().any(|n| n == &name),
            "fresh inactive row swept: {swept:?}"
        );
        assert!(db.get_instance_full(&name).unwrap().is_some());
    }

    #[test]
    #[cfg(unix)]
    fn sweep_skips_inactive_remote_mirror() {
        let db = test_db();
        // A remote mirror's pid means nothing on this host: never swept,
        // inactive or not.
        let name = unique_name("inactmirror");
        insert_row(&db, &name, "inactive", Some(dead_pid()));
        db.conn()
            .execute(
                "UPDATE instances SET origin_device_id = 'remote-dev' WHERE name = ?1",
                [&name],
            )
            .unwrap();
        age_row(&db, &name);
        let swept = sweep_vanished_instances(&db);
        assert!(
            !swept.iter().any(|n| n == &name),
            "remote mirror swept: {swept:?}"
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
        let mut sleeper = spawn_named_sleeper(&name, &format!("proc-old-{}", rand_suffix()));
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

    /// Reap scope (kill arm): a name-only carrier that appears after the
    /// reap began is a late fork of the dying tree, not a new registration —
    /// it carries no binding id of its own (empty process id), so it is in
    /// scope: signalled in the KILL round, and while alive a survivor
    /// (fail-closed). The initial carrier is SIGSTOPped, so the reap burns
    /// its full TERM wait before the KILL re-enumeration and the late fork
    /// lands squarely inside that round: the kill is the scope rule's doing,
    /// not a missed enumeration.
    #[test]
    #[cfg(unix)]
    fn reap_scope_kills_late_name_only_fork() {
        let name = unique_name("scopefork");
        let binding_ids = vec![format!("proc-scope-{}", rand_suffix())];
        let mut first = spawn_named_sleeper(&name, "proc-scope-old");
        let first_pid = first.id();
        wait_for_enumerated(&name, &[], first_pid);
        unsafe { libc::kill(first_pid as libc::pid_t, libc::SIGSTOP) };

        let (tx, rx) = std::sync::mpsc::channel();
        let reap_name = name.clone();
        let reap_bindings = binding_ids.clone();
        let reaper = std::thread::spawn(move || {
            let db = test_db();
            tx.send(()).ok();
            reap_instance_tree_for_excluding(&db, &reap_name, &reap_bindings, &[])
        });
        rx.recv().unwrap();
        // Late and name-only: no epoch token of its own (empty process id)
        // — the mid-reap fork shape of the dying tree.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut late = spawn_named_sleeper(&name, "");
        let late_pid = late.id();

        let result = reaper.join().expect("reap thread");
        first.wait().ok();
        late.wait().ok();
        assert!(
            result.is_ok(),
            "the late fork dies within the signal budget: {result:?}"
        );
        assert!(
            !crate::sys::process::is_alive(first_pid),
            "in-scope initial carrier is reaped"
        );
        assert!(
            !crate::sys::process::is_alive(late_pid),
            "name-only late fork is signalled despite starting after the reap"
        );
    }

    /// Reap scope (spare arm): a carrier that appears after the reap began
    /// with a non-empty `HCOM_PROCESS_ID` REGISTERED mid-sequence — a fresh
    /// binding of a newer epoch, outside the call-start ids — is never
    /// signalled, never a survivor. Same SIGSTOP choreography as the kill
    /// arm: the spare is the scope rule's doing, not a missed enumeration.
    #[test]
    #[cfg(unix)]
    fn reap_scope_spares_late_new_epoch_carrier() {
        let (_dir, db) = file_test_db();
        let db_path = db.path().to_path_buf();
        let name = unique_name("scopespare");
        let binding_ids = vec![format!("proc-bound-{}", rand_suffix())];
        let mut first = spawn_named_sleeper(&name, "proc-scope-old");
        let first_pid = first.id();
        wait_for_enumerated(&name, &[], first_pid);
        unsafe { libc::kill(first_pid as libc::pid_t, libc::SIGSTOP) };

        let fresh_binding = format!("proc-fresh-{}", rand_suffix());
        let (tx, rx) = std::sync::mpsc::channel();
        let reap_name = name.clone();
        let reap_bindings = binding_ids.clone();
        let reap_db_path = db_path.clone();
        let reaper = std::thread::spawn(move || {
            let db = crate::db::HcomDb::open_raw(&reap_db_path).unwrap();
            tx.send(()).ok();
            reap_instance_tree_for_excluding(&db, &reap_name, &reap_bindings, &[])
        });
        rx.recv().unwrap();
        // Late with a fresh binding id outside the call-start set — the
        // binding is REGISTERED mid-sequence (the newer-epoch evidence).
        std::thread::sleep(std::time::Duration::from_millis(200));
        db.set_process_binding(&fresh_binding, "sess", &name)
            .unwrap();
        let mut late = spawn_named_sleeper(&name, &fresh_binding);
        let late_pid = late.id();
        // Exec barrier: pin the late carrier as an ENUMERATED carrier (a
        // pre-exec child carries no identity) — the spare must be the scope
        // rule's doing, never a missed enumeration.
        wait_for_enumerated(&name, &[], late_pid);

        let result = reaper.join().expect("reap thread");
        assert!(
            result.is_ok(),
            "a newer-epoch carrier is never a survivor: {result:?}"
        );
        first.wait().ok();
        assert!(
            !crate::sys::process::is_alive(first_pid),
            "in-scope initial carrier is reaped"
        );
        // try_wait, not is_alive: a SIGKILLed-but-unreaped child is a zombie
        // and reads alive — None means the carrier never got signalled.
        let late_status = late.try_wait().unwrap();
        assert!(
            late_status.is_none(),
            "newer-epoch carrier is spared (pid {late_pid} was signalled: \
             {late_status:?})"
        );
        late.kill().ok();
        late.wait().ok();
    }

    /// Reap scope (epoch arm): a carrier that appears after the reap began
    /// but carries one of the ORIGINAL binding ids — the genuine mid-reap
    /// fork shape, whose inherited env keeps the call-start binding id — is
    /// signalled in the KILL round: same binding epoch as the dying tree.
    /// Same SIGSTOP timing as the kill arm: the catch is the scope rule's
    /// doing, not a missed enumeration.
    #[test]
    #[cfg(unix)]
    fn reap_scope_kills_late_binding_carrier() {
        let name = unique_name("scopebind");
        let binding = format!("proc-scope-{}", rand_suffix());
        let mut first = spawn_named_sleeper(&name, "proc-scope-old");
        let first_pid = first.id();
        wait_for_enumerated(&name, &[], first_pid);
        unsafe { libc::kill(first_pid as libc::pid_t, libc::SIGSTOP) };

        let (tx, rx) = std::sync::mpsc::channel();
        let reap_name = name.clone();
        let reap_binding = binding.clone();
        let reaper = std::thread::spawn(move || {
            let db = test_db();
            tx.send(()).ok();
            reap_instance_tree_for_excluding(
                &db,
                &reap_name,
                std::slice::from_ref(&reap_binding),
                &[],
            )
        });
        rx.recv().unwrap();
        // Late fork shape: no name, only the call-start binding id.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut late = spawn_pid_only_sleeper(&binding);
        let late_pid = late.id();
        wait_for_enumerated(&name, std::slice::from_ref(&binding), late_pid);

        let result = reaper.join().expect("reap thread");
        assert!(
            result.is_ok(),
            "binding-id fork is caught, never a survivor: {result:?}"
        );
        first.wait().ok();
        late.wait().ok();
        assert!(
            !crate::sys::process::is_alive(first_pid),
            "initial carrier is reaped"
        );
        assert!(
            !crate::sys::process::is_alive(late_pid),
            "late binding-id carrier is signalled despite starting after the reap"
        );
    }

    #[test]
    #[cfg(unix)]
    fn reap_scope_boundary_empty_process_id_is_in_scope() {
        // The scope boundary is the fresh binding registry, not the clock: a
        // late carrier with an empty process id is in scope (the name-only
        // late fork — signalled, and while alive a survivor), and only a
        // non-empty process id REGISTERED in the fresh epoch reads as a
        // newer epoch and is spared. start_epoch deliberately never decides.
        let fresh = vec!["proc-fresh-2".to_string()];
        let carrier = |pid: u32, process_id: &str| ProcMatch {
            pid,
            process_id: process_id.to_string(),
            start_epoch: 0.0,
        };
        let mut spared = HashSet::new();
        // Name-only (empty process id): in scope, registry or not.
        assert!(carrier_in_reap_scope(
            &carrier(424242, ""),
            &fresh,
            &mut spared
        ));
        assert!(carrier_in_reap_scope(
            &carrier(424243, ""),
            &[],
            &mut spared
        ));
        // Fresh registered binding id (newer binding epoch): spared.
        assert!(!carrier_in_reap_scope(
            &carrier(424244, "proc-fresh-2"),
            &fresh,
            &mut spared
        ));
        // Call-start binding id (the dying epoch's own token, subtracted
        // from the fresh set by construction): in scope.
        assert!(carrier_in_reap_scope(
            &carrier(424245, "proc-call-start"),
            &fresh,
            &mut spared
        ));
        // Stale non-empty id claimed by no binding at all: in scope — name
        // matching makes the carrier part of the old instance.
        assert!(carrier_in_reap_scope(
            &carrier(424246, "proc-stale"),
            &fresh,
            &mut spared
        ));
    }

    #[test]
    #[cfg(unix)]
    fn reap_scope_spared_carrier_stays_spared_across_rounds() {
        // The spare decision is captured once per carrier: a carrier spared
        // in one round is never reclassified into scope by a later round
        // (e.g. its fresh binding released again before verification).
        let carrier = ProcMatch {
            pid: 425001,
            process_id: "proc-fresh-9".to_string(),
            start_epoch: 0.0,
        };
        let mut spared = HashSet::new();
        let round_one = vec!["proc-fresh-9".to_string()];
        assert!(
            !carrier_in_reap_scope(&carrier, &round_one, &mut spared),
            "the registry round spares the fresh registration"
        );
        assert!(
            !carrier_in_reap_scope(&carrier, &[], &mut spared),
            "a spared carrier stays spared even after its binding vanishes"
        );
        assert!(!carrier_in_reap_scope(
            &carrier,
            &["proc-other".to_string()],
            &mut spared
        ));
    }

    /// Reap scope (stale-id arm): a late child carrying a STALE non-empty
    /// `HCOM_PROCESS_ID` — one no current binding claims, inherited from an
    /// older era — is name-matched to the dying instance and must be killed,
    /// not spared. The pre-v3 rule spared every non-empty id outside the
    /// call-start set, which let such a child outlive its instance's
    /// teardown.
    #[test]
    #[cfg(unix)]
    fn reap_scope_kills_late_stale_unbound_carrier() {
        let name = unique_name("scopestale");
        let binding_ids = vec![format!("proc-bound-{}", rand_suffix())];
        let mut first = spawn_named_sleeper(&name, "proc-scope-old");
        let first_pid = first.id();
        wait_for_enumerated(&name, &[], first_pid);
        unsafe { libc::kill(first_pid as libc::pid_t, libc::SIGSTOP) };

        let (tx, rx) = std::sync::mpsc::channel();
        let reap_name = name.clone();
        let reap_bindings = binding_ids.clone();
        let reaper = std::thread::spawn(move || {
            let db = test_db();
            tx.send(()).ok();
            reap_instance_tree_for_excluding(&db, &reap_name, &reap_bindings, &[])
        });
        rx.recv().unwrap();
        // Late child of the old instance: carries the name plus a stale id
        // that is in NO binding registry.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut late = spawn_named_sleeper(&name, &format!("proc-stale-{}", rand_suffix()));
        let late_pid = late.id();

        let result = reaper.join().expect("reap thread");
        first.wait().ok();
        late.wait().ok();
        assert!(
            result.is_ok(),
            "a stale-id late carrier dies within the signal budget: {result:?}"
        );
        assert!(
            !crate::sys::process::is_alive(first_pid),
            "in-scope initial carrier is reaped"
        );
        assert!(
            !crate::sys::process::is_alive(late_pid),
            "stale-id late carrier is signalled despite its non-empty process id"
        );
    }

    /// Reap scope (round-ordering regression — the read-after-capture rule):
    /// a fresh registration committed and its process spawned at the
    /// boundary between the KILL round's carrier capture and its registry
    /// read — the exact interleaving the old read-before-capture order could
    /// not survive: binding committed after the read, process spawned before
    /// the capture, so the fresh id was missing from the captured id set and
    /// the brand-new process was classified stale (an unclaimed id of the
    /// dying epoch) and SIGKILLed. Capture first and the fresh process is
    /// spawned AFTER it — never classified, never signalled (alive after the
    /// reap), never a survivor (the reap is Ok while it lives). The pair
    /// lands register-then-spawn, the launcher's pre-spawn registration
    /// order (`db.set_process_binding` runs before the tool spawn,
    /// launcher.rs:2005) — which is exactly why a registry read taken after
    /// the capture must include any captured process's binding.
    #[test]
    #[cfg(unix)]
    fn reap_scope_spares_fresh_launch_landing_after_round_capture() {
        let (_dir, db) = file_test_db();
        let db_path = db.path().to_path_buf();
        let name = unique_name("scopeorder");
        let binding_ids = vec![format!("proc-bound-{}", rand_suffix())];
        let mut first = spawn_named_sleeper(&name, "proc-scope-old");
        let first_pid = first.id();
        wait_for_enumerated(&name, &[], first_pid);
        unsafe { libc::kill(first_pid as libc::pid_t, libc::SIGSTOP) };

        let fresh_binding = format!("proc-fresh-{}", rand_suffix());
        let (hook, hit, release) = rendezvous_at(RoundPoint::Captured);
        let reap_name = name.clone();
        let reap_bindings = binding_ids.clone();
        let reaper = std::thread::spawn(move || {
            let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
            arm_round_seam(hook);
            reap_instance_tree_for_excluding(&db, &reap_name, &reap_bindings, &[])
        });
        // Past the full TERM wait (`first` is SIGSTOPped and cannot exit):
        // the KILL round has captured its carrier set.
        hit.recv_timeout(std::time::Duration::from_secs(30))
            .expect("KILL round reaches its capture boundary");
        // The concurrent launch at that boundary: register the fresh
        // binding, THEN spawn its process — both after the capture, before
        // the round's registry read.
        db.set_process_binding(&fresh_binding, "sess", &name)
            .unwrap();
        let mut late = spawn_named_sleeper(&name, &fresh_binding);
        let late_pid = late.id();
        // Let the child exec before releasing the round — a pre-exec child
        // carries no identity yet, so the round's capture only sees it once
        // it enumerates as a carrier.
        wait_for_enumerated(&name, &[], late_pid);
        release.send(()).ok();

        let result = reaper.join().expect("reap thread");
        first.wait().ok();
        assert!(
            result.is_ok(),
            "the fresh process is never a survivor: {result:?}"
        );
        assert!(
            !crate::sys::process::is_alive(first_pid),
            "in-scope initial carrier is reaped"
        );
        // try_wait, not is_alive: a SIGKILLed-but-unreaped child is a zombie
        // and reads alive — None means the fresh process never got signalled.
        let late_status = late.try_wait().unwrap();
        assert!(
            late_status.is_none(),
            "a fresh process spawned after the round's capture is spared \
             end-to-end (pid {late_pid} was signalled: {late_status:?})"
        );
        late.kill().ok();
        late.wait().ok();
    }

    /// Foreign-owner guard (KILL round): a carrier first seen by the KILL
    /// round's own capture never went through the pre-signal guard, so it is
    /// re-proved there — the last point before a KILL goes out. One carrying
    /// another live row's process id is not signalled: it survives, and the
    /// release fails closed on it as a survivor, which is the only honest
    /// outcome while a process this teardown may not touch is still alive.
    #[test]
    #[cfg(target_os = "linux")]
    fn kill_round_leaves_a_late_carrier_another_live_row_holds() {
        let (_dir, db) = file_test_db();
        let db_path = db.path().to_path_buf();
        let name = unique_name("lateforeign");
        let other = unique_name("otherlive");
        let binding_ids = vec![format!("proc-bound-{}", rand_suffix())];
        let foreign_binding = format!("proc-foreign-{}", rand_suffix());
        // The other holder: a live row of its own, holding the id the late
        // carrier carries.
        insert_null_pid_row(&db, &other, &foreign_binding);
        let mut first = spawn_named_sleeper(&name, "proc-scope-old");
        let first_pid = first.id();
        wait_for_enumerated(&name, &[], first_pid);
        unsafe { libc::kill(first_pid as libc::pid_t, libc::SIGSTOP) };

        let (hook, hit, release) = rendezvous_at(RoundPoint::Captured);
        let reap_name = name.clone();
        let reap_bindings = binding_ids.clone();
        let reaper = std::thread::spawn(move || {
            let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
            arm_round_seam(hook);
            reap_instance_tree_for_excluding(&db, &reap_name, &reap_bindings, &[])
        });
        // Past the full TERM wait (`first` is SIGSTOPped and cannot exit):
        // the KILL round has captured its carrier set, and this late carrier
        // is not in it.
        hit.recv_timeout(std::time::Duration::from_secs(30))
            .expect("KILL round reaches its capture boundary");
        let mut late = spawn_named_sleeper(&name, &foreign_binding);
        let late_pid = late.id();
        // Let the child exec before releasing the round: a pre-exec child
        // carries no identity yet, so the round only sees it as a carrier.
        wait_for_enumerated(&name, &[], late_pid);
        release.send(()).ok();

        let result = reaper.join().expect("reap thread");
        first.wait().ok();
        assert!(
            !crate::sys::process::is_alive(first_pid),
            "in-scope initial carrier is reaped"
        );
        // try_wait, not is_alive: a SIGKILLed-but-unreaped child is a zombie
        // and reads alive — None means the late carrier was never signalled.
        let late_status = late.try_wait().unwrap();
        assert!(
            late_status.is_none(),
            "a late carrier another live row holds must not be signalled \
             (pid {late_pid} was signalled: {late_status:?})"
        );
        match result {
            Err(ReapError::Survivors(survivors)) => assert!(
                survivors.contains(&late_pid),
                "the spared carrier is the one that fails the release closed: {survivors:?}"
            ),
            other => panic!("the release must fail closed while it lives: {other:?}"),
        }
        late.kill().ok();
        late.wait().ok();
    }

    /// Reap scope (pre-signal revalidation): a binding landing between the
    /// KILL round's classification and its signal round — the residual
    /// first-hook spawn-to-bind shape — is caught by the pre-signal registry
    /// re-read. The late carrier is captured and classified IN SCOPE against
    /// the earlier read (its id is registered nowhere yet — the stale-id
    /// shape), its registration lands at the classification boundary, and
    /// the revalidation drops it from the signal set into the spared set:
    /// never signalled (alive after the reap), never a survivor.
    #[test]
    #[cfg(unix)]
    fn reap_scope_presignal_recheck_spares_mid_classification_registration() {
        let (_dir, db) = file_test_db();
        let db_path = db.path().to_path_buf();
        let name = unique_name("scoperecheck");
        let binding_ids = vec![format!("proc-bound-{}", rand_suffix())];
        let mut first = spawn_named_sleeper(&name, "proc-scope-old");
        let first_pid = first.id();
        wait_for_enumerated(&name, &[], first_pid);
        unsafe { libc::kill(first_pid as libc::pid_t, libc::SIGSTOP) };

        let late_binding = format!("proc-fresh-{}", rand_suffix());
        let (hook, hit, release) = rendezvous_at(RoundPoint::Classified);
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let reap_name = name.clone();
        let reap_bindings = binding_ids.clone();
        let reaper = std::thread::spawn(move || {
            let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
            arm_round_seam(hook);
            start_tx.send(()).ok();
            reap_instance_tree_for_excluding(&db, &reap_name, &reap_bindings, &[])
        });
        start_rx.recv().unwrap();
        // Late carrier with a not-yet-registered id, spawned after the reap
        // began: it is classified (a late carrier), never a first-snapshot
        // pid.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut late = spawn_named_sleeper(&name, &late_binding);
        let late_pid = late.id();
        wait_for_enumerated(&name, &[], late_pid);
        // The registration lands between classification and the signal
        // round: the pre-signal re-read must spare the carrier.
        hit.recv_timeout(std::time::Duration::from_secs(30))
            .expect("KILL round reaches its classification boundary");
        db.set_process_binding(&late_binding, "sess", &name)
            .unwrap();
        release.send(()).ok();

        let result = reaper.join().expect("reap thread");
        first.wait().ok();
        assert!(
            result.is_ok(),
            "the revalidation-spared carrier is never a survivor: {result:?}"
        );
        assert!(
            !crate::sys::process::is_alive(first_pid),
            "in-scope initial carrier is reaped"
        );
        // try_wait, not is_alive: a SIGKILLed-but-unreaped child is a zombie
        // and reads alive — None means the carrier never got signalled.
        let late_status = late.try_wait().unwrap();
        assert!(
            late_status.is_none(),
            "the pre-signal revalidation drops the mid-classification \
             registration from the signal set (pid {late_pid} was signalled: \
             {late_status:?})"
        );
        late.kill().ok();
        late.wait().ok();
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
    fn omp_minted_pid_parses_omp_shape_only() {
        assert_eq!(omp_minted_pid("omp-123-4-5"), Some(123));
        assert_eq!(omp_minted_pid("550e8400-e29b-41d4-a716-446655440000"), None);
        assert_eq!(omp_minted_pid(""), None);
        assert_eq!(omp_minted_pid("omp-"), None);
        assert_eq!(omp_minted_pid("omp-abc-1"), None);
        assert_eq!(omp_minted_pid("omp--1"), None);
        // A bare `omp-<pid>` is not the minted shape on either side of the
        // contract: the plugin's OMP_ID_PATTERN also demands the trailing group.
        assert_eq!(omp_minted_pid("omp-7"), None);
        assert_eq!(omp_minted_pid("omp-7-"), None);
    }

    // === process_id_trusted: the §1 trust table (pure, injected facts) ===

    #[test]
    fn process_id_trusted_empty_id_refused() {
        assert!(!process_id_trusted(
            "",
            &[7],
            &|_| AncestorProcess::Omp,
            Some(Some(7)),
            &|_| true
        ));
    }

    #[test]
    fn process_id_trusted_omp_id_non_ancestor_pid_refused() {
        // omp-99-… but 99 is not in the ancestor chain, even though 99 runs omp.
        assert!(!process_id_trusted(
            "omp-99-1-2",
            &[7, 3],
            &|_| AncestorProcess::Omp,
            None,
            &|_| true
        ));
    }

    #[test]
    fn process_id_trusted_omp_id_shell_ancestor_refused() {
        // The lotso case: D-69 mints from the login shell's $$; the shell is a
        // live ancestor but runs `sh`, not `omp`.
        assert!(!process_id_trusted(
            "omp-3-1-2",
            &[7, 3],
            &|pid| if pid == 3 {
                AncestorProcess::Other
            } else {
                AncestorProcess::Omp
            },
            None,
            &|_| true
        ));
    }

    #[test]
    fn process_id_trusted_omp_id_unknown_ancestor_kind_refused() {
        // Unreadable /proc comm proves nothing: Unknown never satisfies Omp.
        assert!(!process_id_trusted(
            "omp-3-1-2",
            &[7, 3],
            &|pid| if pid == 3 {
                AncestorProcess::Unknown
            } else {
                AncestorProcess::Omp
            },
            None,
            &|_| true
        ));
    }

    #[test]
    fn process_id_trusted_omp_id_omp_ancestor_trusted() {
        // Nested omp: the minting pid is an ancestor running `omp`. No binding
        // row needed — rule 1 judges purely by ancestry and comm.
        assert!(process_id_trusted(
            "omp-3-1-2",
            &[7, 3],
            &|pid| if pid == 3 {
                AncestorProcess::Omp
            } else {
                AncestorProcess::Other
            },
            None,
            &|_| false
        ));
    }

    #[test]
    fn process_id_trusted_uuid_row_pid_in_ancestors_trusted() {
        // Launcher UUID: row exists, bound instance's recorded pid is in the
        // tree. No comm requirement on this branch.
        assert!(process_id_trusted(
            "550e8400-e29b-41d4-a716-446655440000",
            &[7, 3],
            &|_| AncestorProcess::Other,
            Some(Some(3)),
            &|_| false
        ));
    }

    #[test]
    fn process_id_trusted_uuid_row_pid_outside_ancestors_refused() {
        assert!(!process_id_trusted(
            "550e8400-e29b-41d4-a716-446655440000",
            &[7, 3],
            &|_| AncestorProcess::Omp,
            Some(Some(99)),
            &|_| true
        ));
    }

    #[test]
    fn process_id_trusted_uuid_no_row_refused() {
        // The launcher always pre-registers the binding before spawn, so a
        // live launcher id with no row is foreign.
        assert!(!process_id_trusted(
            "550e8400-e29b-41d4-a716-446655440000",
            &[7, 3],
            &|_| AncestorProcess::Omp,
            None,
            &|_| true
        ));
    }

    #[test]
    fn process_id_trusted_uuid_null_pid_ancestor_carries_id_refused() {
        // Finding 2: a NULL-pid launcher row has no anchor, even if this tree
        // carries the leaked UUID; the wrapper supplies the early anchor.
        assert!(!process_id_trusted(
            "550e8400-e29b-41d4-a716-446655440000",
            &[7, 3],
            &|_| AncestorProcess::Other,
            Some(None),
            &|want| want == "550e8400-e29b-41d4-a716-446655440000"
        ));
    }

    #[test]
    fn process_id_trusted_uuid_null_pid_no_carrier_refused() {
        assert!(!process_id_trusted(
            "550e8400-e29b-41d4-a716-446655440000",
            &[7, 3],
            &|_| AncestorProcess::Omp,
            Some(None),
            &|_| false
        ));
    }

    #[test]
    fn process_id_trusted_non_launcher_no_row_carried_trusted() {
        // Non-OMP hooks retain synthetic/relay/adhoc carriage compatibility
        // even though the presented env value does not prove provenance.
        for id in ["pid-agy-123", "pid-cop-123", "hcom-codex-recipient-42"] {
            assert!(
                process_id_trusted(id, &[7, 3], &|_| AncestorProcess::Omp, None, &|want| want
                    == id),
                "{id} should be trusted when this tree carries it"
            );
        }
    }

    #[test]
    fn process_id_trusted_non_launcher_no_row_uncarried_refused() {
        assert!(!process_id_trusted(
            "pid-agy-123",
            &[7, 3],
            &|_| AncestorProcess::Omp,
            None,
            &|_| false
        ));
    }

    #[test]
    fn process_id_trusted_non_launcher_row_pid_outside_ancestors_refused() {
        // A row that exists still gags the id: only the recorded pid proves it.
        assert!(!process_id_trusted(
            "pid-agy-123",
            &[7, 3],
            &|_| AncestorProcess::Omp,
            Some(Some(99)),
            &|_| true
        ));
    }
    #[test]
    fn process_id_trusted_omp_strict_rejects_carried_synthetic() {
        let id = "pid-agy-123";
        assert!(!process_id_trusted_for_omp(
            id,
            &[7, 3],
            &|_| AncestorProcess::Omp,
            None,
            &|want| want == id,
        ));
        assert!(process_id_trusted(
            id,
            &[7, 3],
            &|_| AncestorProcess::Omp,
            None,
            &|want| want == id,
        ));
    }

    #[test]
    fn process_id_trusted_omp_strict_accepts_proven_launcher() {
        assert!(process_id_trusted_for_omp(
            "550e8400-e29b-41d4-a716-446655440000",
            &[7, 3],
            &|_| AncestorProcess::Other,
            Some(Some(3)),
            &|_| false,
        ));
    }

    #[test]
    fn launcher_shape_detects_uuid_v4() {
        assert!(is_launcher_process_id(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(is_launcher_process_id(
            "0cfec9a4-ddff-45cc-b0bf-c45e6ab65bb2"
        ));
        for other in [
            "",
            "omp-7-1-2",
            "pid-123",
            "hcom-codex-recipient-42",
            "550e8400-e29b-41d4-a716-44665544000",
            "550e8400-e29b-41d4-a716-4466554400000",
            "550e8400-e29b-41d4-a716-44665544000g",
            "550E8400-E29B-41D4-A716-446655440000",
        ] {
            assert!(
                !is_launcher_process_id(other),
                "{other} is not a launcher id"
            );
        }
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
        let db = test_db();
        let name = unique_name("reappid");
        let binding = format!("proc-reap-{}", rand_suffix());
        let mut sleeper = spawn_pid_only_sleeper(&binding);
        let pid = sleeper.id();
        wait_for_enumerated(&name, std::slice::from_ref(&binding), pid);
        assert!(reap_instance_tree_for(&db, &name, &[binding]).is_ok());
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

    // -- Caller identity tree: the spawn gate's self rule -------------------

    /// Poses the caller's identity env — the spawn gate reads these two from
    /// the live env — and restores whatever was there on drop.
    #[cfg(unix)]
    struct CallerIdentityEnv(Option<std::ffi::OsString>, Option<std::ffi::OsString>);

    #[cfg(unix)]
    impl CallerIdentityEnv {
        fn pose(instance_name: Option<&str>, process_id: Option<&str>) -> Self {
            let saved = (
                std::env::var_os("HCOM_INSTANCE_NAME"),
                std::env::var_os("HCOM_PROCESS_ID"),
            );
            unsafe {
                match instance_name {
                    Some(v) => std::env::set_var("HCOM_INSTANCE_NAME", v),
                    None => std::env::remove_var("HCOM_INSTANCE_NAME"),
                }
                match process_id {
                    Some(v) => std::env::set_var("HCOM_PROCESS_ID", v),
                    None => std::env::remove_var("HCOM_PROCESS_ID"),
                }
            }
            Self(saved.0, saved.1)
        }
    }

    #[cfg(unix)]
    impl Drop for CallerIdentityEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.0 {
                    Some(v) => std::env::set_var("HCOM_INSTANCE_NAME", v),
                    None => std::env::remove_var("HCOM_INSTANCE_NAME"),
                }
                match &self.1 {
                    Some(v) => std::env::set_var("HCOM_PROCESS_ID", v),
                    None => std::env::remove_var("HCOM_PROCESS_ID"),
                }
            }
        }
    }

    /// A name/process-id-carrying sleeper in a tree of its own: `sh` spawns
    /// it in the background and exits, so the sleeper is reparented to init —
    /// its ppid chain never passes through the test process. Returns its pid
    /// (it is not our child, so kill it with `libc::kill`).
    #[cfg(unix)]
    fn spawn_detached_named_sleeper(name: &str, process_id: &str) -> u32 {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 300 >/dev/null 2>&1 & echo $!")
            .env("HCOM_INSTANCE_NAME", name)
            .env("HCOM_PROCESS_ID", process_id)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .expect("spawn detached sleeper");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("detached sleeper pid")
    }

    /// A sleeper with no identity env at all: it can sit topologically inside
    /// another process's tree but has no facts to share.
    #[cfg(unix)]
    fn spawn_stripped_sleeper() -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("300")
            .env_remove("HCOM_INSTANCE_NAME")
            .env_remove("HCOM_PROCESS_ID")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn stripped sleep")
    }

    /// Self-gate, name shape: the caller matches the target's carriers by
    /// `HCOM_INSTANCE_NAME` and only its own tree is alive. The carrier
    /// holds the newest binding (a live holder for any foreign caller), so
    /// this Ok is exactly the identity-tree exclusion.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn spawn_allows_name_carriers_in_caller_identity_tree() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = test_db();
        let name = unique_name("selfname");
        let binding = format!("proc-new-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        let mut sleeper = spawn_named_sleeper(&name, &binding);
        let pid = sleeper.id();
        wait_for_enumerated(&name, &[], pid);
        let _identity = CallerIdentityEnv::pose(Some(&name), None);
        assert!(
            check_spawn_allowed(&db, &name).is_ok(),
            "the caller's own identity tree must never block it"
        );
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    /// Self-gate, binding shape: the caller matches by
    /// `HCOM_PROCESS_ID=<binding>` (the self-bound session shape) and only
    /// its own tree is alive — again over a newest-binding carrier that
    /// would refuse any foreign caller.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn spawn_allows_binding_carriers_in_caller_identity_tree() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = test_db();
        let name = unique_name("selfbind");
        let binding = format!("proc-self-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        let mut sleeper = spawn_pid_only_sleeper(&binding);
        let pid = sleeper.id();
        wait_for_enumerated(&name, std::slice::from_ref(&binding), pid);
        let _identity = CallerIdentityEnv::pose(None, Some(&binding));
        assert!(
            check_spawn_allowed(&db, &name).is_ok(),
            "the caller's own identity tree must never block it"
        );
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    /// Foreign gate: a caller with no identity facts finds no root and gets
    /// the exact pre-existing refusal over a live holder. The self rule never
    /// opens the gate for a foreign claimant.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn spawn_refuses_stripped_caller_over_live_holder() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = test_db();
        let name = unique_name("foreign");
        let binding = format!("proc-cur-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        let mut sleeper = spawn_named_sleeper(&name, &binding);
        let pid = sleeper.id();
        wait_for_enumerated(&name, &[], pid);
        let _identity = CallerIdentityEnv::pose(None, None);
        let err = check_spawn_allowed(&db, &name).expect_err("foreign caller must refuse");
        assert_eq!(err.kind, HolderKind::LiveHolder);
        assert!(err.pids.contains(&pid), "refusal names the pid: {err}");
        let shown = err.to_string();
        assert!(
            shown.contains(&format!("refusing to spawn under '{name}'")),
            "exact refusal unchanged: {shown}"
        );
        assert!(
            shown.contains(&format!("hcom kill {name}")),
            "exact refusal unchanged: {shown}"
        );
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    /// Blocker-A shape: the caller matches the target's newest binding, but
    /// a pre-binding orphan is alive in a SEPARATE tree (double-forked,
    /// reparented to init). Reclaiming the name would leave that process
    /// alive under the reclaimed identity, so the gate must refuse with the
    /// orphan classification.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn spawn_refuses_pre_binding_orphan_outside_caller_tree() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = test_db();
        let name = unique_name("orphanout");
        let orphan = spawn_detached_named_sleeper(&name, &format!("proc-old-{}", rand_suffix()));
        wait_for_enumerated(&name, &[], orphan);
        let start = processes_for_instance(&name, &[], &[])
            .into_iter()
            .find(|m| m.pid == orphan)
            .expect("detached sleeper enumerated")
            .start_epoch;
        // New harness bound AFTER the orphan started: the orphan predates it.
        let binding = format!("proc-new-{}", rand_suffix());
        db.set_process_binding(&binding, "sess", &name).unwrap();
        backdate_binding(&db, &binding, start + 3600.0);
        let _identity = CallerIdentityEnv::pose(None, Some(&binding));
        let err = check_spawn_allowed(&db, &name)
            .expect_err("pre-binding orphan outside the caller's tree must refuse");
        assert_eq!(err.kind, HolderKind::Orphan);
        assert!(err.pids.contains(&orphan), "refusal names the pid: {err}");
        assert!(err.to_string().contains(&format!("hcom kill {name}")));
        unsafe {
            libc::kill(orphan as libc::pid_t, libc::SIGKILL);
        }
    }

    /// Blocker-B shape: the kill self-path leaves a name-carrying shell
    /// standing with the row and bindings gone. A caller sharing its
    /// identity facts sees only its own tree (resume/relaunch unblocked); a
    /// caller with stripped identity in that same tree is foreign again.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn spawn_unbound_name_shell_self_ok_stripped_refused() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = test_db();
        let name = unique_name("shellb");
        // The surviving session shell stand-in: name-carrying, and its
        // process id is in no binding (row deleted / bindings released).
        let mut shell = spawn_named_sleeper(&name, &format!("proc-shell-{}", rand_suffix()));
        let pid = shell.id();
        wait_for_enumerated(&name, &[], pid);
        assert!(db.process_binding_ids(&name).unwrap().is_empty());

        let self_claim = CallerIdentityEnv::pose(Some(&name), None);
        assert!(
            check_spawn_allowed(&db, &name).is_ok(),
            "an identity-sharing caller must not be blocked by its own tree"
        );
        drop(self_claim);

        let _stripped = CallerIdentityEnv::pose(None, None);
        let err = check_spawn_allowed(&db, &name)
            .expect_err("a stripped-identity caller must refuse the surviving shell");
        assert_eq!(err.kind, HolderKind::LiveHolder);
        assert!(err.pids.contains(&pid), "refusal names the pid: {err}");
        shell.kill().ok();
        shell.wait().ok();
    }

    /// The root's identity requirement, not topology: the test process is a
    /// name carrier (posed), so its whole subtree is "the holder's tree". A
    /// child sharing the caller's identity facts belongs to that tree; a
    /// child whose env was stripped of identity does NOT — it is a foreign
    /// claimant and must face the full gate.
    #[test]
    #[cfg(unix)]
    #[serial_test::serial]
    fn caller_identity_tree_demands_identity_not_just_topology() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let name = unique_name("trap");
        let mut sharing = spawn_named_sleeper(&name, &format!("proc-share-{}", rand_suffix()));
        let sharing_pid = sharing.id();
        let mut stripped = spawn_stripped_sleeper();
        let stripped_pid = stripped.id();
        wait_for_enumerated(&name, &[], sharing_pid);
        let holders = processes_for_instance(&name, &[], &[]);
        let _identity = CallerIdentityEnv::pose(Some(&name), None);

        let tree = caller_identity_tree(&name, &[], &holders, sharing_pid);
        assert!(
            tree.contains(&std::process::id()),
            "the root climbs to the carrier ancestor: {tree:?}"
        );
        assert!(
            tree.contains(&sharing_pid),
            "identity-sharing child is self: {tree:?}"
        );

        let tree = caller_identity_tree(&name, &[], &holders, stripped_pid);
        assert_eq!(
            tree,
            vec![stripped_pid],
            "a stripped-identity child gets no root — topology alone is not enough"
        );

        sharing.kill().ok();
        sharing.wait().ok();
        stripped.kill().ok();
        stripped.wait().ok();
    }
}
