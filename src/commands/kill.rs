//! Kill command: `hcom kill <name(s)|all|tag:X>`
//!
//!
//! Sends SIGTERM to process groups and optionally closes terminal panes.

use std::collections::HashSet;

use crate::db::HcomDb;
use crate::hooks::common::stop_instance_without_reap;
use crate::identity;
use crate::log::log_info;
use crate::paths;
use crate::pidtrack;
use crate::router::GlobalFlags;
use crate::terminal;
use anyhow::{Result, bail};

/// Parsed arguments for `hcom kill`.
#[derive(clap::Parser, Debug)]
#[command(name = "kill", about = "Kill agent processes")]
pub struct KillArgs {
    /// Targets to kill (names, "all", or "tag:X")
    pub targets: Vec<String>,
}

pub struct KillTrackedResult {
    pub target: String,
    pub pid: u32,
    pub kill_result: terminal::KillResult,
    pub pane_closed: bool,
    pub pane_retry_command: Option<String>,
    pub preset_name: String,
    pub pane_id: String,
    /// The owned pane holds the excluded caller, so it was left open by design.
    pub pane_left_for_caller: bool,
    /// The owned pane's close command needs a PID kill no longer trusts.
    pub pane_close_needs_pid: bool,
    /// Carriers spared because they are the caller's own session tree
    /// (kill self-path only; 0 on the foreign path).
    pub self_excluded: usize,
    pub self_pid: Option<u32>,
    pub self_session: Option<String>,
    pub leftovers_terminated: Option<usize>,
    /// Whether the resolved incarnation's row was actually torn down.
    pub teardown: TeardownOutcome,
}

/// Failed kills keep their structured verification evidence for relay callers.
#[derive(Debug)]
pub struct KillTrackedError(Box<KillFailure>);

#[derive(Debug)]
pub struct KillFailure {
    pub message: String,
    pub launcher_unverified: Option<String>,
    pub survivors: Vec<u32>,
    pub refusal: bool,
    pub self_pid: Option<u32>,
    pub self_session: Option<String>,
    pub self_excluded: usize,
    pub pane_closed: bool,
    pub pane_retry_command: Option<String>,
    pub preset_name: String,
    pub pane_id: String,
    pub pane_left_for_caller: bool,
    pub pane_close_needs_pid: bool,
}

impl KillFailure {
    fn new(message: String) -> Self {
        Self {
            message,
            launcher_unverified: None,
            survivors: Vec::new(),
            refusal: true,
            self_pid: None,
            self_session: None,
            self_excluded: 0,
            pane_closed: false,
            pane_retry_command: None,
            preset_name: String::new(),
            pane_id: String::new(),
            pane_left_for_caller: false,
            pane_close_needs_pid: false,
        }
    }
}

impl std::ops::Deref for KillTrackedError {
    type Target = KillFailure;

    fn deref(&self) -> &KillFailure {
        &self.0
    }
}

impl std::ops::DerefMut for KillTrackedError {
    fn deref_mut(&mut self) -> &mut KillFailure {
        &mut self.0
    }
}

impl From<KillFailure> for KillTrackedError {
    fn from(failure: KillFailure) -> Self {
        Self(Box::new(failure))
    }
}

impl From<String> for KillTrackedError {
    fn from(message: String) -> Self {
        KillFailure::new(message).into()
    }
}

impl KillTrackedError {
    pub fn into_failure(self) -> KillFailure {
        *self.0
    }

    fn excluding(mut self, count: usize, session: Option<&str>) -> Self {
        if count > 0 {
            use std::fmt::Write;
            self.self_pid = Some(std::process::id());
            self.self_session = session.map(str::to_owned);
            self.self_excluded = count;
            let _ = write!(
                &mut self.message,
                "; caller PID {} (session {}) and its own ancestor chain were left running by design",
                std::process::id(),
                session.unwrap_or("unrecorded")
            );
        }
        self
    }

    /// Carry the pane outcome of a kill whose processes are confirmed gone but
    /// whose bookkeeping or launcher proof failed; pane close never upgrades it.
    fn with_pane(mut self, pane: PaneOutcome) -> Self {
        if pane.closed {
            self.message
                .push_str(&pane_info_str(true, &pane.preset_name, &pane.pane_id));
        }
        if let Some(command) = &pane.retry_command {
            self.message.push_str(&format!(
                "\nProcess terminated, but pane remains. Retry this command with approval/escalation:\n{command}"
            ));
        }
        if pane.left_for_caller {
            self.message
                .push_str("\nPane left open by design: it holds the excluded caller.");
        }
        if pane.needs_pid {
            self.message.push('\n');
            self.message.push_str(PANE_NEEDS_PID.trim_start());
        }
        self.pane_closed = pane.closed;
        self.pane_retry_command = pane.retry_command;
        self.preset_name = pane.preset_name;
        self.pane_id = pane.pane_id;
        self.pane_left_for_caller = pane.left_for_caller;
        self.pane_close_needs_pid = pane.needs_pid;
        self
    }
}

/// The pane cleanup that followed native confirmation.
struct PaneOutcome {
    closed: bool,
    retry_command: Option<String>,
    preset_name: String,
    pane_id: String,
    left_for_caller: bool,
    needs_pid: bool,
}

impl std::fmt::Display for KillTrackedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn native_kill_error(name: &str, error: crate::sys::process::KillError) -> KillTrackedError {
    use crate::sys::process::KillError;
    let message =
        format!("Could not stop '{name}': {error}; hcom stop {name} clears the bookkeeping");
    let (survivors, refusal) = match error {
        KillError::Refused(_) => (Vec::new(), true),
        KillError::Survivors(pids) => (pids, false),
        KillError::Unconfirmed { survivors, .. } => (survivors, true),
    };
    KillFailure {
        survivors,
        refusal,
        ..KillFailure::new(message)
    }
    .into()
}

fn launcher_unverified_error(name: &str, warning: &str, self_excluded: bool) -> KillTrackedError {
    let stopped = if self_excluded {
        "captured non-self processes"
    } else {
        "owner tree"
    };
    let message = format!(
        "'{name}' {stopped} terminated, but {warning}; hcom stop {name} clears the bookkeeping"
    );
    KillFailure {
        launcher_unverified: Some(warning.to_owned()),
        refusal: false,
        ..KillFailure::new(message)
    }
    .into()
}

/// Teardown outcome of a kill: whether the row of the incarnation the kill
/// resolved against was actually torn down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownOutcome {
    /// The teardown write landed (`stopped` event and release).
    Completed,
    /// The row changed under the kill (recreated, rebound, vanished, or
    /// reappeared): the teardown was skipped and the row left intact.
    RowReRegistered,
    /// The session's own shutdown finalized the row mid-kill but kept it (the
    /// soft stop: same incarnation, bindings released, row kept as a resume
    /// handle). The kill's teardown write was skipped; nothing re-registered.
    SessionStoppedKeptRow,
    /// The session's own shutdown finalized and deleted the row mid-kill.
    /// The kill's teardown write was skipped; nothing re-registered.
    SessionStoppedReleasedRow,
}

impl TeardownOutcome {
    /// Wire token in the remote kill response payload.
    pub fn as_str(self) -> &'static str {
        match self {
            TeardownOutcome::Completed => "completed",
            TeardownOutcome::RowReRegistered => "row_re_registered",
            TeardownOutcome::SessionStoppedKeptRow => "session_stopped_kept_row",
            TeardownOutcome::SessionStoppedReleasedRow => "session_stopped_released_row",
        }
    }

    /// Parse a remote payload's teardown token. Absent or unrecognized
    /// reads as `None` — never as `Completed`.
    pub fn parse(token: Option<&str>) -> Option<Self> {
        match token {
            Some("completed") => Some(TeardownOutcome::Completed),
            Some("row_re_registered") => Some(TeardownOutcome::RowReRegistered),
            Some("session_stopped_kept_row") => Some(TeardownOutcome::SessionStoppedKeptRow),
            Some("session_stopped_released_row") => {
                Some(TeardownOutcome::SessionStoppedReleasedRow)
            }
            _ => None,
        }
    }
}

/// The incarnation a kill resolved against: the row as read (its `created_at`
/// identity plus `session_id`) and its process binding ids — the binding
/// epoch the kill tears down.
///
/// A same-identity registration admitted mid-kill (`start --as`, a rebind, a
/// relaunch) replaces the row and/or its bindings. The kill's destructive
/// intent is against the OLD incarnation only, so the teardown runs only
/// while this token still describes the row (see
/// [`teardown_if_incarnation_unchanged`]). The comparison covers the
/// name-only rebind (bindings stay empty on both sides): row presence,
/// `session_id`, and the binding id SET are compared together.
#[derive(Debug, Clone, PartialEq)]
struct IncarnationToken {
    created_at: f64,
    session_id: Option<String>,
    agent_id: Option<String>,
    binding_ids: Vec<String>,
}

impl IncarnationToken {
    fn capture(row: &crate::db::InstanceRow, binding_ids: &[String]) -> Self {
        Self::new(
            row.created_at,
            row.session_id.clone(),
            row.agent_id.clone(),
            binding_ids.to_vec(),
        )
    }

    fn new(
        created_at: f64,
        session_id: Option<String>,
        agent_id: Option<String>,
        binding_ids: Vec<String>,
    ) -> Self {
        let mut ids = binding_ids;
        ids.sort();
        ids.dedup();
        Self {
            created_at,
            session_id,
            agent_id,
            binding_ids: ids,
        }
    }
}

/// What a kill resolved against, captured together before any signal: the
/// [`IncarnationToken`] the teardown CAS compares, plus the events
/// watermark (`MAX(events.id)`). The row, its binding epoch, and the
/// watermark come from ONE snapshot ([`Self::read`]), so a `stopped` event
/// committed right after the kill read the row is above the watermark. The
/// watermark is never part of the CAS; it only scopes the lost-CAS
/// classification to `stopped` events written after the kill resolved its
/// target (see [`classify_lost_teardown`]).
struct ResolvedIncarnation {
    token: IncarnationToken,
    event_watermark: i64,
}

impl ResolvedIncarnation {
    /// `name`'s row, its binding ids (newest first), and the events
    /// watermark, read in ONE snapshot.
    fn read(db: &HcomDb, name: &str) -> Result<(Option<crate::db::InstanceRow>, Vec<String>, i64)> {
        db.with_read_snapshot(|tx| {
            let (row, binding_ids) = HcomDb::instance_with_bindings_in(tx, name)?;
            let event_watermark =
                tx.query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |r| r.get(0))?;
            Ok((row, binding_ids, event_watermark))
        })
    }

    fn new(row: &crate::db::InstanceRow, binding_ids: &[String], event_watermark: i64) -> Self {
        Self {
            token: IncarnationToken::capture(row, binding_ids),
            event_watermark,
        }
    }
}

// Test seam: runs right after the kill's one-snapshot read, so a test can
// commit a stop in the gap before any signal.
#[cfg(test)]
thread_local! {
    static CAPTURE_GAP_HOOK: crate::db::GapHook = const { std::cell::Cell::new(None) };
}

#[derive(Clone, Copy)]
enum PaneCleanupProcessState {
    Terminated,
    AlreadyDead,
    NotTerminated,
}

impl From<terminal::KillResult> for PaneCleanupProcessState {
    fn from(result: terminal::KillResult) -> Self {
        match result {
            terminal::KillResult::Sent => Self::Terminated,
            terminal::KillResult::AlreadyDead => Self::AlreadyDead,
            terminal::KillResult::PermissionDenied => Self::NotTerminated,
        }
    }
}

fn report_incomplete_pane_cleanup(
    process_state: PaneCleanupProcessState,
    retry_command: Option<&str>,
) -> bool {
    if matches!(process_state, PaneCleanupProcessState::NotTerminated) {
        return false;
    }
    let Some(command) = retry_command else {
        return false;
    };
    let process_message = match process_state {
        PaneCleanupProcessState::Terminated => "Process terminated",
        PaneCleanupProcessState::AlreadyDead => "Process was already terminated",
        PaneCleanupProcessState::NotTerminated => unreachable!(),
    };
    eprintln!("{process_message}, but pane remains. Retry this command with approval/escalation:");
    eprintln!("{command}");
    true
}

/// Resolve who initiated the kill
fn resolve_initiator(db: &HcomDb, explicit_name: Option<&str>) -> String {
    if let Some(name) = explicit_name {
        return name.to_string();
    }
    match identity::resolve_identity(db, None, None, None, None, None, None) {
        Ok(id) if matches!(id.kind, crate::shared::SenderKind::Instance) => id.name,
        _ => "cli".to_string(),
    }
}

pub fn kill_tracked_instance(
    db: &HcomDb,
    name: &str,
    initiator: &str,
) -> Result<KillTrackedResult, KillTrackedError> {
    let (inst, binding_ids, watermark) =
        ResolvedIncarnation::read(db, name).map_err(|error| error.to_string())?;
    let inst = inst.ok_or_else(|| format!("Agent '{name}' not found"))?;
    kill_resolved_instance(
        db,
        &inst,
        &binding_ids,
        watermark,
        initiator,
        None,
        |_, _, _| Ok(()),
    )
}

/// The self set is injectable so tests never need to signal their own seat.
/// The hook runs after owner/root resolution and before native termination;
/// tests use it to land incarnation changes or a refused termination.
#[cfg(test)]
fn kill_tracked_instance_with_self_pids(
    db: &HcomDb,
    name: &str,
    initiator: &str,
    self_pids: &[u32],
    before_terminate: impl FnOnce(&str, &[String], &[u32]) -> Result<(), crate::proctruth::ReapError>,
) -> Result<KillTrackedResult, KillTrackedError> {
    // The row, its binding epoch, and the events watermark come from ONE
    // snapshot: separate reads can straddle a `start --as` and pair one
    // incarnation's row with another's bindings, and a watermark read after
    // the row can hide a stop that committed in between.
    let (inst, binding_ids, event_watermark) =
        ResolvedIncarnation::read(db, name).map_err(|e| e.to_string())?;
    let inst = inst.ok_or_else(|| format!("Agent '{}' not found", name))?;
    kill_resolved_instance(
        db,
        &inst,
        &binding_ids,
        event_watermark,
        initiator,
        Some(self_pids),
        before_terminate,
    )
}

fn kill_resolved_instance(
    db: &HcomDb,
    inst: &crate::db::InstanceRow,
    binding_ids: &[String],
    event_watermark: i64,
    initiator: &str,
    self_pids: Option<&[u32]>,
    before_terminate: impl FnOnce(&str, &[String], &[u32]) -> Result<(), crate::proctruth::ReapError>,
) -> Result<KillTrackedResult, KillTrackedError> {
    let name = &inst.name;
    #[cfg(test)]
    if let Some(hook) = CAPTURE_GAP_HOOK.with(std::cell::Cell::take) {
        hook(db, name);
    }
    let pid = inst
        .pid
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|&pid| pid != 0)
        .ok_or_else(|| match inst.pid {
            Some(pid) => format!("Refusing to signal PID {pid} for '{name}': invalid recorded PID; hcom stop {name} clears the bookkeeping"),
            None => format!("No tracked PID for '{name}' — hcom stop {name} clears the bookkeeping"),
        })?;
    let owner =
        crate::proctruth::verify_kill_owner(pid, inst.launch_context.as_deref(), binding_ids)
            .map_err(|reason| unverified_owner_error(name, pid, reason))?;
    let owner = owner
        .resolve_root(
            Some(&inst.tool),
            inst.launch_context.as_deref(),
            binding_ids,
        )
        .map_err(|reason| unverified_owner_error(name, pid, reason))?;
    // No caller-chain lookup, pane action or signal can precede owner/root
    // authentication. A bookkeeping-only dead row needs no signal exclusion.
    let caller_chain;
    let self_pids = match self_pids {
        Some(pids) => pids,
        None if owner.identity().is_some() => {
            caller_chain = crate::proctruth::kill_caller_ancestor_pids()
                .map_err(|reason| unverified_owner_error(name, pid, reason))?;
            &caller_chain
        }
        None => &[],
    };

    // The row, binding epoch and watermark were captured before any signal.
    let incarnation = ResolvedIncarnation::new(inst, binding_ids, event_watermark);
    let _teardown_claim = crate::hooks::common::TeardownClaim::register(
        db,
        name,
        incarnation.token.created_at,
        incarnation.token.session_id.as_deref(),
    );
    let excluded: Vec<u32> = self_pids
        .iter()
        .copied()
        .filter(|&candidate| candidate == owner.pid() || candidate == pid)
        .collect();
    before_terminate(name, binding_ids, &excluded).map_err(|error| {
        survivors_error(name, &error).excluding(excluded.len(), inst.session_id.as_deref())
    })?;

    let mut leftovers_terminated = None;
    if owner.is_zombie()
        && let Some(identity) = owner.identity()
    {
        let leftovers = crate::sys::process::terminate_zombie_group_verified(
            pid,
            identity,
            self_pids,
            crate::proctruth::kill_candidate_eligible,
            |candidate| crate::proctruth::verify_kill_candidate(db, name, candidate),
        )
        .map_err(|error| native_kill_error(name, error))?;
        leftovers_terminated = Some(leftovers);
        println!(
            "'{name}' owner PID {pid} already exited; {leftovers} leftover process(es) terminated"
        );
    }
    // Gone and zombie owners recheck false, so this sends them no signal; every
    // mode still runs the receipt-verified pane close after confirmation.
    let (result, pane_closed, followup, preset_name, pane_id) = kill_instance(
        db,
        name,
        &owner,
        inst,
        inst.background != 0,
        binding_ids,
        self_pids,
    )
    .map_err(|error| error.excluding(excluded.len(), inst.session_id.as_deref()))?;
    let pane_left_for_caller = !excluded.is_empty() && !preset_name.is_empty() && !pane_closed;
    let pane = || PaneOutcome {
        closed: pane_closed,
        retry_command: followup.retry_command.clone(),
        preset_name: preset_name.clone(),
        pane_id: pane_id.clone(),
        left_for_caller: pane_left_for_caller,
        needs_pid: followup.needs_pid,
    };
    // Native helpers have confirmed every captured incarnation gone. Only
    // now may the old row's incarnation-bound bookkeeping be released.
    let teardown =
        teardown_if_incarnation_unchanged(db, name, initiator, &incarnation).map_err(|error| {
            let state = if excluded.is_empty() {
                "dead"
            } else {
                "gone (excluding the caller)"
            };
            KillTrackedError::from(format!(
                "Captured processes verified {state}, but '{name}' row was not finalized: {error}. \
                 Recovery: hcom kill {name}"
            ))
            .excluding(excluded.len(), inst.session_id.as_deref())
            .with_pane(pane())
        })?;
    if let Some(warning) = owner.launcher_warning() {
        return Err(
            launcher_unverified_error(name, warning, !excluded.is_empty())
                .excluding(excluded.len(), inst.session_id.as_deref())
                .with_pane(pane()),
        );
    }
    if !excluded.is_empty() {
        println!(
            "'{name}': caller PID {} (session {}) and its own ancestor chain were left running by design; owner/root death is not claimed",
            std::process::id(),
            inst.session_id.as_deref().unwrap_or("unrecorded")
        );
    }

    Ok(KillTrackedResult {
        target: name.to_string(),
        pid: owner.pid(),
        kill_result: result,
        pane_closed,
        pane_retry_command: followup.retry_command,
        preset_name,
        pane_id,
        pane_left_for_caller,
        pane_close_needs_pid: followup.needs_pid,
        self_excluded: excluded.len(),
        self_pid: (!excluded.is_empty()).then_some(std::process::id()),
        self_session: if excluded.is_empty() {
            None
        } else {
            inst.session_id.clone()
        },
        leftovers_terminated,
        teardown,
    })
}

fn unverified_owner_error(name: &str, pid: u32, reason: &str) -> KillTrackedError {
    let leftovers = if crate::sys::process::is_zombie_group_leader(pid) {
        match crate::sys::kill_group::live_members(pid) {
            Ok(members) if !members.is_empty() => format!(
                " Live group member PIDs {} were not signalled.",
                members
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Ok(_) => " No live group members were found; no group was signalled.".into(),
            Err(error) => format!(
                " Live group members could not be enumerated ({error}); no group was signalled."
            ),
        }
    } else {
        String::new()
    };
    format!(
        "Refusing to signal PID {pid} for '{name}': {reason}; no signal sent to the unverified process.{leftovers} \
         hcom stop {name} clears the bookkeeping."
    ).into()
}

/// A refused reap leaves the row and bindings available for a retry.
fn survivors_error(name: &str, error: &crate::proctruth::ReapError) -> KillTrackedError {
    let message = format!("could not stop {name}: {error} — run hcom kill {name} first");
    let survivors = match error {
        crate::proctruth::ReapError::Survivors(pids) => pids.clone(),
        #[cfg(unix)]
        _ => Vec::new(),
    };
    KillFailure {
        refusal: survivors.is_empty(),
        survivors,
        ..KillFailure::new(message)
    }
    .into()
}

/// Re-read the incarnation token of `name` through the teardown transaction;
/// None when the row is gone. The ONLY incarnation read allowed to decide —
/// any read outside the transaction leaves a check/use gap.
fn read_incarnation_tx(
    tx: &rusqlite::Transaction<'_>,
    name: &str,
) -> Result<Option<IncarnationToken>> {
    use rusqlite::OptionalExtension;
    let row: Option<(f64, Option<String>, Option<String>)> = tx
        .query_row(
            "SELECT created_at, session_id, agent_id FROM instances WHERE name = ?1",
            rusqlite::params![name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((created_at, session_id, agent_id)) = row else {
        return Ok(None);
    };
    let mut stmt =
        tx.prepare("SELECT process_id FROM process_bindings WHERE instance_name = ?1")?;
    let binding_ids = stmt
        .query_map(rusqlite::params![name], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(Some(IncarnationToken::new(
        created_at,
        session_id,
        agent_id,
        binding_ids,
    )))
}

/// The kill's teardown write, gated on the incarnation: only the exact
/// incarnation the kill resolved against is torn down. The reap-to-teardown
/// window is real — the spawn gate can admit and recreate the same identity
/// while the reap runs — and a comparison OUTIDE the write leaves a
/// check/use gap a rebind slips through (adopted and finalized as the row to
/// stop), so the token re-read, the comparison, and the teardown writes
/// (`stopped` event + binding release) run in ONE `BEGIN IMMEDIATE`
/// transaction (see [`stop_instance_without_reap`]): whatever the
/// interleaving, a rebind either serializes before the transaction — the
/// comparison sees it and NOTHING is written — or lands after the commit.
/// Row recreated, rebound, vanished, or reappeared (a same-identity
/// `start --as` landing mid-kill): report the row left intact. The
/// comparison is row presence + `session_id` + the binding id set together,
/// so the name-only rebind (bindings stay empty) is caught by `session_id`.
/// A lost comparison writes nothing; only the REPORT distinguishes a
/// re-registration from the session's own shutdown finalizing the row (see
/// [`classify_lost_teardown`]).
fn teardown_if_incarnation_unchanged(
    db: &HcomDb,
    name: &str,
    initiator: &str,
    incarnation: &ResolvedIncarnation,
) -> Result<TeardownOutcome, String> {
    let mut lost = TeardownOutcome::RowReRegistered;
    let committed = stop_instance_without_reap(db, name, initiator, "killed", |tx| {
        let current = read_incarnation_tx(tx, name)?;
        if current.as_ref() == Some(&incarnation.token) {
            return Ok(true);
        }
        lost = classify_lost_teardown(tx, name, incarnation, current)?;
        Ok(false)
    })?;
    Ok(if committed {
        TeardownOutcome::Completed
    } else {
        lost
    })
}

/// Why the teardown CAS lost, read-only inside the same teardown
/// transaction. The row can be stopped while the kill runs: by the
/// session's own exit hook (one already past the claim check, or one with
/// no claim to yield to — a 0.7.29 relay worker kills remotely and writes
/// none), the PTY wrapper's exit cleanup, the daemon's vanished sweep, a
/// stop command, or another kill. Which writer did is irrelevant; the
/// incarnation decides. A `stopped` event for this instance written after
/// the kill resolved its target (id above the watermark) — other than a
/// `stale-harness-exit`, a stale harness declining to touch a rebound row —
/// names the incarnation it stopped by its snapshot: `created_at` (the
/// exact `created_at_bits` whenever present, else the bit pattern of the
/// legacy raw `created_at` token) plus `session_id`. Only when the snapshot
/// has no readable `created_at` does the event's `process_id` stand in, as
/// one of the resolved bindings. An event naming the resolved incarnation
/// is a self-stop: a gone row was released, and a row with the same
/// identity whose bindings only shrank (down to none) was kept. Anything
/// else — no such event, another incarnation's stop, or a current row the
/// kill never resolved — is a genuine re-registration. An event with no
/// readable `created_at` and no `process_id` (no snapshot, or a
/// `created_at` that is absent, null, non-numeric, or not a scalar) names
/// no incarnation: it is logged and never taken for the resolved one.
/// `current` is the incarnation the CAS just read in this transaction.
fn classify_lost_teardown(
    tx: &rusqlite::Transaction<'_>,
    name: &str,
    incarnation: &ResolvedIncarnation,
    current: Option<IncarnationToken>,
) -> Result<TeardownOutcome> {
    use rusqlite::types::ValueRef;
    let token = &incarnation.token;
    // A snapshot renders a NULL session as "" (`get_instance_snapshot`) or
    // as null: both mean no session, on either side of the comparison.
    fn session(id: Option<&str>) -> Option<&str> {
        id.filter(|id| !id.is_empty())
    }
    let mut stmt = tx.prepare(
        "SELECT id, json_extract(data, '$.process_id'), \
                json_extract(data, '$.snapshot.created_at_bits'), \
                json_extract(data, '$.snapshot.session_id'), \
                json_extract(data, '$.snapshot') FROM events \
         WHERE type = 'life' AND instance = ?1 AND id > ?2 \
           AND json_extract(data, '$.action') = 'stopped' \
           AND COALESCE(json_extract(data, '$.reason'), '') != 'stale-harness-exit'",
    )?;
    let mut events = stmt.query_map(rusqlite::params![name, incarnation.event_watermark], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<String>>(1)?,
            match r.get_ref(2)? {
                ValueRef::Integer(bits) => Some(bits as u64),
                _ => None,
            },
            match r.get_ref(3)? {
                ValueRef::Text(id) => Some(String::from_utf8_lossy(id).into_owned()),
                _ => None,
            },
            r.get::<_, Option<String>>(4)?,
        ))
    })?;
    let mut self_stop = false;
    for event in &mut events {
        let (event_id, process_id, created_at_bits, session_id, snapshot) = event?;
        let bits = created_at_bits
            .or_else(|| snapshot.as_deref().and_then(crate::db::raw_created_at_bits));
        let names_resolved = match (bits, process_id) {
            (Some(bits), _) => {
                bits == token.created_at.to_bits()
                    && session(session_id.as_deref()) == session(token.session_id.as_deref())
            }
            (None, Some(process_id)) => token.binding_ids.contains(&process_id),
            // No incarnation to read: never guessed to be this one. Logged,
            // so the conservative report is explained.
            (None, None) => {
                crate::log::log_warn(
                    "kill",
                    "teardown.stop_event_unreadable",
                    &format!(
                        "instance={name} event={event_id} reason={}",
                        if snapshot.is_some() {
                            "unreadable-created_at"
                        } else {
                            "no-snapshot"
                        }
                    ),
                );
                false
            }
        };
        if names_resolved {
            self_stop = true;
            break;
        }
    }
    if !self_stop {
        return Ok(TeardownOutcome::RowReRegistered);
    }
    Ok(match current {
        None => TeardownOutcome::SessionStoppedReleasedRow,
        Some(current)
            if current.created_at.to_bits() == token.created_at.to_bits()
                && current.session_id == token.session_id
                && current.agent_id == token.agent_id
                && current
                    .binding_ids
                    .iter()
                    .all(|id| token.binding_ids.contains(id)) =>
        {
            TeardownOutcome::SessionStoppedKeptRow
        }
        Some(_) => TeardownOutcome::RowReRegistered,
    })
}

fn handle_remote_kill_response(name: &str, response: &serde_json::Value) -> Result<i32> {
    let result = &response["result"];
    let verified = result["verified_kill"].as_bool() == Some(true);
    if !verified {
        eprintln!("Note: remote host predates verified kill; showing its reported result.");
    }
    if result["launcher_unverified"].is_string()
        || result["survivors"]
            .as_array()
            .is_some_and(|pids| !pids.is_empty())
        || result["refusal"].as_bool() == Some(true)
        || (verified && response["ok"].as_bool() == Some(false))
    {
        if let Some(message) = result["error"].as_str() {
            eprintln!("{message}");
        } else {
            if let Some(warning) = result["launcher_unverified"].as_str() {
                eprintln!("'{name}': {warning}");
            }
            if let Some(pids) = result["survivors"].as_array()
                && !pids.is_empty()
            {
                eprintln!(
                    "Survivor PIDs: {}",
                    pids.iter()
                        .map(serde_json::Value::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if result["refusal"].as_bool() == Some(true) {
                eprintln!(
                    "Remote kill refused for '{name}'; hcom stop {name} clears the bookkeeping"
                );
            }
        }
        if result["pane_retry_command"].is_string()
            && let Some((_, device)) = crate::relay::control::split_device_suffix(name)
        {
            eprintln!("Run the pane-close retry command on remote device {device}.");
        }
        return Ok(1);
    }
    let kill_result = result["kill_result"].as_str();

    // No kill_result means an RPC-level failure (e.g. timeout, protocol error).
    if kill_result.is_none() {
        crate::relay::control::require_successful_rpc_result(response.clone())
            .map_err(anyhow::Error::msg)?;
        bail!("Remote kill returned no kill_result");
    }
    let kill_result = kill_result.unwrap();

    // The teardown outcome is part of the kill contract: an outcome-less (or
    // unrecognized) response is never read as a successful teardown.
    let Some(teardown) = TeardownOutcome::parse(result["teardown"].as_str()) else {
        bail!(
            "Remote kill returned no valid teardown outcome (got {:?} — a peer that predates outcome reporting cannot confirm the row teardown)",
            result["teardown"]
        );
    };

    let pid = result["pid"].as_u64().unwrap_or(0);
    let pane_closed = result["pane_closed"].as_bool().unwrap_or(false);
    let preset_name = result["preset_name"].as_str().unwrap_or("");
    let pane_id = result["pane_id"].as_str().unwrap_or("");
    let pane_retry_command = result["pane_retry_command"].as_str();
    let pane_info = pane_info_str(pane_closed, preset_name, pane_id);

    if kill_result == "permission_denied" {
        eprintln!(
            "Permission denied to kill process group {} for '{}'",
            pid, name
        );
        return Ok(1);
    }
    if let Some(leftovers) = result["leftovers_terminated"].as_u64() {
        println!(
            "'{name}' owner PID {pid} already exited; {leftovers} leftover process(es) terminated"
        );
    }
    let excluded_caller = &result["excluded_caller"];
    let self_excluded = excluded_caller["count"].as_u64().unwrap_or(0);
    if self_excluded > 0 {
        let caller = excluded_caller["pid"].as_u64().ok_or_else(|| {
            anyhow::anyhow!("Remote self-kill did not identify its excluded caller")
        })?;
        println!(
            "'{name}': caller PID {caller} (session {}) and its own ancestor chain were left running by design; owner/root death is not claimed",
            excluded_caller["session_id"]
                .as_str()
                .unwrap_or("unrecorded")
        );
        if teardown == TeardownOutcome::Completed {
            for line in render_self_kill_feedback(name, self_excluded as usize) {
                println!("{line}");
            }
            if result["pane_left_for_caller"].as_bool() == Some(true) {
                println!("{PANE_LEFT_FOR_CALLER}");
            }
            return Ok(0);
        }
    }
    // Skipped teardown first, mirroring the local path (it takes precedence
    // over every kill_result report there too): plain report, exit 0.
    if let Some(lines) = render_skipped_teardown_feedback(name, teardown) {
        for line in lines {
            println!("{line}");
        }
        return Ok(0);
    }

    let lines = render_remote_kill_feedback(name, pid, kill_result, &pane_info, teardown)?;
    for line in lines {
        println!("{line}");
    }
    if result["pane_close_needs_pid"].as_bool() == Some(true) {
        println!("{PANE_NEEDS_PID}");
    }
    if pane_retry_command.is_some()
        && let Some((_, device)) = crate::relay::control::split_device_suffix(name)
    {
        eprintln!("Run the pane-close retry command on remote device {device}.");
    }
    Ok(
        if report_incomplete_pane_cleanup(
            match kill_result {
                "sent" => PaneCleanupProcessState::Terminated,
                "already_dead" => PaneCleanupProcessState::AlreadyDead,
                _ => PaneCleanupProcessState::NotTerminated,
            },
            pane_retry_command,
        ) {
            1
        } else {
            0
        },
    )
}

fn render_remote_kill_feedback(
    name: &str,
    pid: u64,
    kill_result: &str,
    pane_info: &str,
    teardown: TeardownOutcome,
) -> Result<Vec<String>> {
    // The skipped-teardown report for remote rows is exactly the local one.
    if let Some(lines) = render_skipped_teardown_feedback(name, teardown) {
        return Ok(lines);
    }
    match kill_result {
        "sent" => Ok(vec![
            format!(
                "Sent SIGTERM to process group {} for '{}'{}",
                pid, name, pane_info
            ),
            format!("  To resume: hcom r {}", name),
        ]),
        "already_dead" => Ok(vec![
            format!(
                "Process group {} not found for '{}' (already terminated){}",
                pid, name, pane_info
            ),
            format!("  To resume: hcom r {}", name),
        ]),
        other => bail!("Remote kill failed for {name}: unexpected kill_result {other}"),
    }
}

/// The self path never closes the pane that holds the excluded caller.
const PANE_LEFT_FOR_CALLER: &str = "  Pane left open by design: it holds the excluded caller.";

/// The pane's close command would need the dead seat's PID; nothing was run.
const PANE_NEEDS_PID: &str = "  Pane not closed: this terminal's close command needs a process ID, and the seat's process ID can no longer be used safely; close the pane manually.";

/// Format the self-path report: the plain stopped report plus the resume
/// hint. Rendered only after the captured non-self members are confirmed gone
/// and the teardown completed; the pane holding the caller stays open.
fn render_self_kill_feedback(name: &str, self_excluded: usize) -> Vec<String> {
    vec![
        format!(
            "{name}: stopped; bindings released. {self_excluded} process(es) in your own session were excluded from the signal (this command is one of them)."
        ),
        format!("  To resume: hcom r {name}"),
    ]
}

/// The CAS-skip report: the old incarnation's processes were reaped, but the
/// row was re-registered during the kill and left intact for the fresh
/// incarnation. Rendered instead of the stopped report on
/// [`TeardownOutcome::RowReRegistered`], on both the self and foreign paths —
/// the destructive intent on the old incarnation succeeded, so this is still
/// a plain success (exit 0).
fn render_re_registered_feedback(name: &str) -> Vec<String> {
    vec![format!(
        "{name}: prior processes reaped; the row was re-registered during this kill and was left intact."
    )]
}

/// The report for a kill whose teardown write did not land, or `None` when
/// it did. Shared by the local and remote render paths; every skip is a
/// plain success (exit 0). The self-stop reports: the kill reaped the
/// processes, but the session's own shutdown hook finalized its row during
/// the kill (soft stop kept it, hard stop deleted it) — nothing
/// re-registered.
fn render_skipped_teardown_feedback(name: &str, teardown: TeardownOutcome) -> Option<Vec<String>> {
    match teardown {
        TeardownOutcome::Completed => None,
        TeardownOutcome::RowReRegistered => Some(render_re_registered_feedback(name)),
        TeardownOutcome::SessionStoppedKeptRow => Some(vec![format!(
            "{name}: processes reaped; the session shut itself down during the kill and kept its row as a resume handle"
        )]),
        TeardownOutcome::SessionStoppedReleasedRow => Some(vec![format!(
            "{name}: processes reaped; the session shut itself down during the kill and released its row"
        )]),
    }
}

/// Run the kill command.
pub fn run(argv: &[String], flags: &GlobalFlags) -> Result<i32> {
    // Filter out global flags already consumed by the router
    let mut filtered = vec!["kill".to_string()];
    let mut skip_next = false;
    for arg in argv {
        if skip_next {
            skip_next = false;
            continue;
        }
        match arg.as_str() {
            "kill" | "--go" => continue,
            "--name" => {
                skip_next = true;
                continue;
            }
            _ => filtered.push(arg.clone()),
        }
    }

    use clap::Parser;
    let kill_args = match KillArgs::try_parse_from(&filtered) {
        Ok(a) => a,
        Err(e) => {
            e.print().ok();
            return Ok(if e.use_stderr() { 1 } else { 0 });
        }
    };

    let targets = kill_args.targets;
    if targets.is_empty() {
        eprintln!(
            "Error: no target specified\n\nUsage: kill <TARGET>...\n\nFor more information, try '--help'."
        );
        return Ok(1);
    }
    let explicit_name = flags.name.clone();

    let db = HcomDb::open()?;
    let hcom_dir = paths::hcom_dir();
    let initiator = resolve_initiator(&db, explicit_name.as_deref());

    // If any target is "all", just kill all
    if targets.iter().any(|t| t == "all") {
        return kill_all(&db, &hcom_dir, &initiator);
    }

    let kill_target = |target: &str| match target.strip_prefix("tag:") {
        Some(tag) => kill_by_tag(&db, &hcom_dir, tag, &initiator),
        None => kill_single(&db, &hcom_dir, target, &initiator),
    };
    // One target's failure is the command's error, as before. With several
    // targets, each one is reported independently and later ones still run.
    if let [target] = targets.as_slice() {
        return kill_target(target);
    }
    let mut worst_exit = 0;
    for target in &targets {
        let exit = kill_target(target).unwrap_or_else(|error| {
            eprintln!("Error: {error}");
            1
        });
        worst_exit = worst_exit.max(exit);
    }
    Ok(worst_exit)
}

/// Format pane close info
fn pane_info_str(pane_closed: bool, preset_name: &str, pane_id: &str) -> String {
    if pane_closed {
        if !pane_id.is_empty() {
            format!(" (closed {} pane {})", preset_name, pane_id)
        } else if !preset_name.is_empty() {
            format!(" (closed {} pane)", preset_name)
        } else {
            String::new()
        }
    } else if !preset_name.is_empty()
        && let Some(preset) = crate::config::get_merged_preset(preset_name)
        && preset.has_close(cfg!(windows))
    {
        if crate::terminal::is_zellij_merged(&preset) {
            return " (zellij pane close unconfirmed)".to_string();
        }
        format!(" (pane close failed for {})", preset_name)
    } else {
        String::new()
    }
}

fn verify_orphan_kill_owner(
    db: &HcomDb,
    orphan: &crate::pidtrack::OrphanProcess,
) -> Result<crate::proctruth::KillOwner, KillTrackedError> {
    let mut context = None;
    for name in &orphan.names {
        let snapshot = db
            .newest_stopped_snapshot(name)
            .map_err(|error| unverified_owner_error(name, orphan.pid, &error.to_string()))?;
        if let Some(snapshot) = snapshot
            && snapshot.get("pid").and_then(serde_json::Value::as_u64)
                == Some(u64::from(orphan.pid))
            && let Some(recorded) = snapshot
                .get("launch_context")
                .and_then(serde_json::Value::as_str)
        {
            context = Some(recorded.to_owned());
            break;
        }
    }
    let ids = std::slice::from_ref(&orphan.process_id);
    crate::proctruth::verify_kill_owner(orphan.pid, context.as_deref(), ids)
        .and_then(|owner| owner.resolve_root(Some(&orphan.tool), context.as_deref(), ids))
        .map_err(|reason| unverified_owner_error(&orphan.names.join(", "), orphan.pid, reason))
}

/// Every target form uses the same owner/root gate, native termination and
/// cleanup. Batch rows, bindings and the stop watermark share one snapshot.
fn kill_all(db: &HcomDb, hcom_dir: &std::path::Path, initiator: &str) -> Result<i32> {
    kill_selected(db, hcom_dir, None, initiator)
}

fn kill_by_tag(db: &HcomDb, hcom_dir: &std::path::Path, tag: &str, initiator: &str) -> Result<i32> {
    kill_selected(db, hcom_dir, Some(tag), initiator)
}

fn kill_selected(
    db: &HcomDb,
    hcom_dir: &std::path::Path,
    tag: Option<&str>,
    initiator: &str,
) -> Result<i32> {
    let (instances, watermark) = db.with_read_snapshot(|tx| {
        let instances = HcomDb::instances_with_bindings_in(tx)?;
        let watermark =
            tx.query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |r| r.get(0))?;
        Ok((instances, watermark))
    })?;
    let mut active_pids = HashSet::new();
    let mut selected = 0;
    let mut killed = 0;
    let mut failed = 0;
    let mut incomplete = 0;
    for (inst, binding_ids) in &instances {
        if inst.origin_device_id.is_some()
            || tag.is_some_and(|tag| inst.tag.as_deref() != Some(tag))
        {
            continue;
        }
        selected += 1;
        // A refused row must not fall through to the pidtrack orphan pass.
        if let Some(pid) = inst.pid.and_then(|pid| u32::try_from(pid).ok()) {
            active_pids.insert(pid);
        }
        let result = match kill_resolved_instance(
            db,
            inst,
            binding_ids,
            watermark,
            initiator,
            None,
            |_, _, _| Ok(()),
        ) {
            Ok(result) => result,
            Err(error) => {
                eprintln!("{error}");
                failed += 1;
                continue;
            }
        };
        if let Some(lines) = render_skipped_teardown_feedback(&inst.name, result.teardown) {
            for line in lines {
                println!("{line}");
            }
            if result.teardown == TeardownOutcome::RowReRegistered {
                failed += 1;
            }
            continue;
        }
        if result.self_excluded > 0 {
            for line in render_self_kill_feedback(&inst.name, result.self_excluded) {
                println!("{line}");
            }
            if result.pane_left_for_caller {
                println!("{PANE_LEFT_FOR_CALLER}");
            }
            killed += 1;
            continue;
        }
        let pane = pane_info_str(result.pane_closed, &result.preset_name, &result.pane_id);
        match result.kill_result {
            terminal::KillResult::Sent => {
                println!(
                    "Sent SIGTERM to process group {} for '{}'{}",
                    result.pid, inst.name, pane
                );
                killed += 1;
            }
            terminal::KillResult::AlreadyDead => {
                println!(
                    "Process group {} already terminated for '{}'",
                    result.pid, inst.name
                );
                killed += 1;
            }
            terminal::KillResult::PermissionDenied => {
                eprintln!(
                    "Permission denied to kill process group {} for '{}'",
                    result.pid, inst.name
                );
                failed += 1;
            }
        }
        if result.pane_close_needs_pid {
            println!("{PANE_NEEDS_PID}");
        }
        incomplete += report_incomplete_pane_cleanup(
            result.kill_result.into(),
            result.pane_retry_command.as_deref(),
        ) as i32;
        println!("  To resume: hcom r {}", inst.name);
    }

    for orphan in pidtrack::get_orphan_processes(hcom_dir, Some(&active_pids)) {
        if tag.is_some_and(|tag| orphan.tag != tag) {
            continue;
        }
        selected += 1;
        let owner = match verify_orphan_kill_owner(db, &orphan) {
            Ok(owner) => owner,
            Err(error) => {
                eprintln!("{error}");
                failed += 1;
                continue;
            }
        };
        let (result, _pane_closed, followup, self_excluded) =
            match kill_orphan_process(db, &owner, &orphan) {
                Ok(result) => result,
                Err(reason) => {
                    if reason.launcher_unverified.is_some() {
                        pidtrack::remove_pid(hcom_dir, orphan.pid);
                    }
                    eprintln!("{reason}");
                    failed += 1;
                    continue;
                }
            };
        if self_excluded {
            killed += 1;
            pidtrack::remove_pid(hcom_dir, orphan.pid);
            continue;
        }
        match result {
            terminal::KillResult::Sent | terminal::KillResult::AlreadyDead => {
                println!(
                    "Stopped process group {} for '{}'",
                    orphan.pid,
                    orphan.names.join(", ")
                );
                killed += 1;
            }
            terminal::KillResult::PermissionDenied => {
                eprintln!("Permission denied to kill process group {}", orphan.pid);
                failed += 1;
            }
        }
        if followup.needs_pid {
            println!("{PANE_NEEDS_PID}");
        }
        incomplete +=
            report_incomplete_pane_cleanup(result.into(), followup.retry_command.as_deref()) as i32;
        if matches!(
            result,
            terminal::KillResult::Sent | terminal::KillResult::AlreadyDead
        ) {
            pidtrack::remove_pid(hcom_dir, orphan.pid);
        }
    }
    if selected == 0 {
        if let Some(tag) = tag {
            eprintln!("No agents with tag '{tag}'");
            return Ok(1);
        }
        println!("No processes with tracked PIDs found");
    } else {
        println!("Killed {killed}, {failed} failed, {incomplete} with incomplete pane cleanup");
    }
    Ok(if failed > 0 || incomplete > 0 { 1 } else { 0 })
}

/// Kill a single instance by name.
fn kill_single(
    db: &HcomDb,
    hcom_dir: &std::path::Path,
    target: &str,
    initiator: &str,
) -> Result<i32> {
    // Fleet-first: a bare name that is live on one other device resolves to
    // that device's `x:DEV` form and falls into the remote branch below, an
    // ambiguous name is refused, and a name live nowhere keeps today's local
    // display-name lookup.
    let name = identity::cli_target(db, target).map_err(anyhow::Error::msg)?;

    let inst = match db.get_instance_full(&name)? {
        Some(inst) => inst,
        None => {
            // Check orphans
            let orphans = pidtrack::get_orphan_processes(hcom_dir, None);
            // Also match by PID number (TUI sends kill by PID for orphans)
            let target_pid = target.parse::<u32>().ok();
            if let Some(orphan) = orphans.iter().find(|o| {
                o.names.contains(&target.to_string())
                    || o.process_id == target
                    || target_pid == Some(o.pid)
            }) {
                let owner = verify_orphan_kill_owner(db, orphan).map_err(anyhow::Error::msg)?;
                let (result, pane_closed, followup, self_excluded) =
                    kill_orphan_process(db, &owner, orphan).map_err(|error| {
                        if error.launcher_unverified.is_some() {
                            pidtrack::remove_pid(hcom_dir, orphan.pid);
                        }
                        anyhow::Error::msg(error)
                    })?;
                if self_excluded {
                    pidtrack::remove_pid(hcom_dir, orphan.pid);
                    return Ok(0);
                }
                let pane_info =
                    pane_info_str(pane_closed, &orphan.terminal_preset, &orphan.pane_id);
                match result {
                    terminal::KillResult::Sent => {
                        println!(
                            "Sent SIGTERM to process group {} for stopped instance '{}'{}",
                            orphan.pid, target, pane_info
                        );
                    }
                    terminal::KillResult::AlreadyDead => {
                        println!(
                            "Process group {} not found for '{}' (already terminated){}",
                            orphan.pid, target, pane_info
                        );
                    }
                    terminal::KillResult::PermissionDenied => {
                        eprintln!("Permission denied to kill process group {}", orphan.pid);
                        return Ok(1);
                    }
                }
                if followup.needs_pid {
                    println!("{PANE_NEEDS_PID}");
                }
                if matches!(
                    result,
                    terminal::KillResult::Sent | terminal::KillResult::AlreadyDead
                ) {
                    pidtrack::remove_pid(hcom_dir, orphan.pid);
                }
                return Ok(
                    if report_incomplete_pane_cleanup(
                        result.into(),
                        followup.retry_command.as_deref(),
                    ) {
                        1
                    } else {
                        0
                    },
                );
            }
            // Fleet resolution already ran: no local row and no live row
            // anywhere, so today's not-found error stands.
            bail!("Agent '{}' not found", target);
        }
    };

    if inst.origin_device_id.is_some() {
        if let Some((base_name, device_short_id)) =
            crate::relay::control::split_device_suffix(&name)
        {
            let result = crate::relay::control::dispatch_remote_raw(
                db,
                device_short_id,
                Some(&name),
                "kill",
                &serde_json::json!({ "target": base_name }),
                crate::relay::control::RPC_DEFAULT_TIMEOUT,
            )
            .map_err(anyhow::Error::msg)?;
            return handle_remote_kill_response(&name, &result);
        }
        bail!("Cannot kill remote '{name}' - missing device suffix");
    }

    // A root-less row held only by orphans is not a dead end: stop releases
    // it without signalling them. Checked whatever the recorded pid: a dead
    // one must not reach the kill, whose group signal could hit orphans that
    // share the dead leader's process group.
    let binding_ids = db.process_binding_ids(&name).unwrap_or_default();
    if let Some(orphans) = crate::proctruth::orphaned_row_carriers(db, &inst, &binding_ids) {
        let pids = orphans
            .iter()
            .map(|o| o.pid.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let n = orphans.len();
        match inst.pid {
            None => bail!(
                "No tracked PID for '{name}', and no live process roots it: {n} orphaned process(es) carry only its identity ({pids}). Run 'hcom stop {name}' to release it; the orphans will not be signalled."
            ),
            Some(pid) => bail!(
                "'{name}' has no live process: its recorded pid {pid} is gone, and no live process roots it: {n} orphaned process(es) carry only its identity ({pids}). Run 'hcom stop {name}' to release it; the orphans will not be signalled."
            ),
        }
    }
    if inst.pid.is_none() {
        bail!(
            "No tracked PID for '{}' — use 'hcom stop {}' instead",
            name,
            name
        );
    }
    let kill_result = kill_tracked_instance(db, &name, initiator).map_err(anyhow::Error::msg)?;
    // Skipped teardown: the processes were reaped, but the kill's teardown
    // write did not land — the row was re-registered mid-kill (left intact
    // for the fresh incarnation) or the session's own shutdown finalized it.
    // Plain report, exit 0 — the destructive intent on the old incarnation
    // succeeded. Checked before the self report: it applies to both paths.
    if let Some(lines) = render_skipped_teardown_feedback(&name, kill_result.teardown) {
        for line in lines {
            println!("{line}");
        }
        return Ok(0);
    }
    // Self-kill: the caller ran inside the instance. The non-self carriers
    // were reaped first (fail closed on survivors — that error is returned
    // before any teardown) and only then was the row stopped and released.
    // The pane close is skipped (it is the caller's own pane) — plain
    // report, exit 0.
    if kill_result.self_excluded > 0 {
        for line in render_self_kill_feedback(&name, kill_result.self_excluded) {
            println!("{line}");
        }
        if kill_result.pane_left_for_caller {
            println!("{PANE_LEFT_FOR_CALLER}");
        }
        return Ok(0);
    }
    let pid = kill_result.pid;
    let pane_closed = kill_result.pane_closed;
    let preset_name = kill_result.preset_name;
    let pane_id = kill_result.pane_id;
    let pane_retry_command = kill_result.pane_retry_command;
    let result = kill_result.kill_result;

    let pane_info = pane_info_str(pane_closed, &preset_name, &pane_id);
    let exit = match result {
        terminal::KillResult::Sent => {
            println!(
                "Sent SIGTERM to process group {} for '{}'{}",
                pid, name, pane_info
            );
            println!("  To resume: hcom r {}", name);
            0
        }
        terminal::KillResult::AlreadyDead => {
            println!(
                "Process group {} not found for '{}' (already terminated){}",
                pid, name, pane_info
            );
            println!("  To resume: hcom r {}", name);
            0
        }
        terminal::KillResult::PermissionDenied => {
            eprintln!(
                "Permission denied to kill process group {} for '{}'",
                pid, name
            );
            1
        }
    };
    if kill_result.pane_close_needs_pid {
        println!("{PANE_NEEDS_PID}");
    }
    Ok(
        if report_incomplete_pane_cleanup(result.into(), pane_retry_command.as_deref()) {
            1
        } else {
            exit
        },
    )
}

/// The terminal metadata of a tracked orphan, for [`terminal::kill_process`].
fn orphan_terminal_info(orphan: &crate::pidtrack::OrphanProcess) -> terminal::TerminalInfo {
    terminal::TerminalInfo {
        preset_name: orphan.terminal_preset.clone(),
        pane_id: orphan.pane_id.clone(),
        process_id: orphan.process_id.clone(),
        kitty_listen_on: orphan.kitty_listen_on.clone(),
        terminal_id: orphan.terminal_id.clone(),
        zellij_session_name: orphan.zellij_session_name.clone(),
    }
}

fn kill_orphan_process(
    db: &HcomDb,
    owner: &crate::proctruth::KillOwner,
    orphan: &crate::pidtrack::OrphanProcess,
) -> Result<(terminal::KillResult, bool, terminal::PaneFollowup, bool), KillTrackedError> {
    let name = orphan.names.join(", ");
    let chain = crate::proctruth::kill_caller_ancestor_pids()
        .map_err(|reason| unverified_owner_error(&name, orphan.pid, reason))?;
    let self_excluded = chain.contains(&owner.pid());
    if owner.is_zombie()
        && let Some(identity) = owner.identity()
    {
        let leftovers = crate::sys::process::terminate_zombie_group_verified(
            orphan.pid,
            identity,
            &chain,
            crate::proctruth::kill_candidate_eligible,
            |candidate| crate::proctruth::verify_kill_candidate(db, &name, candidate),
        )
        .map_err(|error| native_kill_error(&name, error))?;
        println!(
            "'{name}' owner PID {} already exited; {leftovers} leftover process(es) terminated",
            orphan.pid
        );
    }
    // Gone and zombie owners recheck false, so this sends them no signal; every
    // mode still runs the receipt-verified pane close after confirmation.
    let result = terminal::kill_process(
        owner,
        &orphan.names,
        std::slice::from_ref(&orphan.process_id),
        &chain,
        &orphan_terminal_info(orphan),
        |candidate| crate::proctruth::verify_kill_candidate(db, &name, candidate),
    )
    .map_err(|error| native_kill_error(&name, error))?;
    let pane = PaneOutcome {
        closed: result.1,
        retry_command: result.2.retry_command.clone(),
        needs_pid: result.2.needs_pid,
        preset_name: orphan.terminal_preset.clone(),
        pane_id: orphan.pane_id.clone(),
        left_for_caller: self_excluded && !orphan.terminal_preset.is_empty() && !result.1,
    };
    if let Some(warning) = owner.launcher_warning() {
        return Err(launcher_unverified_error(&name, warning, self_excluded).with_pane(pane));
    }
    if self_excluded {
        println!(
            "'{name}': caller PID {} and its own ancestor chain were left running by design; owner/root death is not claimed",
            std::process::id()
        );
        if pane.left_for_caller {
            println!("{PANE_LEFT_FOR_CALLER}");
        }
    }
    Ok((result.0, result.1, result.2, self_excluded))
}

/// Kill a process and close its terminal pane.
/// Returns (KillResult, pane_closed, pane follow-up, preset_name, pane_id).
fn kill_instance(
    db: &HcomDb,
    name: &str,
    owner: &crate::proctruth::KillOwner,
    instance: &crate::db::InstanceRow,
    is_headless: bool,
    binding_ids: &[String],
    excluded: &[u32],
) -> Result<
    (
        terminal::KillResult,
        bool,
        terminal::PaneFollowup,
        String,
        String,
    ),
    KillTrackedError,
> {
    let pid = owner.pid();
    // Headless instances have no terminal pane — skip pane close
    if is_headless {
        let (result, pane_closed, followup) = terminal::kill_process(
            owner,
            &[],
            binding_ids,
            excluded,
            &terminal::TerminalInfo::default(),
            |candidate| crate::proctruth::verify_kill_candidate(db, name, candidate),
        )
        .map_err(|error| native_kill_error(name, error))?;
        log_info(
            "kill",
            "lifecycle.kill",
            &format!(
                "name={} pid={} result={:?} pane_closed={} headless=true",
                name, pid, result, pane_closed
            ),
        );
        return Ok((result, pane_closed, followup, String::new(), String::new()));
    }

    let ti = terminal::resolve_terminal_info(
        instance.terminal_preset_effective.as_deref(),
        instance.launch_context.as_deref(),
    );

    let (result, pane_closed, followup) = terminal::kill_process(
        owner,
        std::slice::from_ref(&instance.name),
        binding_ids,
        excluded,
        &ti,
        |candidate| crate::proctruth::verify_kill_candidate(db, name, candidate),
    )
    .map_err(|error| native_kill_error(name, error))?;

    log_info(
        "kill",
        "lifecycle.kill",
        &format!(
            "name={} pid={} result={:?} pane_closed={}",
            name, pid, result, pane_closed
        ),
    );

    Ok((
        result,
        pane_closed,
        followup,
        ti.preset_name.clone(),
        ti.pane_id.clone(),
    ))
}

#[cfg(test)]
mod tests;
