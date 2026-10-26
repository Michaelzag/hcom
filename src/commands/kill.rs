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
    /// Carriers spared because they are the caller's own session tree
    /// (kill self-path only; 0 on the foreign path).
    pub self_excluded: usize,
    /// Whether the resolved incarnation's row was actually torn down.
    pub teardown: TeardownOutcome,
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

const EPERM_RECHECK_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

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

fn normalize_kill_result(
    name: &str,
    pid: u32,
    result: terminal::KillResult,
    pane_closed: bool,
) -> terminal::KillResult {
    if !matches!(result, terminal::KillResult::PermissionDenied) {
        return result;
    }

    let pid_str = pid.to_string();
    log_info(
        "kill",
        "kill.eperm",
        &format!(
            "kill(2) returned EPERM for name={} pid={}; checking if process already exited",
            name, pid
        ),
    );
    if pane_closed {
        log_info(
            "kill",
            "kill.eperm_resolved",
            &format!(
                "name={} pid={} resolved to already_dead because terminal pane closed",
                name, pid_str
            ),
        );
        return terminal::KillResult::AlreadyDead;
    }

    std::thread::sleep(EPERM_RECHECK_DELAY);
    if !pidtrack::is_alive(pid) {
        log_info(
            "kill",
            "kill.eperm_resolved",
            &format!("name={} pid={} resolved to already_dead", name, pid_str),
        );
        terminal::KillResult::AlreadyDead
    } else {
        terminal::KillResult::PermissionDenied
    }
}

pub fn kill_tracked_instance(
    db: &HcomDb,
    name: &str,
    initiator: &str,
) -> Result<KillTrackedResult, String> {
    kill_tracked_instance_with_self_pids(
        db,
        name,
        initiator,
        &crate::proctruth::caller_ancestor_pids(),
        |n, b, e, capture| {
            crate::proctruth::reap_instance_tree_for_excluding_captured(db, n, b, e, capture)
        },
    )
}

/// [`kill_tracked_instance`] with an injectable self set and reap:
/// production passes [`crate::proctruth::caller_ancestor_pids`] and the real
/// [`crate::proctruth::reap_instance_tree_for_excluding_captured`]; tests
/// pass a fake set holding a sleeper pid plus the real caller pid, and a reap
/// that can mutate the row mid-kill (the teardown CAS seam).
#[allow(clippy::too_many_arguments)]
fn kill_tracked_instance_with_self_pids(
    db: &HcomDb,
    name: &str,
    initiator: &str,
    self_pids: &[u32],
    reap: impl FnOnce(
        &str,
        &[String],
        &[u32],
        crate::proctruth::ReapCapture,
    ) -> Result<(), crate::proctruth::ReapError>,
) -> Result<KillTrackedResult, String> {
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
        self_pids,
        reap,
    )
}

#[allow(clippy::too_many_arguments)]
fn kill_resolved_instance(
    db: &HcomDb,
    inst: &crate::db::InstanceRow,
    binding_ids: &[String],
    event_watermark: i64,
    initiator: &str,
    self_pids: &[u32],
    reap: impl FnOnce(
        &str,
        &[String],
        &[u32],
        crate::proctruth::ReapCapture,
    ) -> Result<(), crate::proctruth::ReapError>,
) -> Result<KillTrackedResult, String> {
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

    // The incarnation this kill resolves against: the row as read plus its
    // binding epoch, and the events watermark read with them. Captured
    // BEFORE any signal; the teardown below runs only while this exact
    // incarnation is still the row's.
    let incarnation = ResolvedIncarnation::new(inst, binding_ids, event_watermark);
    let _teardown_claim = crate::hooks::common::TeardownClaim::register(
        db,
        name,
        incarnation.token.created_at,
        incarnation.token.session_id.as_deref(),
    );
    // A dead leader's group may outlive it or be reused independently. Never
    // signal that group or reap through it; only finalize this incarnation.
    if owner.identity().is_none() {
        let capture = crate::proctruth::gone_kill_capture(inst, binding_ids);
        reap(name, binding_ids, &[], capture).map_err(|error| survivors_error(name, &error))?;
        let teardown = teardown_if_incarnation_unchanged(db, name, initiator, &incarnation)?;
        return Ok(KillTrackedResult {
            target: name.to_owned(),
            pid,
            kill_result: terminal::KillResult::AlreadyDead,
            pane_closed: false,
            pane_retry_command: None,
            preset_name: String::new(),
            pane_id: String::new(),
            self_excluded: 0,
            teardown,
        });
    }

    // Self-kill check BEFORE any signal: when the caller runs inside the
    // instance it is killing, the carrier set holds the caller's own session
    // tree — signalling it would kill this command mid-run and lose the
    // `stopped` write. That path spares the caller's tree (`excluded` below),
    // reaps every other eligible carrier FIRST, and fails closed: the row and
    // bindings are torn down only once no in-scope non-self carrier remains.
    let self_set: HashSet<u32> = self_pids.iter().copied().collect();
    let owners = crate::proctruth::omp_owner_bindings(db, name);
    let mut excluded: Vec<u32> =
        crate::proctruth::processes_for_instance(name, binding_ids, &owners)
            .into_iter()
            .map(|m| m.pid)
            .filter(|p| self_set.contains(p))
            .collect();
    // Native ancestry is available even where /proc carrier enumeration is
    // not. Never terminate the verified interpreter above this kill command.
    if self_set.contains(&pid) && !excluded.contains(&pid) {
        excluded.push(pid);
    }
    // Capture identity, owner ancestry, and the first carrier set before
    // kill_instance signals the recorded process group. Its root may die and
    // reparent eligible descendants before reap begins. Built from the same
    // snapshot as the incarnation above.
    // The capture is also the gate: a refusal returns before `kill_instance`
    // closes the pane or signals the group, and before the reap, leaving the
    // row and its bindings untouched (the teardown claim above is dropped
    // with the early return).
    let capture = crate::proctruth::capture_reap_carriers(
        db,
        name,
        Some(inst),
        binding_ids,
        &owners,
        &excluded,
    )
    .map_err(|error| unverified_owner_error(name, pid, &error.to_string()))?;
    if !excluded.is_empty() {
        return kill_self_tracked_instance(
            db,
            name,
            initiator,
            pid,
            binding_ids,
            &excluded,
            &incarnation,
            capture,
            reap,
        );
    }

    let is_headless = inst.background != 0;
    let (result, pane_closed, pane_retry_command, preset_name, pane_id) =
        kill_instance(db, name, &owner, inst, is_headless)?;
    // Fail-closed ordering, shared with the self path: reap and verify the
    // captured in-scope carrier set FIRST — a survivor fails the kill with
    // the row and bindings untouched — and only then run the teardown write,
    // only while the resolved incarnation is still the row's (see
    // [`teardown_if_incarnation_unchanged`]).
    if let Err(survivors) = reap(name, binding_ids, &[], capture) {
        return Err(survivors_error(name, &survivors));
    }
    let teardown =
        teardown_if_incarnation_unchanged(db, name, initiator, &incarnation).map_err(|error| {
            let process_state = if pidtrack::is_alive(pid) {
                "was signalled"
            } else {
                "is dead"
            };
            format!(
                "Process {pid} {process_state}, but '{name}' row was not finalized: {error}. \
                 Recovery: hcom kill {name}"
            )
        })?;

    Ok(KillTrackedResult {
        target: name.to_string(),
        pid,
        kill_result: result,
        pane_closed,
        pane_retry_command,
        preset_name,
        pane_id,
        self_excluded: 0,
        teardown,
    })
}

fn unverified_owner_error(name: &str, pid: u32, reason: &str) -> String {
    format!(
        "Refusing to signal PID {pid} for '{name}': {reason}; no signal sent to the unverified process. \
         hcom stop {name} clears the bookkeeping."
    )
}

/// A refused reap leaves the row and bindings available for a retry.
fn survivors_error(name: &str, error: &crate::proctruth::ReapError) -> String {
    format!("could not stop {name}: {error} — run hcom kill {name} first")
}

/// A refused capture names the other owner and leaves the row and its
/// bindings alone: there is no `hcom kill <name>` retry to run.
fn refused_capture_error(name: &str, error: &crate::proctruth::ReapError) -> String {
    format!("could not stop {name}: {error} — hcom stop {name} clears the bookkeeping")
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

/// Kill the instance the caller runs inside — fail-closed: reap first, then
/// teardown. The foreign path's reap gate would signal the caller itself, so
/// the carriers outside `excluded` (the caller's own session tree) are
/// reaped here instead — and the row and bindings stay completely untouched
/// until that reap is verified clean. A non-self survivor after the signal
/// budget fails the whole kill with the foreign path's error (survivors
/// listed), so a failed reap is never converted into a successful exit after
/// ownership state is discarded: a kill never reports stopped or releases
/// the row/bindings while any instance process may still be alive. Only the
/// verified-clean reap over an UNCHANGED incarnation unlocks the shared
/// teardown ([`stop_instance_without_reap`]) that writes `stopped` and
/// releases the bindings — a row re-registered mid-kill is left intact (the
/// fresh incarnation is not this kill's business). The terminal group kill /
/// pane close is skipped: the pane is the caller's own, and its group signal
/// would land on this command.
#[allow(clippy::too_many_arguments)]
fn kill_self_tracked_instance(
    db: &HcomDb,
    name: &str,
    initiator: &str,
    pid: u32,
    binding_ids: &[String],
    excluded: &[u32],
    incarnation: &ResolvedIncarnation,
    capture: crate::proctruth::ReapCapture,
    reap: impl FnOnce(
        &str,
        &[String],
        &[u32],
        crate::proctruth::ReapCapture,
    ) -> Result<(), crate::proctruth::ReapError>,
) -> Result<KillTrackedResult, String> {
    // Signal and verify the non-self carriers FIRST. On survivors: bail
    // exactly like the foreign path, before touching the row or bindings.
    if let Err(survivors) = reap(name, binding_ids, excluded, capture) {
        return Err(survivors_error(name, &survivors));
    }
    let teardown =
        teardown_if_incarnation_unchanged(db, name, initiator, incarnation).map_err(|error| {
            format!(
                "Non-self processes stopped, but '{name}' row was not finalized: {error}. \
                 Recovery: hcom kill {name}"
            )
        })?;
    Ok(KillTrackedResult {
        target: name.to_string(),
        pid,
        kill_result: terminal::KillResult::AlreadyDead,
        pane_closed: false,
        pane_retry_command: None,
        preset_name: String::new(),
        pane_id: String::new(),
        self_excluded: excluded.len(),
        teardown,
    })
}

fn handle_remote_kill_response(name: &str, response: &serde_json::Value) -> Result<i32> {
    let result = &response["result"];
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

    // Skipped teardown first, mirroring the local path (it takes precedence
    // over every kill_result report there too): plain report, exit 0.
    if let Some(lines) = render_skipped_teardown_feedback(name, teardown) {
        for line in lines {
            println!("{line}");
        }
        return Ok(0);
    }

    if kill_result == "permission_denied" {
        eprintln!(
            "Permission denied to kill process group {} for '{}'",
            pid, name
        );
        return Ok(1);
    }

    let lines = render_remote_kill_feedback(name, pid, kill_result, &pane_info, teardown)?;
    for line in lines {
        println!("{line}");
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

/// Format the self-path report: the plain stopped report plus the resume
/// hint. Rendered only after a verified-clean non-self reap and the
/// completed teardown — the pane close is skipped (the pane is the caller's
/// own), so this is the whole CLI contract of a self kill.
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

    let mut worst_exit = 0;
    for target in &targets {
        let outcome = if let Some(tag) = target.strip_prefix("tag:") {
            kill_by_tag(&db, &hcom_dir, tag, &initiator)
        } else {
            kill_single(&db, &hcom_dir, target, &initiator)
        };
        let exit = match outcome {
            Ok(exit) => exit,
            Err(error) => {
                eprintln!("Error: {error}");
                1
            }
        };
        if exit > worst_exit {
            worst_exit = exit;
        }
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

/// Reap an orphan's carrier set after its process-group signal: every name
/// it holds, by name or (self-bound trees) by its process id. Returns true
/// when anything survived — the caller must keep the pidtrack handle so a
/// retry can rediscover the orphan.
fn reap_orphan_tree(
    db: &HcomDb,
    orphan: &crate::pidtrack::OrphanProcess,
    captures: Vec<(String, crate::proctruth::ReapCapture)>,
) -> bool {
    let ids: &[String] = if orphan.process_id.is_empty() {
        &[]
    } else {
        std::slice::from_ref(&orphan.process_id)
    };
    let mut survived = false;
    for (orphan_name, capture) in captures {
        if let Err(survivors) = crate::proctruth::reap_instance_tree_for_excluding_captured(
            db,
            &orphan_name,
            ids,
            &[],
            capture,
        ) {
            eprintln!("{}", survivors_error(&orphan_name, &survivors));
            survived = true;
        }
    }
    survived
}

fn capture_orphan_carriers(
    db: &HcomDb,
    orphan: &crate::pidtrack::OrphanProcess,
) -> Result<Vec<(String, crate::proctruth::ReapCapture)>, crate::proctruth::ReapError> {
    let mut captures = Vec::new();
    for name in &orphan.names {
        let (row, binding_ids) = db.get_instance_with_bindings(name).unwrap_or_default();
        let owners = crate::proctruth::omp_owner_bindings(db, name);
        captures.push((
            name.clone(),
            crate::proctruth::capture_reap_carriers(
                db,
                name,
                row.as_ref(),
                &binding_ids,
                &owners,
                &[],
            )?,
        ));
    }
    Ok(captures)
}

fn verify_orphan_kill_owner(
    db: &HcomDb,
    orphan: &crate::pidtrack::OrphanProcess,
) -> Result<crate::proctruth::KillOwner, String> {
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
        .map_err(|reason| unverified_owner_error(&orphan.names.join(", "), orphan.pid, reason))
}

/// Every target form uses the same owner gate, reap and incarnation-bound
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
    let self_pids = crate::proctruth::caller_ancestor_pids();
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
        if inst.pid.is_none() {
            let incarnation = ResolvedIncarnation::new(inst, binding_ids, watermark);
            match teardown_if_incarnation_unchanged(db, &inst.name, initiator, &incarnation) {
                Ok(TeardownOutcome::RowReRegistered) => {
                    eprintln!("{}", crate::hooks::common::skipped_stop_line(&inst.name));
                    failed += 1;
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Error releasing '{}': {error}", inst.name);
                    failed += 1;
                }
            }
            continue;
        }
        let result = match kill_resolved_instance(
            db,
            inst,
            binding_ids,
            watermark,
            initiator,
            &self_pids,
            |name, ids, exclude, capture| {
                crate::proctruth::reap_instance_tree_for_excluding_captured(
                    db, name, ids, exclude, capture,
                )
            },
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
        let captures = if owner.identity().is_some() {
            match capture_orphan_carriers(db, &orphan) {
                Ok(captures) => captures,
                Err(error) => {
                    eprintln!(
                        "{}",
                        refused_capture_error(&orphan.names.join(", "), &error)
                    );
                    failed += 1;
                    continue;
                }
            }
        } else {
            Vec::new()
        };
        let (result, pane_closed, retry) =
            match terminal::kill_process(&owner, &orphan.names, &orphan_terminal_info(&orphan)) {
                Ok(result) => result,
                Err(reason) => {
                    eprintln!(
                        "{}",
                        unverified_owner_error(&orphan.names.join(", "), orphan.pid, &reason)
                    );
                    failed += 1;
                    continue;
                }
            };
        let result =
            normalize_kill_result(&orphan.names.join(", "), orphan.pid, result, pane_closed);
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
        incomplete += report_incomplete_pane_cleanup(result.into(), retry.as_deref()) as i32;
        if reap_orphan_tree(db, &orphan, captures) {
            failed += 1;
        } else {
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
                // A refused capture returns before `kill_process` closes the
                // pane or signals the group; the pidtrack handle stays so a
                // retry can rediscover the orphan.
                let owner = verify_orphan_kill_owner(db, orphan).map_err(anyhow::Error::msg)?;
                let pre_capture = if owner.identity().is_some() {
                    capture_orphan_carriers(db, orphan)
                        .map_err(|e| anyhow::Error::msg(refused_capture_error(target, &e)))?
                } else {
                    Vec::new()
                };
                let (result, pane_closed, pane_retry_command) =
                    terminal::kill_process(&owner, &orphan.names, &orphan_terminal_info(orphan))
                        .map_err(|reason| {
                            anyhow::Error::msg(unverified_owner_error(target, orphan.pid, &reason))
                        })?;
                let result = normalize_kill_result(target, orphan.pid, result, pane_closed);
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
                // The group signal covers the recorded pid; reap any other
                // live processes still holding the orphan's names — by name
                // or, for self-bound trees, by its process id — so the
                // kill is verified whole-instance, not single-pid.
                let reap_failed = reap_orphan_tree(db, orphan, pre_capture);
                // Keep the pidtrack handle while survivors live: it is the
                // only handle by which a retry can rediscover this orphan.
                // Dropping it on reap failure would force a hand-kill from
                // the error text.
                if !reap_failed {
                    pidtrack::remove_pid(hcom_dir, orphan.pid);
                }
                return Ok(
                    if reap_failed
                        || report_incomplete_pane_cleanup(
                            result.into(),
                            pane_retry_command.as_deref(),
                        )
                    {
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

/// Kill a process and close its terminal pane.
/// Returns (KillResult, pane_closed, pane_retry_command, preset_name, pane_id).
fn kill_instance(
    _db: &HcomDb,
    name: &str,
    owner: &crate::proctruth::KillOwner,
    instance: &crate::db::InstanceRow,
    is_headless: bool,
) -> Result<(terminal::KillResult, bool, Option<String>, String, String), String> {
    let pid = owner.pid();
    // Headless instances have no terminal pane — skip pane close
    if is_headless {
        let (result, pane_closed, pane_retry_command) =
            terminal::kill_process(owner, &[], &terminal::TerminalInfo::default())
                .map_err(|reason| unverified_owner_error(name, pid, &reason))?;
        let result = normalize_kill_result(name, pid, result, pane_closed);
        log_info(
            "kill",
            "lifecycle.kill",
            &format!(
                "name={} pid={} result={:?} pane_closed={} headless=true",
                name, pid, result, pane_closed
            ),
        );
        return Ok((
            result,
            pane_closed,
            pane_retry_command,
            String::new(),
            String::new(),
        ));
    }

    let ti = terminal::resolve_terminal_info(
        instance.terminal_preset_effective.as_deref(),
        instance.launch_context.as_deref(),
    );

    let (result, pane_closed, pane_retry_command) =
        terminal::kill_process(owner, std::slice::from_ref(&instance.name), &ti)
            .map_err(|reason| unverified_owner_error(name, pid, &reason))?;
    let result = normalize_kill_result(name, pid, result, pane_closed);

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
        pane_retry_command,
        ti.preset_name.clone(),
        ti.pane_id.clone(),
    ))
}

#[cfg(test)]
mod tests;
