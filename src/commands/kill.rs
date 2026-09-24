//! Kill command: `hcom kill <name(s)|all|tag:X>`
//!
//!
//! Sends SIGTERM to process groups and optionally closes terminal panes.

use std::collections::HashSet;

use crate::db::HcomDb;
use crate::hooks::common::{StopOutcome, stop_instance, stop_instance_without_reap};
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
    binding_ids: Vec<String>,
}

impl IncarnationToken {
    fn capture(row: &crate::db::InstanceRow, binding_ids: &[String]) -> Self {
        Self::new(row.created_at, row.session_id.clone(), binding_ids.to_vec())
    }

    fn new(created_at: f64, session_id: Option<String>, binding_ids: Vec<String>) -> Self {
        let mut ids = binding_ids;
        ids.sort();
        ids.dedup();
        Self {
            created_at,
            session_id,
            binding_ids: ids,
        }
    }
}

/// What a kill resolved against, captured together before any signal: the
/// [`IncarnationToken`] the teardown CAS compares, plus the events
/// watermark (`MAX(events.id)` at capture time). The watermark is never part
/// of the CAS; it only scopes the lost-CAS classification to `stopped`
/// events written after the kill resolved its target (see
/// [`classify_lost_teardown`]).
struct ResolvedIncarnation {
    token: IncarnationToken,
    event_watermark: i64,
}

impl ResolvedIncarnation {
    fn capture(db: &HcomDb, row: &crate::db::InstanceRow, binding_ids: &[String]) -> Result<Self> {
        let event_watermark =
            db.conn()
                .query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |r| r.get(0))?;
        Ok(Self {
            token: IncarnationToken::capture(row, binding_ids),
            event_watermark,
        })
    }
}

const EPERM_RECHECK_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

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
/// [`crate::proctruth::reap_instance_tree_for_excluding`]; tests pass a fake
/// set holding a sleeper pid plus the real caller pid, and a reap that can
/// mutate the row mid-kill (the teardown CAS seam).
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
    let inst = db
        .get_instance_full(name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Agent '{}' not found", name))?;
    let pid = inst
        .pid
        .ok_or_else(|| format!("No tracked PID for '{}'", name))? as u32;
    let binding_ids = db.process_binding_ids(name).map_err(|e| e.to_string())?;

    // The incarnation this kill resolves against: the row as read plus its
    // binding epoch, and the events watermark read with it. Captured BEFORE
    // any signal; the teardown below runs only while this exact incarnation
    // is still the row's.
    let incarnation =
        ResolvedIncarnation::capture(db, &inst, &binding_ids).map_err(|e| e.to_string())?;
    let _teardown_claim = crate::hooks::common::TeardownClaim::register(
        db,
        name,
        incarnation.token.created_at,
        incarnation.token.session_id.as_deref(),
    );

    // Self-kill check BEFORE any signal: when the caller runs inside the
    // instance it is killing, the carrier set holds the caller's own session
    // tree — signalling it would kill this command mid-run and lose the
    // `stopped` write. That path spares the caller's tree (`excluded` below),
    // reaps every other eligible carrier FIRST, and fails closed: the row and
    // bindings are torn down only once no in-scope non-self carrier remains.
    let self_set: HashSet<u32> = self_pids.iter().copied().collect();
    let excluded: Vec<u32> = crate::proctruth::processes_for_instance(name, &binding_ids)
        .into_iter()
        .map(|m| m.pid)
        .filter(|p| self_set.contains(p))
        .collect();
    // Capture identity, owner ancestry, and the first carrier set before
    // kill_instance signals the recorded process group. Its root may die and
    // reparent eligible descendants before reap begins.
    let capture = crate::proctruth::capture_reap_carriers(db, name, &binding_ids, &excluded);
    if !excluded.is_empty() {
        return kill_self_tracked_instance(
            db,
            name,
            initiator,
            pid,
            &binding_ids,
            &excluded,
            &incarnation,
            capture,
            reap,
        );
    }

    let is_headless = inst.background != 0;
    let (result, pane_closed, pane_retry_command, preset_name, pane_id) =
        kill_instance(db, name, pid, &inst, is_headless);
    // Fail-closed ordering, shared with the self path: reap and verify the
    // captured in-scope carrier set FIRST — a survivor fails the kill with
    // the row and bindings untouched — and only then run the teardown write,
    // only while the resolved incarnation is still the row's (see
    // [`teardown_if_incarnation_unchanged`]).
    if let Err(survivors) = reap(name, &binding_ids, &[], capture) {
        return Err(survivors_error(name, &survivors));
    }
    let teardown = teardown_if_incarnation_unchanged(db, name, initiator, &incarnation)?;

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

/// A refused reap leaves the row and bindings available for a retry.
fn survivors_error(name: &str, error: &crate::proctruth::ReapError) -> String {
    format!("could not stop {name}: {error} — run hcom kill {name} first")
}

/// Re-read the incarnation token of `name` through the teardown transaction;
/// None when the row is gone. The ONLY incarnation read allowed to decide —
/// any read outside the transaction leaves a check/use gap.
fn read_incarnation_tx(
    tx: &rusqlite::Transaction<'_>,
    name: &str,
) -> Result<Option<IncarnationToken>> {
    use rusqlite::OptionalExtension;
    let row: Option<(f64, Option<String>)> = tx
        .query_row(
            "SELECT created_at, session_id FROM instances WHERE name = ?1",
            rusqlite::params![name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((created_at, session_id)) = row else {
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
/// transaction. A session hook already running before the claim, or the
/// PTY wrapper's exit cleanup (`by = pty`, see
/// `delivery::cleanup_deleted_instance`), may finalize the row while the
/// kill runs. That is a self-stop, not a re-registration: a `life`/`stopped`
/// event by one of those for
/// this instance written after the kill resolved its target (id above the
/// watermark), keyed to one of the resolved bindings — or, when no process
/// is named, carrying the resolved incarnation's `created_at` in its
/// snapshot (the same identity the CAS compares, so a re-registered
/// bindingless incarnation finalizing mid-kill is not mistaken for the
/// session) — and not a `stale-harness-exit` (a stale harness declining to
/// touch a rebound row). Then a gone row was released by the session, and a
/// row with the same `created_at` + `session_id` whose bindings only shrank
/// was kept by it. Anything else — no such event, a new identity, or any
/// binding the kill never resolved — is a genuine re-registration.
/// `current` is the incarnation the CAS just read in this transaction.
fn classify_lost_teardown(
    tx: &rusqlite::Transaction<'_>,
    name: &str,
    incarnation: &ResolvedIncarnation,
    current: Option<IncarnationToken>,
) -> Result<TeardownOutcome> {
    let token = &incarnation.token;
    let mut stmt = tx.prepare(
        "SELECT json_extract(data, '$.process_id'), \
                json_extract(data, '$.snapshot.created_at') FROM events \
         WHERE type = 'life' AND instance = ?1 AND id > ?2 \
           AND json_extract(data, '$.action') = 'stopped' \
           AND json_extract(data, '$.by') IN ('session', 'pty') \
           AND COALESCE(json_extract(data, '$.reason'), '') != 'stale-harness-exit'",
    )?;
    let mut process_ids = stmt
        .query_map(rusqlite::params![name, incarnation.event_watermark], |r| {
            Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<f64>>(1)?))
        })?;
    let mut self_stop = false;
    for row in &mut process_ids {
        let (process_id, snapshot_created_at) = row?;
        let matches = match process_id {
            Some(id) => token.binding_ids.contains(&id),
            // A null process_id is not proof on its own: the event must
            // carry the RESOLVED incarnation's created_at. A re-registered
            // bindingless incarnation snapshots its OWN created_at, so its
            // exit is a re-registration, not a self-stop.
            None => snapshot_created_at == Some(token.created_at),
        };
        if matches {
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
            if current.created_at == token.created_at
                && current.session_id == token.session_id
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
    let teardown = teardown_if_incarnation_unchanged(db, name, initiator, incarnation)?;
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
        let exit = if let Some(tag) = target.strip_prefix("tag:") {
            kill_by_tag(&db, &hcom_dir, tag, &initiator)?
        } else {
            kill_single(&db, &hcom_dir, target, &initiator)?
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
fn reap_orphan_tree(db: &HcomDb, orphan: &crate::pidtrack::OrphanProcess) -> bool {
    let ids: &[String] = if orphan.process_id.is_empty() {
        &[]
    } else {
        std::slice::from_ref(&orphan.process_id)
    };
    let mut survived = false;
    for orphan_name in &orphan.names {
        if let Err(survivors) = crate::proctruth::reap_instance_tree_for(db, orphan_name, ids) {
            eprintln!("{}", survivors_error(orphan_name, &survivors));
            survived = true;
        }
    }
    survived
}

/// Kill all instances.
fn kill_all(db: &HcomDb, hcom_dir: &std::path::Path, initiator: &str) -> Result<i32> {
    let instances = db.iter_instances_full()?;
    let mut killed = 0;
    let mut failed = 0;
    let mut incomplete = 0;

    // Collect active PIDs for orphan filtering
    let mut active_pids = HashSet::new();

    for inst in &instances {
        // Skip remote instances
        if inst.origin_device_id.is_some() {
            continue;
        }

        if let Some(pid) = inst.pid {
            active_pids.insert(pid as u32);
            let is_headless = inst.background != 0;
            let (result, pane_closed, pane_retry_command, preset_name, pane_id) =
                kill_instance(db, &inst.name, pid as u32, inst, is_headless);
            let pane_info = pane_info_str(pane_closed, &preset_name, &pane_id);
            match result {
                terminal::KillResult::Sent => {
                    println!(
                        "Sent SIGTERM to process group {} for '{}'{}",
                        pid, inst.name, pane_info
                    );
                    killed += 1;
                }
                terminal::KillResult::AlreadyDead => {
                    println!(
                        "Process group {} not found for '{}' (already terminated){}",
                        pid, inst.name, pane_info
                    );
                    killed += 1;
                }
                terminal::KillResult::PermissionDenied => {
                    eprintln!(
                        "Permission denied to kill process group {} for '{}'",
                        pid, inst.name
                    );
                    failed += 1;
                }
            }
            incomplete +=
                report_incomplete_pane_cleanup(result.into(), pane_retry_command.as_deref()) as i32;
            // The release reaps the whole tree; a failure means live
            // processes remain, so it counts against the kill.
            if let StopOutcome::RetryableError(e) =
                stop_instance(db, &inst.name, initiator, "killed")
            {
                eprintln!("Error releasing '{}': {e}", inst.name);
                failed += 1;
            }
            println!("  To resume: hcom r {}", inst.name);
        } else {
            // No PID tracked — just clean up
            if let StopOutcome::RetryableError(e) =
                stop_instance(db, &inst.name, initiator, "killed")
            {
                eprintln!("Error releasing '{}': {e}", inst.name);
                failed += 1;
            }
        }
    }

    // Kill orphans too
    let orphans = pidtrack::get_orphan_processes(hcom_dir, Some(&active_pids));
    for orphan in &orphans {
        let (result, pane_closed, pane_retry_command) = terminal::kill_process(
            orphan.pid,
            &orphan.terminal_preset,
            &orphan.pane_id,
            &orphan.process_id,
            &orphan.kitty_listen_on,
            &orphan.terminal_id,
            &orphan.zellij_session_name,
        );
        let names = orphan.names.join(", ");
        let pane_info = pane_info_str(pane_closed, &orphan.terminal_preset, &orphan.pane_id);
        let result = normalize_kill_result(&names, orphan.pid, result, pane_closed);
        let label = if !names.is_empty() || !pane_info.is_empty() {
            format!(" ({}{})", names, pane_info)
        } else {
            String::new()
        };
        match result {
            terminal::KillResult::Sent => {
                println!(
                    "Sent SIGTERM to orphan process group {}{}",
                    orphan.pid, label
                );
                killed += 1;
            }
            terminal::KillResult::AlreadyDead => {
                println!(
                    "Orphan process group {} already terminated{}",
                    orphan.pid, label
                );
                killed += 1;
            }
            terminal::KillResult::PermissionDenied => {
                failed += 1;
            }
        }
        incomplete +=
            report_incomplete_pane_cleanup(result.into(), pane_retry_command.as_deref()) as i32;
        // Verify the whole carrier set, not just the recorded group: a
        // self-bound tree never carries the orphan's names. Survivors keep
        // their pidtrack handle for a retry.
        let reap_failed = reap_orphan_tree(db, orphan);
        failed += reap_failed as i32;
        if !reap_failed {
            pidtrack::remove_pid(hcom_dir, orphan.pid);
        }
    }

    if killed == 0 && failed == 0 {
        println!("No processes with tracked PIDs found");
    } else if failed > 0 || incomplete > 0 {
        println!(
            "Killed {}, {} failed, {} with incomplete pane cleanup",
            killed, failed, incomplete
        );
    } else {
        println!("Killed {}", killed);
    }

    Ok(if failed > 0 || incomplete > 0 { 1 } else { 0 })
}

/// Kill instances by tag.
fn kill_by_tag(db: &HcomDb, hcom_dir: &std::path::Path, tag: &str, initiator: &str) -> Result<i32> {
    let instances = db.iter_instances_full()?;
    let tagged: Vec<_> = instances
        .iter()
        .filter(|inst| inst.tag.as_deref() == Some(tag) && inst.origin_device_id.is_none())
        .collect();

    let mut killed = 0;
    let mut failed = 0;
    let mut incomplete = 0;

    // Kill active instances with this tag
    for inst in &tagged {
        if let Some(pid) = inst.pid {
            let is_headless = inst.background != 0;
            let (result, pane_closed, pane_retry_command, preset_name, pane_id) =
                kill_instance(db, &inst.name, pid as u32, inst, is_headless);
            let pane_info = pane_info_str(pane_closed, &preset_name, &pane_id);
            match result {
                terminal::KillResult::Sent => {
                    println!(
                        "Sent SIGTERM to process group {} for '{}'{}",
                        pid, inst.name, pane_info
                    );
                    killed += 1;
                }
                terminal::KillResult::AlreadyDead => {
                    println!(
                        "Process group {} already terminated for '{}'",
                        pid, inst.name
                    );
                    killed += 1;
                }
                terminal::KillResult::PermissionDenied => {
                    eprintln!(
                        "Permission denied to kill process group {} for '{}'",
                        pid, inst.name
                    );
                    failed += 1;
                }
            }
            incomplete +=
                report_incomplete_pane_cleanup(result.into(), pane_retry_command.as_deref()) as i32;
            if let StopOutcome::RetryableError(e) =
                stop_instance(db, &inst.name, initiator, "killed")
            {
                eprintln!("Error releasing '{}': {e}", inst.name);
                failed += 1;
            }
        } else {
            // No PID tracked — clean up DB entry
            println!("No tracked process for '{}', stopping instance.", inst.name);
            if let StopOutcome::RetryableError(e) =
                stop_instance(db, &inst.name, initiator, "killed")
            {
                eprintln!("Error releasing '{}': {e}", inst.name);
                failed += 1;
            }
        }
    }

    // Also kill orphan processes with this tag (stopped but still running)
    let active_pids: HashSet<u32> = tagged
        .iter()
        .filter_map(|i| i.pid.map(|p| p as u32))
        .collect();
    let orphans = pidtrack::get_orphan_processes(hcom_dir, Some(&active_pids));
    let tagged_orphans: Vec<_> = orphans.iter().filter(|o| o.tag == tag).collect();
    for orphan in &tagged_orphans {
        let names = orphan.names.join(", ");
        let (result, pane_closed, pane_retry_command) = terminal::kill_process(
            orphan.pid,
            &orphan.terminal_preset,
            &orphan.pane_id,
            &orphan.process_id,
            &orphan.kitty_listen_on,
            &orphan.terminal_id,
            &orphan.zellij_session_name,
        );
        let result = normalize_kill_result(&names, orphan.pid, result, pane_closed);
        let pane_info = pane_info_str(pane_closed, &orphan.terminal_preset, &orphan.pane_id);
        match result {
            terminal::KillResult::Sent => {
                println!(
                    "Sent SIGTERM to stopped process group {} for '{}'{}",
                    orphan.pid, names, pane_info
                );
                killed += 1;
            }
            terminal::KillResult::AlreadyDead => {
                println!(
                    "Process group {} already terminated for '{}'",
                    orphan.pid, names
                );
            }
            terminal::KillResult::PermissionDenied => {
                eprintln!("Permission denied to kill process group {}", orphan.pid);
                failed += 1;
            }
        }
        incomplete +=
            report_incomplete_pane_cleanup(result.into(), pane_retry_command.as_deref()) as i32;
        let reap_failed = reap_orphan_tree(db, orphan);
        failed += reap_failed as i32;
        if !reap_failed {
            pidtrack::remove_pid(hcom_dir, orphan.pid);
        }
    }

    if tagged.is_empty() && tagged_orphans.is_empty() {
        eprintln!("No agents with tag '{}'", tag);
        return Ok(1);
    }

    println!("Killed {} (tag:{})", killed, tag);
    Ok(if failed > 0 || incomplete > 0 { 1 } else { 0 })
}

/// Kill a single instance by name.
fn kill_single(
    db: &HcomDb,
    hcom_dir: &std::path::Path,
    target: &str,
    initiator: &str,
) -> Result<i32> {
    // Resolve display name
    let name = identity::resolve_display_name(db, target).unwrap_or_else(|| target.to_string());

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
                let (result, pane_closed, pane_retry_command) = terminal::kill_process(
                    orphan.pid,
                    &orphan.terminal_preset,
                    &orphan.pane_id,
                    &orphan.process_id,
                    &orphan.kitty_listen_on,
                    &orphan.terminal_id,
                    &orphan.zellij_session_name,
                );
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
                let reap_failed = reap_orphan_tree(db, orphan);
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

/// Kill a process and close its terminal pane.
/// Returns (KillResult, pane_closed, pane_retry_command, preset_name, pane_id).
fn kill_instance(
    _db: &HcomDb,
    name: &str,
    pid: u32,
    instance: &crate::db::InstanceRow,
    is_headless: bool,
) -> (terminal::KillResult, bool, Option<String>, String, String) {
    // Headless instances have no terminal pane — skip pane close
    if is_headless {
        let (result, pane_closed, pane_retry_command) =
            terminal::kill_process(pid, "", "", "", "", "", "");
        let result = normalize_kill_result(name, pid, result, pane_closed);
        log_info(
            "kill",
            "lifecycle.kill",
            &format!(
                "name={} pid={} result={:?} pane_closed={} headless=true",
                name, pid, result, pane_closed
            ),
        );
        return (
            result,
            pane_closed,
            pane_retry_command,
            String::new(),
            String::new(),
        );
    }

    let ti = terminal::resolve_terminal_info(
        instance.terminal_preset_effective.as_deref(),
        instance.launch_context.as_deref(),
    );

    let (result, pane_closed, pane_retry_command) = terminal::kill_process(
        pid,
        &ti.preset_name,
        &ti.pane_id,
        &ti.process_id,
        &ti.kitty_listen_on,
        &ti.terminal_id,
        &ti.zellij_session_name,
    );
    let result = normalize_kill_result(name, pid, result, pane_closed);

    log_info(
        "kill",
        "lifecycle.kill",
        &format!(
            "name={} pid={} result={:?} pane_closed={}",
            name, pid, result, pane_closed
        ),
    );

    (
        result,
        pane_closed,
        pane_retry_command,
        ti.preset_name.clone(),
        ti.pane_id.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[cfg(unix)]
    use serial_test::serial;

    #[test]
    fn test_kill_no_target_fails() {
        // Missing required target → clap error → exit code 1
        let flags = GlobalFlags::default();
        let argv = vec!["kill".to_string()];
        let result = run(&argv, &flags).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn test_kill_args_parse_single() {
        use clap::Parser;
        let args = KillArgs::try_parse_from(["kill", "myagent"]).unwrap();
        assert_eq!(args.targets, vec!["myagent"]);
    }

    #[test]
    fn test_kill_args_parse_multiple() {
        use clap::Parser;
        let args = KillArgs::try_parse_from(["kill", "nozu", "zelu"]).unwrap();
        assert_eq!(args.targets, vec!["nozu", "zelu"]);
    }

    #[test]
    fn test_kill_args_no_target_is_empty_vec() {
        use clap::Parser;
        let args = KillArgs::try_parse_from(["kill"]).unwrap();
        assert!(args.targets.is_empty());
    }

    #[test]
    fn test_normalize_permission_denied_after_pane_close_succeeds() {
        let result =
            normalize_kill_result("luna", 42, terminal::KillResult::PermissionDenied, true);
        assert_eq!(result, terminal::KillResult::AlreadyDead);
    }

    #[test]
    fn test_incomplete_cleanup_requires_terminated_process_and_retry_command() {
        assert!(report_incomplete_pane_cleanup(
            PaneCleanupProcessState::Terminated,
            Some("wezterm cli kill-pane --pane-id 123")
        ));
        assert!(!report_incomplete_pane_cleanup(
            PaneCleanupProcessState::NotTerminated,
            Some("wezterm cli kill-pane --pane-id 123")
        ));
        assert!(!report_incomplete_pane_cleanup(
            PaneCleanupProcessState::AlreadyDead,
            None
        ));
    }

    #[test]
    fn test_handle_remote_kill_response_permission_denied_returns_nonzero() {
        let result = handle_remote_kill_response(
            "luna:ABCD",
            &json!({
                "result": {
                    "pid": 42,
                    "kill_result": "permission_denied",
                    "teardown": "completed",
                    "pane_closed": false,
                    "preset_name": "",
                    "pane_id": ""
                }
            }),
        )
        .unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn test_handle_remote_kill_response_permission_denied_with_closed_pane_succeeds() {
        let result = handle_remote_kill_response(
            "luna:ABCD",
            &json!({
                "ok": true,
                "result": {
                    "pid": 42,
                    "kill_result": "already_dead",
                    "teardown": "completed",
                    "pane_closed": true,
                    "preset_name": "kitty",
                    "pane_id": "@1"
                }
            }),
        )
        .unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn test_render_remote_kill_feedback_sent_matches_cli_contract() {
        let lines = render_remote_kill_feedback(
            "luna:ABCD",
            42,
            "sent",
            " (closed kitty pane @1)",
            TeardownOutcome::Completed,
        )
        .unwrap();
        assert_eq!(
            lines,
            vec![
                "Sent SIGTERM to process group 42 for 'luna:ABCD' (closed kitty pane @1)"
                    .to_string(),
                "  To resume: hcom r luna:ABCD".to_string(),
            ]
        );
    }

    #[test]
    fn test_render_remote_kill_feedback_already_dead_matches_cli_contract() {
        let lines = render_remote_kill_feedback(
            "luna:ABCD",
            42,
            "already_dead",
            "",
            TeardownOutcome::Completed,
        )
        .unwrap();
        assert_eq!(
            lines,
            vec![
                "Process group 42 not found for 'luna:ABCD' (already terminated)".to_string(),
                "  To resume: hcom r luna:ABCD".to_string(),
            ]
        );
    }

    #[test]
    fn test_render_self_kill_feedback_matches_cli_contract() {
        let lines = render_self_kill_feedback("luna", 1);
        assert_eq!(
            lines,
            vec![
                "luna: stopped; bindings released. 1 process(es) in your own session were excluded from the signal (this command is one of them).".to_string(),
                "  To resume: hcom r luna".to_string(),
            ]
        );
    }

    #[test]
    fn test_render_re_registered_feedback_matches_cli_contract() {
        let lines = render_re_registered_feedback("luna");
        assert_eq!(
            lines,
            vec![
                "luna: prior processes reaped; the row was re-registered during this kill and was left intact."
                    .to_string(),
            ]
        );
    }

    #[test]
    fn test_render_session_self_stop_feedback_matches_cli_contract() {
        assert_eq!(
            render_skipped_teardown_feedback("luna", TeardownOutcome::SessionStoppedKeptRow),
            Some(vec![
                "luna: processes reaped; the session shut itself down during the kill and kept its row as a resume handle"
                    .to_string(),
            ])
        );
        assert_eq!(
            render_skipped_teardown_feedback("luna", TeardownOutcome::SessionStoppedReleasedRow),
            Some(vec![
                "luna: processes reaped; the session shut itself down during the kill and released its row"
                    .to_string(),
            ])
        );
        assert_eq!(
            render_skipped_teardown_feedback("luna", TeardownOutcome::Completed),
            None,
            "a landed teardown takes the normal stopped report"
        );
    }

    #[test]
    fn test_handle_remote_kill_response_unknown_result_errors() {
        let err = handle_remote_kill_response(
            "luna:ABCD",
            &json!({
                "result": {
                    "pid": 42,
                    "kill_result": "mystery",
                    "teardown": "completed",
                    "pane_closed": false,
                    "preset_name": "",
                    "pane_id": ""
                }
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unexpected kill_result mystery"));
    }

    #[test]
    fn test_render_remote_kill_feedback_row_re_registered_matches_local() {
        // Remote rows render the CAS-skip report exactly like local ones.
        let lines = render_remote_kill_feedback(
            "luna:ABCD",
            42,
            "sent",
            "",
            TeardownOutcome::RowReRegistered,
        )
        .unwrap();
        assert_eq!(lines, render_re_registered_feedback("luna:ABCD"));
    }

    #[test]
    fn test_render_remote_kill_feedback_session_self_stop_matches_local() {
        // Remote rows render the self-stop reports exactly like local ones,
        // whatever the kill_result.
        for outcome in [
            TeardownOutcome::SessionStoppedKeptRow,
            TeardownOutcome::SessionStoppedReleasedRow,
        ] {
            let lines =
                render_remote_kill_feedback("luna:ABCD", 42, "already_dead", "", outcome).unwrap();
            assert_eq!(
                Some(lines),
                render_skipped_teardown_feedback("luna:ABCD", outcome)
            );
        }
    }

    #[test]
    fn test_handle_remote_kill_response_session_self_stop_exits_zero() {
        for token in ["session_stopped_kept_row", "session_stopped_released_row"] {
            let result = handle_remote_kill_response(
                "luna:ABCD",
                &json!({
                    "ok": true,
                    "result": {
                        "pid": 42,
                        "kill_result": "sent",
                        "teardown": token,
                        "pane_closed": false,
                        "preset_name": "",
                        "pane_id": ""
                    }
                }),
            )
            .unwrap();
            assert_eq!(result, 0, "{token}");
        }
    }

    #[test]
    fn test_handle_remote_kill_response_row_re_registered_exits_zero() {
        let result = handle_remote_kill_response(
            "luna:ABCD",
            &json!({
                "ok": true,
                "result": {
                    "pid": 42,
                    "kill_result": "sent",
                    "teardown": "row_re_registered",
                    "pane_closed": false,
                    "preset_name": "",
                    "pane_id": ""
                }
            }),
        )
        .unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn test_handle_remote_kill_response_without_teardown_errors() {
        // An outcome-less response (a peer predating outcome reporting) must
        // never be read as a successful teardown.
        let err = handle_remote_kill_response(
            "luna:ABCD",
            &json!({
                "ok": true,
                "result": {
                    "pid": 42,
                    "kill_result": "sent",
                    "pane_closed": false,
                    "preset_name": "",
                    "pane_id": ""
                }
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("teardown outcome"),
            "error names the gap: {err}"
        );
    }

    #[test]
    fn test_teardown_outcome_wire_tokens_round_trip() {
        for outcome in [
            TeardownOutcome::Completed,
            TeardownOutcome::RowReRegistered,
            TeardownOutcome::SessionStoppedKeptRow,
            TeardownOutcome::SessionStoppedReleasedRow,
        ] {
            assert_eq!(
                TeardownOutcome::parse(Some(outcome.as_str())),
                Some(outcome)
            );
        }
        assert_eq!(TeardownOutcome::parse(None), None);
        assert_eq!(TeardownOutcome::parse(Some("mystery")), None);
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

    #[cfg(unix)]
    fn wait_for_enumerated(name: &str, pid: u32) {
        for _ in 0..50 {
            if crate::proctruth::processes_for_instance(name, &[])
                .iter()
                .any(|m| m.pid == pid)
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("sleeper {pid} never enumerated under {name}");
    }

    /// What the kill resolves against for `name` (row facts, binding epoch,
    /// and events watermark), captured the way production does.
    #[cfg(unix)]
    fn capture_incarnation(db: &crate::db::HcomDb, name: &str) -> ResolvedIncarnation {
        let row = db.get_instance_full(name).unwrap().expect("row");
        ResolvedIncarnation::capture(db, &row, &db.process_binding_ids(name).unwrap()).unwrap()
    }

    /// A: kill reaps the whole name tree — even processes outside the
    /// recorded pid — and only then deletes the row. A different-named
    /// sleeper must survive.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_reaps_name_tree_outside_recorded_pid() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();

        let tag = format!("{}-{}", std::process::id(), 1);
        let name = format!("hcom-kill-{tag}");
        let other = format!("hcom-kill-other-{tag}");

        // Recorded pid is already dead; the live tree carries only the name.
        let mut recorded = std::process::Command::new("true").spawn().unwrap();
        let recorded_pid = recorded.id() as i64;
        recorded.wait().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) VALUES (?1, 'active', ?2, 'codex', ?3)",
                rusqlite::params![name, now, recorded_pid],
            )
            .unwrap();
        db.set_process_binding("proc-kill-cur", "sess-kill", &name)
            .unwrap();

        let mut sleeper = spawn_named_sleeper(&name, "proc-kill-old");
        let spid = sleeper.id();
        wait_for_enumerated(&name, spid);
        let mut bystander = spawn_named_sleeper(&other, "proc-other");
        let bpid = bystander.id();
        wait_for_enumerated(&other, bpid);

        kill_tracked_instance(&db, &name, "test")
            .unwrap_or_else(|e| panic!("kill must succeed once tree is reaped: {e}"));
        // Reap the (zombie) child so bare kill-0 liveness observes it.
        sleeper.wait().ok();
        assert!(
            !crate::sys::process::is_alive(spid),
            "name-carrying sleeper outside the recorded pid is reaped"
        );
        assert!(
            db.get_instance_full(&name).unwrap().is_none(),
            "row deleted only after the tree is gone"
        );
        assert!(
            crate::sys::process::is_alive(bpid),
            "different-named sleeper survives"
        );
        bystander.kill().ok();
        bystander.wait().ok();
        let _ = _guard;
    }

    #[cfg(unix)]
    fn stopped_events(db: &crate::db::HcomDb, name: &str) -> i64 {
        db.conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = ?1 \
                 AND data LIKE '%\"action\":\"stopped\"%'",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// Self path, corrected fail-closed ordering: the non-self carriers are
    /// signalled and verified gone BEFORE the `stopped` event and the binding
    /// release, and a carrier in the passed-in self set is never signalled.
    /// Ordering proof (the inverse of the old write-first poll): the kill
    /// runs on a thread while this thread polls the invariant — while the
    /// foreign carrier is alive, the row must never read stopped/released
    /// and the bindings must stay intact; they only flip after the carrier
    /// is gone. A release-while-alive state was proven observable at this
    /// poll granularity by the write-first implementation it replaces, so a
    /// regression back to release-before-reap fails this loop.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_self_path_reaps_before_release_and_spares_self() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();

        let tag = format!("{}-self", std::process::id());
        let name = format!("hcom-kill-{tag}");

        let mut recorded = std::process::Command::new("true").spawn().unwrap();
        let recorded_pid = recorded.id() as i64;
        recorded.wait().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) VALUES (?1, 'active', ?2, 'codex', ?3)",
                rusqlite::params![name, now, recorded_pid],
            )
            .unwrap();
        db.set_process_binding("proc-kill-self", "sess-kill-self", &name)
            .unwrap();

        // "Self": a carrier standing in for the caller's own session tree.
        let mut self_sleeper = spawn_named_sleeper(&name, "proc-kill-self-tree");
        let self_pid = self_sleeper.id();
        wait_for_enumerated(&name, self_pid);
        let mut foreign_sleeper = spawn_named_sleeper(&name, "proc-kill-self-foreign");
        let foreign_pid = foreign_sleeper.id();
        wait_for_enumerated(&name, foreign_pid);

        let self_set = vec![std::process::id(), self_pid];
        let db_path = dir.path().join("test.db");
        let kill_name = name.clone();
        let killer = std::thread::spawn(move || {
            let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
            kill_tracked_instance_with_self_pids(
                &db,
                &kill_name,
                "test",
                &self_set,
                |n, b, e, capture| {
                    crate::proctruth::reap_instance_tree_for_excluding_captured(
                        &db, n, b, e, capture,
                    )
                },
            )
        });

        // Invariant poll on a second connection: the release must never be
        // observable while the foreign carrier runs. Transient lock errors
        // read as "not yet observed" (never as released).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let carrier_running = foreign_sleeper
                .try_wait()
                .expect("try_wait foreign carrier")
                .is_none();
            let row_released = db
                .get_instance_full(&name)
                .map(|row| row.is_none())
                .unwrap_or(false);
            let bindings_freed = db
                .process_binding_ids(&name)
                .map(|ids| ids.is_empty())
                .unwrap_or(false);
            assert!(
                !(carrier_running && (row_released || bindings_freed)),
                "row/bindings released while a non-self carrier is still alive"
            );
            if !carrier_running {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("non-self carrier never reaped");
            }
            std::thread::sleep(std::time::Duration::from_micros(200));
        }

        let result = killer.join().expect("kill thread");
        assert!(
            result.is_ok(),
            "kill entry must return Ok (the CLI exit-0 result)"
        );
        let result = result.expect("Ok asserted above");
        assert_eq!(
            result.self_excluded, 1,
            "exactly the self carrier is spared"
        );

        assert!(
            db.get_instance_full(&name).unwrap().is_none(),
            "row released only after the non-self carrier is gone"
        );
        assert_eq!(stopped_events(&db, &name), 1, "stopped event written after");
        assert!(
            db.process_binding_ids(&name).unwrap().is_empty(),
            "process bindings released after"
        );
        assert!(
            !crate::sys::process::is_alive(foreign_pid),
            "non-self carrier is reaped before the teardown"
        );
        assert!(
            crate::sys::process::is_alive(self_pid),
            "self carrier is never signalled"
        );
        assert_eq!(
            render_self_kill_feedback(&name, result.self_excluded),
            vec![
                format!(
                    "{name}: stopped; bindings released. 1 process(es) in your own session were excluded from the signal (this command is one of them)."
                ),
                format!("  To resume: hcom r {name}"),
            ],
            "plain report + resume hint"
        );
        self_sleeper.kill().ok();
        self_sleeper.wait().ok();
        let _ = _guard;
    }

    /// Self path, fail-closed survivor case: when the reap reports non-self
    /// survivors after the signal budget, the kill bails with the foreign
    /// path's error (survivors listed, `run hcom kill` hint) and the row and
    /// bindings stay completely untouched — no stopped event, no release.
    /// The survivor is a name-only late fork — in scope under the epoch rule
    /// (no process id of its own), so a real one surviving the budget would
    /// be reported here. It is forced through the reap seam
    /// (`kill_self_tracked_instance`'s injectable reap): no same-uid process
    /// can outlive SIGTERM+SIGKILL, so a real carrier cannot outlive the
    /// real budget.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_self_path_fails_closed_on_non_self_survivors() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();

        let tag = format!("{}-fc", std::process::id());
        let name = format!("hcom-kill-{tag}");

        let mut recorded = std::process::Command::new("true").spawn().unwrap();
        let recorded_pid = recorded.id() as i64;
        recorded.wait().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) VALUES (?1, 'active', ?2, 'codex', ?3)",
                rusqlite::params![name, now, recorded_pid],
            )
            .unwrap();
        db.set_process_binding("proc-kill-fc", "sess-kill-fc", &name)
            .unwrap();
        let binding_ids = db.process_binding_ids(&name).unwrap();
        let incarnation = capture_incarnation(&db, &name);

        // A name-only carrier that outlives the signal budget — reported as
        // a survivor by the injected reap (it is never signalled here).
        let mut survivor = spawn_named_sleeper(&name, "");
        let survivor_pid = survivor.id();
        wait_for_enumerated(&name, survivor_pid);

        let excluded = vec![std::process::id()];
        let err = kill_self_tracked_instance(
            &db,
            &name,
            "test",
            recorded_pid as u32,
            &binding_ids,
            &excluded,
            &incarnation,
            crate::proctruth::capture_reap_carriers(&db, &name, &binding_ids, &excluded),
            |_, _, _, _capture| Err(crate::proctruth::ReapError::Survivors(vec![survivor_pid])),
        )
        .err()
        .expect("a non-self survivor must fail the kill");
        assert!(
            err.contains(&survivor_pid.to_string()),
            "error lists the survivors: {err}"
        );
        assert!(
            err.contains(&format!("run hcom kill {name} first")),
            "foreign-path failure message: {err}"
        );

        // Fail-closed: no teardown happened at all.
        assert!(
            db.get_instance_full(&name).unwrap().is_some(),
            "row untouched on survivor"
        );
        assert_eq!(stopped_events(&db, &name), 0, "no stopped event written");
        assert_eq!(
            db.process_binding_ids(&name).unwrap(),
            binding_ids,
            "bindings untouched on survivor"
        );
        assert!(
            crate::sys::process::is_alive(survivor_pid),
            "survivor left alone"
        );
        survivor.kill().ok();
        survivor.wait().ok();
        let _ = _guard;
    }

    /// Foreign path through the injectable entry: with no self overlap the
    /// whole tree is reaped before the row is released (fail-closed ordering
    /// unchanged), and the result carries no self report.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_foreign_path_reaps_tree_before_release() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();

        let tag = format!("{}-foreign", std::process::id());
        let name = format!("hcom-kill-{tag}");

        let mut recorded = std::process::Command::new("true").spawn().unwrap();
        let recorded_pid = recorded.id() as i64;
        recorded.wait().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) VALUES (?1, 'active', ?2, 'codex', ?3)",
                rusqlite::params![name, now, recorded_pid],
            )
            .unwrap();
        db.set_process_binding("proc-kill-foreign", "sess-kill-foreign", &name)
            .unwrap();

        let mut sleeper = spawn_named_sleeper(&name, "proc-kill-foreign-tree");
        let spid = sleeper.id();
        wait_for_enumerated(&name, spid);

        let self_set = vec![std::process::id()];
        let result = kill_tracked_instance_with_self_pids(
            &db,
            &name,
            "test",
            &self_set,
            |n, b, e, capture| {
                crate::proctruth::reap_instance_tree_for_excluding_captured(&db, n, b, e, capture)
            },
        )
        .unwrap_or_else(|e| panic!("foreign kill must succeed: {e}"));
        assert_eq!(result.self_excluded, 0, "no self overlap, no self report");
        sleeper.wait().ok();
        assert!(
            !crate::sys::process::is_alive(spid),
            "foreign carrier reaped"
        );
        assert!(
            db.get_instance_full(&name).unwrap().is_none(),
            "row released after the tree is gone"
        );
        assert_eq!(stopped_events(&db, &name), 1, "stopped event written");
        let _ = _guard;
    }

    /// CAS (i): a same-identity rebind landing mid-kill (the reap-to-teardown
    /// window the spawn gate can fill) replaces the row's bindings. The kill
    /// reaps the OLD incarnation's processes but must not tear down the
    /// rebound row — the fresh incarnation is left intact, reported plainly,
    /// exit 0. The rebind is injected through the reap seam right after the
    /// (real) reap verifies clean: the latest possible moment before the
    /// teardown write.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_skips_teardown_when_row_rebound_mid_kill() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();

        let tag = format!("{}-rebind", std::process::id());
        let name = format!("hcom-kill-{tag}");

        let mut recorded = std::process::Command::new("true").spawn().unwrap();
        let recorded_pid = recorded.id() as i64;
        recorded.wait().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) VALUES (?1, 'active', ?2, 'codex', ?3)",
                rusqlite::params![name, now, recorded_pid],
            )
            .unwrap();
        db.set_process_binding("proc-kill-rb-old", "sess-kill-rb", &name)
            .unwrap();
        let binding_ids = db.process_binding_ids(&name).unwrap();

        // The old incarnation's live tree; the real reap below must take it
        // even though the row is rebound before the teardown.
        let mut old_sleeper = spawn_named_sleeper(&name, "proc-kill-rb-tree");
        let old_pid = old_sleeper.id();
        wait_for_enumerated(&name, old_pid);

        let incarnation = capture_incarnation(&db, &name);
        let excluded = vec![std::process::id()];
        let result = kill_self_tracked_instance(
            &db,
            &name,
            "test",
            recorded_pid as u32,
            &binding_ids,
            &excluded,
            &incarnation,
            crate::proctruth::capture_reap_carriers(&db, &name, &binding_ids, &excluded),
            |n, b, e, capture| {
                // The real reap, then the mid-kill rebind: same name, new
                // binding epoch (the `start --as` shape).
                let out = crate::proctruth::reap_instance_tree_for_excluding_captured(
                    &db, n, b, e, capture,
                );
                db.conn()
                    .execute(
                        "DELETE FROM process_bindings WHERE instance_name = ?1",
                        rusqlite::params![n],
                    )
                    .unwrap();
                db.set_process_binding("proc-kill-rb-new", "sess-kill-rb-new", n)
                    .unwrap();
                out
            },
        )
        .unwrap_or_else(|e| panic!("a rebind is not a kill failure: {e}"));

        old_sleeper.wait().ok();
        assert_eq!(result.teardown, TeardownOutcome::RowReRegistered);
        assert!(
            !crate::sys::process::is_alive(old_pid),
            "the old incarnation's processes are reaped"
        );
        // The rebound row is left intact: still there, new binding set, and
        // no stopped event from this kill.
        assert!(
            db.get_instance_full(&name).unwrap().is_some(),
            "rebound row left intact"
        );
        assert_eq!(
            db.process_binding_ids(&name).unwrap(),
            vec!["proc-kill-rb-new".to_string()],
            "the rebind's binding set is untouched"
        );
        assert_eq!(stopped_events(&db, &name), 0, "no stopped event written");
        assert_eq!(
            render_re_registered_feedback(&name),
            vec![format!(
                "{name}: prior processes reaped; the row was re-registered during this kill and was left intact."
            )],
            "the plain CAS-skip report is what the CLI prints"
        );
        let _ = _guard;
    }

    /// CAS (ii): the unchanged path — the token the kill resolved against is
    /// still the row's, so the teardown lands exactly as before this rule.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn teardown_lands_when_incarnation_unchanged() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();

        let name = format!("hcom-kill-{}-casok", std::process::id());
        let mut recorded = std::process::Command::new("true").spawn().unwrap();
        let recorded_pid = recorded.id() as i64;
        recorded.wait().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) VALUES (?1, 'active', ?2, 'codex', ?3)",
                rusqlite::params![name, now, recorded_pid],
            )
            .unwrap();
        db.set_process_binding("proc-keep-cas", "sess-cas", &name)
            .unwrap();

        let incarnation = capture_incarnation(&db, &name);
        let outcome = teardown_if_incarnation_unchanged(&db, &name, "test", &incarnation)
            .unwrap_or_else(|e| panic!("teardown must land: {e}"));
        assert_eq!(outcome, TeardownOutcome::Completed);
        assert!(
            db.get_instance_full(&name).unwrap().is_none(),
            "row torn down when the incarnation is unchanged"
        );
        assert_eq!(stopped_events(&db, &name), 1, "stopped event written");
        let _ = _guard;
    }

    /// CAS (iii), foreign path: the name-only rebind leaves the binding set
    /// EMPTY on both sides, so a binding-only comparison would pass — the
    /// token must catch it through `session_id`. Row re-registered mid-kill:
    /// teardown skipped, row left intact, plain report.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_skips_teardown_when_session_rebinds_without_bindings() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();

        let tag = format!("{}-sessrb", std::process::id());
        let name = format!("hcom-kill-{tag}");

        let mut recorded = std::process::Command::new("true").spawn().unwrap();
        let recorded_pid = recorded.id() as i64;
        recorded.wait().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) VALUES (?1, 'active', ?2, 'codex', ?3)",
                rusqlite::params![name, now, recorded_pid],
            )
            .unwrap();
        // Name-only incarnation: no bindings at all, before or after.

        let self_set = vec![std::process::id()];
        let result = kill_tracked_instance_with_self_pids(
            &db,
            &name,
            "test",
            &self_set,
            |n, _, _, _capture| {
                // The name-only rebind: bindings stay empty, the session
                // changes.
                db.conn()
                    .execute(
                        "UPDATE instances SET session_id = 'sess-rebound' WHERE name = ?1",
                        rusqlite::params![n],
                    )
                    .unwrap();
                Ok(())
            },
        )
        .unwrap_or_else(|e| panic!("a rebind is not a kill failure: {e}"));

        assert_eq!(result.teardown, TeardownOutcome::RowReRegistered);
        let row = db
            .get_instance_full(&name)
            .unwrap()
            .expect("rebound row left intact");
        assert_eq!(row.session_id.as_deref(), Some("sess-rebound"));
        assert_eq!(stopped_events(&db, &name), 0, "no stopped event written");
        assert_eq!(
            render_re_registered_feedback(&name),
            vec![format!(
                "{name}: prior processes reaped; the row was re-registered during this kill and was left intact."
            )],
            "the plain CAS-skip report is what the CLI prints"
        );
        let _ = _guard;
    }

    #[cfg(unix)]
    fn assert_killed_by(db: &HcomDb, name: &str, initiator: &str) {
        let records: Vec<(String, String)> = db.conn().prepare(
            "SELECT json_extract(data, '$.reason'), json_extract(data, '$.by') FROM events WHERE type = 'life' AND instance = ? AND json_extract(data, '$.action') = 'stopped'",
        ).unwrap().query_map(rusqlite::params![name], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(records, vec![("killed".to_string(), initiator.to_string())]);
    }

    /// Insert a bound row (recorded pid already dead) with a live
    /// name-carrying sleeper, the shape the self-stop tests kill.
    #[cfg(unix)]
    fn seed_bound_row_with_sleeper(
        db: &crate::db::HcomDb,
        name: &str,
        process_id: &str,
        session_id: &str,
    ) -> std::process::Child {
        let mut recorded = std::process::Command::new("true").spawn().unwrap();
        let recorded_pid = recorded.id() as i64;
        recorded.wait().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid, session_id) VALUES (?1, 'active', ?2, 'codex', ?3, ?4)",
                rusqlite::params![name, now, recorded_pid, session_id],
            )
            .unwrap();
        db.set_process_binding(process_id, session_id, name)
            .unwrap();
        let sleeper = spawn_named_sleeper(name, process_id);
        wait_for_enumerated(name, sleeper.id());
        sleeper
    }

    /// The soft shutdown hook yields to the kill's claim, leaving the kill
    /// to publish the stopped record under its initiator.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_owns_teardown_when_harness_soft_finalizes_mid_kill() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();

        let name = format!("hcom-kill-{}-softstop", std::process::id());
        let mut sleeper =
            seed_bound_row_with_sleeper(&db, &name, "proc-kill-soft", "sess-kill-soft");
        let spid = sleeper.id();

        let self_set = vec![std::process::id()];
        let result = kill_tracked_instance_with_self_pids(
            &db,
            &name,
            "test",
            &self_set,
            |n, b, e, capture| {
                // The real reap, then the harness's own shutdown hook.
                let out = crate::proctruth::reap_instance_tree_for_excluding_captured(
                    &db, n, b, e, capture,
                );
                crate::hooks::common::soft_finalize_session(&db, n, "shutdown", None, false);
                out
            },
        )
        .unwrap_or_else(|e| panic!("a session self-stop is not a kill failure: {e}"));

        sleeper.wait().ok();
        assert_eq!(result.teardown, TeardownOutcome::Completed);
        assert!(!crate::sys::process::is_alive(spid), "sleeper reaped");
        assert!(db.get_instance_full(&name).unwrap().is_none());
        assert_killed_by(&db, &name, "test");
        let _ = _guard;
    }

    /// The hard SessionEnd hook also yields: the kill owns the stopped
    /// record rather than reporting a session-initiated teardown.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_owns_teardown_when_harness_finalizes_row_mid_kill() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();

        let name = format!("hcom-kill-{}-hardstop", std::process::id());
        let mut sleeper =
            seed_bound_row_with_sleeper(&db, &name, "proc-kill-hard", "sess-kill-hard");
        let spid = sleeper.id();

        let self_set = vec![std::process::id()];
        let result = kill_tracked_instance_with_self_pids(
            &db,
            &name,
            "test",
            &self_set,
            |n, b, e, capture| {
                // The real reap, then the harness's own SessionEnd.
                let out = crate::proctruth::reap_instance_tree_for_excluding_captured(
                    &db, n, b, e, capture,
                );
                assert_eq!(
                    crate::hooks::common::finalize_session(&db, n, "shutdown", None),
                    StopOutcome::AlreadyStopped
                );
                out
            },
        )
        .unwrap_or_else(|e| panic!("a session self-stop is not a kill failure: {e}"));

        sleeper.wait().ok();
        assert_eq!(result.teardown, TeardownOutcome::Completed);
        assert!(!crate::sys::process::is_alive(spid), "sleeper reaped");
        assert!(db.get_instance_full(&name).unwrap().is_none());
        assert_killed_by(&db, &name, "test");
        let _ = _guard;
    }
    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[serial]
    fn kill_reaps_late_child_after_excluded_only_capture() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();
        let name = format!("hcom-kill-{}-empty-capture", std::process::id());
        let mut owner =
            seed_bound_row_with_sleeper(&db, &name, "proc-empty-capture", "sess-empty-capture");
        let mut late = None;
        let result = kill_tracked_instance_with_self_pids(
            &db,
            &name,
            "test",
            &[std::process::id(), owner.id()],
            |n, bindings, excluded, capture| {
                let child = spawn_named_sleeper(n, "");
                wait_for_enumerated(n, child.id());
                late = Some(child);
                crate::proctruth::reap_instance_tree_for_excluding_captured(
                    &db, n, bindings, excluded, capture,
                )
            },
        );
        let mut late = late.expect("reap callback ran");
        let late_alive = !crate::proctruth::process_gone(late.id());
        let owner_alive = crate::sys::process::is_alive(owner.id());
        late.kill().ok();
        late.wait().ok();
        owner.kill().ok();
        owner.wait().ok();
        assert!(owner_alive, "the excluded owner must not be signalled");
        assert!(!late_alive, "the late child must be gone before teardown");
        assert_eq!(result.unwrap().teardown, TeardownOutcome::Completed);
        assert!(db.get_instance_full(&name).unwrap().is_none());
        assert_killed_by(&db, &name, "test");
    }

    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_failure_after_session_yield_keeps_exit_state_and_bindings() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        for soft in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
            db.init_db().unwrap();
            let name = format!("hcom-kill-{}-yield-failure-{soft}", std::process::id());
            let mut survivor =
                seed_bound_row_with_sleeper(&db, &name, "proc-yield-failure", "sess-yield-failure");
            let pid = survivor.id();
            db.conn()
                .execute(
                    "UPDATE instances SET status = 'listening' WHERE name = ?",
                    rusqlite::params![name],
                )
                .unwrap();
            let bindings = db.process_binding_ids(&name).unwrap();
            let result = kill_tracked_instance_with_self_pids(
                &db,
                &name,
                "test",
                &[std::process::id()],
                |n, _, _, _| {
                    let updates = serde_json::json!({"transcript_path": "/ended/transcript"});
                    if soft {
                        crate::hooks::common::soft_finalize_session(
                            &db,
                            n,
                            "shutdown",
                            updates.as_object(),
                            false,
                        );
                    } else {
                        assert_eq!(
                            crate::hooks::common::finalize_session(
                                &db,
                                n,
                                "shutdown",
                                updates.as_object()
                            ),
                            StopOutcome::AlreadyStopped,
                        );
                    }
                    // Model an unkillable survivor after its one-shot hook
                    // has yielded. The guard drops without replaying the hook.
                    Err(crate::proctruth::ReapError::Survivors(vec![pid]))
                },
            );
            let alive = crate::sys::process::is_alive(pid);
            survivor.kill().ok();
            survivor.wait().ok();

            let error = result.err().expect("survivors fail the kill");
            assert!(error.contains(&pid.to_string()), "{error}");
            assert!(alive, "the injected reap leaves its survivor alone");
            let row = db.get_instance_full(&name).unwrap().expect("row retained");
            assert_eq!(row.status, crate::shared::ST_INACTIVE);
            assert_eq!(row.status_context, "exit:shutdown");
            assert_eq!(row.transcript_path, "/ended/transcript");
            assert_eq!(db.process_binding_ids(&name).unwrap(), bindings);
            assert_eq!(stopped_events(&db, &name), 0);
            assert!(
                db.kv_get(&format!("teardown_claim:{name}"))
                    .unwrap()
                    .is_none()
            );
        }
    }

    /// Precedence: a PTY stop lands mid-kill, then a fresh process binds to
    /// the kept row. The new binding is still a genuine re-registration.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_reports_re_registration_when_row_rebinds_after_session_self_stop() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();

        let name = format!("hcom-kill-{}-stoprebind", std::process::id());
        let mut sleeper =
            seed_bound_row_with_sleeper(&db, &name, "proc-kill-sr-old", "sess-kill-sr");

        let self_set = vec![std::process::id()];
        let result = kill_tracked_instance_with_self_pids(
            &db,
            &name,
            "test",
            &self_set,
            |n, b, e, capture| {
                let out = crate::proctruth::reap_instance_tree_for_excluding_captured(
                    &db, n, b, e, capture,
                );
                db.log_life_event(
                    n,
                    "stopped",
                    "pty",
                    "killed",
                    None,
                    Some("proc-kill-sr-old"),
                )
                .unwrap();
                db.conn()
                    .execute(
                        "DELETE FROM process_bindings WHERE instance_name = ?",
                        rusqlite::params![n],
                    )
                    .unwrap();
                db.set_process_binding("proc-kill-sr-new", "sess-kill-sr", n)
                    .unwrap();
                out
            },
        )
        .unwrap_or_else(|e| panic!("a rebind is not a kill failure: {e}"));

        sleeper.wait().ok();
        assert_eq!(result.teardown, TeardownOutcome::RowReRegistered);
        assert_eq!(
            db.process_binding_ids(&name).unwrap(),
            vec!["proc-kill-sr-new".to_string()],
            "the rebind's binding set is untouched"
        );
        let _ = _guard;
    }

    /// Kill a bound row whose PTY wrapper exits mid-kill: the real reap,
    /// then `exit` runs on a second connection (the wrapper is another
    /// process) — typically the wrapper's own exit cleanup. Returns the
    /// kill's teardown outcome.
    #[cfg(unix)]
    fn kill_mid_pty_exit(
        db_path: &std::path::Path,
        name: &str,
        process_id: &str,
        exit: impl FnOnce(&mut crate::db::HcomDb, &str),
    ) -> TeardownOutcome {
        let db = crate::db::HcomDb::open_raw(db_path).unwrap();
        let mut sleeper = seed_bound_row_with_sleeper(&db, name, process_id, "sess-kill-pty");
        let spid = sleeper.id();
        let mut wrapper_db = crate::db::HcomDb::open_raw(db_path).unwrap();
        let self_set = vec![std::process::id()];
        let result = kill_tracked_instance_with_self_pids(
            &db,
            name,
            "test",
            &self_set,
            |n, b, e, capture| {
                let out = crate::proctruth::reap_instance_tree_for_excluding_captured(
                    &db, n, b, e, capture,
                );
                exit(&mut wrapper_db, n);
                out
            },
        )
        .unwrap_or_else(|e| panic!("a PTY exit is not a kill failure: {e}"));
        sleeper.wait().ok();
        assert!(!crate::sys::process::is_alive(spid), "sleeper reaped");
        result.teardown
    }

    /// A PTY soft exit can still win teardown while a kill claim is live.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_reports_session_self_stop_when_pty_keeps_row_mid_kill() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();
        let name = format!("hcom-kill-{}-pty-kept", std::process::id());
        let outcome = kill_mid_pty_exit(&db_path, &name, "proc-pty-kept", |wrapper, n| {
            wrapper
                .log_life_event(n, "stopped", "pty", "killed", None, Some("proc-pty-kept"))
                .unwrap();
            wrapper
                .conn()
                .execute(
                    "DELETE FROM process_bindings WHERE instance_name = ?",
                    rusqlite::params![n],
                )
                .unwrap();
        });
        assert_eq!(outcome, TeardownOutcome::SessionStoppedKeptRow);
        assert!(db.get_instance_full(&name).unwrap().is_some());
        assert_killed_by(&db, &name, "pty");
    }

    /// Self-stop, PTY: the wrapper's own exit cleanup (`by = pty`, keyed to
    /// the bound process id) deletes the row mid-kill — the remote-kill
    /// shape the relay roundtrip hits. Released by the session, not
    /// re-registered.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_reports_session_self_stop_when_pty_exit_cleanup_deletes_row_mid_kill() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();

        let name = format!("hcom-kill-{}-ptyexit", std::process::id());
        let outcome = kill_mid_pty_exit(&db_path, &name, "proc-kill-pty", |wrapper, n| {
            crate::delivery::cleanup_deleted_instance(wrapper, n, "proc-kill-pty");
        });

        assert_eq!(outcome, TeardownOutcome::SessionStoppedReleasedRow);
        assert!(db.get_instance_full(&name).unwrap().is_none(), "row gone");
        assert_eq!(
            stopped_events(&db, &name),
            1,
            "only the wrapper's stopped event; the kill wrote none"
        );
        let _ = _guard;
    }

    /// A PTY `stale-harness-exit` is a stale wrapper declining to touch a
    /// rebound row, never a self-stop — even when the row then vanishes and
    /// the event names a binding the kill resolved.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_reports_re_registration_when_pty_exit_is_stale_harness() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();

        let name = format!("hcom-kill-{}-ptystale", std::process::id());
        let outcome = kill_mid_pty_exit(&db_path, &name, "proc-kill-stale", |wrapper, n| {
            // Rebound to a fresh process, so the old wrapper's exit logs
            // stale-harness-exit (keyed to the resolved binding) and leaves
            // the row; then the row vanishes.
            wrapper
                .conn()
                .execute(
                    "DELETE FROM process_bindings WHERE instance_name = ?1",
                    rusqlite::params![n],
                )
                .unwrap();
            wrapper
                .set_process_binding("proc-kill-stale-new", "sess-kill-pty-new", n)
                .unwrap();
            crate::delivery::cleanup_deleted_instance(wrapper, n, "proc-kill-stale");
            wrapper
                .conn()
                .execute(
                    "DELETE FROM instances WHERE name = ?1",
                    rusqlite::params![n],
                )
                .unwrap();
        });

        let stale: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = ?1 \
                 AND json_extract(data, '$.reason') = 'stale-harness-exit' \
                 AND json_extract(data, '$.process_id') = 'proc-kill-stale'",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stale, 1, "the wrapper logged its stale-harness-exit");
        assert_eq!(outcome, TeardownOutcome::RowReRegistered);
        let _ = _guard;
    }

    /// A PTY stopped event keyed to a process the kill never resolved is
    /// another incarnation's exit, not this session's self-stop.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_reports_re_registration_when_pty_exit_names_foreign_process() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();

        let name = format!("hcom-kill-{}-ptyforeign", std::process::id());
        let outcome = kill_mid_pty_exit(&db_path, &name, "proc-kill-own", |wrapper, n| {
            // No binding left to gate on, so the foreign wrapper's cleanup
            // runs in full: stopped by pty for its own process id, row gone.
            wrapper
                .conn()
                .execute(
                    "DELETE FROM process_bindings WHERE instance_name = ?1",
                    rusqlite::params![n],
                )
                .unwrap();
            crate::delivery::cleanup_deleted_instance(wrapper, n, "proc-kill-foreign");
        });

        assert_eq!(
            stopped_events(&db, &name),
            1,
            "the foreign wrapper's stopped event landed"
        );
        assert!(db.get_instance_full(&name).unwrap().is_none(), "row gone");
        assert_eq!(outcome, TeardownOutcome::RowReRegistered);
        let _ = _guard;
    }

    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_recognizes_bindingless_pty_stop_for_resolved_incarnation() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();
        let name = format!("hcom-kill-{}-bindingless-stop", std::process::id());
        let mut sleeper = seed_bound_row_with_sleeper(
            &db,
            &name,
            "proc-bindingless-stop",
            "sess-bindingless-stop",
        );
        // An exact timestamp isolates the bindingless ownership branch from
        // the separately tracked snapshot JSON float-precision issue.
        db.conn()
            .execute(
                "UPDATE instances SET created_at = 42 WHERE name = ?",
                rusqlite::params![name],
            )
            .unwrap();
        db.conn()
            .execute(
                "DELETE FROM process_bindings WHERE instance_name = ?",
                rusqlite::params![name],
            )
            .unwrap();
        let result = kill_tracked_instance_with_self_pids(
            &db,
            &name,
            "test",
            &[std::process::id()],
            |n, bindings, excluded, capture| {
                crate::proctruth::reap_instance_tree_for_excluding_captured(
                    &db, n, bindings, excluded, capture,
                )?;
                let snapshot = db.get_instance_snapshot(n).unwrap();
                db.log_life_event(n, "stopped", "pty", "killed", snapshot, None)
                    .unwrap();
                db.delete_instance(n).unwrap();
                Ok(())
            },
        );
        sleeper.kill().ok();
        sleeper.wait().ok();
        assert_eq!(
            result.unwrap().teardown,
            TeardownOutcome::SessionStoppedReleasedRow
        );
        assert!(db.get_instance_full(&name).unwrap().is_none());
        assert_killed_by(&db, &name, "pty");
    }

    /// A bindingless re-incarnation finalizing mid-kill is a re-registration,
    /// not this session's self-stop: a null-process_id stopped event is only
    /// trusted when its snapshot carries the RESOLVED incarnation's
    /// created_at (the same identity the CAS compares). The fresh
    /// incarnation's cleanup snapshots its OWN created_at, so attributing
    /// its exit to the resolved session misreports a genuine re-registration.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_reports_re_registration_when_bindingless_reincarnation_finalizes_mid_kill() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();

        let name = format!("hcom-kill-{}-reborn", std::process::id());
        let outcome = kill_mid_pty_exit(&db_path, &name, "proc-kill-reborn", |wrapper, n| {
            // The row is re-registered bindingless under the same name with
            // a NEW created_at; that fresh incarnation then finalizes: its
            // exit cleanup has no binding to key on (process_id=null),
            // snapshots the new row, and releases it.
            wrapper
                .conn()
                .execute(
                    "DELETE FROM process_bindings WHERE instance_name = ?1",
                    rusqlite::params![n],
                )
                .unwrap();
            wrapper
                .conn()
                .execute(
                    "UPDATE instances SET created_at = created_at + 1000 WHERE name = ?1",
                    rusqlite::params![n],
                )
                .unwrap();
            crate::delivery::cleanup_deleted_instance(wrapper, n, "");
        });

        assert_eq!(outcome, TeardownOutcome::RowReRegistered);
        assert!(db.get_instance_full(&name).unwrap().is_none(), "row gone");
        assert_eq!(
            stopped_events(&db, &name),
            1,
            "only the fresh incarnation's stopped event; the kill wrote none"
        );
        let _ = _guard;
    }

    /// CAS (iv), the atomicity fix: the incarnation comparison and the
    /// teardown writes share ONE `BEGIN IMMEDIATE` transaction, so a rebind
    /// can no longer land in the old check/use gap (comparison passed, then
    /// the write adopted and finalized the rebound row). The rebind here
    /// commits on a SECOND connection inside exactly that window — it takes
    /// the write lock at reap end and holds it well past where the old
    /// comparison ran — and the teardown must still skip, leaving the
    /// rebound bindings intact. With CAS (i)/(iii) (rebind landing inside
    /// the reap seam) this pins the skip landing however the rebind times
    /// relative to the reap.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn kill_teardown_skips_when_rebind_commits_in_the_former_check_use_gap() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();

        let name = format!("hcom-kill-{}-gap", std::process::id());

        let mut recorded = std::process::Command::new("true").spawn().unwrap();
        let recorded_pid = recorded.id() as i64;
        recorded.wait().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) VALUES (?1, 'active', ?2, 'codex', ?3)",
                rusqlite::params![name, now, recorded_pid],
            )
            .unwrap();
        db.set_process_binding("proc-gap-old", "sess-gap", &name)
            .unwrap();

        // The concurrent rebind: a second connection holds the write lock
        // across the old check/use window, then lands the `start --as` shape
        // (bindings replaced, row kept).
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let rebind_db_path = db_path.clone();
        let rebind_name = name.clone();
        let rebinder = std::thread::spawn(move || {
            let db2 = crate::db::HcomDb::open_raw(&rebind_db_path).unwrap();
            db2.with_immediate_transaction(|tx| {
                locked_tx.send(()).ok();
                std::thread::sleep(std::time::Duration::from_millis(500));
                tx.execute(
                    "DELETE FROM process_bindings WHERE instance_name = ?1",
                    rusqlite::params![rebind_name],
                )
                .unwrap();
                tx.execute(
                    "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at) \
                     VALUES ('proc-gap-new', 'sess-gap-new', ?1, ?2)",
                    rusqlite::params![rebind_name, now],
                )
                .unwrap();
                Ok(())
            })
        });

        let self_set = vec![std::process::id()];
        let result = kill_tracked_instance_with_self_pids(
            &db,
            &name,
            "test",
            &self_set,
            move |_n, _b, _e, _capture| {
                // Trigger the concurrent rebind from inside the reap seam
                // and wait until it HOLDS the write lock: it now owns the
                // write path until well past where the old comparison ran.
                locked_rx.recv().unwrap();
                Ok(())
            },
        )
        .unwrap_or_else(|e| panic!("a rebind is not a kill failure: {e}"));
        rebinder
            .join()
            .expect("rebind thread")
            .expect("rebind transaction");

        assert_eq!(
            result.teardown,
            TeardownOutcome::RowReRegistered,
            "a rebind committing in the former check/use gap must skip the teardown"
        );
        assert!(
            db.get_instance_full(&name).unwrap().is_some(),
            "rebound row left intact"
        );
        assert_eq!(
            db.process_binding_ids(&name).unwrap(),
            vec!["proc-gap-new".to_string()],
            "the rebind's binding set is untouched"
        );
        assert_eq!(stopped_events(&db, &name), 0, "no stopped event written");
        let _ = _guard;
    }

    /// The structural half of the atomicity contract: the incarnation gate
    /// and the teardown writes are one transaction. While that transaction
    /// runs (the gate closure is inside it), a second connection cannot
    /// write at all — nothing can land between the comparison and the write.
    #[test]
    #[cfg(unix)]
    #[serial]
    fn teardown_txn_holds_the_write_lock_across_compare_and_writes() {
        let _guard = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();

        let name = format!("hcom-kill-{}-lock", std::process::id());

        let mut recorded = std::process::Command::new("true").spawn().unwrap();
        let recorded_pid = recorded.id() as i64;
        recorded.wait().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) VALUES (?1, 'active', ?2, 'codex', ?3)",
                rusqlite::params![name, now, recorded_pid],
            )
            .unwrap();
        db.set_process_binding("proc-lock", "sess-lock", &name)
            .unwrap();

        let db2 = crate::db::HcomDb::open_raw(&db_path).unwrap();
        db2.conn().execute_batch("PRAGMA busy_timeout=0;").unwrap();
        let probe_name = name.clone();
        let committed = stop_instance_without_reap(&db, &name, "test", "killed", move |_tx| {
            // Inside the single teardown transaction, between the compare
            // and the writes: a second writer must find the path locked.
            let blocked = db2.conn().execute(
                "UPDATE instances SET session_id = 'gap' WHERE name = ?1",
                rusqlite::params![probe_name],
            );
            assert!(
                blocked.is_err(),
                "a second writer must not land between the compare and the write: {blocked:?}"
            );
            Ok(true)
        })
        .unwrap_or_else(|e| panic!("teardown must land: {e}"));
        assert!(committed, "the unchanged incarnation is torn down");
        assert!(db.get_instance_full(&name).unwrap().is_none());
        assert_eq!(stopped_events(&db, &name), 1, "stopped event written");
        let _ = _guard;
    }
}
