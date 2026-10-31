//! Launch-context capture plus process/session binding for instance records.
//!
//! This module owns the hook-facing identity handshake:
//! launch metadata capture, placeholder/canonical binding, and instance-row
//! initialization for newly launched or recovered sessions.

use anyhow::Context;
use rusqlite::OptionalExtension;

use crate::db::{HcomDb, InstanceRow};
use crate::hooks::common::PostCommit;
use crate::instance_names::{PLACEHOLDER_CONTEXT, PLACEHOLDER_STATUS};
use crate::proctruth::OmpOwner;
use crate::shared::time::{now_epoch_f64, now_epoch_i64};
use crate::shared::{ST_INACTIVE, ST_LISTENING};

#[cfg(all(test, unix))]
#[path = "instance_binding_terminal_tests.rs"]
mod terminal_ownership_tests;

/// Persist terminal launch metadata without clobbering other launch_context fields.
///
/// The launcher owns the authoritative preset decision. launch_context is only
/// for late-bound metadata such as pane_id, terminal_id, and env snapshot.
pub fn persist_terminal_launch_context(
    db: &HcomDb,
    instance_name: &str,
    requested_preset: Option<&str>,
    effective_preset: &str,
    process_id: Option<&str>,
) -> anyhow::Result<()> {
    let persist = || -> anyhow::Result<()> {
        let row = db
            .get_instance_full(instance_name)?
            .with_context(|| format!("Missing instance '{instance_name}'"))?;
        let mut ctx = omp_launch_context(&row)?;
        if let Some(pid) = process_id.filter(|v| !v.is_empty()) {
            ctx.insert("process_id".into(), serde_json::json!(pid));
        }
        if !effective_preset.is_empty() {
            ctx.insert(
                "terminal_preset_effective".into(),
                serde_json::json!(effective_preset),
            );
            // Legacy compatibility for older readers and migration logic.
            ctx.insert(
                "terminal_preset".into(),
                serde_json::json!(effective_preset),
            );
        }
        if let Some(requested) = requested_preset.filter(|v| !v.is_empty() && *v != "default") {
            ctx.insert(
                "terminal_preset_requested".into(),
                serde_json::json!(requested),
            );
        }
        let mut updates = serde_json::Map::new();
        updates.insert(
            "terminal_preset_requested".into(),
            serde_json::json!(
                requested_preset
                    .filter(|v| !v.is_empty() && *v != "default")
                    .unwrap_or("")
            ),
        );
        updates.insert(
            "terminal_preset_effective".into(),
            serde_json::json!(effective_preset),
        );
        updates.insert(
            "launch_context".into(),
            serde_json::json!(serde_json::to_string(&ctx)?),
        );
        db.update_instance_fields(instance_name, &updates)
    };
    if db.conn().is_autocommit() {
        db.with_immediate_transaction(|_tx| persist())
    } else {
        persist()
    }
}

/// Capture environment context and store it for the instance.
///
/// Captures git branch, terminal program, tty, and relevant env vars.
pub fn capture_and_store_launch_context(db: &HcomDb, instance_name: &str) {
    let result = store_captured_launch_context(db, instance_name, capture_context());
    if let Err(error) = result {
        crate::log::log_error("binding", "capture_launch_context", &format!("{error:#}"));
    }
}

/// Merge an already captured snapshot under the caller's writer transaction.
/// Native owner facts, including malformed facts, are never erased by capture.
pub(crate) fn store_captured_launch_context(
    db: &HcomDb,
    instance_name: &str,
    captured: serde_json::Map<String, serde_json::Value>,
) -> anyhow::Result<()> {
    let store = || -> anyhow::Result<()> {
        let mut ctx = captured;
        let row = db
            .get_instance_full(instance_name)?
            .with_context(|| format!("Missing instance '{instance_name}'"))?;
        let old_ctx = omp_launch_context(&row)?;
        for key in [
            "pane_id",
            "terminal_id",
            "kitty_listen_on",
            "process_id",
            "terminal_preset_effective",
            "omp_owner",
            "omp_launch_anchor",
        ] {
            if let Some(value) = old_ctx.get(key)
                && (matches!(key, "omp_owner" | "omp_launch_anchor")
                    || launch_context_value_missing(ctx.get(key)))
            {
                ctx.insert(key.to_string(), value.clone());
            }
        }
        let mut updates = serde_json::Map::new();
        updates.insert(
            "launch_context".into(),
            serde_json::json!(serde_json::to_string(&ctx)?),
        );
        db.update_instance_fields(instance_name, &updates)
    };
    if db.conn().is_autocommit() {
        db.with_immediate_transaction(|_tx| store())
    } else {
        store()
    }
}

/// "Missing" for the preserve-from-prior-context check. Treats absent, JSON
/// null, and empty strings as missing. Non-string non-null values (numbers,
/// objects, arrays) are considered present even though every preserved field
/// is currently a string — this is intentionally conservative so a future
/// non-string preserved field doesn't silently get clobbered by re-capture.
fn launch_context_value_missing(value: Option<&serde_json::Value>) -> bool {
    match value {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::String(s)) => s.is_empty(),
        Some(_) => false,
    }
}

/// Capture launch context snapshot.
pub(crate) fn capture_context() -> serde_json::Map<String, serde_json::Value> {
    let mut ctx = serde_json::Map::new();

    // Git branch
    let git_branch = std::process::Command::new("git")
        .args(["branch", "--show-current"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    ctx.insert("git_branch".into(), serde_json::json!(git_branch));

    // TTY
    let tty = std::process::Command::new("tty")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    ctx.insert("tty".into(), serde_json::json!(tty));

    // Env vars (only include if set)
    let env_keys = [
        "TERM_PROGRAM",
        "TERM_SESSION_ID",
        "WINDOWID",
        "ITERM_SESSION_ID",
        "KITTY_WINDOW_ID",
        "KITTY_PID",
        "KITTY_LISTEN_ON",
        "ALACRITTY_WINDOW_ID",
        "WEZTERM_PANE",
        "GNOME_TERMINAL_SCREEN",
        "KONSOLE_DBUS_WINDOW",
        "TERMINATOR_UUID",
        "TILIX_ID",
        "GUAKE_TAB_UUID",
        "WT_SESSION",
        "ConEmuHWND",
        "TMUX_PANE",
        "STY",
        "ZELLIJ_SESSION_NAME",
        "ZELLIJ_PANE_ID",
        "SSH_TTY",
        "SSH_CONNECTION",
        "WSL_DISTRO_NAME",
        "VSCODE_PID",
        "CURSOR_AGENT",
        "INSIDE_EMACS",
        "NVIM_LISTEN_ADDRESS",
        "CODESPACE_NAME",
        "GITPOD_WORKSPACE_ID",
        "CLOUD_SHELL",
        "REPL_ID",
    ];
    let mut env_map = serde_json::Map::new();
    for key in &env_keys {
        if let Ok(val) = std::env::var(key)
            && !val.is_empty()
        {
            env_map.insert((*key).to_string(), serde_json::json!(val));
        }
    }
    ctx.insert("env".into(), serde_json::Value::Object(env_map));

    // The launcher already resolved the effective preset; record it so
    // child agents can inherit it (see commands::launch). Pane IDs are
    // late-bound from the env vars the preset declares.
    if let Ok(preset_name) = std::env::var("HCOM_LAUNCHED_PRESET")
        && !preset_name.is_empty()
    {
        ctx.insert(
            "terminal_preset_effective".into(),
            serde_json::json!(preset_name),
        );

        if let Some(pane_id_env) = crate::config::get_merged_preset_pane_id_env(&preset_name)
            && let Ok(pane_id) = std::env::var(pane_id_env)
            && !pane_id.is_empty()
        {
            ctx.insert("pane_id".into(), serde_json::json!(pane_id));
        }
    }

    // Process ID for kitty close-by-env matching
    if let Ok(pid) = std::env::var("HCOM_PROCESS_ID")
        && !pid.is_empty()
    {
        ctx.insert("process_id".into(), serde_json::json!(pid));

        // Terminal ID from parent's stdout capture
        let id_file = crate::paths::hcom_dir()
            .join(".tmp")
            .join("terminal_ids")
            .join(&pid);
        if id_file.exists() {
            if let Ok(content) = std::fs::read_to_string(&id_file) {
                let terminal_id = content.trim().to_string();
                if !terminal_id.is_empty() {
                    if std::env::var("HCOM_LAUNCHED_PRESET").as_deref() == Ok("zellij")
                        && let Some(pane_id) = zellij_pane_id_from_terminal_id(&terminal_id)
                    {
                        ctx.insert("pane_id".into(), serde_json::json!(pane_id));
                    }
                    ctx.insert("terminal_id".into(), serde_json::json!(terminal_id));
                }
            }
            let _ = std::fs::remove_file(&id_file);
        }
    }

    ctx
}

fn zellij_pane_id_from_terminal_id(terminal_id: &str) -> Option<String> {
    terminal_id
        .strip_prefix("terminal_")
        .filter(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
        .map(|suffix| suffix.to_string())
}

fn is_true_launch_placeholder(data: Option<&InstanceRow>) -> bool {
    let Some(data) = data else {
        return false;
    };
    if data.session_id.is_some() {
        return false;
    }

    if crate::instances::is_launching_placeholder(data) {
        return true;
    }

    // OpenCode and other PTY-backed tools can be marked ready/listening by the PTY
    // watcher before their later session-start hook binds a session id. Those rows
    // are still launch placeholders, but no longer match the stricter "pending/new"
    // display predicate. Keep this narrow: active no-session rows are real work, not
    // launch placeholders.
    data.status == ST_LISTENING
        && matches!(
            data.status_context.as_str(),
            "start" | "ready_observed" | "launch_blocked_cleared"
        )
}

fn rekey_migrated_terminal(db: &HcomDb, canonical: &str, ph: &InstanceRow) {
    let Some(context) = ph.launch_context.as_deref() else {
        return;
    };
    let nonce = |context: &str| {
        serde_json::from_str::<serde_json::Value>(context)
            .ok()?
            .get("process_id")?
            .as_str()
            .map(str::to_owned)
    };
    let Some(expected) = nonce(context).filter(|id| !id.is_empty()) else {
        return;
    };
    // A failed/rolled-back migration (or a canonical row retaining another
    // incarnation's metadata) cannot transfer the placeholder's receipt.
    if db
        .get_instance_full(canonical)
        .ok()
        .flatten()
        .and_then(|row| row.launch_context)
        .and_then(|context| nonce(&context))
        .as_deref()
        != Some(expected.as_str())
    {
        return;
    }
    if let Err(error) = crate::terminal::rekey_terminal_owner(&ph.name, canonical, context) {
        crate::log::log_error(
            "binding",
            "placeholder.migrate_terminal_owner",
            &error.to_string(),
        );
    }
}

/// Carry the placeholder's PID and terminal context on the caller's transaction.
/// Receipt ownership is re-keyed only after commit via `rekey_migrated_terminal`;
/// rollback must not change files.
fn migrate_placeholder_runtime_state_in_txn(
    db: &HcomDb,
    tx: &rusqlite::Transaction<'_>,
    canonical_name: &str,
    placeholder_data: Option<&InstanceRow>,
) -> anyhow::Result<()> {
    let Some(ph) = placeholder_data else {
        return Ok(());
    };
    if let Some(pid) = ph.pid
        && let Ok(pid_u32) = u32::try_from(pid)
    {
        db.update_instance_pid(canonical_name, pid_u32)?;
    }
    if let Some(ctx) = &ph.launch_context {
        db.store_launch_context_in_txn(tx, canonical_name, ctx)?;
    }
    Ok(())
}

/// After a restored canonical bind, migrate and retire its true launch
/// placeholder on the same transaction. Every failure rolls back the bind.
fn retire_true_placeholder_after_canonical_bind(
    db: &HcomDb,
    tx: &rusqlite::Transaction<'_>,
    placeholder_name: Option<&String>,
    canonical_name: &str,
    placeholder_data: Option<&InstanceRow>,
) -> anyhow::Result<()> {
    let Some(ph_name) = placeholder_name else {
        return Ok(());
    };
    if ph_name == canonical_name || !is_true_launch_placeholder(placeholder_data) {
        return Ok(());
    }

    db.migrate_notify_endpoints_in_txn(tx, ph_name, canonical_name)?;
    migrate_placeholder_runtime_state_in_txn(db, tx, canonical_name, placeholder_data)?;
    anyhow::ensure!(
        db.delete_instance(ph_name)?,
        "Launch placeholder disappeared during bind"
    );
    Ok(())
}

/// Whether another live process still holds this row. A stale binding alone
/// cannot keep an abandoned identity alive; a live carrier of that binding can.
fn held_by_another_live_process(
    db: &HcomDb,
    name: &str,
    moving_process_id: &str,
    moving_omp_owner: Option<&OmpOwner>,
) -> anyhow::Result<bool> {
    if let Some(owner) = moving_omp_owner {
        let bindings = db.process_bindings_registered(name)?;
        if bindings.iter().all(|(id, _)| id == moving_process_id) {
            return Ok(false);
        }
        let moving_is_bound_here = bindings.iter().any(|(id, _)| id == moving_process_id);
        let row = db
            .get_instance_full(name)?
            .with_context(|| format!("Missing displaced OMP identity '{name}'"))?;
        let native_owner = omp_native_identity(owner.pid);
        let mut carrier_presence = None;
        for (id, registered) in &bindings {
            if id == moving_process_id {
                continue;
            }
            if let Some(pid) = crate::proctruth::omp_minted_pid(id) {
                let session = db.get_process_binding_full(id)?.and_then(|(sid, _)| sid);
                if pid == owner.pid
                    && native_owner.as_deref() == Some(owner.incarnation.as_str())
                    && validate_omp_registration(&row, session.as_deref(), *registered, id, owner)
                        .is_ok()
                {
                    // Multiple minted ids are one holder only with the row's
                    // exact stamp (or strict legacy registration) and fresh
                    // native incarnation, never merely numeric PID equality.
                    continue;
                }
                if crate::proctruth::process_gone(pid) {
                    continue;
                }
            }
            if crate::proctruth::is_launcher_process_id(id) {
                let presence = match carrier_presence {
                    Some(presence) => presence,
                    None => {
                        let Some(stored) = crate::proctruth::stored_omp_owner(&row)? else {
                            return Ok(true);
                        };
                        let pid = omp_row_pid(&row)?;
                        anyhow::ensure!(stored.pid == pid, "OMP stamp/PID mismatch for '{name}'");
                        if !crate::proctruth::process_gone(pid) {
                            if moving_is_bound_here
                                && stored == *owner
                                && native_owner.as_deref() == Some(owner.incarnation.as_str())
                            {
                                // This bound native owner may retain its own launcher aliases.
                                continue;
                            }
                            return Ok(true);
                        }
                        // A retained launcher UUID is stale only when its
                        // stamped native owner is gone AND a checked scan rules
                        // out every other carrier of this row or any retained binding ID.
                        let retained_ids = bindings
                            .iter()
                            .filter(|(id, _)| id != moving_process_id)
                            .map(|(id, _)| id.clone())
                            .collect::<Vec<_>>();
                        let presence =
                            crate::proctruth::omp_carrier_presence(name, &retained_ids, owner);
                        carrier_presence = Some(presence);
                        presence
                    }
                };
                if presence == crate::proctruth::OmpCarrierPresence::Absent {
                    continue;
                }
            }
            // A foreign incarnation or an id with no readable native owner
            // cannot authorize deleting this row or moving its endpoints.
            return Ok(true);
        }
        return Ok(false);
    }
    let others = db.other_process_bindings_for_instance(name, moving_process_id)?;
    if others.is_empty() {
        return Ok(false);
    }
    let owners = crate::proctruth::omp_owner_bindings(db, name);
    Ok(
        crate::proctruth::processes_for_instance("", &others, &owners)
            .into_iter()
            .any(|carrier| {
                !crate::proctruth::process_gone(carrier.pid)
                    && others.iter().any(|id| {
                        carrier.process_id == *id
                            || crate::proctruth::omp_minted_pid(id) == Some(carrier.pid)
                    })
            }),
    )
}

/// Release the displaced session's row with the same snapshotted `life.stopped`
/// event and control-plane cleanup as a regular stop, but without signalling.
/// Called after the moving process has bound its new name, in that same
/// immediate transaction. The caller dispatches the event after commit.
fn release_displaced_session_identity(
    db: &HcomDb,
    tx: &rusqlite::Transaction<'_>,
    displaced_name: &str,
    moving_process_id: &str,
    another_holder: bool,
    omp_owned: bool,
    displaced_session: Option<&str>,
) -> anyhow::Result<Option<(i64, serde_json::Value)>> {
    let Some(row) = db.get_instance_full(displaced_name)? else {
        return Ok(None);
    };
    if another_holder || (!omp_owned && row.session_id.is_none()) {
        return Ok(None);
    }
    let mut snapshot = db
        .get_instance_snapshot(displaced_name)?
        .with_context(|| format!("session switch: missing snapshot for '{displaced_name}'"))?;
    snapshot["name"] = serde_json::json!(displaced_name);
    snapshot["parent_session_id"] = serde_json::json!(row.parent_session_id);
    snapshot["created_at_bits"] = serde_json::json!(row.created_at.to_bits());
    snapshot["last_seen"] = serde_json::json!(row.last_seen);
    snapshot["name_announced"] = serde_json::json!(row.name_announced);
    if omp_owned {
        // The process binding was captured before the switch. Poisoned row
        // session text neither prevents release nor becomes its restore key.
        snapshot["session_id"] = serde_json::json!(displaced_session.unwrap_or(""));
    }
    let event = serde_json::json!({
        "action": "stopped",
        "by": "session_switch",
        "reason": "exit:session_switch",
        "process_id": moving_process_id,
        "snapshot": snapshot,
    });
    let (won, event_id) = db.finalize_instance_stop_in_txn(
        tx,
        displaced_name,
        row.created_at,
        row.pid,
        row.session_id.as_deref(),
        row.agent_id.as_deref(),
        &event,
        None,
        None,
    )?;
    if !won {
        anyhow::bail!("session switch: could not release '{displaced_name}'");
    }
    Ok(event_id.map(|id| (id, event)))
}

/// Move the switching process off its displaced row onto `new_name`, on the
/// caller's transaction. Unless another live process still holds the
/// displaced row, its runtime state (pid, launch_context) and notify endpoints
/// follow the process; then the displaced row is released. Every failure is
/// returned so the caller's whole switch rolls back: no commit ever leaves the
/// endpoints on neither row.
#[allow(clippy::too_many_arguments)]
fn move_process_off_displaced_row(
    db: &HcomDb,
    tx: &rusqlite::Transaction<'_>,
    displaced_name: &str,
    new_name: &str,
    displaced_data: Option<&InstanceRow>,
    moving_process_id: &str,
    moving_omp_owner: Option<&OmpOwner>,
    displaced_session: Option<&str>,
) -> anyhow::Result<Option<(i64, serde_json::Value)>> {
    let another_holder =
        held_by_another_live_process(db, displaced_name, moving_process_id, moving_omp_owner)?;
    if !another_holder {
        // The live process and its terminal move with this binding; a shared
        // row still belongs to its holder.
        migrate_placeholder_runtime_state_in_txn(db, tx, new_name, displaced_data)
            .with_context(|| format!("session switch: moving runtime state to '{new_name}'"))?;
        db.migrate_notify_endpoints_in_txn(tx, displaced_name, new_name)
            .with_context(|| format!("session switch: moving notify endpoints to '{new_name}'"))?;
    }
    release_displaced_session_identity(
        db,
        tx,
        displaced_name,
        moving_process_id,
        another_holder,
        moving_omp_owner.is_some(),
        displaced_session,
    )
}

/// Recreate a missing instance row from an active placeholder (resume after stop/kill).
///
/// The `life.created` event's fan-out runs inline with its TCP wakes
/// collected into `post`: callers inside a write txn pass the txn's
/// PostCommit (fired after commit); callers with no open txn pass a local
/// one and fire it at the call site.
fn recreate_instance_from_placeholder(
    db: &HcomDb,
    target_name: &str,
    session_id: &str,
    ph: Option<&InstanceRow>,
    post: &mut PostCommit,
) -> anyhow::Result<()> {
    if db.get_instance_full(target_name)?.is_some() {
        return Ok(());
    }
    let Some(ph) = ph else {
        anyhow::bail!("Missing launch placeholder to recreate '{target_name}'");
    };
    initialize_instance_in_position_file_checked(
        db,
        target_name,
        Some(session_id),
        ph.parent_session_id.as_deref(),
        ph.parent_name.as_deref(),
        ph.agent_id.as_deref(),
        (!ph.transcript_path.is_empty()).then_some(ph.transcript_path.as_str()),
        Some(ph.tool.as_str()),
        ph.background != 0,
        ph.tag.as_deref(),
        None,
        None,
        ph.hints.as_deref(),
        Some(ph.directory.as_str()),
        post,
    )?;
    Ok(())
}

/// Identity metadata a reclaim or restore carries over: what a `life.stopped`
/// snapshot records about the identity itself (its tool and directory, its
/// lineage, its per-seat settings and its delivery cursor), and nothing of the
/// process incarnation that held it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RebindTargetMetadata {
    pub(crate) tool: String,
    pub(crate) directory: String,
    pub(crate) last_event_id: i64,
    pub(crate) parent_session_id: Option<String>,
    pub(crate) parent_name: Option<String>,
    pub(crate) agent_id: Option<String>,
    pub(crate) transcript_path: Option<String>,
    pub(crate) tag: Option<String>,
    pub(crate) hints: Option<String>,
    pub(crate) wait_timeout: Option<i64>,
    pub(crate) subagent_timeout: Option<i64>,
    pub(crate) background: bool,
    pub(crate) background_log_file: Option<String>,
    pub(crate) launch_args: Option<String>,
    pub(crate) name_announced: i64,
    pub(crate) purpose: Option<String>,
    pub(crate) current: Option<String>,
}

impl RebindTargetMetadata {
    fn from_row(row: InstanceRow) -> Self {
        let text = |value: String| Some(value).filter(|s| !s.is_empty());
        Self {
            tool: row.tool,
            directory: row.directory,
            last_event_id: row.last_event_id,
            parent_session_id: row.parent_session_id,
            parent_name: row.parent_name,
            agent_id: row.agent_id,
            transcript_path: text(row.transcript_path),
            tag: row.tag,
            hints: row.hints,
            wait_timeout: row.wait_timeout,
            subagent_timeout: row.subagent_timeout,
            background: row.background != 0,
            background_log_file: text(row.background_log_file),
            launch_args: row.launch_args,
            name_announced: row.name_announced,
            purpose: row.purpose,
            current: row.current,
        }
    }

    /// Read a `life.stopped` snapshot as stop finalization writes it. Empty
    /// strings read as unset, like the row columns they were copied from.
    fn from_snapshot(snapshot: &serde_json::Value) -> Self {
        let text = |key: &str| {
            snapshot
                .get(key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let int = |key: &str| snapshot.get(key).and_then(|v| v.as_i64());
        Self {
            tool: text("tool").unwrap_or_default(),
            directory: text("directory").unwrap_or_default(),
            last_event_id: int("last_event_id").unwrap_or(0),
            parent_session_id: text("parent_session_id"),
            parent_name: text("parent_name"),
            agent_id: text("agent_id"),
            transcript_path: text("transcript_path"),
            tag: text("tag"),
            hints: text("hints"),
            wait_timeout: int("wait_timeout"),
            subagent_timeout: int("subagent_timeout"),
            background: int("background").unwrap_or(0) != 0,
            background_log_file: text("background_log_file"),
            launch_args: text("launch_args"),
            name_announced: int("name_announced").unwrap_or(0),
            purpose: text("purpose"),
            current: text("current"),
        }
    }
}

/// Load rebind metadata from the live row first, then the newest stopped
/// snapshot. `start --as` and the stopped-snapshot rebuild in
/// [`bind_session_to_process`] both restore the identity's cursor from here.
///
/// The snapshot is selected by action in SQL, not from a window of recent
/// life events, so a stop behind later life events is still found instead of
/// the caller falling back to a fresh cursor. A `stopped` event with no
/// snapshot object (a stale-harness exit) carries no metadata and is skipped.
pub(crate) fn load_rebind_target_metadata(
    db: &HcomDb,
    name: &str,
) -> anyhow::Result<RebindTargetMetadata> {
    use rusqlite::OptionalExtension;

    if let Some(inst) = db.get_instance_full(name)? {
        return Ok(RebindTargetMetadata::from_row(inst));
    }

    let snapshot: Option<String> = db
        .conn()
        .query_row(
            "SELECT json_extract(data, '$.snapshot') FROM events
             WHERE type = 'life'
               AND instance = ?
               AND json_extract(data, '$.action') = 'stopped'
               AND json_type(data, '$.snapshot') = 'object'
             ORDER BY id DESC LIMIT 1",
            rusqlite::params![name],
            |row| row.get(0),
        )
        .optional()?;
    let Some(snapshot) = snapshot else {
        anyhow::bail!("No rebind metadata found for '{}'", name);
    };
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot)?;
    Ok(RebindTargetMetadata::from_snapshot(&snapshot))
}

/// Recreate a missing instance row from the `life.stopped` snapshot that matched
/// its session, for a restore with no placeholder row to copy from. Runs on the
/// caller's transaction (the restore_stopped switch) and opens none of its own,
/// so the row is never visible with the fresh cursor initialization assigns,
/// and a switch that fails later leaves no row behind. Errors when the row
/// cannot be recreated.
///
/// The snapshot is the one stop finalization records
/// ([`HcomDb::finalize_instance_stop_in_txn`]'s `stopped` event), read through
/// [`RebindTargetMetadata::from_snapshot`]. Kept:
/// - lineage: `parent_session_id`, `parent_name`, `agent_id`, so a subagent
///   comes back a subagent ([`crate::instances::is_subagent_instance`]);
/// - classification and routing: `tool`, `directory`, `transcript_path`, `tag`,
///   `hints`, `wait_timeout`, `subagent_timeout`, `background`,
///   `background_log_file`, `launch_args`, `name_announced`, `purpose`,
///   `current`;
/// - the delivery cursor: the name's newest, the one `start --as` restores
///   ([`load_rebind_target_metadata`], read while the row is still missing),
///   so messages sent while it was stopped stay pending.
///
/// Fresh, never copied: `session_id` (the switch's), `created_at`,
/// `created_at_bits`, `last_seen` and `status` (a new row incarnation), `pid`
/// with its `pid_start_time`/`boot_id` (the stopped process; the moving
/// process's pid follows it from the row it leaves), and `origin_device_id`
/// (the row is bound to a process on this device). `parent_session_id` is kept
/// while a row still carries that session: its foreign key admits no other
/// value, and a parent that stopped meanwhile reads NULL, as
/// `ON DELETE SET NULL` leaves a live subagent whose parent row goes away.
fn recreate_instance_from_stopped_snapshot(
    db: &HcomDb,
    tx: &rusqlite::Transaction<'_>,
    target_name: &str,
    session_id: &str,
    snapshot: &serde_json::Value,
    post: &mut PostCommit,
) -> anyhow::Result<()> {
    use rusqlite::OptionalExtension;

    if db.get_instance_full(target_name)?.is_some() {
        return Ok(());
    }
    let cursor = load_rebind_target_metadata(db, target_name)?.last_event_id;
    let identity = RebindTargetMetadata::from_snapshot(snapshot);
    let parent_session_id = match identity.parent_session_id.as_deref() {
        Some(parent) => tx
            .query_row(
                "SELECT 1 FROM instances WHERE session_id = ?",
                rusqlite::params![parent],
                |_| Ok(()),
            )
            .optional()?
            .map(|()| parent),
        None => None,
    };
    initialize_instance_in_position_file_checked(
        db,
        target_name,
        Some(session_id),
        parent_session_id,
        identity.parent_name.as_deref(),
        // Set below: the row insert is INSERT OR REPLACE, which would delete
        // another row holding this UNIQUE agent_id; the UPDATE fails instead.
        None,
        identity.transcript_path.as_deref(),
        Some(identity.tool.as_str()).filter(|tool| !tool.is_empty()),
        identity.background,
        identity.tag.as_deref(),
        identity.wait_timeout,
        identity.subagent_timeout,
        identity.hints.as_deref(),
        Some(identity.directory.as_str()).filter(|dir| !dir.is_empty()),
        post,
    )
    .with_context(|| format!("restore_stopped: could not recreate '{target_name}'"))?;
    let mut updates = serde_json::Map::new();
    updates.insert("last_event_id".into(), serde_json::json!(cursor));
    updates.insert(
        "name_announced".into(),
        serde_json::json!(identity.name_announced),
    );
    for (column, value) in [
        ("agent_id", &identity.agent_id),
        ("background_log_file", &identity.background_log_file),
        ("launch_args", &identity.launch_args),
        ("purpose", &identity.purpose),
        ("current", &identity.current),
    ] {
        if let Some(value) = value {
            updates.insert(column.into(), serde_json::json!(value));
        }
    }
    db.update_instance_fields(target_name, &updates)
        .with_context(|| {
            format!("restore_stopped: could not restore the identity of '{target_name}'")
        })
}

#[cfg(test)]
thread_local! {
    /// Test seam: runs once inside the restore_stopped switch transaction,
    /// after its last write and before the commit, so a test can read the DB
    /// from a second connection the way another process sees it mid-switch.
    static RESTORE_STOPPED_COMMIT_GAP_HOOK: crate::db::GapHook = const { std::cell::Cell::new(None) };
}

/// Whether `process_id` presents the process incarnation the `life.stopped`
/// event `stop` recorded: the stop's own `process_id`, or an OMP-minted id
/// whose pid is the snapshot's anchor pid, alive with the snapshot's start
/// time on the same boot. A launcher-launched seat records its launcher id
/// on the stop, while its plugin re-mints `omp-<pid>-...` once that id's
/// binding is gone, so the anchor arm is what recognizes it. Never the bare
/// pid: a reused pid has a later start time.
fn stop_recorded_process(
    stop: &serde_json::Value,
    process_id: &str,
    live_identity: &dyn Fn(u32) -> Option<(u64, String)>,
) -> bool {
    if stop.get("process_id").and_then(serde_json::Value::as_str) == Some(process_id) {
        return true;
    }
    let Some(pid) = crate::proctruth::omp_minted_pid(process_id) else {
        return false;
    };
    let snapshot = &stop["snapshot"];
    let (Some(anchor), Some(start_time), Some(boot_id)) = (
        snapshot.get("pid").and_then(serde_json::Value::as_u64),
        snapshot
            .get("pid_start_time")
            .and_then(serde_json::Value::as_u64),
        snapshot.get("boot_id").and_then(serde_json::Value::as_str),
    ) else {
        return false;
    };
    anchor == u64::from(pid)
        && live_identity(pid)
            .is_some_and(|(live_start, live_boot)| live_start == start_time && live_boot == boot_id)
}

/// The omp-start hook's resurrection guard (ffc-vpqoz): the stopped name bind
/// Path 2 would recreate for `session_id` when `process_id` is the very
/// process whose stop that was. omp emits `session_shutdown` before it aborts
/// the agent, so an exiting seat's plugin re-runs omp-start from the aborted
/// turn's events after its own release; a process stopped from outside was
/// stopped on purpose. Either way the recorded stop wins. A different process
/// (a resume, a new launch) restores as before, and so does the same process
/// returning from a session switch, which moved it rather than stopped it.
/// Only the automatic hook consults this: an explicit `hcom start` rejoins.
pub fn stopped_restore_for_own_process(
    db: &HcomDb,
    session_id: &str,
    process_id: &str,
) -> Option<String> {
    // A bound session takes Path 1, which never recreates a stopped row.
    if !matches!(db.get_session_binding(session_id), Ok(None)) {
        return None;
    }
    let (name, stop) = db
        .find_stopped_event_by_session_id(session_id)
        .ok()
        .flatten()?;
    if stop.get("by").and_then(serde_json::Value::as_str) == Some("session_switch") {
        return None;
    }
    // A row that still exists is not a resurrection.
    if !matches!(db.get_instance_full(&name), Ok(None)) {
        return None;
    }
    stop_recorded_process(
        &stop,
        process_id,
        &crate::sys::process::procfs_start_identity,
    )
    .then_some(name)
}

fn omp_launch_context(
    row: &InstanceRow,
) -> anyhow::Result<serde_json::Map<String, serde_json::Value>> {
    match row
        .launch_context
        .as_deref()
        .filter(|json| !json.is_empty())
    {
        Some(json) => serde_json::from_str(json)
            .with_context(|| format!("Malformed launch context for '{}'", row.name)),
        None => Ok(serde_json::Map::new()),
    }
}

fn require_local_omp_row(row: &InstanceRow) -> anyhow::Result<()> {
    anyhow::ensure!(
        row.tool == "omp" && row.origin_device_id.as_deref().is_none_or(str::is_empty),
        "Instance '{}' is not a local OMP identity",
        row.name
    );
    Ok(())
}

fn omp_row_pid(row: &InstanceRow) -> anyhow::Result<u32> {
    row.pid
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|&pid| pid != 0)
        .with_context(|| format!("Missing OMP native PID for '{}'", row.name))
}

fn stored_omp_launch_anchor(row: &InstanceRow) -> anyhow::Result<Option<OmpOwner>> {
    let context = omp_launch_context(row)?;
    let Some(value) = context.get("omp_launch_anchor") else {
        return Ok(None);
    };
    let anchor: OmpOwner = serde_json::from_value(value.clone())
        .with_context(|| format!("Malformed OMP launch anchor for '{}'", row.name))?;
    anyhow::ensure!(
        anchor.pid != 0 && !anchor.incarnation.trim().is_empty(),
        "Invalid OMP launch anchor for '{}'",
        row.name
    );
    Ok(Some(anchor))
}

// These probes normally use the shared native boundary. Tests may substitute
// one explicit caller incarnation, scoped to their thread and restored on panic.
fn prove_omp_caller(anchor: u32) -> anyhow::Result<OmpOwner> {
    #[cfg(test)]
    if let Some(result) = OMP_BINDING_OWNER_FIXTURE.with_borrow(|fixture| {
        fixture.as_ref().map(|fixture| {
            anyhow::ensure!(
                (anchor == fixture.owner.pid || fixture.launch_anchor == Some(anchor))
                    && fixture.incarnation.as_deref() == Some(fixture.owner.incarnation.as_str()),
                "OMP caller owner is not current"
            );
            Ok(fixture.owner.clone())
        })
    }) {
        return result;
    }
    crate::proctruth::omp_caller_owner(anchor)
}

fn omp_native_identity(pid: u32) -> Option<String> {
    #[cfg(test)]
    if let Some(identity) = OMP_BINDING_OWNER_FIXTURE.with_borrow(|fixture| {
        fixture
            .as_ref()
            .filter(|fixture| fixture.owner.pid == pid)
            .map(|fixture| fixture.incarnation.clone())
    }) {
        return identity;
    }
    crate::sys::process::identity(pid)
}

fn omp_native_start_epoch(pid: u32) -> Option<f64> {
    #[cfg(test)]
    if let Some(started) = OMP_BINDING_OWNER_FIXTURE.with_borrow(|fixture| {
        fixture
            .as_ref()
            .filter(|fixture| fixture.owner.pid == pid)
            .map(|fixture| fixture.started)
    }) {
        return started;
    }
    crate::sys::process::start_epoch(pid)
}

fn require_omp_owner_current(owner: &OmpOwner) -> anyhow::Result<()> {
    #[cfg(test)]
    if OMP_BINDING_OWNER_FIXTURE.with_borrow(Option::is_some) {
        anyhow::ensure!(
            prove_omp_caller(owner.pid)? == *owner
                && omp_native_identity(owner.pid).as_deref() == Some(owner.incarnation.as_str()),
            "OMP caller incarnation changed"
        );
        return Ok(());
    }
    crate::proctruth::require_omp_owner_current(owner)
}

fn validate_omp_registration(
    row: &InstanceRow,
    binding_session: Option<&str>,
    registered_at: f64,
    process_id: &str,
    owner: &OmpOwner,
) -> anyhow::Result<()> {
    require_local_omp_row(row)?;
    let stored = crate::proctruth::stored_omp_owner(row)?;
    let anchor = stored_omp_launch_anchor(row)?;
    if let Some(stored) = stored {
        let pid = omp_row_pid(row)?;
        anyhow::ensure!(
            stored.pid == pid && stored == *owner,
            "OMP owner stamp disagrees with caller or row PID for '{}'",
            row.name
        );
        return Ok(());
    }
    if let Some(anchor) = anchor {
        let pid = omp_row_pid(row)?;
        anyhow::ensure!(
            anchor.pid == pid
                && omp_native_identity(pid).as_deref() == Some(anchor.incarnation.as_str()),
            "OMP launch anchor is not current for '{}'",
            row.name
        );
        if pid != owner.pid {
            anyhow::ensure!(
                crate::proctruth::is_launcher_process_id(process_id)
                    && binding_session.is_none_or(str::is_empty),
                "Only an unbound OMP launch registration may hand off its wrapper"
            );
        }
        return Ok(());
    }

    // A pre-upgrade binding is registration evidence only if it predates no
    // part of this native process's lifetime. Never invent a timestamp or grace.
    match row.pid {
        Some(_) => anyhow::ensure!(
            omp_row_pid(row)? == owner.pid,
            "OMP legacy row PID disagrees with its native owner for '{}'",
            row.name
        ),
        None => anyhow::ensure!(
            crate::proctruth::omp_minted_pid(process_id) == Some(owner.pid),
            "PID-less OMP legacy registration requires its minted native owner"
        ),
    }
    let started = omp_native_start_epoch(owner.pid)
        .filter(|time| time.is_finite() && *time > 0.0)
        .context("Missing OMP native birth time")?;
    anyhow::ensure!(
        omp_native_identity(owner.pid).as_deref() == Some(owner.incarnation.as_str())
            && registered_at.is_finite()
            && registered_at > 0.0
            && started <= registered_at,
        "OMP legacy binding predates its current native owner for '{}'",
        row.name
    );
    Ok(())
}

/// Authenticate a process-id target without changing any row or binding.
/// A launcher UUID needs a mapped row; only a proven actual OMP may mint anew.
pub(crate) fn authenticated_omp_owner(db: &HcomDb, process_id: &str) -> anyhow::Result<OmpOwner> {
    let minted = crate::proctruth::omp_minted_pid(process_id).filter(|&pid| pid != 0);
    anyhow::ensure!(
        minted.is_some() || crate::proctruth::is_launcher_process_id(process_id),
        "Unknown OMP process identity"
    );
    let binding = db
        .conn()
        .query_row(
            "SELECT instance_name, session_id, updated_at FROM process_bindings WHERE process_id = ?",
            rusqlite::params![process_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, f64>(2)?)),
        )
        .optional()?;
    let mapped = match binding {
        Some((name, session, registered)) => Some((
            db.get_instance_full(&name)?
                .with_context(|| format!("Missing OMP process owner row '{name}'"))?,
            session,
            registered,
        )),
        None => None,
    };
    let anchor = match minted {
        Some(pid) => pid,
        None => omp_row_pid(&mapped.as_ref().context("Unknown OMP launcher identity")?.0)?,
    };
    let owner = prove_omp_caller(anchor)?;
    anyhow::ensure!(
        minted.is_none_or(|pid| pid == owner.pid),
        "OMP minted identity does not name its actual owner"
    );
    if let Some((row, session, registered)) = mapped {
        validate_omp_registration(&row, session.as_deref(), registered, process_id, &owner)?;
    }
    require_omp_owner_current(&owner)?;
    Ok(owner)
}

pub(crate) fn pin_omp_owner(
    db: &HcomDb,
    tx: &rusqlite::Transaction<'_>,
    name: &str,
    owner: &OmpOwner,
) -> anyhow::Result<()> {
    let row = db
        .get_instance_full(name)?
        .with_context(|| format!("Missing OMP identity '{name}' before pin"))?;
    require_local_omp_row(&row)?;
    let mut context = omp_launch_context(&row)?;
    context.insert("omp_owner".into(), serde_json::to_value(owner)?);
    context.remove("omp_launch_anchor");
    anyhow::ensure!(
        tx.execute(
            "UPDATE instances SET pid = ?1, launch_context = ?2 WHERE name = ?3",
            rusqlite::params![i64::from(owner.pid), serde_json::to_string(&context)?, name],
        )? == 1,
        "OMP identity '{name}' vanished before owner pin"
    );
    Ok(())
}

/// Pin only a genuine PID-less predecessor row, never a named repair or remint.
/// A refused name or changed mapping must leave even the caller's own row alone.
pub(crate) fn enroll_pidless_legacy_omp_owner(
    db: &HcomDb,
    process_id: &str,
    expected_name: &str,
    expected_owner: &OmpOwner,
) -> anyhow::Result<()> {
    db.with_immediate_transaction(|tx| {
        crate::identity::validate_protected_identity_checked(db, expected_name)?;
        anyhow::ensure!(
            db.get_process_binding(process_id)?.as_deref() == Some(expected_name),
            "OMP legacy enrollment mapping changed"
        );
        anyhow::ensure!(
            authenticated_omp_owner(db, process_id)? == *expected_owner,
            "OMP legacy enrollment native owner changed"
        );
        let row = db
            .get_instance_full(expected_name)?
            .context("OMP legacy enrollment row disappeared")?;
        require_local_omp_row(&row)?;
        let stored = crate::proctruth::stored_omp_owner(&row)?;
        let anchor = stored_omp_launch_anchor(&row)?;
        anyhow::ensure!(
            !held_by_another_live_process(db, expected_name, process_id, Some(expected_owner),)?,
            "OMP legacy enrollment row has another live holder"
        );
        if row.pid == Some(i64::from(expected_owner.pid))
            && stored.as_ref() == Some(expected_owner)
            && anchor.is_none()
        {
            // Another legacy RPC may have enrolled this exact owner while
            // this request waited for the writer lock. Never rewrite its pin.
            return require_omp_owner_current(expected_owner);
        }
        anyhow::ensure!(
            row.pid.is_none() && stored.is_none() && anchor.is_none(),
            "OMP legacy enrollment requires missing predecessor owner fields"
        );
        pin_omp_owner(db, tx, expected_name, expected_owner)?;
        #[cfg(test)]
        run_omp_commit_gap_hook(db, expected_name);
        require_omp_owner_current(expected_owner)
    })
}

/// A canonical row can be reclaimed only from this exact owner or a
/// conclusively gone historical owner. Unknown facts never authorize adoption.
fn validate_omp_target(
    db: &HcomDb,
    name: &str,
    process_id: &str,
    owner: &OmpOwner,
) -> anyhow::Result<()> {
    let row = db
        .get_instance_full(name)?
        .with_context(|| format!("Missing canonical OMP identity '{name}'"))?;
    require_local_omp_row(&row)?;
    let pid = match row.pid {
        Some(_) => omp_row_pid(&row)?,
        None => {
            // First-start enrollment may use only this caller's exact mapped
            // predecessor row, authenticated again under the bind's writer lock.
            anyhow::ensure!(
                db.get_process_binding(process_id)?.as_deref() == Some(name)
                    && authenticated_omp_owner(db, process_id)? == *owner,
                "Unproven PID-less OMP canonical owner for '{name}'"
            );
            owner.pid
        }
    };
    match crate::proctruth::stored_omp_owner(&row)? {
        Some(stored) => {
            anyhow::ensure!(stored.pid == pid, "OMP stamp/PID mismatch for '{name}'");
            if stored != *owner {
                anyhow::ensure!(
                    crate::proctruth::process_gone(pid),
                    "Canonical OMP identity '{name}' belongs to another live owner"
                );
            } else {
                require_omp_owner_current(owner)?;
            }
        }
        None if pid == owner.pid => {
            let bindings = db.process_bindings_registered(name)?;
            let mut proven = false;
            for (id, registered) in bindings {
                if crate::proctruth::omp_minted_pid(&id) == Some(owner.pid)
                    || crate::proctruth::is_launcher_process_id(&id)
                {
                    let session = db.get_process_binding_full(&id)?.and_then(|(sid, _)| sid);
                    if validate_omp_registration(&row, session.as_deref(), registered, &id, owner)
                        .is_ok()
                    {
                        proven = true;
                        break;
                    }
                }
            }
            anyhow::ensure!(proven, "Unproven legacy OMP canonical owner for '{name}'");
        }
        None => {
            // Parse a present receipt even on a historical row: malformed
            // evidence is never repaired by treating it as absent.
            let launch_anchor = stored_omp_launch_anchor(&row)?;
            if launch_anchor.is_some()
                && crate::proctruth::is_launcher_process_id(process_id)
                && db
                    .get_process_binding_full(process_id)?
                    .is_some_and(|(session, mapped)| {
                        mapped == name && session.as_deref().is_none_or(str::is_empty)
                    })
            {
                // A resumed launch already carries its prior session on the
                // row, but this exact registration has not bound it yet. Prove
                // its current wrapper-to-child handoff again on this writer.
                anyhow::ensure!(
                    authenticated_omp_owner(db, process_id)? == *owner,
                    "OMP launch handoff owner changed for '{name}'"
                );
            } else {
                anyhow::ensure!(
                    crate::proctruth::process_gone(pid),
                    "Canonical OMP native owner for '{name}' is live or unreadable"
                );
            }
        }
    }
    anyhow::ensure!(
        !held_by_another_live_process(db, name, process_id, Some(owner))?,
        "Canonical OMP identity '{name}' has another live holder"
    );
    Ok(())
}

fn validate_omp_session_rows(
    db: &HcomDb,
    session_id: &str,
    target: Option<&str>,
    process_id: &str,
    owner: &OmpOwner,
) -> anyhow::Result<()> {
    let names = db
        .conn()
        .prepare("SELECT name FROM instances WHERE session_id = ?")?
        .query_map(rusqlite::params![session_id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for name in names {
        if target != Some(name.as_str()) {
            validate_omp_target(db, &name, process_id, owner)?;
        }
    }
    Ok(())
}

/// OMP's complete bind, including fresh proof and owner pin, is one commit.
pub(crate) fn bind_omp_session_to_process(
    db: &HcomDb,
    session_id: &str,
    process_id: &str,
) -> anyhow::Result<Option<String>> {
    anyhow::ensure!(!session_id.is_empty(), "Missing OMP session identity");
    let mut post = PostCommit::default();
    let (bound, displaced) = db.with_immediate_transaction(|tx| {
        bind_omp_session_to_process_in_txn(db, tx, session_id, process_id, &mut post)
    })?;
    if let (Some(name), Some(displaced)) = (&bound, &displaced) {
        rekey_migrated_terminal(db, name, displaced);
    }
    post.fire(db);
    Ok(bound)
}

fn bind_omp_session_to_process_in_txn(
    db: &HcomDb,
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    process_id: &str,
    post: &mut PostCommit,
) -> anyhow::Result<(Option<String>, Option<InstanceRow>)> {
    anyhow::ensure!(!session_id.is_empty(), "Missing OMP session identity");
    let owner = authenticated_omp_owner(db, process_id)?;
    let displaced = db
        .get_process_binding(process_id)?
        .map(|name| db.get_instance_full(&name))
        .transpose()?
        .flatten();
    let canonical = db.get_session_binding(session_id)?;
    if let Some(name) = &canonical {
        validate_omp_target(db, name, process_id, &owner)?;
    } else if let Some((name, snapshot)) = db.find_stopped_snapshot_by_session_id(session_id)? {
        if db.get_instance_full(&name)?.is_some() {
            validate_omp_target(db, &name, process_id, &owner)?;
        } else {
            anyhow::ensure!(
                snapshot.get("tool").and_then(serde_json::Value::as_str) == Some("omp")
                    && snapshot
                        .get("origin_device_id")
                        .is_none_or(|value| { value.is_null() || value.as_str() == Some("") }),
                "Stopped identity '{name}' is not local OMP metadata"
            );
        }
    }
    validate_omp_session_rows(db, session_id, canonical.as_deref(), process_id, &owner)?;
    let bound =
        bind_session_to_process_body(db, session_id, Some(process_id), tx, post, Some(&owner))?;
    if let Some(name) = &bound {
        pin_omp_owner(db, tx, name, &owner)?;
        #[cfg(test)]
        run_omp_commit_gap_hook(db, name);
    }
    require_omp_owner_current(&owner)?;
    Ok((bound, displaced))
}

#[cfg(test)]
#[derive(Clone)]
struct OmpBindingOwnerFixture {
    owner: OmpOwner,
    incarnation: Option<String>,
    started: Option<f64>,
    launch_anchor: Option<u32>,
}

#[cfg(test)]
thread_local! {
    static OMP_BINDING_OWNER_FIXTURE: std::cell::RefCell<Option<OmpBindingOwnerFixture>> =
        const { std::cell::RefCell::new(None) };
    static OMP_OWNER_COMMIT_GAP_HOOK: crate::db::GapHook =
        const { std::cell::Cell::new(None) };
    static GENERIC_BIND_ROUTE_GAP_HOOK: crate::db::GapHook =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_omp_binding_owner<T>(owner: OmpOwner, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<OmpBindingOwnerFixture>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OMP_BINDING_OWNER_FIXTURE.set(self.0.take());
        }
    }
    let fixture = OmpBindingOwnerFixture {
        incarnation: Some(owner.incarnation.clone()),
        owner,
        started: Some(1.0),
        launch_anchor: None,
    };
    let _restore = Restore(OMP_BINDING_OWNER_FIXTURE.replace(Some(fixture)));
    f()
}

#[cfg(test)]
fn run_omp_commit_gap_hook(db: &HcomDb, name: &str) {
    if let Some(hook) = OMP_OWNER_COMMIT_GAP_HOOK.with(std::cell::Cell::take) {
        hook(db, name);
    }
}

/// Bind session_id to canonical instance for process_id.
/// Handles 4 paths: canonical exists (with placeholder merge/switch), placeholder bind,
/// and two no-op paths.
///
/// `Ok(Some(name))` means the `name` row exists and its session binding (and
/// process binding, when `process_id` is given) were written. A failed row
/// recreation or binding write is logged here once and returned as an `Err`,
/// never a name; callers must not mint a replacement identity on `Err`.
pub fn bind_session_to_process(
    db: &HcomDb,
    session_id: &str,
    process_id: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let mut post = PostCommit::default();
    let (bound, displaced) = db
        .with_immediate_transaction(|tx| {
            // Discovery and use share the writer lock: a generic target cannot be
            // replaced by an OMP row between routing and its first mutation.
            let process_targets_omp = process_id
                .map(|id| crate::proctruth::process_id_targets_omp(db, id))
                .transpose()?
                .unwrap_or(false);
            let session_targets_omp = match db.get_session_binding(session_id)? {
                Some(name) => db
                    .get_instance_full(&name)?
                    .is_some_and(|row| row.tool == "omp"),
                None => match db.find_stopped_snapshot_by_session_id(session_id)? {
                    Some((name, snapshot)) => {
                        snapshot.get("tool").and_then(serde_json::Value::as_str) == Some("omp")
                            || db
                                .get_instance_full(&name)?
                                .is_some_and(|row| row.tool == "omp")
                    }
                    None => false,
                },
            };
            if process_targets_omp || session_targets_omp {
                let process_id = process_id.context("OMP binding requires a process identity")?;
                return bind_omp_session_to_process_in_txn(
                    db, tx, session_id, process_id, &mut post,
                );
            }
            #[cfg(test)]
            if let Some(hook) = GENERIC_BIND_ROUTE_GAP_HOOK.with(std::cell::Cell::take) {
                hook(db, session_id);
            }
            let displaced = process_id
                .map(|id| db.get_process_binding(id))
                .transpose()?
                .flatten()
                .map(|name| db.get_instance_full(&name))
                .transpose()?
                .flatten();
            let bound =
                bind_session_to_process_body(db, session_id, process_id, tx, &mut post, None)?;
            Ok((bound, displaced))
        })
        .inspect_err(|e| {
            crate::log::log_error(
                "binding",
                "bind_session_to_process.failed",
                &format!("session_id={session_id}, process_id={process_id:?}, err={e:#}"),
            );
        })?;
    if let (Some(name), Some(displaced)) = (&bound, &displaced) {
        rekey_migrated_terminal(db, name, displaced);
    }
    post.fire(db);
    Ok(bound)
}

fn bind_session_to_process_body(
    db: &HcomDb,
    session_id: &str,
    process_id: Option<&str>,
    tx: &rusqlite::Transaction<'_>,
    post: &mut PostCommit,
    omp_owner: Option<&OmpOwner>,
) -> anyhow::Result<Option<String>> {
    if session_id.is_empty() {
        crate::log::log_info("binding", "bind_session_to_process.no_session_id", "");
        return Ok(None);
    }

    crate::log::log_info(
        "binding",
        "bind_session_to_process.entry",
        &format!("session_id={}, process_id={:?}", session_id, process_id),
    );

    // Find placeholder from process binding
    let binding = process_id
        .map(|id| db.get_process_binding_full(id))
        .transpose()?
        .flatten();
    let (placeholder_name, placeholder_data, displaced_session) = match binding {
        Some((session, name)) => {
            let data = db.get_instance_full(&name)?;
            (Some(name), data, session)
        }
        None => (None, None, None),
    };
    anyhow::ensure!(
        omp_owner.is_some()
            || !placeholder_data
                .as_ref()
                .is_some_and(|row| row.tool == "omp"),
        "OMP process target requires authenticated owner proof"
    );

    // Find canonical from session binding
    let canonical = db.get_session_binding(session_id)?;

    // Path 1: Canonical exists (session already bound)
    if let Some(ref canonical_name) = canonical {
        anyhow::ensure!(
            omp_owner.is_some()
                || !db
                    .get_instance_full(canonical_name)?
                    .is_some_and(|row| row.tool == "omp"),
            "OMP canonical target requires authenticated owner proof"
        );
        crate::log::log_info(
            "binding",
            "bind_session_to_process.canonical_exists",
            &format!(
                "canonical={}, placeholder={:?}",
                canonical_name, placeholder_name
            ),
        );

        recreate_instance_from_placeholder(
            db,
            canonical_name,
            session_id,
            placeholder_data.as_ref(),
            post,
        )?;

        // Reset last_stop on resume
        let now = now_epoch_i64();
        let mut resume_updates = serde_json::Map::new();
        resume_updates.insert("last_stop".into(), serde_json::json!(now));

        if let Some(ref ph_name) = placeholder_name
            && ph_name != canonical_name
        {
            let true_placeholder = is_true_launch_placeholder(placeholder_data.as_ref());
            if true_placeholder {
                let merge = |tx: &rusqlite::Transaction<'_>| -> anyhow::Result<()> {
                    if omp_owner.is_some() {
                        anyhow::ensure!(
                            !held_by_another_live_process(
                                db,
                                ph_name,
                                process_id.unwrap_or(""),
                                omp_owner,
                            )?,
                            "OMP launch placeholder has another live holder"
                        );
                    }
                    db.migrate_notify_endpoints_in_txn(tx, ph_name, canonical_name)?;
                    migrate_placeholder_runtime_state_in_txn(
                        db,
                        tx,
                        canonical_name,
                        placeholder_data.as_ref(),
                    )?;
                    anyhow::ensure!(
                        db.delete_instance(ph_name)?,
                        "Launch placeholder disappeared during merge"
                    );
                    Ok(())
                };
                merge(tx)?;
                // Path 1a: True placeholder merge
                if let Some(ref ph_data) = placeholder_data {
                    if let Some(ref tag) = ph_data.tag {
                        resume_updates.insert("tag".into(), serde_json::json!(tag));
                    }
                    if ph_data.background != 0 {
                        resume_updates
                            .insert("background".into(), serde_json::json!(ph_data.background));
                    }
                    if let Some(ref args) = ph_data.launch_args {
                        resume_updates.insert("launch_args".into(), serde_json::json!(args));
                    }
                    // Reset status_context for ready event
                    if std::env::var("HCOM_LAUNCHED").as_deref() == Ok("1") {
                        resume_updates.insert("status_context".into(), serde_json::json!("new"));
                    }
                }
            }
        }

        if omp_owner.is_some() {
            resume_updates.insert("session_id".into(), serde_json::json!(session_id));
            db.rebind_instance_session(canonical_name, session_id)?;
            db.update_instance_fields(canonical_name, &resume_updates)?;
        } else {
            db.update_instance_fields(canonical_name, &resume_updates)?;
        }

        if let Some(pid) = process_id {
            let mut switch = |tx: &rusqlite::Transaction<'_>| {
                db.set_process_binding(pid, session_id, canonical_name)
                    .with_context(|| {
                        format!("bind_canonical.set_process_binding for '{canonical_name}'")
                    })?;
                if let Some(displaced) = &placeholder_name
                    && displaced != canonical_name
                    && !is_true_launch_placeholder(placeholder_data.as_ref())
                {
                    // The move below relocates the displaced row's endpoints
                    // onto the new name in-txn: snapshot its DELIVERY_LOOPS
                    // ports first so the post-commit fire still reaches the
                    // moved listener (S1).
                    post.collect_wake(db, displaced, crate::notify::WakeKind::DELIVERY_LOOPS);
                    return move_process_off_displaced_row(
                        db,
                        tx,
                        displaced,
                        canonical_name,
                        placeholder_data.as_ref(),
                        pid,
                        omp_owner,
                        displaced_session.as_deref(),
                    );
                }
                Ok(None)
            };
            let released = switch(tx)?;
            if let (Some(displaced), Some((id, data))) = (&placeholder_name, released) {
                post.events.push((id, displaced.clone(), data));
            }
        }

        return Ok(Some(canonical_name.clone()));
    }

    // Path 2: session_bindings CASCADE'd on delete — recover canonical name from life.stopped
    let stopped = db.find_stopped_snapshot_by_session_id(session_id)?;
    if let Some((stopped_name, snapshot)) = stopped {
        crate::log::log_info(
            "binding",
            "bind_session_to_process.restore_stopped",
            &format!("stopped_name={stopped_name}, session_id={session_id}"),
        );
        // The whole switch is ONE immediate transaction with nothing committed
        // before it: the restored row, both bindings, the runtime state and
        // endpoints that follow the process, the displaced row's release and
        // the launch placeholder's retirement. Any failure rolls all of it
        // back, leaving the DB exactly as it was before this hook.
        let mut restore = |tx: &rusqlite::Transaction<'_>| {
            anyhow::ensure!(
                omp_owner.is_some()
                    || (snapshot.get("tool").and_then(serde_json::Value::as_str) != Some("omp")
                        && !db
                            .get_instance_full(&stopped_name)?
                            .is_some_and(|row| row.tool == "omp")),
                "OMP restore target requires authenticated owner proof"
            );
            if is_true_launch_placeholder(placeholder_data.as_ref()) {
                recreate_instance_from_placeholder(
                    db,
                    &stopped_name,
                    session_id,
                    placeholder_data.as_ref(),
                    post,
                )?;
            } else {
                // A real old session is not the restored identity: take the
                // stopped name's cursor and settings, never the displaced row's.
                recreate_instance_from_stopped_snapshot(
                    db,
                    tx,
                    &stopped_name,
                    session_id,
                    &snapshot,
                    post,
                )?;
            }

            db.clear_session_id_from_other_instances(session_id, &stopped_name)
                .with_context(|| format!("restore_stopped.clear_session for '{stopped_name}'"))?;
            let mut updates = serde_json::Map::new();
            updates.insert("session_id".into(), serde_json::json!(session_id));
            db.update_instance_fields(&stopped_name, &updates)
                .with_context(|| format!("restore_stopped.update_session for '{stopped_name}'"))?;
            db.rebind_session(session_id, &stopped_name)
                .with_context(|| format!("restore_stopped.rebind_session for '{stopped_name}'"))?;
            let mut released = None;
            if let Some(pid) = process_id {
                db.set_process_binding(pid, session_id, &stopped_name)
                    .with_context(|| {
                        format!("restore_stopped.set_process_binding for '{stopped_name}'")
                    })?;
                if let Some(displaced) = &placeholder_name
                    && displaced != &stopped_name
                    && !is_true_launch_placeholder(placeholder_data.as_ref())
                {
                    // The move below relocates the displaced row's endpoints
                    // onto the new name in-txn: snapshot its DELIVERY_LOOPS
                    // ports first so the post-commit fire still reaches the
                    // moved listener (S1).
                    post.collect_wake(db, displaced, crate::notify::WakeKind::DELIVERY_LOOPS);
                    released = move_process_off_displaced_row(
                        db,
                        tx,
                        displaced,
                        &stopped_name,
                        placeholder_data.as_ref(),
                        pid,
                        omp_owner,
                        displaced_session.as_deref(),
                    )?;
                }
            }
            if omp_owner.is_some()
                && let Some(ph_name) = &placeholder_name
                && ph_name != &stopped_name
                && is_true_launch_placeholder(placeholder_data.as_ref())
            {
                anyhow::ensure!(
                    !held_by_another_live_process(
                        db,
                        ph_name,
                        process_id.unwrap_or(""),
                        omp_owner,
                    )?,
                    "OMP launch placeholder has another live holder"
                );
            }
            retire_true_placeholder_after_canonical_bind(
                db,
                tx,
                placeholder_name.as_ref(),
                &stopped_name,
                placeholder_data.as_ref(),
            )?;

            #[cfg(test)]
            if let Some(hook) = RESTORE_STOPPED_COMMIT_GAP_HOOK.with(std::cell::Cell::take) {
                hook(db, &stopped_name);
            }
            Ok(released)
        };
        let released = restore(tx)?;
        if let (Some(displaced), Some((id, data))) = (&placeholder_name, released) {
            post.events.push((id, displaced.clone(), data));
        }

        return Ok(Some(stopped_name));
    }

    // Path 3: No canonical, but placeholder exists — bind session to placeholder
    if let Some(ref ph_name) = placeholder_name {
        crate::log::log_info(
            "binding",
            "bind_session_to_process.bind_placeholder",
            &format!("placeholder={}, session_id={}", ph_name, session_id),
        );
        let mut updates = serde_json::Map::new();
        updates.insert("session_id".into(), serde_json::json!(session_id));
        db.update_instance_fields(ph_name, &updates)?;

        // Shared rows retain the other live process's session binding. Only
        // the sole holder may replace the old session on this row.
        let shared =
            held_by_another_live_process(db, ph_name, process_id.unwrap_or(""), omp_owner)?;
        anyhow::ensure!(
            omp_owner.is_none() || !shared,
            "OMP row '{ph_name}' has another live holder"
        );
        if shared {
            db.rebind_session(session_id, ph_name)
                .with_context(|| format!("bind_placeholder.rebind_session for '{ph_name}'"))?;
        } else {
            db.rebind_instance_session(ph_name, session_id)
                .with_context(|| format!("bind_placeholder.rebind_session for '{ph_name}'"))?;
        }
        if let Some(pid) = process_id {
            db.set_process_binding(pid, session_id, ph_name)
                .with_context(|| format!("bind_placeholder.set_process_binding for '{ph_name}'"))?;
        }

        return Ok(Some(ph_name.clone()));
    }

    crate::log::log_info("binding", "bind_session_to_process.return_none", "");
    Ok(None)
}

/// Repair a vanished binding using the named row's exact native owner pin.
/// Session metadata is not proof: a same-owner repair may replace poisoned text.
pub(crate) fn recover_omp_process_binding_for_instance(
    db: &HcomDb,
    instance_name: &str,
    session_id: &str,
    process_id: &str,
) -> anyhow::Result<Option<String>> {
    anyhow::ensure!(
        !instance_name.is_empty() && !session_id.is_empty(),
        "Missing OMP repair identity"
    );
    let minted = crate::proctruth::omp_minted_pid(process_id).filter(|&pid| pid != 0);
    anyhow::ensure!(
        minted.is_some() || crate::proctruth::is_launcher_process_id(process_id),
        "Unknown OMP repair process identity"
    );
    db.with_immediate_transaction(|tx| {
        anyhow::ensure!(
            db.get_process_binding(process_id)?.is_none(),
            "OMP process mapping appeared before repair"
        );
        let Some(row) = db.get_instance_full(instance_name)? else {
            // Only a newly proven minted identity can fall through to creation.
            authenticated_omp_owner(db, process_id)?;
            return Ok(None);
        };
        require_local_omp_row(&row)?;
        let pid = omp_row_pid(&row)?;
        let stored = crate::proctruth::stored_omp_owner(&row)?
            .context("OMP repair requires an actual owner stamp")?;
        anyhow::ensure!(stored.pid == pid, "OMP repair stamp/PID mismatch");
        let owner = prove_omp_caller(minted.unwrap_or(pid))?;
        anyhow::ensure!(
            minted.is_none_or(|pid| pid == owner.pid) && stored == owner,
            "OMP repair belongs to another native owner"
        );
        require_omp_owner_current(&owner)?;
        anyhow::ensure!(
            db.get_session_binding(session_id)?
                .as_deref()
                .is_none_or(|name| name == instance_name),
            "OMP repair would replace a different canonical identity"
        );
        anyhow::ensure!(
            !held_by_another_live_process(db, instance_name, process_id, Some(&owner))?,
            "OMP repair row has another live holder"
        );
        validate_omp_session_rows(db, session_id, Some(instance_name), process_id, &owner)?;
        db.clear_session_id_from_other_instances(session_id, instance_name)?;
        let mut updates = serde_json::Map::new();
        updates.insert("session_id".into(), serde_json::json!(session_id));
        db.update_instance_fields(instance_name, &updates)?;
        db.rebind_instance_session(instance_name, session_id)?;
        db.set_process_binding(process_id, session_id, instance_name)?;
        pin_omp_owner(db, tx, instance_name, &owner)?;
        #[cfg(test)]
        run_omp_commit_gap_hook(db, instance_name);
        require_omp_owner_current(&owner)?;
        Ok(Some(instance_name.to_string()))
    })
}

/// Mint an OMP row, both bindings and the native owner pin in one commit.
/// Name allocation uses the same lock order as the ordinary launcher.
pub(crate) fn create_omp_identity(
    db: &HcomDb,
    session_id: &str,
    process_id: &str,
) -> anyhow::Result<String> {
    anyhow::ensure!(!session_id.is_empty(), "Missing OMP session identity");
    anyhow::ensure!(
        crate::proctruth::omp_minted_pid(process_id).is_some_and(|pid| pid != 0),
        "Only a proven OMP-minted identity may create a row"
    );
    let name_lock = crate::instance_names::lock_name_generation(db)?;
    let mut post = PostCommit::default();
    let name = db.with_immediate_transaction(|tx| {
        let owner = authenticated_omp_owner(db, process_id)?;
        anyhow::ensure!(
            db.get_process_binding(process_id)?.is_none(),
            "OMP process mapping appeared before creation"
        );
        anyhow::ensure!(
            db.get_session_binding(session_id)?.is_none()
                && db
                    .find_stopped_snapshot_by_session_id(session_id)?
                    .is_none(),
            "OMP session already has an identity or restore path"
        );
        let carries_session: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM instances WHERE session_id = ?)",
            rusqlite::params![session_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            !carries_session,
            "OMP session metadata already belongs to a row"
        );
        let name = crate::instance_names::allocate_unreserved_name(db)?;
        initialize_instance_in_position_file_checked(
            db,
            &name,
            Some(session_id),
            None,
            None,
            None,
            None,
            Some("omp"),
            false,
            None,
            None,
            None,
            None,
            None,
            &mut post,
        )?;
        db.rebind_session(session_id, &name)?;
        db.set_process_binding(process_id, session_id, &name)?;
        pin_omp_owner(db, tx, &name, &owner)?;
        #[cfg(test)]
        run_omp_commit_gap_hook(db, &name);
        require_omp_owner_current(&owner)?;
        Ok(name)
    })?;
    drop(name_lock);
    post.fire(db);
    Ok(name)
}

/// Initialize the DB row and default bindings for an instance identity.
///
/// This is the shared setup path used by launch, resume, and orphan recovery.
///
/// Plain entry point: the row write, the `life.created` event, and the whole
/// fan-out run inline, and the collected TCP wakes fire before returning.
#[allow(clippy::too_many_arguments)]
pub fn initialize_instance_in_position_file(
    db: &HcomDb,
    instance_name: &str,
    session_id: Option<&str>,
    parent_session_id: Option<&str>,
    parent_name: Option<&str>,
    agent_id: Option<&str>,
    transcript_path: Option<&str>,
    tool: Option<&str>,
    background: bool,
    tag: Option<&str>,
    wait_timeout: Option<i64>,
    subagent_timeout: Option<i64>,
    hints: Option<&str>,
    cwd_override: Option<&str>,
) -> bool {
    let mut post = PostCommit::default();
    let ok = initialize_instance_in_position_file_collected(
        db,
        instance_name,
        session_id,
        parent_session_id,
        parent_name,
        agent_id,
        transcript_path,
        tool,
        background,
        tag,
        wait_timeout,
        subagent_timeout,
        hints,
        cwd_override,
        &mut post,
    );
    if ok {
        post.fire(db);
    }
    ok
}

/// [`initialize_instance_in_position_file`] with the `life.created` fan-out's
/// TCP wakes collected into `post` instead of connected: the row write, the
/// event row, and every follow-up write run inline (joining the caller's
/// write txn when there is one), so call this inside a write txn and run
/// [`PostCommit::fire`] only after that txn commits.
#[allow(clippy::too_many_arguments)]
pub(crate) fn initialize_instance_in_position_file_collected(
    db: &HcomDb,
    instance_name: &str,
    session_id: Option<&str>,
    parent_session_id: Option<&str>,
    parent_name: Option<&str>,
    agent_id: Option<&str>,
    transcript_path: Option<&str>,
    tool: Option<&str>,
    background: bool,
    tag: Option<&str>,
    wait_timeout: Option<i64>,
    subagent_timeout: Option<i64>,
    hints: Option<&str>,
    cwd_override: Option<&str>,
    post: &mut PostCommit,
) -> bool {
    initialize_instance_in_position_file_checked(
        db,
        instance_name,
        session_id,
        parent_session_id,
        parent_name,
        agent_id,
        transcript_path,
        tool,
        background,
        tag,
        wait_timeout,
        subagent_timeout,
        hints,
        cwd_override,
        post,
    )
    .inspect_err(|error| {
        crate::log::log_warn("identity", "registration.refused", &error.to_string());
    })
    .is_ok()
}

#[allow(clippy::too_many_arguments)]
fn initialize_instance_in_position_file_checked(
    db: &HcomDb,
    instance_name: &str,
    session_id: Option<&str>,
    parent_session_id: Option<&str>,
    parent_name: Option<&str>,
    agent_id: Option<&str>,
    transcript_path: Option<&str>,
    tool: Option<&str>,
    background: bool,
    tag: Option<&str>,
    wait_timeout: Option<i64>,
    subagent_timeout: Option<i64>,
    hints: Option<&str>,
    cwd_override: Option<&str>,
    post: &mut PostCommit,
) -> anyhow::Result<()> {
    // Join an existing writer transaction, or take the lock before checking
    // ownership so a concurrent connector registration cannot be overwritten.
    let mut initialize = || -> anyhow::Result<()> {
        crate::identity::validate_new_identity_name(db, instance_name)?;
        let cwd = cwd_override.map(|s| s.to_string()).unwrap_or_else(|| {
            std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default()
        });
        let is_launched = std::env::var("HCOM_LAUNCHED").as_deref() == Ok("1");

        match db.get_instance_full(instance_name)? {
            Some(existing) => {
                let mut updates = serde_json::Map::new();
                updates.insert("directory".into(), serde_json::json!(cwd));

                if let Some(sid) = session_id {
                    updates.insert("session_id".into(), serde_json::json!(sid));
                }
                if let Some(psid) = parent_session_id {
                    updates.insert("parent_session_id".into(), serde_json::json!(psid));
                }
                if let Some(pn) = parent_name {
                    updates.insert("parent_name".into(), serde_json::json!(pn));
                }
                if let Some(aid) = agent_id {
                    updates.insert("agent_id".into(), serde_json::json!(aid));
                }
                if let Some(tp) = transcript_path {
                    updates.insert("transcript_path".into(), serde_json::json!(tp));
                }
                if let Some(t) = tool {
                    updates.insert("tool".into(), serde_json::json!(t));
                }
                if let Some(t) = tag {
                    updates.insert("tag".into(), serde_json::json!(t));
                }
                if background {
                    updates.insert("background".into(), serde_json::json!(1));
                }

                let is_true_placeholder = existing.session_id.is_none();
                let is_pending_placeholder = is_true_placeholder
                    && existing.status == PLACEHOLDER_STATUS
                    && existing.status_context == PLACEHOLDER_CONTEXT;
                if existing.last_event_id == 0 && is_true_placeholder {
                    let current_max = db.get_last_event_id();
                    let launch_event_id = std::env::var("HCOM_LAUNCH_EVENT_ID")
                        .ok()
                        .and_then(|s| s.parse::<i64>().ok());

                    let eid = match launch_event_id {
                        Some(id) if id <= current_max => id,
                        _ => current_max,
                    };
                    updates.insert("last_event_id".into(), serde_json::json!(eid));
                }

                if is_launched {
                    updates.insert("status_context".into(), serde_json::json!("new"));
                }

                if !updates.is_empty() {
                    db.update_instance_fields(instance_name, &updates)?;
                }

                if is_pending_placeholder {
                    auto_subscribe_defaults(
                        db,
                        instance_name,
                        tool.unwrap_or(existing.tool.as_str()),
                    )?;
                }
            }
            None => {
                let now = now_epoch_f64();
                let current_max = db.get_last_event_id();
                let launch_event_id = std::env::var("HCOM_LAUNCH_EVENT_ID")
                    .ok()
                    .and_then(|s| s.parse::<i64>().ok());

                let initial_event_id = match launch_event_id {
                    Some(id) if id <= current_max => id,
                    _ => current_max,
                };

                let mut data = serde_json::Map::new();
                data.insert("name".into(), serde_json::json!(instance_name));
                data.insert("last_event_id".into(), serde_json::json!(initial_event_id));
                data.insert("directory".into(), serde_json::json!(cwd));
                data.insert("last_stop".into(), serde_json::json!(0));
                data.insert("created_at".into(), serde_json::json!(now));
                data.insert(
                    "session_id".into(),
                    match session_id {
                        Some(s) if !s.is_empty() => serde_json::json!(s),
                        _ => serde_json::Value::Null,
                    },
                );
                data.insert("transcript_path".into(), serde_json::json!(""));
                data.insert("name_announced".into(), serde_json::json!(0));
                data.insert("tag".into(), serde_json::Value::Null);
                data.insert("status".into(), serde_json::json!(ST_INACTIVE));
                data.insert("status_time".into(), serde_json::json!(now_epoch_i64()));
                data.insert("status_context".into(), serde_json::json!("new"));
                data.insert("tool".into(), serde_json::json!(tool.unwrap_or("claude")));
                data.insert(
                    "background".into(),
                    serde_json::json!(if background { 1 } else { 0 }),
                );

                if let Some(t) = tag {
                    data.insert("tag".into(), serde_json::json!(t));
                } else if (session_id.is_some() || parent_session_id.is_some() || is_launched)
                    && let Ok(hcom_config) = crate::config::HcomConfig::load(None)
                    && !hcom_config.tag.is_empty()
                {
                    data.insert("tag".into(), serde_json::json!(hcom_config.tag));
                }

                // Resolve HCOM_TIMEOUT explicitly rather than leaving the column
                // unset — the schema's DEFAULT 86400 would otherwise silently
                // mask the configured value for every non-PTY instance (issue #71).
                let effective_wait_timeout =
                    wait_timeout.unwrap_or_else(crate::config::HcomConfig::effective_timeout);
                data.insert(
                    "wait_timeout".into(),
                    serde_json::json!(effective_wait_timeout),
                );
                if let Some(st) = subagent_timeout {
                    data.insert("subagent_timeout".into(), serde_json::json!(st));
                }
                if let Some(h) = hints {
                    data.insert("hints".into(), serde_json::json!(h));
                }
                if let Some(psid) = parent_session_id {
                    data.insert("parent_session_id".into(), serde_json::json!(psid));
                }
                if let Some(pn) = parent_name {
                    data.insert("parent_name".into(), serde_json::json!(pn));
                }
                if let Some(aid) = agent_id {
                    data.insert("agent_id".into(), serde_json::json!(aid));
                }
                if let Some(tp) = transcript_path {
                    data.insert("transcript_path".into(), serde_json::json!(tp));
                }

                anyhow::ensure!(
                    db.save_instance_named(instance_name, &data)?,
                    "Cannot register identity '{instance_name}'"
                );
                log_created_and_auto_subscribe(
                    db,
                    instance_name,
                    is_launched,
                    parent_session_id,
                    parent_name,
                    tool.unwrap_or(""),
                    post,
                )?;
            }
        }
        Ok(())
    };
    if db.conn().is_autocommit() {
        db.with_immediate_transaction(|_tx| initialize())
    } else {
        initialize()
    }
}

/// Log the `life.created` event with its subscription fan-out inline, and
/// auto-subscribe the new row. The fan-out's TCP wakes are collected into
/// `post` (fired by the caller after commit); every DB write runs here, so a
/// caller inside a write txn stays atomic and ordered exactly as before.
fn log_created_and_auto_subscribe(
    db: &HcomDb,
    instance_name: &str,
    is_launched: bool,
    parent_session_id: Option<&str>,
    parent_name: Option<&str>,
    tool: &str,
    post: &mut PostCommit,
) -> anyhow::Result<()> {
    let launcher = std::env::var("HCOM_LAUNCHED_BY").unwrap_or_else(|_| "unknown".to_string());
    let event_data = serde_json::json!({
        "action": "created",
        "by": launcher,
        "is_hcom_launched": is_launched,
        "is_subagent": parent_session_id.is_some(),
        "parent_name": parent_name.unwrap_or(""),
    });
    db.log_event_collected("life", instance_name, &event_data, post)?;
    auto_subscribe_defaults(db, instance_name, tool)
}

/// Create orphaned PTY identity — called when process binding exists but session_id
/// is fresh (e.g., after /clear). Generates new name, creates instance, binds it.
pub fn create_orphaned_pty_identity(
    db: &HcomDb,
    session_id: &str,
    process_id: Option<&str>,
    tool: &str,
) -> Option<String> {
    let name = match crate::instance_names::generate_unique_name(db) {
        Ok(n) => n,
        Err(e) => {
            crate::log::log_error(
                "instances",
                "create_orphaned_pty_identity.name_gen",
                &e.to_string(),
            );
            return None;
        }
    };

    let success = initialize_instance_in_position_file(
        db,
        &name,
        Some(session_id),
        None,
        None,
        None,
        None,
        Some(tool),
        false,
        None,
        None,
        None,
        None,
        None,
    );

    if !success {
        return None;
    }

    if let Err(e) = db.rebind_session(session_id, &name) {
        eprintln!("[hcom] warn: rebind_session failed for {name}: {e}");
    }
    if let Some(pid) = process_id
        && let Err(e) = db.set_process_binding(pid, session_id, &name)
    {
        eprintln!("[hcom] warn: set_process_binding failed for {name}: {e}");
    }

    Some(name)
}

/// Resolve instance name for a process_id via process_bindings.
pub fn resolve_process_binding(db: &HcomDb, process_id: Option<&str>) -> Option<String> {
    let pid = process_id?;
    db.get_process_binding(pid).ok()?
}

/// Resolve process/session bindings. OMP rows require their current mapped owner;
/// session metadata alone is never authority to return an OMP identity.
pub fn resolve_instance_from_binding(
    db: &HcomDb,
    session_id: Option<&str>,
    process_id: Option<&str>,
) -> Option<InstanceRow> {
    let resolve = || -> anyhow::Result<Option<InstanceRow>> {
        let by_process = process_id
            .map(|id| db.get_process_binding(id))
            .transpose()?
            .flatten()
            .map(|name| db.get_instance_full(&name))
            .transpose()?
            .flatten();
        let instance = match by_process {
            Some(instance) => Some(instance),
            None => session_id
                .map(|sid| db.get_session_binding(sid))
                .transpose()?
                .flatten()
                .map(|name| db.get_instance_full(&name))
                .transpose()?
                .flatten(),
        };
        if let Some(instance) = &instance
            && instance.tool == "omp"
        {
            let id = process_id.context("OMP resolution requires a process identity")?;
            anyhow::ensure!(
                db.get_process_binding(id)?.as_deref() == Some(instance.name.as_str()),
                "OMP resolution requires its exact process mapping"
            );
            authenticated_omp_owner(db, id)?;
        }
        Ok(instance)
    };
    if db.conn().is_autocommit() {
        db.with_read_snapshot(|_tx| resolve()).ok().flatten()
    } else {
        resolve().ok().flatten()
    }
}

/// Auto-subscribe instance to default event subscriptions from config.
/// Called during instance creation.
fn auto_subscribe_eligible(tool: &str) -> bool {
    tool.parse::<crate::tool::Tool>()
        .is_ok_and(|tool| tool.spec().released)
}

fn auto_subscribe_defaults(db: &HcomDb, instance_name: &str, tool: &str) -> anyhow::Result<()> {
    if !auto_subscribe_eligible(tool) {
        return Ok(());
    }

    db.cleanup_subscriptions(instance_name)?;
    db.cleanup_thread_memberships_for_name_reuse(instance_name)?;
    let config = match crate::config::HcomConfig::load(None) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    if config.auto_subscribe.is_empty() {
        return Ok(());
    }

    use std::collections::HashMap;

    let preset_to_flags: HashMap<&str, Vec<(&str, &str)>> = HashMap::from([
        ("collision", vec![("collision", "1")]),
        ("created", vec![("action", "created")]),
        ("stopped", vec![("action", "stopped")]),
        ("blocked", vec![("status", "blocked")]),
    ]);

    for preset in config
        .auto_subscribe
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        if let Some(flag_pairs) = preset_to_flags.get(preset) {
            let mut filters: HashMap<String, Vec<String>> = HashMap::new();
            for (key, val) in flag_pairs {
                filters
                    .entry(key.to_string())
                    .or_default()
                    .push(val.to_string());
            }
            crate::db::subscriptions::create_filter_subscription(
                db,
                &filters,
                &[],
                instance_name,
                false,
                None,
            )
            .map_err(anyhow::Error::msg)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::PathBuf;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            // SAFETY: tests using this guard are marked #[serial].
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            // SAFETY: tests using this guard are marked #[serial].
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: tests using this guard are marked #[serial].
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    fn setup_test_db() -> (HcomDb, PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let temp_dir = std::env::temp_dir();
        let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let db_path = temp_dir.join(format!(
            "test_instance_binding_{}_{}.db",
            std::process::id(),
            test_id
        ));

        let db = HcomDb::open_at(&db_path).unwrap();
        (db, db_path)
    }

    fn cleanup(path: PathBuf) {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    fn assert_released_session(db: &HcomDb, name: &str, sid: &str, cursor: i64, transcript: &str) {
        assert!(db.get_instance_full(name).unwrap().is_none());
        assert!(!db.has_session_binding(name));
        assert!(!db.has_process_binding_for_instance(name));
        let endpoints: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM notify_endpoints WHERE instance = ?",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(endpoints, 0);
        let event: String = db
            .conn()
            .query_row(
                "SELECT data FROM events WHERE type = 'life' AND instance = ?
             AND json_extract(data, '$.action') = 'stopped'
             ORDER BY id DESC LIMIT 1",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .unwrap();
        let event: serde_json::Value = serde_json::from_str(&event).unwrap();
        assert_eq!(event["by"], "session_switch");
        assert_eq!(event["reason"], "exit:session_switch");
        assert_eq!(event["snapshot"]["session_id"], sid);
        assert_eq!(event["snapshot"]["last_event_id"], cursor);
        assert_eq!(event["snapshot"]["transcript_path"], transcript);
        assert_eq!(
            db.find_stopped_snapshot_by_session_id(sid)
                .unwrap()
                .unwrap()
                .0,
            name
        );
    }

    #[cfg(unix)]
    fn live_holder(id: &str) -> std::process::Child {
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .env("HCOM_PROCESS_ID", id)
            .spawn()
            .unwrap();
        let bound = vec![id.to_string()];
        for _ in 0..100 {
            if crate::proctruth::processes_for_instance("", &bound, &[])
                .iter()
                .any(|carrier| carrier.pid == child.id())
            {
                return child;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("test holder did not become visible");
    }

    #[test]
    fn auto_subscribe_eligibility_follows_released_specs() {
        assert!(auto_subscribe_eligible("pi"));
        assert!(auto_subscribe_eligible("kimi"));
        assert!(!auto_subscribe_eligible("adhoc"));
        assert!(!auto_subscribe_eligible("unknown"));
    }

    #[test]
    fn test_persist_terminal_launch_context_stores_presets_in_launch_context() {
        let (db, path) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, created_at) VALUES (?1, ?2, ?3)",
                rusqlite::params!["luna", "codex", 1.0f64],
            )
            .unwrap();

        persist_terminal_launch_context(&db, "luna", Some("kitty"), "kitty-tab", Some("proc-1"))
            .unwrap();

        let row = db.get_instance_full("luna").unwrap().unwrap();
        let ctx: serde_json::Value =
            serde_json::from_str(row.launch_context.as_deref().unwrap_or("{}")).unwrap();

        assert_eq!(
            ctx.get("terminal_preset_effective")
                .and_then(|v| v.as_str()),
            Some("kitty-tab")
        );
        assert_eq!(
            ctx.get("terminal_preset").and_then(|v| v.as_str()),
            Some("kitty-tab")
        );
        assert_eq!(
            ctx.get("terminal_preset_requested")
                .and_then(|v| v.as_str()),
            Some("kitty")
        );
        assert_eq!(
            ctx.get("process_id").and_then(|v| v.as_str()),
            Some("proc-1")
        );

        cleanup(path);
    }

    #[test]
    #[serial]
    fn test_capture_context_records_launched_preset() {
        // capture_context tags the launch with HCOM_LAUNCHED_PRESET so later
        // child agents launched from inside this pane can inherit the preset.
        // Running tests inside a herdr session would otherwise leak
        // HERDR_PANE_ID into the captured context, so explicitly clear the
        // herdr-related identity vars before exercising the capture path.
        crate::config::Config::init();
        let _preset = EnvVarGuard::set("HCOM_LAUNCHED_PRESET", "herdr");
        let _herdr_pane = EnvVarGuard::set("HERDR_PANE_ID", "");
        let _herdr_socket = EnvVarGuard::set("HERDR_SOCKET_PATH", "");
        let _herdr_env = EnvVarGuard::set("HERDR_ENV", "");
        let _process_id = EnvVarGuard::set("HCOM_PROCESS_ID", "");

        let ctx = capture_context();

        assert_eq!(
            ctx.get("terminal_preset_effective")
                .and_then(|v| v.as_str()),
            Some("herdr")
        );
        assert!(
            ctx.get("pane_id").is_none(),
            "pane_id should be absent when HERDR_PANE_ID isn't set"
        );
    }

    #[test]
    #[serial]
    fn test_capture_and_store_launch_context_preserves_terminal_metadata() {
        // Preserve only the fields we can't recapture from hook env:
        // pane_id, terminal_id, kitty_listen_on, process_id, and the resolved
        // terminal preset name.
        let (db, path) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, created_at, launch_context) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    "luna",
                    "claude",
                    1.0f64,
                    r#"{"terminal_preset_effective":"herdr","pane_id":"p_7","process_id":"proc-1"}"#
                ],
            )
            .unwrap();
        let _preset = EnvVarGuard::set("HCOM_LAUNCHED_PRESET", "");
        let _process_id = EnvVarGuard::set("HCOM_PROCESS_ID", "");

        capture_and_store_launch_context(&db, "luna");

        let row = db.get_instance_full("luna").unwrap().unwrap();
        let ctx: serde_json::Value =
            serde_json::from_str(row.launch_context.as_deref().unwrap_or("{}")).unwrap();
        assert_eq!(
            ctx.get("terminal_preset_effective")
                .and_then(|v| v.as_str()),
            Some("herdr")
        );
        assert_eq!(ctx.get("pane_id").and_then(|v| v.as_str()), Some("p_7"));
        assert_eq!(
            ctx.get("process_id").and_then(|v| v.as_str()),
            Some("proc-1")
        );

        cleanup(path);
    }

    #[test]
    fn test_bind_session_path2_placeholder() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut data = serde_json::Map::new();
        data.insert("name".into(), serde_json::json!("luna"));
        data.insert("status".into(), serde_json::json!("pending"));
        data.insert("status_context".into(), serde_json::json!("new"));
        data.insert("created_at".into(), serde_json::json!(now));
        db.save_instance_named("luna", &data).unwrap();

        db.set_process_binding("pid-123", "", "luna").unwrap();

        let result = bind_session_to_process(&db, "sid-456", Some("pid-123")).unwrap();
        assert_eq!(result, Some("luna".to_string()));

        let inst = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(inst.session_id.as_deref(), Some("sid-456"));

        let binding = db.get_session_binding("sid-456").unwrap();
        assert_eq!(binding, Some("luna".to_string()));

        cleanup(path);
    }

    #[test]
    fn test_bind_session_path1a_true_placeholder_merge() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut canonical_data = serde_json::Map::new();
        canonical_data.insert("name".into(), serde_json::json!("miso"));
        canonical_data.insert("session_id".into(), serde_json::json!("sid-789"));
        canonical_data.insert("created_at".into(), serde_json::json!(now));
        canonical_data.insert("status".into(), serde_json::json!("listening"));
        db.save_instance_named("miso", &canonical_data).unwrap();
        db.rebind_session("sid-789", "miso").unwrap();

        let mut ph_data = serde_json::Map::new();
        ph_data.insert("name".into(), serde_json::json!("temp"));
        ph_data.insert("tag".into(), serde_json::json!("team"));
        ph_data.insert("created_at".into(), serde_json::json!(now));
        ph_data.insert("status".into(), serde_json::json!("pending"));
        ph_data.insert("status_context".into(), serde_json::json!("new"));
        db.save_instance_named("temp", &ph_data).unwrap();

        db.set_process_binding("pid-123", "", "temp").unwrap();

        let result = bind_session_to_process(&db, "sid-789", Some("pid-123")).unwrap();
        assert_eq!(result, Some("miso".to_string()));

        assert!(db.get_instance_full("temp").unwrap().is_none());

        let inst = db.get_instance_full("miso").unwrap().unwrap();
        assert_eq!(inst.tag.as_deref(), Some("team"));

        cleanup(path);
    }

    #[test]
    fn test_bind_session_path1b_switch_releases_and_restores_old_session() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();
        let read = db
            .log_event(
                "message",
                "sender",
                &serde_json::json!({
                    "from": "sender", "scope": "broadcast", "text": "already read"
                }),
            )
            .unwrap();

        let mut canonical_data = serde_json::Map::new();
        canonical_data.insert("name".into(), serde_json::json!("miso"));
        canonical_data.insert("session_id".into(), serde_json::json!("sid-789"));
        canonical_data.insert("created_at".into(), serde_json::json!(now));
        canonical_data.insert("status".into(), serde_json::json!("listening"));
        db.save_instance_named("miso", &canonical_data).unwrap();
        db.rebind_session("sid-789", "miso").unwrap();

        let mut x_data = serde_json::Map::new();
        x_data.insert("name".into(), serde_json::json!("temp"));
        x_data.insert("session_id".into(), serde_json::json!("sid-old"));
        x_data.insert("tool".into(), serde_json::json!("codex"));
        x_data.insert(
            "transcript_path".into(),
            serde_json::json!("/sessions/old.jsonl"),
        );
        x_data.insert("last_event_id".into(), serde_json::json!(read));
        x_data.insert("created_at".into(), serde_json::json!(now));
        x_data.insert("status".into(), serde_json::json!("listening"));
        db.save_instance_named("temp", &x_data).unwrap();
        db.rebind_session("sid-old", "temp").unwrap();
        db.set_process_binding("pid-123", "sid-old", "temp")
            .unwrap();
        db.upsert_notify_endpoint("temp", "plugin", 53001).unwrap();

        assert_eq!(
            bind_session_to_process(&db, "sid-789", Some("pid-123")).unwrap(),
            Some("miso".into())
        );
        assert_eq!(
            db.get_process_binding("pid-123").unwrap().as_deref(),
            Some("miso")
        );
        assert_released_session(&db, "temp", "sid-old", read, "/sessions/old.jsonl");

        let pending = db
            .log_event(
                "message",
                "sender",
                &serde_json::json!({
                    "from": "sender", "scope": "broadcast", "text": "sent during switch"
                }),
            )
            .unwrap();
        assert_eq!(
            bind_session_to_process(&db, "sid-old", Some("pid-123")).unwrap(),
            Some("temp".into())
        );
        let restored = db.get_instance_full("temp").unwrap().unwrap();
        assert_eq!(restored.session_id.as_deref(), Some("sid-old"));
        assert_eq!(restored.last_event_id, read);
        assert!(
            db.get_unread_messages("temp")
                .iter()
                .any(|m| m.event_id == Some(pending))
        );
        assert_eq!(
            db.get_process_binding("pid-123").unwrap().as_deref(),
            Some("temp")
        );
        cleanup(path);
    }

    #[test]
    fn test_bind_session_path2_switch_retires_displaced_row() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();
        let cursor = db
            .log_event(
                "message",
                "sender",
                &serde_json::json!({
                    "from": "sender", "scope": "broadcast", "text": "already read"
                }),
            )
            .unwrap();
        // Live seat X on session S1, held by this process.
        let mut x_data = serde_json::Map::new();
        x_data.insert("name".into(), serde_json::json!("xrow"));
        x_data.insert("session_id".into(), serde_json::json!("sid-old"));
        x_data.insert("tool".into(), serde_json::json!("codex"));
        x_data.insert(
            "transcript_path".into(),
            serde_json::json!("/sessions/x.jsonl"),
        );
        x_data.insert("last_event_id".into(), serde_json::json!(cursor));
        x_data.insert("created_at".into(), serde_json::json!(now));
        x_data.insert("status".into(), serde_json::json!("listening"));
        db.save_instance_named("xrow", &x_data).unwrap();
        db.rebind_session("sid-old", "xrow").unwrap();
        db.set_process_binding("pid-live", "sid-old", "xrow")
            .unwrap();

        #[cfg(unix)]
        let mut switching = live_holder("pid-live");
        // Session S2's stopped name Y: only the life.stopped snapshot survives.
        let snapshot = serde_json::json!({
            "session_id": "sid-new",
            "tool": "codex",
            "directory": "/tmp/proof-dir",
        });
        db.log_life_event("yrow", "stopped", "test", "exit", Some(snapshot), None)
            .unwrap();

        // The in-process switch: the same live process re-runs its start hook for S2.
        let result = bind_session_to_process(&db, "sid-new", Some("pid-live")).unwrap();
        assert_eq!(result, Some("yrow".to_string()));

        // Y took the process binding; X has a resumable stop snapshot.
        assert_eq!(
            db.get_process_binding("pid-live").unwrap(),
            Some("yrow".to_string())
        );
        assert_eq!(
            db.get_session_binding("sid-new").unwrap(),
            Some("yrow".to_string())
        );

        assert_released_session(&db, "xrow", "sid-old", cursor, "/sessions/x.jsonl");
        assert_eq!(db.get_session_binding("sid-old").unwrap(), None);
        let restored = bind_session_to_process(&db, "sid-old", Some("pid-live")).unwrap();
        assert_eq!(restored.as_deref(), Some("xrow"));
        assert_eq!(
            db.get_instance_full("xrow").unwrap().unwrap().last_event_id,
            cursor
        );
        assert_eq!(
            db.get_process_binding("pid-live").unwrap().as_deref(),
            Some("xrow")
        );
        #[cfg(unix)]
        {
            assert!(
                switching.try_wait().unwrap().is_none(),
                "switch sent a signal"
            );
            switching.kill().unwrap();
            switching.wait().unwrap();
        }

        cleanup(path);
    }

    #[test]
    fn test_own_stop_guard_spares_a_session_switch_back() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let snapshot = |sid: &str| serde_json::json!({"session_id": sid, "tool": "omp", "directory": "/tmp/proof-dir"});
        // The process moved off xrow's session (omp /resume): a switch
        // release, not a stop, so switching back still restores xrow.
        db.log_life_event(
            "xrow",
            "stopped",
            "session_switch",
            "exit:session_switch",
            Some(snapshot("sid-x")),
            Some("pid-live"),
        )
        .unwrap();
        assert_eq!(
            stopped_restore_for_own_process(&db, "sid-x", "pid-live"),
            None
        );
        // A stop of the same process, whoever recorded it, is not undone.
        db.log_life_event(
            "yrow",
            "stopped",
            "cli",
            "external",
            Some(snapshot("sid-y")),
            Some("pid-live"),
        )
        .unwrap();
        assert_eq!(
            stopped_restore_for_own_process(&db, "sid-y", "pid-live").as_deref(),
            Some("yrow")
        );
        cleanup(path);
    }

    #[test]
    #[cfg(unix)]
    fn test_bind_session_path2_switch_shared_row_not_retired() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut x_data = serde_json::Map::new();
        x_data.insert("name".into(), serde_json::json!("xrow"));
        x_data.insert("session_id".into(), serde_json::json!("sid-old"));
        x_data.insert("tool".into(), serde_json::json!("codex"));
        x_data.insert("created_at".into(), serde_json::json!(now));
        x_data.insert("status".into(), serde_json::json!("listening"));
        db.save_instance_named("xrow", &x_data).unwrap();
        db.rebind_session("sid-old", "xrow").unwrap();
        db.set_process_binding("pid-live", "sid-old", "xrow")
            .unwrap();
        // Another process legitimately holds X too.
        db.set_process_binding("pid-other", "sid-old", "xrow")
            .unwrap();
        let mut holder = live_holder("pid-other");
        db.upsert_notify_endpoint("xrow", "plugin", 53002).unwrap();

        let snapshot = serde_json::json!({
            "session_id": "sid-new",
            "tool": "codex",
            "directory": "/tmp/proof-dir",
        });
        db.log_life_event("yrow", "stopped", "test", "exit", Some(snapshot), None)
            .unwrap();

        let result = bind_session_to_process(&db, "sid-new", Some("pid-live")).unwrap();
        assert_eq!(result, Some("yrow".to_string()));

        // Our process still moves to Y, but X stays live for its other holder.
        assert_eq!(
            db.get_process_binding("pid-live").unwrap(),
            Some("yrow".to_string())
        );
        let x = db.get_instance_full("xrow").unwrap().unwrap();
        assert_eq!(x.status, ST_LISTENING);
        assert_eq!(
            db.get_session_binding("sid-old").unwrap(),
            Some("xrow".to_string())
        );
        assert_eq!(
            db.get_process_binding("pid-other").unwrap(),
            Some("xrow".to_string())
        );

        let endpoints: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM notify_endpoints WHERE instance = 'xrow'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(endpoints, 1);
        assert!(
            holder.try_wait().unwrap().is_none(),
            "other process was signalled"
        );
        holder.kill().unwrap();
        holder.wait().unwrap();
        cleanup(path);
    }

    /// Every row of every table, sorted per table: equal states are equal
    /// database contents.
    fn db_state(db: &HcomDb) -> Vec<String> {
        let tables: Vec<String> = db
            .conn()
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let mut state = Vec::new();
        for table in tables {
            let mut stmt = db
                .conn()
                .prepare(&format!("SELECT * FROM \"{table}\""))
                .unwrap();
            let columns = stmt.column_count();
            let mut rows: Vec<String> = stmt
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| row.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .map(|values| format!("{table}: {:?}", values.unwrap()))
                .collect();
            rows.sort();
            state.extend(rows);
        }
        state
    }

    /// A generic seat `xrow` on `sid-old`, held by `pid-live`, plus the stopped
    /// snapshot of `yrow` on `sid-new`. Protected OMP paths use native fixtures below.
    fn seed_path2_switch(db: &HcomDb, endpoints: &[(&str, u16)]) {
        let mut x_data = serde_json::Map::new();
        x_data.insert("name".into(), serde_json::json!("xrow"));
        x_data.insert("session_id".into(), serde_json::json!("sid-old"));
        x_data.insert("tool".into(), serde_json::json!("codex"));
        x_data.insert("created_at".into(), serde_json::json!(now_epoch_i64()));
        x_data.insert("status".into(), serde_json::json!("listening"));
        x_data.insert("pid".into(), serde_json::json!(4242));
        x_data.insert(
            "launch_context".into(),
            serde_json::json!(r#"{"pane_id":"p_9"}"#),
        );
        db.save_instance_named("xrow", &x_data).unwrap();
        db.rebind_session("sid-old", "xrow").unwrap();
        db.set_process_binding("pid-live", "sid-old", "xrow")
            .unwrap();
        for (kind, port) in endpoints {
            db.upsert_notify_endpoint("xrow", kind, *port).unwrap();
        }
        let snapshot = serde_json::json!({
            "session_id": "sid-new",
            "tool": "codex",
            "directory": "/tmp/proof-dir",
        });
        db.log_life_event("yrow", "stopped", "test", "exit", Some(snapshot), None)
            .unwrap();
    }

    /// A switch that fails at its last write, the displaced row's `stopped`
    /// event, leaves the database exactly as it was before the hook: no
    /// restored row, no new life event, both bindings and every endpoint on X.
    #[test]
    #[serial]
    fn test_bind_session_path2_failed_release_rolls_back_whole_switch() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        seed_path2_switch(
            &db,
            &[("pty", 54_001), ("inject", 54_002), ("plugin", 54_003)],
        );
        db.conn()
            .execute_batch(
                "CREATE TRIGGER refuse_x_stop BEFORE INSERT ON events
             WHEN NEW.type = 'life' AND NEW.instance = 'xrow'
               AND json_extract(NEW.data, '$.action') = 'stopped'
             BEGIN SELECT RAISE(ABORT, 'cannot publish stop'); END;",
            )
            .unwrap();
        let before = db_state(&db);

        let err = bind_session_to_process(&db, "sid-new", Some("pid-live")).unwrap_err();
        assert!(
            format!("{err:#}").contains("cannot publish stop"),
            "{err:#}"
        );

        assert_eq!(db_state(&db), before);
        assert!(db.get_instance_full("yrow").unwrap().is_none());
        assert_eq!(
            db.get_process_binding("pid-live").unwrap().as_deref(),
            Some("xrow")
        );
        assert_eq!(
            db.get_session_binding("sid-old").unwrap().as_deref(),
            Some("xrow")
        );
        assert_eq!(db.get_session_binding("sid-new").unwrap(), None);

        cleanup(path);
    }

    /// What a second connection read mid-switch: the endpoints and the
    /// switching process's binding.
    type MidSwitchView = (Vec<(String, String, i64)>, Option<String>);

    thread_local! {
        static SEEN_MID_SWITCH: std::cell::RefCell<Option<MidSwitchView>> =
            const { std::cell::RefCell::new(None) };
    }

    fn endpoint_rows(conn: &rusqlite::Connection) -> Vec<(String, String, i64)> {
        conn.prepare("SELECT instance, kind, port FROM notify_endpoints ORDER BY instance, kind")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    /// Reads over a second connection while the switch holds its writes
    /// uncommitted: what any other process sees mid-switch.
    fn observe_mid_switch(db: &HcomDb, _name: &str) {
        let observer = HcomDb::open_raw(db.path()).unwrap();
        let view = (
            endpoint_rows(observer.conn()),
            observer.get_process_binding("pid-live").unwrap(),
        );
        SEEN_MID_SWITCH.set(Some(view));
    }

    /// The moving process's pty/inject/plugin ports land on Y in the commit
    /// that moves the process: until then every other connection reads them,
    /// and the process, on X; at no point on neither row.
    #[test]
    #[serial]
    fn test_bind_session_path2_moves_endpoints_in_the_switch_commit() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        seed_path2_switch(
            &db,
            &[("pty", 54_101), ("inject", 54_102), ("plugin", 54_103)],
        );
        let ports_on = |name: &str| {
            [("inject", 54_102), ("plugin", 54_103), ("pty", 54_101)]
                .map(|(kind, port)| (name.to_string(), kind.to_string(), port))
                .to_vec()
        };

        RESTORE_STOPPED_COMMIT_GAP_HOOK.with(|hook| hook.set(Some(observe_mid_switch)));
        let result = bind_session_to_process(&db, "sid-new", Some("pid-live")).unwrap();
        RESTORE_STOPPED_COMMIT_GAP_HOOK.with(|hook| hook.set(None));
        assert_eq!(result.as_deref(), Some("yrow"));

        assert_eq!(
            SEEN_MID_SWITCH.take(),
            Some((ports_on("xrow"), Some("xrow".to_string())))
        );
        assert_eq!(endpoint_rows(db.conn()), ports_on("yrow"));
        assert_eq!(
            db.get_process_binding("pid-live").unwrap().as_deref(),
            Some("yrow")
        );
        assert!(db.get_instance_full("xrow").unwrap().is_none());
        let yrow = db.get_instance_full("yrow").unwrap().unwrap();
        assert_eq!(yrow.pid, Some(4242));
        assert_eq!(yrow.launch_context.as_deref(), Some(r#"{"pane_id":"p_9"}"#));

        cleanup(path);
    }

    /// A subagent identity switched away from and back comes back with its
    /// lineage and the rest of its identity, still a subagent by
    /// `is_subagent_instance` (a non-empty `parent_name`, the field `hcom list`
    /// shows as the parent). If its parent stopped meanwhile, it keeps all the
    /// lineage the parent-session foreign key admits.
    #[test]
    #[serial]
    fn test_bind_session_path2_subagent_round_trip_keeps_lineage() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let cursor = db
            .log_event(
                "message",
                "sender",
                &serde_json::json!({
                    "from": "sender", "scope": "broadcast", "text": "already read"
                }),
            )
            .unwrap();

        let mut parent = serde_json::Map::new();
        parent.insert("name".into(), serde_json::json!("luna"));
        parent.insert("session_id".into(), serde_json::json!("sid-parent"));
        parent.insert("created_at".into(), serde_json::json!(now_epoch_i64()));
        parent.insert("status".into(), serde_json::json!("listening"));
        db.save_instance_named("luna", &parent).unwrap();

        let mut sub = serde_json::Map::new();
        for (column, value) in [
            ("session_id", serde_json::json!("sid-sub")),
            ("parent_session_id", serde_json::json!("sid-parent")),
            ("parent_name", serde_json::json!("luna")),
            ("agent_id", serde_json::json!("agent-x")),
            ("tool", serde_json::json!("codex")),
            ("directory", serde_json::json!("/work/sub")),
            ("transcript_path", serde_json::json!("/sessions/sub.jsonl")),
            ("tag", serde_json::json!("crew")),
            ("hints", serde_json::json!("reply in the crew thread")),
            ("wait_timeout", serde_json::json!(600)),
            ("subagent_timeout", serde_json::json!(90)),
            ("launch_args", serde_json::json!("--model small")),
            ("purpose", serde_json::json!("zagdb: rc roll")),
            ("current", serde_json::json!("probing WAL")),
            ("name_announced", serde_json::json!(1)),
            ("last_event_id", serde_json::json!(cursor)),
            ("created_at", serde_json::json!(now_epoch_i64())),
            ("status", serde_json::json!("listening")),
        ] {
            sub.insert(column.into(), value);
        }
        db.save_instance_named("xsub", &sub).unwrap();
        db.rebind_session("sid-sub", "xsub").unwrap();
        db.set_process_binding("pid-live", "sid-sub", "xsub")
            .unwrap();
        let snapshot = serde_json::json!({
            "session_id": "sid-top",
            "tool": "codex",
            "directory": "/work/top",
        });
        db.log_life_event("ytop", "stopped", "test", "exit", Some(snapshot), None)
            .unwrap();
        let identity =
            RebindTargetMetadata::from_row(db.get_instance_full("xsub").unwrap().unwrap());
        let switch = |sid: &str| bind_session_to_process(&db, sid, Some("pid-live")).unwrap();

        assert_eq!(switch("sid-top").as_deref(), Some("ytop"));
        assert!(db.get_instance_full("xsub").unwrap().is_none());
        assert_eq!(switch("sid-sub").as_deref(), Some("xsub"));
        let restored = db.get_instance_full("xsub").unwrap().unwrap();
        assert_eq!(restored.parent_session_id.as_deref(), Some("sid-parent"));
        assert_eq!(restored.parent_name.as_deref(), Some("luna"));
        assert_eq!(restored.agent_id.as_deref(), Some("agent-x"));
        assert!(crate::instances::is_subagent_instance(&restored));
        assert_eq!(RebindTargetMetadata::from_row(restored), identity);

        // The parent stops while the subagent is switched away. The foreign
        // key admits no dangling parent session, so that alone reads NULL.
        assert_eq!(switch("sid-top").as_deref(), Some("ytop"));
        db.delete_instance("luna").unwrap();
        assert_eq!(switch("sid-sub").as_deref(), Some("xsub"));
        let orphaned = db.get_instance_full("xsub").unwrap().unwrap();
        assert!(crate::instances::is_subagent_instance(&orphaned));
        assert_eq!(
            RebindTargetMetadata::from_row(orphaned),
            RebindTargetMetadata {
                parent_session_id: None,
                ..identity
            }
        );

        cleanup(path);
    }

    #[test]
    fn test_bind_session_path3_drops_old_session_binding() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        // Seat X bound to its old session; a brand-new session binds the same row.
        let mut x_data = serde_json::Map::new();
        x_data.insert("name".into(), serde_json::json!("xrow"));
        x_data.insert("session_id".into(), serde_json::json!("sid-old"));
        x_data.insert("tool".into(), serde_json::json!("codex"));
        x_data.insert("created_at".into(), serde_json::json!(now));
        x_data.insert("status".into(), serde_json::json!("listening"));
        db.save_instance_named("xrow", &x_data).unwrap();
        db.rebind_session("sid-old", "xrow").unwrap();
        db.set_process_binding("pid-live", "sid-old", "xrow")
            .unwrap();

        let result = bind_session_to_process(&db, "sid-brand-new", Some("pid-live")).unwrap();
        assert_eq!(result, Some("xrow".to_string()));

        // Same row, new session; the old session's binding is gone so a later
        // resume of the old session can't bind to this row.
        let x = db.get_instance_full("xrow").unwrap().unwrap();
        assert_eq!(x.session_id.as_deref(), Some("sid-brand-new"));
        assert_eq!(
            db.get_session_binding("sid-brand-new").unwrap(),
            Some("xrow".to_string())
        );
        assert_eq!(db.get_session_binding("sid-old").unwrap(), None);
        assert_eq!(
            db.get_process_binding("pid-live").unwrap(),
            Some("xrow".to_string())
        );

        cleanup(path);
    }

    #[test]
    #[cfg(unix)]
    fn test_bind_session_path3_preserves_other_live_process_session() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let mut x = serde_json::Map::new();
        x.insert("name".into(), serde_json::json!("xrow"));
        x.insert("session_id".into(), serde_json::json!("sid-old"));
        x.insert("tool".into(), serde_json::json!("codex"));
        x.insert("created_at".into(), serde_json::json!(now_epoch_i64()));
        x.insert("status".into(), serde_json::json!("listening"));
        db.save_instance_named("xrow", &x).unwrap();
        db.rebind_session("sid-old", "xrow").unwrap();
        db.set_process_binding("pid-live", "sid-old", "xrow")
            .unwrap();
        db.set_process_binding("pid-other", "sid-old", "xrow")
            .unwrap();
        let mut holder = live_holder("pid-other");

        assert_eq!(
            bind_session_to_process(&db, "sid-brand-new", Some("pid-live"))
                .unwrap()
                .as_deref(),
            Some("xrow")
        );
        assert_eq!(
            db.get_session_binding("sid-old").unwrap().as_deref(),
            Some("xrow")
        );
        assert_eq!(
            db.get_session_binding("sid-brand-new").unwrap().as_deref(),
            Some("xrow")
        );
        assert_eq!(
            db.get_process_binding("pid-other").unwrap().as_deref(),
            Some("xrow")
        );
        assert_eq!(
            bind_session_to_process(&db, "sid-old", Some("pid-other"))
                .unwrap()
                .as_deref(),
            Some("xrow")
        );
        assert!(holder.try_wait().unwrap().is_none());
        holder.kill().unwrap();
        holder.wait().unwrap();
        cleanup(path);
    }

    #[test]
    #[cfg(unix)]
    fn test_bind_session_path1b_preserves_other_live_process_row() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        for (name, sid) in [("xrow", "sid-old"), ("yrow", "sid-new")] {
            let mut row = serde_json::Map::new();
            row.insert("name".into(), serde_json::json!(name));
            row.insert("session_id".into(), serde_json::json!(sid));
            row.insert("tool".into(), serde_json::json!("codex"));
            row.insert("created_at".into(), serde_json::json!(now_epoch_i64()));
            row.insert("status".into(), serde_json::json!("listening"));
            db.save_instance_named(name, &row).unwrap();
            db.rebind_session(sid, name).unwrap();
        }
        db.set_process_binding("pid-live", "sid-old", "xrow")
            .unwrap();
        db.set_process_binding("pid-other", "sid-old", "xrow")
            .unwrap();
        db.upsert_notify_endpoint("xrow", "plugin", 53003).unwrap();
        let mut holder = live_holder("pid-other");

        assert_eq!(
            bind_session_to_process(&db, "sid-new", Some("pid-live"))
                .unwrap()
                .as_deref(),
            Some("yrow")
        );
        assert_eq!(
            db.get_process_binding("pid-live").unwrap().as_deref(),
            Some("yrow")
        );
        assert_eq!(
            db.get_process_binding("pid-other").unwrap().as_deref(),
            Some("xrow")
        );
        assert_eq!(
            db.get_session_binding("sid-old").unwrap().as_deref(),
            Some("xrow")
        );
        assert_eq!(
            db.get_instance_full("xrow").unwrap().unwrap().status,
            ST_LISTENING
        );
        let endpoints: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM notify_endpoints WHERE instance = 'xrow'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(endpoints, 1);
        assert!(holder.try_wait().unwrap().is_none());
        holder.kill().unwrap();
        holder.wait().unwrap();
        cleanup(path);
    }

    #[test]
    fn test_bind_session_no_match() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();

        let result = bind_session_to_process(&db, "sid-999", None).unwrap();
        assert_eq!(result, None);

        cleanup(path);
    }

    #[test]
    fn test_create_orphaned_pty_identity_basic() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();

        let result = create_orphaned_pty_identity(&db, "sess-orphan", Some("pid-orphan"), "claude");
        assert!(result.is_some(), "should create orphaned identity");

        let name = result.unwrap();
        let inst = db.get_instance_full(&name).unwrap().unwrap();
        assert_eq!(inst.session_id.as_deref(), Some("sess-orphan"));
        assert_eq!(inst.tool, "claude");

        assert_eq!(
            db.get_session_binding("sess-orphan").unwrap(),
            Some(name.clone())
        );
        assert_eq!(db.get_process_binding("pid-orphan").unwrap(), Some(name));

        cleanup(path);
    }

    #[test]
    fn test_create_orphaned_pty_identity_no_process_id() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();

        let result = create_orphaned_pty_identity(&db, "sess-orphan2", None, "gemini");
        assert!(result.is_some());

        let name = result.unwrap();
        let inst = db.get_instance_full(&name).unwrap().unwrap();
        assert_eq!(inst.tool, "gemini");
        assert_eq!(db.get_session_binding("sess-orphan2").unwrap(), Some(name));

        cleanup(path);
    }

    #[test]
    fn test_resolve_from_binding_process_binding() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut data = serde_json::Map::new();
        data.insert("name".into(), serde_json::json!("luna"));
        data.insert("session_id".into(), serde_json::json!("sess-1"));
        data.insert("created_at".into(), serde_json::json!(now));
        data.insert("status".into(), serde_json::json!("listening"));
        db.save_instance_named("luna", &data).unwrap();
        db.set_process_binding("pid-1", "sess-1", "luna").unwrap();

        let result = resolve_instance_from_binding(&db, None, Some("pid-1"));
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "luna");

        cleanup(path);
    }

    #[test]
    fn test_resolve_from_binding_session_binding() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut data = serde_json::Map::new();
        data.insert("name".into(), serde_json::json!("nova"));
        data.insert("session_id".into(), serde_json::json!("sess-2"));
        data.insert("created_at".into(), serde_json::json!(now));
        data.insert("status".into(), serde_json::json!("active"));
        db.save_instance_named("nova", &data).unwrap();
        db.rebind_session("sess-2", "nova").unwrap();

        let result = resolve_instance_from_binding(&db, Some("sess-2"), None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "nova");

        cleanup(path);
    }

    #[test]
    fn test_resolve_from_binding_process_over_session() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut d1 = serde_json::Map::new();
        d1.insert("name".into(), serde_json::json!("luna"));
        d1.insert("created_at".into(), serde_json::json!(now));
        d1.insert("status".into(), serde_json::json!("active"));
        db.save_instance_named("luna", &d1).unwrap();
        db.set_process_binding("pid-1", "", "luna").unwrap();

        let mut d2 = serde_json::Map::new();
        d2.insert("name".into(), serde_json::json!("nova"));
        d2.insert("session_id".into(), serde_json::json!("sess-2"));
        d2.insert("created_at".into(), serde_json::json!(now));
        d2.insert("status".into(), serde_json::json!("active"));
        db.save_instance_named("nova", &d2).unwrap();
        db.rebind_session("sess-2", "nova").unwrap();

        let result = resolve_instance_from_binding(&db, Some("sess-2"), Some("pid-1"));
        assert_eq!(result.unwrap().name, "luna");

        cleanup(path);
    }

    #[test]
    fn test_resolve_from_binding_process_binding_instance_deleted() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();

        db.set_process_binding("pid-ghost", "", "ghost").unwrap();

        let result = resolve_instance_from_binding(&db, None, Some("pid-ghost"));
        assert!(result.is_none());

        cleanup(path);
    }

    #[test]
    fn test_resolve_from_binding_no_match() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();

        let result = resolve_instance_from_binding(&db, Some("nonexistent"), Some("nope"));
        assert!(result.is_none());

        cleanup(path);
    }

    #[test]
    fn test_session_binding_cascade_on_instance_delete() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut data = serde_json::Map::new();
        data.insert("name".into(), serde_json::json!("luna"));
        data.insert("session_id".into(), serde_json::json!("sess-1"));
        data.insert("created_at".into(), serde_json::json!(now));
        data.insert("status".into(), serde_json::json!("active"));
        db.save_instance_named("luna", &data).unwrap();
        db.rebind_session("sess-1", "luna").unwrap();

        assert_eq!(
            db.get_session_binding("sess-1").unwrap(),
            Some("luna".to_string())
        );

        db.delete_instance("luna").unwrap();
        assert_eq!(db.get_session_binding("sess-1").unwrap(), None);

        cleanup(path);
    }

    #[test]
    fn test_bind_session_restores_deleted_canonical_from_placeholder() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut canonical_data = serde_json::Map::new();
        canonical_data.insert("name".into(), serde_json::json!("miso"));
        canonical_data.insert("session_id".into(), serde_json::json!("sid-resume"));
        canonical_data.insert("tool".into(), serde_json::json!("antigravity"));
        canonical_data.insert("created_at".into(), serde_json::json!(now));
        canonical_data.insert("status".into(), serde_json::json!("listening"));
        db.save_instance_named("miso", &canonical_data).unwrap();
        db.rebind_session("sid-resume", "miso").unwrap();

        let mut ph_data = serde_json::Map::new();
        ph_data.insert("name".into(), serde_json::json!("nova"));
        ph_data.insert("tool".into(), serde_json::json!("antigravity"));
        ph_data.insert("tag".into(), serde_json::json!("work"));
        ph_data.insert("created_at".into(), serde_json::json!(now));
        ph_data.insert("status".into(), serde_json::json!("pending"));
        ph_data.insert("status_context".into(), serde_json::json!("new"));
        db.save_instance_named("nova", &ph_data).unwrap();
        db.set_process_binding("pid-agy", "", "nova").unwrap();

        let snapshot = serde_json::json!({
            "session_id": "sid-resume",
            "tool": "antigravity",
            "tag": "work",
        });
        db.log_life_event("miso", "stopped", "test", "exit", Some(snapshot), None)
            .unwrap();

        db.delete_instance("miso").unwrap();
        assert!(db.get_instance_full("miso").unwrap().is_none());
        assert_eq!(db.get_session_binding("sid-resume").unwrap(), None);

        let result = bind_session_to_process(&db, "sid-resume", Some("pid-agy")).unwrap();
        assert_eq!(result, Some("miso".to_string()));

        let restored = db.get_instance_full("miso").unwrap().unwrap();
        assert_eq!(restored.session_id.as_deref(), Some("sid-resume"));
        assert_eq!(restored.tool, "antigravity");
        assert_eq!(restored.tag.as_deref(), Some("work"));
        assert!(db.get_instance_full("nova").unwrap().is_none());

        cleanup(path);
    }

    /// Process bindings that name an instance row which does not exist.
    fn ghost_process_bindings(db: &HcomDb) -> Vec<(String, String)> {
        let mut stmt = db
            .conn()
            .prepare(
                "SELECT process_id, instance_name FROM process_bindings
                 WHERE instance_name NOT IN (SELECT name FROM instances)",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    #[serial]
    fn test_restore_stopped_recreates_swept_row_from_snapshot() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();

        // Only the stopped snapshot survives: no row, no placeholder, no binding.
        let snapshot = serde_json::json!({
            "session_id": "ses-ghost",
            "tool": "omp",
            "directory": "/tmp/proof-dir",
            "tag": "crew",
            "background": 0,
            "transcript_path": "",
            "hints": "reply in the crew thread",
        });
        db.log_life_event(
            "valo",
            "stopped",
            "daemon",
            "vanished",
            Some(snapshot),
            None,
        )
        .unwrap();

        let result = with_omp_binding_owner(
            OmpOwner {
                pid: 777,
                incarnation: "snapshot-owner".into(),
            },
            || bind_session_to_process(&db, "ses-ghost", Some("omp-777-aa-bb")),
        )
        .unwrap();
        assert_eq!(result, Some("valo".to_string()));

        let valo = db.get_instance_full("valo").unwrap().expect("valo row");
        assert_eq!(valo.session_id.as_deref(), Some("ses-ghost"));
        assert_eq!(valo.tool, "omp");
        assert_eq!(valo.directory, "/tmp/proof-dir");
        assert_eq!(valo.tag.as_deref(), Some("crew"));
        assert_eq!(valo.hints.as_deref(), Some("reply in the crew thread"));
        assert_eq!(
            db.get_session_binding("ses-ghost").unwrap(),
            Some("valo".to_string())
        );
        assert_eq!(
            db.get_process_binding("omp-777-aa-bb").unwrap(),
            Some("valo".to_string())
        );
        assert!(ghost_process_bindings(&db).is_empty());

        cleanup(path);
    }

    /// The rebuilt row resumes delivery where its identity stopped: messages
    /// sent while it was stopped are still pending for it, and nothing it had
    /// read before the stop comes back.
    #[test]
    #[serial]
    fn test_restore_stopped_rebuild_keeps_messages_sent_while_stopped() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let broadcast = |text: &str| {
            db.log_event(
                "message",
                "nova",
                &serde_json::json!({"from": "nova", "scope": "broadcast", "text": text}),
            )
            .unwrap()
        };

        let read_before_stop = broadcast("read before the stop");
        let mut valo_data = serde_json::Map::new();
        valo_data.insert("name".into(), serde_json::json!("valo"));
        valo_data.insert("session_id".into(), serde_json::json!("ses-cursor"));
        valo_data.insert("tool".into(), serde_json::json!("omp"));
        valo_data.insert("created_at".into(), serde_json::json!(now_epoch_i64()));
        valo_data.insert("status".into(), serde_json::json!("listening"));
        valo_data.insert("last_event_id".into(), serde_json::json!(read_before_stop));
        db.save_instance_named("valo", &valo_data).unwrap();

        // The sweep's release: snapshot, stopped event, row gone.
        let snapshot = db.get_instance_snapshot("valo").unwrap();
        db.log_life_event("valo", "stopped", "daemon", "vanished", snapshot, None)
            .unwrap();
        db.delete_instance("valo").unwrap();

        let sent_while_stopped = broadcast("broadcast while stopped");
        let mention_while_stopped = db
            .log_event(
                "message",
                "nova",
                &serde_json::json!({
                    "from": "nova",
                    "scope": "mentions",
                    "mentions": ["valo"],
                    "text": "mention while stopped",
                }),
            )
            .unwrap();

        let result = with_omp_binding_owner(
            OmpOwner {
                pid: 778,
                incarnation: "snapshot-cursor-owner".into(),
            },
            || bind_session_to_process(&db, "ses-cursor", Some("omp-778-aa-bb")),
        )
        .unwrap();
        assert_eq!(result, Some("valo".to_string()));

        let valo = db.get_instance_full("valo").unwrap().expect("valo row");
        assert_eq!(
            valo.last_event_id, read_before_stop,
            "the rebuilt row keeps its stopped snapshot's cursor"
        );
        let pending: Vec<i64> = db
            .get_unread_messages("valo")
            .iter()
            .filter_map(|m| m.event_id)
            .collect();
        assert_eq!(pending, vec![sent_while_stopped, mention_while_stopped]);

        cleanup(path);
    }

    #[test]
    #[serial]
    fn test_bind_placeholder_fk_failure_is_an_error_not_a_name() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();

        // A process binding that names a row which no longer exists.
        db.set_process_binding("pid-ghost", "", "ghost").unwrap();

        let result = bind_session_to_process(&db, "ses-unknown", Some("pid-ghost"));
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(db.get_session_binding("ses-unknown").unwrap(), None);
        assert!(db.get_instance_full("ghost").unwrap().is_none());

        cleanup(path);
    }

    #[test]
    #[serial]
    fn test_bind_session_restore_stopped_deletes_true_placeholder() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut fano_data = serde_json::Map::new();
        fano_data.insert("name".into(), serde_json::json!("fano"));
        fano_data.insert("tool".into(), serde_json::json!("opencode"));
        fano_data.insert("created_at".into(), serde_json::json!(now));
        fano_data.insert("status".into(), serde_json::json!("inactive"));
        db.save_instance_named("fano", &fano_data).unwrap();

        let snapshot = serde_json::json!({
            "session_id": "ses-opencode-1",
            "tool": "opencode",
        });
        db.log_life_event("fano", "stopped", "test", "exit", Some(snapshot), None)
            .unwrap();

        let mut mozi_data = serde_json::Map::new();
        mozi_data.insert("name".into(), serde_json::json!("mozi"));
        mozi_data.insert("tool".into(), serde_json::json!("opencode"));
        mozi_data.insert("created_at".into(), serde_json::json!(now));
        mozi_data.insert("status".into(), serde_json::json!("pending"));
        mozi_data.insert("status_context".into(), serde_json::json!("new"));
        db.save_instance_named("mozi", &mozi_data).unwrap();
        db.set_process_binding("pid-oc", "", "mozi").unwrap();

        db.upsert_notify_endpoint("mozi", "pty", 55_568).unwrap();
        db.upsert_notify_endpoint("fano", "plugin", 58_898).unwrap();

        let result = bind_session_to_process(&db, "ses-opencode-1", Some("pid-oc")).unwrap();
        assert_eq!(result, Some("fano".to_string()));

        assert!(db.get_instance_full("mozi").unwrap().is_none());
        let fano = db.get_instance_full("fano").unwrap().unwrap();
        assert_eq!(fano.session_id.as_deref(), Some("ses-opencode-1"));
        assert_eq!(
            db.get_session_binding("ses-opencode-1").unwrap(),
            Some("fano".to_string())
        );
        assert_eq!(
            db.get_process_binding("pid-oc").unwrap(),
            Some("fano".to_string())
        );

        cleanup(path);
    }

    #[test]
    #[serial]
    fn test_restore_stopped_migrates_pid_and_launch_context_to_canonical() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut fano_data = serde_json::Map::new();
        fano_data.insert("name".into(), serde_json::json!("fano"));
        fano_data.insert("tool".into(), serde_json::json!("opencode"));
        fano_data.insert("created_at".into(), serde_json::json!(now));
        fano_data.insert("status".into(), serde_json::json!("inactive"));
        db.save_instance_named("fano", &fano_data).unwrap();
        db.log_life_event(
            "fano",
            "stopped",
            "test",
            "exit",
            Some(serde_json::json!({ "session_id": "ses-oc-pid", "tool": "opencode" })),
            None,
        )
        .unwrap();

        // Launch placeholder with the runtime state the PTY wrapper writes at spawn.
        let mut mozi_data = serde_json::Map::new();
        mozi_data.insert("name".into(), serde_json::json!("mozi"));
        mozi_data.insert("tool".into(), serde_json::json!("opencode"));
        mozi_data.insert("created_at".into(), serde_json::json!(now));
        mozi_data.insert("status".into(), serde_json::json!("pending"));
        mozi_data.insert("status_context".into(), serde_json::json!("new"));
        db.save_instance_named("mozi", &mozi_data).unwrap();
        db.set_process_binding("pid-oc", "", "mozi").unwrap();
        db.update_instance_pid("mozi", 4242).unwrap();
        db.store_launch_context("mozi", r#"{"pane_id":"kitty-99"}"#)
            .unwrap();

        let result = bind_session_to_process(&db, "ses-oc-pid", Some("pid-oc")).unwrap();
        assert_eq!(result, Some("fano".to_string()));

        // Placeholder gone; pid + launch_context now live on the canonical so the
        // restored agent stays killable and its pane closeable.
        assert!(db.get_instance_full("mozi").unwrap().is_none());
        let fano = db.get_instance_full("fano").unwrap().unwrap();
        assert_eq!(fano.pid, Some(4242));
        assert!(
            fano.launch_context
                .as_deref()
                .unwrap_or_default()
                .contains("kitty-99"),
            "launch_context not migrated: {:?}",
            fano.launch_context
        );

        cleanup(path);
    }

    #[test]
    #[serial]
    fn test_restore_stopped_migrates_ready_promoted_placeholder_runtime_state() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut fano_data = serde_json::Map::new();
        fano_data.insert("name".into(), serde_json::json!("fano"));
        fano_data.insert("tool".into(), serde_json::json!("opencode"));
        fano_data.insert("created_at".into(), serde_json::json!(now));
        fano_data.insert("status".into(), serde_json::json!("inactive"));
        db.save_instance_named("fano", &fano_data).unwrap();
        db.log_life_event(
            "fano",
            "stopped",
            "test",
            "exit",
            Some(serde_json::json!({ "session_id": "ses-oc-ready", "tool": "opencode" })),
            None,
        )
        .unwrap();

        // PTY ready detection can promote the launch row before opencode-start binds
        // the session. It is still the launch placeholder and must be retired.
        let mut mozi_data = serde_json::Map::new();
        mozi_data.insert("name".into(), serde_json::json!("mozi"));
        mozi_data.insert("tool".into(), serde_json::json!("opencode"));
        mozi_data.insert("created_at".into(), serde_json::json!(now));
        mozi_data.insert("status".into(), serde_json::json!("listening"));
        mozi_data.insert("status_context".into(), serde_json::json!("start"));
        db.save_instance_named("mozi", &mozi_data).unwrap();
        db.set_process_binding("pid-oc-ready", "", "mozi").unwrap();
        db.update_instance_pid("mozi", 4343).unwrap();
        db.store_launch_context("mozi", r#"{"pane_id":"kitty-101"}"#)
            .unwrap();

        let result = bind_session_to_process(&db, "ses-oc-ready", Some("pid-oc-ready")).unwrap();
        assert_eq!(result, Some("fano".to_string()));

        assert!(db.get_instance_full("mozi").unwrap().is_none());
        let fano = db.get_instance_full("fano").unwrap().unwrap();
        assert_eq!(fano.pid, Some(4343));
        assert!(
            fano.launch_context
                .as_deref()
                .unwrap_or_default()
                .contains("kitty-101"),
            "launch_context not migrated: {:?}",
            fano.launch_context
        );

        cleanup(path);
    }

    #[test]
    fn test_restore_stopped_keeps_active_no_session_row() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut fano_data = serde_json::Map::new();
        fano_data.insert("name".into(), serde_json::json!("fano"));
        fano_data.insert("tool".into(), serde_json::json!("opencode"));
        fano_data.insert("created_at".into(), serde_json::json!(now));
        fano_data.insert("status".into(), serde_json::json!("inactive"));
        db.save_instance_named("fano", &fano_data).unwrap();
        db.log_life_event(
            "fano",
            "stopped",
            "test",
            "exit",
            Some(serde_json::json!({ "session_id": "ses-keep", "tool": "opencode" })),
            None,
        )
        .unwrap();

        // An ACTIVE row bound to the pid that happens to lack a session_id — NOT a launch
        // placeholder (status_context != "new", status active). It must not be deleted.
        let mut busy_data = serde_json::Map::new();
        busy_data.insert("name".into(), serde_json::json!("busy"));
        busy_data.insert("tool".into(), serde_json::json!("opencode"));
        busy_data.insert("created_at".into(), serde_json::json!(now));
        busy_data.insert("status".into(), serde_json::json!("active"));
        busy_data.insert("status_context".into(), serde_json::json!("tool:write"));
        db.save_instance_named("busy", &busy_data).unwrap();
        db.set_process_binding("pid-busy", "", "busy").unwrap();

        let result = bind_session_to_process(&db, "ses-keep", Some("pid-busy")).unwrap();
        assert_eq!(result, Some("fano".to_string()));

        assert!(
            db.get_instance_full("busy").unwrap().is_some(),
            "active non-placeholder row must not be deleted by restore_stopped"
        );

        cleanup(path);
    }

    fn notify_endpoint_port(db: &HcomDb, instance: &str, kind: &str) -> Option<i64> {
        db.conn()
            .query_row(
                "SELECT port FROM notify_endpoints WHERE instance = ?1 AND kind = ?2",
                rusqlite::params![instance, kind],
                |row| row.get(0),
            )
            .ok()
    }

    struct MigrateNotifyFailGuard;

    impl MigrateNotifyFailGuard {
        fn enable() -> Self {
            HcomDb::set_test_migrate_notify_fail(true);
            Self
        }
    }

    impl Drop for MigrateNotifyFailGuard {
        fn drop(&mut self) {
            HcomDb::set_test_migrate_notify_fail(false);
        }
    }

    #[test]
    #[serial]
    fn test_delete_placeholder_failure_rolls_back_bind_and_notify_migration() {
        let (db, path) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, session_id, created_at, status, status_context)
             VALUES ('fano', 'opencode', 'sid-real', 1.0, 'inactive', ''),
                    ('mozi', 'opencode', NULL, 2.0, 'pending', 'new')",
                [],
            )
            .unwrap();
        db.rebind_session("sid-real", "fano").unwrap();
        db.set_process_binding("pid-oc", "", "mozi").unwrap();
        db.upsert_notify_endpoint("fano", "plugin", 58_898).unwrap();
        db.upsert_notify_endpoint("mozi", "pty", 55_568).unwrap();
        db.conn()
            .execute_batch(
                "CREATE TRIGGER refuse_placeholder_delete BEFORE DELETE ON instances
             WHEN OLD.name = 'mozi'
             BEGIN SELECT RAISE(ABORT, 'placeholder delete refused'); END;",
            )
            .unwrap();
        let before = db_state(&db);
        assert!(bind_session_to_process(&db, "sid-real", Some("pid-oc")).is_err());
        assert_eq!(db_state(&db), before);
        assert_eq!(notify_endpoint_port(&db, "fano", "plugin"), Some(58_898));
        assert_eq!(notify_endpoint_port(&db, "fano", "pty"), None);
        assert_eq!(notify_endpoint_port(&db, "mozi", "pty"), Some(55_568));
        cleanup(path);
    }

    #[test]
    #[serial]
    fn test_failed_retire_migration_rolls_back_whole_bind() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let _guard = MigrateNotifyFailGuard::enable();
        let now = now_epoch_i64();

        let mut fano_data = serde_json::Map::new();
        fano_data.insert("name".into(), serde_json::json!("fano"));
        fano_data.insert("tool".into(), serde_json::json!("opencode"));
        fano_data.insert("created_at".into(), serde_json::json!(now));
        fano_data.insert("status".into(), serde_json::json!("inactive"));
        db.save_instance_named("fano", &fano_data).unwrap();

        let snapshot = serde_json::json!({
            "session_id": "ses-opencode-1",
            "tool": "opencode",
        });
        db.log_life_event("fano", "stopped", "test", "exit", Some(snapshot), None)
            .unwrap();

        let mut mozi_data = serde_json::Map::new();
        mozi_data.insert("name".into(), serde_json::json!("mozi"));
        mozi_data.insert("tool".into(), serde_json::json!("opencode"));
        mozi_data.insert("created_at".into(), serde_json::json!(now));
        mozi_data.insert("status".into(), serde_json::json!("pending"));
        mozi_data.insert("status_context".into(), serde_json::json!("new"));
        db.save_instance_named("mozi", &mozi_data).unwrap();
        db.set_process_binding("pid-oc", "", "mozi").unwrap();

        let before = db_state(&db);
        assert!(bind_session_to_process(&db, "ses-opencode-1", Some("pid-oc")).is_err());
        assert_eq!(db_state(&db), before);

        assert!(db.get_instance_full("mozi").unwrap().is_some());
        assert_eq!(db.get_session_binding("ses-opencode-1").unwrap(), None);

        cleanup(path);
    }

    #[test]
    fn test_bind_session_idempotent_same_session() {
        crate::config::Config::init();
        let (db, path) = setup_test_db();
        let now = now_epoch_i64();

        let mut data = serde_json::Map::new();
        data.insert("name".into(), serde_json::json!("luna"));
        data.insert("status".into(), serde_json::json!("pending"));
        data.insert("status_context".into(), serde_json::json!("new"));
        data.insert("created_at".into(), serde_json::json!(now));
        db.save_instance_named("luna", &data).unwrap();
        db.set_process_binding("pid-1", "", "luna").unwrap();

        let r1 = bind_session_to_process(&db, "sess-1", Some("pid-1")).unwrap();
        assert_eq!(r1, Some("luna".to_string()));

        let r2 = bind_session_to_process(&db, "sess-1", Some("pid-1")).unwrap();
        assert_eq!(r2, Some("luna".to_string()));

        let inst = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(inst.session_id.as_deref(), Some("sess-1"));

        cleanup(path);
    }

    #[test]
    fn test_auto_subscribe_creates_collision_subscription() {
        let (db, path) = setup_test_db();

        use std::collections::HashMap;
        let mut filters: HashMap<String, Vec<String>> = HashMap::new();
        filters.insert("collision".to_string(), vec!["1".to_string()]);

        let result = crate::db::subscriptions::create_filter_subscription(
            &db,
            &filters,
            &[],
            "test-agent",
            false,
            None,
        );
        assert!(result.is_ok(), "subscription creation should succeed");

        let rows: Vec<String> = db
            .conn()
            .prepare("SELECT key FROM kv WHERE key LIKE 'events_sub:%'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(rows.len(), 1, "should have 1 subscription");

        cleanup(path);
    }

    #[test]
    #[serial]
    fn test_pending_placeholder_promotion_auto_subscribes_without_created_event() {
        let _env = EnvVarGuard::set("HCOM_AUTO_SUBSCRIBE", "collision");
        let (db, path) = setup_test_db();

        let now = now_epoch_i64();
        let mut data = serde_json::Map::new();
        data.insert("name".into(), serde_json::json!("luna"));
        data.insert("status".into(), serde_json::json!(PLACEHOLDER_STATUS));
        data.insert(
            "status_context".into(),
            serde_json::json!(PLACEHOLDER_CONTEXT),
        );
        data.insert("created_at".into(), serde_json::json!(now));
        data.insert(
            "last_event_id".into(),
            serde_json::json!(db.get_last_event_id()),
        );
        db.save_instance_named("luna", &data).unwrap();

        let ok = initialize_instance_in_position_file(
            &db,
            "luna",
            None,
            None,
            None,
            None,
            None,
            Some("codex"),
            false,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(ok);
        let ok_again = initialize_instance_in_position_file(
            &db,
            "luna",
            None,
            None,
            None,
            None,
            None,
            Some("codex"),
            false,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(ok_again);

        let created_count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE instance = 'luna'
                   AND type = 'life'
                   AND json_extract(data, '$.action') = 'created'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(created_count, 0);

        let collision_sub_count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM kv
                 WHERE key LIKE 'events_sub:%'
                   AND json_extract(value, '$.caller') = 'luna'
                   AND json_extract(value, '$.filters.collision[0]') IS NOT NULL
                   AND COALESCE(json_extract(value, '$.delivery_only'), 0) != 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(collision_sub_count, 1);

        cleanup(path);
    }

    #[test]
    #[serial]
    fn new_row_honors_configured_hcom_timeout() {
        // Regression test for issue #71: a brand-new instance row (the path
        // used by vanilla `hcom start`, launched, and resumed sessions) must
        // carry the effective HCOM_TIMEOUT rather than silently falling back
        // to the old always-86400 schema default.
        let _env = EnvVarGuard::set("HCOM_TIMEOUT", "30");
        let (db, path) = setup_test_db();

        let ok = initialize_instance_in_position_file(
            &db,
            "luna",
            None,
            None,
            None,
            None,
            None,
            Some("claude"),
            false,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(ok);

        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.wait_timeout, Some(30));

        cleanup(path);
    }

    #[test]
    #[serial]
    fn new_row_falls_back_to_120_without_config() {
        let _env = EnvVarGuard::unset("HCOM_TIMEOUT");
        let (db, path) = setup_test_db();

        let ok = initialize_instance_in_position_file(
            &db,
            "luna",
            None,
            None,
            None,
            None,
            None,
            Some("claude"),
            false,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(ok);

        let row = db.get_instance_full("luna").unwrap().unwrap();
        // Default HcomConfig::timeout is 86400 (schema-equivalent default),
        // preserved for anyone who hasn't set HCOM_TIMEOUT.
        assert_eq!(row.wait_timeout, Some(86400));

        cleanup(path);
    }

    fn omp_test_db() -> (HcomDb, tempfile::TempDir, OmpOwner) {
        crate::config::Config::init();
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_at(&dir.path().join("hcom.db")).unwrap();
        let owner = OmpOwner {
            pid: std::process::id(),
            incarnation: "binding-test-native-incarnation".into(),
        };
        (db, dir, owner)
    }

    fn seed_omp_owner_row(
        db: &HcomDb,
        name: &str,
        session: Option<&str>,
        process_id: Option<&str>,
        owner: &OmpOwner,
    ) {
        db.conn()
            .execute(
                "INSERT INTO instances
             (name, tool, session_id, pid, created_at, status, status_context,
              last_event_id, directory, transcript_path, launch_context)
             VALUES (?1, 'omp', ?2, ?3, ?4, 'listening', 'ready', 17, ?5, ?6, ?7)",
                rusqlite::params![
                    name,
                    session,
                    i64::from(owner.pid),
                    now_epoch_f64(),
                    "/tmp/omp-binding-directory",
                    "/tmp/omp-binding-transcript.jsonl",
                    serde_json::json!({
                        "omp_owner": owner,
                        "pane_id": format!("{name}-pane"),
                    })
                    .to_string(),
                ],
            )
            .unwrap();
        if let Some(session) = session {
            db.rebind_session(session, name).unwrap();
        }
        if let Some(id) = process_id {
            db.set_process_binding(id, session.unwrap_or(""), name)
                .unwrap();
        }
    }

    fn assert_omp_pin(db: &HcomDb, name: &str, owner: &OmpOwner) {
        let row = db.get_instance_full(name).unwrap().unwrap();
        assert_eq!(row.pid, Some(i64::from(owner.pid)));
        assert_eq!(
            crate::proctruth::stored_omp_owner(&row).unwrap(),
            Some(owner.clone())
        );
        assert!(
            !omp_launch_context(&row)
                .unwrap()
                .contains_key("omp_launch_anchor")
        );
    }

    #[test]
    #[serial]
    fn omp_borrowed_minted_and_launcher_leave_complete_state() {
        let (db, _dir, parent) = omp_test_db();
        let minted = format!("omp-{}-parent", parent.pid);
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        seed_omp_owner_row(&db, "parent", Some("sid-parent"), Some(&minted), &parent);
        db.set_process_binding(launcher, "sid-parent", "parent")
            .unwrap();
        db.upsert_notify_endpoint("parent", "plugin", 54_201)
            .unwrap();
        db.upsert_notify_endpoint("parent", "pty", 54_202).unwrap();
        let child = OmpOwner {
            pid: parent.pid.checked_add(1).unwrap(),
            incarnation: "different-child-incarnation".into(),
        };
        with_omp_binding_owner(child.clone(), || {
            for id in [&*minted, launcher] {
                let before = db_state(&db);
                assert!(authenticated_omp_owner(&db, id).is_err());
                assert!(bind_omp_session_to_process(&db, "sid-child", id).is_err());
                assert!(create_omp_identity(&db, "sid-child", id).is_err());
                assert_eq!(db_state(&db), before);
            }
        });
        db.delete_process_binding(launcher).unwrap();
        with_omp_binding_owner(child, || {
            let before = db_state(&db);
            assert!(
                recover_omp_process_binding_for_instance(&db, "parent", "sid-child", launcher,)
                    .is_err()
            );
            assert_eq!(db_state(&db), before);
        });
    }

    #[test]
    #[serial]
    fn omp_rejects_unknown_ids_and_wrapper_minted_identity() {
        let (db, _dir, owner) = omp_test_db();
        with_omp_binding_owner(owner.clone(), || {
            let wrapper = owner.pid.checked_add(1).unwrap();
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().launch_anchor = Some(wrapper);
            });
            for id in [
                String::new(),
                "pid-synthetic".to_string(),
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                format!("omp-{wrapper}-wrapper"),
            ] {
                let before = db_state(&db);
                assert!(authenticated_omp_owner(&db, &id).is_err());
                assert!(bind_omp_session_to_process(&db, "sid-new", &id).is_err());
                assert!(create_omp_identity(&db, "sid-new", &id).is_err());
                assert_eq!(db_state(&db), before);
            }
        });
    }

    #[test]
    #[serial]
    fn omp_same_incarnation_duplicate_switch_moves_runtime_and_releases_displaced() {
        let (db, _dir, owner) = omp_test_db();
        let moving = format!("omp-{}-moving", owner.pid);
        let duplicate = format!("omp-{}-duplicate", owner.pid);
        seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
        seed_omp_owner_row(&db, "yrow", Some("sid-new"), None, &owner);
        db.conn()
            .execute(
                "UPDATE instances SET launch_context = ? WHERE name = 'yrow'",
                rusqlite::params![serde_json::json!({"omp_owner": owner}).to_string()],
            )
            .unwrap();
        // Both row session columns are poisoned, while their authoritative
        // bindings still describe the same-owner transition correctly.
        db.conn()
            .execute_batch(
                "UPDATE instances SET session_id = NULL WHERE name = 'yrow';
             UPDATE instances SET session_id = 'sid-new' WHERE name = 'xrow';",
            )
            .unwrap();
        db.set_process_binding(&duplicate, "sid-old", "xrow")
            .unwrap();
        for (kind, port) in [("pty", 54_211), ("inject", 54_212), ("plugin", 54_213)] {
            db.upsert_notify_endpoint("xrow", kind, port).unwrap();
        }
        let result = with_omp_binding_owner(owner.clone(), || {
            bind_omp_session_to_process(&db, "sid-new", &moving)
        })
        .unwrap();
        assert_eq!(result.as_deref(), Some("yrow"));
        assert_released_session(
            &db,
            "xrow",
            "sid-old",
            17,
            "/tmp/omp-binding-transcript.jsonl",
        );
        assert_eq!(db.get_process_binding(&duplicate).unwrap(), None);
        assert_eq!(
            db.get_process_binding(&moving).unwrap().as_deref(),
            Some("yrow")
        );
        assert_eq!(
            endpoint_rows(db.conn()),
            vec![
                ("yrow".into(), "inject".into(), 54_212),
                ("yrow".into(), "plugin".into(), 54_213),
                ("yrow".into(), "pty".into(), 54_211),
            ],
        );
        let row = db.get_instance_full("yrow").unwrap().unwrap();
        assert_eq!(row.last_event_id, 17);
        assert_eq!(omp_launch_context(&row).unwrap()["pane_id"], "xrow-pane");
        assert_omp_pin(&db, "yrow", &owner);
    }

    #[test]
    #[serial]
    fn omp_same_owner_repairs_poisoned_canonical_session_metadata() {
        let (db, _dir, owner) = omp_test_db();
        let id = format!("omp-{}-current", owner.pid);
        seed_omp_owner_row(&db, "luna", Some("sid-poison"), None, &owner);
        db.rebind_session("sid-real", "luna").unwrap();
        db.set_process_binding(&id, "sid-real", "luna").unwrap();
        db.upsert_notify_endpoint("luna", "plugin", 54_221).unwrap();
        let result = with_omp_binding_owner(owner.clone(), || {
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().started = None;
            });
            store_captured_launch_context(&db, "luna", serde_json::Map::new()).unwrap();
            bind_session_to_process(&db, "sid-real", Some(&id))
        })
        .unwrap();
        assert_eq!(result.as_deref(), Some("luna"));
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.session_id.as_deref(), Some("sid-real"));
        assert_eq!(row.last_event_id, 17);
        assert_eq!(db.get_session_binding("sid-poison").unwrap(), None);
        assert_eq!(
            db.get_session_binding("sid-real").unwrap().as_deref(),
            Some("luna")
        );
        assert_eq!(
            endpoint_rows(db.conn()),
            vec![("luna".into(), "plugin".into(), 54_221)]
        );
        assert_omp_pin(&db, "luna", &owner);
    }

    #[test]
    #[serial]
    fn omp_exact_owner_repairs_vanished_launcher_binding_despite_poisoned_session() {
        let (db, _dir, owner) = omp_test_db();
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        seed_omp_owner_row(&db, "luna", Some("sid-poison"), None, &owner);
        db.delete_session_binding("sid-poison").unwrap();
        db.upsert_notify_endpoint("luna", "pty", 54_231).unwrap();
        let result = with_omp_binding_owner(owner.clone(), || {
            recover_omp_process_binding_for_instance(&db, "luna", "sid-real", launcher)
        })
        .unwrap();
        assert_eq!(result.as_deref(), Some("luna"));
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.session_id.as_deref(), Some("sid-real"));
        assert_eq!(row.last_event_id, 17);
        assert_eq!(row.directory, "/tmp/omp-binding-directory");
        assert_eq!(
            db.get_process_binding(launcher).unwrap().as_deref(),
            Some("luna")
        );
        assert_eq!(
            endpoint_rows(db.conn()),
            vec![("luna".into(), "pty".into(), 54_231)]
        );
        assert_omp_pin(&db, "luna", &owner);

        db.delete_process_binding(launcher).unwrap();
        let reused = OmpOwner {
            incarnation: "new-native-incarnation".into(),
            ..owner
        };
        with_omp_binding_owner(reused, || {
            let before = db_state(&db);
            assert!(
                recover_omp_process_binding_for_instance(&db, "luna", "sid-another", launcher,)
                    .is_err()
            );
            assert_eq!(db_state(&db), before);
        });
    }

    #[test]
    #[serial]
    fn omp_missing_or_unreadable_owner_facts_never_mutate_mapped_rows() {
        let (db, _dir, owner) = omp_test_db();
        let id = format!("omp-{}-current", owner.pid);
        seed_omp_owner_row(&db, "luna", Some("sid-old"), Some(&id), &owner);
        db.upsert_notify_endpoint("luna", "plugin", 54_241).unwrap();
        with_omp_binding_owner(owner.clone(), || {
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().incarnation = None;
            });
            let before = db_state(&db);
            assert!(bind_omp_session_to_process(&db, "sid-new", &id).is_err());
            assert_eq!(db_state(&db), before);
        });
        for context in [
            "{malformed".to_string(),
            r#"{"omp_owner":null}"#.to_string(),
            r#"{"omp_owner":{"pid":0,"incarnation":"bad"}}"#.to_string(),
            serde_json::json!({"omp_owner": {
                "pid": owner.pid, "incarnation": "older-native-incarnation",
            }})
            .to_string(),
        ] {
            db.conn()
                .execute(
                    "UPDATE instances SET launch_context = ? WHERE name = 'luna'",
                    rusqlite::params![context],
                )
                .unwrap();
            with_omp_binding_owner(owner.clone(), || {
                let captured = store_captured_launch_context(&db, "luna", serde_json::Map::new());
                if context == "{malformed" {
                    assert!(captured.is_err());
                } else {
                    captured.unwrap();
                }
                let before = db_state(&db);
                assert!(authenticated_omp_owner(&db, &id).is_err());
                assert!(bind_omp_session_to_process(&db, "sid-new", &id).is_err());
                assert_eq!(db_state(&db), before);
            });
        }
        db.conn()
            .execute(
                "UPDATE instances SET launch_context = ?, pid = ? WHERE name = 'luna'",
                rusqlite::params![
                    serde_json::json!({"omp_owner": owner}).to_string(),
                    i64::from(owner.pid.checked_add(1).unwrap()),
                ],
            )
            .unwrap();
        with_omp_binding_owner(owner.clone(), || {
            let before = db_state(&db);
            assert!(bind_omp_session_to_process(&db, "sid-new", &id).is_err());
            assert_eq!(db_state(&db), before);
        });
        db.conn()
            .execute(
                "UPDATE instances SET launch_context = ?, pid = NULL WHERE name = 'luna'",
                rusqlite::params![serde_json::json!({"omp_owner": owner}).to_string()],
            )
            .unwrap();
        with_omp_binding_owner(owner.clone(), || {
            let before = db_state(&db);
            assert!(bind_omp_session_to_process(&db, "sid-new", &id).is_err());
            assert_eq!(db_state(&db), before);
        });
        db.conn().execute(
            "UPDATE instances SET pid = ?, origin_device_id = 'remote-device' WHERE name = 'luna'",
            rusqlite::params![i64::from(owner.pid)],
        ).unwrap();
        with_omp_binding_owner(owner, || {
            let before = db_state(&db);
            assert!(bind_omp_session_to_process(&db, "sid-new", &id).is_err());
            assert_eq!(db_state(&db), before);
        });
    }

    #[test]
    #[serial]
    fn omp_legacy_enrollment_requires_readable_birth_at_or_before_registration() {
        let (db, _dir, owner) = omp_test_db();
        let id = format!("omp-{}-legacy", owner.pid);
        seed_omp_owner_row(&db, "luna", Some("sid-old"), Some(&id), &owner);
        db.conn()
            .execute(
                "UPDATE instances SET launch_context = '{}' WHERE name = 'luna'",
                [],
            )
            .unwrap();
        db.conn()
            .execute(
                "UPDATE process_bindings SET updated_at = 100.0 WHERE process_id = ?",
                rusqlite::params![id],
            )
            .unwrap();
        with_omp_binding_owner(owner.clone(), || {
            for started in [None, Some(100.000_001)] {
                OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                    fixture.as_mut().unwrap().started = started;
                });
                let before = db_state(&db);
                assert!(bind_omp_session_to_process(&db, "sid-new", &id).is_err());
                assert_eq!(db_state(&db), before);
            }
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().started = Some(100.0);
            });
            db.conn()
                .execute(
                    "UPDATE process_bindings SET updated_at = 'unreadable' WHERE process_id = ?",
                    rusqlite::params![id],
                )
                .unwrap();
            let before = db_state(&db);
            assert!(authenticated_omp_owner(&db, &id).is_err());
            assert!(bind_omp_session_to_process(&db, "sid-new", &id).is_err());
            assert_eq!(db_state(&db), before);
            db.conn()
                .execute(
                    "UPDATE process_bindings SET updated_at = 100.0 WHERE process_id = ?",
                    rusqlite::params![id],
                )
                .unwrap();
            let before = db_state(&db);
            assert_eq!(authenticated_omp_owner(&db, &id).unwrap(), owner);
            assert_eq!(
                db_state(&db),
                before,
                "authentication must remain read-only"
            );
            assert_eq!(
                bind_omp_session_to_process(&db, "sid-new", &id)
                    .unwrap()
                    .as_deref(),
                Some("luna"),
            );
        });
        assert_omp_pin(&db, "luna", &owner);
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        db.delete_process_binding(&id).unwrap();
        db.conn()
            .execute(
                "UPDATE instances SET launch_context = '{}' WHERE name = 'luna'",
                [],
            )
            .unwrap();
        db.set_process_binding(launcher, "sid-new", "luna").unwrap();
        db.conn()
            .execute(
                "UPDATE process_bindings SET updated_at = 100.0 WHERE process_id = ?",
                rusqlite::params![launcher],
            )
            .unwrap();
        with_omp_binding_owner(owner.clone(), || {
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().started = Some(100.0);
            });
            assert_eq!(authenticated_omp_owner(&db, launcher).unwrap(), owner);
            assert_eq!(
                bind_omp_session_to_process(&db, "sid-launcher", launcher)
                    .unwrap()
                    .as_deref(),
                Some("luna"),
            );
        });
        assert_omp_pin(&db, "luna", &owner);
    }

    fn seed_pidless_legacy_omp(db: &HcomDb, process_id: &str) -> String {
        let name = create_orphaned_pty_identity(db, "sid-legacy", Some(process_id), "omp")
            .expect("the predecessor plain-session creation path");
        let row = db.get_instance_full(&name).unwrap().unwrap();
        assert_eq!(row.pid, None, "the real predecessor did not set a PID");
        assert_eq!(crate::proctruth::stored_omp_owner(&row).unwrap(), None);
        assert_eq!(stored_omp_launch_anchor(&row).unwrap(), None);
        assert_eq!(row.session_id.as_deref(), Some("sid-legacy"));
        assert_eq!(
            db.get_process_binding_full(process_id).unwrap(),
            Some((Some("sid-legacy".into()), name.clone())),
        );
        assert_eq!(
            db.get_session_binding("sid-legacy").unwrap(),
            Some(name.clone())
        );
        db.conn()
            .execute(
                "UPDATE instances SET last_event_id = 17 WHERE name = ?",
                rusqlite::params![name],
            )
            .unwrap();
        db.upsert_notify_endpoint(&name, "pty", 54_301).unwrap();
        db.upsert_notify_endpoint(&name, "plugin", 54_302).unwrap();
        name
    }

    #[test]
    #[serial]
    fn pidless_legacy_omp_old_plugin_operations_enroll_without_reminting() {
        for operation in ["read", "check", "ack", "status", "soft-stop"] {
            let (_dir, _, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
            let db = HcomDb::open().unwrap();
            let pid = std::process::id();
            let owner = OmpOwner {
                pid,
                incarnation: crate::sys::process::identity(pid).unwrap(),
            };
            let started = crate::sys::process::start_epoch(pid).unwrap();
            let process_id = format!("omp-{pid}-pidless-{operation}");
            let _id = EnvVarGuard::set("HCOM_PROCESS_ID", &process_id);
            let _name = EnvVarGuard::unset("HCOM_INSTANCE_NAME");
            let name = seed_pidless_legacy_omp(&db, &process_id);
            db.conn()
                .execute_batch(
                    "INSERT INTO events (id, type, timestamp, instance, data) VALUES
                     (41, 'message', '2026-10-30T00:00:00Z', 'sender',
                      '{\"from\":\"sender\",\"scope\":\"broadcast\",\"text\":\"first legacy mail\"}'),
                     (42, 'message', '2026-10-30T00:00:01Z', 'sender',
                      '{\"from\":\"sender\",\"scope\":\"broadcast\",\"text\":\"second legacy mail\"}');",
                )
                .unwrap();
            with_omp_binding_owner(owner.clone(), || {
                OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                    fixture.as_mut().unwrap().started = Some(started);
                });
                let before = db_state(&db);
                assert_eq!(authenticated_omp_owner(&db, &process_id).unwrap(), owner);
                assert_eq!(db_state(&db), before, "authentication must stay read-only");
                let (hook, flags): (&str, &[&str]) = match operation {
                    "read" => ("omp-read", &[]),
                    "check" => ("omp-read", &["--check"]),
                    "ack" => ("omp-read", &["--ack", "--up-to", "41"]),
                    "status" => ("omp-status", &["--status", "active", "--context", "legacy"]),
                    "soft-stop" => ("omp-stop", &["--soft", "--reason", "restart"]),
                    _ => unreachable!(),
                };
                let mut argv = vec!["--name".to_string(), name.clone()];
                argv.extend(flags.iter().map(|arg| arg.to_string()));
                let (code, output) = crate::hooks::omp::dispatch_omp_hook(hook, &argv);
                assert_eq!(code, 0, "{operation}: {output}");
                match operation {
                    "read" => {
                        let mail: serde_json::Value = serde_json::from_str(&output).unwrap();
                        assert_eq!(mail[0]["message"], "first legacy mail");
                        assert_eq!(mail[1]["message"], "second legacy mail");
                    }
                    "check" => assert_eq!(output, "true"),
                    "ack" => assert_eq!(
                        serde_json::from_str::<serde_json::Value>(&output).unwrap(),
                        serde_json::json!({"acked_to": 41}),
                    ),
                    _ => assert_eq!(
                        serde_json::from_str::<serde_json::Value>(&output).unwrap()["ok"],
                        true,
                    ),
                }
                assert_omp_pin(&db, &name, &owner);
                let row = db.get_instance_full(&name).unwrap().unwrap();
                assert_eq!(row.last_event_id, if operation == "ack" { 41 } else { 17 });
                assert_eq!(row.session_id.as_deref(), Some("sid-legacy"));
                assert_eq!(
                    db.get_process_binding_full(&process_id).unwrap(),
                    Some((Some("sid-legacy".into()), name.clone())),
                );
                if operation == "soft-stop" {
                    assert!(
                        endpoint_rows(db.conn()).is_empty(),
                        "soft-stop removes the stopped incarnation's notify endpoints",
                    );
                } else {
                    assert_eq!(
                        endpoint_rows(db.conn()),
                        vec![
                            (name.clone(), "plugin".into(), 54_302),
                            (name.clone(), "pty".into(), 54_301),
                        ],
                    );
                }
                if operation == "status" {
                    assert_eq!(row.status, "active");
                    assert_eq!(row.status_context, "legacy");
                }
                if operation == "soft-stop" {
                    assert_eq!(row.status, "inactive");
                    assert_eq!(db.get_session_binding("sid-legacy").unwrap(), None);
                    let (code, output) = crate::hooks::omp::dispatch_omp_hook(
                        "omp-start",
                        &[
                            "--session-id".into(),
                            "sid-restarted".into(),
                            "--notify-port".into(),
                            "54303".into(),
                        ],
                    );
                    assert_eq!(code, 0, "{output}");
                    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
                    assert_eq!(response["name"], name);
                    assert_eq!(response["session_id"], "sid-restarted");
                    let restarted = db.get_instance_full(&name).unwrap().unwrap();
                    assert_eq!(restarted.last_event_id, 17);
                    assert_eq!(restarted.status, "listening");
                    assert_eq!(restarted.session_id.as_deref(), Some("sid-restarted"));
                    assert_eq!(
                        db.get_process_binding_full(&process_id).unwrap(),
                        Some((Some("sid-restarted".into()), name.clone())),
                    );
                    assert_eq!(
                        endpoint_rows(db.conn()),
                        vec![(name.clone(), "plugin".into(), 54_303)],
                    );
                }
                let rows: i64 = db
                    .conn()
                    .query_row("SELECT COUNT(*) FROM instances", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(rows, 1, "the existing name must never be reminted");
            });
        }
    }

    #[test]
    #[serial]
    fn pidless_legacy_omp_captured_enrollment_replays_after_same_owner_pin() {
        let (_dir, _, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let pid = std::process::id();
        let owner = OmpOwner {
            pid,
            incarnation: crate::sys::process::identity(pid).unwrap(),
        };
        let process_id = format!("omp-{pid}-pidless-queued-enrollment");
        let name = seed_pidless_legacy_omp(&db, &process_id);
        let ctx = crate::shared::context::HcomContext::from_env(
            &std::collections::HashMap::from([("HCOM_PROCESS_ID".into(), process_id.clone())]),
            home,
        );
        let argv = vec!["--name".into(), name.clone(), "--check".into()];
        with_omp_binding_owner(owner.clone(), || {
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().started = crate::sys::process::start_epoch(pid);
            });
            // Request B authenticates while the predecessor still has no PID.
            let before = db_state(&db);
            let queued_owner = authenticated_omp_owner(&db, &process_id).unwrap();
            assert_eq!(db_state(&db), before);
            assert_eq!(db.get_instance_full(&name).unwrap().unwrap().pid, None);
            // Request A wins the writer lock and completes genuine enrollment.
            assert_eq!(
                crate::hooks::common::omp_hook_caller_gate(&ctx, &db, "omp-read", &argv).unwrap(),
                Some(owner.clone()),
            );
            assert_omp_pin(&db, &name, &owner);
            let enrolled = db_state(&db);
            // Request B's captured legacy path now enters its writer section.
            enroll_pidless_legacy_omp_owner(&db, &process_id, &name, &queued_owner).unwrap();
            assert_eq!(
                db_state(&db),
                enrolled,
                "same-owner replay must write nothing"
            );
            assert_eq!(
                crate::hooks::common::omp_hook_caller_gate(&ctx, &db, "omp-read", &argv).unwrap(),
                Some(owner.clone()),
            );
            assert_eq!(db_state(&db), enrolled);
        });
    }

    #[test]
    #[serial]
    fn pidless_legacy_omp_first_start_pins_inside_the_checked_bind() {
        for session in ["sid-legacy", "sid-first-start"] {
            let (_dir, _, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
            let db = HcomDb::open().unwrap();
            let pid = std::process::id();
            let owner = OmpOwner {
                pid,
                incarnation: crate::sys::process::identity(pid).unwrap(),
            };
            let process_id = format!("omp-{pid}-pidless-first-start");
            let name = seed_pidless_legacy_omp(&db, &process_id);
            let ctx = crate::shared::context::HcomContext::from_env(
                &std::collections::HashMap::from([("HCOM_PROCESS_ID".into(), process_id.clone())]),
                home,
            );
            let argv = vec!["--session-id".into(), session.into()];
            with_omp_binding_owner(owner.clone(), || {
                OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                    fixture.as_mut().unwrap().started = crate::sys::process::start_epoch(pid);
                });
                let before = db_state(&db);
                let proven =
                    crate::hooks::common::omp_hook_caller_gate(&ctx, &db, "omp-start", &argv)
                        .unwrap()
                        .unwrap();
                assert_eq!(db_state(&db), before, "start must not precommit enrollment");
                let (code, output) = crate::hooks::omp::handle_start(&ctx, &db, &argv, &proven);
                assert_eq!(code, 0, "{output}");
                let response: serde_json::Value = serde_json::from_str(&output).unwrap();
                assert_eq!(response["name"], name);
                assert_eq!(response["session_id"], session);
                assert_omp_pin(&db, &name, &owner);
                let row = db.get_instance_full(&name).unwrap().unwrap();
                assert_eq!(row.last_event_id, 17);
                assert_eq!(row.session_id.as_deref(), Some(session));
                assert_eq!(db.get_session_binding(session).unwrap(), Some(name.clone()));
                assert_eq!(
                    db.get_process_binding_full(&process_id).unwrap(),
                    Some((Some(session.into()), name.clone())),
                );
                assert_eq!(
                    endpoint_rows(db.conn()),
                    vec![
                        (name.clone(), "plugin".into(), 54_302),
                        (name.clone(), "pty".into(), 54_301),
                    ],
                );
            });
        }
    }

    #[test]
    #[serial]
    fn pidless_legacy_omp_refused_bind_rolls_back_its_owner_pin() {
        let (_dir, _, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let pid = std::process::id();
        let owner = OmpOwner {
            pid,
            incarnation: crate::sys::process::identity(pid).unwrap(),
        };
        let process_id = format!("omp-{pid}-pidless-bind-rollback");
        let name = seed_pidless_legacy_omp(&db, &process_id);
        db.conn()
            .execute_batch(
                "CREATE TRIGGER refuse_legacy_bind BEFORE UPDATE OF session_id ON instances
             BEGIN SELECT RAISE(ABORT, 'refused legacy bind'); END;",
            )
            .unwrap();
        let ctx = crate::shared::context::HcomContext::from_env(
            &std::collections::HashMap::from([("HCOM_PROCESS_ID".into(), process_id.clone())]),
            home,
        );
        with_omp_binding_owner(owner, || {
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().started = crate::sys::process::start_epoch(pid);
            });
            let before = db_state(&db);
            crate::hooks::common::omp_hook_caller_gate(
                &ctx,
                &db,
                "omp-start",
                &["--session-id".into(), "sid-legacy".into()],
            )
            .unwrap();
            assert!(bind_omp_session_to_process(&db, "sid-legacy", &process_id).is_err());
            assert_eq!(db_state(&db), before);
            assert_eq!(db.get_instance_full(&name).unwrap().unwrap().pid, None);
            OMP_OWNER_COMMIT_GAP_HOOK.with(|hook| {
                hook.set(Some(expire_omp_owner_before_commit));
            });
            assert!(
                crate::hooks::common::omp_hook_caller_gate(
                    &ctx,
                    &db,
                    "omp-read",
                    &["--name".into(), name.clone()],
                )
                .is_err(),
            );
            assert_eq!(
                db_state(&db),
                before,
                "failed enrollment must roll back its pin"
            );
        });
    }

    #[test]
    #[serial]
    fn pidless_legacy_omp_invalid_owner_evidence_never_mutates() {
        for case in [
            "stale-registration",
            "reused-pid",
            "unreadable-registration",
            "unreadable-token",
            "unreadable-birth",
            "zero-birth",
            "infinite-birth",
            "wrong-pid",
            "zero-pid",
            "negative-pid",
            "malformed-context",
            "malformed-stamp",
            "stamped-without-pid",
            "receipt-without-pid",
            "malformed-receipt",
            "cross-seat",
            "launcher-without-pid",
            "remote-row",
        ] {
            let (_dir, _, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
            let db = HcomDb::open().unwrap();
            let pid = std::process::id();
            let owner = OmpOwner {
                pid,
                incarnation: crate::sys::process::identity(pid).unwrap(),
            };
            let started = crate::sys::process::start_epoch(pid).unwrap();
            let process_id = match case {
                "cross-seat" => format!("omp-{}-pidless-foreign", pid + 1),
                "launcher-without-pid" => "550e8400-e29b-41d4-a716-446655440000".into(),
                _ => format!("omp-{pid}-pidless-refusal"),
            };
            let name = seed_pidless_legacy_omp(&db, &process_id);
            let context = match case {
                "malformed-context" => Some("{malformed".to_string()),
                "malformed-stamp" => Some(r#"{"omp_owner":null}"#.to_string()),
                "stamped-without-pid" => Some(serde_json::json!({"omp_owner": owner}).to_string()),
                "receipt-without-pid" => {
                    Some(serde_json::json!({"omp_launch_anchor": owner}).to_string())
                }
                "malformed-receipt" => Some(r#"{"omp_launch_anchor":null}"#.to_string()),
                _ => None,
            };
            if let Some(context) = context {
                db.conn()
                    .execute(
                        "UPDATE instances SET launch_context = ?1 WHERE name = ?2",
                        rusqlite::params![context, name],
                    )
                    .unwrap();
            }
            if matches!(case, "wrong-pid" | "zero-pid" | "negative-pid") {
                let wrong = match case {
                    "wrong-pid" => i64::from(pid) + 1,
                    "zero-pid" => 0,
                    _ => -1,
                };
                db.conn()
                    .execute(
                        "UPDATE instances SET pid = ?1 WHERE name = ?2",
                        rusqlite::params![wrong, name],
                    )
                    .unwrap();
            }
            if matches!(case, "stale-registration" | "reused-pid") {
                db.conn()
                    .execute(
                        "UPDATE process_bindings SET updated_at = ?1 WHERE process_id = ?2",
                        rusqlite::params![started - 0.000_001, process_id],
                    )
                    .unwrap();
            }
            if case == "unreadable-registration" {
                db.conn().execute(
                    "UPDATE process_bindings SET updated_at = 'unreadable' WHERE process_id = ?",
                    rusqlite::params![process_id],
                ).unwrap();
            }
            if case == "remote-row" {
                db.conn()
                    .execute(
                        "UPDATE instances SET origin_device_id = 'another-device' WHERE name = ?",
                        rusqlite::params![name],
                    )
                    .unwrap();
            }
            let ctx = crate::shared::context::HcomContext::from_env(
                &std::collections::HashMap::from([("HCOM_PROCESS_ID".into(), process_id.clone())]),
                home,
            );
            with_omp_binding_owner(owner, || {
                OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                    let fixture = fixture.as_mut().unwrap();
                    fixture.started = match case {
                        "unreadable-birth" => None,
                        "zero-birth" => Some(0.0),
                        "infinite-birth" => Some(f64::INFINITY),
                        _ => Some(started),
                    };
                    if case == "unreadable-token" {
                        fixture.incarnation = None;
                    }
                    if case == "reused-pid" {
                        fixture.owner.incarnation = "reused-native-incarnation".into();
                        fixture.incarnation = Some(fixture.owner.incarnation.clone());
                    }
                });
                let before = db_state(&db);
                assert!(authenticated_omp_owner(&db, &process_id).is_err(), "{case}");
                for (hook, flags) in [
                    ("omp-read", vec![]),
                    ("omp-read", vec!["--check"]),
                    ("omp-read", vec!["--ack", "--up-to", "42"]),
                    ("omp-status", vec!["--status", "active"]),
                    ("omp-stop", vec!["--soft"]),
                    ("omp-start", vec!["--session-id", "sid-legacy"]),
                ] {
                    let mut argv = vec!["--name".to_string(), name.clone()];
                    argv.extend(flags.into_iter().map(str::to_string));
                    let (_, output) =
                        crate::hooks::common::omp_hook_caller_gate(&ctx, &db, hook, &argv)
                            .unwrap_err();
                    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
                    assert!(response["error"].is_string(), "{case}: {output}");
                    assert!(response.get("transient").is_none(), "{case}: {output}");
                }
                assert!(
                    bind_omp_session_to_process(&db, "sid-legacy", &process_id).is_err(),
                    "{case}"
                );
                assert_eq!(db_state(&db), before, "{case}");
            });
        }
    }

    #[test]
    #[serial]
    fn pidless_legacy_omp_foreign_canonical_row_is_not_adopted() {
        for foreign_id in [None, Some("omp-1-foreign-pidless-canonical")] {
            let (_dir, _, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
            let db = HcomDb::open().unwrap();
            let pid = std::process::id();
            let owner = OmpOwner {
                pid,
                incarnation: crate::sys::process::identity(pid).unwrap(),
            };
            let process_id = format!("omp-{pid}-pidless-canonical-refusal");
            let mapped = seed_pidless_legacy_omp(&db, &process_id);
            let canonical =
                create_orphaned_pty_identity(&db, "sid-foreign-canonical", foreign_id, "omp")
                    .unwrap();
            assert_eq!(db.get_instance_full(&canonical).unwrap().unwrap().pid, None);
            with_omp_binding_owner(owner.clone(), || {
                OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                    fixture.as_mut().unwrap().started = crate::sys::process::start_epoch(pid);
                });
                let before = db_state(&db);
                assert_eq!(authenticated_omp_owner(&db, &process_id).unwrap(), owner);
                assert!(
                    bind_omp_session_to_process(&db, "sid-foreign-canonical", &process_id,)
                        .is_err()
                );
                assert_eq!(db_state(&db), before);
                db.set_process_binding(
                    "550e8400-e29b-41d4-a716-446655440123",
                    "sid-legacy",
                    &mapped,
                )
                .unwrap();
                let before = db_state(&db);
                assert!(
                    enroll_pidless_legacy_omp_owner(&db, &process_id, &mapped, &owner,).is_err()
                );
                assert!(bind_omp_session_to_process(&db, "sid-legacy", &process_id).is_err());
                assert_eq!(
                    db_state(&db),
                    before,
                    "a foreign holder must keep the row unchanged"
                );
            });
        }
    }

    #[cfg(unix)]
    struct OmpTestChild(std::process::Child);

    #[cfg(unix)]
    impl OmpTestChild {
        fn spawn() -> Self {
            Self(
                std::process::Command::new("sleep")
                    .arg("60")
                    .spawn()
                    .unwrap(),
            )
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    #[cfg(unix)]
    impl Drop for OmpTestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn omp_carrier_probe_test_child(
        name: &str,
        process_id: &str,
    ) -> (tempfile::TempDir, OmpTestChild) {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("omp");
        std::os::unix::fs::symlink("/bin/sh", &executable).unwrap();
        // A native omp comm marker stays eligible even below a shared tool broker.
        // The held pipe blocks the shell builtin without spawning another child.
        let child = OmpTestChild(
            std::process::Command::new(&executable)
                .args(["-c", "read _"])
                .env("HCOM_INSTANCE_NAME", name)
                .env("HCOM_PROCESS_ID", process_id)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        assert_eq!(
            std::fs::read_to_string(format!("/proc/{}/comm", child.pid()))
                .unwrap()
                .trim_end(),
            "omp"
        );
        (dir, child)
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn omp_wrapper_handoff_requires_current_empty_launch_receipt_then_removes_it() {
        let (db, _dir, owner) = omp_test_db();
        let wrapper = OmpTestChild::spawn();
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        db.conn().execute(
            "INSERT INTO instances (name, tool, created_at, status, status_context, launch_context)
             VALUES ('luna', 'omp', ?1, ?2, ?3, '{\"pane_id\":\"launch-pane\"}')",
            rusqlite::params![now_epoch_f64(), PLACEHOLDER_STATUS, PLACEHOLDER_CONTEXT],
        ).unwrap();
        db.set_process_binding(launcher, "", "luna").unwrap();
        assert!(db.set_instance_pid_if_unset("luna", wrapper.pid()).unwrap());
        assert!(!db.set_instance_pid_if_unset("luna", owner.pid).unwrap());
        let anchor = OmpOwner {
            pid: wrapper.pid(),
            incarnation: crate::sys::process::identity(wrapper.pid()).unwrap(),
        };
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(
            stored_omp_launch_anchor(&row).unwrap(),
            Some(anchor.clone())
        );
        store_captured_launch_context(&db, "luna", serde_json::Map::new()).unwrap();
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(
            stored_omp_launch_anchor(&row).unwrap(),
            Some(anchor.clone())
        );
        with_omp_binding_owner(owner.clone(), || {
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                let fixture = fixture.as_mut().unwrap();
                fixture.launch_anchor = Some(wrapper.pid());
                fixture.started = None;
            });
            for context in [
                serde_json::json!({"omp_launch_anchor": {
                    "pid": wrapper.pid(), "incarnation": "prior-wrapper-incarnation",
                }}),
                serde_json::json!({"omp_launch_anchor": {
                    "pid": owner.pid, "incarnation": anchor.incarnation,
                }}),
                serde_json::json!({"pane_id": "launch-pane"}),
            ] {
                db.conn()
                    .execute(
                        "UPDATE instances SET launch_context = ? WHERE name = 'luna'",
                        rusqlite::params![context.to_string()],
                    )
                    .unwrap();
                let before = db_state(&db);
                assert!(bind_omp_session_to_process(&db, "sid-new", launcher).is_err());
                assert_eq!(db_state(&db), before);
            }
            db.conn()
                .execute(
                    "UPDATE instances SET launch_context = ? WHERE name = 'luna'",
                    rusqlite::params![
                        serde_json::json!({
                            "omp_launch_anchor": anchor, "pane_id": "launch-pane",
                        })
                        .to_string()
                    ],
                )
                .unwrap();
            db.set_process_binding(launcher, "sid-unexpected", "luna")
                .unwrap();
            let before = db_state(&db);
            assert!(bind_omp_session_to_process(&db, "sid-new", launcher).is_err());
            assert_eq!(db_state(&db), before);
            db.set_process_binding(launcher, "", "luna").unwrap();
            assert_eq!(
                bind_omp_session_to_process(&db, "sid-new", launcher)
                    .unwrap()
                    .as_deref(),
                Some("luna"),
            );
        });
        assert_omp_pin(&db, "luna", &owner);
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.session_id.as_deref(), Some("sid-new"));
        assert_eq!(omp_launch_context(&row).unwrap()["pane_id"], "launch-pane");
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_resumed_launch_handoff_authenticates_and_binds_through_both_target_paths() {
        for canonical_exists in [false, true] {
            let (db, _dir, owner) = omp_test_db();
            let mut wrapper = OmpTestChild::spawn();
            let launcher = "550e8400-e29b-41d4-a716-446655440000";
            crate::launcher::register_launch_instance(
                &db,
                "luna",
                Some("sid-prior"),
                launcher,
                "omp",
                false,
                None,
                "/tmp/omp-resumed-launch",
            )
            .unwrap();
            assert!(db.set_instance_pid_if_unset("luna", wrapper.pid()).unwrap());
            store_captured_launch_context(
                &db,
                "luna",
                serde_json::Map::from_iter([("pane_id".into(), serde_json::json!("resume-pane"))]),
            )
            .unwrap();
            if canonical_exists {
                db.rebind_session("sid-prior", "luna").unwrap();
            }
            let launched = db.get_instance_full("luna").unwrap().unwrap();
            assert_eq!(launched.session_id.as_deref(), Some("sid-prior"));
            assert_eq!(launched.pid, Some(i64::from(wrapper.pid())));
            assert!(!is_true_launch_placeholder(Some(&launched)));
            assert_eq!(
                stored_omp_launch_anchor(&launched).unwrap(),
                Some(OmpOwner {
                    pid: wrapper.pid(),
                    incarnation: crate::sys::process::identity(wrapper.pid()).unwrap(),
                })
            );
            assert_eq!(
                db.get_process_binding_full(launcher).unwrap(),
                Some((None, "luna".into()))
            );
            // Deliberately omit the launcher's later child-PID update: the
            // live wrapper and its receipt are still on this resumed row.
            let before_auth = db_state(&db);
            with_omp_binding_owner(owner.clone(), || {
                OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                    fixture.as_mut().unwrap().launch_anchor = Some(wrapper.pid());
                });
                assert_eq!(authenticated_omp_owner(&db, launcher).unwrap(), owner);
                assert_eq!(db_state(&db), before_auth);
                assert_eq!(
                    bind_omp_session_to_process(&db, "sid-prior", launcher)
                        .unwrap()
                        .as_deref(),
                    Some("luna")
                );
            });
            assert_omp_pin(&db, "luna", &owner);
            let bound = db.get_instance_full("luna").unwrap().unwrap();
            assert_eq!(bound.name, launched.name);
            assert_eq!(bound.created_at, launched.created_at);
            assert_eq!(bound.session_id.as_deref(), Some("sid-prior"));
            assert_eq!(
                omp_launch_context(&bound).unwrap()["pane_id"],
                "resume-pane"
            );
            assert_eq!(
                db.get_session_binding("sid-prior").unwrap().as_deref(),
                Some("luna")
            );
            assert_eq!(
                db.get_process_binding_full(launcher).unwrap(),
                Some((Some("sid-prior".into()), "luna".into()))
            );
            assert!(wrapper.0.try_wait().unwrap().is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_resumed_launch_foreign_and_stale_receipts_leave_complete_state() {
        let (db, _dir, owner) = omp_test_db();
        let wrapper = OmpTestChild::spawn();
        let foreign = OmpTestChild::spawn();
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        crate::launcher::register_launch_instance(
            &db,
            "luna",
            Some("sid-prior"),
            launcher,
            "omp",
            false,
            None,
            "/tmp/omp-resumed-launch",
        )
        .unwrap();
        assert!(db.set_instance_pid_if_unset("luna", wrapper.pid()).unwrap());
        with_omp_binding_owner(owner, || {
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().launch_anchor = Some(wrapper.pid());
            });
            for anchor in [
                OmpOwner {
                    pid: wrapper.pid(),
                    incarnation: "prior-wrapper-incarnation".into(),
                },
                OmpOwner {
                    pid: foreign.pid(),
                    incarnation: crate::sys::process::identity(foreign.pid()).unwrap(),
                },
            ] {
                db.conn()
                    .execute(
                        "UPDATE instances SET launch_context = ? WHERE name = 'luna'",
                        rusqlite::params![
                            serde_json::json!({
                                "omp_launch_anchor": anchor,
                                "pane_id": "resume-pane",
                            })
                            .to_string()
                        ],
                    )
                    .unwrap();
                let before = db_state(&db);
                assert!(authenticated_omp_owner(&db, launcher).is_err());
                assert!(bind_omp_session_to_process(&db, "sid-prior", launcher).is_err());
                assert_eq!(db_state(&db), before);
            }
        });
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_resumed_launch_pin_failure_reaches_pin_and_rolls_back_complete_state() {
        let (db, _dir, owner) = omp_test_db();
        let wrapper = OmpTestChild::spawn();
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        crate::launcher::register_launch_instance(
            &db,
            "luna",
            Some("sid-prior"),
            launcher,
            "omp",
            false,
            None,
            "/tmp/omp-resumed-launch",
        )
        .unwrap();
        assert!(db.set_instance_pid_if_unset("luna", wrapper.pid()).unwrap());
        store_captured_launch_context(
            &db,
            "luna",
            serde_json::Map::from_iter([("pane_id".into(), serde_json::json!("resume-pane"))]),
        )
        .unwrap();
        db.conn()
            .execute_batch(
                "CREATE TRIGGER refuse_resumed_launch_pin BEFORE UPDATE OF pid ON instances
                 WHEN NEW.name = 'luna'
                 BEGIN SELECT RAISE(ABORT, 'pr127 resumed launch pin refused'); END;",
            )
            .unwrap();
        let before = db_state(&db);
        let error = with_omp_binding_owner(owner.clone(), || {
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().launch_anchor = Some(wrapper.pid());
            });
            assert_eq!(authenticated_omp_owner(&db, launcher).unwrap(), owner);
            bind_omp_session_to_process(&db, "sid-prior", launcher).unwrap_err()
        });
        assert!(
            format!("{error:#}").contains("pr127 resumed launch pin refused"),
            "{error:#}"
        );
        assert_eq!(db_state(&db), before);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_resumed_launch_receipt_never_authorizes_another_mapped_registration() {
        let (db, _dir, owner) = omp_test_db();
        let wrapper = OmpTestChild::spawn();
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        let moving_launcher = "550e8400-e29b-41d4-a716-446655440001";
        let moving = format!("omp-{}-moving", owner.pid);
        seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
        db.set_process_binding(moving_launcher, "sid-old", "xrow")
            .unwrap();
        crate::launcher::register_launch_instance(
            &db,
            "luna",
            Some("sid-prior"),
            launcher,
            "omp",
            false,
            None,
            "/tmp/omp-resumed-launch",
        )
        .unwrap();
        assert!(db.set_instance_pid_if_unset("luna", wrapper.pid()).unwrap());
        with_omp_binding_owner(owner.clone(), || {
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().launch_anchor = Some(wrapper.pid());
            });
            for id in [&*moving, moving_launcher] {
                let before = db_state(&db);
                assert_eq!(authenticated_omp_owner(&db, id).unwrap(), owner);
                let error = bind_omp_session_to_process(&db, "sid-prior", id).unwrap_err();
                assert!(
                    format!("{error:#}").contains("is live or unreadable"),
                    "{error:#}"
                );
                assert_eq!(db_state(&db), before);
            }
        });
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_resumed_launch_handoff_still_rejects_a_foreign_live_holder() {
        let (db, _dir, owner) = omp_test_db();
        let wrapper = OmpTestChild::spawn();
        let mut foreign = OmpTestChild::spawn();
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        crate::launcher::register_launch_instance(
            &db,
            "luna",
            Some("sid-prior"),
            launcher,
            "omp",
            false,
            None,
            "/tmp/omp-resumed-launch",
        )
        .unwrap();
        assert!(db.set_instance_pid_if_unset("luna", wrapper.pid()).unwrap());
        let foreign_id = format!("omp-{}-foreign", foreign.pid());
        db.set_process_binding(&foreign_id, "sid-prior", "luna")
            .unwrap();
        let before = db_state(&db);
        let error = with_omp_binding_owner(owner.clone(), || {
            OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
                fixture.as_mut().unwrap().launch_anchor = Some(wrapper.pid());
            });
            assert_eq!(authenticated_omp_owner(&db, launcher).unwrap(), owner);
            bind_omp_session_to_process(&db, "sid-prior", launcher).unwrap_err()
        });
        assert!(
            format!("{error:#}").contains("has another live holder"),
            "{error:#}"
        );
        assert_eq!(db_state(&db), before);
        assert!(foreign.0.try_wait().unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_dead_owner_retained_launchers_adopt_canonical_and_move_runtime() {
        let (db, _dir, owner) = omp_test_db();
        let mut historical = OmpTestChild::spawn();
        let historical_owner = OmpOwner {
            pid: historical.pid(),
            incarnation: crate::sys::process::identity(historical.pid()).unwrap(),
        };
        historical.0.kill().unwrap();
        historical.0.wait().unwrap();
        assert!(crate::proctruth::process_gone(historical_owner.pid));
        let moving = format!("omp-{}-moving", owner.pid);
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        let other_launcher = "550e8400-e29b-41d4-a716-446655440001";
        seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
        seed_omp_owner_row(
            &db,
            "yrow",
            Some("sid-new"),
            Some(launcher),
            &historical_owner,
        );
        db.set_process_binding(other_launcher, "sid-new", "yrow")
            .unwrap();
        db.conn()
            .execute(
                "UPDATE instances SET last_event_id = 41, launch_context = ? WHERE name = 'yrow'",
                rusqlite::params![serde_json::json!({"omp_owner": historical_owner}).to_string()],
            )
            .unwrap();
        for (name, kind, port) in [
            ("xrow", "pty", 54_341),
            ("xrow", "plugin", 54_342),
            ("yrow", "inject", 54_343),
        ] {
            db.upsert_notify_endpoint(name, kind, port).unwrap();
        }
        let result = with_omp_binding_owner(owner.clone(), || {
            crate::proctruth::with_omp_carrier_presence(
                crate::proctruth::OmpCarrierPresence::Absent,
                || bind_omp_session_to_process(&db, "sid-new", &moving),
            )
        })
        .unwrap();
        assert_eq!(result.as_deref(), Some("yrow"));
        assert_omp_pin(&db, "yrow", &owner);
        assert_released_session(
            &db,
            "xrow",
            "sid-old",
            17,
            "/tmp/omp-binding-transcript.jsonl",
        );
        assert_eq!(db.get_session_binding("sid-old").unwrap(), None);
        assert_eq!(
            db.get_session_binding("sid-new").unwrap().as_deref(),
            Some("yrow")
        );
        for id in [&*moving, launcher, other_launcher] {
            assert_eq!(
                db.get_process_binding_full(id).unwrap(),
                Some((Some("sid-new".into()), "yrow".into()))
            );
        }
        let row = db.get_instance_full("yrow").unwrap().unwrap();
        assert_eq!(row.session_id.as_deref(), Some("sid-new"));
        assert_eq!(row.last_event_id, 41);
        assert_eq!(omp_launch_context(&row).unwrap()["pane_id"], "xrow-pane");
        assert_eq!(
            endpoint_rows(db.conn()),
            vec![
                ("yrow".into(), "inject".into(), 54_343),
                ("yrow".into(), "plugin".into(), 54_342),
                ("yrow".into(), "pty".into(), 54_341),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_retained_launcher_live_native_owner_refuses_without_mutation() {
        let (db, _dir, owner) = omp_test_db();
        let mut foreign = OmpTestChild::spawn();
        let foreign_owner = OmpOwner {
            pid: foreign.pid(),
            incarnation: crate::sys::process::identity(foreign.pid()).unwrap(),
        };
        let moving = format!("omp-{}-moving", owner.pid);
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
        seed_omp_owner_row(&db, "yrow", Some("sid-new"), Some(launcher), &foreign_owner);
        db.upsert_notify_endpoint("xrow", "pty", 54_351).unwrap();
        db.upsert_notify_endpoint("yrow", "plugin", 54_352).unwrap();
        assert!(!crate::proctruth::process_gone(foreign_owner.pid));
        let before = db_state(&db);
        let error = with_omp_binding_owner(owner, || {
            crate::proctruth::with_omp_carrier_presence(
                crate::proctruth::OmpCarrierPresence::Absent,
                || bind_omp_session_to_process(&db, "sid-new", &moving).unwrap_err(),
            )
        });
        assert!(
            format!("{error:#}").contains("belongs to another live owner"),
            "{error:#}"
        );
        assert_eq!(db_state(&db), before);
        assert!(foreign.0.try_wait().unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_dead_owner_retained_launcher_unknown_carriers_preserve_complete_state() {
        let (db, _dir, owner) = omp_test_db();
        let mut historical = OmpTestChild::spawn();
        let historical_owner = OmpOwner {
            pid: historical.pid(),
            incarnation: crate::sys::process::identity(historical.pid()).unwrap(),
        };
        historical.0.kill().unwrap();
        historical.0.wait().unwrap();
        assert!(crate::proctruth::process_gone(historical_owner.pid));
        let moving = format!("omp-{}-moving", owner.pid);
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
        seed_omp_owner_row(
            &db,
            "yrow",
            Some("sid-new"),
            Some(launcher),
            &historical_owner,
        );
        db.upsert_notify_endpoint("xrow", "pty", 54_361).unwrap();
        db.upsert_notify_endpoint("yrow", "plugin", 54_362).unwrap();
        let before = db_state(&db);
        let error = with_omp_binding_owner(owner, || {
            crate::proctruth::with_omp_carrier_presence(
                crate::proctruth::OmpCarrierPresence::Unknown,
                || bind_omp_session_to_process(&db, "sid-new", &moving).unwrap_err(),
            )
        });
        assert!(
            format!("{error:#}").contains("has another live holder"),
            "{error:#}"
        );
        assert_eq!(db_state(&db), before);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_dead_owner_retained_launcher_live_exact_carriers_preserve_complete_state() {
        for (carrier_name, carrier_id) in [
            ("yrow", ""),
            ("another-row", "550e8400-e29b-41d4-a716-446655440000"),
        ] {
            let (db, _dir, owner) = omp_test_db();
            let mut historical = OmpTestChild::spawn();
            let historical_owner = OmpOwner {
                pid: historical.pid(),
                incarnation: crate::sys::process::identity(historical.pid()).unwrap(),
            };
            historical.0.kill().unwrap();
            historical.0.wait().unwrap();
            assert!(crate::proctruth::process_gone(historical_owner.pid));
            let moving = format!("omp-{}-moving", owner.pid);
            let launcher = "550e8400-e29b-41d4-a716-446655440000";
            seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
            seed_omp_owner_row(
                &db,
                "yrow",
                Some("sid-new"),
                Some(launcher),
                &historical_owner,
            );
            let mut carrier = OmpTestChild(
                std::process::Command::new("sleep")
                    .arg("60")
                    .env("HCOM_INSTANCE_NAME", carrier_name)
                    .env("HCOM_PROCESS_ID", carrier_id)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let before = db_state(&db);
            let error = with_omp_binding_owner(owner, || {
                crate::proctruth::with_omp_carrier_presence(
                    crate::proctruth::OmpCarrierPresence::Present,
                    || bind_omp_session_to_process(&db, "sid-new", &moving).unwrap_err(),
                )
            });
            assert!(
                format!("{error:#}").contains("has another live holder"),
                "{error:#}"
            );
            assert_eq!(db_state(&db), before);
            assert!(carrier.0.try_wait().unwrap().is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_dead_owner_retained_launcher_pin_failure_rolls_back_the_complete_switch() {
        let (db, _dir, owner) = omp_test_db();
        let mut historical = OmpTestChild::spawn();
        let historical_owner = OmpOwner {
            pid: historical.pid(),
            incarnation: crate::sys::process::identity(historical.pid()).unwrap(),
        };
        historical.0.kill().unwrap();
        historical.0.wait().unwrap();
        assert!(crate::proctruth::process_gone(historical_owner.pid));
        let moving = format!("omp-{}-moving", owner.pid);
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
        seed_omp_owner_row(
            &db,
            "yrow",
            Some("sid-new"),
            Some(launcher),
            &historical_owner,
        );
        db.conn()
            .execute(
                "UPDATE instances SET last_event_id = 41 WHERE name = 'yrow'",
                [],
            )
            .unwrap();
        db.upsert_notify_endpoint("xrow", "pty", 54_371).unwrap();
        db.upsert_notify_endpoint("yrow", "plugin", 54_372).unwrap();
        // PID migration occurs while xrow still exists. Only the final owner
        // pin runs after its release, so this cannot pass on an earlier error.
        db.conn()
            .execute_batch(
                "CREATE TRIGGER refuse_retained_launcher_pin BEFORE UPDATE OF pid ON instances
                 WHEN NEW.name = 'yrow' AND NOT EXISTS
                      (SELECT 1 FROM instances WHERE name = 'xrow')
                 BEGIN SELECT RAISE(ABORT, 'pr127 retained launcher final pin refused'); END;",
            )
            .unwrap();
        let before = db_state(&db);
        let error = with_omp_binding_owner(owner, || {
            crate::proctruth::with_omp_carrier_presence(
                crate::proctruth::OmpCarrierPresence::Absent,
                || bind_omp_session_to_process(&db, "sid-new", &moving).unwrap_err(),
            )
        });
        assert!(
            format!("{error:#}").contains("pr127 retained launcher final pin refused"),
            "{error:#}"
        );
        assert_eq!(db_state(&db), before);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_retained_binding_release_requires_complete_dead_native_owner_evidence() {
        for case in [
            "missing-stamp",
            "malformed-context",
            "malformed-stamp",
            "partial-stamp",
            "missing-pid",
            "mismatched-pid",
            "reused-live-pid",
            "opaque-id",
            "additional-live-holder",
        ] {
            let (db, _dir, owner) = omp_test_db();
            let mut historical = OmpTestChild::spawn();
            let historical_owner = OmpOwner {
                pid: historical.pid(),
                incarnation: crate::sys::process::identity(historical.pid()).unwrap(),
            };
            historical.0.kill().unwrap();
            historical.0.wait().unwrap();
            assert!(crate::proctruth::process_gone(historical_owner.pid));
            let mut foreign = OmpTestChild::spawn();
            let moving = format!("omp-{}-moving", owner.pid);
            let retained = if case == "opaque-id" {
                "opaque-retained-id"
            } else {
                "550e8400-e29b-41d4-a716-446655440000"
            };
            seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
            seed_omp_owner_row(
                &db,
                "yrow",
                Some("sid-new"),
                Some(retained),
                &historical_owner,
            );
            let context = match case {
                "missing-stamp" => Some("{}".to_string()),
                "malformed-context" => Some("{malformed".to_string()),
                "malformed-stamp" => Some(r#"{"omp_owner":null}"#.to_string()),
                "partial-stamp" => Some(
                    serde_json::json!({"omp_owner": {"pid": historical_owner.pid}}).to_string(),
                ),
                "reused-live-pid" => Some(
                    serde_json::json!({"omp_owner": {
                        "pid": foreign.pid(), "incarnation": "prior-native-incarnation",
                    }})
                    .to_string(),
                ),
                _ => None,
            };
            if let Some(context) = context {
                db.conn()
                    .execute(
                        "UPDATE instances SET launch_context = ? WHERE name = 'yrow'",
                        rusqlite::params![context],
                    )
                    .unwrap();
            }
            match case {
                "missing-pid" => {
                    db.conn()
                        .execute("UPDATE instances SET pid = NULL WHERE name = 'yrow'", [])
                        .unwrap();
                }
                "mismatched-pid" | "reused-live-pid" => {
                    db.conn()
                        .execute(
                            "UPDATE instances SET pid = ? WHERE name = 'yrow'",
                            rusqlite::params![i64::from(foreign.pid())],
                        )
                        .unwrap();
                }
                "additional-live-holder" => {
                    db.set_process_binding(
                        &format!("omp-{}-foreign", foreign.pid()),
                        "sid-new",
                        "yrow",
                    )
                    .unwrap();
                }
                _ => {}
            }
            let before = db_state(&db);
            with_omp_binding_owner(owner.clone(), || {
                crate::proctruth::with_omp_carrier_presence(
                    crate::proctruth::OmpCarrierPresence::Absent,
                    || {
                        let held = held_by_another_live_process(&db, "yrow", &moving, Some(&owner));
                        if matches!(
                            case,
                            "malformed-context"
                                | "malformed-stamp"
                                | "partial-stamp"
                                | "missing-pid"
                                | "mismatched-pid"
                        ) {
                            assert!(held.is_err(), "{case}");
                        } else {
                            assert!(held.unwrap(), "{case}");
                        }
                        assert!(
                            bind_omp_session_to_process(&db, "sid-new", &moving).is_err(),
                            "{case}"
                        );
                    },
                );
            });
            assert_eq!(db_state(&db), before, "{case}");
            assert!(foreign.0.try_wait().unwrap().is_none(), "{case}");
        }
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn pr127_dead_owner_retained_launcher_checked_native_platform_contract() {
        let (db, _dir, mut owner) = omp_test_db();
        // The checked probe reads native facts directly, not the binding-owner
        // seam. Give the authenticated moving owner its real incarnation.
        owner.incarnation = crate::sys::process::identity(owner.pid).unwrap();
        let mut historical = OmpTestChild::spawn();
        let historical_owner = OmpOwner {
            pid: historical.pid(),
            incarnation: crate::sys::process::identity(historical.pid()).unwrap(),
        };
        historical.0.kill().unwrap();
        historical.0.wait().unwrap();
        assert!(crate::proctruth::process_gone(historical_owner.pid));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let (_unrelated_dir, mut unrelated) =
            omp_carrier_probe_test_child("pr127-native-unrelated", "pr127-native-unrelated-id");
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let mut unrelated = OmpTestChild::spawn();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let owner_status =
                std::fs::read_to_string(format!("/proc/{}/status", owner.pid)).unwrap();
            let unrelated_status =
                std::fs::read_to_string(format!("/proc/{}/status", unrelated.pid())).unwrap();
            assert_eq!(
                owner_status
                    .lines()
                    .find(|line| line.starts_with("Uid:"))
                    .unwrap(),
                unrelated_status
                    .lines()
                    .find(|line| line.starts_with("Uid:"))
                    .unwrap()
            );
            assert!(crate::proctruth::carrier_eligible(unrelated.pid()));
            let environment = std::fs::read(format!("/proc/{}/environ", unrelated.pid())).unwrap();
            assert!(
                environment
                    .split(|byte| *byte == 0)
                    .any(|entry| entry == b"HCOM_INSTANCE_NAME=pr127-native-unrelated")
            );
            assert!(
                environment
                    .split(|byte| *byte == 0)
                    .any(|entry| entry == b"HCOM_PROCESS_ID=pr127-native-unrelated-id")
            );
        }
        let moving = format!("omp-{}-native-moving", owner.pid);
        let launcher = "13712700-0000-4000-8000-000000000127";
        let source = "pr127-native-source";
        let target = "pr127-native-target";
        seed_omp_owner_row(&db, source, Some("sid-native-old"), Some(&moving), &owner);
        seed_omp_owner_row(
            &db,
            target,
            Some("sid-native-new"),
            Some(launcher),
            &historical_owner,
        );
        db.conn()
            .execute(
                "UPDATE instances SET last_event_id = 41 WHERE name = ?",
                rusqlite::params![target],
            )
            .unwrap();
        db.upsert_notify_endpoint(source, "pty", 54_381).unwrap();
        db.upsert_notify_endpoint(target, "plugin", 54_382).unwrap();
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let before = db_state(&db);
        with_omp_binding_owner(owner.clone(), || {
            assert_eq!(authenticated_omp_owner(&db, &moving).unwrap(), owner);
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                let fixture = crate::proctruth::OmpCarrierProbeFixture {
                    candidates: vec![owner.pid, historical_owner.pid, unrelated.pid()],
                    environment_permission_denied_pid: None,
                };
                crate::proctruth::with_omp_carrier_probe_fixture(fixture, || {
                    // Both calls share candidate IO, never a final observation override.
                    let presence = crate::proctruth::omp_carrier_presence(
                        target,
                        &[launcher.to_string()],
                        &owner,
                    );
                    assert_eq!(presence, crate::proctruth::OmpCarrierPresence::Absent);
                    assert_eq!(
                        bind_omp_session_to_process(&db, "sid-native-new", &moving)
                            .unwrap()
                            .as_deref(),
                        Some(target)
                    );
                    assert_omp_pin(&db, target, &owner);
                    assert_released_session(
                        &db,
                        source,
                        "sid-native-old",
                        17,
                        "/tmp/omp-binding-transcript.jsonl",
                    );
                    assert_eq!(db.get_session_binding("sid-native-old").unwrap(), None);
                    assert_eq!(
                        db.get_session_binding("sid-native-new").unwrap().as_deref(),
                        Some(target)
                    );
                    for id in [&*moving, launcher] {
                        assert_eq!(
                            db.get_process_binding_full(id).unwrap(),
                            Some((Some("sid-native-new".into()), target.into()))
                        );
                    }
                    let row = db.get_instance_full(target).unwrap().unwrap();
                    assert_eq!(row.session_id.as_deref(), Some("sid-native-new"));
                    assert_eq!(row.last_event_id, 41);
                    assert_eq!(
                        endpoint_rows(db.conn()),
                        vec![
                            (target.into(), "plugin".into(), 54_382),
                            (target.into(), "pty".into(), 54_381),
                        ]
                    );
                });
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                assert_eq!(
                    crate::proctruth::omp_carrier_presence(target, &[launcher.to_string()], &owner),
                    crate::proctruth::OmpCarrierPresence::Unknown
                );
                let error =
                    bind_omp_session_to_process(&db, "sid-native-new", &moving).unwrap_err();
                assert!(
                    format!("{error:#}").contains("has another live holder"),
                    "{error:#}"
                );
                assert_eq!(db_state(&db), before);
            }
        });
        assert!(unrelated.0.try_wait().unwrap().is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[serial]
    fn pr127_dead_owner_retained_launcher_native_environment_permission_denied_preserves_complete_state()
     {
        let (db, _dir, mut owner) = omp_test_db();
        owner.incarnation = crate::sys::process::identity(owner.pid).unwrap();
        let mut historical = OmpTestChild::spawn();
        let historical_owner = OmpOwner {
            pid: historical.pid(),
            incarnation: crate::sys::process::identity(historical.pid()).unwrap(),
        };
        historical.0.kill().unwrap();
        historical.0.wait().unwrap();
        assert!(crate::proctruth::process_gone(historical_owner.pid));
        let (_unrelated_dir, mut unrelated) = omp_carrier_probe_test_child(
            "pr127-native-eacces-unrelated",
            "pr127-native-eacces-unrelated-id",
        );
        let owner_status = std::fs::read_to_string(format!("/proc/{}/status", owner.pid)).unwrap();
        let unrelated_status =
            std::fs::read_to_string(format!("/proc/{}/status", unrelated.pid())).unwrap();
        assert_eq!(
            owner_status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .unwrap(),
            unrelated_status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .unwrap()
        );
        assert!(crate::proctruth::carrier_eligible(unrelated.pid()));
        let moving = format!("omp-{}-native-eacces-moving", owner.pid);
        let launcher = "13712700-0000-4000-8000-000000000128";
        let source = "pr127-native-eacces-source";
        let target = "pr127-native-eacces-target";
        seed_omp_owner_row(&db, source, Some("sid-eacces-old"), Some(&moving), &owner);
        seed_omp_owner_row(
            &db,
            target,
            Some("sid-eacces-new"),
            Some(launcher),
            &historical_owner,
        );
        db.upsert_notify_endpoint(source, "pty", 54_391).unwrap();
        db.upsert_notify_endpoint(target, "plugin", 54_392).unwrap();
        let before = db_state(&db);
        with_omp_binding_owner(owner.clone(), || {
            assert_eq!(authenticated_omp_owner(&db, &moving).unwrap(), owner);
            crate::proctruth::with_omp_carrier_probe_fixture(
                crate::proctruth::OmpCarrierProbeFixture {
                    candidates: vec![owner.pid, historical_owner.pid, unrelated.pid()],
                    environment_permission_denied_pid: None,
                },
                || {
                    assert_eq!(
                        crate::proctruth::omp_carrier_presence(
                            target,
                            &[launcher.to_string()],
                            &owner,
                        ),
                        crate::proctruth::OmpCarrierPresence::Absent
                    );
                },
            );
            crate::proctruth::with_omp_carrier_probe_fixture(
                crate::proctruth::OmpCarrierProbeFixture {
                    candidates: vec![owner.pid, historical_owner.pid, unrelated.pid()],
                    environment_permission_denied_pid: Some(unrelated.pid()),
                },
                || {
                    assert_eq!(
                        crate::proctruth::omp_carrier_presence(
                            target,
                            &[launcher.to_string()],
                            &owner,
                        ),
                        crate::proctruth::OmpCarrierPresence::Unknown
                    );
                    let error =
                        bind_omp_session_to_process(&db, "sid-eacces-new", &moving).unwrap_err();
                    assert!(
                        format!("{error:#}").contains("has another live holder"),
                        "{error:#}"
                    );
                    assert_eq!(db_state(&db), before);
                },
            );
        });
        assert_eq!(db_state(&db), before);
        assert!(unrelated.0.try_wait().unwrap().is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[serial]
    fn pr127_dead_owner_retained_minted_alias_live_native_carrier_refuses() {
        let (db, _dir, mut owner) = omp_test_db();
        owner.incarnation = crate::sys::process::identity(owner.pid).unwrap();
        let mut historical = OmpTestChild::spawn();
        let historical_owner = OmpOwner {
            pid: historical.pid(),
            incarnation: crate::sys::process::identity(historical.pid()).unwrap(),
        };
        let moving = format!("omp-{}-native-alias-moving", owner.pid);
        let old_alias = format!("omp-{}-retained-alias", historical_owner.pid);
        let launcher = "13712700-0000-4000-8000-000000000129";
        let other_launcher = "13712700-0000-4000-8000-000000000130";
        let source = "pr127-native-alias-source";
        let target = "pr127-native-alias-target";
        seed_omp_owner_row(&db, source, Some("sid-alias-old"), Some(&moving), &owner);
        seed_omp_owner_row(
            &db,
            target,
            Some("sid-alias-new"),
            Some(launcher),
            &historical_owner,
        );
        db.set_process_binding(other_launcher, "sid-alias-new", target)
            .unwrap();
        db.set_process_binding(&old_alias, "sid-alias-new", target)
            .unwrap();
        historical.0.kill().unwrap();
        historical.0.wait().unwrap();
        assert!(crate::proctruth::process_gone(historical_owner.pid));
        let (_carrier_dir, mut carrier) = omp_carrier_probe_test_child("", &old_alias);
        assert_ne!(carrier.pid(), owner.pid);
        assert_ne!(carrier.pid(), historical_owner.pid);
        let carrier_incarnation = crate::sys::process::identity(carrier.pid()).unwrap();
        let owner_status = std::fs::read_to_string(format!("/proc/{}/status", owner.pid)).unwrap();
        let carrier_status =
            std::fs::read_to_string(format!("/proc/{}/status", carrier.pid())).unwrap();
        assert_eq!(
            owner_status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .unwrap(),
            carrier_status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .unwrap()
        );
        assert!(crate::proctruth::carrier_eligible(carrier.pid()));
        let environment = std::fs::read(format!("/proc/{}/environ", carrier.pid())).unwrap();
        assert!(
            environment
                .split(|byte| *byte == 0)
                .any(|entry| entry == b"HCOM_INSTANCE_NAME=")
        );
        let alias_entry = format!("HCOM_PROCESS_ID={old_alias}");
        assert!(
            environment
                .split(|byte| *byte == 0)
                .any(|entry| entry == alias_entry.as_bytes())
        );
        db.upsert_notify_endpoint(source, "pty", 54_401).unwrap();
        db.upsert_notify_endpoint(target, "plugin", 54_402).unwrap();
        let retained_ids = db
            .process_binding_ids(target)
            .unwrap()
            .into_iter()
            .filter(|id| id != &moving)
            .collect::<Vec<_>>();
        let before = db_state(&db);
        let fixture = crate::proctruth::OmpCarrierProbeFixture {
            candidates: vec![owner.pid, historical_owner.pid, carrier.pid()],
            environment_permission_denied_pid: None,
        };
        crate::proctruth::with_omp_carrier_probe_fixture(fixture, || {
            with_omp_binding_owner(owner.clone(), || {
                assert_eq!(authenticated_omp_owner(&db, &moving).unwrap(), owner);
                assert_eq!(
                    crate::proctruth::omp_carrier_presence(target, &retained_ids, &owner),
                    crate::proctruth::OmpCarrierPresence::Present
                );
                let error = bind_omp_session_to_process(&db, "sid-alias-new", &moving)
                    .expect_err("a live retained minted-alias carrier must prevent adoption");
                assert!(
                    format!("{error:#}").contains("has another live holder"),
                    "{error:#}"
                );
                assert_eq!(db_state(&db), before);
                assert!(carrier.0.try_wait().unwrap().is_none());
                assert_eq!(
                    crate::sys::process::identity(carrier.pid()).as_deref(),
                    Some(carrier_incarnation.as_str())
                );

                carrier.0.kill().unwrap();
                carrier.0.wait().unwrap();
                assert!(crate::proctruth::process_gone(carrier.pid()));
                assert_eq!(
                    crate::proctruth::omp_carrier_presence(target, &retained_ids, &owner),
                    crate::proctruth::OmpCarrierPresence::Absent
                );
                assert_eq!(
                    bind_omp_session_to_process(&db, "sid-alias-new", &moving)
                        .unwrap()
                        .as_deref(),
                    Some(target)
                );
                assert_omp_pin(&db, target, &owner);
                assert_released_session(
                    &db,
                    source,
                    "sid-alias-old",
                    17,
                    "/tmp/omp-binding-transcript.jsonl",
                );
                assert_eq!(db.get_session_binding("sid-alias-old").unwrap(), None);
                assert_eq!(
                    db.get_session_binding("sid-alias-new").unwrap().as_deref(),
                    Some(target)
                );
                for id in [&*moving, launcher, other_launcher, &*old_alias] {
                    assert_eq!(
                        db.get_process_binding_full(id).unwrap(),
                        Some((Some("sid-alias-new".into()), target.into()))
                    );
                }
                let row = db.get_instance_full(target).unwrap().unwrap();
                assert_eq!(row.session_id.as_deref(), Some("sid-alias-new"));
                assert_eq!(row.last_event_id, 17);
                let endpoints = endpoint_rows(db.conn());
                assert_eq!(
                    endpoints,
                    vec![
                        (target.into(), "plugin".into(), 54_402),
                        (target.into(), "pty".into(), 54_401),
                    ]
                );
                let mut expected_ids = [&*moving, launcher, other_launcher, &*old_alias];
                expected_ids.sort_unstable();
                let mut actual_ids = db.process_binding_ids(target).unwrap();
                actual_ids.sort_unstable();
                assert!(
                    actual_ids.iter().map(String::as_str).eq(expected_ids),
                    "{actual_ids:?}"
                );

                let unmapped = format!("omp-{}-native-alias-unbound", owner.pid);
                assert_eq!(db.get_process_binding_full(&unmapped).unwrap(), None);
                assert_eq!(authenticated_omp_owner(&db, &unmapped).unwrap(), owner);
                let before_unmapped = db_state(&db);
                let error = bind_omp_session_to_process(&db, "sid-alias-new", &unmapped)
                    .expect_err("an unmapped same-owner minted ID must not reuse retained UUIDs");
                assert!(
                    format!("{error:#}").contains("has another live holder"),
                    "{error:#}"
                );
                assert_eq!(db_state(&db), before_unmapped);

                assert_eq!(
                    bind_omp_session_to_process(&db, "sid-alias-new", &moving)
                        .expect("same-session replay must retain the adopted canonical identity")
                        .as_deref(),
                    Some(target)
                );
                assert_omp_pin(&db, target, &owner);
                assert_eq!(
                    db.get_session_binding("sid-alias-new").unwrap().as_deref(),
                    Some(target)
                );
                for id in [&*moving, launcher, other_launcher, &*old_alias] {
                    assert_eq!(
                        db.get_process_binding_full(id).unwrap(),
                        Some((Some("sid-alias-new".into()), target.into()))
                    );
                }
                let replayed = db.get_instance_full(target).unwrap().unwrap();
                assert_eq!(replayed.session_id.as_deref(), Some("sid-alias-new"));
                assert_eq!(replayed.last_event_id, row.last_event_id);
                assert_eq!(replayed.transcript_path, row.transcript_path);
                assert_eq!(replayed.directory, row.directory);
                assert_eq!(
                    omp_launch_context(&replayed).unwrap(),
                    omp_launch_context(&row).unwrap()
                );
                assert_eq!(endpoint_rows(db.conn()), endpoints);
                let mut actual_ids = db.process_binding_ids(target).unwrap();
                actual_ids.sort_unstable();
                assert!(
                    actual_ids.iter().map(String::as_str).eq(expected_ids),
                    "{actual_ids:?}"
                );

                let fresh_session = "sid-alias-branch";
                assert_eq!(db.get_session_binding(fresh_session).unwrap(), None);
                assert!(
                    db.find_stopped_snapshot_by_session_id(fresh_session)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    bind_omp_session_to_process(&db, fresh_session, &moving)
                        .expect("a fresh session branch must reuse the adopted canonical identity")
                        .as_deref(),
                    Some(target)
                );
                assert_omp_pin(&db, target, &owner);
                assert_eq!(
                    db.get_session_binding(fresh_session).unwrap().as_deref(),
                    Some(target)
                );
                assert_eq!(db.get_session_binding("sid-alias-new").unwrap(), None);
                assert_eq!(
                    db.get_process_binding_full(&moving).unwrap(),
                    Some((Some(fresh_session.into()), target.into()))
                );
                for id in [launcher, other_launcher, &*old_alias] {
                    assert_eq!(db.get_process_binding(id).unwrap().as_deref(), Some(target));
                }
                let branched = db.get_instance_full(target).unwrap().unwrap();
                assert_eq!(branched.session_id.as_deref(), Some(fresh_session));
                assert_eq!(branched.last_event_id, row.last_event_id);
                assert_eq!(branched.transcript_path, row.transcript_path);
                assert_eq!(branched.directory, row.directory);
                assert_eq!(
                    omp_launch_context(&branched).unwrap(),
                    omp_launch_context(&row).unwrap()
                );
                assert_eq!(endpoint_rows(db.conn()), endpoints);
                let mut actual_ids = db.process_binding_ids(target).unwrap();
                actual_ids.sort_unstable();
                assert!(
                    actual_ids.iter().map(String::as_str).eq(expected_ids),
                    "{actual_ids:?}"
                );
            });
        });
    }

    fn expire_omp_owner_before_commit(_db: &HcomDb, _name: &str) {
        OMP_BINDING_OWNER_FIXTURE.with_borrow_mut(|fixture| {
            fixture.as_mut().unwrap().incarnation = None;
        });
    }

    #[test]
    #[serial]
    fn omp_create_auth_pin_binding_and_event_failure_leave_no_partial_identity() {
        for trigger in [
            "CREATE TRIGGER fail_omp_binding BEFORE INSERT ON process_bindings
             BEGIN SELECT RAISE(ABORT, 'process binding refused'); END;",
            "CREATE TRIGGER fail_omp_pin BEFORE UPDATE OF launch_context ON instances
             WHEN json_extract(NEW.launch_context, '$.omp_owner.pid') IS NOT NULL
             BEGIN SELECT RAISE(ABORT, 'owner pin refused'); END;",
            "CREATE TRIGGER fail_omp_created BEFORE INSERT ON events
             WHEN NEW.type = 'life' AND json_extract(NEW.data, '$.action') = 'created'
             BEGIN SELECT RAISE(ABORT, 'created event refused'); END;",
        ] {
            let (db, _dir, owner) = omp_test_db();
            let id = format!("omp-{}-new", owner.pid);
            db.conn().execute_batch(trigger).unwrap();
            let before = db_state(&db);
            with_omp_binding_owner(owner, || {
                assert!(create_omp_identity(&db, "sid-new", &id).is_err());
            });
            assert_eq!(db_state(&db), before);
            assert_eq!(db.get_process_binding(&id).unwrap(), None);
            assert_eq!(db.get_session_binding("sid-new").unwrap(), None);
        }
        for late_failure in [false, true] {
            let (db, _dir, owner) = omp_test_db();
            let id = format!("omp-{}-new", owner.pid);
            let before = db_state(&db);
            with_omp_binding_owner(owner, || {
                if late_failure {
                    OMP_OWNER_COMMIT_GAP_HOOK.with(|hook| {
                        hook.set(Some(expire_omp_owner_before_commit));
                    });
                } else {
                    expire_omp_owner_before_commit(&db, "");
                }
                assert!(create_omp_identity(&db, "sid-new", &id).is_err());
            });
            assert_eq!(db_state(&db), before);
        }
    }

    #[test]
    #[serial]
    fn omp_creator_refuses_existing_mapping_canonical_restore_and_unreadable_sql() {
        let (db, _dir, owner) = omp_test_db();
        let mapped = format!("omp-{}-mapped", owner.pid);
        let fresh = format!("omp-{}-fresh", owner.pid);
        seed_omp_owner_row(&db, "luna", Some("sid-existing"), Some(&mapped), &owner);
        with_omp_binding_owner(owner.clone(), || {
            let before = db_state(&db);
            assert!(create_omp_identity(&db, "sid-new", &mapped).is_err());
            assert!(create_omp_identity(&db, "sid-existing", &fresh).is_err());
            assert_eq!(db_state(&db), before);
            db.log_life_event(
                "prior",
                "stopped",
                "test",
                "exit",
                Some(serde_json::json!({"tool":"omp", "session_id":"sid-stopped"})),
                None,
            )
            .unwrap();
            let before = db_state(&db);
            assert!(create_omp_identity(&db, "sid-stopped", &fresh).is_err());
            assert_eq!(db_state(&db), before);
        });
        db.conn()
            .execute_batch("DROP TABLE process_bindings;")
            .unwrap();
        with_omp_binding_owner(owner, || {
            let before = db_state(&db);
            assert!(authenticated_omp_owner(&db, &fresh).is_err());
            assert!(bind_omp_session_to_process(&db, "sid-new", &fresh).is_err());
            assert!(create_omp_identity(&db, "sid-new", &fresh).is_err());
            assert_eq!(db_state(&db), before);
        });
    }

    #[test]
    #[serial]
    fn omp_failed_switch_pin_rolls_back_cursor_endpoints_release_and_wakes() {
        let (db, _dir, owner) = omp_test_db();
        let moving = format!("omp-{}-moving", owner.pid);
        let duplicate = format!("omp-{}-duplicate", owner.pid);
        seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
        seed_omp_owner_row(&db, "yrow", Some("sid-new"), None, &owner);
        db.set_process_binding(&duplicate, "sid-old", "xrow")
            .unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        db.upsert_notify_endpoint("xrow", "pty", listener.local_addr().unwrap().port())
            .unwrap();
        db.conn().execute_batch(
            "CREATE TRIGGER fail_switch_pin BEFORE UPDATE OF launch_context ON instances
             WHEN NEW.name = 'yrow' AND json_extract(NEW.launch_context, '$.omp_owner.pid') IS NOT NULL
             BEGIN SELECT RAISE(ABORT, 'switch pin refused'); END;",
        ).unwrap();
        let before = db_state(&db);
        with_omp_binding_owner(owner, || {
            assert!(bind_omp_session_to_process(&db, "sid-new", &moving).is_err());
        });
        assert_eq!(db_state(&db), before);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    #[serial]
    fn omp_duplicate_switch_late_failure_restores_poisoned_rows() {
        let (db, _dir, owner) = omp_test_db();
        let moving = format!("omp-{}-moving", owner.pid);
        let duplicate = format!("omp-{}-duplicate", owner.pid);
        seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
        seed_omp_owner_row(&db, "yrow", Some("sid-new"), None, &owner);
        db.conn()
            .execute_batch(
                "UPDATE instances SET session_id = NULL WHERE name = 'yrow';
                 UPDATE instances SET session_id = 'sid-new' WHERE name = 'xrow';",
            )
            .unwrap();
        db.set_process_binding(&duplicate, "sid-old", "xrow")
            .unwrap();
        db.upsert_notify_endpoint("xrow", "pty", 54_321).unwrap();
        db.upsert_notify_endpoint("yrow", "plugin", 54_322).unwrap();
        db.conn()
            .execute_batch(
                "CREATE TRIGGER fail_poisoned_switch_pin
                 BEFORE UPDATE OF launch_context ON instances WHEN NEW.name = 'yrow'
                 BEGIN SELECT RAISE(ABORT, 'poisoned switch later write refused'); END;",
            )
            .unwrap();
        let before = db_state(&db);
        let error = with_omp_binding_owner(owner, || {
            bind_omp_session_to_process(&db, "sid-new", &moving).unwrap_err()
        });
        assert!(
            error
                .to_string()
                .contains("poisoned switch later write refused"),
            "{error:#}",
        );
        assert_eq!(db_state(&db), before);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn omp_foreign_live_holder_preserves_displaced_state_and_blocks_canonical_takeover() {
        let (db, _dir, owner) = omp_test_db();
        let mut foreign = OmpTestChild::spawn();
        let moving = format!("omp-{}-moving", owner.pid);
        let foreign_id = format!("omp-{}-foreign-source", foreign.pid());
        seed_omp_owner_row(&db, "xrow", Some("sid-old"), Some(&moving), &owner);
        seed_omp_owner_row(&db, "yrow", Some("sid-new"), None, &owner);
        db.set_process_binding(&foreign_id, "sid-old", "xrow")
            .unwrap();
        db.upsert_notify_endpoint("xrow", "plugin", 54_251).unwrap();
        with_omp_binding_owner(owner.clone(), || {
            assert_eq!(
                bind_omp_session_to_process(&db, "sid-new", &moving)
                    .unwrap()
                    .as_deref(),
                Some("yrow"),
            );
        });
        let xrow = db.get_instance_full("xrow").unwrap().unwrap();
        assert_eq!(xrow.session_id.as_deref(), Some("sid-old"));
        assert_eq!(xrow.last_event_id, 17);
        assert_eq!(
            db.get_process_binding(&foreign_id).unwrap().as_deref(),
            Some("xrow")
        );
        assert_eq!(
            db.get_session_binding("sid-old").unwrap().as_deref(),
            Some("xrow")
        );
        assert_eq!(
            endpoint_rows(db.conn()),
            vec![("xrow".into(), "plugin".into(), 54_251)]
        );
        let foreign_owner = OmpOwner {
            pid: foreign.pid(),
            incarnation: crate::sys::process::identity(foreign.pid()).unwrap(),
        };
        seed_omp_owner_row(&db, "foreign", Some("sid-foreign"), None, &foreign_owner);
        with_omp_binding_owner(owner, || {
            let before = db_state(&db);
            assert!(bind_omp_session_to_process(&db, "sid-foreign", &moving).is_err());
            assert_eq!(db_state(&db), before);
        });
        assert!(
            foreign.0.try_wait().unwrap().is_none(),
            "foreign holder was signalled"
        );
    }

    thread_local! {
        static OMP_COMMIT_OBSERVER: std::cell::RefCell<Option<(Vec<String>, bool)>> =
            const { std::cell::RefCell::new(None) };
    }

    fn observe_omp_identity_before_commit(db: &HcomDb, name: &str) {
        let observer = HcomDb::open_raw(db.path()).unwrap();
        OMP_COMMIT_OBSERVER.set(Some((
            db_state(&observer),
            observer.get_instance_full(name).unwrap().is_some(),
        )));
    }

    #[test]
    #[serial]
    fn omp_creation_row_bindings_pin_and_event_become_visible_together() {
        let (db, _dir, owner) = omp_test_db();
        let id = format!("omp-{}-new", owner.pid);
        let before = db_state(&db);
        let name = with_omp_binding_owner(owner.clone(), || {
            OMP_OWNER_COMMIT_GAP_HOOK.with(|hook| {
                hook.set(Some(observe_omp_identity_before_commit));
            });
            create_omp_identity(&db, "sid-new", &id)
        })
        .unwrap();
        assert_eq!(OMP_COMMIT_OBSERVER.take(), Some((before, false)));
        assert_eq!(
            db.get_process_binding(&id).unwrap().as_deref(),
            Some(name.as_str())
        );
        assert_eq!(
            db.get_session_binding("sid-new").unwrap().as_deref(),
            Some(name.as_str())
        );
        assert_omp_pin(&db, &name, &owner);
        let created: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE instance = ? AND type = 'life'
             AND json_extract(data, '$.action') = 'created'",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(created, 1);
    }

    #[test]
    #[serial]
    fn omp_repair_owner_change_rolls_back_poisoned_metadata_and_bindings() {
        let (db, _dir, owner) = omp_test_db();
        let launcher = "550e8400-e29b-41d4-a716-446655440000";
        seed_omp_owner_row(&db, "luna", Some("sid-poison"), None, &owner);
        db.upsert_notify_endpoint("luna", "plugin", 54_261).unwrap();
        let before = db_state(&db);
        with_omp_binding_owner(owner, || {
            OMP_OWNER_COMMIT_GAP_HOOK.with(|hook| {
                hook.set(Some(expire_omp_owner_before_commit));
            });
            assert!(
                recover_omp_process_binding_for_instance(&db, "luna", "sid-real", launcher,)
                    .is_err()
            );
        });
        assert_eq!(db_state(&db), before);
    }

    #[test]
    #[serial]
    fn omp_canonical_and_restore_targets_reject_generic_unknown_or_missing_ids() {
        let (db, _dir, owner) = omp_test_db();
        seed_omp_owner_row(&db, "luna", Some("sid-existing"), None, &owner);
        db.upsert_notify_endpoint("luna", "plugin", 54_271).unwrap();
        db.log_life_event(
            "prior",
            "stopped",
            "test",
            "exit",
            Some(serde_json::json!({"tool":"omp", "session_id":"sid-stopped"})),
            None,
        )
        .unwrap();
        for session in ["sid-existing", "sid-stopped"] {
            for id in [
                None,
                Some("550e8400-e29b-41d4-a716-446655440000"),
                Some("pid-synthetic"),
            ] {
                let before = db_state(&db);
                assert!(bind_session_to_process(&db, session, id).is_err());
                assert_eq!(db_state(&db), before);
            }
        }
        db.set_process_binding("pid-synthetic", "sid-existing", "luna")
            .unwrap();
        let before = db_state(&db);
        assert!(bind_session_to_process(&db, "sid-fresh", Some("pid-synthetic")).is_err());
        assert_eq!(db_state(&db), before);
    }

    fn change_generic_route_to_omp_target(db: &HcomDb, _session: &str) {
        db.conn()
            .execute("UPDATE instances SET tool = 'omp' WHERE name = 'luna'", [])
            .unwrap();
    }

    #[test]
    #[serial]
    fn generic_bind_rejects_omp_target_discovered_after_initial_routing() {
        let (db, _dir, owner) = omp_test_db();
        seed_omp_owner_row(&db, "luna", Some("sid-existing"), None, &owner);
        db.conn()
            .execute(
                "UPDATE instances SET tool = 'codex' WHERE name = 'luna'",
                [],
            )
            .unwrap();
        let before = db_state(&db);
        GENERIC_BIND_ROUTE_GAP_HOOK.with(|hook| {
            hook.set(Some(change_generic_route_to_omp_target));
        });
        assert!(bind_session_to_process(&db, "sid-existing", None).is_err());
        assert_eq!(db_state(&db), before);
    }

    #[test]
    #[serial]
    fn omp_resolver_requires_current_process_mapping_not_session_metadata() {
        let (db, _dir, owner) = omp_test_db();
        let id = format!("omp-{}-mapped", owner.pid);
        seed_omp_owner_row(&db, "luna", Some("sid-real"), Some(&id), &owner);
        db.upsert_notify_endpoint("luna", "plugin", 54_281).unwrap();
        let before = db_state(&db);
        assert!(resolve_instance_from_binding(&db, Some("sid-real"), None).is_none());
        assert!(
            resolve_instance_from_binding(
                &db,
                Some("sid-real"),
                Some("550e8400-e29b-41d4-a716-446655440000"),
            )
            .is_none()
        );
        with_omp_binding_owner(
            OmpOwner {
                pid: owner.pid.checked_add(1).unwrap(),
                incarnation: "borrowed-child-incarnation".into(),
            },
            || {
                assert!(resolve_instance_from_binding(&db, Some("sid-real"), Some(&id)).is_none());
            },
        );
        with_omp_binding_owner(owner, || {
            let row = resolve_instance_from_binding(&db, Some("sid-real"), Some(&id)).unwrap();
            assert_eq!(row.name, "luna");
            assert_eq!(row.last_event_id, 17);
        });
        assert_eq!(db_state(&db), before);
    }
}
