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
use crate::instances::update_instance_position;
use crate::proctruth::{AncestorProcess, OmpOwnerProof};
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
    let mut ctx = db
        .get_instance_full(instance_name)?
        .and_then(|pos| pos.launch_context)
        .and_then(|json| {
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&json).ok()
        })
        .unwrap_or_default();

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
        serde_json::json!(serde_json::to_string(&ctx).unwrap_or_else(|_| "{}".to_string())),
    );
    db.update_instance_fields(instance_name, &updates)
}

/// Capture environment context and store it for the instance.
///
/// Captures git branch, terminal program, tty, and relevant env vars.
pub fn capture_and_store_launch_context(db: &HcomDb, instance_name: &str) {
    let new_ctx = capture_context();

    // Preserve fields from prior context that can't be recaptured in hook env
    let preserve_keys = [
        "pane_id",
        "terminal_id",
        "kitty_listen_on",
        "process_id",
        "terminal_preset_effective",
    ];
    let mut ctx = new_ctx;

    let missing: Vec<&str> = preserve_keys
        .iter()
        .filter(|k| launch_context_value_missing(ctx.get(**k)))
        .copied()
        .collect();

    if !missing.is_empty()
        && let Ok(Some(pos)) = db.get_instance_full(instance_name)
        && let Some(old_json) = &pos.launch_context
        && let Ok(old_ctx) = serde_json::from_str::<serde_json::Value>(old_json)
    {
        for k in &missing {
            if let Some(val) = old_ctx.get(*k)
                && !launch_context_value_missing(Some(val))
            {
                ctx.insert(k.to_string(), val.clone());
            }
        }
    }

    let json = serde_json::to_string(&ctx).unwrap_or_else(|_| "{}".to_string());
    let mut updates = serde_json::Map::new();
    updates.insert("launch_context".into(), serde_json::json!(json));
    update_instance_position(db, instance_name, &updates);
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
fn capture_context() -> serde_json::Map<String, serde_json::Value> {
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

pub(crate) fn is_true_launch_placeholder(data: Option<&InstanceRow>) -> bool {
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

fn migrate_placeholder_notify(db: &HcomDb, placeholder_name: &str, canonical_name: &str) -> bool {
    match db.migrate_notify_endpoints(placeholder_name, canonical_name) {
        Ok(()) => true,
        Err(e) => {
            crate::log::log_error("binding", "placeholder.migrate_endpoints", &format!("{e}"));
            false
        }
    }
}

/// Delete a true launch placeholder row. Notify endpoints remain on the canonical instance.
fn delete_true_placeholder_instance(db: &HcomDb, placeholder_name: &str) {
    match db.delete_instance(placeholder_name) {
        Ok(true) => {}
        Ok(false) => {
            crate::log::log_info(
                "binding",
                "placeholder.delete_missing",
                &format!("placeholder={placeholder_name}"),
            );
        }
        Err(e) => {
            crate::log::log_error("binding", "placeholder.delete", &format!("{e}"));
        }
    }
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

/// Carry runtime state the PTY wrapper wrote onto the placeholder row over to the
/// canonical instance before the placeholder is deleted. The OS `pid` and terminal
/// `launch_context` (pane_id) are written once at spawn under the launch name
/// (`src/pty/mod.rs`); without migrating them, `hcom kill <canonical>` finds no pid
/// and can't close the terminal pane.
fn migrate_placeholder_runtime_state(
    db: &HcomDb,
    canonical_name: &str,
    placeholder_data: Option<&InstanceRow>,
) {
    let Some(ph) = placeholder_data else {
        return;
    };
    if let Some(pid) = ph.pid
        && let Ok(pid_u32) = u32::try_from(pid)
        && let Err(e) = db.update_instance_pid(canonical_name, pid_u32)
    {
        crate::log::log_error("binding", "placeholder.migrate_pid", &format!("{e}"));
    }
    if let Some(ref ctx) = ph.launch_context
        && let Err(e) = db.store_launch_context(canonical_name, ctx)
    {
        crate::log::log_error(
            "binding",
            "placeholder.migrate_launch_context",
            &format!("{e}"),
        );
    }
    rekey_migrated_terminal(db, canonical_name, ph);
}

/// [`migrate_placeholder_runtime_state`] on the caller's transaction, with no
/// BEGIN of its own. Receipt ownership is re-keyed by the binding caller only
/// after commit via `rekey_migrated_terminal`; rollback must not change files.
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

fn delete_true_placeholder_if_migrated(
    db: &HcomDb,
    placeholder_name: &str,
    canonical_name: &str,
    placeholder_data: Option<&InstanceRow>,
) {
    if is_true_launch_placeholder(placeholder_data) {
        // Move pid/launch_context to the canonical row before dropping the placeholder
        // so the restored agent stays killable and its pane closeable.
        migrate_placeholder_runtime_state(db, canonical_name, placeholder_data);
        delete_true_placeholder_instance(db, placeholder_name);
    }
}

/// Path 2: after restore_stopped bind, merge notify ports and drop the launch
/// placeholder, on the switch's transaction. Best effort: a failed endpoint
/// merge keeps the placeholder, endpoints and all, and the bind still stands.
fn retire_true_placeholder_after_canonical_bind(
    db: &HcomDb,
    tx: &rusqlite::Transaction<'_>,
    placeholder_name: Option<&String>,
    canonical_name: &str,
    placeholder_data: Option<&InstanceRow>,
) {
    let Some(ph_name) = placeholder_name else {
        return;
    };
    if ph_name == canonical_name || !is_true_launch_placeholder(placeholder_data) {
        return;
    }

    if let Err(e) = db.migrate_notify_endpoints_in_txn(tx, ph_name, canonical_name) {
        crate::log::log_error("binding", "placeholder.migrate_endpoints", &format!("{e}"));
        return;
    }

    // Move pid/launch_context to the canonical row before dropping the placeholder
    // so the restored agent stays killable and its pane closeable.
    if let Err(e) =
        migrate_placeholder_runtime_state_in_txn(db, tx, canonical_name, placeholder_data)
    {
        crate::log::log_error(
            "binding",
            "placeholder.migrate_runtime_state",
            &format!("{e}"),
        );
    }
    delete_true_placeholder_instance(db, ph_name);
}

/// Strict retirement for OMP's carrying transaction. Unlike the standalone
/// best-effort path, any migration/deletion failure aborts the owner claim.
fn retire_true_placeholder_after_canonical_bind_in_txn(
    db: &HcomDb,
    tx: &rusqlite::Transaction<'_>,
    placeholder_name: Option<&String>,
    canonical_name: &str,
    placeholder_data: Option<&InstanceRow>,
) -> anyhow::Result<()> {
    let Some(name) = placeholder_name else {
        return Ok(());
    };
    if name == canonical_name || !is_true_launch_placeholder(placeholder_data) {
        return Ok(());
    }
    db.migrate_notify_endpoints_in_txn(tx, name, canonical_name)?;
    migrate_placeholder_runtime_state_in_txn(db, tx, canonical_name, placeholder_data)?;
    anyhow::ensure!(
        db.delete_instance(name)?,
        "OMP launch placeholder disappeared"
    );
    Ok(())
}

/// Whether another live process still holds this row. A stale binding alone
/// cannot keep an abandoned identity alive; a live carrier of that binding can.
fn held_by_another_live_process(
    db: &HcomDb,
    name: &str,
    moving_process_id: &str,
) -> anyhow::Result<bool> {
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
) -> anyhow::Result<Option<(i64, serde_json::Value)>> {
    let Some(row) = db.get_instance_full(displaced_name)? else {
        return Ok(None);
    };
    if row.session_id.is_none()
        || held_by_another_live_process(db, displaced_name, moving_process_id)?
    {
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
fn move_process_off_displaced_row(
    db: &HcomDb,
    tx: &rusqlite::Transaction<'_>,
    displaced_name: &str,
    new_name: &str,
    displaced_data: Option<&InstanceRow>,
    moving_process_id: &str,
) -> anyhow::Result<Option<(i64, serde_json::Value)>> {
    if !held_by_another_live_process(db, displaced_name, moving_process_id)? {
        // The live process and its terminal move with this binding; a shared
        // row still belongs to its holder.
        migrate_placeholder_runtime_state_in_txn(db, tx, new_name, displaced_data)
            .with_context(|| format!("session switch: moving runtime state to '{new_name}'"))?;
        db.migrate_notify_endpoints_in_txn(tx, displaced_name, new_name)
            .with_context(|| format!("session switch: moving notify endpoints to '{new_name}'"))?;
    }
    release_displaced_session_identity(db, tx, displaced_name, moving_process_id)
}

fn notify_session_switch_stop(db: &HcomDb, name: &str, event: Option<(i64, serde_json::Value)>) {
    if let Some((id, data)) = event {
        crate::db::subscriptions::process_logged_event(db, id, "life", name, &data);
    }
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
    caller_tx: Option<&rusqlite::Transaction<'_>>,
    post: &mut PostCommit,
) -> anyhow::Result<()> {
    if db.get_instance_full(target_name)?.is_some() {
        return Ok(());
    }
    let Some(ph) = ph else {
        return Ok(());
    };
    if let Some(tx) = caller_tx
        && let Some(agent_id) = &ph.agent_id
    {
        // The initializer inserts with OR REPLACE. Transfer the UNIQUE agent
        // identity explicitly, never by implicitly deleting the source row
        // (and its endpoints) before the binding migration reaches it.
        let changed = tx.execute(
            "UPDATE instances SET agent_id = NULL
             WHERE name = ?1 AND created_at = ?2 AND agent_id = ?3
               AND pid IS ?4 AND session_id IS ?5",
            rusqlite::params![ph.name, ph.created_at, agent_id, ph.pid, ph.session_id],
        )?;
        anyhow::ensure!(
            changed == 1,
            "OMP placeholder incarnation changed before recreation"
        );
    }
    let initialized = initialize_instance_in_position_file_collected(
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
    );
    anyhow::ensure!(initialized, "could not recreate instance '{target_name}'");
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
    if !initialize_instance_in_position_file_collected(
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
    ) {
        anyhow::bail!("restore_stopped: could not recreate the instance row for '{target_name}'");
    }
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
    /// Between the entry snapshot and BEGIN IMMEDIATE: a deterministic raced
    /// replacement/UUID remap must invalidate the pending claim, and a
    /// mapping that appears before a plain mint must refuse it.
    static OMP_BIND_CLAIM_GAP_HOOK: crate::db::GapHook = const { std::cell::Cell::new(None) };
    /// After the final actual-owner pin, before commit: observers still see
    /// the old binding, row PID and endpoints together (no minted row yet).
    static OMP_BIND_COMMIT_GAP_HOOK: crate::db::GapHook = const { std::cell::Cell::new(None) };
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessBindingEpoch {
    session_id: Option<String>,
    instance_name: String,
    updated_at_bits: u64,
}

fn process_binding_epoch(
    db: &HcomDb,
    process_id: &str,
) -> anyhow::Result<Option<ProcessBindingEpoch>> {
    Ok(db
        .conn()
        .query_row(
            "SELECT session_id, instance_name, updated_at
             FROM process_bindings WHERE process_id = ?1",
            [process_id],
            |row| {
                Ok(ProcessBindingEpoch {
                    session_id: row.get(0)?,
                    instance_name: row.get(1)?,
                    updated_at_bits: row.get::<_, f64>(2)?.to_bits(),
                })
            },
        )
        .optional()?)
}

/// Whether the session has no carriers, or exactly the expected row, bound or
/// not and whatever its tool or status.
fn session_carriers_match(
    db: &HcomDb,
    session_id: &str,
    expected_name: Option<&str>,
) -> anyhow::Result<bool> {
    Ok(db.conn().query_row(
        "SELECT CASE WHEN ?2 IS NULL THEN COUNT(*) = 0
         ELSE COUNT(*) = 1 AND COALESCE(MIN(name = ?2), 0) = 1 END
         FROM instances WHERE session_id = ?1",
        rusqlite::params![session_id, expected_name],
        |row| row.get::<_, bool>(0),
    )?)
}

fn same_row_incarnation(expected: Option<&InstanceRow>, current: Option<&InstanceRow>) -> bool {
    match (expected, current) {
        (None, None) => true,
        (Some(expected), Some(current)) => {
            expected.name == current.name
                && expected.created_at.to_bits() == current.created_at.to_bits()
                && expected.agent_id == current.agent_id
                && expected.pid == current.pid
                && expected.session_id == current.session_id
                && expected.tool == current.tool
                && expected.origin_device_id == current.origin_device_id
        }
        _ => false,
    }
}

/// A launch's original, still-unbound UUID tuple and row incarnation. Keep this
/// across spawn; refreshing it after a failed write would authorize a new owner.
#[derive(Debug, Clone)]
pub(crate) struct OmpLaunchPidSnapshot {
    pub(crate) row: InstanceRow,
    process_id: String,
    binding: ProcessBindingEpoch,
}

/// Capture before spawn. A resumed row may already have its prior session ID;
/// the launch reservation is the original UUID binding's NULL session, not the
/// instance's session column.
pub(crate) fn capture_omp_launch_pid(
    db: &HcomDb,
    process_id: &str,
    instance_name: &str,
) -> anyhow::Result<Option<OmpLaunchPidSnapshot>> {
    if !crate::proctruth::is_launcher_process_id(process_id) {
        return Ok(None);
    }
    db.with_read_snapshot(|_tx| {
        let Some(binding) = process_binding_epoch(db, process_id)? else {
            return Ok(None);
        };
        if binding.session_id.is_some() || binding.instance_name != instance_name {
            return Ok(None);
        }
        let Some(row) = db.get_instance_full(instance_name)? else {
            return Ok(None);
        };
        if row.tool != "omp" {
            return Ok(None);
        }
        if let Some(pid) = row.pid
            && !u32::try_from(pid)
                .ok()
                .is_some_and(crate::proctruth::caller_is_pre_omp_launch_runner)
        {
            return Ok(None);
        }
        Ok(Some(OmpLaunchPidSnapshot {
            row,
            process_id: process_id.to_owned(),
            binding,
        }))
    })
}

/// Record only this launch's next PID. A successful write advances the local
/// expectation (runner/NULL -> wrapper -> child); a lost CAS never re-reads and
/// retries against a bound owner, canonical move or replacement row.
pub(crate) fn record_omp_launch_pid(
    db: &HcomDb,
    expected: &mut OmpLaunchPidSnapshot,
    new_pid: u32,
) -> anyhow::Result<bool> {
    let changed = db.with_immediate_transaction(|tx| {
        if process_binding_epoch(db, &expected.process_id)?.as_ref() != Some(&expected.binding) {
            return Ok(false);
        }
        db.compare_and_set_instance_pid_in_txn(tx, &expected.row, new_pid)
    })?;
    if changed {
        expected.row.pid = Some(i64::from(new_pid));
    }
    Ok(changed)
}

struct OmpBindingSnapshot {
    binding: Option<ProcessBindingEpoch>,
    row: Option<InstanceRow>,
    canonical: Option<String>,
    target_name: Option<String>,
    target_row: Option<InstanceRow>,
}

impl OmpBindingSnapshot {
    fn capture(db: &HcomDb, session_id: &str, process_id: &str) -> anyhow::Result<Self> {
        let binding = process_binding_epoch(db, process_id)?;
        let row = binding
            .as_ref()
            .map(|binding| db.get_instance_full(&binding.instance_name))
            .transpose()?
            .flatten();
        let canonical = db.get_session_binding(session_id)?;
        let target_name = match &canonical {
            Some(name) => Some(name.clone()),
            None => db
                .find_stopped_snapshot_by_session_id(session_id)?
                .map(|(name, _)| name),
        };
        let target_row = match target_name.as_deref() {
            Some(name) if row.as_ref().is_some_and(|row| row.name == name) => None,
            Some(name) => db.get_instance_full(name)?,
            None => None,
        };
        Ok(Self {
            binding,
            row,
            canonical,
            target_name,
            target_row,
        })
    }

    fn target_row(&self) -> Option<&InstanceRow> {
        self.row
            .as_ref()
            .filter(|row| self.target_name.as_deref() == Some(row.name.as_str()))
            .or(self.target_row.as_ref())
    }

    fn matches(&self, current: &Self) -> bool {
        self.binding == current.binding
            && self.canonical == current.canonical
            && self.target_name == current.target_name
            && same_row_incarnation(self.row.as_ref(), current.row.as_ref())
            && same_row_incarnation(self.target_row.as_ref(), current.target_row.as_ref())
    }
}

fn verified_omp_binding_owner(
    process_id: &str,
    snapshot: &OmpBindingSnapshot,
    owner_under_anchor: &dyn Fn(u32) -> Option<OmpOwnerProof>,
) -> anyhow::Result<(u32, OmpOwnerProof)> {
    if let Some(pid) = crate::proctruth::omp_minted_pid(process_id) {
        let proof = owner_under_anchor(pid)
            .filter(|proof| proof.owner_pid == pid && proof.anchor_kind == AncestorProcess::Omp)
            .context("OMP process ID does not name the nearest actual OMP owner")?;
        return Ok((pid, proof));
    }
    anyhow::ensure!(
        crate::proctruth::is_launcher_process_id(process_id),
        "OMP binding requires a launcher UUID or an OMP-minted process ID"
    );
    let row = snapshot
        .row
        .as_ref()
        .context("OMP launcher binding has no instance row")?;
    let anchor = row
        .pid
        .and_then(|pid| u32::try_from(pid).ok())
        .context("OMP launcher binding has no process anchor")?;
    let proof =
        owner_under_anchor(anchor).context("OMP launcher has no nearest actual OMP owner")?;
    let actual_anchor = proof.owner_pid == anchor && proof.anchor_kind == AncestorProcess::Omp;
    if !actual_anchor && proof.anchor_kind != AncestorProcess::OmpLauncherShim {
        anyhow::ensure!(
            proof.anchor_kind == AncestorProcess::Other
                && is_true_launch_placeholder(Some(row))
                && snapshot
                    .binding
                    .as_ref()
                    .is_some_and(|binding| binding.session_id.is_none()),
            "OMP wrapper handoff requires a still-unbound launch placeholder"
        );
    }
    Ok((anchor, proof))
}

/// OMP's owner claim and the whole session bind share one immediate transaction.
/// Existing actual-OMP anchors and verified native OMP launch shims need no
/// receipt or new metadata. An ordinary wrapper is only a first launch claim.
pub(crate) fn bind_omp_session_to_process(
    db: &HcomDb,
    session_id: &str,
    process_id: &str,
) -> anyhow::Result<Option<String>> {
    bind_omp_session_to_process_checked(
        db,
        session_id,
        process_id,
        &crate::proctruth::caller_omp_owner_under_anchor,
    )
    .inspect_err(|error| {
        crate::log::log_error(
            "binding",
            "bind_omp_session_to_process.failed",
            &format!("session_id={session_id}, process_id={process_id}, err={error:#}"),
        );
    })
}

fn bind_omp_session_to_process_checked(
    db: &HcomDb,
    session_id: &str,
    process_id: &str,
    owner_under_anchor: &dyn Fn(u32) -> Option<OmpOwnerProof>,
) -> anyhow::Result<Option<String>> {
    anyhow::ensure!(!session_id.is_empty(), "OMP session ID is empty");
    let expected =
        db.with_read_snapshot(|_tx| OmpBindingSnapshot::capture(db, session_id, process_id))?;
    #[cfg(test)]
    if let Some(hook) = OMP_BIND_CLAIM_GAP_HOOK.with(std::cell::Cell::take) {
        hook(db, process_id);
    }
    let mut post = PostCommit::default();
    let name = db.with_immediate_transaction(|tx| {
        let current = OmpBindingSnapshot::capture(db, session_id, process_id)?;
        anyhow::ensure!(
            expected.matches(&current),
            "OMP binding incarnation or process mapping changed before claim"
        );
        // Fresh kernel proof under the write lock, before any mutation.
        let (source_anchor, owner_proof) =
            verified_omp_binding_owner(process_id, &current, owner_under_anchor)?;
        let owner = owner_proof.owner_pid;
        if let Some(target) = current.target_row() {
            // A session ID locates a canonical candidate; it cannot authorize
            // taking a live foreign seat. Propagate registry errors even when
            // direct kernel proof already establishes the same owner.
            let bindings = db.process_binding_ids(&target.name)?;
            let same_owner = |pid| {
                pid == owner
                    || (if pid == source_anchor {
                        Some(owner_proof)
                    } else {
                        owner_under_anchor(pid)
                    })
                    .is_some_and(|proof| {
                        proof.owner_pid == owner
                            && proof.anchor_kind == AncestorProcess::OmpLauncherShim
                    })
            };
            let same_bound_minted_owner = target.pid.is_none()
                && crate::proctruth::omp_minted_pid(process_id) == Some(owner)
                && current
                    .binding
                    .as_ref()
                    .is_some_and(|binding| binding.instance_name == target.name)
                && same_row_incarnation(current.row.as_ref(), Some(target));
            let target_pid = target.pid.and_then(|pid| u32::try_from(pid).ok());
            let target_owned = target_pid.is_some_and(&same_owner);
            if !same_bound_minted_owner && !target_owned {
                match crate::proctruth::classify_row_carriers(db, target, &bindings) {
                    crate::proctruth::CarrierVerdict::Rooted { pid, .. } => {
                        anyhow::ensure!(
                            if Some(pid) == target_pid {
                                target_owned
                            } else {
                                same_owner(pid)
                            },
                            "OMP canonical target '{}' has another live owner",
                            target.name
                        );
                    }
                    crate::proctruth::CarrierVerdict::Orphaned(_) => {}
                    crate::proctruth::CarrierVerdict::Undetermined(why) => {
                        anyhow::bail!(
                            "OMP canonical target '{}' ownership is undetermined: {why}",
                            target.name
                        );
                    }
                }
            }
        }
        let name =
            bind_session_to_process_body(db, session_id, Some(process_id), Some(tx), &mut post)?;
        if let Some(name) = &name {
            let final_row = db
                .get_instance_full(name)?
                .with_context(|| format!("OMP bound row '{name}' is missing"))?;
            let original = if current.target_name.as_deref() == Some(name.as_str()) {
                current.target_row()
            } else {
                current.row.as_ref().filter(|row| row.name == *name)
            };
            if let Some(original) = original {
                anyhow::ensure!(
                    original.created_at.to_bits() == final_row.created_at.to_bits()
                        && original.agent_id == final_row.agent_id,
                    "OMP canonical row incarnation changed during bind"
                );
            }
            let bound = db.get_process_binding_full(process_id)?;
            anyhow::ensure!(
                bound.as_ref().is_some_and(|(bound_sid, bound_name)| {
                    bound_sid.as_deref() == Some(session_id) && bound_name == name
                }),
                "OMP process binding did not commit its session claim"
            );
            anyhow::ensure!(
                verified_omp_binding_owner(process_id, &current, owner_under_anchor)?
                    == (source_anchor, owner_proof),
                "OMP owner changed during bind"
            );
            // Runtime migration may have copied the old wrapper PID. The actual
            // owner pin is LAST, in the same commit as both bindings.
            anyhow::ensure!(
                db.compare_and_set_instance_pid_in_txn(tx, &final_row, owner)?,
                "OMP owner pin lost its row incarnation"
            );
            #[cfg(test)]
            if let Some(hook) = OMP_BIND_COMMIT_GAP_HOOK.with(std::cell::Cell::take) {
                hook(db, name);
            }
        }
        Ok(name)
    })?;
    if let (Some(name), Some(row)) = (name.as_deref(), expected.row.as_ref()) {
        rekey_migrated_terminal(db, name, row);
    }
    post.fire(db);
    Ok(name)
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
    bind_session_to_process_body(db, session_id, process_id, None, &mut post).inspect_err(|e| {
        crate::log::log_error(
            "binding",
            "bind_session_to_process.failed",
            &format!("session_id={session_id}, process_id={process_id:?}, err={e:#}"),
        );
    })
}

fn bind_session_to_process_body(
    db: &HcomDb,
    session_id: &str,
    process_id: Option<&str>,
    caller_tx: Option<&rusqlite::Transaction<'_>>,
    post: &mut PostCommit,
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
    let (placeholder_name, placeholder_data) = if let Some(pid) = process_id {
        if caller_tx.is_some() {
            let name = db.get_process_binding(pid)?;
            let row = name
                .as_deref()
                .map(|name| db.get_instance_full(name))
                .transpose()?
                .flatten();
            (name, row)
        } else {
            match db.get_process_binding(pid) {
                Ok(Some(name)) => {
                    let data = match db.get_instance_full(&name) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("[hcom] warn: get_instance_full failed for {name}: {e}");
                            None
                        }
                    };
                    (Some(name), data)
                }
                _ => (None, None),
            }
        }
    } else {
        (None, None)
    };

    // Find canonical from session binding
    let canonical = if caller_tx.is_some() {
        db.get_session_binding(session_id)?
    } else {
        match db.get_session_binding(session_id) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[hcom] warn: get_session_binding failed for {session_id}: {e}");
                None
            }
        }
    };

    // Path 1: Canonical exists (session already bound)
    if let Some(ref canonical_name) = canonical {
        crate::log::log_info(
            "binding",
            "bind_session_to_process.canonical_exists",
            &format!(
                "canonical={}, placeholder={:?}",
                canonical_name, placeholder_name
            ),
        );

        // The OMP caller carries creation fan-out in its one collector.
        recreate_instance_from_placeholder(
            db,
            canonical_name,
            session_id,
            placeholder_data.as_ref(),
            caller_tx,
            post,
        )?;
        if caller_tx.is_none() {
            post.fire(db);
            *post = PostCommit::default();
        }

        // Reset last_stop on resume
        let now = now_epoch_i64();
        let mut resume_updates = serde_json::Map::new();
        resume_updates.insert("last_stop".into(), serde_json::json!(now));

        if let Some(ref ph_name) = placeholder_name
            && ph_name != canonical_name
        {
            let true_placeholder = is_true_launch_placeholder(placeholder_data.as_ref());
            let migrated = if true_placeholder && caller_tx.is_none() {
                migrate_placeholder_notify(db, ph_name, canonical_name)
            } else {
                false
            };
            if is_true_launch_placeholder(placeholder_data.as_ref()) {
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

                if let Some(tx) = caller_tx {
                    retire_true_placeholder_after_canonical_bind_in_txn(
                        db,
                        tx,
                        placeholder_name.as_ref(),
                        canonical_name,
                        placeholder_data.as_ref(),
                    )?;
                } else if migrated {
                    delete_true_placeholder_if_migrated(
                        db,
                        ph_name,
                        canonical_name,
                        placeholder_data.as_ref(),
                    );
                }
            }
        }

        if caller_tx.is_some() {
            db.update_instance_fields(canonical_name, &resume_updates)?;
        } else {
            update_instance_position(db, canonical_name, &resume_updates);
        }

        if let Some(pid) = process_id {
            let mut bind_canonical = |tx: &rusqlite::Transaction<'_>| {
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
                    );
                }
                Ok(None)
            };
            let released = match caller_tx {
                Some(tx) => bind_canonical(tx)?,
                None => db.with_immediate_transaction(bind_canonical)?,
            };
            if caller_tx.is_none() {
                if let Some(ph) = placeholder_data.as_ref() {
                    rekey_migrated_terminal(db, canonical_name, ph);
                }
                post.fire(db);
                if let Some(displaced) = &placeholder_name {
                    notify_session_switch_stop(db, displaced, released);
                }
            } else if let (Some(displaced), Some((id, event))) = (&placeholder_name, released) {
                post.events.push((id, displaced.clone(), event));
            }
        }

        return Ok(Some(canonical_name.clone()));
    }

    // Path 2: session_bindings CASCADE'd on delete — recover canonical name from life.stopped
    let stopped = if caller_tx.is_some() {
        db.find_stopped_snapshot_by_session_id(session_id)?
    } else {
        db.find_stopped_snapshot_by_session_id(session_id)
            .ok()
            .flatten()
    };
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
        let mut restore_stopped = |tx: &rusqlite::Transaction<'_>| {
            if is_true_launch_placeholder(placeholder_data.as_ref()) {
                recreate_instance_from_placeholder(
                    db,
                    &stopped_name,
                    session_id,
                    placeholder_data.as_ref(),
                    caller_tx,
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
                    )?;
                }
            }
            if caller_tx.is_some() {
                retire_true_placeholder_after_canonical_bind_in_txn(
                    db,
                    tx,
                    placeholder_name.as_ref(),
                    &stopped_name,
                    placeholder_data.as_ref(),
                )?;
            } else {
                retire_true_placeholder_after_canonical_bind(
                    db,
                    tx,
                    placeholder_name.as_ref(),
                    &stopped_name,
                    placeholder_data.as_ref(),
                );
            }

            #[cfg(test)]
            if let Some(hook) = RESTORE_STOPPED_COMMIT_GAP_HOOK.with(std::cell::Cell::take) {
                hook(db, &stopped_name);
            }
            Ok(released)
        };
        let released = match caller_tx {
            Some(tx) => restore_stopped(tx)?,
            None => db.with_immediate_transaction(restore_stopped)?,
        };
        if caller_tx.is_none() {
            if let Some(ph) = placeholder_data.as_ref() {
                rekey_migrated_terminal(db, &stopped_name, ph);
            }
            post.fire(db);
            if let Some(displaced) = &placeholder_name {
                notify_session_switch_stop(db, displaced, released);
            }
        } else if let (Some(displaced), Some((id, event))) = (&placeholder_name, released) {
            post.events.push((id, displaced.clone(), event));
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
        if caller_tx.is_some() {
            db.update_instance_fields(ph_name, &updates)
                .with_context(|| format!("bind_placeholder.update_session for '{ph_name}'"))?;
        } else {
            update_instance_position(db, ph_name, &updates);
        }

        // Shared rows retain the other live process's session binding. Only
        // the sole holder may replace the old session on this row.
        let shared = held_by_another_live_process(db, ph_name, process_id.unwrap_or(""))?;
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

/// Restore a soft-stopped OMP's missing process binding. The environment name
/// only locates a candidate; its PID must be the actual OMP owner or a verified
/// native OMP launch shim. Ordinary wrappers and PID-less rows grant no authority.
pub fn recover_process_binding_for_instance(
    db: &HcomDb,
    instance_name: &str,
    session_id: &str,
    process_id: &str,
) -> anyhow::Result<Option<String>> {
    recover_process_binding_for_instance_checked(
        db,
        instance_name,
        session_id,
        process_id,
        &crate::proctruth::caller_omp_owner_under_anchor,
    )
    .inspect_err(|error| {
        crate::log::log_error("binding", "recover.omp_owner", &format!("{error:#}"));
    })
}

fn recover_process_binding_for_instance_checked(
    db: &HcomDb,
    instance_name: &str,
    session_id: &str,
    process_id: &str,
    owner_under_anchor: &dyn Fn(u32) -> Option<OmpOwnerProof>,
) -> anyhow::Result<Option<String>> {
    if instance_name.is_empty() || session_id.is_empty() || process_id.is_empty() {
        return Ok(None);
    }
    let (expected, binding, session_binding) = db.with_read_snapshot(|_tx| {
        Ok((
            db.get_instance_full(instance_name)?,
            process_binding_epoch(db, process_id)?,
            db.get_session_binding(session_id)?,
        ))
    })?;
    let Some(expected) = expected else {
        return Ok(None);
    };
    db.with_immediate_transaction(|tx| {
        let current = db.get_instance_full(instance_name)?;
        anyhow::ensure!(
            same_row_incarnation(Some(&expected), current.as_ref())
                && process_binding_epoch(db, process_id)? == binding
                && db.get_session_binding(session_id)? == session_binding,
            "OMP recovery incarnation or mapping changed"
        );
        anyhow::ensure!(
            binding.is_none() && session_binding.is_none(),
            "OMP recovery requires missing bindings; use the session binder"
        );
        anyhow::ensure!(
            current.as_ref().is_some_and(|row| {
                row.tool == "omp"
                    && row.status == ST_INACTIVE
                    && row.origin_device_id.as_deref().is_none_or(str::is_empty)
            }),
            "OMP recovery target is not an inactive local OMP row"
        );
        let anchor = expected
            .pid
            .and_then(|pid| u32::try_from(pid).ok())
            .context("OMP recovery has no actual-owner PID")?;
        let proof = owner_under_anchor(anchor).context("OMP recovery has no actual owner")?;
        let owner = proof.owner_pid;
        anyhow::ensure!(
            ((owner == anchor && proof.anchor_kind == AncestorProcess::Omp)
                || proof.anchor_kind == AncestorProcess::OmpLauncherShim)
                && (crate::proctruth::omp_minted_pid(process_id) == Some(owner)
                    || crate::proctruth::is_launcher_process_id(process_id)),
            "OMP recovery target is not owned by the caller"
        );
        db.clear_session_id_from_other_instances(session_id, instance_name)?;
        let mut updates = serde_json::Map::new();
        updates.insert("session_id".into(), serde_json::json!(session_id));
        db.update_instance_fields(instance_name, &updates)?;
        db.rebind_session(session_id, instance_name)?;
        db.set_process_binding(process_id, session_id, instance_name)?;
        let mut pinned = expected;
        pinned.session_id = Some(session_id.to_owned());
        anyhow::ensure!(
            db.compare_and_set_instance_pid_in_txn(tx, &pinned, owner)?,
            "OMP recovery lost its row incarnation"
        );
        Ok(Some(instance_name.to_owned()))
    })
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
    post.fire(db);
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

        let success = match db.get_instance_full(instance_name) {
            Ok(Some(existing)) => {
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
                    let _ = db.update_instance_fields(instance_name, &updates);
                }

                if is_pending_placeholder {
                    auto_subscribe_defaults(
                        db,
                        instance_name,
                        tool.unwrap_or(existing.tool.as_str()),
                    );
                }

                true
            }
            Ok(None) => {
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

                match db.save_instance_named(instance_name, &data) {
                    Ok(true) => {
                        log_created_and_auto_subscribe(
                            db,
                            instance_name,
                            is_launched,
                            parent_session_id,
                            parent_name,
                            tool.unwrap_or(""),
                            post,
                        )?;
                        true
                    }
                    Ok(false) => true,
                    Err(_) => false,
                }
            }
            Err(_) => false,
        };
        if !success {
            anyhow::bail!("Cannot register identity '{instance_name}'");
        }
        Ok(())
    };
    let result = if db.conn().is_autocommit() {
        db.with_immediate_transaction(|_tx| initialize())
    } else {
        initialize()
    };
    match result {
        Ok(()) => true,
        Err(error) => {
            crate::log::log_warn("identity", "registration.refused", &error.to_string());
            false
        }
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
    auto_subscribe_defaults(db, instance_name, tool);
    Ok(())
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

/// The OMP plain-session fallback once the checked binder found no process
/// binding, session binding or stopped restore candidate. The minted PID only
/// locates the actual owner. The reserved-then-promoted row, both bindings and
/// the owner pin commit together. Creation, not recovery: a row already
/// carrying the session ID, or a mapping that appeared since that miss, is
/// refused, never taken over or cleared.
pub(crate) fn create_omp_identity(
    db: &HcomDb,
    session_id: &str,
    process_id: &str,
) -> anyhow::Result<String> {
    create_omp_identity_checked(
        db,
        session_id,
        process_id,
        &crate::proctruth::caller_omp_owner_under_anchor,
    )
    .inspect_err(|error| {
        crate::log::log_error(
            "binding",
            "create_omp_identity.failed",
            &format!("session_id={session_id}, process_id={process_id}, err={error:#}"),
        );
    })
}

fn create_omp_identity_checked(
    db: &HcomDb,
    session_id: &str,
    process_id: &str,
    owner_under_anchor: &dyn Fn(u32) -> Option<OmpOwnerProof>,
) -> anyhow::Result<String> {
    anyhow::ensure!(!session_id.is_empty(), "OMP session ID is empty");
    anyhow::ensure!(!process_id.is_empty(), "OMP process ID is empty");
    let (expected, carriers_absent) = db.with_read_snapshot(|_tx| {
        Ok((
            OmpBindingSnapshot::capture(db, session_id, process_id)?,
            session_carriers_match(db, session_id, None)?,
        ))
    })?;
    // A row carrying this session ID is occupied even with no binding.
    anyhow::ensure!(
        expected.binding.is_none()
            && expected.canonical.is_none()
            && expected.target_name.is_none()
            && carriers_absent,
        "OMP plain identity requires an unclaimed process and session"
    );
    #[cfg(test)]
    if let Some(hook) = OMP_BIND_CLAIM_GAP_HOOK.with(std::cell::Cell::take) {
        hook(db, process_id);
    }
    // Lock order, as for every name reserver: name_gen.lock, then BEGIN
    // IMMEDIATE. Both stay held from the reservation through the final pin.
    let name_lock = crate::instance_names::lock_name_generation(db)?;
    let mut post = PostCommit::default();
    let created = db.with_immediate_transaction(|tx| {
        let current = OmpBindingSnapshot::capture(db, session_id, process_id)?;
        anyhow::ensure!(
            expected.matches(&current) && session_carriers_match(db, session_id, None)?,
            "OMP plain identity candidate appeared before creation"
        );
        let (anchor, owner_proof) =
            verified_omp_binding_owner(process_id, &current, owner_under_anchor)?;
        let owner = owner_proof.owner_pid;
        // Reserve, then promote, like the generic mint: no `created` event.
        let name = crate::instance_names::reserve_generated_name_locked(db, &name_lock)?;
        anyhow::ensure!(
            initialize_instance_in_position_file_collected(
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
            ),
            "Cannot register OMP identity '{name}'"
        );
        let promoted = db
            .get_instance_full(&name)?
            .with_context(|| format!("OMP minted row '{name}' is missing"))?;
        // The new row must be the session's sole carrier, so the clearing
        // UPDATE inside `rebind_session` below matches no other row.
        anyhow::ensure!(
            session_carriers_match(db, session_id, Some(name.as_str()))?,
            "OMP session ID is not carried by its new row alone"
        );
        db.rebind_session(session_id, &name)
            .with_context(|| format!("create_omp_identity.rebind_session for '{name}'"))?;
        db.set_process_binding(process_id, session_id, &name)
            .with_context(|| format!("create_omp_identity.set_process_binding for '{name}'"))?;
        let final_row = db
            .get_instance_full(&name)?
            .with_context(|| format!("OMP minted row '{name}' is missing"))?;
        anyhow::ensure!(
            same_row_incarnation(Some(&promoted), Some(&final_row))
                && final_row.tool == "omp"
                && final_row.session_id.as_deref() == Some(session_id),
            "OMP minted row changed during creation"
        );
        let bound = db.get_process_binding_full(process_id)?;
        let session_owner = db.get_session_binding(session_id)?;
        anyhow::ensure!(
            bound
                .as_ref()
                .is_some_and(|(bound_session_id, bound_name)| {
                    bound_session_id.as_deref() == Some(session_id)
                        && bound_name.as_str() == name.as_str()
                })
                && session_owner.as_deref() == Some(name.as_str()),
            "OMP minted bindings did not commit their claim"
        );
        anyhow::ensure!(
            verified_omp_binding_owner(process_id, &current, owner_under_anchor)?
                == (anchor, owner_proof),
            "OMP owner changed during creation"
        );
        // The actual-owner pin is LAST, in the same commit as both bindings.
        anyhow::ensure!(
            db.compare_and_set_instance_pid_in_txn(tx, &final_row, owner)?,
            "OMP owner pin lost its row incarnation"
        );
        #[cfg(test)]
        if let Some(hook) = OMP_BIND_COMMIT_GAP_HOOK.with(std::cell::Cell::take) {
            hook(db, &name);
        }
        Ok(name)
    });
    // Released after the commit or rollback; wakes fire only after both.
    drop(name_lock);
    let name = created?;
    post.fire(db);
    Ok(name)
}

/// Resolve instance name for a process_id via process_bindings.
pub fn resolve_process_binding(db: &HcomDb, process_id: Option<&str>) -> Option<String> {
    let pid = process_id?;
    db.get_process_binding(pid).ok()?
}

/// Resolve instance via process binding, session binding, or transcript marker.
pub fn resolve_instance_from_binding(
    db: &HcomDb,
    session_id: Option<&str>,
    process_id: Option<&str>,
) -> Option<InstanceRow> {
    if let Some(pid) = process_id
        && let Ok(Some(name)) = db.get_process_binding(pid)
        && let Ok(Some(instance)) = db.get_instance_full(&name)
    {
        return Some(instance);
    }

    if let Some(sid) = session_id
        && let Some(name) = db.get_session_binding(sid).ok().flatten()
        && let Ok(Some(instance)) = db.get_instance_full(&name)
    {
        return Some(instance);
    }

    None
}

/// Auto-subscribe instance to default event subscriptions from config.
/// Called during instance creation.
fn auto_subscribe_eligible(tool: &str) -> bool {
    tool.parse::<crate::tool::Tool>()
        .is_ok_and(|tool| tool.spec().released)
}

fn auto_subscribe_defaults(db: &HcomDb, instance_name: &str, tool: &str) {
    if !auto_subscribe_eligible(tool) {
        return;
    }

    let _ = db.cleanup_subscriptions(instance_name);
    let _ = db.cleanup_thread_memberships_for_name_reuse(instance_name);
    let config = match crate::config::HcomConfig::load(None) {
        Ok(c) => c,
        Err(_) => return,
    };
    if config.auto_subscribe.is_empty() {
        return;
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
            let _ = crate::db::subscriptions::create_filter_subscription(
                db,
                &filters,
                &[],
                instance_name,
                false,
                None,
            );
        }
    }
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
        x_data.insert("tool".into(), serde_json::json!("omp"));
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
        x_data.insert("tool".into(), serde_json::json!("omp"));
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
            "tool": "omp",
            "directory": "/tmp/proof-dir",
        });
        db.log_life_event("yrow", "stopped", "test", "exit", Some(snapshot), None)
            .unwrap();

        // The in-process switch: the same live process re-runs omp-start for S2.
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
        x_data.insert("tool".into(), serde_json::json!("omp"));
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
            "tool": "omp",
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

    /// A live omp seat `xrow` on `sid-old`, held by `pid-live`, plus the stopped
    /// snapshot of `yrow` on `sid-new` that a switch to `sid-new` restores.
    fn seed_path2_switch(db: &HcomDb, endpoints: &[(&str, u16)]) {
        let mut x_data = serde_json::Map::new();
        x_data.insert("name".into(), serde_json::json!("xrow"));
        x_data.insert("session_id".into(), serde_json::json!("sid-old"));
        x_data.insert("tool".into(), serde_json::json!("omp"));
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
            "tool": "omp",
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
            ("tool", serde_json::json!("omp")),
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
            "tool": "omp",
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
        x_data.insert("tool".into(), serde_json::json!("omp"));
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
        x.insert("tool".into(), serde_json::json!("omp"));
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
            row.insert("tool".into(), serde_json::json!("omp"));
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

        let result = bind_session_to_process(&db, "ses-ghost", Some("omp-777-aa-bb")).unwrap();
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

        let result = bind_session_to_process(&db, "ses-cursor", Some("omp-778-aa-bb")).unwrap();
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
    fn test_delete_placeholder_failure_keeps_notify_on_canonical() {
        let (db, path) = setup_test_db();

        db.upsert_notify_endpoint("fano", "plugin", 58_898).unwrap();
        db.upsert_notify_endpoint("mozi", "pty", 55_568).unwrap();
        db.migrate_notify_endpoints("mozi", "fano").unwrap();

        delete_true_placeholder_instance(&db, "ghost_placeholder");

        assert_eq!(notify_endpoint_port(&db, "fano", "plugin"), Some(58_898));
        assert_eq!(notify_endpoint_port(&db, "fano", "pty"), Some(55_568));

        cleanup(path);
    }

    #[test]
    #[serial]
    fn test_retire_skips_delete_when_migrate_fails() {
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

        let result = bind_session_to_process(&db, "ses-opencode-1", Some("pid-oc")).unwrap();
        assert_eq!(result, Some("fano".to_string()));

        assert!(db.get_instance_full("mozi").unwrap().is_some());
        assert_eq!(
            db.get_session_binding("ses-opencode-1").unwrap(),
            Some("fano".to_string())
        );

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

    const OMP_LAUNCH_ID: &str = "af04a012-7f6f-4a43-9c83-854a11f69dc2";

    fn seed_omp_claim(db: &HcomDb, id: &str, sid: Option<&str>, pid: Option<u32>) {
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, tool, created_at, agent_id, session_id, pid, status, status_context,
                  last_event_id)
                 VALUES ('luna', 'omp', 1.25, 'launch-agent', ?1, ?2, 'inactive', 'new', 27)",
                rusqlite::params![sid, pid.map(i64::from)],
            )
            .unwrap();
        db.set_process_binding(id, "", "luna").unwrap();
    }

    fn seed_omp_target(db: &HcomDb, path: &str) {
        match path {
            "canonical" => {
                db.conn()
                    .execute(
                        "INSERT INTO instances (name, tool, created_at, session_id, status)
                         VALUES ('fano', 'omp', 2.25, 'sid-owner', 'inactive')",
                        [],
                    )
                    .unwrap();
                db.rebind_session("sid-owner", "fano").unwrap();
            }
            "stopped" => {
                db.log_life_event(
                    "fano",
                    "stopped",
                    "test",
                    "exit",
                    Some(serde_json::json!({"tool": "omp", "session_id": "sid-owner"})),
                    None,
                )
                .unwrap();
            }
            "placeholder" => {}
            _ => panic!("unknown binding path"),
        }
    }

    fn omp_claim_owner(anchor: u32) -> Option<OmpOwnerProof> {
        let anchor_kind = match anchor {
            100 => AncestorProcess::Other,
            200 => AncestorProcess::Omp,
            300 => AncestorProcess::OmpLauncherShim,
            _ => return None,
        };
        Some(OmpOwnerProof {
            owner_pid: 200,
            anchor_kind,
        })
    }

    thread_local! {
        static OMP_OBSERVED_STATE: std::cell::RefCell<Option<Vec<String>>> =
            const { std::cell::RefCell::new(None) };
    }

    fn observe_omp_commit(db: &HcomDb, _name: &str) {
        let observer = HcomDb::open_raw(db.path()).unwrap();
        OMP_OBSERVED_STATE.set(Some(db_state(&observer)));
    }

    #[test]
    #[serial]
    fn omp_wrapper_claim_and_actual_owner_pin_commit_together() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (db, path) = setup_test_db();
        seed_omp_claim(&db, OMP_LAUNCH_ID, None, Some(100));
        let before = db_state(&db);
        OMP_BIND_COMMIT_GAP_HOOK.with(|hook| hook.set(Some(observe_omp_commit)));
        assert_eq!(
            bind_omp_session_to_process_checked(&db, "sid-owner", OMP_LAUNCH_ID, &omp_claim_owner)
                .unwrap()
                .as_deref(),
            Some("luna")
        );
        assert_eq!(OMP_OBSERVED_STATE.take(), Some(before));
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.pid, Some(200));
        assert_eq!(row.session_id.as_deref(), Some("sid-owner"));
        assert_eq!(row.last_event_id, 27);
        assert_eq!(
            db.get_process_binding_full(OMP_LAUNCH_ID).unwrap(),
            Some((Some("sid-owner".into()), "luna".into()))
        );
        assert_eq!(
            db.get_session_binding("sid-owner").unwrap().as_deref(),
            Some("luna")
        );
        assert_eq!(
            bind_omp_session_to_process_checked(&db, "sid-owner", OMP_LAUNCH_ID, &omp_claim_owner)
                .unwrap()
                .as_deref(),
            Some("luna")
        );
        let after_retry = db_state(&db);
        assert!(
            bind_omp_session_to_process_checked(&db, "sid-sibling", OMP_LAUNCH_ID, &|_| None)
                .is_err()
        );
        assert_eq!(db_state(&db), after_retry);
        assert_eq!(
            db.get_instance_full("luna").unwrap().unwrap().pid,
            Some(200)
        );
        cleanup(path);
    }

    #[test]
    #[serial]
    fn omp_legacy_actual_anchor_needs_no_placeholder_metadata() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (db, path) = setup_test_db();
        seed_omp_claim(&db, OMP_LAUNCH_ID, Some("sid-prior"), Some(200));
        db.set_process_binding(OMP_LAUNCH_ID, "sid-prior", "luna")
            .unwrap();
        db.rebind_session("sid-prior", "luna").unwrap();
        assert_eq!(
            bind_omp_session_to_process_checked(&db, "sid-owner", OMP_LAUNCH_ID, &omp_claim_owner)
                .unwrap()
                .as_deref(),
            Some("luna")
        );
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.pid, Some(200));
        assert_eq!(row.session_id.as_deref(), Some("sid-owner"));
        assert!(row.launch_context.is_none());
        assert_eq!(db.get_session_binding("sid-prior").unwrap(), None);
        cleanup(path);

        let (db, path) = setup_test_db();
        let before = db_state(&db);
        assert_eq!(
            bind_omp_session_to_process_checked(
                &db,
                "sid-plain",
                "omp-200-plain",
                &omp_claim_owner
            )
            .unwrap(),
            None
        );
        assert_eq!(db_state(&db), before);
        assert!(
            bind_omp_session_to_process_checked(
                &db,
                "sid-plain",
                "omp-300-foreign",
                &omp_claim_owner
            )
            .is_err()
        );
        assert_eq!(db_state(&db), before);
        cleanup(path);
    }

    #[test]
    #[serial]
    fn omp_wrapper_claim_refuses_bound_or_nonlaunch_rows_without_mutation() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for case in ["preset-row-session", "bound-process-session", "active-row"] {
            let (db, path) = setup_test_db();
            seed_omp_claim(
                &db,
                OMP_LAUNCH_ID,
                (case == "preset-row-session").then_some("sid-prior"),
                Some(100),
            );
            if case == "bound-process-session" {
                db.set_process_binding(OMP_LAUNCH_ID, "sid-prior", "luna")
                    .unwrap();
            }
            if case == "active-row" {
                db.set_status("luna", "active", "tool").unwrap();
            }
            let before = db_state(&db);
            assert!(
                bind_omp_session_to_process_checked(
                    &db,
                    "sid-owner",
                    OMP_LAUNCH_ID,
                    &omp_claim_owner
                )
                .is_err(),
                "{case}"
            );
            assert_eq!(db_state(&db), before, "{case}");
            cleanup(path);
        }
    }

    fn replace_pending_omp_row(db: &HcomDb, _id: &str) {
        let prior = db.get_instance_full("luna").unwrap().unwrap();
        assert!(db.delete_instance("luna").unwrap());
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, tool, created_at, agent_id, session_id, pid, status, status_context)
                 VALUES ('luna', 'omp', 9.5, 'replacement-agent', ?1, ?2, 'inactive', 'new')",
                rusqlite::params![prior.session_id, prior.pid],
            )
            .unwrap();
        OMP_OBSERVED_STATE.set(Some(db_state(db)));
    }

    fn remap_pending_omp_uuid(db: &HcomDb, id: &str) {
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, created_at, pid, status, status_context)
                 VALUES ('fano', 'omp', 2.25, 100, 'inactive', 'new')",
                [],
            )
            .unwrap();
        db.set_process_binding(id, "", "fano").unwrap();
        OMP_OBSERVED_STATE.set(Some(db_state(db)));
    }

    fn renew_pending_omp_uuid_epoch(db: &HcomDb, id: &str) {
        db.conn()
            .execute(
                "UPDATE process_bindings SET updated_at = updated_at + 1 WHERE process_id = ?1",
                [id],
            )
            .unwrap();
        OMP_OBSERVED_STATE.set(Some(db_state(db)));
    }

    #[test]
    #[serial]
    fn omp_claim_rejects_replaced_rows_remapped_uuids_and_new_binding_epochs() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for race in [
            replace_pending_omp_row as fn(&HcomDb, &str),
            remap_pending_omp_uuid,
            renew_pending_omp_uuid_epoch,
        ] {
            let (db, path) = setup_test_db();
            seed_omp_claim(&db, OMP_LAUNCH_ID, None, Some(100));
            OMP_BIND_CLAIM_GAP_HOOK.with(|hook| hook.set(Some(race)));
            assert!(
                bind_omp_session_to_process_checked(
                    &db,
                    "sid-owner",
                    OMP_LAUNCH_ID,
                    &omp_claim_owner
                )
                .is_err()
            );
            assert_eq!(db_state(&db), OMP_OBSERVED_STATE.take().unwrap());
            cleanup(path);
        }
    }

    fn appear_canonical_session(db: &HcomDb, _id: &str) {
        seed_omp_target(db, "canonical");
        OMP_OBSERVED_STATE.set(Some(db_state(db)));
    }

    fn appear_stopped_restore(db: &HcomDb, _id: &str) {
        seed_omp_target(db, "stopped");
        OMP_OBSERVED_STATE.set(Some(db_state(db)));
    }

    /// A row carrying the session ID with no process, session or stopped
    /// mapping. The binder misses it, yet it occupies the session.
    fn appear_unbound_session_row(db: &HcomDb, id: &str) {
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, created_at, session_id, status)
                 VALUES ('fano', 'omp', 2.25, 'sid-owner', 'listening')",
                [],
            )
            .unwrap();
        assert_eq!(
            bind_omp_session_to_process_checked(db, "sid-owner", id, &omp_claim_owner).unwrap(),
            None
        );
        OMP_OBSERVED_STATE.set(Some(db_state(db)));
    }

    /// A process, session or restore mapping, or a row already carrying the
    /// session ID, present when the plain mint starts or appearing in its
    /// snapshot-to-transaction gap refuses the mint. The holder stays exactly
    /// as it appeared and the creation subscriber gets no wake.
    #[test]
    #[serial]
    fn omp_plain_mint_refuses_a_mapping_that_appears_after_the_miss() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let id = "omp-200-plain";
        for race in [
            remap_pending_omp_uuid as fn(&HcomDb, &str),
            appear_canonical_session,
            appear_stopped_restore,
            appear_unbound_session_row,
        ] {
            for in_gap in [false, true] {
                let (db, path) = setup_test_db();
                let listener = subscribe_omp_creation(&db);
                assert_eq!(
                    bind_omp_session_to_process_checked(&db, "sid-owner", id, &omp_claim_owner)
                        .unwrap(),
                    None
                );
                if in_gap {
                    OMP_BIND_CLAIM_GAP_HOOK.with(|hook| hook.set(Some(race)));
                } else {
                    race(&db, id);
                }
                assert!(
                    create_omp_identity_checked(&db, "sid-owner", id, &omp_claim_owner).is_err(),
                    "in_gap={in_gap}"
                );
                assert_eq!(
                    db_state(&db),
                    OMP_OBSERVED_STATE.take().unwrap(),
                    "in_gap={in_gap}"
                );
                assert_eq!(
                    listener.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock,
                    "in_gap={in_gap}"
                );
                cleanup(path);
            }
        }
    }

    fn win_omp_claim_before_waiters_lock(db: &HcomDb, id: &str) {
        assert_eq!(
            bind_omp_session_to_process_checked(db, "sid-owner", id, &omp_claim_owner)
                .unwrap()
                .as_deref(),
            Some("luna")
        );
        OMP_OBSERVED_STATE.set(Some(db_state(db)));
    }

    #[test]
    #[serial]
    fn omp_waiting_sibling_cannot_use_a_preclaim_wrapper_snapshot() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (db, path) = setup_test_db();
        seed_omp_claim(&db, OMP_LAUNCH_ID, None, Some(100));
        OMP_BIND_CLAIM_GAP_HOOK.with(|hook| hook.set(Some(win_omp_claim_before_waiters_lock)));
        assert!(
            bind_omp_session_to_process_checked(&db, "sid-sibling", OMP_LAUNCH_ID, &|anchor| {
                (anchor == 100 || anchor == 300).then_some(OmpOwnerProof {
                    owner_pid: 300,
                    anchor_kind: if anchor == 300 {
                        AncestorProcess::Omp
                    } else {
                        AncestorProcess::Other
                    },
                })
            })
            .is_err()
        );
        assert_eq!(db_state(&db), OMP_OBSERVED_STATE.take().unwrap());
        assert_eq!(
            db.get_instance_full("luna").unwrap().unwrap().pid,
            Some(200)
        );
        assert_eq!(db.get_session_binding("sid-sibling").unwrap(), None);
        cleanup(path);
    }

    fn subscribe_omp_creation(db: &HcomDb) -> std::net::TcpListener {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at)
                 VALUES ('mora', 'listening', 0.5)",
                [],
            )
            .unwrap();
        db.upsert_notify_endpoint("mora", "plugin", listener.local_addr().unwrap().port())
            .unwrap();
        crate::db::subscriptions::create_filter_subscription(
            db,
            &std::collections::HashMap::from([
                ("type".into(), vec!["life".into()]),
                ("action".into(), vec!["created".into()]),
            ]),
            &[],
            "mora",
            false,
            None,
        )
        .unwrap();
        listener
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[serial]
    fn omp_all_binding_paths_roll_back_and_fire_no_wakes_when_the_final_pin_fails() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for binding_path in ["canonical", "stopped", "placeholder", "plain-mint"] {
            for raise in ["ABORT, 'cannot pin actual owner'", "IGNORE"] {
                let (db, path) = setup_test_db();
                seed_omp_claim(&db, OMP_LAUNCH_ID, None, Some(100));
                let plain = binding_path == "plain-mint";
                if !plain {
                    seed_omp_target(&db, binding_path);
                }
                db.upsert_notify_endpoint("luna", "inject", 54_991).unwrap();
                let listener = subscribe_omp_creation(&db);
                db.conn()
                    .execute_batch(&format!(
                        "CREATE TRIGGER refuse_omp_pin BEFORE UPDATE OF pid ON instances
                         WHEN NEW.pid = 200
                         BEGIN SELECT RAISE({raise}); END;"
                    ))
                    .unwrap();
                let before = db_state(&db);
                // The plain mint is the launcher-less fallback: a fresh session
                // for an unbound minted ID, beside the untouched launch claim.
                let refused = if plain {
                    create_omp_identity_checked(&db, "sid-plain", "omp-200-new", &omp_claim_owner)
                        .is_err()
                } else {
                    bind_omp_session_to_process_checked(
                        &db,
                        "sid-owner",
                        OMP_LAUNCH_ID,
                        &omp_claim_owner,
                    )
                    .is_err()
                };
                assert!(refused, "{binding_path}/{raise}");
                assert_eq!(db_state(&db), before, "{binding_path}/{raise}");
                assert_eq!(
                    listener.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock,
                    "{binding_path}/{raise}"
                );
                if plain {
                    // Once the pin may land, the same mint commits it, and its
                    // reserve-then-promote creation still publishes no wake.
                    db.conn()
                        .execute_batch("DROP TRIGGER refuse_omp_pin")
                        .unwrap();
                    let minted = create_omp_identity_checked(
                        &db,
                        "sid-plain",
                        "omp-200-new",
                        &omp_claim_owner,
                    );
                    let name = minted.unwrap();
                    let row = db.get_instance_full(&name).unwrap().unwrap();
                    assert_eq!(row.pid, Some(200), "{raise}");
                    assert_eq!(
                        db.get_process_binding_full("omp-200-new").unwrap(),
                        Some((Some("sid-plain".into()), name.clone()))
                    );
                    assert_eq!(db.get_session_binding("sid-plain").unwrap(), Some(name));
                    assert_eq!(
                        listener.accept().unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock,
                        "{raise}"
                    );
                }
                cleanup(path);
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[serial]
    fn omp_canonical_adoption_pins_after_runtime_copy_and_invalidates_late_pid_writes() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for binding_path in ["canonical", "stopped"] {
            let (db, path) = setup_test_db();
            seed_omp_claim(&db, OMP_LAUNCH_ID, None, None);
            let mut launch = capture_omp_launch_pid(&db, OMP_LAUNCH_ID, "luna")
                .unwrap()
                .unwrap();
            assert!(record_omp_launch_pid(&db, &mut launch, 100).unwrap());
            seed_omp_target(&db, binding_path);
            db.upsert_notify_endpoint("luna", "inject", 54_992).unwrap();
            let listener = subscribe_omp_creation(&db);
            let before = db_state(&db);
            OMP_BIND_COMMIT_GAP_HOOK.with(|hook| hook.set(Some(observe_omp_commit)));
            assert_eq!(
                bind_omp_session_to_process_checked(
                    &db,
                    "sid-owner",
                    OMP_LAUNCH_ID,
                    &omp_claim_owner
                )
                .unwrap()
                .as_deref(),
                Some("fano")
            );
            assert_eq!(OMP_OBSERVED_STATE.take(), Some(before));
            assert!(db.get_instance_full("luna").unwrap().is_none());
            let row = db.get_instance_full("fano").unwrap().unwrap();
            assert_eq!(row.pid, Some(200));
            assert_eq!(row.session_id.as_deref(), Some("sid-owner"));
            assert_eq!(notify_endpoint_port(&db, "fano", "inject"), Some(54_992));
            if binding_path == "stopped" {
                assert_eq!(row.agent_id.as_deref(), Some("launch-agent"));
                assert!(
                    listener.accept().is_ok(),
                    "creation wake fires after commit"
                );
            }
            let committed = db_state(&db);
            assert!(!record_omp_launch_pid(&db, &mut launch, 300).unwrap());
            assert_eq!(db_state(&db), committed);
            assert_eq!(
                db.get_instance_full("fano").unwrap().unwrap().pid,
                Some(200)
            );
            cleanup(path);
        }
    }

    #[test]
    #[serial]
    fn omp_owner_proof_and_binding_write_failures_roll_back_the_claim() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for failure in ["binding", "owner-proof", "created-event"] {
            let (db, path) = setup_test_db();
            seed_omp_claim(&db, OMP_LAUNCH_ID, None, Some(100));
            if failure == "binding" {
                db.conn()
                    .execute_batch(
                        "CREATE TRIGGER refuse_omp_binding BEFORE INSERT ON process_bindings
                         BEGIN SELECT RAISE(ABORT, 'cannot bind owner'); END;",
                    )
                    .unwrap();
            }
            if failure == "created-event" {
                seed_omp_target(&db, "stopped");
                db.conn()
                    .execute_batch(
                        "CREATE TRIGGER refuse_omp_created BEFORE INSERT ON events
                         WHEN NEW.type = 'life' AND json_extract(NEW.data, '$.action') = 'created'
                         BEGIN SELECT RAISE(ABORT, 'cannot publish creation'); END;",
                    )
                    .unwrap();
            }
            let before = db_state(&db);
            let proofs = std::cell::Cell::new(0);
            let owner = |anchor| {
                let count = proofs.get();
                proofs.set(count + 1);
                if failure == "owner-proof" && count > 0 {
                    None
                } else {
                    omp_claim_owner(anchor)
                }
            };
            assert!(
                bind_omp_session_to_process_checked(&db, "sid-owner", OMP_LAUNCH_ID, &owner)
                    .is_err()
            );
            assert_eq!(db_state(&db), before, "{failure}");
            cleanup(path);
        }
    }

    #[test]
    #[serial]
    fn omp_delayed_pre_and_post_spawn_writers_lose_after_new_or_resumed_owner_claims() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for prior_session in [None, Some("sid-prior")] {
            let (db, path) = setup_test_db();
            seed_omp_claim(&db, OMP_LAUNCH_ID, prior_session, None);
            let mut launch = capture_omp_launch_pid(&db, OMP_LAUNCH_ID, "luna")
                .unwrap()
                .unwrap();
            let mut delayed_pre = launch.clone();
            assert!(record_omp_launch_pid(&db, &mut launch, 100).unwrap());
            let mut delayed_post = launch.clone();
            if prior_session.is_some() {
                // Resume's preset row SID cannot use the wrapper exception.
                // Its legitimate child record must still work before binding.
                assert!(record_omp_launch_pid(&db, &mut launch, 200).unwrap());
            }
            bind_omp_session_to_process_checked(&db, "sid-owner", OMP_LAUNCH_ID, &omp_claim_owner)
                .unwrap();
            let claimed = db_state(&db);
            assert!(!record_omp_launch_pid(&db, &mut delayed_pre, 100).unwrap());
            assert!(!record_omp_launch_pid(&db, &mut delayed_post, 300).unwrap());
            assert_eq!(db_state(&db), claimed);
            assert_eq!(
                db.get_instance_full("luna").unwrap().unwrap().pid,
                Some(200)
            );
            assert!(
                capture_omp_launch_pid(&db, OMP_LAUNCH_ID, "luna")
                    .unwrap()
                    .is_none()
            );
            cleanup(path);
        }
    }

    #[test]
    #[serial]
    fn omp_pid_bookkeeping_refuses_reused_names_remapped_uuids_and_changed_epochs() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for after_prewrite in [false, true] {
            for race in [
                replace_pending_omp_row as fn(&HcomDb, &str),
                remap_pending_omp_uuid,
                renew_pending_omp_uuid_epoch,
            ] {
                let (db, path) = setup_test_db();
                seed_omp_claim(&db, OMP_LAUNCH_ID, Some("sid-prior"), None);
                let mut launch = capture_omp_launch_pid(&db, OMP_LAUNCH_ID, "luna")
                    .unwrap()
                    .unwrap();
                if after_prewrite {
                    assert!(record_omp_launch_pid(&db, &mut launch, 100).unwrap());
                }
                race(&db, OMP_LAUNCH_ID);
                let raced = db_state(&db);
                assert!(!record_omp_launch_pid(&db, &mut launch, 300).unwrap());
                assert_eq!(db_state(&db), raced);
                OMP_OBSERVED_STATE.take();
                cleanup(path);
            }
        }
    }

    #[test]
    #[serial]
    fn omp_named_recovery_requires_the_targets_actual_owner_and_rolls_back_failed_binds() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for case in [
            "foreign-owner",
            "pidless",
            "wrapper",
            "active",
            "write-failure",
            "owner",
        ] {
            let (db, path) = setup_test_db();
            let pid = match case {
                "pidless" => None,
                "wrapper" => Some(100),
                _ => Some(200),
            };
            seed_omp_claim(&db, OMP_LAUNCH_ID, Some("sid-prior"), pid);
            db.delete_process_binding(OMP_LAUNCH_ID).unwrap();
            if case == "active" {
                db.set_status("luna", "active", "tool").unwrap();
            }
            if case == "write-failure" {
                db.conn()
                    .execute_batch(
                        "CREATE TRIGGER refuse_recovered_owner BEFORE INSERT ON process_bindings
                         BEGIN SELECT RAISE(ABORT, 'cannot restore owner'); END;",
                    )
                    .unwrap();
            }
            let before = db_state(&db);
            let id = if case == "foreign-owner" {
                "omp-300-foreign"
            } else {
                "omp-200-owner"
            };
            let result = recover_process_binding_for_instance_checked(
                &db,
                "luna",
                "sid-owner",
                id,
                &omp_claim_owner,
            );
            if case == "owner" {
                assert_eq!(result.unwrap().as_deref(), Some("luna"));
                let row = db.get_instance_full("luna").unwrap().unwrap();
                assert_eq!(row.pid, Some(200));
                assert_eq!(row.session_id.as_deref(), Some("sid-owner"));
                assert_eq!(row.created_at.to_bits(), 1.25f64.to_bits());
                assert_eq!(row.agent_id.as_deref(), Some("launch-agent"));
                assert_eq!(
                    db.get_process_binding_full(id).unwrap(),
                    Some((Some("sid-owner".into()), "luna".into()))
                );
            } else {
                assert!(result.is_err(), "{case}");
                assert_eq!(db_state(&db), before, "{case}");
            }
            cleanup(path);
        }
    }

    #[test]
    #[serial]
    fn omp_pidless_canonical_retry_uses_its_existing_minted_owner_mapping() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (db, path) = setup_test_db();
        let id = "omp-200-owner";
        seed_omp_claim(&db, id, Some("sid-owner"), None);
        db.set_process_binding(id, "sid-owner", "luna").unwrap();
        db.rebind_session("sid-owner", "luna").unwrap();
        let original = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(
            bind_omp_session_to_process_checked(&db, "sid-owner", id, &omp_claim_owner)
                .unwrap()
                .as_deref(),
            Some("luna")
        );
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.pid, Some(200));
        assert_eq!(row.created_at.to_bits(), original.created_at.to_bits());
        assert_eq!(row.agent_id, original.agent_id);
        assert_eq!(row.last_event_id, original.last_event_id);
        cleanup(path);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[serial]
    fn omp_canonical_session_id_cannot_authorize_a_foreign_live_target() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (db, path) = setup_test_db();
        seed_omp_target(&db, "canonical");
        let foreign = std::process::id();
        db.update_instance_pid("fano", foreign).unwrap();
        let owner = foreign.checked_add(10_000).unwrap();
        let id = format!("omp-{owner}-new-owner");
        let before = db_state(&db);
        let error = bind_omp_session_to_process_checked(&db, "sid-owner", &id, &|anchor| {
            (anchor == owner).then_some(OmpOwnerProof {
                owner_pid: owner,
                anchor_kind: AncestorProcess::Omp,
            })
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("another live owner"),
            "{error:#}"
        );
        assert_eq!(db_state(&db), before);
        cleanup(path);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[serial]
    fn omp_displaced_stop_and_endpoint_wakes_roll_back_with_the_final_owner_pin() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for binding_path in ["canonical", "stopped"] {
            let (db, path) = setup_test_db();
            seed_omp_claim(&db, OMP_LAUNCH_ID, Some("sid-prior"), Some(200));
            db.set_process_binding(OMP_LAUNCH_ID, "sid-prior", "luna")
                .unwrap();
            db.rebind_session("sid-prior", "luna").unwrap();
            seed_omp_target(&db, binding_path);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            db.upsert_notify_endpoint("luna", "pty", listener.local_addr().unwrap().port())
                .unwrap();
            db.conn()
                .execute_batch(
                    "CREATE TRIGGER refuse_pin_after_stop BEFORE UPDATE OF pid ON instances
                     WHEN NEW.pid = 200 AND EXISTS (
                         SELECT 1 FROM events WHERE instance = 'luna' AND type = 'life'
                           AND json_extract(data, '$.by') = 'session_switch')
                     BEGIN SELECT RAISE(ABORT, 'cannot pin after displaced stop'); END;",
                )
                .unwrap();
            let before = db_state(&db);
            let error = bind_omp_session_to_process_checked(
                &db,
                "sid-owner",
                OMP_LAUNCH_ID,
                &omp_claim_owner,
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("cannot pin after displaced stop"),
                "{error:#}"
            );
            assert_eq!(db_state(&db), before, "{binding_path}");
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            cleanup(path);
        }
    }

    #[test]
    #[serial]
    fn omp_bound_native_shim_reuses_one_source_proof_per_bind_phase() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (db, path) = setup_test_db();
        seed_omp_claim(&db, OMP_LAUNCH_ID, Some("sid-owner"), Some(300));
        db.set_process_binding(OMP_LAUNCH_ID, "sid-owner", "luna")
            .unwrap();
        db.rebind_session("sid-owner", "luna").unwrap();
        let anchors = std::cell::RefCell::new(Vec::new());
        let proof = |anchor| {
            anchors.borrow_mut().push(anchor);
            omp_claim_owner(anchor)
        };
        assert_eq!(
            bind_omp_session_to_process_checked(&db, "sid-owner", OMP_LAUNCH_ID, &proof)
                .unwrap()
                .as_deref(),
            Some("luna")
        );
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.pid, Some(200));
        assert_eq!(row.session_id.as_deref(), Some("sid-owner"));
        assert!(row.launch_context.is_none());
        assert_eq!(
            anchors.into_inner(),
            vec![300, 300],
            "pre/post bind refresh independently; canonical policy does not re-read the same anchor"
        );
        cleanup(path);
    }

    #[test]
    #[serial]
    fn omp_different_canonical_anchor_requires_its_own_complete_proof() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for target_kind in [
            Some(AncestorProcess::OmpLauncherShim),
            Some(AncestorProcess::Other),
            None,
        ] {
            let (db, path) = setup_test_db();
            let target = std::process::id();
            let owner = target.checked_add(10_000).unwrap();
            let id = format!("omp-{owner}-owner");
            seed_omp_claim(&db, &id, Some("sid-owner"), Some(target));
            db.set_process_binding(&id, "sid-owner", "luna").unwrap();
            db.rebind_session("sid-owner", "luna").unwrap();
            let before = db_state(&db);
            let anchors = std::cell::RefCell::new(Vec::new());
            let proof = |anchor| {
                anchors.borrow_mut().push(anchor);
                if anchor == owner {
                    Some(OmpOwnerProof {
                        owner_pid: owner,
                        anchor_kind: AncestorProcess::Omp,
                    })
                } else if anchor == target {
                    target_kind.map(|anchor_kind| OmpOwnerProof {
                        owner_pid: owner,
                        anchor_kind,
                    })
                } else {
                    None
                }
            };
            let result = bind_omp_session_to_process_checked(&db, "sid-owner", &id, &proof);
            if target_kind == Some(AncestorProcess::OmpLauncherShim) {
                assert_eq!(result.unwrap().as_deref(), Some("luna"));
                assert_eq!(
                    db.get_instance_full("luna").unwrap().unwrap().pid,
                    Some(i64::from(owner))
                );
                assert_eq!(anchors.into_inner(), vec![owner, target, owner]);
            } else {
                assert!(result.is_err());
                assert_eq!(db_state(&db), before);
                assert_eq!(
                    anchors.into_inner(),
                    vec![owner, target],
                    "a classifier returning the same root must not repeat the failed proof"
                );
            }
            cleanup(path);
        }
    }

    #[test]
    #[serial]
    fn omp_launch_pid_cas_refuses_changed_tool_or_origin() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for change in [
            "UPDATE instances SET tool = 'claude' WHERE name = 'luna'",
            "UPDATE instances SET origin_device_id = 'remote-device' WHERE name = 'luna'",
        ] {
            let (db, path) = setup_test_db();
            seed_omp_claim(&db, OMP_LAUNCH_ID, None, None);
            let mut captured = capture_omp_launch_pid(&db, OMP_LAUNCH_ID, "luna")
                .unwrap()
                .unwrap();
            db.conn().execute(change, []).unwrap();
            let before = db_state(&db);
            assert!(!record_omp_launch_pid(&db, &mut captured, 100).unwrap());
            assert_eq!(db_state(&db), before);
            assert_eq!(db.get_instance_full("luna").unwrap().unwrap().pid, None);
            cleanup(path);
        }
    }

    #[test]
    #[serial]
    fn omp_launch_pid_cas_accepts_equivalent_local_origin_encodings() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        for (initial, current) in [
            (None, None),
            (Some(""), Some("")),
            (None, Some("")),
            (Some(""), None),
        ] {
            let (db, path) = setup_test_db();
            seed_omp_claim(&db, OMP_LAUNCH_ID, None, None);
            db.conn()
                .execute(
                    "UPDATE instances SET origin_device_id = ?1 WHERE name = 'luna'",
                    rusqlite::params![initial],
                )
                .unwrap();
            let mut captured = capture_omp_launch_pid(&db, OMP_LAUNCH_ID, "luna")
                .unwrap()
                .unwrap();
            db.conn()
                .execute(
                    "UPDATE instances SET origin_device_id = ?1 WHERE name = 'luna'",
                    rusqlite::params![current],
                )
                .unwrap();
            assert!(record_omp_launch_pid(&db, &mut captured, 100).unwrap());
            assert_eq!(
                db.get_instance_full("luna").unwrap().unwrap().pid,
                Some(100)
            );
            cleanup(path);
        }
    }
}
