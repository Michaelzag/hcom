//! Omp Coding Agent hook handlers — argv-based lifecycle plus TypeScript plugin.

use std::time::Instant;

use anyhow::{Context, Result};

use serde_json::Value;

use crate::bootstrap;
use crate::db::HcomDb;
use crate::instance_binding;
use crate::instance_lifecycle as lifecycle;
use crate::instances;
use crate::log::{log_error, log_info};
use crate::shared::ST_LISTENING;
use crate::shared::context::HcomContext;

use crate::hooks::common;

fn parse_flag(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .cloned()
}

fn has_flag(argv: &[String], flag: &str) -> bool {
    argv.iter().any(|a| a == flag)
}

pub(crate) fn upsert_plugin_notify_endpoint(
    db: &HcomDb,
    instance_name: &str,
    port: u16,
) -> Result<()> {
    db.upsert_notify_endpoint(instance_name, "plugin", port)
        .with_context(|| format!("Failed to register plugin notify port for {instance_name}"))
}

fn initialize_last_event_id(db: &HcomDb, instance_name: &str, current: i64) -> Result<i64> {
    if current != 0 {
        return Ok(current);
    }
    let launch_event_id: Option<i64> = std::env::var("HCOM_LAUNCH_EVENT_ID")
        .ok()
        .and_then(|s| s.parse().ok());
    let current_max: i64 =
        db.conn()
            .query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |row| {
                row.get(0)
            })?;
    let new_id = match launch_event_id {
        Some(lei) if lei <= current_max => lei,
        _ => current_max,
    };
    let mut updates = serde_json::Map::new();
    updates.insert("last_event_id".into(), serde_json::json!(new_id));
    db.update_instance_fields(instance_name, &updates)?;
    Ok(new_id)
}

fn instance_name_from_env(ctx: &HcomContext) -> Option<String> {
    ctx.raw_env
        .get("HCOM_INSTANCE_NAME")
        .filter(|s| !s.is_empty())
        .cloned()
}

fn bootstrap_for(ctx: &HcomContext, db: &HcomDb, instance_name: &str) -> String {
    let tag = db
        .get_instance_full(instance_name)
        .ok()
        .flatten()
        .and_then(|d| d.tag.clone())
        .unwrap_or_default();
    let hcom_config = crate::config::HcomConfig::load(None).unwrap_or_default();
    let relay_enabled = crate::relay::is_relay_enabled(&hcom_config);
    let effective_tag = if tag.is_empty() {
        &hcom_config.tag
    } else {
        &tag
    };
    bootstrap::get_bootstrap(
        db,
        &ctx.hcom_dir,
        instance_name,
        "omp",
        ctx.is_background,
        ctx.is_launched,
        &ctx.notes,
        effective_tag,
        relay_enabled,
        ctx.background_name.as_deref(),
    )
}

/// Readiness is separate from the checked bind so a lost RPC response can be
/// replayed. Both ends of this transaction fence an obsolete start completion.
fn require_start_binding(
    db: &HcomDb,
    instance_name: &str,
    session_id: &str,
    process_id: &str,
    owner: &crate::proctruth::OmpOwner,
) -> Result<crate::db::InstanceRow> {
    anyhow::ensure!(
        db.get_process_binding_full(process_id)?
            .as_ref()
            .is_some_and(|(session, name)| {
                name == instance_name && session.as_deref() == Some(session_id)
            }),
        "OMP start superseded by a newer process binding"
    );
    let row = db
        .get_instance_full(instance_name)?
        .ok_or_else(|| anyhow::anyhow!("OMP start instance no longer exists"))?;
    anyhow::ensure!(
        row.tool == "omp"
            && row.origin_device_id.as_deref().unwrap_or("").is_empty()
            && row.session_id.as_deref() == Some(session_id)
            && row.pid == Some(i64::from(owner.pid))
            && crate::proctruth::stored_omp_owner(&row)?.as_ref() == Some(owner),
        "OMP start superseded: session or native owner changed"
    );
    Ok(row)
}

pub(super) fn complete_start_readiness(
    ctx: &HcomContext,
    db: &HcomDb,
    argv: &[String],
    instance_name: &str,
    session_id: &str,
    process_id: &str,
    owner: &crate::proctruth::OmpOwner,
) -> Result<common::PostCommit> {
    let transcript_path = parse_flag(argv, "--transcript-path").filter(|path| !path.is_empty());
    let cwd = parse_flag(argv, "--cwd").filter(|path| !path.is_empty());
    let directory = cwd.as_deref().or_else(|| ctx.cwd.to_str());
    let notify_port: Option<u16> = parse_flag(argv, "--notify-port").and_then(|s| s.parse().ok());
    // git/tty/terminal receipt I/O must not hold the database write lock.
    let mut captured = instance_binding::capture_context();
    captured.insert("process_id".into(), serde_json::json!(process_id));
    db.with_immediate_transaction(|_| {
        anyhow::ensure!(
            instance_binding::authenticated_omp_owner(db, process_id)? == *owner,
            "OMP ownership refused: start owner changed"
        );
        let existing = require_start_binding(db, instance_name, session_id, process_id, owner)?;
        let cursor = initialize_last_event_id(db, instance_name, existing.last_event_id)?;
        let mut post = common::PostCommit::default();
        let status_time = crate::shared::time::now_epoch_i64();
        lifecycle::set_status_collected(
            db,
            instance_name,
            ST_LISTENING,
            "start",
            Default::default(),
            &mut post,
        );
        instance_binding::store_captured_launch_context(db, instance_name, captured)?;

        let mut updates = serde_json::Map::new();
        updates.insert("tool".into(), serde_json::json!("omp"));
        updates.insert("session_id".into(), serde_json::json!(session_id));
        if let Some(path) = transcript_path.as_deref() {
            updates.insert("transcript_path".into(), serde_json::json!(path));
        }
        if let Some(directory) = directory {
            updates.insert("directory".into(), serde_json::json!(directory));
        }
        db.update_instance_fields(instance_name, &updates)?;
        if let Some(port) = notify_port {
            upsert_plugin_notify_endpoint(db, instance_name, port)?;
            post.collect_wake(db, instance_name, crate::notify::WakeKind::DELIVERY_LOOPS);
        }

        // The lifecycle writer is intentionally void. Verify its required
        // state along with the checked metadata and endpoint before commit.
        let ready = require_start_binding(db, instance_name, session_id, process_id, owner)?;
        anyhow::ensure!(
            ready.status == ST_LISTENING
                && ready.status_context == "start"
                && ready.status_detail.is_empty()
                && ready.status_time >= status_time
                && ready.last_stop >= status_time
                && ready.last_event_id == cursor
                && directory.is_none_or(|directory| ready.directory == directory)
                && transcript_path
                    .as_deref()
                    .is_none_or(|path| ready.transcript_path == path),
            "OMP start readiness could not be stored"
        );
        if let Some(port) = notify_port {
            let stored: u16 = db.conn().query_row(
                "SELECT port FROM notify_endpoints WHERE instance = ?1 AND kind = 'plugin'",
                rusqlite::params![instance_name],
                |row| row.get(0),
            )?;
            anyhow::ensure!(
                stored == port,
                "OMP start notify endpoint could not be stored"
            );
        }
        // Re-authenticate native caller facts immediately before this
        // transaction commits, not merely before the earlier binding commit.
        anyhow::ensure!(
            instance_binding::authenticated_omp_owner(db, process_id)? == *owner,
            "OMP ownership refused: start owner changed before commit"
        );
        Ok(post)
    })
}

pub(crate) fn handle_start(
    ctx: &HcomContext,
    db: &HcomDb,
    argv: &[String],
    owner: &crate::proctruth::OmpOwner,
) -> (i32, String) {
    // The dispatcher (and direct-test boundary) already ran the shared caller
    // gate. Retain that proof instead of walking the same ancestry again.
    let process_id = common::omp_hook_process_id(ctx).expect("caller gate authenticated an id");
    let session_id = match parse_flag(argv, "--session-id").filter(|sid| !sid.is_empty()) {
        Some(sid) => sid,
        None => return common::omp_hook_failure(&anyhow::anyhow!("Missing --session-id")),
    };

    // Best effort: the running session already has its plugin loaded.
    if !crate::hooks::omp::ensure_omp_plugin_installed() {
        log_info(
            "hooks",
            "omp-start.plugin_refresh_failed",
            &format!(
                "could not install current plugin at {}",
                crate::hooks::omp::get_omp_plugin_path().display()
            ),
        );
    }

    if let Some(stopped) =
        instance_binding::stopped_restore_for_own_process(db, &session_id, process_id)
    {
        log_info(
            "hooks",
            "omp-start.own_stop_restore_skipped",
            &format!(
                "instance={stopped} session_id={session_id} process_id={process_id} \
                 reason=this process's own stop is recorded; restore left to a new process"
            ),
        );
        return (
            0,
            serde_json::json!({"ok": true, "restored": false, "stopped": stopped}).to_string(),
        );
    }

    let bound = match instance_binding::bind_omp_session_to_process(db, &session_id, process_id) {
        Ok(name) => name,
        Err(error) => return common::omp_hook_failure(&error),
    };
    let recovered = if bound.is_none() {
        match instance_name_from_env(ctx) {
            Some(name) => match instance_binding::recover_omp_process_binding_for_instance(
                db,
                &name,
                &session_id,
                process_id,
            ) {
                Ok(name) => name,
                Err(error) => return common::omp_hook_failure(&error),
            },
            None => None,
        }
    } else {
        None
    };
    let instance_name = match bound.or(recovered) {
        Some(name) => name,
        None => {
            let hcom_config = crate::config::HcomConfig::load(None).unwrap_or_default();
            // Direct callers cannot turn an inherited HCOM_LAUNCHED=1 into
            // launch provenance for an OMP-minted plain-session id.
            let is_launched =
                ctx.is_launched && crate::proctruth::is_launcher_process_id(process_id);
            if !is_launched && !hcom_config.plain_sessions {
                log_info(
                    "hooks",
                    "omp-start.unbound_no_launch",
                    &format!(
                        "no instance bound, not hcom-launched, and [launch.omp].plain_sessions is off \
                         (enable with `hcom config plain_sessions true`); session_id={session_id} process_id={process_id}"
                    ),
                );
                return common::omp_hook_failure(&anyhow::anyhow!(
                    "No instance bound to this process"
                ));
            }
            match instance_binding::create_omp_identity(db, &session_id, process_id) {
                Ok(name) => {
                    log_info(
                        "hooks",
                        "omp-start.minted_identity",
                        &format!("instance={name} session_id={session_id} process_id={process_id}"),
                    );
                    name
                }
                Err(error) => return common::omp_hook_failure(&error),
            }
        }
    };

    let post = match complete_start_readiness(
        ctx,
        db,
        argv,
        &instance_name,
        &session_id,
        process_id,
        owner,
    ) {
        Ok(post) => post,
        Err(error) => return common::omp_hook_failure(&error),
    };
    post.fire(db);
    crate::delivery_policy::warn_unheld_roles(db);
    log_info(
        "hooks",
        "omp-start.bind",
        &format!("instance={instance_name} session_id={session_id}"),
    );
    crate::relay::worker::ensure_worker(true);

    let response = serde_json::json!({
        "name": instance_name,
        "session_id": session_id,
        "bootstrap": bootstrap_for(ctx, db, &instance_name),
    });
    (0, response.to_string())
}

/// `omp-role --name <n> --session-id <sid> --role <r>`: add-only delivery
/// role registration (crate::delivery_policy::register_role). The plugin
/// sends it once per binding when the omp session carries conductor-guard's
/// `conductor-role` marker. It is a separate hook rather than an `omp-start`
/// flag because the marker can land after the session_start bind, and an
/// older binary answers an unknown hook with an error instead of failing the
/// bind.
pub(crate) fn handle_role(db: &HcomDb, argv: &[String]) -> (i32, String) {
    let (Some(name), Some(session_id), Some(role)) = (
        parse_flag(argv, "--name"),
        parse_flag(argv, "--session-id"),
        parse_flag(argv, "--role"),
    ) else {
        return (
            0,
            r#"{"error":"Missing --name, --session-id or --role"}"#.to_string(),
        );
    };
    // `transient` tells the plugin to retry (locked DB); any other error is
    // final and the plugin stops asking for this binding.
    match crate::delivery_policy::register_role(db, &name, &session_id, &role) {
        Ok(()) => (0, serde_json::json!({"ok": true, "role": role}).to_string()),
        Err(error) => (
            0,
            serde_json::json!({"error": error.message, "transient": error.transient}).to_string(),
        ),
    }
}

pub(crate) fn handle_status(db: &HcomDb, argv: &[String]) -> (i32, String) {
    let name = match parse_flag(argv, "--name") {
        Some(n) => n,
        None => return (0, r#"{"error":"Missing --name or --status"}"#.to_string()),
    };
    let status = match parse_flag(argv, "--status") {
        Some(s) => s,
        None => return (0, r#"{"error":"Missing --name or --status"}"#.to_string()),
    };
    let context = parse_flag(argv, "--context").unwrap_or_default();
    let detail = parse_flag(argv, "--detail").unwrap_or_default();
    let was_listening = db
        .get_instance_full(&name)
        .ok()
        .flatten()
        .is_some_and(|inst| inst.status == ST_LISTENING);

    lifecycle::set_status(
        db,
        &name,
        &status,
        &context,
        lifecycle::StatusUpdate {
            detail: &detail,
            ..Default::default()
        },
    );
    if status == ST_LISTENING && !was_listening {
        crate::notify::wake(db, &name, &[]);
    }
    (0, r#"{"ok":true}"#.to_string())
}

fn handle_read(db: &HcomDb, argv: &[String]) -> (i32, String) {
    let name = match parse_flag(argv, "--name") {
        Some(n) => n,
        None => return (0, r#"{"error":"Missing --name"}"#.to_string()),
    };
    let format_mode = has_flag(argv, "--format");
    let check_mode = has_flag(argv, "--check");
    let ack_mode = has_flag(argv, "--ack");

    let raw_messages = db.get_unread_messages(&name);
    let messages: Vec<Value> = raw_messages.iter().map(common::message_to_value).collect();

    if format_mode {
        if messages.is_empty() {
            return (0, String::new());
        }
        let deliver = common::limit_delivery_messages(&messages);
        return (
            0,
            common::format_messages_json_for_instance(db, &deliver, &name),
        );
    }
    if ack_mode {
        if let Some(up_to) = parse_flag(argv, "--up-to") {
            let Ok(ack_id) = up_to.parse::<i64>() else {
                return (
                    0,
                    serde_json::json!({"error": format!("Invalid --up-to: {}", up_to)}).to_string(),
                );
            };
            let mut updates = serde_json::Map::new();
            updates.insert("last_event_id".into(), serde_json::json!(ack_id));
            instances::update_instance_position(db, &name, &updates);
            return (0, serde_json::json!({"acked_to": ack_id}).to_string());
        }
        if messages.is_empty() {
            return (0, r#"{"acked":0}"#.to_string());
        }
        let ack_id = messages
            .iter()
            .filter_map(|m| m.get("event_id").and_then(|v| v.as_i64()))
            .max()
            .filter(|id| *id > 0)
            .unwrap_or_else(|| db.get_last_event_id());
        if ack_id > 0 {
            let mut updates = serde_json::Map::new();
            updates.insert("last_event_id".into(), serde_json::json!(ack_id));
            instances::update_instance_position(db, &name, &updates);
        }
        return (0, serde_json::json!({"acked": messages.len()}).to_string());
    }
    if check_mode {
        return (
            0,
            if messages.is_empty() { "false" } else { "true" }.to_string(),
        );
    }
    (
        0,
        serde_json::to_string(&messages).unwrap_or_else(|_| "[]".to_string()),
    )
}

fn handle_beforetool(db: &HcomDb, argv: &[String]) -> (i32, String) {
    let name = match parse_flag(argv, "--name") {
        Some(n) => n,
        None => return (0, r#"{"decision":"allow"}"#.to_string()),
    };
    let tool_name = parse_flag(argv, "--tool").unwrap_or_default();
    let input = parse_flag(argv, "--input-json")
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if !tool_name.is_empty() {
        common::update_tool_status(db, &name, "omp", &tool_name, &input);
    }
    (0, r#"{"decision":"allow"}"#.to_string())
}

/// `omp-stop`: `--soft` keeps the row and process binding (the omp owner's
/// session_shutdown ahead of /restart, which execs the same pid and rebinds).
/// Without it the row is fully released on Linux. Off Linux nothing can see
/// the session's other carriers, so the row is soft-stopped as with `--soft`
/// instead, and a row already inactive is left as is.
///
/// omp-stop is only ever invoked by the omp session on itself, so the
/// caller's ancestry (this hcom child -> omp -> pty wrapper -> terminal) is
/// the exiting session's own tree: it is excluded from the stop's signals.
/// Every other carrier (tool subprocesses, MCP/LSP servers) is still reaped,
/// and a survivor still blocks the release.
pub(crate) fn handle_stop(db: &HcomDb, argv: &[String]) -> (i32, String) {
    let name = match parse_flag(argv, "--name") {
        Some(n) => n,
        None => return (0, r#"{"error":"Missing --name"}"#.to_string()),
    };
    let reason = parse_flag(argv, "--reason").unwrap_or_else(|| "unknown".to_string());
    if has_flag(argv, "--soft") {
        common::soft_finalize_session(db, &name, &reason, None, true);
        (0, r#"{"ok":true,"soft":true}"#.to_string())
    } else {
        common::finalize_session_excluding(
            db,
            &name,
            &reason,
            None,
            &crate::proctruth::caller_ancestor_pids(),
        );
        (0, r#"{"ok":true}"#.to_string())
    }
}

pub fn dispatch_omp_hook(hook_name: &str, argv: &[String]) -> (i32, String) {
    let start = Instant::now();
    let mut ctx = HcomContext::from_os();
    // This dispatcher is authoritative about its presenter even when an
    // inherited HCOM_TOOL points at a different tool.
    ctx.tool = crate::tool::Tool::Omp;
    crate::paths::ensure_hcom_directories_at(&ctx.hcom_dir);
    let db = match HcomDb::open() {
        Ok(db) => db,
        Err(e) => {
            log_error(
                "hooks",
                "hook.error",
                &format!("hook={} op=db_open err={}", hook_name, e),
            );
            // Transient: the plugin retries (e.g. `omp-role` after a busy
            // or briefly unavailable database).
            return (
                0,
                serde_json::json!({"error": format!("DB open failed: {}", e), "transient": true})
                    .to_string(),
            );
        }
    };
    let handler_argv: Vec<String> = if !argv.is_empty() && argv[0] == hook_name {
        argv[1..].to_vec()
    } else {
        argv.to_vec()
    };
    let caller_owner = match common::omp_hook_caller_gate(&ctx, &db, hook_name, &handler_argv) {
        Ok(owner) => owner,
        Err(refusal) => return refusal,
    };
    if caller_owner.is_none() {
        // Unknown hooks retain the existing protected-name/activity behavior.
        if let Some(refusal) = common::protected_hook_name_refusal(&db, &handler_argv) {
            return refusal;
        }
        if !common::hook_gate_check(&mut ctx, &db) {
            return (0, String::new());
        }
    } else {
        // The authenticated owner already proves this presented identity.
        // Only a launcher UUID can additionally substantiate a launch claim.
        ctx.is_launched = ctx.is_launched
            && common::omp_hook_process_id(&ctx)
                .is_some_and(crate::proctruth::is_launcher_process_id);
    }
    let hook_name_owned = hook_name.to_string();
    let handler_start = Instant::now();
    let (exit_code, output) = common::dispatch_with_panic_guard(
        "omp",
        &hook_name_owned,
        (
            0,
            serde_json::json!({"error": "internal panic"}).to_string(),
        ),
        || match hook_name_owned.as_str() {
            "omp-start" => handle_start(
                &ctx,
                &db,
                &handler_argv,
                caller_owner
                    .as_ref()
                    .expect("recognized start has a caller owner"),
            ),
            "omp-status" => handle_status(&db, &handler_argv),
            "omp-read" => handle_read(&db, &handler_argv),
            "omp-beforetool" => handle_beforetool(&db, &handler_argv),
            "omp-stop" => handle_stop(&db, &handler_argv),
            "omp-role" => handle_role(&db, &handler_argv),
            _ => (
                0,
                serde_json::json!({"error": format!("Unknown Omp hook: {}", hook_name_owned)})
                    .to_string(),
            ),
        },
    );
    log_info(
        "hooks",
        "omp.dispatch.timing",
        &format!(
            "hook={} handler_ms={:.2} total_ms={:.2} exit_code={}",
            hook_name,
            handler_start.elapsed().as_secs_f64() * 1000.0,
            start.elapsed().as_secs_f64() * 1000.0,
            exit_code
        ),
    );
    (exit_code, output)
}
