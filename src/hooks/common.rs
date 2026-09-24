//! Shared hook functions — deliver, poll, bind, bootstrap, finalize.

use std::collections::BTreeSet;
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rusqlite::params;
use serde_json::Value;

use crate::bootstrap;
use crate::db::{HcomDb, InstanceRow, Message};
use crate::identity;
use crate::instance_lifecycle as lifecycle;
use crate::instances;
use crate::log;
use crate::messages;
use crate::shared::constants::{BIND_MARKER_RE, MAX_MESSAGES_PER_DELIVERY};
use crate::shared::context::HcomContext;
use crate::shared::{ST_ACTIVE, ST_INACTIVE, ST_LISTENING};

/// Run a hook handler with panic safety.
///
/// Catches panics in the handler closure, logs them, and returns the fallback
/// value instead of crashing the host process. Used by all tool dispatchers.
pub(crate) fn dispatch_with_panic_guard<R>(
    tool: &str,
    hook_name: &str,
    fallback: R,
    f: impl FnOnce() -> R,
) -> R {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => {
            log::log_error(
                "hooks",
                &format!("{tool}.dispatch.panic"),
                &format!("hook={hook_name}"),
            );
            fallback
        }
    }
}

/// Commands auto-approved in tool permission rules (Claude/Gemini/Codex settings).
///
/// Included: read-only queries, messaging, and session lifecycle commands that
/// agents need to run without user approval prompts.
/// Excluded: `stop`, `kill`, `run`, `reset` — these are destructive or
/// admin-level and require explicit user approval.
pub(crate) const SAFE_HCOM_COMMANDS: &[&str] = &[
    "send",
    "start",
    "help",
    "--help",
    "-h",
    "list",
    "events",
    "listen",
    "relay",
    "config",
    "transcript",
    "archive",
    "bundle",
    "status",
    "term",
    "hooks",
    "--version",
    "-v",
    "--new-terminal",
];

/// Pre-gate check: should hooks proceed?
///
///
/// - HCOM-launched (process_id or is_launched) → always proceed
/// - Otherwise: check if DB has any instances → if not, skip (exit 0, empty output)
///
/// This prevents outputting hints/errors when hcom is installed but not actively used.
pub fn hook_gate_check(ctx: &mut HcomContext, db: &HcomDb) -> bool {
    // Sanitize once before the gate reads identity. The context's presenter
    // tool selects OMP's strict proof or the other hooks' carriage rule.
    ctx.trust_process_id(db);
    if ctx.process_id.is_some() || ctx.is_launched {
        return true;
    }
    // Check if any instances exist — distinguish "no rows" from DB error
    match db
        .conn()
        .query_row("SELECT 1 FROM instances LIMIT 1", [], |_| Ok(()))
    {
        Ok(()) => true,
        Err(rusqlite::Error::QueryReturnedNoRows) => false,
        Err(e) => {
            log::log_warn(
                "hooks",
                "gate.db_error",
                &format!("hook gate DB check failed: {e}, proceeding anyway"),
            );
            true // On DB error, proceed rather than silently disabling hooks
        }
    }
}

/// Convert a db::Message to a serde_json::Value object.
pub(crate) fn message_to_value(m: &Message) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("from".into(), Value::String(m.from.clone()));
    obj.insert("message".into(), Value::String(m.text.clone()));
    if let Some(ref intent) = m.intent {
        obj.insert("intent".into(), Value::String(intent.clone()));
    }
    if let Some(ref thread) = m.thread {
        obj.insert("thread".into(), Value::String(thread.clone()));
    }
    if let Some(id) = m.event_id {
        obj.insert("event_id".into(), serde_json::json!(id));
    }
    if let Some(ref ts) = m.timestamp {
        obj.insert("timestamp".into(), Value::String(ts.clone()));
    }
    if let Some(ref delivered_to) = m.delivered_to {
        obj.insert("delivered_to".into(), serde_json::json!(delivered_to));
    }
    if let Some(ref bundle_id) = m.bundle_id {
        obj.insert("bundle_id".into(), Value::String(bundle_id.clone()));
    }
    Value::Object(obj)
}

/// Load config hints string (from instance-level or global config).
/// Call once per hook invocation and pass to format functions.
pub(crate) fn load_config_hints() -> String {
    crate::config::HcomConfig::load(None)
        .map(|c| c.hints.clone())
        .unwrap_or_default()
}

/// Build instance-data lookup function for message formatting.
pub(crate) fn make_instance_lookup(db: &HcomDb) -> impl Fn(&str) -> Option<Value> + '_ {
    |name: &str| db.get_instance(name).ok().flatten()
}

/// Build a tip-tracking callback for hook message formatting.
pub(crate) fn make_tip_checker(db: &HcomDb) -> impl Fn(&str, &str) -> (bool, Box<dyn Fn()>) + '_ {
    move |instance_name: &str, tip_key: &str| {
        let seen = crate::core::tips::has_seen_tip(db, instance_name, tip_key);
        let db_path = db.path().to_path_buf();
        let instance_name = instance_name.to_string();
        let tip_key = tip_key.to_string();
        let mark = Box::new(move || {
            if let Ok(mark_db) = HcomDb::open_at(&db_path) {
                crate::core::tips::mark_tip_seen(&mark_db, &instance_name, &tip_key);
            }
        }) as Box<dyn Fn()>;
        (seen, mark)
    }
}

/// Prepared delivery — messages formatted but cursor not yet advanced.
///
/// Used by tools that need to ensure stdout write succeeds before committing.
pub struct PreparedDelivery {
    pub messages: Vec<Value>,
    pub formatted: String,
    pub ack: super::DeliveryAck,
}

/// Options for [`assemble_gemini_family_lifecycle_outputs`].
pub(crate) struct GeminiFamilyLifecycleOpts {
    /// BeforeAgent only: return wake-only context when agy has no pending messages.
    pub allow_wake_no_pending: bool,
    /// Set instance status to active/prompt when there are no pending messages.
    /// Should be true only for BeforeAgent; false for AfterTool (which fires mid-turn
    /// after every tool call and must not overwrite the current in-progress status).
    pub set_status_on_empty: bool,
}

/// Combined lifecycle hook text + optional deferred ack / early wake-only return.
pub(crate) struct GeminiFamilyLifecycleOutput {
    pub parts: Vec<String>,
    pub delivery_ack: Option<super::DeliveryAck>,
    pub early_wake_context: Option<String>,
}

/// Shared beforeagent/aftertool output assembly for Gemini and Antigravity.
pub(crate) fn assemble_gemini_family_lifecycle_outputs(
    db: &HcomDb,
    ctx: &HcomContext,
    instance: &InstanceRow,
    is_agy: bool,
    opts: GeminiFamilyLifecycleOpts,
) -> GeminiFamilyLifecycleOutput {
    let instance_name = &instance.name;
    let mut parts: Vec<String> = Vec::new();
    let mut delivery_ack = None;

    if is_agy {
        // agy gets one short anti-stall preamble before each delivery (see
        // ANTIGRAVITY_DELIVERY_ACTION). On an empty wake it gets nothing and
        // simply ends its turn — no discovery prompt is needed.
        if let Some(prepared) = prepare_pending_messages(db, instance_name) {
            parts.push(bootstrap::ANTIGRAVITY_DELIVERY_ACTION.to_string());
            parts.push(prepared.formatted);
            delivery_ack = Some(prepared.ack);
        } else if opts.allow_wake_no_pending && instance.name_announced != 0 {
            return GeminiFamilyLifecycleOutput {
                parts: vec![],
                delivery_ack: None,
                early_wake_context: None,
            };
        }
        if let Some(bootstrap) =
            inject_bootstrap_once(db, ctx, instance_name, instance, &instance.tool)
        {
            parts.push(bootstrap);
        }
    } else {
        if let Some(bootstrap) =
            inject_bootstrap_once(db, ctx, instance_name, instance, &instance.tool)
        {
            parts.push(bootstrap);
        }
        if let Some(prepared) = prepare_pending_messages(db, instance_name) {
            parts.push(prepared.formatted);
            delivery_ack = Some(prepared.ack);
        } else if opts.set_status_on_empty {
            lifecycle::set_status(db, instance_name, ST_ACTIVE, "prompt", Default::default());
        }
    }

    GeminiFamilyLifecycleOutput {
        parts,
        delivery_ack,
        early_wake_context: None,
    }
}

pub(crate) fn limit_delivery_messages(messages: &[Value]) -> Vec<Value> {
    if messages.len() > MAX_MESSAGES_PER_DELIVERY {
        messages[..MAX_MESSAGES_PER_DELIVERY].to_vec()
    } else {
        messages.to_vec()
    }
}

pub(crate) fn format_messages_json_for_instance(
    db: &HcomDb,
    messages: &[Value],
    instance_name: &str,
) -> String {
    let get_instance_data = make_instance_lookup(db);
    let hints = load_config_hints();
    let get_config_hints = || hints.clone();
    let tip_checker = make_tip_checker(db);
    messages::format_messages_json(
        messages,
        instance_name,
        &get_instance_data,
        &get_config_hints,
        Some(&tip_checker),
    )
}

pub(crate) fn format_hook_messages_for_instance(
    db: &HcomDb,
    messages: &[Value],
    instance_name: &str,
) -> String {
    let get_instance_data = make_instance_lookup(db);
    let hints = load_config_hints();
    let get_config_hints = || hints.clone();
    messages::format_hook_messages(
        messages,
        instance_name,
        &get_instance_data,
        &get_config_hints,
        None,
    )
}

/// Prepare pending messages for delivery without committing cursor advance.
///
/// Returns formatted text + ack token. Caller must call `commit_delivery_ack`
/// after the output is successfully written (e.g. stdout flush).
pub fn prepare_pending_messages(db: &HcomDb, instance_name: &str) -> Option<PreparedDelivery> {
    let raw_messages = db.get_unread_messages(instance_name);
    prepare_raw_messages(db, instance_name, raw_messages)
}

/// Commit a deferred delivery ack — advance cursor and set status.
pub fn commit_delivery_ack(db: &HcomDb, ack: &super::DeliveryAck) {
    let mut updates = serde_json::Map::new();
    updates.insert("last_event_id".into(), serde_json::json!(ack.last_event_id));
    if ack.mark_announced {
        updates.insert("name_announced".into(), serde_json::json!(true));
    }
    instances::update_instance_position(db, &ack.instance_name, &updates);

    lifecycle::set_status(
        db,
        &ack.instance_name,
        ST_ACTIVE,
        &ack.status_context,
        lifecycle::StatusUpdate {
            msg_ts: &ack.msg_ts,
            ..Default::default()
        },
    );
}

/// Prepare raw messages into a PreparedDelivery without committing cursor/status.
///
/// Cursor advance and status update are deferred to `commit_delivery_ack`.
fn prepare_raw_messages(
    db: &HcomDb,
    instance_name: &str,
    raw_messages: Vec<Message>,
) -> Option<PreparedDelivery> {
    if raw_messages.is_empty() {
        return None;
    }

    let messages: Vec<Value> = raw_messages.iter().map(message_to_value).collect();
    let deliver = limit_delivery_messages(&messages);
    let formatted = format_messages_json_for_instance(db, &deliver, instance_name);

    let sender = deliver
        .first()
        .and_then(|m| m.get("from").and_then(|v| v.as_str()))
        .unwrap_or("unknown");
    let sender_display = identity::get_display_name(db, sender);
    let last_id = deliver
        .last()
        .and_then(|m| m.get("event_id").and_then(|v| v.as_i64()))
        .unwrap_or(0);
    let msg_ts = deliver
        .last()
        .and_then(|m| m.get("timestamp").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    Some(PreparedDelivery {
        messages: deliver,
        formatted,
        ack: super::DeliveryAck {
            instance_name: instance_name.to_string(),
            last_event_id: last_id,
            status_context: format!("deliver:{}", sender_display),
            msg_ts,
            mark_announced: false,
        },
    })
}

/// Fetch unread messages, update cursor, set delivery status.
///
/// Returns (delivered_messages, formatted_json). Empty vec and None if no messages.
/// Callers that need additional formatting can use the returned messages vec.
///
pub fn deliver_pending_messages(db: &HcomDb, instance_name: &str) -> (Vec<Value>, Option<String>) {
    let raw_messages = db.get_unread_messages(instance_name);
    let Some(prepared) = prepare_raw_messages(db, instance_name, raw_messages) else {
        return (vec![], None);
    };
    commit_delivery_ack(db, &prepared.ack);
    (prepared.messages, Some(prepared.formatted))
}

/// Result of [`poll_messages`].
pub struct PollResult {
    /// True if a message was delivered (Stop/SubagentStop should be blocked
    /// so Claude sees `output` on its next turn instead of ending).
    pub delivered: bool,
    /// `{"decision":"block","reason":...}` when `delivered`, else `None`.
    pub output: Option<Value>,
    pub timed_out: bool,
    /// Deferred cursor/status commit. Caller must call `commit_delivery_ack`
    /// only after `output` has been successfully written to stdout — never
    /// before, since Claude only reads `output` on exit 0 and a premature
    /// commit would advance the cursor past a message Claude never saw.
    pub ack: Option<super::DeliveryAck>,
}

/// Stop hook polling loop — NOT used by main PTY path.
///
/// Runs for: headless instances, vanilla tool instances, subagent polling.
/// Main PTY path bypasses this (HCOM_PTY_MODE=1, PTY wrapper handles injection).
///
/// Uses select() on a TCP socket for efficient wake-on-message delivery.
/// Senders call `crate::notify::wake` (kind=`hook`) to wake the select().
///
/// Always exits 0: Claude ignores stdout JSON on exit 2 for Stop/SubagentStop
/// (stderr-only feedback), so a delivered message must go out as exit 0 +
/// `{"decision":"block"}` or Claude never sees it.
pub fn poll_messages(
    db: &HcomDb,
    instance_name: &str,
    timeout_secs: u64,
    is_background: bool,
) -> PollResult {
    match poll_messages_inner(db, instance_name, timeout_secs, is_background) {
        Ok(result) => result,
        Err(e) => {
            log::log_error(
                "hooks",
                "hook.error",
                &format!("hook=poll_messages err={}", e),
            );
            PollResult {
                delivered: false,
                output: None,
                timed_out: false,
                ack: None,
            }
        }
    }
}

fn poll_messages_inner(
    db: &HcomDb,
    instance_name: &str,
    timeout_secs: u64,
    is_background: bool,
) -> Result<PollResult> {
    // Check instance exists
    let instance_data = db
        .get_instance_full(instance_name)
        .context("DB error checking instance")?;
    if instance_data.is_none() {
        return Ok(PollResult {
            delivered: false,
            output: None,
            timed_out: false,
            ack: None,
        });
    }

    // Setup TCP notification socket
    let (notify_server, tcp_mode) = setup_tcp_notification(instance_name);
    let notify_port = notify_server
        .as_ref()
        .and_then(|s| s.local_addr().ok())
        .map(|a| a.port());

    // Register TCP mode
    let mut updates = serde_json::Map::new();
    updates.insert("tcp_mode".into(), serde_json::json!(tcp_mode));
    instances::update_instance_position(db, instance_name, &updates);

    // Register hook notify endpoint
    if let Some(port) = notify_port {
        register_hook_notify_port(db, instance_name, port);
    }

    // Set listening status
    lifecycle::set_status(db, instance_name, ST_LISTENING, "", Default::default());

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    let result = poll_loop(
        db,
        instance_name,
        timeout,
        start,
        is_background,
        notify_server.as_ref(),
    );

    // Cleanup: close socket, remove notify endpoint
    drop(notify_server);
    delete_hook_notify_endpoint(db, instance_name);

    result
}

fn poll_loop(
    db: &HcomDb,
    instance_name: &str,
    timeout: Duration,
    start: Instant,
    is_background: bool,
    notify_server: Option<&TcpListener>,
) -> Result<PollResult> {
    let empty = || PollResult {
        delivered: false,
        output: None,
        timed_out: false,
        ack: None,
    };
    let mut waited = false;
    while start.elapsed() < timeout {
        // Check if instance still exists (stopped = row deleted)
        let instance_data = db.get_instance_full(instance_name)?;
        if instance_data.is_none() {
            return Ok(empty());
        }

        // Poll for messages BEFORE select to catch transition gap
        let raw_messages = db.get_unread_messages(instance_name);
        if !raw_messages.is_empty() {
            // Orphan detection: don't deliver if parent died.
            // Only check after we've waited at least once — on the first iteration stdin
            // may legitimately be closed (e.g. subprocess invocation via `input=...`).
            if waited && !is_background && check_stdin_closed() {
                return Ok(empty());
            }

            if let Some(prepared) = prepare_raw_messages(db, instance_name, raw_messages) {
                // Do NOT commit the ack here — the caller must only advance
                // the cursor after `output` is actually flushed to stdout.
                // Claude discards stdout JSON on exit 2, so this must be
                // reported via exit 0 + decision:block for Claude to see it.
                let output = serde_json::json!({
                    "decision": "block",
                    "reason": prepared.formatted,
                });
                return Ok(PollResult {
                    delivered: true,
                    output: Some(output),
                    timed_out: false,
                    ack: Some(prepared.ack),
                });
            }
        }

        // Calculate remaining time
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            break;
        }
        let remaining = timeout - elapsed;

        // TCP select for notifications (or fallback poll). Relay imports
        // (pull.rs) call `crate::notify::wake_all` after every batch, so the
        // TCP wake fires as soon as remote events land — no separate relay
        // polling needed.
        let wait_time = if notify_server.is_some() {
            Duration::from_secs(remaining.as_secs().min(30))
        } else {
            Duration::from_millis(remaining.as_millis().min(100) as u64)
        };

        if let Some(server) = notify_server {
            // Block until a wake-up connection arrives instead of busy-looping
            if crate::sys::net::wait_readable(server, wait_time) {
                // Drain all pending connections
                if let Err(e) = server.set_nonblocking(true) {
                    log::log_warn(
                        "hooks",
                        "poll.nonblocking_failed",
                        &format!("set_nonblocking failed: {e}, skipping drain"),
                    );
                } else {
                    while let Ok((conn, _)) = server.accept() {
                        drop(conn);
                    }
                }
            }
        } else {
            std::thread::sleep(wait_time);
        }

        waited = true;

        // Update heartbeat (also re-asserts tcp_mode=1 for self-healing)
        let _ = db.update_heartbeat(instance_name);
    }

    // Timeout reached
    Ok(PollResult {
        delivered: false,
        output: None,
        timed_out: true,
        ack: None,
    })
}

/// Check if stdin is closed (orphan detection heuristic).
///
/// Piped stdin (normal for hook subprocess invocation) always gets POLLHUP
/// after the payload is consumed — this is NOT an orphan signal. Only check
/// POLLERR (broken pipe) and POLLNVAL (fd was closed/invalidated).
///
fn check_stdin_closed() -> bool {
    crate::sys::io::stdin_appears_broken()
}

/// Create TCP server socket for instant message wake notifications.
fn setup_tcp_notification(instance_name: &str) -> (Option<TcpListener>, bool) {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            listener.set_nonblocking(true).unwrap_or(());
            (Some(listener), true)
        }
        Err(e) => {
            log::log_error(
                "hooks",
                "hook.error",
                &format!("hook=tcp_notification instance={} err={}", instance_name, e),
            );
            (None, false)
        }
    }
}

/// Register hook notify port in DB.
fn register_hook_notify_port(db: &HcomDb, instance_name: &str, port: u16) {
    if let Err(e) = db.upsert_notify_endpoint(instance_name, "hook", port) {
        log::log_warn(
            "native",
            "hooks.register_notify_fail",
            &format!(
                "Failed to register hook notify port for {}: {}",
                instance_name, e
            ),
        );
    }
}

/// Remove hook notify endpoint from DB.
fn delete_hook_notify_endpoint(db: &HcomDb, instance_name: &str) {
    let _ = db.conn().execute(
        "DELETE FROM notify_endpoints WHERE instance = ? AND kind = 'hook'",
        params![instance_name],
    );
}

/// Find last [hcom:xxx] marker in transcript.
///
/// Reads file backwards in 64MB chunks with 70-byte overlap to find marker.
pub fn find_last_bind_marker(transcript_path: &str) -> Option<String> {
    let path = Path::new(transcript_path);
    let metadata = std::fs::metadata(path).ok()?;
    let file_size = metadata.len() as usize;

    if file_size == 0 {
        return None;
    }

    let chunk_size: usize = 64 * 1024 * 1024; // 64MB
    let overlap: usize = 70; // max prefix len (12) + max instance name (50) + margin
    let marker_prefixes: &[&[u8]] = &[b"[hcom:"];

    let mut file = std::fs::File::open(path).ok()?;

    let mut pos = file_size;
    let mut carry: Vec<u8> = Vec::new();

    while pos > 0 {
        let read_size = chunk_size.min(pos);
        pos -= read_size;

        use std::io::{Read as _, Seek, SeekFrom};
        file.seek(SeekFrom::Start(pos as u64)).ok()?;

        let mut data = vec![0u8; read_size];
        file.read_exact(&mut data).ok()?;

        // Combine data + carry for overlap handling
        let mut buf = data.clone();
        buf.extend_from_slice(&carry);

        // Find the last occurrence of any marker prefix
        let mut best_idx: Option<usize> = None;
        for prefix in marker_prefixes {
            if let Some(idx) = rfind_bytes(&buf, prefix) {
                match best_idx {
                    Some(current) if idx > current => best_idx = Some(idx),
                    None => best_idx = Some(idx),
                    _ => {}
                }
            }
        }

        if let Some(idx) = best_idx {
            // Find closing bracket
            if let Some(end_offset) = buf[idx..].iter().position(|&b| b == b']') {
                let marker_bytes = &buf[idx..idx + end_offset + 1];
                if let Ok(marker_str) = std::str::from_utf8(marker_bytes)
                    && let Some(caps) = BIND_MARKER_RE.captures(marker_str)
                {
                    return Some(caps[1].to_string());
                }
            }
        }

        // Keep overlap for next chunk
        carry = if overlap > 0 && data.len() >= overlap {
            data[..overlap].to_vec()
        } else {
            data
        };
    }

    None
}

/// Reverse search for byte pattern in buffer.
fn rfind_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&i| haystack[i..i + needle.len()] == *needle)
}

/// Inject bootstrap text if not already announced.
///
/// Idempotent — checks name_announced flag and only injects once
/// per instance lifecycle. Returns bootstrap text if injection needed,
/// None if already announced.
///
pub fn inject_bootstrap_once(
    db: &HcomDb,
    ctx: &HcomContext,
    instance_name: &str,
    instance_data: &InstanceRow,
    tool: &str,
) -> Option<String> {
    if instance_data.name_announced != 0 {
        return None;
    }

    let tag = instance_data.tag.as_deref().unwrap_or("");
    let hcom_config = crate::config::HcomConfig::load(None).unwrap_or_default();
    let relay_enabled = crate::relay::is_relay_enabled(&hcom_config);

    let bootstrap_text = bootstrap::get_bootstrap(
        db,
        &ctx.hcom_dir,
        instance_name,
        tool,
        ctx.is_background,
        ctx.is_launched,
        &ctx.notes,
        tag,
        relay_enabled,
        ctx.background_name.as_deref(),
    );

    // Mark as announced
    let mut updates = serde_json::Map::new();
    updates.insert("name_announced".into(), serde_json::json!(true));
    instances::update_instance_position(db, instance_name, &updates);

    Some(bootstrap_text)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TranscriptOwnerResolution {
    Owner(String),
    Ambiguous(Vec<String>),
    Unknown,
}

/// Resolve Claude ownership from bounded, structured transcript/session evidence.
///
/// Only envelope metadata is inspected. Ordinary message content, summaries,
/// tool output, bootstrap text, and `[hcom:name]` markers are intentionally out
/// of scope for lineage resolution.
pub(crate) fn resolve_claude_transcript_owner(
    db: &HcomDb,
    transcript_path: &str,
    incoming_session_id: Option<&str>,
) -> Result<TranscriptOwnerResolution> {
    const MAX_BYTES: usize = 512 * 1024;
    const MAX_RECORDS: usize = 2048;

    let mut owners = BTreeSet::new();
    let mut structured_session_ids = BTreeSet::new();

    let incoming_is_validated = match incoming_session_id.filter(|value| !value.is_empty()) {
        Some(session_id) => db.get_validated_claude_session_owner(session_id)?.is_some(),
        None => false,
    };
    if incoming_is_validated && let Some(session_id) = incoming_session_id {
        // A hook-provided incoming ID is only self-authenticating after a
        // trusted SessionStart or prior structured-lineage validation.
        structured_session_ids.insert(session_id.to_string());
    }

    if !transcript_path.is_empty() {
        owners.extend(db.get_instances_by_transcript_path(transcript_path)?);

        match std::fs::File::open(transcript_path) {
            Ok(file) => {
                // Head-biased by design: fork ancestry is copied into the first
                // records, and SessionStart must never stall on a huge transcript.
                let mut input = Vec::with_capacity(MAX_BYTES + 1);
                file.take((MAX_BYTES + 1) as u64).read_to_end(&mut input)?;
                let input_is_truncated = input.len() > MAX_BYTES;
                input.truncate(MAX_BYTES);
                for line in input
                    .split_inclusive(|byte| *byte == b'\n')
                    .take(MAX_RECORDS)
                {
                    // The bounded read may end in the middle of a UTF-8 code
                    // point or JSON record. Ignore only that incomplete tail
                    // rather than failing after valid earlier rows.
                    if input_is_truncated && !line.ends_with(b"\n") {
                        break;
                    }
                    let Ok(line) = std::str::from_utf8(line) else {
                        continue;
                    };
                    let Ok(value) = serde_json::from_str::<Value>(line) else {
                        continue;
                    };
                    for session_id in [
                        value.get("sessionId").and_then(Value::as_str),
                        value.get("session_id").and_then(Value::as_str),
                    ]
                    .into_iter()
                    .flatten()
                    .filter(|value| !value.is_empty())
                    {
                        // Claude rewrites top-level IDs to the new fork UUID.
                        // Until that incoming binding is validated, the same ID
                        // cannot prove its own ownership. Different top-level
                        // IDs remain useful structured ancestry evidence.
                        if incoming_session_id != Some(session_id) || incoming_is_validated {
                            structured_session_ids.insert(session_id.to_string());
                        }
                    }
                    if let Some(session_id) = value
                        .get("message")
                        .and_then(|message| message.get("session_id"))
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                    {
                        // Envelope message.session_id is independent structured
                        // provenance and may legitimately equal the current ID.
                        structured_session_ids.insert(session_id.to_string());
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    for session_id in structured_session_ids {
        if let Some(owner) = db.get_session_binding(&session_id)? {
            owners.insert(owner);
        }
    }

    Ok(match owners.len() {
        0 => TranscriptOwnerResolution::Unknown,
        1 => TranscriptOwnerResolution::Owner(owners.into_iter().next().unwrap()),
        _ => TranscriptOwnerResolution::Ambiguous(owners.into_iter().collect()),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeIdentityEvidence {
    pub process_binding: Option<(Option<String>, String)>,
    pub process_session_id: Option<String>,
    pub process_owner: Option<String>,
    pub session_owner: Option<String>,
    pub validated_session_owner: Option<String>,
    pub owners_disagree: bool,
    pub lineage_scanned: bool,
    pub lineage: TranscriptOwnerResolution,
}

/// Load the identity facts shared by SessionStart and ordinary Claude hooks.
///
/// The caller supplies only the lineage-scan policy; owner selection remains
/// local to each resolution path.
pub(crate) fn load_claude_identity_evidence(
    db: &HcomDb,
    process_id: Option<&str>,
    session_id: &str,
    transcript_path: &str,
    should_scan_lineage: impl FnOnce(&ClaudeIdentityEvidence) -> bool,
) -> Result<ClaudeIdentityEvidence> {
    let process_binding = match process_id.filter(|value| !value.is_empty()) {
        Some(process_id) => db.get_process_binding_full(process_id)?,
        None => None,
    };
    let process_session_id = process_binding
        .as_ref()
        .and_then(|(session_id, _)| session_id.clone());
    let process_owner = process_binding
        .as_ref()
        .map(|(_, instance_name)| instance_name.clone());
    let session_owner = if session_id.is_empty() {
        None
    } else {
        db.get_session_binding(session_id)?
    };
    let validated_session_owner = if session_id.is_empty() {
        None
    } else {
        db.get_validated_claude_session_owner(session_id)?
    };
    let owners_disagree = matches!(
        (&process_owner, &session_owner),
        (Some(process_owner), Some(session_owner)) if process_owner != session_owner
    );

    let mut evidence = ClaudeIdentityEvidence {
        process_binding,
        process_session_id,
        process_owner,
        session_owner,
        validated_session_owner,
        owners_disagree,
        lineage_scanned: false,
        lineage: TranscriptOwnerResolution::Unknown,
    };
    evidence.lineage_scanned = should_scan_lineage(&evidence);
    if evidence.lineage_scanned {
        evidence.lineage = resolve_claude_transcript_owner(
            db,
            transcript_path,
            (!session_id.is_empty()).then_some(session_id),
        )?;
    }
    Ok(evidence)
}

/// Initialize instance context from hook data via binding lookup.
///
/// Structured session/transcript identity wins over a conflicting process
/// binding. Transcript scanning stays off the common hot path: it runs only
/// when the session is unbound or its binding has not yet been validated.
///
/// Returns (instance_name, metadata_updates, is_matched_resume).
pub fn init_hook_context(
    db: &HcomDb,
    ctx: &HcomContext,
    session_id: &str,
    transcript_path: &str,
) -> (Option<String>, serde_json::Map<String, Value>, bool) {
    let start = Instant::now();
    let evidence = match load_claude_identity_evidence(
        db,
        ctx.process_id.as_deref(),
        session_id,
        transcript_path,
        |evidence| {
            let binding_needs_validation = evidence.session_owner.is_some()
                && evidence.validated_session_owner.as_ref() != evidence.session_owner.as_ref();
            evidence.session_owner.is_none() || binding_needs_validation
        },
    ) {
        Ok(evidence) => evidence,
        Err(error) => {
            log::log_warn(
                "hooks",
                "init_hook_context.identity_evidence_error",
                &format!(
                    "session_id={} transcript_path={} process_id={:?} err={}",
                    session_id, transcript_path, ctx.process_id, error
                ),
            );
            return (None, serde_json::Map::new(), false);
        }
    };
    let evidence_ms = start.elapsed().as_secs_f64() * 1000.0;
    let historical_process_binding = evidence
        .process_session_id
        .as_deref()
        .filter(|bound_session_id| !bound_session_id.is_empty())
        .is_some_and(|bound_session_id| bound_session_id != session_id);

    let mut instance_name = if let Some(validated_owner) = evidence.validated_session_owner.clone()
    {
        Some(validated_owner)
    } else if evidence.lineage_scanned {
        match &evidence.lineage {
            TranscriptOwnerResolution::Owner(owner) => Some(owner.clone()),
            TranscriptOwnerResolution::Ambiguous(owners) => {
                log::log_warn(
                    "hooks",
                    "init_hook_context.identity_ambiguous",
                    &format!(
                        "session_id={} transcript_path={} process_id={:?} process_owner={:?} session_owner={:?} transcript_owners={:?}",
                        session_id,
                        transcript_path,
                        ctx.process_id,
                        evidence.process_owner,
                        evidence.session_owner,
                        owners,
                    ),
                );
                None
            }
            TranscriptOwnerResolution::Unknown => {
                if evidence.session_owner.is_some() {
                    log::log_warn(
                        "hooks",
                        "init_hook_context.unvalidated_session_rejected",
                        &format!(
                            "session_id={} transcript_path={} process_id={:?} process_owner={:?} session_owner={:?}",
                            session_id,
                            transcript_path,
                            ctx.process_id,
                            evidence.process_owner,
                            evidence.session_owner,
                        ),
                    );
                    None
                } else if historical_process_binding {
                    log::log_warn(
                        "hooks",
                        "init_hook_context.historical_process_rejected",
                        &format!(
                            "session_id={} transcript_path={} process_id={:?} process_session_id={:?} process_owner={:?}",
                            session_id,
                            transcript_path,
                            ctx.process_id,
                            evidence.process_session_id,
                            evidence.process_owner,
                        ),
                    );
                    None
                } else {
                    evidence.process_owner.clone()
                }
            }
        }
    } else {
        evidence
            .session_owner
            .clone()
            .or_else(|| evidence.process_owner.clone())
    };

    if instance_name.is_none()
        && !matches!(&evidence.lineage, TranscriptOwnerResolution::Ambiguous(_))
        && evidence.session_owner.is_none()
        && evidence.process_owner.is_none()
    {
        instance_name = try_bind_from_transcript(db, session_id, transcript_path);
    }
    let Some(name) = instance_name else {
        log::log_info(
            "hooks",
            "init_hook_context.timing",
            &format!(
                "evidence_ms={:.2} total_ms={:.2} result=no_instance owners_disagree={}",
                evidence_ms,
                start.elapsed().as_secs_f64() * 1000.0,
                evidence.owners_disagree
            ),
        );
        return (None, serde_json::Map::new(), false);
    };

    let mut updates = serde_json::Map::new();
    updates.insert(
        "directory".into(),
        Value::String(ctx.cwd.to_string_lossy().to_string()),
    );
    if !transcript_path.is_empty() {
        updates.insert(
            "transcript_path".into(),
            Value::String(transcript_path.to_string()),
        );
    }
    if ctx.is_background
        && let Some(ref bg_name) = ctx.background_name
    {
        updates.insert("background".into(), serde_json::json!(true));
        let log_file = ctx.hcom_dir.join(".tmp").join("logs").join(bg_name);
        updates.insert(
            "background_log_file".into(),
            Value::String(log_file.to_string_lossy().to_string()),
        );
    }

    let instance = db.get_instance_full(&name).ok().flatten();
    let is_matched_resume = !session_id.is_empty()
        && instance
            .as_ref()
            .is_some_and(|data| data.session_id.as_deref() == Some(session_id));

    if is_matched_resume
        && matches!(&evidence.lineage, TranscriptOwnerResolution::Owner(owner) if owner == &name)
        && evidence.session_owner.as_deref() == Some(name.as_str())
        && let Err(error) = db.mark_claude_session_validated(session_id, &name)
    {
        log::log_warn(
            "hooks",
            "init_hook_context.validation_cache_write_failed",
            &format!("session_id={} owner={} err={}", session_id, name, error),
        );
    }

    if evidence.lineage_scanned
        && matches!(&evidence.lineage, TranscriptOwnerResolution::Owner(owner) if owner == &name)
        && !is_matched_resume
    {
        log::log_warn(
            "hooks",
            "init_hook_context.unpromoted_lineage_rejected",
            &format!(
                "session_id={} owner={} primary_session={:?} total_ms={:.2}",
                session_id,
                name,
                instance.as_ref().and_then(|row| row.session_id.as_deref()),
                start.elapsed().as_secs_f64() * 1000.0,
            ),
        );
        return (None, serde_json::Map::new(), false);
    }

    log::log_info(
        "hooks",
        "init_hook_context.timing",
        &format!(
            "instance={} evidence_ms={:.2} total_ms={:.2} validated={} owners_disagree={}",
            name,
            evidence_ms,
            start.elapsed().as_secs_f64() * 1000.0,
            evidence.validated_session_owner.is_some(),
            evidence.owners_disagree,
        ),
    );

    (Some(name), updates, is_matched_resume)
}

/// Transcript marker fallback binding.
///
/// Searches transcript for [hcom:name] marker and creates session binding
/// if instance is pending. Fast path: skips file I/O if no pending instances.
///
fn try_bind_from_transcript(
    db: &HcomDb,
    session_id: &str,
    transcript_path: &str,
) -> Option<String> {
    if transcript_path.is_empty() || session_id.is_empty() {
        return None;
    }

    // Fast path: skip file I/O if no pending instances
    let pending = get_pending_instances(db);
    if pending.is_empty() {
        return None;
    }

    let instance_name = find_last_bind_marker(transcript_path)?;

    // Only bind if instance is in pending list
    if !pending.contains(&instance_name) {
        log::log_info(
            "hooks",
            "transcript.bind.skip",
            &format!("instance={} not in pending={:?}", instance_name, pending),
        );
        return None;
    }

    // Verify instance exists
    let instance = db.get_instance_full(&instance_name).ok()??;
    let _ = instance; // just checking existence

    // Create binding
    if let Err(e) = db.rebind_instance_session(&instance_name, session_id) {
        log::log_error(
            "hooks",
            "transcript.bind.error",
            &format!("instance={} err={}", instance_name, e),
        );
        return None;
    }

    let mut updates = serde_json::Map::new();
    updates.insert("session_id".into(), Value::String(session_id.to_string()));
    instances::update_instance_position(db, &instance_name, &updates);
    if let Err(error) = db.mark_claude_session_validated(session_id, &instance_name) {
        log::log_warn(
            "hooks",
            "transcript.bind.validation_cache_failed",
            &format!("instance={} err={}", instance_name, error),
        );
    }

    log::log_info(
        "hooks",
        "transcript.bind.success",
        &format!("instance={}", instance_name),
    );

    Some(instance_name)
}

/// Get instances pending session binding (session_id IS NULL, non-adhoc).
///
/// "Pending" means the instance was created (e.g., by launcher) but hasn't
/// been bound to a tool session yet. Used as fast-path optimization before
/// doing expensive transcript marker search.
///
pub fn get_pending_instances(db: &HcomDb) -> Vec<String> {
    // Purge leaked launch placeholders before treating them as bindable.
    // Otherwise an old transcript marker can silently re-bind a stale row.
    lifecycle::cleanup_stale_placeholders(db);
    let mut stmt = match db.conn().prepare(
        "SELECT name FROM instances WHERE session_id IS NULL AND tool != 'adhoc' ORDER BY created_at DESC",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    stmt.query_map([], |row| row.get::<_, String>(0))
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
}

/// Wake an instance's hook poll loop via TCP connection.
///
/// Best-effort: opens DB, finds hook wake endpoint, sends brief TCP connect.
/// Wraps `crate::notify::wake` with kind=`hook` for the hook poll path —
/// PTY/listen wakes go through `crate::notify::wake` directly.
///
pub fn notify_hook_instance(instance_name: &str) {
    if let Ok(db) = HcomDb::open() {
        notify_hook_instance_with_db(&db, instance_name);
    }
}

/// Wake hook poll loop with an existing DB handle.
pub fn notify_hook_instance_with_db(db: &HcomDb, instance_name: &str) {
    crate::notify::wake(db, instance_name, &[crate::notify::WakeKind::Hook]);
}

/// Stop instance: log snapshot, clean bindings, delete row.
///
/// Handles: snapshot capture, session/process/notify/subscription cleanup,
/// life event logging, and instance deletion.
pub fn stop_instance(
    db: &HcomDb,
    instance_name: &str,
    initiated_by: &str,
    reason: &str,
) -> StopOutcome {
    stop_instance_inner(
        db,
        instance_name,
        initiated_by,
        reason,
        false,
        0,
        true,
        &[],
        None,
    )
}
pub(crate) fn stop_instance_with_capture(
    db: &HcomDb,
    instance_name: &str,
    initiated_by: &str,
    reason: &str,
    capture: crate::proctruth::ReapCapture,
) -> StopOutcome {
    stop_instance_inner(
        db,
        instance_name,
        initiated_by,
        reason,
        false,
        0,
        true,
        &[],
        Some(capture),
    )
}

/// External side effects of a stop: subscription notifications, listener
/// wakes, relay push. On the standalone path they fire inline, exactly as
/// they always have. On the kill path the whole teardown shares one
/// transaction, so they queue here and [`Self::fire`] runs them right after
/// that single commit — never before the writes are durable.
#[derive(Default)]
struct PostCommit {
    /// `(event_id, instance, event_data)` per `stopped` event written.
    events: Vec<(i64, String, serde_json::Value)>,
    wake_ports: Vec<u16>,
    push: bool,
}

impl PostCommit {
    fn fire(&self, db: &HcomDb) {
        for (event_id, instance, event_data) in &self.events {
            crate::db::subscriptions::process_logged_event(
                db, *event_id, "life", instance, event_data,
            );
        }
        if !self.wake_ports.is_empty() {
            crate::notify::wake_ports(&self.wake_ports, crate::notify::WAKE_TARGETED_MS);
        }
        if self.push {
            crate::relay::spawn_background_push();
        }
    }
}

/// Stop instance without the process-truth reap gate — the kill path's
/// teardown, gated and atomic. The full [`stop_instance`] DB teardown
/// (snapshot, children, `stopped` event, release) with no signals.
///
/// `unchanged` is the kill's incarnation gate. It runs INSIDE the single
/// `BEGIN IMMEDIATE` transaction that also carries every teardown write
/// (children first, then this row's `stopped` event and release), so a
/// re-registration can never land between the check and the use: it either
/// serializes before the transaction — `unchanged` reads it, NOTHING is
/// written, and the call returns `false` (the row left intact for the fresh
/// incarnation) — or it lands after the commit. On `true`, the whole
/// teardown (children, `stopped` event, release, capability revocation)
/// committed as one unit and the external side effects fire right after.
/// Any error rolls the whole teardown back and returns `Err`.
///
/// The `kill` command owns every call (self and foreign paths): it reaps the
/// carrier set itself and verifies it gone BEFORE this teardown runs
/// (survivors bail the kill with the row and bindings untouched — fail-closed,
/// so the `stopped` write never lands while an instance process may still be
/// alive), and it tears down only the one binding epoch it resolved against.
/// The self path additionally needs the reap gate off because the caller is
/// itself a carrier, and the reap gate's headless group kill would land on
/// the caller's own session tree.
pub fn stop_instance_without_reap(
    db: &HcomDb,
    instance_name: &str,
    initiated_by: &str,
    reason: &str,
    unchanged: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<bool>,
) -> Result<bool, String> {
    let queued = db
        .with_immediate_transaction(|tx| -> Result<Option<PostCommit>> {
            if !unchanged(tx)? {
                return Ok(None);
            }
            let mut post = PostCommit::default();
            match stop_instance_inner_scoped(
                db,
                instance_name,
                initiated_by,
                reason,
                false,
                0,
                false,
                Some(tx),
                &mut post,
                &[],
                None,
            ) {
                StopOutcome::Stopped | StopOutcome::AlreadyStopped => {}
                StopOutcome::RetryableError(e) => anyhow::bail!("{e}"),
            }
            Ok(Some(post))
        })
        .map_err(|e| e.to_string())?;
    match queued {
        Some(post) => {
            post.fire(db);
            Ok(true)
        }
        None => Ok(false),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    Stopped,
    AlreadyStopped,
    RetryableError(StopError),
}

impl StopOutcome {
    /// The stop left the row alone because it is another incarnation now: a
    /// session re-registered the name mid-stop. Not stopped, and not a
    /// failure to retry against the new row.
    pub fn is_re_registered(&self) -> bool {
        matches!(self, Self::RetryableError(error) if error.re_registered)
    }
}

/// Why a stop left the row in place. Displays as its message. Only the
/// incarnation guard constructs the re-registration case, through
/// [`StopError::re_registered`]; everything else converts from a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopError {
    message: String,
    re_registered: bool,
}

impl StopError {
    fn re_registered() -> Self {
        Self {
            message: "row re-registered during stop".to_string(),
            re_registered: true,
        }
    }
}

impl From<String> for StopError {
    fn from(message: String) -> Self {
        Self {
            message,
            re_registered: false,
        }
    }
}

impl std::fmt::Display for StopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// What a stop or kill site prints for a name whose release it skipped
/// because the row was re-registered mid-stop (see
/// [`StopOutcome::is_re_registered`]). Never "Stopped": the new row is live.
pub(crate) fn skipped_stop_line(display: &str) -> String {
    format!("{display} skipped: {}", StopError::re_registered())
}

/// Stop a stale launch placeholder bound to `capture`: the incarnation the
/// cleanup read (row plus binding epoch, one snapshot). A rebind after that
/// read is another incarnation and is left intact.
pub(crate) fn stop_placeholder_instance(
    db: &HcomDb,
    instance_name: &str,
    initiated_by: &str,
    reason: &str,
    capture: crate::proctruth::ReapCapture,
) -> StopOutcome {
    stop_instance_inner(
        db,
        instance_name,
        initiated_by,
        reason,
        true,
        0,
        true,
        &[],
        Some(capture),
    )
}

/// Max recursion depth for subagent cleanup. Prevents stack overflow if DB
/// corruption creates a parent_session_id cycle.
const MAX_STOP_DEPTH: u32 = 10;

fn child_instance_names(db: &HcomDb, column: &str, value: &str) -> Result<Vec<String>> {
    let sql = match column {
        "parent_session_id" => "SELECT name FROM instances WHERE parent_session_id = ?",
        "parent_name" => "SELECT name FROM instances WHERE parent_name = ?",
        _ => anyhow::bail!("unsupported child relationship: {column}"),
    };
    let mut stmt = db.conn().prepare(sql)?;
    let rows = stmt.query_map(params![value], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Whether the headless row's recorded pid still leads this instance's tree:
/// some live identity carrier of `instance_name` is in process group `pid`.
/// The recorded pid is the launch-script bash, which leads the group but
/// never carries the identity; `hcom pty` below it does.
#[cfg(target_os = "linux")]
fn headless_group_holds_carrier(db: &HcomDb, instance_name: &str, pid: u32) -> bool {
    let binding_ids = db.process_binding_ids(instance_name).unwrap_or_default();
    let owners = crate::proctruth::omp_owner_bindings(db, instance_name);
    crate::proctruth::group_holds_instance_carrier(pid, instance_name, &binding_ids, &owners)
}

/// No /proc outside Linux: the recorded group is signalled as before.
#[cfg(not(target_os = "linux"))]
fn headless_group_holds_carrier(_db: &HcomDb, _instance_name: &str, _pid: u32) -> bool {
    true
}

/// Whether the caller's own tree (`exclude`: the caller and its ancestors) is
/// provably outside the recorded group `pid`, so a session releasing its own
/// row may signal that group. Linux proves it from each pid's /proc pgrp.
#[cfg(target_os = "linux")]
fn caller_tree_outside_group(pid: u32, exclude: &[u32]) -> bool {
    crate::proctruth::pids_outside_group(pid, exclude)
}

/// Nothing proves it off Linux: no /proc pgrp, and `exclude` holds only the
/// caller's own pid. On Windows the group signal kills the whole tree under
/// the recorded root, and a headless session's releasing CLI is in that tree.
#[cfg(not(target_os = "linux"))]
fn caller_tree_outside_group(_pid: u32, _exclude: &[u32]) -> bool {
    false
}

/// The incarnation a stop may release (see [`row_re_registered`]).
enum BoundIncarnation {
    /// The row the stop read at entry. Its release CAS compares
    /// `created_at`, `session_id`, and `agent_id`; bindings keep the
    /// `expected_process_id` gate.
    Entry,
    /// The row a pre-signal capture was taken against, binding epoch
    /// included; `None` when no row existed at capture time.
    Captured(Option<crate::proctruth::CapturedIncarnation>),
}

/// Whether `name`'s row is now another incarnation than the bound one. An
/// absent row is not: the release CAS reports it as already stopped. The
/// row identity (`created_at` bits, `session_id`, `agent_id`) decides; a
/// captured binding epoch only ever adds a refusal. It loses to any binding
/// the capture never saw (a newer epoch). Bindings the row's own session
/// released since do not count, down to none at all: `soft_finalize_session`
/// with `keep_process_binding: false` empties the same row's bindings and
/// keeps the row, and an unbound replacement is caught by its new
/// `created_at`. Read through `conn`, so inside the finalize transaction it
/// decides with the writes (the finalize CAS applies the same epoch rule).
fn row_re_registered(
    conn: &rusqlite::Connection,
    name: &str,
    entry: &InstanceRow,
    bound: &BoundIncarnation,
) -> Result<bool> {
    use rusqlite::OptionalExtension;
    let Some((created_at, session_id, agent_id)) = conn
        .query_row(
            "SELECT created_at, session_id, agent_id FROM instances WHERE name = ?",
            params![name],
            |row| {
                Ok((
                    row.get::<_, f64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(false);
    };
    let (bound_created_at, bound_session_id, bound_agent_id, bound_bindings) = match bound {
        BoundIncarnation::Entry => (
            entry.created_at,
            entry.session_id.as_deref(),
            entry.agent_id.as_deref(),
            None,
        ),
        BoundIncarnation::Captured(None) => return Ok(true),
        BoundIncarnation::Captured(Some(captured)) => (
            captured.created_at,
            captured.session_id.as_deref(),
            captured.agent_id.as_deref(),
            Some(&captured.binding_ids),
        ),
    };
    if created_at.to_bits() != bound_created_at.to_bits()
        || session_id.as_deref() != bound_session_id
        || agent_id.as_deref() != bound_agent_id
    {
        return Ok(true);
    }
    let Some(bound_bindings) = bound_bindings else {
        return Ok(false);
    };
    let mut stmt =
        conn.prepare("SELECT process_id FROM process_bindings WHERE instance_name = ?")?;
    let current = stmt
        .query_map(params![name], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(current.iter().any(|id| !bound_bindings.contains(id)))
}

/// The guard's refusal: nothing was signalled or written for the new row.
fn re_registered_outcome(instance_name: &str) -> StopOutcome {
    log::log_info(
        "hooks",
        "stop_instance.re_registered",
        &format!("instance={instance_name}; release skipped, row left to its new incarnation"),
    );
    StopOutcome::RetryableError(StopError::re_registered())
}

#[allow(clippy::too_many_arguments)]
fn stop_instance_inner(
    db: &HcomDb,
    instance_name: &str,
    initiated_by: &str,
    reason: &str,
    placeholder: bool,
    depth: u32,
    reap_gate: bool,
    exclude: &[u32],
    pre_capture: Option<crate::proctruth::ReapCapture>,
) -> StopOutcome {
    stop_instance_inner_scoped(
        db,
        instance_name,
        initiated_by,
        reason,
        placeholder,
        depth,
        reap_gate,
        None,
        &mut PostCommit::default(),
        exclude,
        pre_capture,
    )
}

// Test seam: runs as a stop starts, after its caller's read (a stop or kill
// command's enumeration) and before any read of its own, so a test can land
// a rebind or replacement in that gap.
#[cfg(test)]
thread_local! {
    pub(crate) static STOP_ENTRY_GAP_HOOK: crate::db::GapHook =
        const { std::cell::Cell::new(None) };
}

/// [`stop_instance_inner`] with the write scope spelled out. `tx: None` is
/// the standalone path: every node finalizes in its own transaction and
/// fires its external side effects inline — unchanged historical behavior.
/// `tx: Some` is the kill path's shared transaction: every write (children
/// included) joins `tx`, and external effects queue into `post` until the
/// one commit.
///
/// `exclude` is a pid set the stop never signals: the headless group signal
/// runs only when every pid in it is provably outside the recorded group
/// (Linux; skipped elsewhere), and the reap spares carriers in it (they never
/// count as survivors). Every caller but the omp owner's exit release passes
/// `&[]`; child stops forward the same set.
#[allow(clippy::too_many_arguments)]
fn stop_instance_inner_scoped(
    db: &HcomDb,
    instance_name: &str,
    initiated_by: &str,
    reason: &str,
    placeholder: bool,
    depth: u32,
    reap_gate: bool,
    tx: Option<&rusqlite::Transaction<'_>>,
    post: &mut PostCommit,
    exclude: &[u32],
    pre_capture: Option<crate::proctruth::ReapCapture>,
) -> StopOutcome {
    if depth >= MAX_STOP_DEPTH {
        log::log_warn(
            "core",
            "stop_instance.max_depth",
            &format!(
                "Recursion limit ({}) reached stopping {}; possible cycle",
                MAX_STOP_DEPTH, instance_name
            ),
        );
        return StopOutcome::RetryableError(
            format!("recursion limit reached while stopping {instance_name}").into(),
        );
    }

    #[cfg(test)]
    if let Some(hook) = STOP_ENTRY_GAP_HOOK.with(std::cell::Cell::take) {
        hook(db, instance_name);
    }

    // The row this stop works from and the one incarnation it may release
    // come from ONE snapshot. A threaded pre-signal capture binds the row
    // its caller read together with the bindings (bulk kill and stop, stale
    // placeholder cleanup). A reap-gated stop without one reads the row and
    // its binding epoch together here and binds that: an entry read alone
    // never sees a binding a rebind adds, and a second read for the reap
    // could pair this row with another incarnation's bindings. Only the
    // kill's teardown (reap gate off, inside the kill's own CAS
    // transaction) binds its entry read.
    let read_error = |e: &dyn std::fmt::Display| {
        StopOutcome::RetryableError(format!("could not read instance {instance_name}: {e}").into())
    };
    let (row, pre_capture) = match pre_capture {
        None if reap_gate => match db.get_instance_with_bindings(instance_name) {
            Ok((row, ids)) => {
                let owners = crate::proctruth::omp_owner_bindings(db, instance_name);
                let capture = row.as_ref().map(|row| {
                    crate::proctruth::capture_reap_carriers(
                        instance_name,
                        Some(row),
                        &ids,
                        &owners,
                        exclude,
                    )
                });
                (row, capture)
            }
            Err(e) => return read_error(&e),
        },
        pre_capture => match db.get_instance_full(instance_name) {
            Ok(row) => (row, pre_capture),
            Err(e) => return read_error(&e),
        },
    };
    let Some(instance_data) = row else {
        return StopOutcome::AlreadyStopped;
    };

    // A capture taken for another incarnation authorizes nothing against
    // this row: no signal, no child stop, no reap, no release. The finalize
    // transaction re-checks it.
    let bound = match &pre_capture {
        Some(capture) => BoundIncarnation::Captured(capture.incarnation().cloned()),
        None => BoundIncarnation::Entry,
    };
    if matches!(bound, BoundIncarnation::Captured(_)) {
        match row_re_registered(db.conn(), instance_name, &instance_data, &bound) {
            Ok(false) => {}
            Ok(true) => return re_registered_outcome(instance_name),
            Err(e) => {
                return StopOutcome::RetryableError(
                    format!("could not read instance {instance_name}: {e}").into(),
                );
            }
        }
    }

    // The headless group step may kill the recorded root before the reap
    // snapshots its descendants, so the capture above holds the proven
    // carrier identities first: reparenting cannot erase that ownership
    // evidence. The reap's call-start epoch is the captured one.
    let (capture, binding_ids) = match pre_capture {
        Some(capture) => {
            let ids = capture
                .incarnation()
                .map(|captured| captured.binding_ids.clone())
                .unwrap_or_default();
            (Some(capture), ids)
        }

        None => (None, Vec::new()),
    };

    // Kill headless processes (background=true)
    // Skipped when the reap gate is off (the kill paths): kill owns the
    // signalling — the foreign path signals the process group and both paths
    // reap the carrier set BEFORE calling in (fail-closed) — and on the self
    // path this group signal would land on the caller's own tree.
    let pid = instance_data.pid;
    let is_headless = instance_data.background != 0;
    if let Some(pid_val) = pid {
        let pid_u32 = pid_val as u32;
        if is_headless {
            // Gated with the reap below: skipped on the kill paths, where the
            // group signal could land on the caller's own tree (self path).
            // A session releasing its own row (non-empty `exclude`) signals
            // only a group its tree is provably outside of, which only Linux
            // can prove; elsewhere that release skips the signal. Any stop
            // skips a group holding none of this instance's carriers (pid
            // reuse). The reap below still handles every carrier not in
            // `exclude`.
            if reap_gate {
                if !exclude.is_empty() && !caller_tree_outside_group(pid_u32, exclude) {
                    log::log_info(
                        "hooks",
                        "stop_instance.headless_self_skip",
                        &format!("instance={instance_name} pid={pid_u32}"),
                    );
                } else if !headless_group_holds_carrier(db, instance_name, pid_u32) {
                    log::log_info(
                        "hooks",
                        "stop_instance.headless_signal_skipped",
                        &format!(
                            "instance={instance_name} pid={pid_u32} reason=no_carrier_in_group"
                        ),
                    );
                } else {
                    // Graceful-then-forceful group kill: terminate_group (Unix: SIGTERM;
                    // Windows: forceful process-tree kill) → poll up to 2s for exit →
                    // kill_group (Unix: SIGKILL; Windows: tree kill again). The poll also
                    // waits out Windows' asynchronous TerminateProcess.
                    use crate::sys::process::GroupSignal;
                    if crate::sys::process::terminate_group(pid_u32) == GroupSignal::Sent {
                        let mut dead = false;
                        for _ in 0..20 {
                            std::thread::sleep(Duration::from_millis(100));
                            if !crate::sys::process::is_alive(pid_u32) {
                                dead = true;
                                break;
                            }
                        }
                        if !dead {
                            crate::sys::process::kill_group(pid_u32);
                        }
                    }
                    // NotFound/PermissionDenied from initial signal is fine — process already gone or foreign
                }
            }
        } else {
            // Track surviving PTY processes in pidtrack
            let alive = crate::sys::process::is_alive(pid_u32);
            if alive {
                let hcom_dir = crate::paths::hcom_dir();

                let ti = crate::terminal::resolve_terminal_info(
                    instance_data.terminal_preset_effective.as_deref(),
                    instance_data.launch_context.as_deref(),
                );
                let terminal_preset = ti.preset_name;
                let pane_id = ti.pane_id;
                let mut proc_id = ti.process_id;
                let terminal_id = ti.terminal_id;
                let kitty_listen_on = ti.kitty_listen_on;
                let zellij_session_name = ti.zellij_session_name;
                // Fallback: process_bindings table
                if proc_id.is_empty()
                    && let Ok(mut stmt) = db
                        .conn()
                        .prepare("SELECT process_id FROM process_bindings WHERE instance_name = ?")
                    && let Ok(val) =
                        stmt.query_row(params![instance_name], |row| row.get::<_, String>(0))
                {
                    proc_id = val;
                }
                // Grab notify/inject ports before DB cleanup deletes them
                let mut notify_port: u16 = 0;
                let mut inject_port: u16 = 0;
                if let Ok(mut stmt) = db
                    .conn()
                    .prepare("SELECT kind, port FROM notify_endpoints WHERE instance = ?")
                    && let Ok(rows) = stmt.query_map(params![instance_name], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })
                {
                    for row in rows.flatten() {
                        match row.0.as_str() {
                            "pty" => notify_port = row.1 as u16,
                            "inject" => inject_port = row.1 as u16,
                            _ => {}
                        }
                    }
                }

                crate::pidtrack::record_pid(&crate::pidtrack::PidRecord {
                    hcom_dir: &hcom_dir,
                    pid: pid_val as u32,
                    tool: &instance_data.tool,
                    name: instance_name,
                    directory: &instance_data.directory,
                    process_id: &proc_id,
                    terminal_preset: &terminal_preset,
                    pane_id: &pane_id,
                    terminal_id: &terminal_id,
                    kitty_listen_on: &kitty_listen_on,
                    zellij_session_name: &zellij_session_name,
                    session_id: instance_data.session_id.as_deref().unwrap_or(""),
                    notify_port,
                    inject_port,
                    tag: instance_data.tag.as_deref().unwrap_or(""),
                });
                log::log_info(
                    "stop",
                    "pidtrack_recorded",
                    &format!(
                        "pid={} instance={} preset={} pane_id={}",
                        pid_val, instance_name, terminal_preset, pane_id
                    ),
                );
            }
        }
    }

    // Capture wake ports BEFORE cleanup deletes them; we'll fire wakes after
    // delete so any remaining listeners see the row is gone.
    let wake_ports = crate::notify::snapshot_wake_ports(db, instance_name);

    // Prepare snapshot before delete (preserves data for transcript access)
    // Use Option values directly so None serializes as JSON null
    let snapshot = serde_json::json!({
        "name": instance_name,
        "transcript_path": instance_data.transcript_path,
        "session_id": instance_data.session_id,
        "tool": instance_data.tool,
        "directory": instance_data.directory,
        "parent_name": instance_data.parent_name,
        "parent_session_id": instance_data.parent_session_id,
        "tag": instance_data.tag,
        "wait_timeout": instance_data.wait_timeout,
        "subagent_timeout": instance_data.subagent_timeout,
        "hints": instance_data.hints,
        "pid": instance_data.pid,
        "created_at": instance_data.created_at,
        "created_at_bits": instance_data.created_at.to_bits(),
        "last_seen": instance_data.last_seen,
        "background": instance_data.background,
        "agent_id": instance_data.agent_id,
        "name_announced": instance_data.name_announced,
        "launch_args": instance_data.launch_args,
        "origin_device_id": instance_data.origin_device_id,
        "background_log_file": instance_data.background_log_file,
        "last_event_id": instance_data.last_event_id,
        "purpose": instance_data.purpose.as_deref().unwrap_or_default(),
        "current": instance_data.current.as_deref().unwrap_or_default(),
    });

    // Snapshot both child sets before deleting the parent. Only the teardown
    // winner processes them, but it still needs relationships that may be
    // cascaded or otherwise obscured by the parent deletion.
    let session_subagents = match instance_data.session_id.as_deref() {
        Some(session_id) => match child_instance_names(db, "parent_session_id", session_id) {
            Ok(children) => children,
            Err(e) => {
                return StopOutcome::RetryableError(
                    format!("could not enumerate session children of {instance_name}: {e}").into(),
                );
            }
        },
        None => Vec::new(),
    };
    let native_children = match child_instance_names(db, "parent_name", instance_name) {
        Ok(children) => children,
        Err(e) => {
            return StopOutcome::RetryableError(
                format!("could not enumerate native children of {instance_name}: {e}").into(),
            );
        }
    };

    // Finish children first while the parent row keeps the teardown retryable.
    // Concurrent callers may repeat this work; every child has its own atomic
    // event/delete gate.
    // A child re-registered mid-stop is another session's row now, left to
    // it exactly as a lost release CAS always was; it does not fail the parent.
    for sub_name in session_subagents {
        let outcome = stop_instance_inner_scoped(
            db,
            &sub_name,
            initiated_by,
            "parent_stopped",
            false,
            depth + 1,
            reap_gate,
            tx,
            post,
            exclude,
            None,
        );
        if !outcome.is_re_registered()
            && let StopOutcome::RetryableError(error) = outcome
        {
            log::log_warn(
                "hooks",
                "finalize.child_stop_incomplete",
                &format!("parent={instance_name} child={sub_name} err={error}"),
            );
            return StopOutcome::RetryableError(
                format!("could not stop child {sub_name}: {error}").into(),
            );
        }
    }

    // Native subagent rows carry session_id=NULL and inherit the root session
    // as parent_session_id, so only parent_name links nested children. A row
    // already stopped via the session set is a no-op here.
    for child in native_children {
        let outcome = stop_instance_inner_scoped(
            db,
            &child,
            initiated_by,
            "parent_stopped",
            false,
            depth + 1,
            reap_gate,
            tx,
            post,
            exclude,
            None,
        );
        if !outcome.is_re_registered()
            && let StopOutcome::RetryableError(error) = outcome
        {
            log::log_warn(
                "hooks",
                "finalize.child_stop_incomplete",
                &format!("parent={instance_name} child={child} err={error}"),
            );
            return StopOutcome::RetryableError(
                format!("could not stop child {child}: {error}").into(),
            );
        }
    }
    // Reap the proven in-scope tree for this name before releasing the row.
    // Process truth gates the release: the stopped event is only written
    // (and the row only deleted) once no in-scope process holds the instance
    // by name or binding process id. A foreign holder is excluded and logged
    // without being signalled. The pty wrapper goes first within the reap.
    // Skipped when the reap gate is off (the kill paths): kill has already
    // reaped and verified the eligible carrier set before this teardown,
    // and only after its own incarnation CAS.
    if let Some(capture) = capture
        && let Err(survivors) = crate::proctruth::reap_instance_tree_for_excluding_captured(
            db,
            instance_name,
            &binding_ids,
            exclude,
            capture,
        )
    {
        let error = survivors.to_string();
        log::log_warn(
            "hooks",
            "stop_instance.reap_incomplete",
            &format!("instance={instance_name} err={error}"),
        );
        return StopOutcome::RetryableError(
            format!(
                "could not stop {instance_name}: {error} — run hcom kill {instance_name} first"
            )
            .into(),
        );
    }

    // Key the release to the current process incarnation: the stopped event
    // carries the newest binding's process_id, and finalize only deletes
    // when it still matches (a stale harness exiting under a live name
    // logs stale-harness-exit and leaves the row).
    let expected_process_id: Option<String> = db
        .newest_process_binding(instance_name)
        .ok()
        .flatten()
        .map(|(process_id, _)| process_id);

    // Publish the winner's pre-delete snapshot in the same transaction that
    // deletes the row and its control-plane state. Event failure rolls the
    // deletion back, so another invocation can retry the whole teardown.
    let mut event_data = serde_json::json!({
        "action": "stopped",
        "by": initiated_by,
        "reason": reason,
        "process_id": expected_process_id.as_deref(),
        "snapshot": snapshot,
    });
    if placeholder {
        event_data["placeholder"] = serde_json::json!(true);
    }
    // The release CAS runs under the bound incarnation's identity: a captured
    // row (bulk kill) or the entry read.
    let (created_at, pid, session_id, agent_id) = match &bound {
        BoundIncarnation::Captured(Some(captured)) => (
            captured.created_at,
            captured.pid,
            captured.session_id.as_deref(),
            captured.agent_id.as_deref(),
        ),
        _ => (
            instance_data.created_at,
            instance_data.pid,
            instance_data.session_id.as_deref(),
            instance_data.agent_id.as_deref(),
        ),
    };
    let captured_bindings: Option<&[String]> = match &bound {
        BoundIncarnation::Captured(Some(captured)) => Some(captured.binding_ids.as_slice()),
        _ => None,
    };
    // `None`: the row is another incarnation now, so nothing was written.
    let finalized: Result<Option<bool>> = match tx {
        Some(tx) => match row_re_registered(tx, instance_name, &instance_data, &bound) {
            Ok(true) => Ok(None),
            Ok(false) => db
                .finalize_instance_stop_in_txn(
                    tx,
                    instance_name,
                    created_at,
                    pid,
                    session_id,
                    agent_id,
                    &event_data,
                    expected_process_id.as_deref(),
                    captured_bindings,
                )
                .map(|(won, event_id)| {
                    if let Some(event_id) = event_id {
                        // Deferred: the shared transaction is not committed yet.
                        post.events
                            .push((event_id, instance_name.to_string(), event_data.clone()));
                    }
                    Some(won)
                }),
            Err(e) => Err(e),
        },
        None => db
            .with_immediate_transaction(|tx| {
                if row_re_registered(tx, instance_name, &instance_data, &bound)? {
                    return Ok(None);
                }
                db.finalize_instance_stop_in_txn(
                    tx,
                    instance_name,
                    created_at,
                    pid,
                    session_id,
                    agent_id,
                    &event_data,
                    expected_process_id.as_deref(),
                    captured_bindings,
                )
                .map(Some)
            })
            .map(|finalized| {
                finalized.map(|(won, event_id)| {
                    // Best-effort external effect, only once the event is durable.
                    if let Some(event_id) = event_id {
                        crate::db::subscriptions::process_logged_event(
                            db,
                            event_id,
                            "life",
                            instance_name,
                            &event_data,
                        );
                    }
                    won
                })
            }),
    };
    match finalized {
        Ok(Some(true)) => {}
        Ok(Some(false)) => return StopOutcome::AlreadyStopped,
        Ok(None) => return re_registered_outcome(instance_name),
        Err(e) => {
            log::log_warn(
                "hooks",
                "finalize.transaction_failed",
                &format!("instance={instance_name} err={e}"),
            );
            return StopOutcome::RetryableError(
                format!("could not finalize stop for {instance_name}: {e}").into(),
            );
        }
    }

    // Capabilities are scoped to the deleted actor. Root teardown also
    // revokes every child token in the shared Claude session and drops
    // outstanding stop-claim correlation records.
    let _ = db.revoke_claude_actor_capabilities_for_instance(instance_name);
    if let Some(ref session_id) = instance_data.session_id {
        let _ = db.revoke_claude_actor_capabilities_for_session(session_id);
        let _ = db.kv_delete_prefix(&format!("subagent_stop_inflight:{session_id}:"));
    }

    if tx.is_some() {
        // Deferred: the shared transaction is not committed yet.
        post.wake_ports.extend(wake_ports);
        post.push = true;
    } else {
        // Notify remaining listeners AFTER delete (so they see the row is gone)
        crate::notify::wake_ports(&wake_ports, crate::notify::WAKE_TARGETED_MS);

        // Trigger relay push (best-effort)
        crate::relay::spawn_background_push();
    }
    StopOutcome::Stopped
}

#[derive(serde::Deserialize)]
struct TeardownOwner {
    pid: u32,
    process_start: String,
    // The claim writer before the bits (never in a release) wrote only a
    // `created_at` float; the comparison falls back to it (see
    // `yield_to_teardown`).
    created_at_bits: Option<u64>,
    session_id: Option<String>,
}

/// An in-flight kill owns the stopped record before it sends any signal.
/// Session hooks yield only for the claimed incarnation and live OS identity;
/// a crashed killer or a re-registered name cannot block the next session end.
pub(crate) struct TeardownClaim<'a> {
    db: &'a HcomDb,
    key: String,
    value: String,
}

impl<'a> TeardownClaim<'a> {
    pub(crate) fn register(
        db: &'a HcomDb,
        instance_name: &str,
        created_at: f64,
        session_id: Option<&str>,
    ) -> Option<Self> {
        let pid = std::process::id();
        let Some(process_start) = crate::sys::process::identity(pid) else {
            log::log_warn(
                "kill",
                "teardown.claim_identity_failed",
                &format!("pid={pid}"),
            );
            return None;
        };
        let key = format!("teardown_claim:{instance_name}");
        let value = serde_json::json!({
            "pid": pid,
            "process_start": process_start,
            // Preserve the exact SQLite f64; JSON's default float parser can
            // round a fractional timestamp to a neighboring representable value.
            "created_at_bits": created_at.to_bits(),
            "session_id": session_id,
        })
        .to_string();
        // The latest killer owns the claim, including when replacing a dead
        // owner. Earlier guards cannot clear another process's ownership.
        if let Err(e) = db.kv_set(&key, Some(&value)) {
            log::log_warn(
                "kill",
                "teardown.claim_write_failed",
                &format!("instance={instance_name} err={e}"),
            );
            return None;
        }
        Some(Self { db, key, value })
    }
}

impl Drop for TeardownClaim<'_> {
    fn drop(&mut self) {
        // Compare and delete in one statement: a second killer may have
        // replaced the claim while this one was signalling.
        let _ = self.db.conn().execute(
            "DELETE FROM kv WHERE key = ? AND value = ?",
            params![self.key, self.value],
        );
    }
}

/// What a session finalizer does about an in-flight kill's teardown claim.
enum TeardownYield {
    /// No live killer's claim covers this row — including a dead or
    /// malformed claim, or one naming another session or incarnation. The
    /// finalizer owns the teardown.
    NoClaim,
    /// A live claim names this session but no `created_at` can be read from
    /// it (absent, null, non-numeric, not a scalar). The row is held for the
    /// live kill — no teardown, no exit writes, logged — and the incarnation
    /// is never guessed.
    Held,
    /// Yield to the live kill, carrying the incarnation the finalizer's
    /// exit writes may target.
    YieldTo(f64, Option<String>),
}

/// The [`TeardownYield`] for `instance_name`: [`TeardownYield::YieldTo`]
/// when a live killer's claim covers this row, carrying the incarnation the
/// finalizer's exit writes may target.
///
/// Bits are authoritative. A claim without them is matched on the exact bit
/// pattern of its raw `created_at` token (a float decode can change a ULP).
/// When a live claim names this session but no `created_at` can be read
/// from it (absent, null, non-numeric, not a scalar), the finalizer fails
/// closed like the daemon sweep: [`TeardownYield::Held`] holds the row for
/// the live kill, and never guesses the incarnation.
fn yield_to_teardown(db: &HcomDb, instance_name: &str) -> TeardownYield {
    let Some(value) = db
        .kv_get(&format!("teardown_claim:{instance_name}"))
        .ok()
        .flatten()
    else {
        return TeardownYield::NoClaim;
    };
    let Some(owner) = serde_json::from_str::<TeardownOwner>(&value).ok() else {
        return TeardownYield::NoClaim;
    };
    if !crate::sys::process::has_identity(owner.pid, &owner.process_start) {
        return TeardownYield::NoClaim;
    }
    let Some(row) = db.get_instance_full(instance_name).ok().flatten() else {
        return TeardownYield::NoClaim;
    };
    // Another session is another incarnation, whatever the timestamp says.
    if row.session_id != owner.session_id {
        return TeardownYield::NoClaim;
    }
    let Some(bits) = owner
        .created_at_bits
        .or_else(|| crate::db::raw_created_at_bits(&value))
    else {
        log::log_warn(
            "hooks",
            "sessionend.teardown_claim_held",
            &format!(
                "instance={instance_name} reason=unreadable-created_at; row left to the live kill, no exit writes"
            ),
        );
        return TeardownYield::Held;
    };
    if row.created_at.to_bits() != bits {
        return TeardownYield::NoClaim;
    }
    log::log_info(
        "hooks",
        "sessionend.yielded_to_teardown",
        &format!("instance={instance_name}"),
    );
    TeardownYield::YieldTo(row.created_at, row.session_id)
}

/// Keep the one-shot hook's exit state if the kill fails, but never apply
/// that state to a name reused after the claim check. The immediate write
/// lock covers the incarnation re-read and both existing same-connection
/// writers, so a concurrent replacement cannot land between those writes.
fn persist_yielded_session_exit(
    db: &HcomDb,
    instance_name: &str,
    incarnation: (f64, Option<String>),
    reason: &str,
    updates: Option<&serde_json::Map<String, Value>>,
) {
    use rusqlite::OptionalExtension;

    let updated = db.with_immediate_transaction(|tx| {
        let current: Option<(f64, Option<String>)> = tx
            .query_row(
                "SELECT created_at, session_id FROM instances WHERE name = ?",
                params![instance_name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if !current.is_some_and(|(created_at, session_id)| {
            created_at.to_bits() == incarnation.0.to_bits() && session_id == incarnation.1
        }) {
            return Ok(false);
        }
        lifecycle::set_status(
            db,
            instance_name,
            ST_INACTIVE,
            &format!("exit:{}", reason),
            Default::default(),
        );
        if let Some(updates) = updates {
            instances::update_instance_position(db, instance_name, updates);
        }
        Ok(true)
    });
    match updated {
        Ok(true) => {}
        Ok(false) => log::log_info(
            "hooks",
            "sessionend.yield_incarnation_changed",
            &format!("instance={instance_name}; exit writes skipped"),
        ),
        Err(error) => log::log_warn(
            "hooks",
            "sessionend.yield_write_failed",
            &format!("instance={instance_name} err={error}"),
        ),
    }
}

// Test seam: runs between the soft stop's snapshot read and its writes, so
// a test can land a rebind or replacement in that gap.
#[cfg(test)]
thread_local! {
    static SOFT_STOP_GAP_HOOK: crate::db::GapHook = const { std::cell::Cell::new(None) };
}

/// Soft session end for Antigravity: mark inactive without deleting the `instances` row.
///
/// agy has no process-death hook — its hook set is only PreToolUse/PostToolUse/
/// PreInvocation/PostInvocation/Stop. We synthesize "SessionEnd" from `Stop`, which
/// fires when an *execution loop* terminates, NOT when the process dies: the agy
/// editor stays alive and routinely runs more turns after a `Stop` (observed in the
/// wild — instances soft-stopped here go straight back to listening/active). So the
/// hook path must never hard-delete: doing so would strand a still-running agent.
/// agy's real teardown is the PTY exit (`cleanup_antigravity_pty_exit`), which sees
/// the inactive status and preserves the row for `hcom r`.
///
/// Clears session bindings (and process bindings unless `keep_process_binding`),
/// and logs a stopped life event with snapshot, but does not delete the instance row.
/// The row and its binding epoch are read in ONE snapshot and every write runs
/// in one transaction gated on that incarnation: a `start --as` replacement or
/// a rebind landing after the read keeps its status, bindings, and
/// subscriptions, and gets no stopped record from this session.
///
/// OMP soft-stop passes `keep_process_binding: true` so the live process can rebind
/// via `bind_session_to_process` on the next turn. Antigravity passes `false`.
/// A live kill claim keeps the early exit status and metadata writes, but
/// leaves the stopped event, bindings, and row release to the kill. A live
/// claim whose incarnation cannot be read holds the row without those writes.
pub fn soft_finalize_session(
    db: &HcomDb,
    instance_name: &str,
    reason: &str,
    updates: Option<&serde_json::Map<String, Value>>,
    keep_process_binding: bool,
) {
    match yield_to_teardown(db, instance_name) {
        TeardownYield::NoClaim => {}
        TeardownYield::Held => return,
        TeardownYield::YieldTo(created_at, session_id) => {
            persist_yielded_session_exit(
                db,
                instance_name,
                (created_at, session_id),
                reason,
                updates,
            );
            return;
        }
    }
    let (row, binding_ids) = match db.get_instance_with_bindings(instance_name) {
        Ok((Some(row), ids)) => (row, ids),
        Ok((None, _)) => return,
        Err(e) => {
            log::log_warn(
                "hooks",
                "sessionend.soft.read_failed",
                &format!("instance={instance_name} err={e}"),
            );
            return;
        }
    };
    #[cfg(test)]
    if let Some(hook) = SOFT_STOP_GAP_HOOK.with(std::cell::Cell::take) {
        hook(db, instance_name);
    }
    let bound = BoundIncarnation::Captured(Some(crate::proctruth::CapturedIncarnation {
        created_at: row.created_at,
        pid: row.pid,
        session_id: row.session_id.clone(),
        agent_id: row.agent_id.clone(),
        binding_ids,
    }));
    log::log_info(
        "hooks",
        "sessionend.soft",
        &format!("instance={} reason={}", instance_name, reason),
    );

    let written = db.with_immediate_transaction(|tx| {
        use rusqlite::OptionalExtension;
        let present = tx
            .query_row(
                "SELECT 1 FROM instances WHERE name = ?",
                params![instance_name],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !present || row_re_registered(tx, instance_name, &row, &bound)? {
            return Ok(false);
        }

        lifecycle::set_status(
            db,
            instance_name,
            ST_INACTIVE,
            &format!("exit:{}", reason),
            Default::default(),
        );

        if let Some(updates) = updates {
            instances::update_instance_position(db, instance_name, updates);
        }

        // Re-read inside the gated transaction: the snapshot carries the
        // exit writes above, and it is still the incarnation just checked.
        let Some(instance_data) = db.get_instance_full(instance_name)? else {
            return Ok(false);
        };

        let snapshot = serde_json::json!({
            "name": instance_name,
            "transcript_path": instance_data.transcript_path,
            "session_id": instance_data.session_id,
            "tool": instance_data.tool,
            "directory": instance_data.directory,
            "parent_name": instance_data.parent_name,
            "parent_session_id": instance_data.parent_session_id,
            "tag": instance_data.tag,
            "wait_timeout": instance_data.wait_timeout,
            "subagent_timeout": instance_data.subagent_timeout,
            "hints": instance_data.hints,
            "pid": instance_data.pid,
            "created_at": instance_data.created_at,
            "created_at_bits": instance_data.created_at.to_bits(),
            "last_seen": instance_data.last_seen,
            "background": instance_data.background,
            "agent_id": instance_data.agent_id,
            "name_announced": instance_data.name_announced,
            "launch_args": instance_data.launch_args,
            "origin_device_id": instance_data.origin_device_id,
            "background_log_file": instance_data.background_log_file,
            "last_event_id": instance_data.last_event_id,
            "purpose": instance_data.purpose.as_deref().unwrap_or_default(),
            "current": instance_data.current.as_deref().unwrap_or_default(),
        });

        if let Some(session_id) = &instance_data.session_id {
            let _ = tx.execute(
                "DELETE FROM session_bindings WHERE session_id = ?",
                params![session_id],
            );
            if !keep_process_binding {
                let _ = tx.execute(
                    "DELETE FROM process_bindings WHERE session_id = ?",
                    params![session_id],
                );
            }
        }

        let _ = db.delete_notify_endpoints(instance_name);
        if !keep_process_binding {
            let _ = tx.execute(
                "DELETE FROM process_bindings WHERE instance_name = ?",
                params![instance_name],
            );
        }
        let _ = db.cleanup_subscriptions(instance_name);

        if let Err(e) = db.log_life_event(
            instance_name,
            "stopped",
            "session",
            &format!("exit:{}", reason),
            Some(snapshot),
            // Soft stops preserve the row for resume; no incarnation is
            // released, so no process_id is claimed.
            None,
        ) {
            log::log_warn(
                "hooks",
                "sessionend.soft.life_event_failed",
                &format!("log_life_event failed for {instance_name}: {e}"),
            );
        }
        Ok(true)
    });
    match written {
        Ok(true) => {}
        Ok(false) => log::log_info(
            "hooks",
            "sessionend.soft.re_registered",
            &format!(
                "instance={instance_name}; another incarnation holds the name, soft stop skipped"
            ),
        ),
        Err(e) => log::log_warn(
            "hooks",
            "sessionend.soft.write_failed",
            &format!("instance={instance_name} err={e}"),
        ),
    }
}

/// Set inactive status, persist updates, and stop instance.
///
/// Common to Claude and Gemini SessionEnd handlers. Catches DB errors
/// internally — callers don't need error handling — but returns the
/// [`StopOutcome`] so tests can observe it.
///
/// When the reap gate refuses (harness survivors after SIGKILL) the session
/// is NOT cleanly ended: the row lingers and the harness still runs. That
/// must be visible, so the refusal is logged at warn with the surviving pids
/// (they ride in the error text) AND printed to hook stderr — the same
/// channel hook denials use — while the hook exit code stays 0 (SessionEnd
/// must not block the harness from exiting; the operator reads the warning
/// and runs `hcom kill <name>`).
pub fn finalize_session(
    db: &HcomDb,
    instance_name: &str,
    reason: &str,
    updates: Option<&serde_json::Map<String, Value>>,
) -> StopOutcome {
    finalize_session_excluding(db, instance_name, reason, updates, &[])
}

/// [`finalize_session`] with an exclusion set: pids in `exclude` are never
/// signalled by the stop (headless group signal and reap alike) and never
/// count as survivors. For a session releasing its own row while its own
/// process tree is still running (the omp owner's exit release). A headless
/// row's recorded group is signalled only when `exclude` is provably outside
/// it, which only Linux can prove.
///
/// Off Linux a non-empty `exclude` never deletes the row: without /proc the
/// reap and the headless check see none of the session's other carriers, so
/// a release would report success blind (see `keep_own_row_off_linux`).
/// A live kill claim preserves the early exit status and metadata writes
/// and returns `AlreadyStopped`; the kill owns the stopped event and release.
/// A live claim whose incarnation cannot be read holds the row the same way,
/// without the exit writes.
pub fn finalize_session_excluding(
    db: &HcomDb,
    instance_name: &str,
    reason: &str,
    updates: Option<&serde_json::Map<String, Value>>,
    exclude: &[u32],
) -> StopOutcome {
    match yield_to_teardown(db, instance_name) {
        TeardownYield::NoClaim => {}
        TeardownYield::Held => return StopOutcome::AlreadyStopped,
        TeardownYield::YieldTo(created_at, session_id) => {
            persist_yielded_session_exit(
                db,
                instance_name,
                (created_at, session_id),
                reason,
                updates,
            );
            return StopOutcome::AlreadyStopped;
        }
    }
    #[cfg(not(target_os = "linux"))]
    if !exclude.is_empty() {
        return keep_own_row_off_linux(db, instance_name, reason, updates);
    }

    log::log_info(
        "hooks",
        "sessionend",
        &format!("instance={} reason={}", instance_name, reason),
    );

    // Set inactive status
    lifecycle::set_status(
        db,
        instance_name,
        ST_INACTIVE,
        &format!("exit:{}", reason),
        Default::default(),
    );

    // Persist metadata updates
    if let Some(updates) = updates {
        instances::update_instance_position(db, instance_name, updates);
    }

    // Full stop_instance chain: snapshot, cleanup bindings, log, delete
    let outcome = stop_instance_inner(
        db,
        instance_name,
        "session",
        &format!("exit:{}", reason),
        false,
        0,
        true,
        exclude,
        None,
    );
    // A re-registered name belongs to another session now; the guard logged
    // the skip, and this session's own end is not a refused stop.
    if !outcome.is_re_registered()
        && let StopOutcome::RetryableError(e) = &outcome
    {
        log::log_warn(
            "hooks",
            "sessionend.stop_refused",
            &format!("instance={instance_name} reason={reason} err={e}"),
        );
        eprintln!("[hcom] warn: SessionEnd for '{instance_name}' did not stop the session: {e}");
    }
    outcome
}

/// A session's own release off Linux: soft-stop exactly as `omp-stop --soft`
/// does (row kept inactive, soft stopped event, process binding kept) and
/// signal nothing — the pre-release owner-close outcome. A row already
/// inactive (the graceful path soft-stopped it first) is left as is: no
/// second stopped event. Returns `Stopped` when this call soft-stopped the
/// row, `AlreadyStopped` when there was nothing to change.
#[cfg(not(target_os = "linux"))]
fn keep_own_row_off_linux(
    db: &HcomDb,
    instance_name: &str,
    reason: &str,
    updates: Option<&serde_json::Map<String, Value>>,
) -> StopOutcome {
    let status = match db.get_instance_full(instance_name) {
        Ok(Some(row)) => row.status,
        Ok(None) => return StopOutcome::AlreadyStopped,
        Err(e) => {
            return StopOutcome::RetryableError(
                format!("could not read instance {instance_name}: {e}").into(),
            );
        }
    };
    log::log_info(
        "hooks",
        "stop_instance.self_release_kept_off_linux",
        &format!("instance={instance_name} reason={reason} status={status}"),
    );
    if status == ST_INACTIVE {
        return StopOutcome::AlreadyStopped;
    }
    soft_finalize_session(db, instance_name, reason, updates, true);
    StopOutcome::Stopped
}

/// Update instance status for tool execution.
///
/// Calls extract_tool_detail for tool-specific detail formatting,
/// then sets status to active with tool context.
///
pub fn update_tool_status(
    db: &HcomDb,
    instance_name: &str,
    tool: &str,
    tool_name: &str,
    tool_input: &Value,
) {
    let detail = super::family::extract_tool_detail(tool, tool_name, tool_input);
    // Live subtask: omp/pi tool calls carry the agent's intent as `i` in the
    // input object (forwarded wholesale by the hcom.ts extension). No-op for
    // payloads without one, so other tools never clobber an explicit phase.
    crate::title::record_intent(db, instance_name, tool_input);
    lifecycle::set_status(
        db,
        instance_name,
        ST_ACTIVE,
        &format!("tool:{}", tool_name),
        lifecycle::StatusUpdate {
            detail: &detail,
            ..Default::default()
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::test_helpers::isolated_test_env;
    use serial_test::serial;
    use std::io::Write;

    #[test]
    fn test_find_last_bind_marker_basic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transcript.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "some log data").unwrap();
        writeln!(f, "more data [hcom:luna] more stuff").unwrap();
        writeln!(f, "trailing data").unwrap();

        let result = find_last_bind_marker(path.to_str().unwrap());
        assert_eq!(result, Some("luna".to_string()));
    }

    #[test]
    fn test_find_last_bind_marker_returns_last() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transcript.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "[hcom:first]").unwrap();
        writeln!(f, "[hcom:second]").unwrap();
        writeln!(f, "[hcom:third]").unwrap();

        let result = find_last_bind_marker(path.to_str().unwrap());
        assert_eq!(result, Some("third".to_string()));
    }

    #[test]
    fn test_find_last_bind_marker_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transcript.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "no markers here").unwrap();

        let result = find_last_bind_marker(path.to_str().unwrap());
        assert!(result.is_none());
    }

    #[test]
    fn test_find_last_bind_marker_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transcript.jsonl");
        std::fs::File::create(&path).unwrap();

        let result = find_last_bind_marker(path.to_str().unwrap());
        assert!(result.is_none());
    }

    #[test]
    fn test_find_last_bind_marker_missing_file() {
        let result = find_last_bind_marker("/nonexistent/path.jsonl");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_last_bind_marker_large_file_marker_at_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transcript.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        // Write ~1MB of padding + marker at end
        let padding = "x".repeat(1024);
        for _ in 0..1024 {
            writeln!(f, "{}", padding).unwrap();
        }
        writeln!(f, "[hcom:bigtarget]").unwrap();

        let result = find_last_bind_marker(path.to_str().unwrap());
        assert_eq!(result, Some("bigtarget".to_string()));
    }

    #[test]
    fn test_rfind_bytes_basic() {
        let haystack = b"hello [hcom:test] world [hcom:second] end";
        assert_eq!(rfind_bytes(haystack, b"[hcom:"), Some(24));
    }

    #[test]
    fn test_rfind_bytes_not_found() {
        assert_eq!(rfind_bytes(b"hello world", b"[hcom:"), None);
    }

    #[test]
    fn test_rfind_bytes_empty() {
        assert_eq!(rfind_bytes(b"", b"[hcom:"), None);
        assert_eq!(rfind_bytes(b"hello", b""), None);
    }

    #[test]
    fn test_check_stdin_closed_does_not_panic() {
        // Verify the function runs without panicking regardless of stdin state.
        // In test context stdin is typically a pipe — check_stdin_closed should
        // return false because POLLHUP (normal pipe EOF) is NOT treated as closed.
        let result = check_stdin_closed();
        // Don't assert specific value — stdin state varies across test runners.
        let _ = result;
    }

    #[test]
    fn test_setup_tcp_notification() {
        let (server, tcp_mode) = setup_tcp_notification("test_instance");
        assert!(tcp_mode);
        assert!(server.is_some());

        let addr = server.as_ref().unwrap().local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[test]
    #[serial]
    fn test_notify_hook_instance_missing_instance() {
        // Best-effort wake must not panic when the DB opens but the named
        // instance has no row (the common case for a stale notify target).
        let (_dir, _hcom_dir, _home, _guard) = isolated_test_env();
        notify_hook_instance("nonexistent");
    }

    fn make_test_db() -> (tempfile::TempDir, crate::db::HcomDb) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();
        (dir, db)
    }

    fn insert_test_instance(db: &crate::db::HcomDb, name: &str) {
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, status, status_context, status_time, created_at, last_event_id)
                 VALUES (?1, 'claude', 'listening', 'start', 0, 0, 0)",
                [name],
            )
            .unwrap();
    }

    /// `start --as` lands between the soft stop's read and its writes: the
    /// row is recreated as another incarnation bound to its own process.
    /// The old session's soft stop touches none of it — no exit status, no
    /// binding released, no stopped record.
    #[test]
    #[serial]
    fn soft_stop_spares_a_replacement_landing_after_its_read() {
        let _env = isolated_test_env();
        let (_dir, db) = make_test_db();
        fn seed(db: &HcomDb, name: &str, created_at: f64, session: &str, process: &str) {
            db.conn()
                .execute(
                    "INSERT INTO instances (name, tool, status, status_context, status_time, \
                     created_at, last_event_id, session_id) \
                     VALUES (?1, 'antigravity', 'listening', 'start', 0, ?2, 0, ?3)",
                    params![name, created_at, session],
                )
                .unwrap();
            db.set_process_binding(process, session, name).unwrap();
        }
        fn replace(db: &HcomDb, name: &str) {
            db.conn()
                .execute(
                    "DELETE FROM process_bindings WHERE instance_name = ?1",
                    params![name],
                )
                .unwrap();
            db.conn()
                .execute("DELETE FROM instances WHERE name = ?1", params![name])
                .unwrap();
            seed(db, name, 2.0, "sess-new", "proc-new");
        }
        seed(&db, "agy", 1.0, "sess-old", "proc-old");
        SOFT_STOP_GAP_HOOK.with(|hook| hook.set(Some(replace)));
        soft_finalize_session(&db, "agy", "shutdown", None, false);
        SOFT_STOP_GAP_HOOK.with(|hook| hook.set(None));

        let row = db
            .get_instance_full("agy")
            .unwrap()
            .expect("replacement row retained");
        assert_eq!(row.created_at, 2.0);
        assert_eq!(row.status, "listening", "no exit status on the replacement");
        assert_eq!(db.process_binding_ids("agy").unwrap(), vec!["proc-new"]);
        let stopped: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = 'agy' \
                 AND json_extract(data, '$.action') = 'stopped'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stopped, 0, "no stopped record for the replacement");
    }

    #[test]
    fn test_update_tool_status_records_intent_as_current() {
        let (_dir, db) = make_test_db();
        insert_test_instance(&db, "nova");

        // Payload carrying the omp tool intent updates the live subtask.
        update_tool_status(
            &db,
            "nova",
            "omp",
            "read",
            &serde_json::json!({"i": "Reading model role settings", "path": "/tmp/x"}),
        );
        let row = db.get_instance_full("nova").unwrap().unwrap();
        assert_eq!(row.current.as_deref(), Some("Reading model role settings"));

        // Payload without an intent leaves the phase alone.
        update_tool_status(
            &db,
            "nova",
            "omp",
            "read",
            &serde_json::json!({"path": "/tmp/x"}),
        );
        let row = db.get_instance_full("nova").unwrap().unwrap();
        assert_eq!(row.current.as_deref(), Some("Reading model role settings"));
    }

    fn insert_bound_claude_instance(
        db: &crate::db::HcomDb,
        name: &str,
        session_id: &str,
        transcript_path: &str,
    ) {
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, tool, session_id, transcript_path, status, status_context, status_time, created_at, last_event_id)
                 VALUES (?1, 'claude', ?2, ?3, 'listening', 'start', 0, 0, 0)",
                rusqlite::params![name, session_id, transcript_path],
            )
            .unwrap();
        db.set_session_binding(session_id, name).unwrap();
        db.mark_claude_session_validated(session_id, name).unwrap();
    }

    fn context_with_process_id(
        cwd: &std::path::Path,
        process_id: Option<&str>,
    ) -> crate::shared::context::HcomContext {
        let mut env = std::collections::HashMap::new();
        if let Some(process_id) = process_id {
            env.insert("HCOM_PROCESS_ID".to_string(), process_id.to_string());
        }
        crate::shared::context::HcomContext::from_env(&env, cwd.to_path_buf())
    }

    #[test]
    fn transcript_lineage_uses_structured_fork_ancestry() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-original", "");
        let transcript = dir.path().join("fork.jsonl");
        std::fs::write(
            &transcript,
            concat!(
                "{\"sessionId\":\"session-new\",\"message\":{\"session_id\":\"session-original\"}}\n",
                "{\"session_id\":\"session-new\"}\n"
            ),
        )
        .unwrap();

        assert_eq!(
            resolve_claude_transcript_owner(
                &db,
                transcript.to_str().unwrap(),
                Some("session-new"),
            )
            .unwrap(),
            TranscriptOwnerResolution::Owner("niza".to_string())
        );
    }

    #[test]
    fn transcript_lineage_deduplicates_multiple_records_for_one_owner() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-original", "");
        let transcript = dir.path().join("same-owner.jsonl");
        std::fs::write(
            &transcript,
            concat!(
                "{\"sessionId\":\"session-original\"}\n",
                "{\"session_id\":\"session-original\"}\n",
                "{\"message\":{\"session_id\":\"session-original\"}}\n"
            ),
        )
        .unwrap();

        assert_eq!(
            resolve_claude_transcript_owner(&db, transcript.to_str().unwrap(), None).unwrap(),
            TranscriptOwnerResolution::Owner("niza".to_string())
        );
    }

    #[test]
    fn transcript_lineage_rejects_conflicting_owners() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-niza", "");
        insert_bound_claude_instance(&db, "lava", "session-lava", "");
        let transcript = dir.path().join("conflict.jsonl");
        std::fs::write(
            &transcript,
            concat!(
                "{\"sessionId\":\"session-niza\"}\n",
                "{\"message\":{\"session_id\":\"session-lava\"}}\n"
            ),
        )
        .unwrap();

        assert_eq!(
            resolve_claude_transcript_owner(&db, transcript.to_str().unwrap(), None).unwrap(),
            TranscriptOwnerResolution::Ambiguous(vec!["lava".to_string(), "niza".to_string()])
        );
    }

    #[test]
    fn transcript_lineage_ignores_ids_inside_message_content() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "lava", "session-lava", "");
        let transcript = dir.path().join("quoted.jsonl");
        std::fs::write(
            &transcript,
            "{\"message\":{\"content\":\"quoted session_id session-lava\",\"nested\":{\"session_id\":\"session-lava\"}}}\n",
        )
        .unwrap();

        assert_eq!(
            resolve_claude_transcript_owner(&db, transcript.to_str().unwrap(), None).unwrap(),
            TranscriptOwnerResolution::Unknown
        );
    }

    #[test]
    fn transcript_lineage_handles_missing_and_oversized_files() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-original", "");
        assert_eq!(
            resolve_claude_transcript_owner(
                &db,
                dir.path().join("missing.jsonl").to_str().unwrap(),
                None,
            )
            .unwrap(),
            TranscriptOwnerResolution::Unknown
        );

        let transcript = dir.path().join("oversized.jsonl");
        let mut file = std::fs::File::create(&transcript).unwrap();
        for _ in 0..2048 {
            writeln!(file, "{{\"type\":\"padding\"}}").unwrap();
        }
        writeln!(file, "{{\"sessionId\":\"session-original\"}}").unwrap();
        assert_eq!(
            resolve_claude_transcript_owner(&db, transcript.to_str().unwrap(), None).unwrap(),
            TranscriptOwnerResolution::Unknown
        );
    }

    #[test]
    fn transcript_lineage_ignores_truncated_utf8_tail() {
        const MAX_BYTES: usize = 512 * 1024;

        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-original", "");
        let transcript = dir.path().join("truncated-utf8.jsonl");
        let mut contents = b"{\"sessionId\":\"session-original\"}\n".to_vec();
        contents.resize(MAX_BYTES - 1, b' ');
        contents.extend_from_slice("€\n".as_bytes());
        std::fs::write(&transcript, contents).unwrap();

        assert_eq!(
            resolve_claude_transcript_owner(&db, transcript.to_str().unwrap(), None).unwrap(),
            TranscriptOwnerResolution::Owner("niza".to_string())
        );
    }

    #[test]
    fn transcript_lineage_rejects_duplicate_exact_path_owners() {
        let (dir, db) = make_test_db();
        let transcript = dir.path().join("shared.jsonl");
        std::fs::write(&transcript, "").unwrap();
        insert_bound_claude_instance(&db, "niza", "session-niza", transcript.to_str().unwrap());
        insert_bound_claude_instance(&db, "lava", "session-lava", transcript.to_str().unwrap());

        assert_eq!(
            resolve_claude_transcript_owner(&db, transcript.to_str().unwrap(), None).unwrap(),
            TranscriptOwnerResolution::Ambiguous(vec!["lava".to_string(), "niza".to_string()])
        );
    }

    #[test]
    fn hook_context_skips_transcript_scan_when_process_and_session_agree() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-niza", "");
        insert_bound_claude_instance(&db, "lava", "session-lava", "");
        db.set_process_binding("process-niza", "session-niza", "niza")
            .unwrap();
        let transcript = dir.path().join("irrelevant-conflict.jsonl");
        std::fs::write(
            &transcript,
            "{\"message\":{\"session_id\":\"session-lava\"}}\n",
        )
        .unwrap();
        let ctx = context_with_process_id(dir.path(), Some("process-niza"));

        let (owner, _, _) =
            init_hook_context(&db, &ctx, "session-niza", transcript.to_str().unwrap());
        assert_eq!(owner.as_deref(), Some("niza"));
    }

    #[test]
    fn hook_context_uses_session_owner_with_empty_process_id() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-niza", "");
        let ctx = context_with_process_id(dir.path(), Some(""));

        let (owner, _, _) = init_hook_context(&db, &ctx, "session-niza", "");
        assert_eq!(owner.as_deref(), Some("niza"));
    }

    #[test]
    fn hook_context_prefers_session_owner_over_conflicting_process_owner() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-niza", "");
        insert_bound_claude_instance(&db, "lava", "session-lava", "");
        db.set_process_binding("process-restored", "session-lava", "lava")
            .unwrap();
        let ctx = context_with_process_id(dir.path(), Some("process-restored"));

        let (owner, _, _) = init_hook_context(&db, &ctx, "session-niza", "");
        assert_eq!(owner.as_deref(), Some("niza"));
    }

    #[test]
    fn hook_context_fails_closed_on_poisoned_session_vs_transcript_ancestry() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-original", "");
        insert_bound_claude_instance(&db, "lava", "session-poisoned", "");
        db.kv_set("claude_lineage_validated:session-poisoned", None)
            .unwrap();
        db.set_process_binding("process-restored", "session-original", "niza")
            .unwrap();
        let transcript = dir.path().join("poisoned.jsonl");
        std::fs::write(
            &transcript,
            "{\"message\":{\"session_id\":\"session-original\"}}\n",
        )
        .unwrap();
        let ctx = context_with_process_id(dir.path(), Some("process-restored"));

        let (owner, _, _) =
            init_hook_context(&db, &ctx, "session-poisoned", transcript.to_str().unwrap());
        assert!(owner.is_none());
    }

    #[test]
    fn hook_context_revalidates_agreeing_but_untrusted_poisoned_binding() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-original", "");
        insert_bound_claude_instance(&db, "lava", "session-poisoned", "");
        db.kv_set("claude_lineage_validated:session-poisoned", None)
            .unwrap();
        db.set_process_binding("process-poisoned", "session-poisoned", "lava")
            .unwrap();
        let transcript = dir.path().join("poisoned-agree.jsonl");
        std::fs::write(
            &transcript,
            "{\"sessionId\":\"session-poisoned\",\"message\":{\"session_id\":\"session-original\"}}\n",
        )
        .unwrap();
        let ctx = context_with_process_id(dir.path(), Some("process-poisoned"));

        let (owner, _, is_primary) =
            init_hook_context(&db, &ctx, "session-poisoned", transcript.to_str().unwrap());
        assert!(owner.is_none());
        assert!(!is_primary, "ordinary hooks must not promote a generation");
        assert_eq!(
            db.get_instance_full("lava")
                .unwrap()
                .unwrap()
                .status_context,
            "start",
            "rejecting a hook must not mutate the other instance's status"
        );
    }

    #[test]
    fn hook_context_caches_validated_lineage_after_one_scan() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "niza", "session-niza", "");
        db.kv_set("claude_lineage_validated:session-niza", None)
            .unwrap();
        db.set_process_binding("process-niza", "session-niza", "niza")
            .unwrap();
        let transcript = dir.path().join("validate-once.jsonl");
        std::fs::write(
            &transcript,
            "{\"message\":{\"session_id\":\"session-niza\"}}\n",
        )
        .unwrap();
        let ctx = context_with_process_id(dir.path(), Some("process-niza"));

        let (owner, _, is_primary) =
            init_hook_context(&db, &ctx, "session-niza", transcript.to_str().unwrap());
        assert_eq!(owner.as_deref(), Some("niza"));
        assert!(is_primary);
        assert_eq!(
            db.get_validated_claude_session_owner("session-niza")
                .unwrap()
                .as_deref(),
            Some("niza")
        );

        std::fs::write(
            &transcript,
            "{\"message\":{\"session_id\":\"session-other\"}}\n",
        )
        .unwrap();
        let (owner, _, _) =
            init_hook_context(&db, &ctx, "session-niza", transcript.to_str().unwrap());
        assert_eq!(owner.as_deref(), Some("niza"));
    }

    #[test]
    fn hook_context_rejects_historical_process_fallback_for_unbound_session() {
        let (dir, db) = make_test_db();
        insert_bound_claude_instance(&db, "lava", "session-old", "");
        db.set_process_binding("process-restored", "session-old", "lava")
            .unwrap();
        let ctx = context_with_process_id(dir.path(), Some("process-restored"));

        let (owner, _, _) = init_hook_context(&db, &ctx, "session-new", "");
        assert!(owner.is_none());
    }

    #[test]
    fn hook_context_keeps_fresh_process_fallback_without_lineage() {
        let (dir, db) = make_test_db();
        insert_test_instance(&db, "fresh");
        db.set_process_binding("process-fresh", "", "fresh")
            .unwrap();
        let ctx = context_with_process_id(dir.path(), Some("process-fresh"));

        let (owner, _, _) = init_hook_context(&db, &ctx, "session-new", "");
        assert_eq!(owner.as_deref(), Some("fresh"));
    }

    fn insert_test_message(
        db: &crate::db::HcomDb,
        instance: &str,
        from: &str,
        text: &str,
        timestamp: &str,
    ) {
        let data = serde_json::json!({
            "from": from,
            "text": text,
            "scope": "broadcast",
        })
        .to_string();
        db.conn()
            .execute(
                "INSERT INTO events (type, timestamp, instance, data) VALUES ('message', ?1, ?2, ?3)",
                rusqlite::params![timestamp, instance, data],
            )
            .unwrap();
    }

    #[test]
    fn test_prepare_and_commit_delivery() {
        let (_dir, db) = make_test_db();
        insert_test_instance(&db, "nova");
        insert_test_message(&db, "luna", "luna", "hello", "2026-01-01T00:00:01Z");

        let prepared = prepare_pending_messages(&db, "nova").unwrap();
        assert!(!prepared.formatted.is_empty());
        assert_eq!(prepared.ack.instance_name, "nova");

        // Before commit: cursor not advanced (prepare_raw_messages defers)
        let cursor_before: i64 = db
            .conn()
            .query_row(
                "SELECT last_event_id FROM instances WHERE name = 'nova'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor_before, 0);

        // Commit
        commit_delivery_ack(&db, &prepared.ack);

        // After commit: cursor advanced, status updated
        let cursor_after: i64 = db
            .conn()
            .query_row(
                "SELECT last_event_id FROM instances WHERE name = 'nova'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor_after, prepared.ack.last_event_id);

        let instance = db.get_instance_full("nova").unwrap().unwrap();
        assert_eq!(instance.status, ST_ACTIVE);
        assert!(instance.status_context.starts_with("deliver:"));
    }

    #[test]
    fn test_stop_instance_basic_cleanup() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();

        // Create parent instance
        let _ = db.conn().execute(
            "INSERT INTO instances (name, tool, session_id, status, status_context, status_time, created_at)
             VALUES ('parent', 'claude', 'sess-1', 'active', 'new', 0, 0)",
            [],
        );
        // Add notify endpoint
        let _ = db.conn().execute(
            "INSERT INTO notify_endpoints (instance, kind, port, updated_at) VALUES ('parent', 'pty', 9999, 0)",
            [],
        );
        // Add process binding and Claude actor correlation state
        let _ = db.conn().execute(
            "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at) VALUES ('proc-1', 'sess-1', 'parent', 0)",
            [],
        );
        let token = db
            .issue_claude_actor_capability("sess-1", "tool-1", None, "parent")
            .unwrap();
        db.kv_set("subagent_stop_inflight:sess-1:a1:x", Some("owner"))
            .unwrap();

        stop_instance(&db, "parent", "test", "test_cleanup");

        // Instance should be deleted
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM instances WHERE name = 'parent'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "instance should be deleted");

        // Notify endpoints should be deleted
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM notify_endpoints WHERE instance = 'parent'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "notify endpoints should be deleted");

        // Process bindings should be deleted
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM process_bindings WHERE instance_name = 'parent'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "process bindings should be deleted");

        assert_eq!(
            db.resolve_claude_actor_capability(&token, "sess-1")
                .unwrap(),
            None,
            "root stop should revoke session actor capabilities"
        );
        let claude_kv: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM kv WHERE key LIKE 'subagent_stop_inflight:sess-1:%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            claude_kv, 0,
            "root stop should remove Claude actor correlation state"
        );

        // Life event should be logged
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = 'parent'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "life event should be logged");
    }

    #[test]
    fn test_stop_instance_recursive_subagent_cleanup() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();

        // Create parent instance with session_id
        let _ = db.conn().execute(
            "INSERT INTO instances (name, tool, session_id, status, status_context, status_time, created_at)
             VALUES ('parent', 'claude', 'sess-parent', 'active', 'new', 0, 0)",
            [],
        );
        // Create subagent linked to parent via parent_session_id
        let _ = db.conn().execute(
            "INSERT INTO instances (name, tool, session_id, parent_session_id, parent_name, status, status_context, status_time, created_at)
             VALUES ('sub1', 'claude', 'sess-sub1', 'sess-parent', 'parent', 'active', 'new', 0, 0)",
            [],
        );
        // Create second subagent
        let _ = db.conn().execute(
            "INSERT INTO instances (name, tool, session_id, parent_session_id, parent_name, status, status_context, status_time, created_at)
             VALUES ('sub2', 'claude', 'sess-sub2', 'sess-parent', 'parent', 'active', 'new', 0, 0)",
            [],
        );

        // Stop parent — should recursively stop subagents
        stop_instance(&db, "parent", "test", "test_recursive");

        // All three instances should be deleted
        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM instances", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            count, 0,
            "all instances (parent + subagents) should be deleted"
        );

        // Life events should be logged for all three
        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM events WHERE type = 'life'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 3, "life events for parent + 2 subagents");
    }

    #[test]
    fn test_stop_instance_recursive_depth_2() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();

        // parent → sub1 → subsub1 (depth-2 chain proves real recursion)
        let _ = db.conn().execute(
            "INSERT INTO instances (name, tool, session_id, status, status_context, status_time, created_at)
             VALUES ('parent', 'claude', 'sess-p', 'active', 'running', 0, 0)",
            [],
        );
        let _ = db.conn().execute(
            "INSERT INTO instances (name, tool, session_id, parent_session_id, parent_name, status, status_context, status_time, created_at)
             VALUES ('sub1', 'claude', 'sess-s1', 'sess-p', 'parent', 'active', 'running', 0, 0)",
            [],
        );
        let _ = db.conn().execute(
            "INSERT INTO instances (name, tool, session_id, parent_session_id, parent_name, status, status_context, status_time, created_at)
             VALUES ('subsub1', 'claude', 'sess-ss1', 'sess-s1', 'sub1', 'active', 'running', 0, 0)",
            [],
        );

        stop_instance(&db, "parent", "test", "test_depth2");

        // All three levels should be cleaned up
        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM instances", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "all 3 levels should be deleted");

        // Verify life events logged for each level
        let stopped: Vec<String> = db.conn()
            .prepare("SELECT instance FROM events WHERE type = 'life' AND data LIKE '%stopped%' ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(stopped.len(), 3, "life events for all 3 levels");
        // subsub1 stopped first (deepest), then sub1, then parent
        assert_eq!(stopped[0], "subsub1");
        assert_eq!(stopped[1], "sub1");
        assert_eq!(stopped[2], "parent");
    }

    #[test]
    fn test_stop_instance_depth_limit() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();

        // Create a chain deeper than MAX_STOP_DEPTH to verify the limit kicks in
        // We'll create 12 levels (limit is 10)
        for i in 0..12u32 {
            let name = format!("inst{}", i);
            let session_id = format!("sess-{}", i);
            let parent_sid = if i == 0 {
                String::new()
            } else {
                format!("sess-{}", i - 1)
            };

            if i == 0 {
                let _ = db.conn().execute(
                    "INSERT INTO instances (name, tool, session_id, status, status_context, status_time, created_at)
                     VALUES (?1, 'claude', ?2, 'active', 'running', 0, 0)",
                    rusqlite::params![name, session_id],
                );
            } else {
                let parent_name = format!("inst{}", i - 1);
                let _ = db.conn().execute(
                    "INSERT INTO instances (name, tool, session_id, parent_session_id, parent_name, status, status_context, status_time, created_at)
                     VALUES (?1, 'claude', ?2, ?3, ?4, 'active', 'running', 0, 0)",
                    rusqlite::params![name, session_id, parent_sid, parent_name],
                );
            }
        }

        // Stop root. Hitting the depth guard leaves the full chain retryable;
        // partial deletion would orphan the surviving descendants.
        stop_instance(&db, "inst0", "test", "test_depth_limit");

        let remaining: Vec<String> = db
            .conn()
            .prepare("SELECT name FROM instances ORDER BY CAST(SUBSTR(name, 5) AS INTEGER)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(
            remaining,
            (0..12).map(|i| format!("inst{i}")).collect::<Vec<_>>(),
            "an incomplete child cascade must leave every ancestor retryable"
        );
        let stopped: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stopped, 0, "an incomplete cascade must publish no stops");
    }

    #[test]
    fn test_stop_instance_idempotent() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();

        // Create instance
        let _ = db.conn().execute(
            "INSERT INTO instances (name, tool, status, status_context, status_time, created_at)
             VALUES ('inst', 'claude', 'active', 'new', 0, 0)",
            [],
        );

        // Stop twice — second call should be a no-op
        stop_instance(&db, "inst", "test", "first");
        stop_instance(&db, "inst", "test", "second");

        // Only one life event
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = 'inst'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "only one life event for idempotent stop");
    }

    #[test]
    fn test_stop_instance_nonexistent() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();

        // Should be a no-op, not panic
        stop_instance(&db, "nonexistent", "test", "test");
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[serial]
    fn stop_keeps_row_when_launch_persists_pid_mid_reap() {
        use crate::proctruth::{RoundPoint, arm_round_seam};
        use std::os::unix::process::CommandExt;

        let _env = isolated_test_env();
        let (dir, db) = make_test_db();
        let name = format!("launch-race-{}", std::process::id());
        insert_test_instance(&db, &name);
        db.set_process_binding("proc-launch-race", "session-race", &name)
            .unwrap();
        // An old carrier ensures the KILL-round seam fires even though the
        // pre-registered row has no pid yet.
        let _old = OwnedGroup(
            std::process::Command::new("sleep")
                .arg("300")
                .env("HCOM_INSTANCE_NAME", &name)
                .env_remove("HCOM_PROCESS_ID")
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let launched = std::rc::Rc::new(std::cell::RefCell::new(None));
        let observed = launched.clone();
        let launch_db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        let launch_name = name.clone();
        arm_round_seam(move |point| {
            if point == RoundPoint::Captured && observed.borrow().is_none() {
                let child = OwnedGroup(
                    std::process::Command::new("sleep")
                        .arg("300")
                        .env_remove("HCOM_INSTANCE_NAME")
                        .env_remove("HCOM_PROCESS_ID")
                        .process_group(0)
                        .spawn()
                        .unwrap(),
                );
                launch_db
                    .update_instance_pid(&launch_name, child.0.id())
                    .unwrap();
                *observed.borrow_mut() = Some(child);
            }
        });

        let outcome = stop_instance(&db, &name, "test", "stop");
        // Clear the thread-local hook before any assertion can unwind.
        arm_round_seam(|_| {});
        assert!(
            matches!(&outcome, StopOutcome::RetryableError(e) if e.to_string().contains("persisted its pid")),
            "{outcome:?}"
        );
        let pid = launched.borrow().as_ref().expect("seam fired").0.id();
        assert!(crate::sys::process::is_alive(pid));
        assert_eq!(
            db.get_instance_full(&name).unwrap().unwrap().pid,
            Some(pid as i64)
        );
        assert_eq!(
            db.process_binding_ids(&name).unwrap(),
            vec!["proc-launch-race"]
        );
        let stopped: i64 = db.conn().query_row(
            "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = ? AND json_extract(data, '$.action') = 'stopped'",
            params![name], |row| row.get(0),
        ).unwrap();
        assert_eq!(stopped, 0);
    }

    #[test]
    fn test_stale_stop_cannot_delete_reused_name() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, session_id, agent_id, tool, status, status_context, status_time, created_at)
                 VALUES ('inst', 'old-session', 'old-agent', 'claude', 'active', 'running', 0, 1)",
                [],
            )
            .unwrap();
        let old = db.get_instance_full("inst").unwrap().unwrap();
        db.delete_instance("inst").unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, session_id, agent_id, tool, status, status_context, status_time, created_at)
                 VALUES ('inst', 'new-session', 'new-agent', 'claude', 'active', 'running', 0, 2)",
                [],
            )
            .unwrap();
        let event = serde_json::json!({"action": "stopped", "snapshot": {"name": "inst"}});

        let won = db
            .finalize_instance_stop(
                "inst",
                old.created_at,
                old.pid,
                old.session_id.as_deref(),
                old.agent_id.as_deref(),
                &event,
                None,
                None,
            )
            .unwrap();
        assert!(!won, "the stale row incarnation must lose its delete CAS");
        let current = db.get_instance_full("inst").unwrap().unwrap();
        assert_eq!(current.session_id.as_deref(), Some("new-session"));
        let stopped: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = 'inst'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stopped, 0, "a stale stopper must publish no event");
    }

    #[test]
    fn test_child_enumeration_error_keeps_parent_retryable() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, session_id, tool, status, status_context, status_time, created_at)
                 VALUES ('parent', 'sess-1', 'claude', 'active', 'running', 0, 1)",
                [],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, parent_name, tool, status, status_context, status_time, created_at)
                 VALUES (x'80', 'parent', 'claude', 'active', 'running', 0, 2)",
                [],
            )
            .unwrap();

        let outcome = stop_instance(&db, "parent", "test", "child-read-error");
        assert!(matches!(outcome, StopOutcome::RetryableError(_)));
        assert!(db.get_instance("parent").unwrap().is_some());
        let stopped: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = 'parent'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stopped, 0);
    }

    #[test]
    fn test_stop_instance_does_not_publish_until_delete_wins() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, session_id, tool, status, status_context, status_time, created_at)
                 VALUES ('inst', 'sess-1', 'claude', 'active', 'running', 0, 0)",
                [],
            )
            .unwrap();
        db.set_session_binding("sess-1", "inst").unwrap();
        // RAISE(IGNORE) makes DELETE report zero affected rows, modeling a
        // contender that lost the teardown ownership CAS.
        db.conn()
            .execute_batch(
                "CREATE TRIGGER suppress_inst_delete BEFORE DELETE ON instances
                 WHEN OLD.name = 'inst' BEGIN SELECT RAISE(IGNORE); END;",
            )
            .unwrap();

        stop_instance(&db, "inst", "test", "first");
        assert!(db.get_instance("inst").unwrap().is_some());
        assert_eq!(
            db.get_session_binding("sess-1").unwrap().as_deref(),
            Some("inst"),
            "a failed ownership delete must leave bindings retryable"
        );
        let stopped: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = 'inst'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stopped, 0, "a losing teardown must not publish stopped");

        db.conn()
            .execute_batch("DROP TRIGGER suppress_inst_delete;")
            .unwrap();

        // Event insertion and deletion form one transaction. If publication
        // fails, SQLite must restore both the row and its binding.
        db.conn()
            .execute_batch(
                "CREATE TRIGGER reject_stopped_event BEFORE INSERT ON events
                 WHEN NEW.type = 'life' AND NEW.instance = 'inst'
                 BEGIN SELECT RAISE(ABORT, 'injected event failure'); END;",
            )
            .unwrap();
        stop_instance(&db, "inst", "test", "event-failure");
        assert!(db.get_instance("inst").unwrap().is_some());
        assert_eq!(
            db.get_session_binding("sess-1").unwrap().as_deref(),
            Some("inst"),
            "event failure must roll back deletion and cleanup"
        );
        db.conn()
            .execute_batch("DROP TRIGGER reject_stopped_event;")
            .unwrap();

        stop_instance(&db, "inst", "test", "retry");
        assert!(db.get_instance("inst").unwrap().is_none());
        let stopped: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = 'inst'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stopped, 1, "the retry winner publishes exactly once");
    }

    #[test]
    #[serial]
    fn session_finalizers_yield_to_live_teardown_claim() {
        let _env = isolated_test_env();
        let (_dir, db) = make_test_db();
        for soft in [false, true] {
            let name = if soft { "claim-soft" } else { "claim-hard" };
            insert_test_instance(&db, name);
            db.set_process_binding("claim-process", "claim-session", name)
                .unwrap();
            // Integer timestamps hid the lossy JSON float parser. This
            // fractional created_at must keep the live claim's identity.
            let created_at = f64::from_bits(4745294612153761801);
            db.conn()
                .execute(
                    "UPDATE instances SET created_at = ? WHERE name = ?",
                    params![created_at, name],
                )
                .unwrap();
            let _claim = TeardownClaim::register(&db, name, created_at, None).unwrap();
            let updates = serde_json::json!({"transcript_path": "/ended/transcript"});
            if soft {
                soft_finalize_session(&db, name, "shutdown", updates.as_object(), false);
            } else {
                assert_eq!(
                    finalize_session(&db, name, "shutdown", updates.as_object()),
                    StopOutcome::AlreadyStopped,
                );
            }
            let row = db
                .get_instance_full(name)
                .unwrap()
                .expect("claimed row retained");
            assert_eq!(row.status, ST_INACTIVE);
            assert_eq!(row.status_context, "exit:shutdown");
            assert_eq!(row.transcript_path, "/ended/transcript");
            assert_eq!(db.process_binding_ids(name).unwrap(), vec!["claim-process"]);
            let events: i64 = db
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE instance = ? AND type = 'life' AND json_extract(data, '$.action') = 'stopped'",
                    [name],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(events, 0, "yield leaves the stopped event to the kill");
        }
    }

    #[test]
    #[serial]
    fn yielded_exit_does_not_update_re_registered_name() {
        let _env = isolated_test_env();
        for (created_at, session_id) in [(1.0, None), (0.0, Some("replacement-session"))] {
            let (_dir, db) = make_test_db();
            insert_test_instance(&db, "reused");
            let _claim = TeardownClaim::register(&db, "reused", 0.0, None).unwrap();
            let incarnation = match yield_to_teardown(&db, "reused") {
                TeardownYield::YieldTo(created_at, session_id) => (created_at, session_id),
                _ => panic!("live claim matches"),
            };
            db.delete_instance("reused").unwrap();
            insert_test_instance(&db, "reused");
            db.conn().execute(
                "UPDATE instances SET created_at = ?, session_id = ?, transcript_path = '/new/session' WHERE name = 'reused'",
                params![created_at, session_id],
            ).unwrap();

            let updates = serde_json::json!({"transcript_path": "/old/session"});
            persist_yielded_session_exit(
                &db,
                "reused",
                incarnation,
                "shutdown",
                updates.as_object(),
            );

            let row = db.get_instance_full("reused").unwrap().unwrap();
            assert_eq!(row.status, ST_LISTENING);
            assert_eq!(row.status_context, "start");
            assert_eq!(row.transcript_path, "/new/session");
            assert_eq!(row.created_at, created_at);
            assert_eq!(row.session_id.as_deref(), session_id);
            let events: i64 = db
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE instance = 'reused'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(events, 0, "a superseded yield writes no event");
        }
    }

    #[test]
    #[serial]
    fn session_finalize_ignores_claim_for_another_incarnation() {
        let _env = isolated_test_env();
        for (created_at, session_id) in [(1.0, None), (0.0, Some("new-session"))] {
            let (_dir, db) = make_test_db();
            insert_test_instance(&db, "reclaimed");
            let _claim = TeardownClaim::register(&db, "reclaimed", 0.0, None).unwrap();
            db.conn()
                .execute(
                    "UPDATE instances SET created_at = ?, session_id = ? WHERE name = 'reclaimed'",
                    params![created_at, session_id],
                )
                .unwrap();

            assert_eq!(
                finalize_session(&db, "reclaimed", "shutdown", None),
                StopOutcome::Stopped,
            );
            assert!(db.get_instance_full("reclaimed").unwrap().is_none());
            let snapshot = newest_stopped_snapshot(&db, "reclaimed");
            assert_eq!(snapshot["created_at"], serde_json::json!(created_at));
            assert_eq!(snapshot["session_id"], serde_json::json!(session_id));
        }
    }

    #[test]
    #[serial]
    fn session_finalizers_ignore_stale_and_malformed_teardown_claims() {
        let _env = isolated_test_env();
        let (_dir, db) = make_test_db();
        for value in [
            "not-json".to_string(),
            serde_json::json!({"pid": std::process::id(), "process_start": "wrong-start", "created_at_bits": 0_u64, "session_id": null})
                .to_string(),
            serde_json::json!({"pid": u32::MAX, "process_start": "dead", "created_at_bits": 0_u64, "session_id": null}).to_string(),
        ] {
            for soft in [false, true] {
                let name = "stale-claim";
                insert_test_instance(&db, name);
                db.set_process_binding("stale-process", "stale-session", name)
                    .unwrap();
                db.kv_set(&format!("teardown_claim:{name}"), Some(&value))
                    .unwrap();
                if soft {
                    soft_finalize_session(&db, name, "shutdown", None, false);
                    assert_eq!(
                        db.get_instance_full(name).unwrap().unwrap().status,
                        ST_INACTIVE
                    );
                    db.delete_instance(name).unwrap();
                } else {
                    assert_eq!(
                        finalize_session(&db, name, "shutdown", None),
                        StopOutcome::Stopped
                    );
                    assert!(db.get_instance_full(name).unwrap().is_none());
                }
                assert!(db.process_binding_ids(name).unwrap().is_empty());
                let reason: String = db.conn().query_row(
                    "SELECT json_extract(data, '$.reason') FROM events WHERE instance = ? AND json_extract(data, '$.action') = 'stopped' ORDER BY id DESC LIMIT 1",
                    [name], |row| row.get(0),
                ).unwrap();
                assert_eq!(reason, "exit:shutdown");
            }
        }
    }

    #[test]
    #[serial]
    fn teardown_claim_drop_clears_only_its_own_owner() {
        let _env = isolated_test_env();
        let (_dir, db) = make_test_db();
        let key = "teardown_claim:claim-owner";
        db.kv_set(key, Some(r#"{"pid":1,"process_start":"stale"}"#))
            .unwrap();
        insert_test_instance(&db, "claim-owner");
        let claim = TeardownClaim::register(&db, "claim-owner", 0.0, None).unwrap();
        assert!(
            !matches!(
                yield_to_teardown(&db, "claim-owner"),
                TeardownYield::NoClaim
            ),
            "stale owner replaced"
        );
        drop(claim);
        assert!(db.kv_get(key).unwrap().is_none());

        let claim = TeardownClaim::register(&db, "claim-owner", 0.0, None).unwrap();
        let foreign = serde_json::json!({
            "pid": std::process::id().wrapping_add(1),
            "process_start": "another-killer",
            "created_at_bits": 0_u64,
            "session_id": null,
        })
        .to_string();
        db.kv_set(key, Some(&foreign)).unwrap();
        drop(claim);
        assert_eq!(db.kv_get(key).unwrap().as_deref(), Some(foreign.as_str()));
    }

    #[test]
    fn test_finalize_session_calls_stop() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();

        // Use status_context != "new" to avoid triggering the "ready" life event
        let _ = db.conn().execute(
            "INSERT INTO instances (name, tool, session_id, status, status_context, status_time, created_at)
             VALUES ('inst', 'claude', 'sess-1', 'active', 'running', 0, 0)",
            [],
        );

        let outcome = finalize_session(&db, "inst", "user_quit", None);
        assert_eq!(outcome, StopOutcome::Stopped);

        // Instance should be deleted
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM instances WHERE name = 'inst'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "finalize_session should delete instance");

        // "stopped" life event logged
        let count: i64 = db.conn().query_row(
            "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = 'inst' AND data LIKE '%stopped%'",
            [], |r| r.get(0)
        ).unwrap();
        assert_eq!(count, 1, "stopped life event should be logged");
    }

    #[test]
    fn test_stale_placeholder_marker_does_not_rebind() {
        crate::config::Config::init();
        let (dir, db) = make_test_db();

        // Simulate a leaked launch placeholder older than the stale threshold.
        let old_time = crate::shared::time::now_epoch_f64()
            - (lifecycle::CLEANUP_PLACEHOLDER_THRESHOLD as f64 + 80.0);
        let _ = db.conn().execute(
            "INSERT INTO instances (name, tool, status, status_context, created_at)
             VALUES ('luna', 'claude', 'pending', 'new', ?1)",
            rusqlite::params![old_time],
        );

        let transcript = dir.path().join("transcript.jsonl");
        std::fs::write(&transcript, "assistant output [hcom:luna]\n").unwrap();

        let ctx = crate::shared::context::HcomContext::from_env(
            &std::collections::HashMap::new(),
            dir.path().to_path_buf(),
        );
        let (instance_name, _updates, _matched_resume) =
            init_hook_context(&db, &ctx, "sess-fresh", transcript.to_str().unwrap());

        assert!(
            instance_name.is_none(),
            "stale placeholder should be cleaned before transcript binding"
        );

        assert!(
            db.get_instance_full("luna").unwrap().is_none(),
            "stale placeholder row should be deleted"
        );

        assert_eq!(
            db.get_session_binding("sess-fresh").unwrap(),
            None,
            "fresh session must not get bound via stale marker"
        );
    }

    #[test]
    fn soft_finalize_session_keeps_instance_row() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();
        let now = chrono::Utc::now().timestamp() as f64;
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, session_id)
                 VALUES ('vine', 'listening', ?1, 'antigravity', 'sess-soft-1')",
                rusqlite::params![now],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO session_bindings (session_id, instance_name, created_at)
                 VALUES ('sess-soft-1', 'vine', ?1)",
                rusqlite::params![now],
            )
            .unwrap();

        db.conn()
            .execute(
                "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
                 VALUES ('pid-soft', 'sess-soft-1', 'vine', ?1)",
                rusqlite::params![now],
            )
            .unwrap();

        soft_finalize_session(&db, "vine", "unknown", None, false);

        assert!(db.get_instance_full("vine").unwrap().is_some());
        let status = db.get_status("vine").unwrap().map(|(s, _)| s);
        assert_eq!(status.as_deref(), Some(ST_INACTIVE));
        assert_eq!(db.get_session_binding("sess-soft-1").unwrap(), None);
        assert_eq!(
            db.find_stopped_instance_by_session_id("sess-soft-1")
                .unwrap()
                .as_deref(),
            Some("vine")
        );
        assert_eq!(db.get_process_binding("pid-soft").unwrap(), None);
    }

    #[test]
    fn soft_finalize_session_can_keep_process_binding() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();
        let now = chrono::Utc::now().timestamp() as f64;
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, session_id)
                 VALUES ('luna', 'listening', ?1, 'omp', 'sess-keep')",
                rusqlite::params![now],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO session_bindings (session_id, instance_name, created_at)
                 VALUES ('sess-keep', 'luna', ?1)",
                rusqlite::params![now],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
                 VALUES ('pid-keep', 'sess-keep', 'luna', ?1)",
                rusqlite::params![now],
            )
            .unwrap();

        soft_finalize_session(&db, "luna", "turn_end", None, true);

        assert_eq!(
            db.get_process_binding("pid-keep").unwrap(),
            Some("luna".to_string())
        );
        assert_eq!(db.get_session_binding("sess-keep").unwrap(), None);
        assert_eq!(
            db.get_status("luna").unwrap().map(|(s, _)| s),
            Some(ST_INACTIVE.to_string())
        );
    }

    /// Newest `stopped` life-event snapshot for `name`.
    fn newest_stopped_snapshot(db: &crate::db::HcomDb, name: &str) -> Value {
        let data: String = db
            .conn()
            .query_row(
                "SELECT data FROM events WHERE type = 'life' AND instance = ?1
                   AND json_extract(data, '$.action') = 'stopped'
                 ORDER BY id DESC LIMIT 1",
                [name],
                |r| r.get(0),
            )
            .unwrap();
        serde_json::from_str::<Value>(&data).unwrap()["snapshot"].clone()
    }

    fn insert_titled_instance(db: &crate::db::HcomDb, name: &str) {
        insert_test_instance(db, name);
        crate::title::set_purpose(db, name, "zagdb: rc.48 roll");
        crate::title::set_current(db, name, "probing WAL");
    }

    #[test]
    fn soft_stop_snapshot_carries_purpose_and_current() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();
        insert_titled_instance(&db, "tala");

        soft_finalize_session(&db, "tala", "shutdown", None, true);

        let snapshot = newest_stopped_snapshot(&db, "tala");
        assert_eq!(snapshot["purpose"], "zagdb: rc.48 roll");
        assert_eq!(snapshot["current"], "probing WAL");
    }

    #[test]
    fn hard_stop_snapshot_carries_purpose_and_current() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();
        insert_titled_instance(&db, "tala");

        assert_eq!(
            stop_instance(&db, "tala", "test", "exit:shutdown"),
            StopOutcome::Stopped
        );

        let snapshot = newest_stopped_snapshot(&db, "tala");
        assert_eq!(snapshot["purpose"], "zagdb: rc.48 roll");
        assert_eq!(snapshot["current"], "probing WAL");
    }

    fn insert_headless_instance(db: &crate::db::HcomDb, name: &str, pid: u32) {
        insert_test_instance(db, name);
        db.conn()
            .execute(
                "UPDATE instances SET background = 1, pid = ?1 WHERE name = ?2",
                rusqlite::params![pid as i64, name],
            )
            .unwrap();
    }

    /// Test-owned process group: Drop SIGKILLs the whole group the spawned
    /// leader leads (Windows: its tree), then reaps the leader. The leader is
    /// never reaped before that, so its pgid cannot be recycled under the
    /// signal, and no failure path, panics included, leaves a member running.
    struct OwnedGroup(std::process::Child);

    impl Drop for OwnedGroup {
        fn drop(&mut self) {
            crate::sys::process::kill_child_group(&mut self.0);
            let _ = self.0.wait();
        }
    }

    #[cfg(target_os = "linux")]
    fn process_gone(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            Ok(stat) => stat
                .rsplit_once(')')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
        }
    }

    #[cfg(target_os = "linux")]
    fn wait_gone(pid: u32) -> bool {
        for _ in 0..50 {
            if process_gone(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// The headless shape in a group the test owns: a `sh` leader (the
    /// recorded pid, carrying no identity) over a carrier of `name` and a
    /// member carrying nothing, which only a group signal reaches. Returns
    /// (group, carrier, member) once the carrier is enumerable.
    #[cfg(target_os = "linux")]
    fn spawn_headless_group(name: &str) -> (OwnedGroup, u32, u32) {
        use std::io::BufRead;
        use std::os::unix::process::CommandExt;
        let mut group = OwnedGroup(
            std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "env HCOM_INSTANCE_NAME={name} sleep 300 >/dev/null 2>&1 & echo $!; \
                     sleep 300 >/dev/null 2>&1 & echo $!; wait"
                ))
                .env_remove("HCOM_INSTANCE_NAME")
                .env_remove("HCOM_PROCESS_ID")
                .stdout(std::process::Stdio::piped())
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let mut pids = std::io::BufReader::new(group.0.stdout.take().unwrap())
            .lines()
            .map(|line| line.unwrap().trim().parse::<u32>().unwrap());
        let carrier = pids.next().unwrap();
        let member = pids.next().unwrap();
        // `$!` is echoed while the job may still be `env`, before it execs
        // `sleep` with the name; stopping earlier would find no carrier.
        let enumerated = (0..50).any(|_| {
            let found = crate::proctruth::processes_for_instance(name, &[], &[])
                .iter()
                .any(|m| m.pid == carrier);
            if !found {
                std::thread::sleep(Duration::from_millis(100));
            }
            found
        });
        assert!(
            enumerated,
            "carrier {carrier} never enumerated as a carrier of {name}"
        );
        (group, carrier, member)
    }

    /// A headless row whose recorded pid was reused by an unrelated process
    /// (own group, no hcom identity anywhere in it): the stop must not signal
    /// it, and the row is still released.
    #[cfg(target_os = "linux")]
    #[test]
    fn headless_stop_does_not_signal_reused_pid() {
        use std::os::unix::process::CommandExt;
        crate::config::Config::init();
        let (_dir, db) = make_test_db();
        let name = format!("reuse{}", std::process::id());
        let mut stranger = std::process::Command::new("sleep")
            .arg("300")
            .env_remove("HCOM_INSTANCE_NAME")
            .env_remove("HCOM_PROCESS_ID")
            .process_group(0)
            .spawn()
            .unwrap();
        insert_headless_instance(&db, &name, stranger.id());

        let outcome = stop_instance(&db, &name, "test", "reused_pid");

        let alive = stranger.try_wait().unwrap().is_none();
        let _ = stranger.kill();
        let _ = stranger.wait();
        assert_eq!(outcome, StopOutcome::Stopped);
        assert!(alive, "unrelated process at the recorded pid was signalled");
        assert!(db.get_instance_full(&name).unwrap().is_none());
    }

    /// The real headless shape: the recorded pid leads the group without
    /// carrying the identity; a carrier below it does. The stop signals the
    /// whole group, so the member no reap would find dies too.
    #[cfg(target_os = "linux")]
    #[test]
    fn headless_stop_signals_group_holding_a_carrier() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();
        let name = format!("carry{}", std::process::id());
        let (group, carrier, member) = spawn_headless_group(&name);
        let leader = group.0.id();
        insert_headless_instance(&db, &name, leader);

        let outcome = stop_instance(&db, &name, "test", "headless_stop");

        assert_eq!(outcome, StopOutcome::Stopped);
        assert!(wait_gone(leader), "group leader survived the headless stop");
        assert!(
            wait_gone(carrier),
            "carrier {carrier} survived the headless stop"
        );
        assert!(
            wait_gone(member),
            "member {member} survived the headless stop"
        );
    }

    /// The session's own release (non-empty `exclude`) never signals a
    /// recorded group holding a pid of its own tree, even when the recorded
    /// pid itself is not excluded. The reap still takes every other carrier,
    /// and the row is released.
    #[cfg(target_os = "linux")]
    #[test]
    fn self_release_spares_group_holding_its_own_tree() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();
        let name = format!("selfin{}", std::process::id());
        let (group, carrier, member) = spawn_headless_group(&name);
        insert_headless_instance(&db, &name, group.0.id());

        // `member` stands in for the releasing CLI: inside the group, excluded.
        let outcome = finalize_session_excluding(&db, &name, "shutdown", None, &[member]);

        assert_eq!(outcome, StopOutcome::Stopped);
        assert!(wait_gone(carrier), "carrier {carrier} survived the release");
        assert!(
            !process_gone(member),
            "the release signalled a group holding its own tree"
        );
        assert!(db.get_instance_full(&name).unwrap().is_none());
    }

    /// Linux proves from /proc that the caller's tree is outside a recorded
    /// group, so the session's own release still signals that group.
    #[cfg(target_os = "linux")]
    #[test]
    fn self_release_signals_headless_group_outside_its_tree() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();
        let name = format!("selfout{}", std::process::id());
        let (group, _carrier, member) = spawn_headless_group(&name);
        insert_headless_instance(&db, &name, group.0.id());

        let outcome = finalize_session_excluding(
            &db,
            &name,
            "shutdown",
            None,
            &crate::proctruth::caller_ancestor_pids(),
        );

        assert_eq!(outcome, StopOutcome::Stopped);
        assert!(wait_gone(member), "member {member} survived the release");
        assert!(db.get_instance_full(&name).unwrap().is_none());
    }

    /// Off Linux nothing sees a session's other carriers, so its own release
    /// keeps the row instead of deleting it on a blind reap: soft-stopped as
    /// by `omp-stop --soft` (inactive, one stopped event, process binding
    /// kept), with no signal to anything, a headless row's recorded group
    /// included.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn self_release_keeps_row_off_linux() {
        crate::config::Config::init();
        let (_dir, db) = make_test_db();
        let name = format!("selfoff{}", std::process::id());
        #[cfg(windows)]
        let root = OwnedGroup(
            std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 300"])
                .spawn()
                .unwrap(),
        );
        #[cfg(unix)]
        let root = {
            use std::os::unix::process::CommandExt;
            OwnedGroup(
                std::process::Command::new("sleep")
                    .arg("300")
                    .process_group(0)
                    .spawn()
                    .unwrap(),
            )
        };
        let pid = root.0.id();
        insert_headless_instance(&db, &name, pid);
        db.set_process_binding("proc-selfoff", "", &name).unwrap();

        let outcome = finalize_session_excluding(
            &db,
            &name,
            "shutdown",
            None,
            &crate::proctruth::caller_ancestor_pids(),
        );

        assert_eq!(outcome, StopOutcome::Stopped);
        assert!(
            crate::sys::process::is_alive(pid),
            "the session's own release signalled the recorded group"
        );
        let row = db
            .get_instance_full(&name)
            .unwrap()
            .expect("the session's own release deleted the row off Linux");
        assert_eq!(row.status, ST_INACTIVE);
        assert_eq!(
            db.process_binding_ids(&name).unwrap(),
            vec!["proc-selfoff".to_string()]
        );
        let stopped: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = ?1
                   AND json_extract(data, '$.action') = 'stopped'",
                [&name],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stopped, 1);
    }
}
