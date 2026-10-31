use super::*;
use crate::db::HcomDb;
use crate::instances;
use crate::shared::context::HcomContext;
use crate::shared::{ST_ACTIVE, ST_LISTENING};
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn setup_test_db() -> (HcomDb, PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let temp_dir = std::env::temp_dir();
    let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let db_path = temp_dir.join(format!(
        "test_omp_hooks_{}_{}.db",
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

fn save_test_instance(db: &HcomDb, name: &str, status: &str) {
    let mut row = serde_json::Map::new();
    row.insert("name".into(), serde_json::json!(name));
    row.insert("tool".into(), serde_json::json!("omp"));
    row.insert("status".into(), serde_json::json!(status));
    row.insert("status_context".into(), serde_json::json!(""));
    row.insert("status_detail".into(), serde_json::json!(""));
    row.insert("created_at".into(), serde_json::json!(1.0));
    db.save_instance_named(name, &row).unwrap();
}

fn test_omp_owner() -> crate::proctruth::OmpOwner {
    let pid = std::process::id();
    crate::proctruth::OmpOwner {
        pid,
        incarnation: crate::sys::process::identity(pid).expect("native test process identity"),
    }
}

fn test_process_id(suffix: &str) -> String {
    format!("omp-{}-{suffix}", std::process::id())
}

fn pin_test_omp_owner(db: &HcomDb, name: &str) {
    let owner = test_omp_owner();
    let row = db.get_instance_full(name).unwrap().unwrap();
    let mut context: serde_json::Map<String, serde_json::Value> = row
        .launch_context
        .as_deref()
        .map(|json| serde_json::from_str(json).unwrap())
        .unwrap_or_default();
    context.insert("omp_owner".into(), serde_json::json!(owner));
    db.update_instance_fields(
        name,
        &serde_json::Map::from_iter([
            ("pid".into(), serde_json::json!(owner.pid)),
            (
                "launch_context".into(),
                serde_json::json!(serde_json::to_string(&context).unwrap()),
            ),
        ]),
    )
    .unwrap();
}

fn bind_test_omp_process(db: &HcomDb, name: &str, session: &str, suffix: &str) {
    pin_test_omp_owner(db, name);
    db.set_process_binding(&test_process_id(suffix), session, name)
        .unwrap();
}

fn start_through_caller_gate(ctx: &HcomContext, db: &HcomDb, argv: &[String]) -> (i32, String) {
    let owner = match crate::hooks::common::omp_hook_caller_gate(ctx, db, "omp-start", argv) {
        Ok(Some(owner)) => owner,
        Err(refusal) => return refusal,
        Ok(None) => unreachable!("omp-start is recognized"),
    };
    handle_start(ctx, db, argv, &owner)
}

// Only substitute the native caller boundary, scoped to this one invocation.
// Real process-id shape, mapped-row evidence, owner pins and all writes remain
// checked by the production binding/readiness path.
fn start_as_test_owner(ctx: &HcomContext, db: &HcomDb, argv: &[String]) -> (i32, String) {
    crate::instance_binding::with_omp_binding_owner(test_omp_owner(), || {
        start_through_caller_gate(ctx, db, argv)
    })
}

fn bind_probe() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn await_connect(listener: &TcpListener, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(_) => return true,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return false,
        }
    }
}

#[test]
#[serial_test::serial]
fn strip_managed_extension_removes_only_hcom_entry() {
    with_isolated_omp_env(|_| {
        let current = get_omp_plugin_path().to_string_lossy().to_string();

        // Current managed path (two-token) is removed; user extension survives.
        let mut args = vec![
            "--model".into(),
            "opus".into(),
            "-e".into(),
            current.clone(),
            "-e".into(),
            "/home/u/mine.ts".into(),
        ];
        strip_managed_extension_args(&mut args);
        assert_eq!(
            args,
            vec!["--model", "opus", "-e", "/home/u/mine.ts"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );

        // Idempotent.
        let once = args.clone();
        strip_managed_extension_args(&mut args);
        assert_eq!(args, once);

        // Legacy/moved managed path (missing file) via lexical fallback:
        // basename hcom.ts under an `extensions` dir, incl. the `=` form.
        let mut legacy = vec![
            "--extension=/old/place/.omp/agent/extensions/hcom.ts".into(),
            "--extension".into(),
            "/old/place/extensions/hcom.ts".into(),
            "--extension=/home/u/other.ts".into(),
        ];
        strip_managed_extension_args(&mut legacy);
        assert_eq!(legacy, vec!["--extension=/home/u/other.ts".to_string()]);

        // A user extension merely named hcom.ts but NOT under `extensions/` is
        // preserved (narrow matcher).
        let mut keep = vec!["-e".into(), "/home/u/project/hcom.ts".into()];
        strip_managed_extension_args(&mut keep);
        assert_eq!(
            keep,
            vec!["-e".to_string(), "/home/u/project/hcom.ts".to_string()]
        );

        // An EXISTING non-hcom file at extensions/hcom.ts must survive: the
        // lexical fallback applies only to moved/missing files.
        let dir = tempfile::tempdir().unwrap();
        let ext_dir = dir.path().join("extensions");
        std::fs::create_dir_all(&ext_dir).unwrap();
        let user_file = ext_dir.join("hcom.ts");
        std::fs::write(&user_file, "export default () => {}; // not hcom").unwrap();
        let user_arg = user_file.to_string_lossy().to_string();
        let mut existing = vec!["-e".into(), user_arg.clone()];
        strip_managed_extension_args(&mut existing);
        assert_eq!(existing, vec!["-e".to_string(), user_arg]);
    });
}

#[test]
fn plugin_bootstraps_via_hidden_message() {
    assert!(PLUGIN_SOURCE.contains("before_agent_start"));
    assert!(PLUGIN_SOURCE.contains("customType: \"hcom-bootstrap\""));
    assert!(PLUGIN_SOURCE.contains("display: false"));
    assert!(!PLUGIN_SOURCE.contains("text: `${bootstrapText}\\n\\n${event.text}`"));
}

#[test]
fn plugin_reconcile_does_not_report_active_polling_status() {
    assert!(
        !PLUGIN_SOURCE
            .contains("reportStatus(currentCtx, currentCtx.isIdle() ? \"listening\" : \"active\")")
    );
    assert!(PLUGIN_SOURCE.contains("pi.on(\"agent_end\""));
    assert!(PLUGIN_SOURCE.contains("IDLE_DEBOUNCE_MS"));
    assert!(PLUGIN_SOURCE.contains("currentCtx?.isIdle()"));
    assert!(!PLUGIN_SOURCE.contains("pi.on(\"turn_end\", async (_event, ctx) => {\n\t\tcurrentCtx = ctx;\n\t\tawait reportStatus(ctx, \"listening\");"));
}

#[test]
fn plugin_delivery_reports_active_edge() {
    assert!(PLUGIN_SOURCE.contains("reportStatus(ctx, \"active\""));
    assert!(PLUGIN_SOURCE.contains("`deliver:${sender}`"));
}

// The embedded plugin is include_str!'d and never tsc'd, so these guard the
// delivery-correctness invariants that upstream API/lifecycle drift silently
// broke before (see PR review). They pin behavior, not just strings.

#[test]
fn plugin_acks_transform_submission_in_before_agent_start() {
    // omp applies the bodyless-wake transform inline (no source:"extension"
    // re-emit), so the transform-path ack must happen in before_agent_start.
    // Without it pendingAckId stays set and deliverPending jams forever.
    let idx = PLUGIN_SOURCE
        .find("pi.on(\"before_agent_start\"")
        .expect("before_agent_start handler present");
    assert!(
        PLUGIN_SOURCE[idx..].contains("ackPending(\"before_agent_start\")"),
        "before_agent_start must ack the inline transform submission"
    );
    assert!(PLUGIN_SOURCE.contains("if (pendingAckId !== null) await ackPending"));
}

#[test]
fn plugin_replays_wakes_dropped_during_in_flight_window() {
    // In-flight/pending-ack wakes must be queued and replayed, not dropped.
    assert!(PLUGIN_SOURCE.contains("deliveryPending"));
    assert!(PLUGIN_SOURCE.contains("schedulePendingDelivery"));
    assert!(PLUGIN_SOURCE.contains("drainPendingDelivery"));
    // ackPending drains so the transform-path ack replays queued wakes.
    let idx = PLUGIN_SOURCE
        .find("async function ackPending")
        .expect("ackPending present");
    assert!(PLUGIN_SOURCE[idx..].contains("drainPendingDelivery(\"post_ack_wake\")"));
}

#[test]
fn plugin_keeps_ack_gate_until_command_succeeds() {
    let idx = PLUGIN_SOURCE
        .find("async function ackPending")
        .expect("ackPending present");
    let ack = &PLUGIN_SOURCE[idx..];
    let command = ack.find("await hcom([\"omp-read\"").expect("ack command");
    let clear = ack.find("pendingAckId = null").expect("pending ack clear");
    assert!(
        command < clear,
        "pendingAckId must remain set while the ack command is in flight"
    );
    assert!(ack.contains("if (result.code !== 0)"));
    assert!(ack.contains("plugin.delivery_ack_failed"));
    assert!(PLUGIN_SOURCE.contains("ackInFlight"));
    assert!(PLUGIN_SOURCE.contains("await ackPending(\"reconcile\")"));
}

#[test]
fn start_handler_registering_plugin_notify_wakes_pty_delivery_loop() {
    let _env = isolated_omp_env();
    let (db, path) = setup_test_db();
    let temp = tempfile::TempDir::new().unwrap();
    save_test_instance(&db, "luna", ST_ACTIVE);
    bind_test_omp_process(&db, "luna", "", "notify");

    let pty_listener = bind_probe();
    let pty_port = pty_listener.local_addr().unwrap().port();
    db.upsert_notify_endpoint("luna", "pty", pty_port).unwrap();

    let plugin_listener = bind_probe();
    let plugin_port = plugin_listener.local_addr().unwrap().port();

    let env = std::collections::HashMap::from([
        ("HCOM_PROCESS_ID".to_string(), test_process_id("notify")),
        ("HCOM_LAUNCHED".to_string(), "1".to_string()),
        ("HCOM_TOOL".to_string(), "omp".to_string()),
    ]);
    let ctx = HcomContext::from_env(&env, temp.path().to_path_buf());

    let (code, output) = start_as_test_owner(
        &ctx,
        &db,
        &[
            "--session-id".to_string(),
            "sid-omp".to_string(),
            "--notify-port".to_string(),
            plugin_port.to_string(),
            "--cwd".to_string(),
            temp.path().to_string_lossy().to_string(),
        ],
    );

    assert_eq!(code, 0);
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(response.get("name").and_then(|v| v.as_str()), Some("luna"));
    assert!(db.has_notify_endpoint_kind("luna", "plugin"));

    let stored_plugin_port: i64 = db
        .conn()
        .query_row(
            "SELECT port FROM notify_endpoints WHERE instance = 'luna' AND kind = 'plugin'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_plugin_port, i64::from(plugin_port));
    assert!(
        await_connect(&pty_listener, Duration::from_millis(500)),
        "successful plugin bind must wake the PTY delivery loop so launch readiness is observed promptly"
    );

    drop(plugin_listener);
    cleanup(path);
}

#[test]
#[serial_test::serial]
fn omp_role_registers_delivery_role_for_the_bound_session() {
    // The policy exists before the env points at the dir (see
    // `isolated_test_env_with_config`).
    let _env = crate::hooks::test_helpers::isolated_test_env_with_config(Some(
        "[delivery.conductor]\ndelegate = \"mupe\"\n",
    ));
    unsafe {
        std::env::remove_var("PI_CODING_AGENT_DIR");
    }
    let (db, path) = setup_test_db();
    let temp = tempfile::TempDir::new().unwrap();
    save_test_instance(&db, "luna", ST_ACTIVE);
    bind_test_omp_process(&db, "luna", "", "role");
    let env = std::collections::HashMap::from([
        ("HCOM_PROCESS_ID".to_string(), test_process_id("role")),
        ("HCOM_LAUNCHED".to_string(), "1".to_string()),
        ("HCOM_TOOL".to_string(), "omp".to_string()),
    ]);
    let ctx = HcomContext::from_env(&env, temp.path().to_path_buf());
    let (code, output) = start_as_test_owner(
        &ctx,
        &db,
        &["--session-id".to_string(), "sid-omp".to_string()],
    );
    assert_eq!(code, 0);
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(response["name"].as_str(), Some("luna"), "{output}");
    let role = |session: &str| {
        let argv: Vec<String> = [
            "--name",
            "luna",
            "--session-id",
            session,
            "--role",
            "conductor",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let (code, output) = handle_role(&db, &argv);
        assert_eq!(code, 0);
        serde_json::from_str::<serde_json::Value>(&output).unwrap()
    };

    // Bound without the marker: no role, the filter is off, and bind says so.
    assert_eq!(
        crate::delivery_policy::role_status_lines(&db),
        vec!["conductor role: NONE".to_string()]
    );
    let log = std::fs::read_to_string(crate::paths::log_path()).unwrap_or_default();
    assert!(log.contains("\"role_unheld\""), "{log}");

    // Another session cannot claim the row's role; the bound session can.
    assert!(role("sid-other")["error"].is_string());
    assert_eq!(role("sid-omp")["ok"], serde_json::json!(true));
    assert_eq!(
        crate::delivery_policy::role_status_lines(&db),
        vec!["conductor role: luna".to_string()]
    );
    cleanup(path);
}

#[test]
fn plugin_notify_registration_failure_does_not_wake_delivery_loop() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_ACTIVE);

    let pty_listener = bind_probe();
    let pty_port = pty_listener.local_addr().unwrap().port();
    db.upsert_notify_endpoint("luna", "pty", pty_port).unwrap();

    db.conn()
        .execute_batch(
            "CREATE TRIGGER fail_plugin_notify_insert
             BEFORE INSERT ON notify_endpoints
             WHEN NEW.kind = 'plugin'
             BEGIN
               SELECT RAISE(ABORT, 'plugin registration blocked');
             END;",
        )
        .unwrap();

    let plugin_listener = bind_probe();
    let plugin_port = plugin_listener.local_addr().unwrap().port();
    assert!(upsert_plugin_notify_endpoint(&db, "luna", plugin_port).is_err());

    assert!(!db.has_notify_endpoint_kind("luna", "plugin"));
    assert!(
        !await_connect(&pty_listener, Duration::from_millis(100)),
        "failed plugin bind must not wake delivery loops"
    );

    drop(plugin_listener);
    cleanup(path);
}

#[test]
fn status_handler_wakes_plugin_only_when_entering_listening() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_LISTENING);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    db.upsert_notify_endpoint("luna", "plugin", port).unwrap();

    let argv = vec![
        "--name".to_string(),
        "luna".to_string(),
        "--status".to_string(),
        ST_LISTENING.to_string(),
    ];
    let (code, _) = handle_status(&db, &argv);
    assert_eq!(code, 0);
    std::thread::sleep(Duration::from_millis(20));
    assert!(listener.accept().is_err());

    let mut updates = serde_json::Map::new();
    updates.insert("status".into(), serde_json::json!(ST_ACTIVE));
    instances::update_instance_position(&db, "luna", &updates);

    let (code, _) = handle_status(&db, &argv);
    assert_eq!(code, 0);
    let mut accepted = false;
    for _ in 0..10 {
        if listener.accept().is_ok() {
            accepted = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(accepted);

    cleanup(path);
}

#[test]
fn start_handler_uses_central_binding_for_existing_session() {
    let _env = isolated_omp_env();
    let (db, path) = setup_test_db();
    let temp = tempfile::TempDir::new().unwrap();

    let mut canonical = serde_json::Map::new();
    canonical.insert("name".into(), serde_json::json!("miso"));
    canonical.insert("tool".into(), serde_json::json!("omp"));
    canonical.insert("session_id".into(), serde_json::json!("sid-123"));
    canonical.insert("status".into(), serde_json::json!(ST_LISTENING));
    canonical.insert("status_context".into(), serde_json::json!(""));
    canonical.insert("status_detail".into(), serde_json::json!(""));
    canonical.insert("last_event_id".into(), serde_json::json!(42));
    canonical.insert("created_at".into(), serde_json::json!(1.0));
    db.save_instance_named("miso", &canonical).unwrap();
    db.rebind_session("sid-123", "miso").unwrap();
    pin_test_omp_owner(&db, "miso");

    let mut placeholder = serde_json::Map::new();
    placeholder.insert("name".into(), serde_json::json!("temp"));
    placeholder.insert("tool".into(), serde_json::json!("omp"));
    placeholder.insert("status".into(), serde_json::json!("pending"));
    placeholder.insert("status_context".into(), serde_json::json!("new"));
    placeholder.insert("status_detail".into(), serde_json::json!(""));
    placeholder.insert("created_at".into(), serde_json::json!(1.0));
    db.save_instance_named("temp", &placeholder).unwrap();
    bind_test_omp_process(&db, "temp", "", "canonical");

    let env = std::collections::HashMap::from([
        ("HCOM_PROCESS_ID".to_string(), test_process_id("canonical")),
        ("HCOM_LAUNCHED".to_string(), "1".to_string()),
        ("HCOM_TOOL".to_string(), "omp".to_string()),
    ]);
    let ctx = HcomContext::from_env(&env, temp.path().to_path_buf());

    let (code, output) = start_as_test_owner(
        &ctx,
        &db,
        &[
            "--session-id".to_string(),
            "sid-123".to_string(),
            "--cwd".to_string(),
            temp.path().to_string_lossy().to_string(),
        ],
    );
    assert_eq!(code, 0);
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(response.get("name").and_then(|v| v.as_str()), Some("miso"));
    assert!(db.get_instance_full("temp").unwrap().is_none());
    assert_eq!(
        db.get_process_binding(&test_process_id("canonical"))
            .unwrap(),
        Some("miso".to_string())
    );

    let rebound = db.get_instance_full("miso").unwrap().unwrap();
    assert_eq!(rebound.last_event_id, 42);
    assert_eq!(rebound.directory, temp.path().to_string_lossy());

    cleanup(path);
}

/// A swept seat restarting on its old session keeps its name: only the
/// stopped snapshot survives (no row, no placeholder, no binding), and the
/// start hook rebuilds the row instead of minting a new identity.
#[test]
#[serial_test::serial]
fn start_handler_restores_swept_row_from_stopped_snapshot() {
    let _env = isolated_omp_env();
    let (db, path) = setup_test_db();
    let temp = tempfile::TempDir::new().unwrap();

    let snapshot = serde_json::json!({
        "session_id": "sid-swept",
        "tool": "omp",
        "directory": temp.path().to_string_lossy(),
        "background": 0,
        "transcript_path": "",
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

    let env = std::collections::HashMap::from([
        ("HCOM_PROCESS_ID".to_string(), test_process_id("swept")),
        ("HCOM_LAUNCHED".to_string(), "1".to_string()),
        ("HCOM_TOOL".to_string(), "omp".to_string()),
    ]);
    let ctx = HcomContext::from_env(&env, temp.path().to_path_buf());

    let (code, output) = start_as_test_owner(
        &ctx,
        &db,
        &[
            "--session-id".to_string(),
            "sid-swept".to_string(),
            "--cwd".to_string(),
            temp.path().to_string_lossy().to_string(),
        ],
    );
    assert_eq!(code, 0);
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(response.get("name").and_then(|v| v.as_str()), Some("valo"));

    let valo = db.get_instance_full("valo").unwrap().expect("valo row");
    assert_eq!(valo.tool, "omp");
    assert_eq!(valo.session_id.as_deref(), Some("sid-swept"));
    assert_eq!(
        db.get_session_binding("sid-swept").unwrap(),
        Some("valo".to_string())
    );
    assert_eq!(
        db.get_process_binding(&test_process_id("swept")).unwrap(),
        Some("valo".to_string())
    );
    // No minted identity: valo is the only row.
    let rows: i64 = db
        .conn()
        .query_row("SELECT COUNT(*) FROM instances", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1);

    cleanup(path);
}

#[test]
fn soft_stop_keeps_instance_row_and_process_binding() {
    let (db, path) = setup_test_db();
    let now = chrono::Utc::now().timestamp() as f64;
    db.conn()
        .execute(
            "INSERT INTO instances (name, status, created_at, tool, session_id)
             VALUES ('luna', 'listening', ?1, 'omp', 'sid-soft')",
            rusqlite::params![now],
        )
        .unwrap();
    db.set_process_binding("pid-soft", "sid-soft", "luna")
        .unwrap();
    db.rebind_session("sid-soft", "luna").unwrap();

    let (code, output) = handle_stop(
        &db,
        &[
            "--name".to_string(),
            "luna".to_string(),
            "--soft".to_string(),
            "--reason".to_string(),
            "turn_end".to_string(),
        ],
    );

    assert_eq!(code, 0);
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(response.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(response.get("soft").and_then(|v| v.as_bool()), Some(true));
    assert!(db.get_instance_full("luna").unwrap().is_some());
    assert_eq!(
        db.get_status("luna").unwrap().map(|(s, _)| s),
        Some(crate::shared::ST_INACTIVE.to_string())
    );
    assert_eq!(
        db.get_process_binding("pid-soft").unwrap(),
        Some("luna".to_string())
    );
    assert_eq!(db.get_session_binding("sid-soft").unwrap(), None);

    cleanup(path);
}

/// The omp owner's close on Linux: session_shutdown soft-stops (`--soft`),
/// then the process-exit release runs `omp-stop` without it. The row is gone,
/// and a resume from the newest stopped snapshot restores the title.
#[cfg(target_os = "linux")]
#[test]
#[serial_test::serial]
fn omp_owner_close_releases_row_and_resume_restores_title() {
    // The resume guard requires the omp session file on disk: point the omp
    // root at a fake HOME and seed sid-roc-close under the same root the
    // production lookup searches (never real ~/.omp, never hardcoded).
    let (_dir, _home, _guard) = isolated_omp_env();
    unsafe {
        std::env::remove_var("PI_CODING_AGENT_SESSION_DIR");
        std::env::remove_var("XDG_DATA_HOME");
        std::env::remove_var("OMP_PROFILE");
        std::env::remove_var("PI_PROFILE");
        std::env::remove_var("PI_CONFIG_DIR");
    }
    let root = crate::transcript::omp_session_roots()
        .into_iter()
        .next()
        .expect("omp always has exactly one active session root")
        .join("project");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("sid-roc-close.jsonl"), "{}").unwrap();
    crate::config::Config::init();
    let (db, path) = setup_test_db();
    let name = format!("rocclose{}", std::process::id());
    let process_id = format!("pid-roc-close-{}", std::process::id());
    save_test_instance(&db, &name, ST_LISTENING);
    // Any real dir outside /tmp: omp resume redirects /tmp snapshot dirs.
    db.conn()
        .execute(
            "UPDATE instances SET session_id = 'sid-roc-close', directory = ?2 WHERE name = ?1",
            rusqlite::params![name, env!("CARGO_MANIFEST_DIR")],
        )
        .unwrap();
    db.set_process_binding(&process_id, "sid-roc-close", &name)
        .unwrap();
    db.rebind_session("sid-roc-close", &name).unwrap();
    crate::title::set_purpose(&db, &name, "zagdb: rc.48 roll");
    crate::title::set_current(&db, &name, "probing WAL");

    let stop = |soft: bool| {
        let mut argv = vec![
            "--name".to_string(),
            name.clone(),
            "--reason".to_string(),
            "shutdown".to_string(),
        ];
        if soft {
            argv.push("--soft".to_string());
        }
        handle_stop(&db, &argv)
    };
    assert_eq!(stop(true).0, 0);
    assert!(db.get_instance_full(&name).unwrap().is_some());
    assert_eq!(stop(false).0, 0);

    assert!(
        db.get_instance_full(&name).unwrap().is_none(),
        "exit release must remove the row"
    );
    let loaded = crate::commands::resume::load_stopped_snapshot(&db, &name).unwrap();
    assert_eq!(loaded.7, "zagdb: rc.48 roll");
    assert_eq!(loaded.8, "probing WAL");
    let plan = crate::commands::resume::prepare_resume_plan(
        &db,
        &name,
        false,
        &[],
        &crate::router::GlobalFlags::default(),
    )
    .unwrap();
    assert_eq!(plan.launch.purpose.as_deref(), Some("zagdb: rc.48 roll"));
    assert_eq!(plan.launch.current.as_deref(), Some("probing WAL"));

    cleanup(path);
}

/// omp refuses to start with cwd under /tmp, so an explicit `--dir /tmp` on
/// an omp resume is refused before any launch, naming the guard.
#[cfg(target_os = "linux")]
#[test]
fn omp_resume_refuses_explicit_tmp_dir() {
    crate::config::Config::init();
    let (db, path) = setup_test_db();
    let name = format!("rocdir{}", std::process::id());
    save_test_instance(&db, &name, ST_LISTENING);
    db.conn()
        .execute(
            "UPDATE instances SET session_id = 'sid-roc-dir', directory = ?2 WHERE name = ?1",
            rusqlite::params![name, env!("CARGO_MANIFEST_DIR")],
        )
        .unwrap();
    let argv = [
        "--name".to_string(),
        name.clone(),
        "--reason".to_string(),
        "shutdown".to_string(),
    ];
    assert_eq!(handle_stop(&db, &argv).0, 0);

    let err = crate::commands::resume::prepare_resume_plan(
        &db,
        &name,
        false,
        &["--dir".to_string(), "/tmp".to_string()],
        &crate::router::GlobalFlags::default(),
    )
    .err()
    .expect("explicit --dir /tmp must be refused for omp");
    assert!(err.to_string().contains("omp /tmp start guard"), "{err}");

    cleanup(path);
}

/// The omp owner's close off Linux keeps the row: session_shutdown's `--soft`
/// stop leaves the resume handle, and the exit release after it changes
/// nothing (no event, so no second stopped event; binding kept).
#[cfg(not(target_os = "linux"))]
#[test]
fn omp_owner_close_keeps_row_off_linux() {
    crate::config::Config::init();
    let (db, path) = setup_test_db();
    let name = format!("rockeep{}", std::process::id());
    let process_id = format!("pid-roc-keep-{}", std::process::id());
    save_test_instance(&db, &name, ST_LISTENING);
    db.set_process_binding(&process_id, "", &name).unwrap();

    let stop = |soft: bool| {
        let mut argv = vec![
            "--name".to_string(),
            name.clone(),
            "--reason".to_string(),
            "shutdown".to_string(),
        ];
        if soft {
            argv.push("--soft".to_string());
        }
        handle_stop(&db, &argv)
    };
    let events = || -> i64 {
        db.conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE instance = ?1",
                [&name],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(stop(true).0, 0);
    let after_soft = events();
    assert_eq!(stop(false).0, 0);

    assert_eq!(events(), after_soft, "the exit release wrote events");
    let row = db
        .get_instance_full(&name)
        .unwrap()
        .expect("the exit release deleted the row off Linux");
    assert_eq!(row.status, crate::shared::ST_INACTIVE);
    assert_eq!(db.get_process_binding(&process_id).unwrap(), Some(name));

    cleanup(path);
}

#[test]
fn start_rebinds_via_process_binding_after_soft_stop() {
    let _env = isolated_omp_env();
    let (db, path) = setup_test_db();
    let temp = tempfile::TempDir::new().unwrap();
    save_test_instance(&db, "miso", ST_LISTENING);
    db.conn()
        .execute(
            "UPDATE instances SET session_id = 'sid-old' WHERE name = 'miso'",
            [],
        )
        .unwrap();
    bind_test_omp_process(&db, "miso", "sid-old", "rebind");
    db.rebind_session("sid-old", "miso").unwrap();

    let (stop_code, _) = handle_stop(
        &db,
        &[
            "--name".to_string(),
            "miso".to_string(),
            "--soft".to_string(),
        ],
    );
    assert_eq!(stop_code, 0);
    assert_eq!(
        db.get_process_binding(&test_process_id("rebind")).unwrap(),
        Some("miso".to_string())
    );

    let env = std::collections::HashMap::from([
        ("HCOM_PROCESS_ID".to_string(), test_process_id("rebind")),
        ("HCOM_LAUNCHED".to_string(), "1".to_string()),
        ("HCOM_TOOL".to_string(), "omp".to_string()),
    ]);
    let ctx = HcomContext::from_env(&env, temp.path().to_path_buf());

    let (code, output) = start_as_test_owner(
        &ctx,
        &db,
        &[
            "--session-id".to_string(),
            "sid-new".to_string(),
            "--cwd".to_string(),
            temp.path().to_string_lossy().to_string(),
        ],
    );

    assert_eq!(code, 0);
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(response.get("name").and_then(|v| v.as_str()), Some("miso"));
    assert_eq!(
        db.get_process_binding(&test_process_id("rebind")).unwrap(),
        Some("miso".to_string())
    );
    assert_eq!(
        db.get_session_binding("sid-new").unwrap(),
        Some("miso".to_string())
    );
    let rebound = db.get_instance_full("miso").unwrap().unwrap();
    assert_eq!(rebound.session_id.as_deref(), Some("sid-new"));
    assert_eq!(rebound.status, ST_LISTENING);

    cleanup(path);
}

#[test]
fn start_recovers_active_same_owner_binding_when_process_mapping_cleared() {
    let _env = isolated_omp_env();
    let (db, path) = setup_test_db();
    let temp = tempfile::TempDir::new().unwrap();
    save_test_instance(&db, "miso", ST_LISTENING);
    db.conn()
        .execute(
            "UPDATE instances SET session_id = 'sid-old' WHERE name = 'miso'",
            [],
        )
        .unwrap();
    db.rebind_session("sid-old", "miso").unwrap();
    pin_test_omp_owner(&db, "miso");

    let env = std::collections::HashMap::from([
        ("HCOM_PROCESS_ID".to_string(), test_process_id("repair")),
        ("HCOM_INSTANCE_NAME".to_string(), "miso".to_string()),
        ("HCOM_LAUNCHED".to_string(), "1".to_string()),
        ("HCOM_TOOL".to_string(), "omp".to_string()),
    ]);
    let ctx = HcomContext::from_env(&env, temp.path().to_path_buf());

    let (code, output) = start_as_test_owner(
        &ctx,
        &db,
        &[
            "--session-id".to_string(),
            "sid-new".to_string(),
            "--cwd".to_string(),
            temp.path().to_string_lossy().to_string(),
        ],
    );

    assert_eq!(code, 0);
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(response.get("name").and_then(|v| v.as_str()), Some("miso"));
    assert_eq!(
        db.get_process_binding(&test_process_id("repair")).unwrap(),
        Some("miso".to_string())
    );
    assert_eq!(
        db.get_session_binding("sid-new").unwrap(),
        Some("miso".to_string())
    );

    cleanup(path);
}

/// A plain omp session as `handle_start` sees it after entry-point
/// sanitization: a process id the tree could prove (the plugin minted it),
/// `HCOM_LAUNCHED=1` inherited from a leaked environment, and `is_launched`
/// false because no launcher issued the id.
fn plain_session_ctx(cwd: &std::path::Path) -> HcomContext {
    let env = std::collections::HashMap::from([
        ("HCOM_PROCESS_ID".to_string(), test_process_id("plain")),
        ("HCOM_LAUNCHED".to_string(), "1".to_string()),
        ("HCOM_TOOL".to_string(), "omp".to_string()),
    ]);
    let mut ctx = HcomContext::from_env(&env, cwd.to_path_buf());
    ctx.is_launched = false;
    ctx
}

fn instance_count(db: &HcomDb) -> i64 {
    db.conn()
        .query_row("SELECT COUNT(*) FROM instances", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn plain_session_without_opt_in_does_not_mint() {
    let (_dir, home, _guard) = isolated_omp_env();
    let (db, path) = setup_test_db();

    let (code, output) = start_as_test_owner(
        &plain_session_ctx(&home),
        &db,
        &["--session-id".to_string(), "sid-plain".to_string()],
    );

    assert_eq!(code, 0);
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(response["error"].is_string(), "{output}");
    assert!(response.get("transient").is_none(), "{output}");
    assert_eq!(instance_count(&db), 0);
    assert_eq!(
        db.get_process_binding(&test_process_id("plain")).unwrap(),
        None
    );
    assert_eq!(db.get_session_binding("sid-plain").unwrap(), None);

    cleanup(path);
}

#[test]
fn plain_session_with_opt_in_mints_identity() {
    let (_dir, home, _guard) = isolated_omp_env();
    std::fs::write(
        crate::paths::config_toml_path(),
        "[launch.omp]\nplain_sessions = true\n",
    )
    .unwrap();
    let (db, path) = setup_test_db();

    let (code, output) = start_as_test_owner(
        &plain_session_ctx(&home),
        &db,
        &["--session-id".to_string(), "sid-plain".to_string()],
    );

    assert_eq!(code, 0);
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    let name = response
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("expected a minted name, got: {output}"))
        .to_string();
    assert_eq!(
        db.get_process_binding(&test_process_id("plain")).unwrap(),
        Some(name.clone())
    );
    assert_eq!(
        db.get_session_binding("sid-plain").unwrap(),
        Some(name.clone())
    );
    let row = db.get_instance_full(&name).unwrap().unwrap();
    assert_eq!(row.tool, "omp");

    cleanup(path);
}

#[test]
fn start_hook_replaces_stale_installed_plugin() {
    let (_dir, home, _guard) = isolated_omp_env();
    let plugin = get_omp_plugin_path();
    assert!(
        plugin.starts_with(&home),
        "plugin path escaped the test HOME"
    );
    std::fs::create_dir_all(plugin.parent().unwrap()).unwrap();
    // An older hcom's plugin: carries the ownership marker, differs from source.
    std::fs::write(&plugin, r#"const x = customType: "hcom-bootstrap";"#).unwrap();
    let (db, path) = setup_test_db();

    // Authenticated plain session without opt-in: policy refusal still refreshes.
    let (code, _) = start_as_test_owner(
        &plain_session_ctx(&home),
        &db,
        &["--session-id".to_string(), "sid-refresh".to_string()],
    );

    assert_eq!(code, 0);
    assert_eq!(std::fs::read_to_string(&plugin).unwrap(), PLUGIN_SOURCE);

    cleanup(path);
}

#[test]
fn recover_rejects_non_omp_tool() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", crate::shared::ST_INACTIVE);
    db.conn()
        .execute(
            "UPDATE instances SET tool = 'claude' WHERE name = 'luna'",
            [],
        )
        .unwrap();

    crate::instance_binding::with_omp_binding_owner(test_omp_owner(), || {
        assert!(
            crate::instance_binding::recover_omp_process_binding_for_instance(
                &db,
                "luna",
                "sid-new",
                &test_process_id("repair-other-tool")
            )
            .is_err()
        );
    });

    cleanup(path);
}

#[test]
fn recover_rejects_unproven_active_instance() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_LISTENING);

    crate::instance_binding::with_omp_binding_owner(test_omp_owner(), || {
        assert!(
            crate::instance_binding::recover_omp_process_binding_for_instance(
                &db,
                "luna",
                "sid-new",
                &test_process_id("repair-unproven")
            )
            .is_err()
        );
    });

    cleanup(path);
}

const OMP_CALLER_GATE_CASES: &[(&str, &[&str])] = &[
    (
        "omp-start",
        &["--session-id", "sid-own", "--notify-port", "32101"],
    ),
    ("omp-status", &["--name", "luna", "--status", "listening"]),
    ("omp-read", &["--name", "luna"]),
    ("omp-read", &["--name", "luna", "--format"]),
    ("omp-read", &["--name", "luna", "--check"]),
    ("omp-read", &["--name", "luna", "--ack", "--up-to", "99"]),
    ("omp-beforetool", &["--name", "luna", "--tool", "bash"]),
    ("omp-stop", &["--name", "luna", "--soft"]),
    ("omp-stop", &["--name", "luna"]),
    (
        "omp-role",
        &[
            "--name",
            "luna",
            "--session-id",
            "sid-own",
            "--role",
            "conductor",
        ],
    ),
];

#[test]
fn caller_gate_refuses_missing_or_borrowed_ids_for_every_hook_mode() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_ACTIVE);
    bind_test_omp_process(&db, "luna", "sid-own", "borrowed");
    let launcher = "550e8400-e29b-41d4-a716-446655440123";
    db.set_process_binding(launcher, "sid-own", "luna").unwrap();
    let owner = test_omp_owner();
    let descendant = crate::proctruth::OmpOwner {
        pid: owner.pid + 1,
        incarnation: "descendant-native-incarnation".to_string(),
    };
    let before = db.get_instance("luna").unwrap().unwrap();

    for identity in [
        None,
        Some(test_process_id("borrowed")),
        Some(launcher.to_string()),
    ] {
        let env = identity
            .as_ref()
            .map(|id| std::collections::HashMap::from([("HCOM_PROCESS_ID".into(), id.clone())]))
            .unwrap_or_default();
        let mut ctx = HcomContext::from_env(&env, std::env::temp_dir());
        // Entry-point sanitation must not turn a present refused id into an
        // absent-id/activity fallback on a database containing other rows.
        ctx.process_id = None;
        crate::instance_binding::with_omp_binding_owner(descendant.clone(), || {
            for (hook, args) in OMP_CALLER_GATE_CASES {
                let argv: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
                let (code, output) =
                    crate::hooks::common::omp_hook_caller_gate(&ctx, &db, hook, &argv).unwrap_err();
                let response: serde_json::Value = serde_json::from_str(&output).unwrap();
                assert_eq!(code, 0, "{hook}: {output}");
                assert!(response["error"].is_string(), "{hook}: {output}");
                assert!(response.get("transient").is_none(), "{hook}: {output}");
            }
        });
    }
    assert_eq!(db.get_instance("luna").unwrap().unwrap(), before);
    assert!(!db.has_notify_endpoint_kind("luna", "plugin"));
    cleanup(path);
}

#[test]
fn caller_gate_requires_the_authenticated_process_exact_mapped_name() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_ACTIVE);
    save_test_instance(&db, "other", ST_ACTIVE);
    bind_test_omp_process(&db, "other", "sid-other", "name-mismatch");
    pin_test_omp_owner(&db, "luna");
    let env = std::collections::HashMap::from([(
        "HCOM_PROCESS_ID".to_string(),
        test_process_id("name-mismatch"),
    )]);
    let ctx = HcomContext::from_env(&env, std::env::temp_dir());
    crate::instance_binding::with_omp_binding_owner(test_omp_owner(), || {
        for (hook, args) in OMP_CALLER_GATE_CASES
            .iter()
            .filter(|(hook, _)| *hook != "omp-start")
        {
            let argv: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
            let (_, output) =
                crate::hooks::common::omp_hook_caller_gate(&ctx, &db, hook, &argv).unwrap_err();
            let response: serde_json::Value = serde_json::from_str(&output).unwrap();
            assert!(response["error"].is_string(), "{hook}: {output}");
            assert!(response.get("transient").is_none(), "{hook}: {output}");
        }
    });
    cleanup(path);
}

#[test]
#[serial_test::serial]
fn pidless_legacy_omp_name_refusal_does_not_enroll_mapped_identity() {
    let (_dir, home, _guard) = isolated_omp_env();
    let (db, path) = setup_test_db();
    let process_id = test_process_id("pidless-name-refusal");
    let name = crate::instance_binding::create_orphaned_pty_identity(
        &db,
        "sid-legacy-name",
        Some(&process_id),
        "omp",
    )
    .unwrap();
    let row = db.get_instance_full(&name).unwrap().unwrap();
    assert_eq!(row.pid, None);
    assert_eq!(crate::proctruth::stored_omp_owner(&row).unwrap(), None);
    db.upsert_notify_endpoint(&name, "plugin", 54_311).unwrap();
    let before = db.get_instance(&name).unwrap().unwrap();
    let binding = db.get_process_binding_full(&process_id).unwrap();
    let registered = db.process_bindings_registered(&name).unwrap();
    let ctx = HcomContext::from_env(
        &std::collections::HashMap::from([("HCOM_PROCESS_ID".into(), process_id.clone())]),
        home,
    );
    crate::instance_binding::with_omp_binding_owner(test_omp_owner(), || {
        assert_eq!(
            crate::instance_binding::authenticated_omp_owner(&db, &process_id).unwrap(),
            test_omp_owner(),
        );
        for refused_name in [None, Some("another-seat"), Some("bigboss")] {
            for hook in ["omp-read", "omp-status", "omp-stop", "omp-role"] {
                let argv = refused_name
                    .map(|name| vec!["--name".into(), name.into()])
                    .unwrap_or_default();
                let (_, output) =
                    crate::hooks::common::omp_hook_caller_gate(&ctx, &db, hook, &argv).unwrap_err();
                let response: serde_json::Value = serde_json::from_str(&output).unwrap();
                assert!(response["error"].is_string(), "{hook}: {output}");
                assert!(response.get("transient").is_none(), "{hook}: {output}");
                assert_eq!(db.get_instance(&name).unwrap().unwrap(), before);
                assert_eq!(db.get_process_binding_full(&process_id).unwrap(), binding);
                assert_eq!(db.process_bindings_registered(&name).unwrap(), registered);
                assert_eq!(
                    db.get_session_binding("sid-legacy-name").unwrap(),
                    Some(name.clone()),
                );
                let port: i64 = db
                    .conn()
                    .query_row(
                        "SELECT port FROM notify_endpoints WHERE instance = ? AND kind = 'plugin'",
                        rusqlite::params![name],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(port, 54_311);
            }
        }
    });
    cleanup(path);
}

#[test]
fn caller_gate_accepts_native_pins_and_verified_legacy_registration() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_ACTIVE);
    bind_test_omp_process(&db, "luna", "sid-own", "gate-owner");
    let env = std::collections::HashMap::from([(
        "HCOM_PROCESS_ID".to_string(),
        test_process_id("gate-owner"),
    )]);
    let mut ctx = HcomContext::from_env(&env, std::env::temp_dir());
    ctx.process_id = None;
    crate::instance_binding::with_omp_binding_owner(test_omp_owner(), || {
        for legacy in [false, true] {
            if legacy {
                db.conn()
                    .execute(
                        "UPDATE instances SET launch_context = '{}' WHERE name = 'luna'",
                        [],
                    )
                    .unwrap();
            }
            for (hook, args) in OMP_CALLER_GATE_CASES {
                let argv: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
                assert_eq!(
                    crate::hooks::common::omp_hook_caller_gate(&ctx, &db, hook, &argv).unwrap(),
                    Some(test_omp_owner()),
                    "{hook}, legacy={legacy}"
                );
            }
        }
        db.delete_process_binding(&test_process_id("gate-owner"))
            .unwrap();
        assert_eq!(
            crate::hooks::common::omp_hook_caller_gate(&ctx, &db, "omp-start", &[]).unwrap(),
            Some(test_omp_owner())
        );
        assert!(
            crate::hooks::common::omp_hook_caller_gate(
                &ctx,
                &db,
                "omp-status",
                &["--name".into(), "luna".into()]
            )
            .is_err()
        );
    });
    // Unknown RPCs do not acquire an identity requirement.
    let empty = HcomContext::from_env(&Default::default(), std::env::temp_dir());
    assert_eq!(
        crate::hooks::common::omp_hook_caller_gate(&empty, &db, "omp-unknown", &[]).unwrap(),
        None
    );
    cleanup(path);
}

#[test]
fn generic_activity_gate_cannot_reenable_an_omp_target_after_identity_stripping() {
    let _env = isolated_omp_env();
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_ACTIVE);
    bind_test_omp_process(&db, "luna", "sid-own", "activity");
    let launcher = "550e8400-e29b-41d4-a716-446655440124";
    db.set_process_binding(launcher, "sid-own", "luna").unwrap();
    for id in [test_process_id("activity"), launcher.to_string()] {
        let env = std::collections::HashMap::from([
            ("HCOM_PROCESS_ID".to_string(), id),
            ("HCOM_TOOL".to_string(), "claude".to_string()),
        ]);
        let mut ctx = HcomContext::from_env(&env, std::env::temp_dir());
        ctx.process_id = None;
        assert!(!crate::hooks::common::hook_gate_check(&mut ctx, &db));
    }
    let generic_env = std::collections::HashMap::from([(
        "HCOM_PROCESS_ID".to_string(),
        "generic-session".to_string(),
    )]);
    let mut generic = HcomContext::from_env(&generic_env, std::env::temp_dir());
    assert!(crate::hooks::common::hook_gate_check(&mut generic, &db));
    db.conn()
        .execute_batch("DROP TABLE process_bindings")
        .unwrap();
    let env =
        std::collections::HashMap::from([("HCOM_PROCESS_ID".to_string(), launcher.to_string())]);
    let mut failed_lookup = HcomContext::from_env(&env, std::env::temp_dir());
    assert!(!crate::hooks::common::hook_gate_check(
        &mut failed_lookup,
        &db
    ));
    cleanup(path);
}

#[test]
fn caller_gate_preserves_sql_contention_after_identity_stripping() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_ACTIVE);
    db.conn()
        .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA busy_timeout=0;")
        .unwrap();
    let locker = rusqlite::Connection::open(&path).unwrap();
    locker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let env =
        std::collections::HashMap::from([("HCOM_PROCESS_ID".to_string(), test_process_id("busy"))]);
    let mut ctx = HcomContext::from_env(&env, std::env::temp_dir());
    ctx.process_id = None;
    let (code, output) =
        crate::hooks::common::omp_hook_caller_gate(&ctx, &db, "omp-start", &[]).unwrap_err();
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(code, 0);
    assert!(response["error"].is_string(), "{output}");
    assert_eq!(response["transient"], true);
    locker.execute_batch("ROLLBACK").unwrap();
    drop(locker);
    cleanup(path);
}

#[test]
fn protected_name_contention_retains_its_sqlite_type_for_hook_retry() {
    let _env = isolated_omp_env();
    let (db, path) = setup_test_db();
    db.conn()
        .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA busy_timeout=0;")
        .unwrap();
    let locker = rusqlite::Connection::open(&path).unwrap();
    locker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    // Exercise the protected-name lookup directly, so an earlier caller-auth
    // query cannot mask a string-erasing validator on the hook error path.
    let error = crate::identity::validate_protected_identity_checked(&db, "luna").unwrap_err();
    assert!(crate::db::is_busy_error(&error));
    let (code, output) = crate::hooks::common::omp_hook_failure(&error);
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(code, 0);
    assert!(response["error"].is_string());
    assert_eq!(response["transient"], true);
    locker.execute_batch("ROLLBACK").unwrap();
    drop(locker);
    cleanup(path);
}

#[test]
fn start_readiness_fences_both_newer_process_mapping_and_row_session() {
    let (_dir, home, _guard) = isolated_omp_env();
    for row_only_fence in [false, true] {
        let (db, path) = setup_test_db();
        save_test_instance(&db, "luna", ST_ACTIVE);
        bind_test_omp_process(&db, "luna", "", "stale-readiness");
        let process_id = test_process_id("stale-readiness");
        let env =
            std::collections::HashMap::from([("HCOM_PROCESS_ID".to_string(), process_id.clone())]);
        let ctx = HcomContext::from_env(&env, home.clone());
        crate::instance_binding::with_omp_binding_owner(test_omp_owner(), || {
            assert_eq!(
                crate::instance_binding::bind_omp_session_to_process(&db, "sid-old", &process_id)
                    .unwrap(),
                Some("luna".to_string())
            );
            assert_eq!(
                crate::instance_binding::bind_omp_session_to_process(&db, "sid-new", &process_id)
                    .unwrap(),
                Some("luna".to_string())
            );
            if row_only_fence {
                // A matching process binding alone does not authorize
                // completion if the row already belongs to a newer session.
                db.set_process_binding(&process_id, "sid-old", "luna")
                    .unwrap();
            }
            db.conn()
                .execute(
                    "UPDATE instances SET directory = 'new-dir', transcript_path = 'new.jsonl',
                 status = 'active', last_event_id = 73 WHERE name = 'luna'",
                    [],
                )
                .unwrap();
            db.upsert_notify_endpoint("luna", "plugin", 32102).unwrap();
            let before = db.get_instance("luna").unwrap().unwrap();
            let argv: Vec<String> = [
                "--cwd",
                "old-dir",
                "--transcript-path",
                "old.jsonl",
                "--notify-port",
                "32101",
            ]
            .iter()
            .map(|arg| arg.to_string())
            .collect();
            assert!(
                super::handlers::complete_start_readiness(
                    &ctx,
                    &db,
                    &argv,
                    "luna",
                    "sid-old",
                    &process_id,
                    &test_omp_owner()
                )
                .is_err()
            );
            assert_eq!(db.get_instance("luna").unwrap().unwrap(), before);
            let port: u16 = db
                .conn()
                .query_row(
                    "SELECT port FROM notify_endpoints WHERE instance = 'luna' AND kind = 'plugin'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(port, 32102);
        });
        cleanup(path);
    }
}

#[test]
fn start_replays_a_committed_bind_after_endpoint_failure_without_reminting() {
    let (_dir, home, _guard) = isolated_omp_env();
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_ACTIVE);
    bind_test_omp_process(&db, "luna", "", "readiness-replay");
    let process_id = test_process_id("readiness-replay");
    let env =
        std::collections::HashMap::from([("HCOM_PROCESS_ID".to_string(), process_id.clone())]);
    let ctx = HcomContext::from_env(&env, home.clone());
    db.conn()
        .execute(
            "UPDATE instances SET directory = 'before-dir', transcript_path = 'before.jsonl',
         last_event_id = 42 WHERE name = 'luna'",
            [],
        )
        .unwrap();
    let listener = bind_probe();
    db.upsert_notify_endpoint("luna", "pty", listener.local_addr().unwrap().port())
        .unwrap();
    db.conn()
        .execute_batch(
            "CREATE TRIGGER fail_start_endpoint BEFORE INSERT ON notify_endpoints
         WHEN NEW.kind = 'plugin' BEGIN SELECT RAISE(ABORT, 'endpoint blocked'); END;",
        )
        .unwrap();
    let argv: Vec<String> = [
        "--session-id",
        "sid-ready",
        "--cwd",
        "after-dir",
        "--transcript-path",
        "after.jsonl",
        "--notify-port",
        "32103",
    ]
    .iter()
    .map(|arg| arg.to_string())
    .collect();
    let (code, output) = start_as_test_owner(&ctx, &db, &argv);
    let failed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(code, 0);
    assert!(failed["error"].is_string(), "{output}");
    assert!(failed.get("transient").is_none(), "{output}");
    assert!(failed.get("name").is_none(), "{output}");
    assert_eq!(
        db.get_process_binding_full(&process_id).unwrap(),
        Some((Some("sid-ready".to_string()), "luna".to_string()))
    );
    let before_replay = db.get_instance_full("luna").unwrap().unwrap();
    assert_eq!(before_replay.directory, "before-dir");
    assert_eq!(before_replay.transcript_path, "before.jsonl");
    assert_eq!(before_replay.last_event_id, 42);
    assert!(!db.has_notify_endpoint_kind("luna", "plugin"));
    assert!(!await_connect(&listener, Duration::from_millis(100)));

    db.conn()
        .execute_batch("DROP TRIGGER fail_start_endpoint")
        .unwrap();
    for _ in 0..2 {
        let (code, output) = start_as_test_owner(&ctx, &db, &argv);
        let response: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(code, 0);
        assert_eq!(response["name"], "luna", "{output}");
        assert_eq!(response["session_id"], "sid-ready", "{output}");
        let ready = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(ready.status, ST_LISTENING);
        assert_eq!(ready.session_id.as_deref(), Some("sid-ready"));
        assert_eq!(ready.last_event_id, 42);
        assert_eq!(ready.directory, "after-dir");
        assert_eq!(ready.transcript_path, "after.jsonl");
        assert_eq!(
            crate::proctruth::stored_omp_owner(&ready).unwrap(),
            Some(test_omp_owner())
        );
        assert_eq!(instance_count(&db), 1);
    }
    assert!(await_connect(&listener, Duration::from_millis(500)));
    cleanup(path);
}

#[test]
fn readiness_status_write_failure_rolls_back_metadata_and_endpoint() {
    let (_dir, home, _guard) = isolated_omp_env();
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_ACTIVE);
    bind_test_omp_process(&db, "luna", "sid-status", "status-failure");
    db.conn()
        .execute(
            "UPDATE instances SET session_id = 'sid-status', directory = 'before-dir',
         last_event_id = 42 WHERE name = 'luna'",
            [],
        )
        .unwrap();
    let process_id = test_process_id("status-failure");
    let env =
        std::collections::HashMap::from([("HCOM_PROCESS_ID".to_string(), process_id.clone())]);
    let ctx = HcomContext::from_env(&env, home);
    let before = db.get_instance("luna").unwrap().unwrap();
    db.conn()
        .execute_batch(
            "CREATE TRIGGER fail_start_status BEFORE UPDATE OF status ON instances
         WHEN NEW.status = 'listening' BEGIN SELECT RAISE(ABORT, 'status blocked'); END;",
        )
        .unwrap();
    let argv: Vec<String> = ["--cwd", "after-dir", "--notify-port", "32104"]
        .iter()
        .map(|arg| arg.to_string())
        .collect();
    crate::instance_binding::with_omp_binding_owner(test_omp_owner(), || {
        let error = match super::handlers::complete_start_readiness(
            &ctx,
            &db,
            &argv,
            "luna",
            "sid-status",
            &process_id,
            &test_omp_owner(),
        ) {
            Ok(_) => panic!("failed listening write reported readiness"),
            Err(error) => error,
        };
        let (code, output) = crate::hooks::common::omp_hook_failure(&error);
        let response: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(code, 0);
        assert!(response["error"].is_string());
        assert!(response.get("transient").is_none());
    });
    assert_eq!(db.get_instance("luna").unwrap().unwrap(), before);
    assert!(!db.has_notify_endpoint_kind("luna", "plugin"));
    cleanup(path);
}

#[test]
fn refused_start_does_not_refresh_a_plugin_or_create_an_identity() {
    let (_dir, home, _guard) = isolated_omp_env();
    let plugin = get_omp_plugin_path();
    std::fs::create_dir_all(plugin.parent().unwrap()).unwrap();
    let stale = r#"const x = customType: "hcom-bootstrap";"#;
    std::fs::write(&plugin, stale).unwrap();
    let (db, path) = setup_test_db();
    let mut ctx = plain_session_ctx(&home);
    ctx.raw_env
        .insert("HCOM_PROCESS_ID".into(), "omp-0-borrowed".into());
    ctx.process_id = None;
    let (code, output) = start_through_caller_gate(
        &ctx,
        &db,
        &["--session-id".to_string(), "sid-refused".to_string()],
    );
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(code, 0);
    assert!(response["error"].is_string());
    assert!(response.get("transient").is_none());
    assert_eq!(std::fs::read_to_string(&plugin).unwrap(), stale);
    assert_eq!(instance_count(&db), 0);
    cleanup(path);
}

#[test]
fn failed_bind_or_named_repair_never_falls_through_to_mint() {
    let (_dir, home, _guard) = isolated_omp_env();
    std::fs::write(
        crate::paths::config_toml_path(),
        "[launch.omp]\nplain_sessions = true\n",
    )
    .unwrap();
    for canonical in [false, true] {
        let (db, path) = setup_test_db();
        save_test_instance(&db, "other", ST_ACTIVE);
        let owner = test_omp_owner();
        let stale = serde_json::json!({
            "omp_owner": {
                "pid": owner.pid,
                "incarnation": format!("{}-not-this-owner", owner.incarnation),
            },
        });
        db.conn()
            .execute(
                "UPDATE instances SET pid = ?1, launch_context = ?2, session_id = 'sid-other'
             WHERE name = 'other'",
                rusqlite::params![i64::from(owner.pid), stale.to_string()],
            )
            .unwrap();
        if canonical {
            db.rebind_session("sid-other", "other").unwrap();
        }
        let process_id = test_process_id("no-remint");
        let env = std::collections::HashMap::from([
            ("HCOM_PROCESS_ID".to_string(), process_id.clone()),
            ("HCOM_INSTANCE_NAME".to_string(), "other".to_string()),
        ]);
        let ctx = HcomContext::from_env(&env, home.clone());
        let before = db.get_instance("other").unwrap().unwrap();
        let (code, output) =
            start_as_test_owner(&ctx, &db, &["--session-id".into(), "sid-other".into()]);
        let response: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(code, 0);
        assert!(
            response["error"].is_string(),
            "canonical={canonical}: {output}"
        );
        assert!(response.get("name").is_none(), "{output}");
        assert!(response.get("transient").is_none(), "{output}");
        assert_eq!(db.get_process_binding(&process_id).unwrap(), None);
        assert_eq!(db.get_instance("other").unwrap().unwrap(), before);
        assert_eq!(instance_count(&db), 1);
        cleanup(path);
    }
}

#[test]
fn own_stopped_start_response_is_preserved_only_after_caller_authentication() {
    let (_dir, home, _guard) = isolated_omp_env();
    let (db, path) = setup_test_db();
    let process_id = test_process_id("own-stopped");
    db.log_life_event(
        "luna",
        "stopped",
        "hook",
        "shutdown",
        Some(serde_json::json!({"tool": "omp", "session_id": "sid-stopped"})),
        Some(&process_id),
    )
    .unwrap();
    let env = std::collections::HashMap::from([("HCOM_PROCESS_ID".to_string(), process_id)]);
    let ctx = HcomContext::from_env(&env, home);
    let (code, output) =
        start_as_test_owner(&ctx, &db, &["--session-id".into(), "sid-stopped".into()]);
    assert_eq!(code, 0);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output).unwrap(),
        serde_json::json!({"ok": true, "restored": false, "stopped": "luna"}),
    );
    let descendant = crate::proctruth::OmpOwner {
        pid: std::process::id() + 1,
        incarnation: "different-native-incarnation".into(),
    };
    crate::instance_binding::with_omp_binding_owner(descendant, || {
        let (code, output) =
            start_through_caller_gate(&ctx, &db, &["--session-id".into(), "sid-stopped".into()]);
        let response: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(code, 0);
        assert!(response["error"].is_string());
        assert!(response.get("restored").is_none());
        assert!(response.get("transient").is_none());
    });
    assert_eq!(instance_count(&db), 0);
    cleanup(path);
}

/// Manual/CI scenario: nested OMP task extension must not steal parent identity
/// after soft-stop + session_branch rebind. Run with:
/// `cargo test omp_nested_task_identity_survives_soft_stop -- --ignored`
#[test]
#[ignore = "requires live OMP nested task; run manually"]
fn omp_nested_task_identity_survives_soft_stop() {
    // Launch OMP via hcom, soft-stop parent turn, spawn nested task extension,
    // verify child does not bind and parent recovers on next turn.
}

// ── Plugin install/remove safety ──────────────────────────────────

/// Isolated HCOM_DIR and HOME (via `isolated_test_env`), Config reset, and
/// PI_CODING_AGENT_DIR unset so the default ~/.omp plugin path is used. Hold
/// the returned values for the test's lifetime. Required by anything that runs
/// `handle_start`: it rewrites the installed plugin file.
fn isolated_omp_env() -> (
    tempfile::TempDir,
    PathBuf,
    crate::hooks::test_helpers::EnvGuard,
) {
    let (dir, _hcom, home, guard) = crate::hooks::test_helpers::isolated_test_env();
    unsafe {
        std::env::remove_var("PI_CODING_AGENT_DIR");
    }
    (dir, home, guard)
}

fn with_isolated_omp_env(f: impl FnOnce(&std::path::Path)) {
    let (_dir, home, _guard) = isolated_omp_env();
    f(&home);
}
#[test]
#[serial_test::serial]
fn plugin_dir_respects_pi_coding_agent_dir() {
    let (_dir, _hcom, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
    let custom = home.join("custom-omp");
    unsafe {
        std::env::set_var("PI_CODING_AGENT_DIR", &custom);
    }

    let path = get_omp_plugin_path();
    assert_eq!(path, custom.join("extensions").join("hcom.ts"));
}

#[test]
fn extension_inject_args_contains_absolute_plugin_path() {
    with_isolated_omp_env(|_| {
        let args = extension_inject_args();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "-e");
        let path = std::path::Path::new(&args[1]);
        assert!(path.is_absolute());
        assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("hcom.ts"));
    });
}

#[test]
fn plugin_source_uses_omp_cli_commands_only() {
    assert!(PLUGIN_SOURCE.contains("[\"omp-read\""));
    assert!(PLUGIN_SOURCE.contains("[\"omp-status\""));
    assert!(PLUGIN_SOURCE.contains("[\"omp-stop\""));
    assert!(!PLUGIN_SOURCE.contains("[\"pi-read\""));
    assert!(!PLUGIN_SOURCE.contains("[\"pi-status\""));
    assert!(!PLUGIN_SOURCE.contains("[\"pi-stop\""));
}

#[test]
fn plugin_source_matches_omp_input_result_shape() {
    assert!(PLUGIN_SOURCE.contains("return {}"));
    assert!(PLUGIN_SOURCE.contains("return { text:"));
    assert!(PLUGIN_SOURCE.contains("return { handled: true }"));
    assert!(!PLUGIN_SOURCE.contains("action: \"continue\""));
    assert!(!PLUGIN_SOURCE.contains("action: \"transform\""));
    assert!(!PLUGIN_SOURCE.contains("action: \"handled\""));
    assert!(!PLUGIN_SOURCE.contains("streamingBehavior"));
}

#[test]
fn plugin_source_handles_omp_session_switch_and_shutdown_shape() {
    assert!(PLUGIN_SOURCE.contains("pi.on(\"session_switch\""));
    assert!(PLUGIN_SOURCE.contains("pi.on(\"session_shutdown\""));
    assert!(PLUGIN_SOURCE.contains("plugin.session_shutdown_skipped"));
    assert!(PLUGIN_SOURCE.contains("nested_session"));
    assert!(PLUGIN_SOURCE.contains("HCOM_OMP_IDENTITY_OWNER"));
    assert!(PLUGIN_SOURCE.contains("plugin.bind_skipped_nested"));
    assert!(PLUGIN_SOURCE.contains("ownsIdentity"));
    assert!(PLUGIN_SOURCE.contains("keepOwner: true"));
    // session_switch must also keepOwner (same race as session_branch).
    let switch_idx = PLUGIN_SOURCE
        .find("pi.on(\"session_switch\"")
        .expect("session_switch handler present");
    assert!(
        PLUGIN_SOURCE[switch_idx..].contains("resetBinding({ keepOwner: true })"),
        "session_switch must keepOwner across rebind"
    );
    // Dead session-id gates removed (SessionShutdownEvent has no sessionId).
    assert!(!PLUGIN_SOURCE.contains("foreign_session"));
    assert!(!PLUGIN_SOURCE.contains("rootSessionId"));
    assert!(!PLUGIN_SOURCE.contains("shutdownSessionIdFromEvent"));
    assert!(!PLUGIN_SOURCE.contains("shutdownReasonFromEvent"));
}

#[test]
fn install_writes_plugin_source() {
    with_isolated_omp_env(|_| {
        assert!(install_omp_plugin().unwrap());
        let content = std::fs::read_to_string(get_omp_plugin_path()).unwrap();
        assert_eq!(content, PLUGIN_SOURCE);
        assert!(verify_omp_plugin_installed());
    });
}

#[test]
fn install_refuses_to_overwrite_non_hcom_file() {
    with_isolated_omp_env(|_| {
        let path = get_omp_plugin_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "// user's custom plugin").unwrap();

        let result = install_omp_plugin();
        assert!(result.is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "// user's custom plugin",
        );
        assert!(!verify_omp_plugin_installed());
    });
}

#[test]
fn install_upgrades_stale_hcom_owned_plugin() {
    with_isolated_omp_env(|_| {
        let path = get_omp_plugin_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Old hcom plugin: has the ownership marker but doesn't match current source.
        std::fs::write(&path, r#"const x = customType: "hcom-bootstrap";"#).unwrap();

        assert!(install_omp_plugin().unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), PLUGIN_SOURCE,);
        assert!(verify_omp_plugin_installed());
    });
}

#[test]
fn remove_deletes_hcom_plugin() {
    with_isolated_omp_env(|_| {
        install_omp_plugin().unwrap();
        let path = get_omp_plugin_path();
        assert!(path.exists());

        remove_omp_plugin().unwrap();
        assert!(!path.exists());
    });
}

#[test]
fn remove_preserves_non_hcom_file() {
    with_isolated_omp_env(|_| {
        let path = get_omp_plugin_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "// user's custom plugin").unwrap();

        remove_omp_plugin().unwrap();
        assert!(path.exists(), "non-hcom file must not be removed");
    });
}
