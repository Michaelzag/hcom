use super::*;
use crate::db::HcomDb;
use crate::instances;
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
fn plugin_rebinds_identity_on_session_branch() {
    // /branch mints a new session id and emits only session_branch (not
    // session_switch); the plugin must reset+rebind or delivery dies.
    // keepOwner retains process-env identity ownership so nested task
    // extensions still skip bind while this instance rebinds.
    let idx = PLUGIN_SOURCE
        .find("pi.on(\"session_branch\"")
        .expect("session_branch handler present");
    let handler = &PLUGIN_SOURCE[idx..];
    assert!(handler.contains("resetBinding({ keepOwner: true })"));
    assert!(handler.contains("bindIdentity(ctx)"));
}

#[test]
fn plugin_notify_registration_wakes_pty_delivery_loop() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_ACTIVE);

    let pty_listener = bind_probe();
    let pty_port = pty_listener.local_addr().unwrap().port();
    db.upsert_notify_endpoint("luna", "pty", pty_port).unwrap();

    let plugin_listener = bind_probe();
    let plugin_port = plugin_listener.local_addr().unwrap().port();
    upsert_plugin_notify_endpoint(&db, "luna", plugin_port);

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
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_ACTIVE);
    db.conn()
        .execute(
            "UPDATE instances SET session_id = 'sid-omp' WHERE name = 'luna'",
            [],
        )
        .unwrap();
    db.rebind_session("sid-omp", "luna").unwrap();
    db.set_process_binding("pid-omp", "sid-omp", "luna")
        .unwrap();
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

    // Bound without a registration: no role, so the filter is off.
    assert_eq!(
        crate::delivery_policy::role_status_lines(&db),
        vec!["conductor role: NONE".to_string()]
    );

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
    upsert_plugin_notify_endpoint(&db, "luna", plugin_port);

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
fn recover_refuses_non_omp_row_without_mutation() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", crate::shared::ST_INACTIVE);
    db.conn()
        .execute(
            "UPDATE instances SET tool = 'claude' WHERE name = 'luna'",
            [],
        )
        .unwrap();

    let result = crate::instance_binding::recover_process_binding_for_instance(
        &db, "luna", "sid-new", "pid-1",
    );

    assert!(
        result.is_err(),
        "a non-omp row is a refused candidate: {result:?}"
    );
    assert_eq!(db.get_process_binding("pid-1").unwrap(), None);
    assert_eq!(db.get_session_binding("sid-new").unwrap(), None);
    let row = db.get_instance_full("luna").unwrap().unwrap();
    assert_eq!(row.tool, "claude");
    assert_eq!(row.session_id, None);

    cleanup(path);
}

#[test]
fn recover_reports_no_candidate_for_an_unknown_name() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", crate::shared::ST_INACTIVE);

    let result = crate::instance_binding::recover_process_binding_for_instance(
        &db, "ghost", "sid-new", "pid-1",
    );

    assert_eq!(result.unwrap(), None);
    assert_eq!(db.get_process_binding("pid-1").unwrap(), None);
    assert_eq!(db.get_session_binding("sid-new").unwrap(), None);
    assert_eq!(
        db.get_instance_full("luna").unwrap().unwrap().session_id,
        None
    );

    cleanup(path);
}

/// The plugin's retry-with-new-identity signal for a truly unbound presenter.
fn legacy_unbound() -> serde_json::Value {
    serde_json::json!({"error": "HCOM_PROCESS_ID not set"})
}

fn is_transient(response: &serde_json::Value) -> bool {
    response.get("transient") == Some(&serde_json::json!(true))
}

#[test]
fn missing_identity_without_a_raw_owner_is_legacy_unbound() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_LISTENING);

    for (raw_id, raw_name) in [
        (None, None),
        (Some(""), Some("")),
        (Some("pid-unknown"), None),
        (None, Some("ghost")),
        (Some("pid-unknown"), Some("ghost")),
    ] {
        assert_eq!(
            super::handlers::missing_omp_identity_error(&db, raw_id, raw_name),
            legacy_unbound(),
            "raw_id={raw_id:?} raw_name={raw_name:?}"
        );
    }

    cleanup(path);
}

#[test]
fn missing_identity_with_an_existing_raw_owner_is_a_final_refusal() {
    let (db, path) = setup_test_db();
    save_test_instance(&db, "luna", ST_LISTENING);
    db.set_process_binding("pid-luna", "", "luna").unwrap();
    // A mapping whose row is gone still names an owner the caller never proved.
    db.set_process_binding("pid-dangling", "", "ghost").unwrap();

    for (raw_id, raw_name) in [
        (Some("pid-luna"), None),
        (Some("pid-dangling"), None),
        (Some("pid-luna"), Some("ghost")),
        // A known-partial miss on the id still fails closed on the extant name.
        (Some("pid-unknown"), Some("luna")),
        (None, Some("luna")),
    ] {
        let response = super::handlers::missing_omp_identity_error(&db, raw_id, raw_name);
        assert_ne!(
            response,
            legacy_unbound(),
            "an existing owner must not invite a re-mint: raw_id={raw_id:?} raw_name={raw_name:?}"
        );
        assert!(response["error"].is_string(), "{response}");
        assert!(
            !is_transient(&response),
            "an ownership refusal is final: raw_id={raw_id:?} raw_name={raw_name:?}"
        );
    }

    cleanup(path);
}

#[test]
fn missing_identity_lookup_failure_is_transient_not_unbound() {
    let (db, path) = setup_test_db();
    db.conn()
        .execute_batch("DROP TABLE process_bindings")
        .unwrap();
    let response = super::handlers::missing_omp_identity_error(&db, Some("pid-luna"), None);
    assert!(is_transient(&response), "{response}");
    assert_ne!(response, legacy_unbound());
    cleanup(path);

    let (db, path) = setup_test_db();
    db.conn().execute_batch("DROP TABLE instances").unwrap();
    let response = super::handlers::missing_omp_identity_error(&db, None, Some("luna"));
    assert!(is_transient(&response), "{response}");
    assert_ne!(response, legacy_unbound());
    cleanup(path);
}

#[test]
fn plugin_source_pins_soft_stop_polish_markers() {
    assert!(PLUGIN_SOURCE.contains("Symbol.for(\"hcom.omp.identity\")"));
    assert!(PLUGIN_SOURCE.contains("stopReconcileTimer"));
    assert!(PLUGIN_SOURCE.contains("tearingDown"));
    assert!(PLUGIN_SOURCE.contains("HCOM_TIMEOUT_MS"));
    assert!(PLUGIN_SOURCE.contains("1800"));
    let shutdown_idx = PLUGIN_SOURCE
        .find("pi.on(\"session_shutdown\"")
        .expect("session_shutdown handler present");
    let handler = &PLUGIN_SOURCE[shutdown_idx..];
    assert!(
        handler.contains("keepOwner = !softStopOk"),
        "failed soft-stop path must keepOwner"
    );
    assert!(
        handler.contains("reg.tearingDown = false"),
        "failed soft-stop keepOwner must clear tearingDown so owner can rebind"
    );
    assert!(
        PLUGIN_SOURCE.contains("reg.tearingDown && !ownsIdentity"),
        "tearingDown must not block the owning extension from rebinding"
    );
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
/// the returned values for the test's lifetime. Required by anything that
/// writes or resolves the installed plugin file.
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
