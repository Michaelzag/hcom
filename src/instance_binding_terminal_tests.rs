use super::*;
use crate::terminal;
use serial_test::serial;
use std::collections::HashMap;

// Adapted from ReviewHcom95b's two repros: exercise the actual canonical bind
// rather than simulating migration by copying launch_context alone.
fn review_custom_case(
    launch_as: &str,
    kill_as: &str,
    opener_stdout: &str,
    pane_env: &str,
    transactional: bool,
) -> (bool, String) {
    let scratch = tempfile::tempdir().unwrap();
    let open = scratch.path().join("open.sh");
    let close = scratch.path().join("close.sh");
    let closed = scratch.path().join("closed");
    std::fs::write(&open, format!("printf '%s\\n' '{opener_stdout}'\n")).unwrap();
    std::fs::write(
        &close,
        format!("printf '%s' \"$1\" > '{}'\n", closed.display()),
    )
    .unwrap();
    let config = format!(
        "[terminal]\nactive = 'myterm'\n[terminal.presets.myterm]\nopen = 'sh {} {{script}}'\nclose = 'sh {} {{pane_id}}'\nbinary = 'sh'\npane_id_env = 'MYTERM_PANE'\n",
        open.display(),
        close.display()
    );
    let _guard = crate::hooks::test_helpers::isolated_test_env_with_config(Some(&config));
    let db = HcomDb::open_raw(&scratch.path().join("test.db")).unwrap();
    db.init_db().unwrap();
    let env = HashMap::from([
        ("HCOM_INSTANCE_NAME".to_string(), launch_as.to_string()),
        ("HCOM_PROCESS_ID".to_string(), "review-nonce".to_string()),
    ]);
    let (result, _) = terminal::launch_terminal(
        ":",
        &env,
        Some("/x"),
        false,
        false,
        Some("myterm"),
        false,
        Some("omp"),
    )
    .unwrap();
    assert!(matches!(result, terminal::LaunchResult::Success));
    let saved: Vec<_> = [
        ("HCOM_LAUNCHED_PRESET", "myterm"),
        ("MYTERM_PANE", pane_env),
        ("HCOM_PROCESS_ID", "review-nonce"),
    ]
    .into_iter()
    .map(|(key, value)| {
        let old = std::env::var_os(key);
        unsafe { std::env::set_var(key, value) };
        (key, old)
    })
    .collect();
    db.save_instance_named(
        launch_as,
        &serde_json::Map::from_iter([
            ("tool".into(), serde_json::json!("omp")),
            ("created_at".into(), serde_json::json!(1.0)),
            ("status".into(), serde_json::json!("pending")),
            ("status_context".into(), serde_json::json!("new")),
        ]),
    )
    .unwrap();
    capture_and_store_launch_context(&db, launch_as);
    for (key, old) in saved {
        unsafe {
            match old {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
    if kill_as != launch_as {
        db.save_instance_named(
            kill_as,
            &serde_json::Map::from_iter([
                ("tool".into(), serde_json::json!("omp")),
                ("created_at".into(), serde_json::json!(1.0)),
                ("status".into(), serde_json::json!("inactive")),
            ]),
        )
        .unwrap();
        db.set_process_binding("review-nonce", "", launch_as)
            .unwrap();
        if transactional {
            db.log_life_event(
                kill_as,
                "stopped",
                "test",
                "exit",
                Some(serde_json::json!({"session_id":"review-session", "tool":"omp"})),
                None,
            )
            .unwrap();
        } else {
            db.rebind_session("review-session", kill_as).unwrap();
        }
        assert_eq!(
            bind_session_to_process(&db, "review-session", Some("review-nonce"))
                .unwrap()
                .as_deref(),
            Some(kill_as)
        );
        assert!(db.get_instance_full(launch_as).unwrap().is_none());
    }
    let row = db.get_instance_full(kill_as).unwrap().unwrap();
    let info = terminal::resolve_terminal_info(
        row.terminal_preset_effective.as_deref(),
        row.launch_context.as_deref(),
    );
    let owner = crate::proctruth::verify_kill_owner(2_000_000_000, None, &[]).unwrap();
    let (_, pane_closed, _) = terminal::kill_process(
        &owner,
        std::slice::from_ref(&row.name),
        &[],
        &[],
        &info,
        |_| Ok(()),
        &mut crate::sys::process::UnsignaledCarriers::default(),
    )
    .unwrap();
    (
        pane_closed,
        std::fs::read_to_string(closed).unwrap_or_default(),
    )
}

#[test]
#[serial]
fn review_pane_id_env_still_wins_over_opener_stdout() {
    let (_, log) = review_custom_case("bura", "bura", "launched window ok", "pane-42", false);
    assert_eq!(log, "pane-42");
}

#[test]
#[serial]
fn review_restored_canonical_still_closes_its_pane() {
    for transactional in [false, true] {
        let (closed, log) = review_custom_case("mozi", "fano", "pane-7", "pane-7", transactional);
        assert!(
            closed,
            "restored canonical lost its pane close (transactional={transactional})"
        );
        assert_eq!(log, "pane-7");
    }
}
