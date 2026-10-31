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
    let process_id = "550e8400-e29b-41d4-a716-446655440000";
    let env = HashMap::from([
        ("HCOM_INSTANCE_NAME".to_string(), launch_as.to_string()),
        ("HCOM_PROCESS_ID".to_string(), process_id.to_string()),
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
        ("HCOM_PROCESS_ID", process_id),
    ]
    .into_iter()
    .map(|(key, value)| {
        let old = std::env::var_os(key);
        unsafe { std::env::set_var(key, value) };
        (key, old)
    })
    .collect();
    crate::launcher::register_launch_instance(
        &db, launch_as, None, process_id, "omp", false, None, "/x",
    )
    .unwrap();
    let owner = OmpOwner {
        pid: std::process::id(),
        incarnation: crate::sys::process::identity(std::process::id()).unwrap(),
    };
    assert!(db.set_instance_pid_if_unset(launch_as, owner.pid).unwrap());
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
                ("pid".into(), serde_json::json!(owner.pid)),
                (
                    "launch_context".into(),
                    serde_json::json!({"omp_owner": owner}).to_string().into(),
                ),
            ]),
        )
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
            with_omp_binding_owner(owner, || {
                bind_session_to_process(&db, "review-session", Some(process_id))
            })
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
    let (_, pane_closed, _) =
        terminal::kill_process(2_000_000_000, std::slice::from_ref(&row.name), &info);
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
