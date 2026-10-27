use super::*;
use crate::hooks::common::StopOutcome;
use serde_json::json;
#[cfg(unix)]
use serial_test::serial;

#[cfg(unix)]
fn terminal_ownership_case(
    target: &str,
    pane: &str,
    opened_as: Option<&str>,
    helper_pane: Option<&str>,
    silent: bool,
) -> (bool, String) {
    let (pane_closed, marker) = terminal_ownership_case_with_kill(
        target,
        pane,
        opened_as,
        helper_pane,
        silent,
        |db, name| {
            let row = db.get_instance_full(name).unwrap().unwrap();
            let owner = crate::proctruth::verify_kill_owner(2_000_000_000, None, &[]).unwrap();
            let (_, pane_closed, _, _, _) =
                kill_instance(db, name, &owner, &row, false, &[], &[]).unwrap();
            pane_closed
        },
    );
    (pane_closed, marker.unwrap_or_default())
}

#[cfg(unix)]
fn terminal_ownership_case_with_kill(
    target: &str,
    pane: &str,
    opened_as: Option<&str>,
    helper_pane: Option<&str>,
    silent: bool,
    kill: impl FnOnce(&HcomDb, &str) -> bool,
) -> (bool, Option<String>) {
    use std::collections::HashMap;
    let process_id = format!("launch-nonce-{target}");
    let scratch = tempfile::tempdir().unwrap();
    let open = scratch.path().join("open.sh");
    let close = scratch.path().join("close.sh");
    let closed = scratch.path().join("closed");
    std::fs::write(
            &open,
            "case \"$2\" in /silent-cwd) ;; /instance-cwd|/helper-cwd) printf 'tui-%s\\n' \"$2\" ;; *) printf 'gnome-terminal-seat-%s\\n' \"$1\" ;; esac\n",
        )
        .unwrap();
    std::fs::write(
        &close,
        format!("printf '%s' \"$1\" > '{}'\n", closed.display()),
    )
    .unwrap();
    let config = format!(
        "[relay]\nenabled = false\n[terminal]\nactive = 'gnomeseat'\n[terminal.presets.gnomeseat]\nopen = 'sh {} {{instance_name}} {{cwd}} {{script}}'\nclose = 'sh {} {{pane_id}}'\nbinary = 'sh'\npane_id_env = 'GNOME_SEAT_UNIT'\n",
        open.display(),
        close.display()
    );
    let _guard = crate::hooks::test_helpers::isolated_test_env_with_config(Some(&config));
    let db = HcomDb::open_raw(&scratch.path().join("test.db")).unwrap();
    db.init_db().unwrap();
    if let Some(name) = opened_as {
        let env = HashMap::from([
            ("HCOM_INSTANCE_NAME".to_string(), name.to_string()),
            ("HCOM_PROCESS_ID".to_string(), process_id.clone()),
        ]);
        let (result, _) = terminal::launch_terminal(
            ":",
            &env,
            if silent {
                Some("/silent-cwd")
            } else {
                helper_pane.map(|_| "/instance-cwd")
            },
            false,
            false,
            Some("gnomeseat"),
            false,
            Some("omp"),
        )
        .unwrap();
        assert!(matches!(result, terminal::LaunchResult::Success));
    }
    if let Some(helper_pane) = helper_pane {
        // A helper window (the `hcom` TUI) opened later under the same
        // instance identity: same nonce, no tool instance being launched.
        let env = HashMap::from([
            ("HCOM_INSTANCE_NAME".to_string(), "bura".to_string()),
            ("HCOM_PROCESS_ID".to_string(), process_id.clone()),
        ]);
        let (result, _) = terminal::launch_terminal(
            ":",
            &env,
            Some(helper_pane),
            false,
            false,
            Some("gnomeseat"),
            false,
            None,
        )
        .unwrap();
        assert!(matches!(result, terminal::LaunchResult::Success));
    }
    // Exactly the metadata a manual omp start inherits from its shell.
    let saved: Vec<_> = [
        ("HCOM_LAUNCHED_PRESET", "gnomeseat"),
        ("GNOME_SEAT_UNIT", pane),
        ("HCOM_PROCESS_ID", process_id.as_str()),
    ]
    .into_iter()
    .map(|(key, value)| {
        let old = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        (key, old)
    })
    .collect();
    db.save_instance_named(
        target,
        &serde_json::Map::from_iter([
            ("tool".into(), json!("omp")),
            ("created_at".into(), json!(1.0)),
        ]),
    )
    .unwrap();
    crate::instance_binding::capture_and_store_launch_context(&db, target);
    for (key, old) in saved {
        unsafe {
            match old {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
    let pane_closed = kill(&db, target);
    let marker = match std::fs::read_to_string(closed) {
        Ok(marker) => Some(marker),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("read pane-close marker: {error}"),
    };
    (pane_closed, marker)
}

#[cfg(unix)]
fn spawn_bound_pane_owner(db: &HcomDb, name: &str) -> std::process::Child {
    use std::os::unix::process::CommandExt;

    // Like the bound-sleeper fixtures, this shell stands in for a non-OMP
    // tool: these tests cover pane cleanup, not launcher/root discovery.

    let process_id = format!("launch-nonce-{name}");
    db.set_process_binding(&process_id, "sess-owned-pane", name)
        .unwrap();
    db.conn()
        .execute(
            "UPDATE instances SET tool = 'codex', status = 'active', \
             session_id = 'sess-owned-pane' WHERE name = ?",
            rusqlite::params![name],
        )
        .unwrap();
    let mut command = std::process::Command::new("sh");
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("HCOM_") {
            command.env_remove(key);
        }
    }
    let owner = command
        .args(["-c", "read -r _"])
        .process_group(0)
        .env("HCOM_DIR", std::env::var_os("HCOM_DIR").unwrap())
        .env("HCOM_INSTANCE_NAME", name)
        .env("HCOM_PROCESS_ID", &process_id)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn owned-pane process");
    db.update_instance_pid(name, owner.id()).unwrap();
    wait_for_enumerated(name, owner.id());
    owner
}

#[cfg(unix)]
#[test]
#[serial]
fn terminal_ownership_inherited_seat_is_not_closed() {
    // A hand-started omp inherits another seat's GNOME_SEAT_UNIT; the
    // resume/kill of its instance must not close that unit.
    let (closed, log) =
        terminal_ownership_case("bura", "gnome-terminal-seat-neka", None, None, false);
    assert!(!closed, "bura must not close neka's terminal");
    assert_eq!(log, "");
}

#[cfg(unix)]
#[test]
#[serial]
fn terminal_ownership_silent_opener_still_closes_own_pane() {
    // tmux/tmux-split-style openers print no pane id and the child
    // captures its own pane through the environment instead: a proven
    // launch must still close that pane.
    let (closed, log) = terminal_ownership_case("bura", "silent-pane-7", Some("bura"), None, true);
    assert!(closed);
    assert_eq!(log, "silent-pane-7");
}

#[cfg(unix)]
#[test]
#[serial]
fn terminal_ownership_helper_window_cannot_reroute_teardown() {
    // A later helper window (the `hcom` TUI) opened under the same
    // instance identity must not take over the receipt: the kill still
    // closes the instance's own pane, never the helper's.
    let (closed, log) =
        terminal_ownership_case("bura", "", Some("bura"), Some("/helper-cwd"), false);
    assert!(closed);
    assert_eq!(log, "tui-/instance-cwd");
}

#[cfg(unix)]
#[test]
#[serial]
fn terminal_ownership_launched_seat_closes_its_own_pane() {
    let (closed, log) = terminal_ownership_case(
        "bura",
        "gnome-terminal-seat-bura",
        Some("bura"),
        None,
        false,
    );
    assert!(closed);
    assert_eq!(log, "gnome-terminal-seat-bura");
}

#[cfg(unix)]
#[test]
#[serial]
fn terminal_ownership_without_launch_closes_nothing() {
    let (closed, log) = terminal_ownership_case("bura", "", None, None, false);
    assert!(!closed);
    assert_eq!(log, "");
}

#[cfg(unix)]
#[test]
#[serial]
fn kill_gone_owner_closes_its_owned_pane() {
    let name = format!("hcom-pane-gone-{}", std::process::id());
    let pane = format!("gnome-terminal-seat-{name}");
    let (closed, marker) =
        terminal_ownership_case_with_kill(&name, &pane, Some(&name), None, false, |db, name| {
            let mut owner = spawn_bound_pane_owner(db, name);
            let pid = owner.id();
            drop(owner.stdin.take());
            owner.wait().unwrap();
            assert!(crate::sys::process::is_definitely_dead(pid));

            let (row, bindings, watermark) = ResolvedIncarnation::read(db, name).unwrap();
            let result = kill_resolved_instance(
                db,
                &row.unwrap(),
                &bindings,
                watermark,
                "test",
                Some(&[std::process::id()]),
                |_, _, _| Ok(()),
            )
            .unwrap_or_else(|error| panic!("confirmed-Gone kill must succeed: {error}"));
            assert_eq!(result.kill_result, terminal::KillResult::AlreadyDead);
            assert_eq!(result.leftovers_terminated, None);
            assert_eq!(result.teardown, TeardownOutcome::Completed);
            assert!(result.pane_retry_command.is_none());
            assert_eq!(result.preset_name, "gnomeseat");
            assert_eq!(result.pane_id, pane);
            assert!(db.get_instance_full(name).unwrap().is_none());
            assert!(db.process_binding_ids(name).unwrap().is_empty());
            assert_killed_by(db, name, "test");
            result.pane_closed
        });
    assert!(
        closed,
        "the confirmed-Gone command path closes its owned pane"
    );
    assert_eq!(marker.as_deref(), Some(pane.as_str()));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
#[serial]
fn kill_zombie_owner_closes_its_owned_pane_after_confirmation() {
    let name = format!("hcom-pane-zombie-{}", std::process::id());
    let pane = format!("gnome-terminal-seat-{name}");
    let (closed, marker) =
        terminal_ownership_case_with_kill(&name, &pane, Some(&name), None, false, |db, name| {
            let mut owner = spawn_bound_pane_owner(db, name);
            let pid = owner.id();
            drop(owner.stdin.take());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !crate::sys::process::is_zombie_group_leader(pid) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "owned-pane process never became an unreaped zombie group leader"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            let (row, bindings, watermark) = ResolvedIncarnation::read(db, name).unwrap();
            let result = kill_resolved_instance(
                db,
                &row.unwrap(),
                &bindings,
                watermark,
                "test",
                Some(&[std::process::id()]),
                |_, _, _| Ok(()),
            );
            owner.wait().unwrap();
            let result = result
                .unwrap_or_else(|error| panic!("confirmed-zombie kill must succeed: {error}"));
            assert_eq!(result.kill_result, terminal::KillResult::AlreadyDead);
            assert_eq!(result.leftovers_terminated, Some(0));
            assert_eq!(result.teardown, TeardownOutcome::Completed);
            assert!(result.pane_retry_command.is_none());
            assert_eq!(result.preset_name, "gnomeseat");
            assert_eq!(result.pane_id, pane);
            assert!(db.get_instance_full(name).unwrap().is_none());
            assert!(db.process_binding_ids(name).unwrap().is_empty());
            assert_killed_by(db, name, "test");
            result.pane_closed
        });
    assert!(
        closed,
        "the confirmed-zombie command path closes its owned pane"
    );
    assert_eq!(marker.as_deref(), Some(pane.as_str()));
}

#[cfg(unix)]
#[test]
#[serial]
fn kill_self_exclusion_leaves_its_owned_pane_open_by_design() {
    let name = format!("hcom-pane-self-{}", std::process::id());
    let pane = format!("gnome-terminal-seat-{name}");
    let (closed, marker) =
        terminal_ownership_case_with_kill(&name, &pane, Some(&name), None, false, |db, name| {
            let mut owner = spawn_bound_pane_owner(db, name);
            let pid = owner.id();
            let (row, bindings, watermark) = ResolvedIncarnation::read(db, name).unwrap();
            let result = kill_resolved_instance(
                db,
                &row.unwrap(),
                &bindings,
                watermark,
                "test",
                Some(&[std::process::id(), pid]),
                |_, _, _| Ok(()),
            );
            let owner_alive = owner.try_wait().unwrap().is_none();
            drop(owner.stdin.take());
            owner.wait().unwrap();
            let result =
                result.unwrap_or_else(|error| panic!("self-excluded kill must succeed: {error}"));

            assert!(owner_alive, "the self-excluded owner is never signalled");
            assert_eq!(result.self_excluded, 1);
            assert_eq!(result.self_pid, Some(std::process::id()));
            assert_eq!(result.self_session.as_deref(), Some("sess-owned-pane"));
            assert_eq!(result.leftovers_terminated, None);
            assert_eq!(result.teardown, TeardownOutcome::Completed);
            assert_eq!(result.preset_name, "gnomeseat");
            assert_eq!(result.pane_id, pane);
            assert!(
                result.pane_retry_command.is_none(),
                "no retry for a pane left open by design"
            );
            assert!(
                !report_incomplete_pane_cleanup(
                    result.kill_result.into(),
                    result.pane_retry_command.as_deref(),
                ),
                "the caller's intentionally open pane is not a pane-close failure"
            );
            assert!(db.get_instance_full(name).unwrap().is_none());
            assert!(db.process_binding_ids(name).unwrap().is_empty());
            assert_killed_by(db, name, "test");
            result.pane_closed
        });
    assert!(!closed, "the self-excluded caller's owned pane stays open");
    assert!(
        marker.is_none(),
        "no terminal close command runs for the caller's pane"
    );
}

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
            "Sent SIGTERM to process group 42 for 'luna:ABCD' (closed kitty pane @1)".to_string(),
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
        if crate::proctruth::processes_for_instance(name, &[], &[])
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
    let (row, binding_ids, event_watermark) = ResolvedIncarnation::read(db, name).unwrap();
    ResolvedIncarnation::new(&row.expect("row"), &binding_ids, event_watermark)
}

/// A: kill reaps the authorized tree — even bound carriers outside the
/// recorded pid — and only then deletes the row. Unbound same-name and
/// different-named sleepers must survive.
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

    // The verified owner and a second identity carrier have different PIDs.
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
    let mut owner = spawn_named_sleeper(&name, "proc-kill-cur");
    db.update_instance_pid(&name, owner.id()).unwrap();

    let mut sleeper = spawn_named_sleeper(&name, "proc-kill-cur");
    let spid = sleeper.id();
    wait_for_enumerated(&name, spid);
    let mut unbound = spawn_named_sleeper(&name, "proc-kill-old");
    wait_for_enumerated(&name, unbound.id());
    let mut bystander = spawn_named_sleeper(&other, "proc-other");
    let bpid = bystander.id();
    wait_for_enumerated(&other, bpid);

    kill_tracked_instance(&db, &name, "test")
        .unwrap_or_else(|e| panic!("kill must succeed once tree is reaped: {e}"));
    // Reap the (zombie) child so bare kill-0 liveness observes it.
    sleeper.wait().ok();
    owner.wait().unwrap();
    assert!(
        !crate::sys::process::is_alive(spid),
        "bound sleeper outside the recorded pid is reaped"
    );
    assert!(
        db.get_instance_full(&name).unwrap().is_none(),
        "row deleted only after the tree is gone"
    );
    assert!(
        crate::sys::process::is_alive(bpid),
        "different-named sleeper survives"
    );
    let unbound_alive = unbound
        .try_wait()
        .expect("try_wait unbound carrier")
        .is_none();
    unbound.kill().ok();
    unbound.wait().ok();
    bystander.kill().ok();
    bystander.wait().ok();
    assert!(
        unbound_alive,
        "unbound same-name sleeper is never signalled"
    );
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

    // "Self": the verified, bound root standing in for the caller's own seat.
    let mut self_sleeper = spawn_named_sleeper(&name, "proc-kill-self");
    let self_pid = self_sleeper.id();
    db.update_instance_pid(&name, self_pid).unwrap();
    wait_for_enumerated(&name, self_pid);
    let mut foreign_sleeper = spawn_named_sleeper(&name, "proc-kill-self");
    let foreign_pid = foreign_sleeper.id();
    wait_for_enumerated(&name, foreign_pid);

    let self_set = vec![std::process::id(), self_pid];
    let db_path = dir.path().join("test.db");
    let kill_name = name.clone();
    let killer = std::thread::spawn(move || {
        let db = crate::db::HcomDb::open_raw(&db_path).unwrap();
        kill_tracked_instance_with_self_pids(&db, &kill_name, "test", &self_set, |_, _, _| Ok(()))
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
/// The survivor is a bound carrier born after the verified, excluded
/// owner, outside that owner's native tree. It is forced through the
/// termination seam: no same-uid process can outlive SIGTERM+SIGKILL,
/// so a real carrier cannot outlive the real budget.
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

    let mut owner = seed_bound_row_with_sleeper(&db, &name, "proc-kill-fc", "sess-kill-fc");
    let owner_pid = owner.id();
    let binding_ids = db.process_binding_ids(&name).unwrap();

    // An eligible bound carrier that outlives the signal budget — reported
    // as a survivor by the injected reap (it is never signalled here).
    let mut survivor = spawn_named_sleeper(&name, "proc-kill-fc");
    let survivor_pid = survivor.id();
    wait_for_enumerated(&name, survivor_pid);

    let excluded = vec![std::process::id(), owner_pid];
    let err = kill_tracked_instance_with_self_pids(&db, &name, "test", &excluded, |_, _, _| {
        Err(crate::proctruth::ReapError::Survivors(vec![survivor_pid]))
    })
    .err()
    .expect("a non-self survivor must fail the kill")
    .to_string();
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
    assert!(
        crate::sys::process::is_alive(owner_pid),
        "verified self root is never signalled"
    );
    survivor.kill().ok();
    survivor.wait().ok();
    owner.kill().ok();
    owner.wait().ok();
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
    db.update_instance_pid(&name, spid).unwrap();
    wait_for_enumerated(&name, spid);

    let self_set = vec![std::process::id()];
    let result =
        kill_tracked_instance_with_self_pids(&db, &name, "test", &self_set, |_, _, _| Ok(()))
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
/// exit 0. The rebind is injected after owner/incarnation verification,
/// before native termination and the final teardown write.
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

    // The old incarnation's verified owner; native termination must take
    // it even though the row is rebound before the teardown.
    let mut old_sleeper = spawn_named_sleeper(&name, "proc-kill-rb-old");
    let old_pid = old_sleeper.id();
    db.update_instance_pid(&name, old_pid).unwrap();
    wait_for_enumerated(&name, old_pid);

    let excluded = vec![std::process::id()];
    let result = kill_tracked_instance_with_self_pids(&db, &name, "test", &excluded, |n, _, _| {
        // Rebind after owner verification: same name, new binding
        // epoch (the `start --as` shape).
        db.conn()
            .execute(
                "DELETE FROM process_bindings WHERE instance_name = ?1",
                rusqlite::params![n],
            )
            .unwrap();
        db.set_process_binding("proc-kill-rb-new", "sess-kill-rb-new", n)
            .unwrap();
        Ok(())
    })
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
    let result = kill_tracked_instance_with_self_pids(&db, &name, "test", &self_set, |n, _, _| {
        // The name-only rebind: bindings stay empty, the session
        // changes.
        db.conn()
            .execute(
                "UPDATE instances SET session_id = 'sess-rebound' WHERE name = ?1",
                rusqlite::params![n],
            )
            .unwrap();
        Ok(())
    })
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

/// Insert a bound row whose recorded, verified owner is the live sleeper.
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
    db.update_instance_pid(name, sleeper.id()).unwrap();
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
    let mut sleeper = seed_bound_row_with_sleeper(&db, &name, "proc-kill-soft", "sess-kill-soft");
    let spid = sleeper.id();

    let self_set = vec![std::process::id()];
    let result = kill_tracked_instance_with_self_pids(&db, &name, "test", &self_set, |n, _, _| {
        // The harness's own shutdown hook runs while the kill holds its claim.
        crate::hooks::common::soft_finalize_session(&db, n, "shutdown", None, false);
        Ok(())
    })
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
    let mut sleeper = seed_bound_row_with_sleeper(&db, &name, "proc-kill-hard", "sess-kill-hard");
    let spid = sleeper.id();

    let self_set = vec![std::process::id()];
    let result = kill_tracked_instance_with_self_pids(&db, &name, "test", &self_set, |n, _, _| {
        // The harness's own SessionEnd runs while the kill holds its claim.
        assert_eq!(
            crate::hooks::common::finalize_session(&db, n, "shutdown", None),
            StopOutcome::AlreadyStopped
        );
        Ok(())
    })
    .unwrap_or_else(|e| panic!("a session self-stop is not a kill failure: {e}"));

    sleeper.wait().ok();
    assert_eq!(result.teardown, TeardownOutcome::Completed);
    assert!(!crate::sys::process::is_alive(spid), "sleeper reaped");
    assert!(db.get_instance_full(&name).unwrap().is_none());
    assert_killed_by(&db, &name, "test");
    let _ = _guard;
}

/// No claim at all is live mixed-version code, not a dead branch: a
/// 0.7.29 relay worker kills remotely and writes none, and a claim that
/// fails to register leaves the same state. With no claim to yield to,
/// the session's own exit hook ends the session as a natural exit — its
/// reason, its initiator — and the kill's lost teardown reports that as
/// the session's self-stop, never a re-registration: released by the
/// hard SessionEnd, kept by the soft stop.
#[test]
#[cfg(unix)]
#[serial]
fn kill_without_a_claim_reports_the_session_exit_hook_as_self_stop() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    for soft in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();
        let name = format!("hcom-kill-{}-no-claim-{soft}", std::process::id());
        let mut sleeper = seed_bound_row_with_sleeper(&db, &name, "proc-no-claim", "sess-no-claim");
        let result = kill_tracked_instance_with_self_pids(
            &db,
            &name,
            "test",
            &[std::process::id()],
            |n, _, _| {
                // The kill holds no claim, the state a 0.7.29 relay
                // worker's kill leaves.
                db.kv_set(&format!("teardown_claim:{n}"), None).unwrap();
                if soft {
                    crate::hooks::common::soft_finalize_session(&db, n, "shutdown", None, false);
                } else {
                    assert_eq!(
                        crate::hooks::common::finalize_session(&db, n, "shutdown", None),
                        StopOutcome::Stopped
                    );
                }
                Ok(())
            },
        )
        .unwrap_or_else(|e| panic!("a session self-stop is not a kill failure: {e}"));
        sleeper.wait().ok();

        let (expected, row_kept) = if soft {
            (TeardownOutcome::SessionStoppedKeptRow, true)
        } else {
            (TeardownOutcome::SessionStoppedReleasedRow, false)
        };
        assert_eq!(result.teardown, expected, "soft={soft}");
        assert_eq!(
            db.get_instance_full(&name).unwrap().is_some(),
            row_kept,
            "soft={soft}"
        );
        let records: Vec<(String, String)> = db
            .conn()
            .prepare(
                "SELECT json_extract(data, '$.reason'), json_extract(data, '$.by') \
                     FROM events WHERE type = 'life' AND instance = ?1 \
                     AND json_extract(data, '$.action') = 'stopped'",
            )
            .unwrap()
            .query_map(rusqlite::params![name], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            records,
            vec![("exit:shutdown".to_string(), "session".to_string())],
            "soft={soft}: the session's own record, the kill wrote none"
        );
    }
}

/// This covers command CAS/teardown ordering; the callback precedes native capture.
/// The exact post-capture rescan proof lives in `sys::kill_tree_linux::tests`:
/// `forks_made_during_the_kill_are_absorbed_and_confirmed_gone`.
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
        |n, _, _| {
            let child = spawn_named_sleeper(n, "proc-empty-capture");
            wait_for_enumerated(n, child.id());
            late = Some(child);
            Ok(())
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
            |n, _, _| {
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

        let error = result.err().expect("survivors fail the kill").to_string();
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
    let mut sleeper = seed_bound_row_with_sleeper(&db, &name, "proc-kill-sr-old", "sess-kill-sr");

    let self_set = vec![std::process::id()];
    let result = kill_tracked_instance_with_self_pids(&db, &name, "test", &self_set, |n, _, _| {
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
        Ok(())
    })
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

/// Kill a bound row whose PTY wrapper exits mid-kill: `exit` runs on a
/// second connection (the wrapper is another process), after owner
/// verification but before native termination. Returns the kill's
/// teardown outcome.
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
    let result = kill_tracked_instance_with_self_pids(&db, name, "test", &self_set, |n, _, _| {
        exit(&mut wrapper_db, n);
        Ok(())
    })
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

/// Kill a bound row (`created_at = 42`) whose vanished sweep releases it
/// mid-kill: the real reap, then a `stopped by=daemon` event whose
/// snapshot carries `event_bits` as its `created_at_bits` beside the
/// row's own session (`None`: no snapshot at all), and the row deleted —
/// optionally replaced by another incarnation. Returns the kill's
/// teardown outcome.
#[cfg(unix)]
fn kill_mid_daemon_sweep(
    db_path: &std::path::Path,
    name: &str,
    event_bits: Option<serde_json::Value>,
    replace: bool,
) -> TeardownOutcome {
    let db = crate::db::HcomDb::open_raw(db_path).unwrap();
    db.init_db().unwrap();
    let mut sleeper =
        seed_bound_row_with_sleeper(&db, name, "proc-kill-vanished", "sess-kill-vanished");
    db.conn()
        .execute(
            "UPDATE instances SET created_at = 42 WHERE name = ?",
            rusqlite::params![name],
        )
        .unwrap();
    let spid = sleeper.id();
    let result = kill_tracked_instance_with_self_pids(
            &db, name, "test", &[std::process::id()],
            |n, _, _| {
                let snapshot = event_bits.map(|bits| {
                    serde_json::json!({ "created_at_bits": bits, "session_id": "sess-kill-vanished" })
                });
                db.log_life_event(n, "stopped", "daemon", "vanished", snapshot, Some("newest-binding")).unwrap();
                db.delete_instance(n).unwrap();
                if replace {
                    db.conn().execute(
                        "INSERT INTO instances (name, status, created_at, session_id) VALUES (?1, 'active', 1, 'replacement')",
                        rusqlite::params![n],
                    ).unwrap();
                }
                Ok(())
            },
        ).unwrap();
    sleeper.wait().ok();
    assert!(!crate::sys::process::is_alive(spid));
    result.teardown
}

#[test]
#[cfg(unix)]
#[serial]
fn kill_reports_session_self_stop_when_vanished_sweep_deletes_row_mid_kill() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let dir = tempfile::tempdir().unwrap();
    let outcome = kill_mid_daemon_sweep(
        &dir.path().join("test.db"),
        &format!("hcom-kill-{}-vanished", std::process::id()),
        Some(serde_json::json!(42f64.to_bits() as i64)),
        false,
    );
    assert_eq!(outcome, TeardownOutcome::SessionStoppedReleasedRow);
}

#[test]
#[cfg(unix)]
#[serial]
fn kill_reports_re_registration_for_vanished_sweep_from_other_incarnation() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let dir = tempfile::tempdir().unwrap();
    let name = format!("hcom-kill-{}-vanished-other", std::process::id());
    let outcome = kill_mid_daemon_sweep(
        &dir.path().join("test.db"),
        &name,
        Some(serde_json::json!(1)),
        true,
    );
    assert_eq!(outcome, TeardownOutcome::RowReRegistered);
    let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
    assert!(
        db.get_instance_full(&name).unwrap().is_some(),
        "replacement row survives"
    );
}

/// A PTY exit that commits its stop right after the kill read the row is
/// above the kill's watermark, because the watermark comes from the same
/// snapshot as the row and its bindings: a self-stop, not a
/// re-registration. A watermark read after the row would hide it.
#[test]
#[cfg(unix)]
#[serial]
fn kill_reports_pty_self_stop_committed_right_after_its_read() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = HcomDb::open_raw(&db_path).unwrap();
    db.init_db().unwrap();
    let name = format!("hcom-kill-{}-capture-gap", std::process::id());
    let mut sleeper = seed_bound_row_with_sleeper(&db, &name, "proc-gap", "sess-gap");
    CAPTURE_GAP_HOOK.with(|hook| hook.set(Some(capture_gap_finalize)));
    /// The PTY wrapper's exit release, in its production snapshot shape.
    fn capture_gap_finalize(db: &HcomDb, name: &str) {
        let mut snapshot = db.get_instance_snapshot(name).unwrap().unwrap();
        let bits = snapshot["created_at"].as_f64().unwrap().to_bits();
        snapshot["created_at_bits"] = serde_json::json!(bits);
        db.log_life_event(
            name,
            "stopped",
            "pty",
            "killed",
            Some(snapshot),
            Some("proc-gap"),
        )
        .unwrap();
        db.delete_instance(name).unwrap();
    }
    let result = kill_tracked_instance_with_self_pids(
        &db,
        &name,
        "test",
        &[std::process::id()],
        |_, _, _| Ok(()),
    )
    .unwrap();
    sleeper.wait().ok();
    assert_eq!(result.teardown, TeardownOutcome::SessionStoppedReleasedRow);
}

#[test]
#[cfg(unix)]
#[serial]
fn kill_reports_re_registration_for_unreadable_vanished_sweep() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    for (index, value) in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!("bad")),
    ]
    .into_iter()
    .enumerate()
    {
        let dir = tempfile::tempdir().unwrap();
        let outcome = kill_mid_daemon_sweep(
            &dir.path().join("test.db"),
            &format!(
                "hcom-kill-{}-vanished-unreadable-{index}",
                std::process::id()
            ),
            value,
            false,
        );
        assert_eq!(outcome, TeardownOutcome::RowReRegistered);
    }
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

/// The incarnation decides, not the writer: a PTY wrapper whose process
/// the kill never resolved releases the row the kill resolved, and its
/// stopped snapshot names that very incarnation. The resolved row was
/// stopped and nothing re-registered, so the lost teardown is the
/// session's self-stop.
#[test]
#[cfg(unix)]
#[serial]
fn kill_reports_self_stop_when_a_foreign_wrapper_releases_the_resolved_incarnation() {
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
    assert_eq!(outcome, TeardownOutcome::SessionStoppedReleasedRow);
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
    let mut sleeper =
        seed_bound_row_with_sleeper(&db, &name, "proc-bindingless-stop", "sess-bindingless-stop");
    // The bindingless branch is keyed to the exact `created_at` bit
    // pattern, so the fixture's stopped snapshot carries it the way the
    // PTY wrapper's exit cleanup writes it (see
    // `delivery::cleanup_deleted_instance`).
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
        |n, _, _| {
            let snapshot = db.get_instance_snapshot(n).unwrap().map(|mut snapshot| {
                if let Some(created_at) = snapshot
                    .get("created_at")
                    .and_then(serde_json::Value::as_f64)
                    && let Some(object) = snapshot.as_object_mut()
                {
                    object.insert(
                        "created_at_bits".to_string(),
                        serde_json::json!(created_at.to_bits()),
                    );
                }
                snapshot
            });
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

/// The pre-#21 writer's rows still release. 0.7.29 wrote
/// `instances.created_at` as a fractional f64 through exactly the writer
/// below; every release path binds the value re-read from that same row
/// in the same transaction as the delete. One row per release path, each
/// asserted GONE afterwards — the ghost-row failure is any path that
/// leaves the row behind.
#[test]
#[cfg(unix)]
#[serial]
fn rows_written_by_the_0_7_29_writer_release_through_close_kill_and_sweep() {
    // ULP-critical: both float decoders in the stack mangle this one, a
    // correctly rounded parse does not.
    const FRACTIONAL: f64 = 1_790_000_000.000_002_1;
    assert_eq!(FRACTIONAL.to_bits(), 4_745_294_612_153_761_801);

    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let dir = tempfile::tempdir().unwrap();
    let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
    db.init_db().unwrap();

    // (i) close — the byte-identical 0.7.29 production writer.

    let close_name = format!("hcom_close_{}_oldwriter", std::process::id());
    assert!(
        crate::instance_binding::initialize_instance_in_position_file(
            &db,
            &close_name,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
        )
    );
    let close_row = db
        .get_instance_full(&close_name)
        .unwrap()
        .expect("0.7.29 writer stored the row");
    assert_ne!(
        close_row.created_at.fract(),
        0.0,
        "0.7.29 wrote a fractional created_at"
    );
    let closed = crate::hooks::common::stop_instance(&db, &close_name, "test", "test-close");
    assert!(
        db.get_instance_full(&close_name).unwrap().is_none(),
        "close left a ghost row for {close_name}: {closed:?}"
    );
    assert_eq!(closed, crate::hooks::common::StopOutcome::Stopped);

    // (ii) kill — the same writer, pinned to a ULP-critical value.
    let kill_name = format!("hcom-kill-{}-oldwriter", std::process::id());
    legacy_row(&db, &kill_name, FRACTIONAL);
    db.update_instance_pid(&kill_name, dead_pid()).unwrap();
    db.set_process_binding("proc-oldwriter", &format!("sess-{kill_name}"), &kill_name)
        .unwrap();
    let killed = kill_tracked_instance_with_self_pids(
        &db,
        &kill_name,
        "test",
        &[std::process::id()],
        |_, _, _| Ok(()),
    )
    .unwrap_or_else(|e| panic!("a release through kill is not a kill failure: {e}"));
    assert_eq!(killed.teardown, TeardownOutcome::Completed);
    assert!(
        db.get_instance_full(&kill_name).unwrap().is_none(),
        "kill left a ghost row for {kill_name}"
    );

    // (iii) sweep — the same deterministic write, released by the daemon.
    let sweep_name = format!("hcom-sweep-{}-oldwriter", std::process::id());
    legacy_row(&db, &sweep_name, FRACTIONAL);
    // Positive death evidence: the `omp-<pid>` binding the sweep reads
    // (off Linux it skips inactive rows, hence the active status).
    let evidence_pid = dead_pid();
    db.set_process_binding(
        &format!("omp-{evidence_pid}"),
        &format!("sess-{sweep_name}"),
        &sweep_name,
    )
    .unwrap();
    let swept = crate::proctruth::sweep_vanished_instances(&db);
    assert!(
        swept.contains(&sweep_name),
        "sweep held the vanished row: {swept:?}"
    );
    assert!(
        db.get_instance_full(&sweep_name).unwrap().is_none(),
        "sweep left a ghost row for {sweep_name}"
    );
    let _ = _guard;
}

/// The 0.7.29 row writer: the same `serde_json::Map` shape
/// `initialize_instance_in_position_file` builds (see the
/// `data.insert("created_at", json!(now))` there), with `created_at`
/// pinned to `now` so the release CAS runs against a fixed,
/// ULP-critical value instead of whatever the clock produced. `pid` and
/// the bindings are attached afterwards by the release path's caller —
/// 0.7.29's `start` filled those in separately too.
#[cfg(unix)]
fn legacy_row(db: &HcomDb, name: &str, now: f64) {
    let mut data = serde_json::Map::new();
    data.insert("name".into(), serde_json::json!(name));
    data.insert("last_event_id".into(), serde_json::json!(0));
    data.insert("directory".into(), serde_json::json!(""));
    data.insert("last_stop".into(), serde_json::json!(0));
    data.insert("created_at".into(), serde_json::json!(now));
    data.insert(
        "session_id".into(),
        serde_json::json!(format!("sess-{name}")),
    );
    data.insert("transcript_path".into(), serde_json::json!(""));
    data.insert("name_announced".into(), serde_json::json!(0));
    data.insert("tag".into(), serde_json::Value::Null);
    data.insert("status".into(), serde_json::json!("active"));
    data.insert(
        "status_time".into(),
        serde_json::json!(crate::shared::time::now_epoch_i64()),
    );
    data.insert("status_context".into(), serde_json::json!("new"));
    data.insert("tool".into(), serde_json::json!("codex"));
    data.insert("background".into(), serde_json::json!(0));
    data.insert("wait_timeout".into(), serde_json::json!(86400));
    assert!(db.save_instance_named(name, &data).unwrap());
}

#[cfg(unix)]
fn dead_pid() -> u32 {
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    pid
}

/// A bindingless self-stop is recognized on the EXACT `created_at` bit
/// pattern, not on a float round trip. Measured on this build,
/// `json_extract` decodes 1762720048.770769 exactly (...223), so the
/// f64 compare happens to agree here; serde_json's own f64 parser does
/// not (it mangles ~1 value in 8, e.g. 1790000000.0000021 -> ...800).
/// The integer bit pattern removes the decoder from the comparison
/// entirely, and this pins that contract on the bindingless branch: a
/// null-`process_id` stop is a self-stop only on the exact bits.
#[test]
#[cfg(unix)]
#[serial]
fn classify_lost_teardown_matches_bindingless_stops_on_exact_created_at_bits() {
    const CREATED_AT: f64 = 1_762_720_048.770_769;
    assert_eq!(CREATED_AT.to_bits(), 4_745_180_191_745_201_223);

    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let dir = tempfile::tempdir().unwrap();
    let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
    db.init_db().unwrap();
    let name = format!("hcom-kill-{}-bits", std::process::id());

    // The session's own stopped record, written through the production
    // snapshot shape: the fractional created_at beside its exact bit
    // pattern, and no process named (bindingless).
    db.log_life_event(
        &name,
        "stopped",
        "session",
        "exit:normal",
        Some(serde_json::json!({
            "name": name,
            "created_at": CREATED_AT,
            "created_at_bits": CREATED_AT.to_bits(),
        })),
        None,
    )
    .unwrap();

    let incarnation = ResolvedIncarnation {
        token: IncarnationToken::new(CREATED_AT, None, None, vec![]),
        event_watermark: 0,
    };
    let outcome = db
        .with_immediate_transaction(|tx| classify_lost_teardown(tx, &name, &incarnation, None))
        .unwrap();
    assert_eq!(outcome, TeardownOutcome::SessionStoppedReleasedRow);
    let _ = _guard;
}

/// The mixed-version window: install does not stop a 0.7.29 process — an
/// old relay worker or hook — from writing to the upgraded log, so a
/// stopped event can carry `created_at` with NO `created_at_bits`. The
/// 0.7.30 teardown classification must still match that row as a
/// self-stop on the legacy `created_at` identity: a missing bits field is
/// never a mismatch. `created_at_bits` stays authoritative whenever it is
/// present, so a row whose bits name another incarnation never falls back
/// to `created_at`.
#[test]
#[cfg(unix)]
#[serial]
fn classify_lost_teardown_matches_a_pre_v20_event_without_bits() {
    // ULP-critical: serde_json's own f64 parser mangles this one
    // (...801 -> ...800), a correctly rounded parse does not. The 0.7.29
    // writer serialized the value through serde.
    const CREATED_AT: f64 = 1_790_000_000.000_002_1;
    assert_eq!(CREATED_AT.to_bits(), 4_745_294_612_153_761_801);

    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let dir = tempfile::tempdir().unwrap();
    let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
    db.init_db().unwrap();

    // The stopped record exactly as 0.7.29 wrote it: `created_at` in the
    // snapshot, no `created_at_bits`.
    let name = format!("hcom-kill-{}-pre-v20", std::process::id());
    db.log_life_event(
        &name,
        "stopped",
        "session",
        "exit:normal",
        Some(serde_json::json!({ "name": name, "created_at": CREATED_AT })),
        None,
    )
    .unwrap();

    let classify = |against: f64, event_name: &str| {
        let incarnation = ResolvedIncarnation {
            token: IncarnationToken::new(against, None, None, vec![]),
            event_watermark: 0,
        };
        db.with_immediate_transaction(|tx| {
            classify_lost_teardown(tx, event_name, &incarnation, None)
        })
        .unwrap()
    };

    // Positive: the pre-v20 row is a self-stop on created_at alone.
    assert_eq!(
        classify(CREATED_AT, &name),
        TeardownOutcome::SessionStoppedReleasedRow
    );
    // Negative: another incarnation's created_at never matches it.
    assert_eq!(
        classify(CREATED_AT + 1000.0, &name),
        TeardownOutcome::RowReRegistered
    );

    // Grey: bits are authoritative — a row carrying a different
    // created_at_bits never falls back to created_at.
    let bits_name = format!("hcom-kill-{}-pre-v20-bits", std::process::id());
    db.log_life_event(
        &bits_name,
        "stopped",
        "session",
        "exit:normal",
        Some(serde_json::json!({
            "name": bits_name,
            "created_at": CREATED_AT,
            "created_at_bits": (CREATED_AT + 1000.0).to_bits(),
        })),
        None,
    )
    .unwrap();
    assert_eq!(
        classify(CREATED_AT, &bits_name),
        TeardownOutcome::RowReRegistered
    );
    let _ = _guard;
}

// The legacy `created_at` fallback serves two sites: the kill's
// lost-teardown classification (a `stopped` snapshot as SQLite renders
// it) and the session finalizers' claim check (the raw kv claim). A token
// neither can read names no incarnation and is never taken for one: the
// classification logs it and keeps the conservative report, and a live
// kill's claim holds the row untouched.
#[cfg(unix)]
const LEGACY_CREATED_AT: f64 = 1_790_000_000.000_002_1;

#[cfg(unix)]
fn legacy_db() -> (tempfile::TempDir, HcomDb) {
    let dir = tempfile::tempdir().unwrap();
    let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
    db.init_db().unwrap();
    (dir, db)
}

#[cfg(unix)]
fn logged(event: &str, needle: &str) -> bool {
    std::fs::read_to_string(crate::paths::log_path())
        .unwrap_or_default()
        .lines()
        .any(|line| line.contains(event) && line.contains(needle))
}

/// Classify a lost teardown (row gone) against one bindingless `stopped`
/// event with raw `data`; returns the outcome and the event id.
#[cfg(unix)]
fn classify_legacy_stop_event(db: &HcomDb, name: &str, data: &str) -> (TeardownOutcome, i64) {
    db.conn()
        .execute(
            "INSERT INTO events (timestamp, type, instance, data) \
                 VALUES ('2026-09-24T00:00:00Z', 'life', ?1, ?2)",
            rusqlite::params![name, data],
        )
        .unwrap();
    let event_id = db.conn().last_insert_rowid();
    let incarnation = ResolvedIncarnation {
        token: IncarnationToken::new(LEGACY_CREATED_AT, None, None, vec![]),
        event_watermark: 0,
    };
    let outcome = db
        .with_immediate_transaction(|tx| classify_lost_teardown(tx, name, &incarnation, None))
        .unwrap();
    (outcome, event_id)
}

#[cfg(unix)]
fn assert_stop_event_not_matched(db: &HcomDb, name: &str, data: &str, reason: &str) {
    let (outcome, event_id) = classify_legacy_stop_event(db, name, data);
    assert_eq!(outcome, TeardownOutcome::RowReRegistered, "{data}");
    assert!(
        logged(
            "teardown.stop_event_unreadable",
            &format!("instance={name} event={event_id} reason={reason}")
        ),
        "the unreadable event is logged: {data}"
    );
}

/// A live kill's claim on `name` (session `sess-legacy`) with no bits
/// and `created_at_member` spliced in raw. Both session finalizers must
/// hold the row for the kill: no exit writes, no binding release, no
/// stopped event, and the hold logged.
#[cfg(unix)]
fn assert_live_claim_holds_the_row(db: &HcomDb, name: &str, created_at_member: &str) {
    db.conn()
        .execute(
            "INSERT INTO instances (name, status, created_at, tool, session_id) \
                 VALUES (?1, 'active', ?2, 'codex', 'sess-legacy')",
            rusqlite::params![name, LEGACY_CREATED_AT],
        )
        .unwrap();
    db.set_process_binding("proc-legacy", "sess-legacy", name)
        .unwrap();
    let pid = std::process::id();
    let start = crate::sys::process::identity(pid).expect("own process identity");
    let claim = format!(
        r#"{{"pid":{pid},"process_start":{},"session_id":"sess-legacy"{created_at_member}}}"#,
        serde_json::Value::String(start)
    );
    db.kv_set(&format!("teardown_claim:{name}"), Some(&claim))
        .unwrap();

    crate::hooks::common::soft_finalize_session(db, name, "shutdown", None, false);
    assert_eq!(
        crate::hooks::common::finalize_session(db, name, "shutdown", None),
        StopOutcome::AlreadyStopped,
        "{claim}"
    );
    let row = db
        .get_instance_full(name)
        .unwrap()
        .expect("row held for the live kill");
    assert_eq!(row.status, "active", "no exit writes: {claim}");
    assert_eq!(
        db.process_binding_ids(name).unwrap(),
        vec!["proc-legacy".to_string()],
        "bindings left to the kill: {claim}"
    );
    assert_eq!(
        stopped_events(db, name),
        0,
        "the stopped event is the kill's"
    );
    assert!(
        logged(
            "sessionend.teardown_claim_held",
            &format!("instance={name} reason=unreadable-created_at")
        ),
        "the hold is logged: {claim}"
    );
}

#[test]
#[cfg(unix)]
#[serial]
fn legacy_created_at_absent_is_never_matched_and_holds_the_row() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let (_dir, db) = legacy_db();
    let name = format!("hcom-kill-{}-legacy-absent", std::process::id());
    assert_stop_event_not_matched(
        &db,
        &format!("{name}-event"),
        r#"{"action":"stopped","by":"session","reason":"exit:normal","process_id":null,"snapshot":{"name":"x"}}"#,
        "unreadable-created_at",
    );
    assert_live_claim_holds_the_row(&db, &format!("{name}-claim"), "");
}

#[test]
#[cfg(unix)]
#[serial]
fn legacy_created_at_null_is_never_matched_and_holds_the_row() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let (_dir, db) = legacy_db();
    let name = format!("hcom-kill-{}-legacy-null", std::process::id());
    assert_stop_event_not_matched(
        &db,
        &format!("{name}-event"),
        r#"{"action":"stopped","by":"session","reason":"exit:normal","process_id":null,"snapshot":{"created_at":null}}"#,
        "unreadable-created_at",
    );
    assert_live_claim_holds_the_row(&db, &format!("{name}-claim"), r#","created_at":null"#);
}

#[test]
#[cfg(unix)]
#[serial]
fn legacy_created_at_non_numeric_string_is_never_matched_and_holds_the_row() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let (_dir, db) = legacy_db();
    let name = format!("hcom-kill-{}-legacy-iso", std::process::id());
    assert_stop_event_not_matched(
        &db,
        &format!("{name}-event"),
        r#"{"action":"stopped","by":"session","reason":"exit:normal","process_id":null,"snapshot":{"created_at":"2026-09-24T10:00:00Z"}}"#,
        "unreadable-created_at",
    );
    assert_live_claim_holds_the_row(
        &db,
        &format!("{name}-claim"),
        r#","created_at":"2026-09-24T10:00:00Z""#,
    );
}

#[test]
#[cfg(unix)]
#[serial]
fn legacy_created_at_non_scalar_is_never_matched_and_holds_the_row() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let (_dir, db) = legacy_db();
    let name = format!("hcom-kill-{}-legacy-bool", std::process::id());
    assert_stop_event_not_matched(
        &db,
        &format!("{name}-event"),
        r#"{"action":"stopped","by":"session","reason":"exit:normal","process_id":null,"snapshot":{"created_at":true}}"#,
        "unreadable-created_at",
    );
    assert_live_claim_holds_the_row(&db, &format!("{name}-claim"), r#","created_at":true"#);
}

/// No snapshot at all: what a 0.7.29 PTY exit writes when its snapshot
/// read fails (and it deletes the row anyway). Classification only; a
/// claim has no snapshot to lose.
#[test]
#[cfg(unix)]
#[serial]
fn stop_event_without_a_snapshot_is_never_matched() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let (_dir, db) = legacy_db();
    let name = format!("hcom-kill-{}-legacy-nosnap", std::process::id());
    assert_stop_event_not_matched(
        &db,
        &name,
        r#"{"action":"stopped","by":"pty","reason":"closed","process_id":null}"#,
        "no-snapshot",
    );
}

/// A quoted number padded before its delimiter: only a raw claim can
/// carry it, and the raw scan cannot read it, so the claim holds the
/// row. SQLite renders the same snapshot token compactly, so the
/// classification reads it exactly and matches the session's stop.
#[test]
#[cfg(unix)]
#[serial]
fn padded_legacy_claim_created_at_holds_the_row() {
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let (_dir, db) = legacy_db();
    let name = format!("hcom-kill-{}-legacy-padded", std::process::id());
    assert_live_claim_holds_the_row(
        &db,
        &format!("{name}-claim"),
        r#","created_at": "1790000000.0000021" "#,
    );
    let (outcome, _) = classify_legacy_stop_event(
        &db,
        &format!("{name}-event"),
        r#"{"action":"stopped","by":"session","reason":"exit:normal","process_id":null,"snapshot":{"created_at": "1790000000.0000021" }}"#,
    );
    assert_eq!(outcome, TeardownOutcome::SessionStoppedReleasedRow);
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
    let result =
        kill_tracked_instance_with_self_pids(&db, &name, "test", &self_set, move |_n, _b, _e| {
            // Trigger the concurrent rebind from inside the termination seam
            // and wait until it HOLDS the write lock: it now owns the
            // write path until well past where the old comparison ran.
            locked_rx.recv().unwrap();
            Ok(())
        })
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

/// `hcom kill` on the henu shape (no pid, no live root, one orphan)
/// cannot signal anything, so it names the orphan and points at the
/// stop that releases the row. The row stays; the orphan is untouched.
#[test]
#[cfg(target_os = "linux")]
#[serial]
fn kill_names_the_orphans_of_a_root_less_row_and_points_at_stop() {
    use crate::proctruth::orphan_fixtures;
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let dir = tempfile::tempdir().unwrap();
    let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
    db.init_db().unwrap();
    let name = orphan_fixtures::unique("kill-henu");
    let session = format!("{name}-session");
    orphan_fixtures::seed_seat_row(&db, &name, &session, dir.path());
    let orphan = orphan_fixtures::spawn_orphan(&name);

    let err = kill_single(&db, dir.path(), &name, "test")
        .expect_err("a pid-less row cannot be killed")
        .to_string();
    assert_eq!(
        err,
        format!(
            "No tracked PID for '{name}', and no live process roots it: 1 orphaned process(es) carry only its identity ({}). Run 'hcom stop {name}' to release it; the orphans will not be signalled.",
            orphan.carrier
        )
    );
    assert!(db.get_instance_full(&name).unwrap().is_some());
    assert!(orphan.alive(orphan.carrier), "kill signalled the orphan");
}

/// A pid-less row with a live root (the valo shape: an `omp` holding its
/// session transcript, with a carrier child) keeps the old hint.
#[test]
#[cfg(target_os = "linux")]
#[serial]
fn kill_keeps_the_stop_hint_for_a_pid_less_row_with_a_live_root() {
    use crate::proctruth::orphan_fixtures;
    let _guard = crate::hooks::test_helpers::isolated_test_env();
    let dir = tempfile::tempdir().unwrap();
    let db = crate::db::HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
    db.init_db().unwrap();
    let name = orphan_fixtures::unique("kill-valo");
    let session = format!("{name}-session");
    orphan_fixtures::seed_seat_row(&db, &name, &session, dir.path());
    let seat = orphan_fixtures::spawn_session_seat(dir.path(), &session, &name, "omp");

    let err = kill_single(&db, dir.path(), &name, "test")
        .expect_err("a pid-less row cannot be killed")
        .to_string();
    assert_eq!(
        err,
        format!("No tracked PID for '{name}' — use 'hcom stop {name}' instead")
    );
    assert!(db.get_instance_full(&name).unwrap().is_some());
    assert!(seat.alive(seat.holder) && seat.alive(seat.carrier));
}

// ── fleet-wide bare-name resolution ─────────────────────────────────

const FLEET_DEV: &str = "11111111-1111-4111-8111-111111111111";
const FLEET_DEV_B: &str = "22222222-2222-4222-8222-222222222222";

/// The `x:DEV` form a device's rows carry, from the canonical short-id
/// derivation.
fn remote_form(base: &str, device_uuid: &str) -> String {
    format!("{base}:{}", crate::relay::device_short_id(device_uuid))
}

fn fleet_db() -> (tempfile::TempDir, HcomDb) {
    let dir = tempfile::tempdir().unwrap();
    let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
    db.init_db().unwrap();
    (dir, db)
}

fn insert_mirror(db: &HcomDb, name: &str, device_uuid: &str) {
    let now = chrono::Utc::now().timestamp_millis() as f64;
    db.conn()
        .execute(
            "INSERT INTO instances (name, status, status_context, status_time,
                                        created_at, tool, origin_device_id)
                 VALUES (?1, 'listening', 'ready', ?2, ?2, 'omp', ?3)",
            rusqlite::params![name, now, device_uuid],
        )
        .unwrap();
}

/// A live LOCAL row in the given status/context (no origin device).
fn insert_local(db: &HcomDb, name: &str, status: &str, context: &str) {
    let now = chrono::Utc::now().timestamp_millis() as f64;
    db.conn()
        .execute(
            "INSERT INTO instances (name, status, status_context, status_time,
                                        created_at, tool)
                 VALUES (?1, ?2, ?3, ?4, ?4, 'omp')",
            rusqlite::params![name, status, context, now],
        )
        .unwrap();
}

/// A live local row is a fleet candidate, not a short-circuit: with a
/// live mirror of the same base name the kill refuses, naming both
/// forms, exactly as `hcom send @luna` does in the same database.
#[test]
#[serial_test::serial]
fn a_live_local_name_and_a_live_mirror_are_refused_with_both_forms() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let (dir, db) = fleet_db();
    insert_local(&db, "luna", "listening", "ready");
    insert_mirror(&db, &remote_form("luna", FLEET_DEV), FLEET_DEV);
    let err = kill_single(&db, dir.path(), "luna", "tester").expect_err("refused");
    let err = err.to_string();
    assert!(err.contains("@luna,"), "{err}");
    assert!(err.contains(&remote_form("luna", FLEET_DEV)), "{err}");
}

/// A stopped local row is never a candidate, so the name belongs to the
/// one device it is still live on.
#[test]
#[serial_test::serial]
fn a_stopped_local_name_with_a_live_remote_takes_the_kill_rpc_path() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let (dir, db) = fleet_db();
    insert_local(&db, "luna", "stopped", "exit");
    insert_mirror(&db, &remote_form("luna", FLEET_DEV), FLEET_DEV);
    let err = kill_single(&db, dir.path(), "luna", "tester").expect_err("remote kill");
    let err = err.to_string();
    assert!(err.contains("relay worker not running"), "{err}");
    assert!(!err.contains("not found"), "{err}");
}

/// A bare name whose only live candidate is another device's row reaches
/// the KILL RPC, not the local not-found error. With no relay configured
/// the dispatch is the deterministic proof: the worker gate refuses it.
#[test]
#[serial_test::serial]
fn a_bare_name_live_on_one_remote_device_takes_the_kill_rpc_path() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let (dir, db) = fleet_db();
    insert_mirror(&db, &remote_form("luna", FLEET_DEV), FLEET_DEV);
    let err = kill_single(&db, dir.path(), "luna", "tester").expect_err("remote kill");
    let err = err.to_string();
    assert!(err.contains("relay worker not running"), "{err}");
    assert!(!err.contains("not found"), "{err}");
}

#[test]
#[serial_test::serial]
fn a_bare_name_live_on_two_remote_devices_is_refused_with_both_forms() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let (dir, db) = fleet_db();
    insert_mirror(&db, &remote_form("luna", FLEET_DEV), FLEET_DEV);
    insert_mirror(&db, &remote_form("luna", FLEET_DEV_B), FLEET_DEV_B);
    let err = kill_single(&db, dir.path(), "luna", "tester").expect_err("refused");
    let err = err.to_string();
    assert!(err.contains(&remote_form("luna", FLEET_DEV)), "{err}");
    assert!(err.contains(&remote_form("luna", FLEET_DEV_B)), "{err}");
}

/// A name live nowhere keeps today's not-found error verbatim.
#[test]
#[serial_test::serial]
fn a_bare_name_live_nowhere_is_still_not_found() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let (dir, db) = fleet_db();
    let err = kill_single(&db, dir.path(), "luna", "tester").expect_err("not found");
    assert_eq!(err.to_string(), "Agent 'luna' not found");
}
