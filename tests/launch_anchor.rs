//! Launch anchors, end to end against the real binary.
//!
//! The trust gate accepts a launcher process id only when its row records a
//! pid that is an ancestor of the hook presenting it. Every launch shape that
//! pre-registers a launcher id must record that anchor before the tool can
//! fire its first hook: run-here records the launcher's own pid before it
//! execs the script; new-window and background scripts run the internal
//! `hcom launch-anchor`, which records its parent (the script).
//!
//! The launched tool is a fake `claude` that fires the real `sessionstart`
//! hook with the inherited launch env and exits. No real tool runs.
//!
//! Linux only: the gate's ancestry proof reads /proc.

#![cfg(target_os = "linux")]

mod support;

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use support::{Hcom, unique_suffix};

fn open_db(h: &Hcom) -> rusqlite::Connection {
    rusqlite::Connection::open(h.path().join("hcom.db")).expect("open isolated hcom.db")
}

fn init(h: &Hcom) {
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");
}

/// A fake `claude` that pipes a SessionStart payload to the real hook and
/// records `<sid> <own pid> <parent pid> <hook exit>` in `reports/<pid>`.
fn install_fake_claude(h: &Hcom) -> (PathBuf, PathBuf) {
    let fakebin = h.root_path().join("fakebin");
    let reports = h.root_path().join("reports");
    fs::create_dir_all(&fakebin).expect("create fakebin");
    fs::create_dir_all(&reports).expect("create reports dir");
    let bin = env!("CARGO_BIN_EXE_hcom");
    let script = format!(
        r#"#!/bin/bash
sid="sid-anchor-$$"
printf '{{"session_id":"%s","cwd":"%s","hook_event_name":"SessionStart","source":"startup"}}' "$sid" "$PWD" \
  | '{bin}' sessionstart > /dev/null 2>&1
echo "$sid $$ $PPID $?" > '{reports}/'"$$"
"#,
        reports = reports.display()
    );
    let claude = fakebin.join("claude");
    fs::write(&claude, script).expect("write fake claude");
    fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).expect("chmod fake claude");
    (fakebin, reports)
}

/// `h.cmd()` with the fake tool dir first on PATH.
fn launch_cmd(h: &Hcom, fakebin: &Path) -> Command {
    let mut cmd = h.cmd();
    let inherited: OsString = cmd
        .get_envs()
        .find(|(key, _)| *key == "PATH")
        .and_then(|(_, value)| value.map(|v| v.to_os_string()))
        .unwrap_or_default();
    let mut entries = vec![fakebin.to_path_buf()];
    entries.extend(std::env::split_paths(&inherited));
    cmd.env("PATH", std::env::join_paths(entries).expect("join PATH"));
    cmd.stdin(Stdio::null());
    cmd
}

struct Report {
    sid: String,
    pid: u32,
    ppid: u32,
}

fn wait_for_reports(h: &Hcom, reports: &Path, expected: usize) -> Vec<Report> {
    h.eventually("fake claude reports", Duration::from_secs(30), || {
        let entries: Vec<_> = fs::read_dir(reports)
            .map(|dir| dir.flatten().collect())
            .unwrap_or_default();
        Ok((entries.len() >= expected).then_some(()))
    });
    fs::read_dir(reports)
        .expect("read reports")
        .flatten()
        .map(|entry| {
            let line = fs::read_to_string(entry.path()).expect("read report");
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 4, "malformed report: {line:?}");
            assert_eq!(fields[3], "0", "sessionstart hook failed: {line:?}");
            Report {
                sid: fields[0].to_string(),
                pid: fields[1].parse().expect("report pid"),
                ppid: fields[2].parse().expect("report ppid"),
            }
        })
        .collect()
}

/// The instance the launcher pre-registered for `sid`'s tool, and its
/// recorded anchor pid, read through the session binding the hook created.
fn bound_instance(h: &Hcom, sid: &str) -> Option<(String, Option<i64>)> {
    open_db(h)
        .query_row(
            "SELECT i.name, i.pid FROM session_bindings s JOIN instances i ON i.name = s.instance_name
             WHERE s.session_id = ?1",
            [sid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()
}

#[test]
fn new_window_launch_anchors_its_script_and_binds_first_hook() {
    // count > 1 is always new-window. The custom terminal command runs the
    // generated script detached, the way a real terminal window would.
    let h = Hcom::new();
    init(&h);
    let (fakebin, reports) = install_fake_claude(&h);
    let out = launch_cmd(&h, &fakebin)
        .args([
            "2",
            "claude",
            "-p",
            "hi",
            "--terminal",
            "bash {script}",
            "--go",
        ])
        .output()
        .expect("run hcom launch");
    assert_eq!(
        out.status.code(),
        Some(0),
        "launch failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reports = wait_for_reports(&h, &reports, 2);
    for report in &reports {
        let bound = bound_instance(&h, &report.sid);
        assert!(
            bound.is_some(),
            "first hook of tool pid {} did not bind its launched row",
            report.pid
        );
        let (name, anchor) = bound.unwrap();
        assert_eq!(
            anchor,
            Some(report.ppid as i64),
            "{name}'s anchor is not the launch script that started its tool"
        );
    }
}

#[test]
fn run_here_claude_print_launch_binds_first_hook() {
    // Run-here replaces the launcher with its script, so the launcher's pid
    // is the tool's parent and must already be on the row at exec.
    let h = Hcom::new();
    init(&h);
    let (fakebin, reports) = install_fake_claude(&h);
    let out = launch_cmd(&h, &fakebin)
        .args(["claude", "-p", "hi", "--run-here", "--go"])
        .output()
        .expect("run hcom launch");
    assert_eq!(
        out.status.code(),
        Some(0),
        "run-here launch failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reports = wait_for_reports(&h, &reports, 1);
    let report = &reports[0];
    let bound = bound_instance(&h, &report.sid);
    assert!(
        bound.is_some(),
        "first hook of run-here tool pid {} did not bind its launched row",
        report.pid
    );
    assert_eq!(bound.unwrap().1, Some(report.ppid as i64));
}

const LAUNCHER_ID: &str = "4f1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f";

fn seed_launch_row(h: &Hcom, name: &str, process_id: &str, pid: Option<i64>) {
    let db = open_db(h);
    db.execute(
        "INSERT INTO instances (name, tool, status, status_context, status_time, created_at, last_event_id, pid)
         VALUES (?1, 'claude', 'pending', 'launch', 0, 0, 0, ?2)",
        rusqlite::params![name, pid],
    )
    .expect("seed instance");
    db.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, NULL, ?2, 0)",
        rusqlite::params![process_id, name],
    )
    .expect("seed process binding");
}

fn row_pid(h: &Hcom, name: &str) -> Option<i64> {
    open_db(h)
        .query_row("SELECT pid FROM instances WHERE name = ?1", [name], |r| {
            r.get(0)
        })
        .expect("row exists")
}

fn run_anchor(h: &Hcom, process_id: &str, args: &[&str]) -> i32 {
    let out = h
        .cmd()
        .env("HCOM_PROCESS_ID", process_id)
        .arg("launch-anchor")
        .args(args)
        .output()
        .expect("run launch-anchor");
    out.status.code().unwrap_or(-1)
}

#[test]
fn launch_anchor_records_only_its_parent_on_its_own_unanchored_row() {
    let h = Hcom::new();
    init(&h);
    let suffix = unique_suffix();

    // Positive: matching launcher id, no anchor yet -> its parent (this test
    // process) becomes the anchor.
    let fresh = format!("fresh{suffix}");
    seed_launch_row(&h, &fresh, LAUNCHER_ID, None);

    // Any argument is refused: there is no way to name a pid.
    assert_ne!(run_anchor(&h, LAUNCHER_ID, &["12345"]), 0);
    assert_eq!(row_pid(&h, &fresh), None, "an argument changed the row");

    // An id that matches no binding changes nothing.
    let stranger = "0b1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f";
    assert_ne!(run_anchor(&h, stranger, &[]), 0);
    assert_eq!(row_pid(&h, &fresh), None, "an unbound id changed the row");

    // A bound id that is not launcher-shaped is refused.
    let synthetic = format!("omp-1-{suffix}-1");
    let other = format!("other{suffix}");
    seed_launch_row(&h, &other, &synthetic, None);
    assert_ne!(run_anchor(&h, &synthetic, &[]), 0);
    assert_eq!(row_pid(&h, &other), None, "a non-launcher id anchored");

    assert_eq!(run_anchor(&h, LAUNCHER_ID, &[]), 0);
    assert_eq!(row_pid(&h, &fresh), Some(std::process::id() as i64));

    // An anchor already set is never replaced. The preset pid is provably
    // not a live process.
    let dead_pid = (100_000i64..110_000)
        .find(|pid| !Path::new(&format!("/proc/{pid}")).exists())
        .expect("find an unused pid");
    let anchored = format!("anchored{suffix}");
    let anchored_id = "1b1c2d3e-5a6b-4c7d-8e9f-0a1b2c3d4e5f";
    seed_launch_row(&h, &anchored, anchored_id, Some(dead_pid));
    assert_ne!(run_anchor(&h, anchored_id, &[]), 0);
    assert_eq!(
        row_pid(&h, &anchored),
        Some(dead_pid),
        "an existing anchor was replaced"
    );

    // These rows record pids this fixture never spawned (the test runner
    // itself among them); fixture teardown signals every recorded pid's
    // group, so they must not outlive the test.
    let db = open_db(&h);
    db.execute("DELETE FROM process_bindings", [])
        .expect("clear bindings");
    db.execute("DELETE FROM instances", [])
        .expect("clear instances");
}
