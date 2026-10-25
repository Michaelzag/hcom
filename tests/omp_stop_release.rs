//! `hcom omp-stop` without `--soft` releases the omp owner's row from within
//! its session tree. Its ancestor is spared, and a sibling outside both the
//! recorded and caller-rooted trees is not signalled even if it carries the
//! same binding. Linux only: off Linux this release soft-stops the row.

#![cfg(target_os = "linux")]

mod support;

use std::fs;
use std::os::unix::fs as unix_fs;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};
use support::{Hcom, unique_suffix};

fn wait_with_deadline(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll child") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// SIGKILL the whole group `child` leads (spawned with `process_group(0)`),
/// then reap it. Called only while the leader is unreaped, so its pgid cannot
/// have been recycled.
fn kill_group(child: &mut Child) {
    unsafe {
        libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
    }
    let _ = child.wait();
}

#[test]
fn omp_stop_release_spares_caller_tree_and_out_of_scope_sibling() {
    let h = Hcom::new();
    fs::write(h.path().join("config.toml"), "[relay]\nenabled = false\n")
        .expect("disable fixture relay");
    // Creates the schema in the isolated HCOM_DIR.
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");

    let suffix = unique_suffix();
    let name = format!("rocstop{suffix}");
    let process_id = uuid::Uuid::new_v4().to_string();
    let fakebin = h.root_path().join("fakebin");
    fs::create_dir_all(&fakebin).expect("create fakebin");
    let omp = fakebin.join("omp");
    unix_fs::symlink("/bin/bash", &omp).expect("symlink omp stand-in");
    let go = h.root_path().join("go-stop");

    // A real kernel PID recognized as OMP, not the actual application. It
    // waits until its UUID, row PID and bindings are durably seeded.
    let mut session = h
        .external_cmd(&omp)
        .arg("-c")
        .arg("while [ ! -e \"$GO\" ]; do sleep 0.05; done; \"$BIN\" omp-stop --name \"$NAME\" --reason shutdown; exit $?")
        .env("GO", &go)
        .env("BIN", env!("CARGO_BIN_EXE_hcom"))
        .env("NAME", &name)
        .env("HCOM_PROCESS_ID", &process_id)
        .env("HCOM_LAUNCHED", "1")
        .env("HCOM_TOOL", "omp")
        .process_group(0)
        .spawn()
        .expect("spawn recognized OMP session");
    h.track_cleanup_pid(session.id() as i64);
    let db = rusqlite::Connection::open(h.path().join("hcom.db")).expect("open db");
    db.execute(
        "INSERT INTO instances (name, tool, session_id, status, status_context, status_time, created_at, last_event_id, pid)
         VALUES (?1, 'omp', ?2, 'listening', 'start', 0, 0, 0, ?3)",
        rusqlite::params![name, format!("sid-{suffix}"), session.id()],
    )
    .expect("seed instance");
    db.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![process_id, format!("sid-{suffix}"), name],
    )
    .expect("seed process binding");
    db.execute(
        "INSERT INTO session_bindings (session_id, instance_name, created_at) VALUES (?1, ?2, 0)",
        rusqlite::params![format!("sid-{suffix}"), name],
    )
    .expect("seed session binding");

    // A leaked desktop-shaped carrier: it has the binding but is a sibling
    // of the session shell, not a descendant of either owning root.
    let mut sibling = h
        .external_cmd("sleep")
        .arg("300")
        .env("HCOM_PROCESS_ID", &process_id)
        .process_group(0)
        .spawn()
        .expect("spawn sibling carrier");

    h.track_cleanup_pid(sibling.id() as i64);
    fs::write(&go, "").expect("trigger stop after fixture seed");

    let session_status = wait_with_deadline(&mut session, Duration::from_secs(30));
    if session_status.is_none() {
        kill_group(&mut session);
    }
    let sibling_status = sibling.try_wait().expect("poll out-of-scope sibling");
    if sibling_status.is_none() {
        kill_group(&mut sibling);
    }

    let session_status = session_status.expect("omp-stop session shell did not exit");
    assert_eq!(
        session_status.signal(),
        None,
        "the caller's own tree was signalled: {session_status:?}"
    );
    assert_eq!(session_status.code(), Some(0), "{session_status:?}");

    let rows: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM instances WHERE name = ?1",
            [&name],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "row not released");
    let stopped: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = ?1
               AND json_extract(data, '$.action') = 'stopped'",
            [&name],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stopped, 1, "no stopped event");
    assert!(
        sibling_status.is_none(),
        "out-of-scope sibling was signalled: {sibling_status:?}"
    );
}
