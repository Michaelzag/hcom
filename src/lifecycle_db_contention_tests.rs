//! SQLite contention at the kill/resume/launch boundary. Every command uses
//! an isolated HCOM_DIR; all locks come from a separate SQLite connection.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serial_test::serial;

use crate::commands::kill::{TeardownOutcome, kill_tracked_instance};
use crate::commands::resume::run_local_resume_result;
use crate::db::HcomDb;
use crate::router::GlobalFlags;

struct Writer {
    release: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Writer {
    fn hold(db: &HcomDb, duration: Option<Duration>, change: &str) -> Self {
        let path = db.path().to_path_buf();
        let change = change.to_string();
        let (held_tx, held_rx) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let conn = Connection::open(path).unwrap();
            conn.execute_batch("PRAGMA busy_timeout=0; BEGIN IMMEDIATE;")
                .unwrap();
            conn.execute_batch(&change).unwrap();
            held_tx.send(()).unwrap();
            let _ = released.recv_timeout(duration.unwrap_or(Duration::from_secs(10)));
            conn.execute_batch("COMMIT").unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            release,
            thread: Some(thread),
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
            && !std::thread::panicking()
        {
            panic!("concurrent writer failed");
        }
    }
}

fn seed_dead_row(db: &HcomDb) -> u32 {
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    db.conn().execute(
        "INSERT INTO instances (name, status, status_context, created_at, tool, pid, session_id, directory)
         VALUES ('seat', 'active', 'tool:bash', 1.0, 'codex', ?1, 'local-session', ?2)",
        rusqlite::params![pid, crate::paths::hcom_dir().to_string_lossy()],
    ).unwrap();
    db.set_process_binding("dead-binding", "local-session", "seat")
        .unwrap();
    pid
}

fn stopped_events(db: &HcomDb) -> i64 {
    db.conn()
        .query_row(
            "SELECT count(*) FROM events WHERE type='life' AND instance='seat'
         AND json_extract(data, '$.action')='stopped'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

fn remote_history(db: &HcomDb) {
    db.log_life_event("seat:HODA", "stopped", "test", "exit", None, None)
        .unwrap();
}

#[test]
#[serial]
fn kill_retries_contended_finalize_without_losing_the_snapshot() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let pid = seed_dead_row(&db);
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(
        &db,
        Some(Duration::from_millis(250)),
        "UPDATE instances SET current='writer' WHERE name='seat'",
    );
    let result = kill_tracked_instance(&db, "seat", "test");
    drop(writer);
    let result =
        result.unwrap_or_else(|e| panic!("dead process must be finalized after contention: {e}"));
    assert_eq!(result.teardown, TeardownOutcome::Completed);
    assert!(!crate::pidtrack::is_alive(pid));
    assert!(db.get_instance_full("seat").unwrap().is_none());
    assert!(db.process_binding_ids("seat").unwrap().is_empty());
    assert_eq!(stopped_events(&db), 1);
    let snapshot: String = db
        .conn()
        .query_row(
            "SELECT json_extract(data, '$.snapshot.session_id') FROM events
         WHERE instance='seat' AND json_extract(data, '$.action')='stopped'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(snapshot, "local-session");
}

#[test]
#[serial]
fn kill_busy_deadline_reports_dead_process_and_recovery() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let pid = seed_dead_row(&db);
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(
        &db,
        None,
        "UPDATE instances SET current='writer' WHERE name='seat'",
    );
    let started = Instant::now();
    let error = kill_tracked_instance(&db, "seat", "test")
        .err()
        .expect("writer still holds the DB")
        .to_string();
    let elapsed = started.elapsed();
    assert!(!crate::pidtrack::is_alive(pid));
    assert_eq!(
        db.get_instance_full("seat").unwrap().unwrap().status,
        "active"
    );
    assert_eq!(stopped_events(&db), 0);
    drop(writer);
    assert!(
        elapsed < Duration::from_secs(3),
        "unbounded retry: {elapsed:?}"
    );
    assert!(
        error.contains("dead") && error.contains("not finalized"),
        "{error}"
    );
    assert!(error.contains("hcom kill seat"), "{error}");
    kill_tracked_instance(&db, "seat", "test").unwrap();
    assert!(db.get_instance_full("seat").unwrap().is_none());
    assert_eq!(stopped_events(&db), 1);
}

#[test]
#[serial]
fn kill_retry_keeps_an_incarnation_committed_by_the_writer() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(
        &db,
        Some(Duration::from_millis(250)),
        "UPDATE instances SET session_id='replacement-session' WHERE name='seat'",
    );
    let result = kill_tracked_instance(&db, "seat", "test");
    drop(writer);
    let result = result.unwrap_or_else(|e| panic!("retry must recheck the incarnation: {e}"));
    assert_eq!(result.teardown, TeardownOutcome::RowReRegistered);
    assert_eq!(
        db.get_instance_full("seat")
            .unwrap()
            .unwrap()
            .session_id
            .as_deref(),
        Some("replacement-session")
    );
    assert_eq!(stopped_events(&db), 0);
    assert_eq!(
        db.process_binding_ids("seat").unwrap(),
        vec!["dead-binding"]
    );
}

#[test]
#[serial]
fn resume_busy_stale_local_row_does_not_become_off_host_history() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    remote_history(&db);
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(
        &db,
        None,
        "UPDATE instances SET current='writer' WHERE name='seat'",
    );
    let error = run_local_resume_result(&db, "seat", false, &[], &GlobalFlags::default())
        .unwrap_err()
        .to_string();
    drop(writer);
    assert!(
        error.contains("stale") && error.contains("locked"),
        "{error}"
    );
    assert!(error.contains("hcom kill seat"), "{error}");
    assert!(!error.contains("not an identity on this host"), "{error}");
    assert!(db.get_instance_full("seat").unwrap().is_some());
    assert_eq!(stopped_events(&db), 0);
}

#[test]
#[serial]
fn resume_keeps_the_local_live_refusal_despite_remote_history() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    db.update_instance_pid("seat", std::process::id()).unwrap();
    remote_history(&db);
    let writer = Writer::hold(
        &db,
        None,
        "UPDATE instances SET current='writer' WHERE name='seat'",
    );
    let error = run_local_resume_result(&db, "seat", false, &[], &GlobalFlags::default())
        .unwrap_err()
        .to_string();
    drop(writer);
    assert!(error.contains("still active"), "{error}");
    assert!(!error.contains("not an identity on this host"), "{error}");
    assert_eq!(
        db.get_instance_full("seat").unwrap().unwrap().pid,
        Some(std::process::id() as i64)
    );
}

fn assert_resume_keeps_row(db: &HcomDb) {
    let bindings = db.process_binding_ids("seat").unwrap();
    let before = db.get_instance_full("seat").unwrap().unwrap();
    let plan = crate::commands::resume::prepare_resume_plan(
        db,
        "seat",
        false,
        &[],
        &GlobalFlags::default(),
    );
    assert!(plan.is_err(), "a held seat must not admit another harness");
    let after = db.get_instance_full("seat").unwrap().expect("held row");
    assert_eq!(after.pid, before.pid);
    assert_eq!(after.session_id, before.session_id);
    assert_eq!(after.created_at.to_bits(), before.created_at.to_bits());
    assert_eq!(db.process_binding_ids("seat").unwrap(), bindings);
    assert_eq!(stopped_events(db), 0);
}

// Adapted from ReviewHcom99AfterRelease's isolated valo probe. Its dated
// transcript is visible to endpoint ownership, but not the HCOM-carrier scan.
#[test]
#[serial]
fn resume_holds_a_seat_owned_endpoint_without_hcom_carriers() {
    let (_dir, _hcom, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let dead = seed_dead_row(&db);
    let _transcript =
        std::fs::File::create(home.join("2026-09-25T16-03-17-000Z_local-session.jsonl")).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    db.conn()
        .execute(
            "UPDATE instances SET pid=NULL, last_seen=?1 WHERE name='seat'",
            [crate::shared::time::now_epoch_i64() - 200],
        )
        .unwrap();
    db.set_process_binding(
        &format!("omp-{dead}-a470463d-1174"),
        "local-session",
        "seat",
    )
    .unwrap();
    db.upsert_notify_endpoint("seat", "plugin", listener.local_addr().unwrap().port())
        .unwrap();
    assert!(
        !crate::proctruth::sweep_vanished_instances(&db)
            .iter()
            .any(|name| name == "seat")
    );
    assert_resume_keeps_row(&db);
    // A recorded dead pid is not enough when its own endpoint is still live.
    db.update_instance_pid("seat", dead).unwrap();
    assert_resume_keeps_row(&db);
    assert!(listener.local_addr().is_ok());
}

struct EndpointHolder(std::process::Child);

impl Drop for EndpointHolder {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

#[test]
#[serial]
fn resume_holds_a_sessionless_omp_endpoint_owner() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let (_dir, _hcom, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let dead = seed_dead_row(&db);
    let executable = home.join("omp");
    std::os::unix::fs::symlink("/bin/bash", &executable).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let fd = listener.as_raw_fd();
    let mut command = std::process::Command::new(executable);
    command
        .args(["-c", "read -r -t 300"])
        .env_remove("HCOM_INSTANCE_NAME")
        .env_remove("HCOM_PROCESS_ID")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: only this fixture's listener fd has its close-on-exec flag
    // cleared in the child; no allocation or locks occur after fork.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let holder = EndpointHolder(command.spawn().unwrap());
    drop(listener);
    db.conn().execute("UPDATE instances SET tool='omp', pid=NULL, session_id=NULL, last_seen=?1 WHERE name='seat'",
        [crate::shared::time::now_epoch_i64() - 200]).unwrap();
    db.set_process_binding(&format!("omp-{dead}-a470463d-1174"), "", "seat")
        .unwrap();
    db.upsert_notify_endpoint("seat", "plugin", port).unwrap();
    assert!(
        !crate::proctruth::sweep_vanished_instances(&db)
            .iter()
            .any(|name| name == "seat")
    );
    assert_resume_keeps_row(&db);
    assert!(!crate::proctruth::process_gone(holder.0.id()));
}

#[test]
#[serial]
fn resume_holds_a_dead_pid_inside_the_sweep_fresh_grace() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    db.conn()
        .execute(
            "UPDATE instances SET last_seen=?1 WHERE name='seat'",
            [crate::shared::time::now_epoch_i64()],
        )
        .unwrap();
    assert!(
        !crate::proctruth::sweep_vanished_instances(&db)
            .iter()
            .any(|name| name == "seat")
    );
    assert_resume_keeps_row(&db);
}

#[test]
#[serial]
fn resume_holds_a_live_shell_binding_even_without_a_marker() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    db.set_process_binding(
        &format!("omp-{}-a470463d-1174", std::process::id()),
        "",
        "seat",
    )
    .unwrap();
    assert!(
        !crate::proctruth::sweep_vanished_instances(&db)
            .iter()
            .any(|name| name == "seat")
    );
    assert_resume_keeps_row(&db);
}

#[test]
#[serial]
fn resume_rechecks_fresh_activity_committed_while_awaiting_the_write_lock() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let dead = seed_dead_row(&db);
    db.conn().execute(
        "INSERT INTO instances(name, pid, status, created_at, tool, parent_name) VALUES('child', ?1, 'active', 1, 'codex', 'seat')",
        [i64::from(dead)],
    ).unwrap();
    let writer = Writer::hold(
        &db,
        Some(Duration::from_millis(250)),
        &format!(
            "UPDATE instances SET last_seen={} WHERE name='seat'",
            crate::shared::time::now_epoch_i64()
        ),
    );
    assert_resume_keeps_row(&db);
    drop(writer);
    assert!(
        db.get_instance_full("child").unwrap().is_some(),
        "failed parent recovery must not release its children"
    );
}

#[test]
#[serial]
fn resume_row_read_failure_does_not_prescribe_killing_the_seat() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    db.conn()
        .execute_batch("DROP TABLE process_bindings")
        .unwrap();
    let error = run_local_resume_result(&db, "seat", false, &[], &GlobalFlags::default())
        .unwrap_err()
        .to_string();
    assert!(
        !error.contains("hcom kill"),
        "unreadable ownership must not suggest a destructive command: {error}"
    );
    assert!(db.get_instance_full("seat").unwrap().is_some());
    assert_eq!(stopped_events(&db), 0);
}

#[test]
#[serial]
fn resume_rechecks_endpoint_ownership_committed_while_awaiting_the_write_lock() {
    let (_dir, _hcom, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    let _transcript =
        std::fs::File::create(home.join("2026-09-25T16-03-17-000Z_local-session.jsonl")).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let writer = Writer::hold(
        &db,
        Some(Duration::from_millis(250)),
        &format!(
            "INSERT INTO notify_endpoints(instance, kind, port, updated_at) VALUES('seat', 'plugin', {}, 1)",
            listener.local_addr().unwrap().port()
        ),
    );
    assert_resume_keeps_row(&db);
    drop(writer);
    assert!(listener.local_addr().is_ok());
}

#[test]
#[serial]
fn resume_rechecks_the_binding_epoch_after_waiting_for_the_write_lock() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    let writer = Writer::hold(
        &db,
        Some(Duration::from_millis(250)),
        "UPDATE instances SET session_id='replacement-session' WHERE name='seat';
         UPDATE process_bindings SET process_id='replacement-binding', session_id='replacement-session' WHERE instance_name='seat'",
    );
    let plan = crate::commands::resume::prepare_resume_plan(
        &db,
        "seat",
        false,
        &[],
        &GlobalFlags::default(),
    );
    drop(writer);
    assert!(plan.is_err());
    assert_eq!(
        db.get_instance_full("seat")
            .unwrap()
            .unwrap()
            .session_id
            .as_deref(),
        Some("replacement-session")
    );
    assert_eq!(
        db.process_binding_ids("seat").unwrap(),
        vec!["replacement-binding"]
    );
    assert_eq!(stopped_events(&db), 0);
}

#[test]
#[serial]
fn resume_preserves_rows_when_endpoint_ownership_cannot_be_read() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    db.conn()
        .execute_batch("DROP TABLE notify_endpoints")
        .unwrap();
    assert_resume_keeps_row(&db);
}

#[test]
#[serial]
fn resume_busy_pidless_row_does_not_prescribe_killing_the_seat() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    db.conn()
        .execute(
            "UPDATE instances SET pid=NULL, tool='omp' WHERE name='seat'",
            [],
        )
        .unwrap();
    let orphan = crate::proctruth::orphan_fixtures::spawn_orphan("seat");
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(
        &db,
        None,
        "UPDATE instances SET current='writer' WHERE name='seat'",
    );
    let error = run_local_resume_result(&db, "seat", false, &[], &GlobalFlags::default())
        .unwrap_err()
        .to_string();
    drop(writer);
    assert!(
        !error.contains("hcom kill"),
        "pidless contention must not prescribe an unusable kill: {error}"
    );
    assert!(db.get_instance_full("seat").unwrap().is_some());
    assert_eq!(stopped_events(&db), 0);
    assert!(orphan.alive(orphan.carrier) && orphan.alive(orphan.standin));
}

#[test]
#[serial]
fn resume_foreign_owner_refusal_does_not_prescribe_killing_the_seat() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let dead = seed_dead_row(&db);
    let orphan = crate::proctruth::orphan_fixtures::spawn_orphan("seat");
    db.conn().execute(
        "INSERT INTO instances(name, status, created_at, tool, pid, session_id) VALUES('other', 'active', 2, 'codex', ?1, 'other-session')",
        [i64::from(orphan.carrier)],
    ).unwrap();
    // The foreign live row also owns this recorded root's minted id. The
    // capture must refuse that ambiguous registry even though the pid died.
    let foreign_id = format!("omp-{dead}-a470463d-1174");
    db.set_process_binding(&foreign_id, "other-session", "other")
        .unwrap();
    let error = run_local_resume_result(&db, "seat", false, &[], &GlobalFlags::default())
        .unwrap_err()
        .to_string();
    assert!(
        !error.contains("hcom kill"),
        "ownership refusal must not prescribe a destructive retry: {error}"
    );
    assert!(db.get_instance_full("seat").unwrap().is_some());
    assert_eq!(
        db.get_process_binding(&foreign_id).unwrap().as_deref(),
        Some("other")
    );
    assert_eq!(stopped_events(&db), 0);
    assert!(orphan.alive(orphan.carrier) && orphan.alive(orphan.standin));
}

#[test]
#[serial]
fn resume_pidless_undetermined_row_does_not_prescribe_killing_the_seat() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    db.conn()
        .execute("UPDATE instances SET pid=NULL WHERE name='seat'", [])
        .unwrap();
    let writer = Writer::hold(
        &db,
        None,
        "UPDATE instances SET current='writer' WHERE name='seat'",
    );
    let error = run_local_resume_result(&db, "seat", false, &[], &GlobalFlags::default())
        .unwrap_err()
        .to_string();
    drop(writer);
    assert!(
        !error.contains("hcom kill"),
        "undetermined pidless row must not prescribe an unusable kill: {error}"
    );
    assert!(db.get_instance_full("seat").unwrap().is_some());
    assert_eq!(stopped_events(&db), 0);
}

#[test]
#[serial]
fn resume_releases_a_proven_dead_parent_and_child_in_one_transaction() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let dead = seed_dead_row(&db);
    db.conn().execute(
        "INSERT INTO instances(name, pid, status, created_at, tool, parent_name) VALUES('child', ?1, 'active', 1, 'codex', 'seat')",
        [i64::from(dead)],
    ).unwrap();
    let plan = crate::commands::resume::prepare_resume_plan(
        &db,
        "seat",
        false,
        &[],
        &GlobalFlags::default(),
    );
    assert!(plan.is_ok());
    assert!(db.get_instance_full("seat").unwrap().is_none());
    assert!(db.get_instance_full("child").unwrap().is_none());
    assert_eq!(stopped_events(&db), 1);
    let child_stops: i64 = db.conn().query_row(
        "SELECT count(*) FROM events WHERE type='life' AND instance='child' AND json_extract(data, '$.action')='stopped'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(child_stops, 1);
}

#[test]
#[serial]
fn resume_keeps_the_whole_tree_when_an_empty_child_has_a_live_endpoint() {
    let (_dir, _hcom, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let dead = seed_dead_row(&db);
    let _transcript =
        std::fs::File::create(home.join("2026-09-25T16-03-17-000Z_child-session.jsonl")).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    db.conn().execute(
        "INSERT INTO instances(name, pid, status, created_at, tool, parent_name, session_id) VALUES('child', ?1, 'active', 1, 'codex', 'seat', 'child-session')",
        [i64::from(dead)],
    ).unwrap();
    db.upsert_notify_endpoint("child", "plugin", listener.local_addr().unwrap().port())
        .unwrap();
    assert_resume_keeps_row(&db);
    assert!(db.get_instance_full("child").unwrap().is_some());
}

#[test]
#[serial]
fn resume_busy_tree_guidance_refuses_an_endpoint_held_child() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let (_dir, _hcom, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let dead = seed_dead_row(&db);
    let executable = home.join("omp");
    std::os::unix::fs::symlink("/bin/bash", &executable).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let fd = listener.as_raw_fd();
    let port = listener.local_addr().unwrap().port();
    let mut command = std::process::Command::new(executable);
    command
        .args(["-c", "read -r -t 300"])
        .env_remove("HCOM_INSTANCE_NAME")
        .env_remove("HCOM_PROCESS_ID")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: only the fixture listener is inherited by this idle child.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let holder = EndpointHolder(command.spawn().unwrap());
    drop(listener);
    db.conn().execute(
        "INSERT INTO instances(name, pid, status, created_at, tool, parent_name) VALUES('child', ?1, 'active', 1, 'omp', 'seat')",
        [i64::from(dead)],
    ).unwrap();
    db.upsert_notify_endpoint("child", "plugin", port).unwrap();
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(
        &db,
        None,
        "UPDATE instances SET current='writer' WHERE name='seat'",
    );
    let error = crate::commands::resume::prepare_resume_plan(
        &db,
        "seat",
        false,
        &[],
        &GlobalFlags::default(),
    )
    .err()
    .expect("the busy tree must refuse")
    .to_string();
    drop(writer);
    assert!(
        error.contains("locked"),
        "the real DB failure must survive: {error}"
    );
    assert!(
        !error.contains("hcom kill"),
        "a held child must not receive destructive recovery advice: {error}"
    );
    assert!(db.get_instance_full("seat").unwrap().is_some());
    assert!(db.get_instance_full("child").unwrap().is_some());
    assert_eq!(stopped_events(&db), 0);
    assert!(!crate::proctruth::process_gone(holder.0.id()));
}

#[test]
#[serial]
fn resume_busy_tree_guidance_keeps_usable_recovery_for_all_dead_rows() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let dead = seed_dead_row(&db);
    db.conn().execute(
        "INSERT INTO instances(name, pid, status, created_at, tool, parent_name) VALUES('child', ?1, 'active', 1, 'codex', 'seat')",
        [i64::from(dead)],
    ).unwrap();
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(
        &db,
        None,
        "UPDATE instances SET current='writer' WHERE name='seat'",
    );
    let error = crate::commands::resume::prepare_resume_plan(
        &db,
        "seat",
        false,
        &[],
        &GlobalFlags::default(),
    )
    .err()
    .expect("the DB is busy")
    .to_string();
    drop(writer);
    assert!(
        error.contains("locked") && error.contains("hcom kill seat"),
        "{error}"
    );
    kill_tracked_instance(&db, "seat", "test").unwrap();
    assert!(db.get_instance_full("seat").unwrap().is_none());
    assert!(db.get_instance_full("child").unwrap().is_none());
    assert_eq!(stopped_events(&db), 1);
}

#[test]
#[serial]
fn resume_busy_tree_guidance_refuses_unknown_child_ownership() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    db.conn().execute_batch(
        "INSERT INTO instances(name, status, created_at, tool, parent_name) VALUES('child', 'active', 1, 'codex', 'seat')",
    ).unwrap();
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(
        &db,
        None,
        "UPDATE instances SET current='writer' WHERE name='seat'",
    );
    let error = crate::commands::resume::prepare_resume_plan(
        &db,
        "seat",
        false,
        &[],
        &GlobalFlags::default(),
    )
    .err()
    .expect("unknown child ownership must refuse")
    .to_string();
    drop(writer);
    assert!(
        !error.contains("hcom kill"),
        "unknown child evidence must fail closed: {error}"
    );
    assert!(db.get_instance_full("seat").unwrap().is_some());
    assert!(db.get_instance_full("child").unwrap().is_some());
    assert_eq!(stopped_events(&db), 0);
}

struct TestProcess(PathBuf);
impl Drop for TestProcess {
    fn drop(&mut self) {
        if let Ok(pid) = std::fs::read_to_string(&self.0)
            && let Ok(pid) = pid.trim().parse::<u32>()
        {
            crate::sys::process::kill(pid);
        }
    }
}

fn wait_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[serial]
fn launched_terminal_is_not_zero_launched_when_db_reopen_is_busy() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, hcom_dir, home, _guard) = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    // Exercise the rollback-journal configuration too: an exclusive writer
    // blocks the post-spawn reopen's WAL PRAGMA, not the successful spawn.
    db.conn()
        .execute_batch("PRAGMA journal_mode=DELETE;")
        .unwrap();
    let pid_file = home.join("launched.pid");
    let held_file = home.join("writer-held");
    let _child = TestProcess(pid_file.clone());
    let terminal = home.join("test-terminal");
    std::fs::write(&terminal, format!(
        "#!/bin/sh\nsleep 30 >/dev/null 2>&1 &\necho $! > '{}'\nfor i in $(seq 1 500); do\n [ -e '{}' ] && exit 0\n sleep 0.01\ndone\nexit 1\n",
        pid_file.display(), held_file.display(),
    )).unwrap();
    std::fs::set_permissions(&terminal, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (release, released) = mpsc::channel();
    let db_path = db.path().to_path_buf();
    let wait_pid = pid_file.clone();
    let thread = std::thread::spawn(move || {
        wait_file(&wait_pid);
        let conn = Connection::open(db_path).unwrap();
        conn.execute_batch(
            "PRAGMA busy_timeout=1000; BEGIN EXCLUSIVE; UPDATE instances SET current='writer';",
        )
        .unwrap();
        std::fs::write(held_file, "held").unwrap();
        let _ = released.recv_timeout(Duration::from_secs(20));
        conn.execute_batch("COMMIT").unwrap();
    });
    let writer = Writer {
        release,
        thread: Some(thread),
    };
    let env = std::collections::HashMap::from([
        ("HCOM_PROCESS_ID".to_string(), "test-launch".to_string()),
        (
            "HCOM_DIR".to_string(),
            hcom_dir.to_string_lossy().to_string(),
        ),
    ]);
    let result = crate::launcher::launch_pty(
        "omp",
        &home.to_string_lossy(),
        &env,
        "seat",
        &[],
        false,
        Some(&format!("{} {{script}}", terminal.display())),
        false,
        false,
    );
    let pid = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    assert!(
        crate::pidtrack::is_alive(pid),
        "terminal's launched process must exist"
    );
    drop(writer);
    assert!(
        result.unwrap_or_else(|e| panic!("terminal launched, bookkeeping must only warn: {e}"))
    );
}
