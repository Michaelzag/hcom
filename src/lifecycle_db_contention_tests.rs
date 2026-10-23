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
            conn.execute_batch("PRAGMA busy_timeout=0; BEGIN IMMEDIATE;").unwrap();
            conn.execute_batch(&change).unwrap();
            held_tx.send(()).unwrap();
            let _ = released.recv_timeout(duration.unwrap_or(Duration::from_secs(10)));
            conn.execute_batch("COMMIT").unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self { release, thread: Some(thread) }
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
    db.set_process_binding("dead-binding", "local-session", "seat").unwrap();
    pid
}

fn stopped_events(db: &HcomDb) -> i64 {
    db.conn().query_row(
        "SELECT count(*) FROM events WHERE type='life' AND instance='seat'
         AND json_extract(data, '$.action')='stopped'", [], |r| r.get(0),
    ).unwrap()
}

fn remote_history(db: &HcomDb) {
    db.log_life_event("seat:HODA", "stopped", "test", "exit", None, None).unwrap();
}

#[test]
#[serial]
fn kill_retries_contended_finalize_without_losing_the_snapshot() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let pid = seed_dead_row(&db);
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(&db, Some(Duration::from_millis(250)), "UPDATE instances SET current='writer' WHERE name='seat'");
    let result = kill_tracked_instance(&db, "seat", "test");
    drop(writer);
    let result = result.unwrap_or_else(|e| panic!("dead process must be finalized after contention: {e}"));
    assert_eq!(result.teardown, TeardownOutcome::Completed);
    assert!(!crate::pidtrack::is_alive(pid));
    assert!(db.get_instance_full("seat").unwrap().is_none());
    assert!(db.process_binding_ids("seat").unwrap().is_empty());
    assert_eq!(stopped_events(&db), 1);
    let snapshot: String = db.conn().query_row(
        "SELECT json_extract(data, '$.snapshot.session_id') FROM events
         WHERE instance='seat' AND json_extract(data, '$.action')='stopped'", [], |r| r.get(0),
    ).unwrap();
    assert_eq!(snapshot, "local-session");
}

#[test]
#[serial]
fn kill_busy_deadline_reports_dead_process_and_recovery() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    let pid = seed_dead_row(&db);
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(&db, None, "UPDATE instances SET current='writer' WHERE name='seat'");
    let started = Instant::now();
    let error = kill_tracked_instance(&db, "seat", "test").err().expect("writer still holds the DB");
    let elapsed = started.elapsed();
    assert!(!crate::pidtrack::is_alive(pid));
    assert_eq!(db.get_instance_full("seat").unwrap().unwrap().status, "active");
    assert_eq!(stopped_events(&db), 0);
    drop(writer);
    assert!(elapsed < Duration::from_secs(3), "unbounded retry: {elapsed:?}");
    assert!(error.contains("dead") && error.contains("not finalized"), "{error}");
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
    let writer = Writer::hold(&db, Some(Duration::from_millis(250)), "UPDATE instances SET session_id='replacement-session' WHERE name='seat'");
    let result = kill_tracked_instance(&db, "seat", "test");
    drop(writer);
    let result = result.unwrap_or_else(|e| panic!("retry must recheck the incarnation: {e}"));
    assert_eq!(result.teardown, TeardownOutcome::RowReRegistered);
    assert_eq!(db.get_instance_full("seat").unwrap().unwrap().session_id.as_deref(), Some("replacement-session"));
    assert_eq!(stopped_events(&db), 0);
    assert_eq!(db.process_binding_ids("seat").unwrap(), vec!["dead-binding"]);
}

#[test]
#[serial]
fn resume_busy_stale_local_row_does_not_become_off_host_history() {
    let _env = crate::hooks::test_helpers::isolated_test_env();
    let db = HcomDb::open().unwrap();
    seed_dead_row(&db);
    remote_history(&db);
    db.conn().busy_timeout(Duration::ZERO).unwrap();
    let writer = Writer::hold(&db, None, "UPDATE instances SET current='writer' WHERE name='seat'");
    let error = run_local_resume_result(&db, "seat", false, &[], &GlobalFlags::default()).unwrap_err().to_string();
    drop(writer);
    assert!(error.contains("stale") && error.contains("locked"), "{error}");
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
    let writer = Writer::hold(&db, None, "UPDATE instances SET current='writer' WHERE name='seat'");
    let error = run_local_resume_result(&db, "seat", false, &[], &GlobalFlags::default()).unwrap_err().to_string();
    drop(writer);
    assert!(error.contains("still active"), "{error}");
    assert!(!error.contains("not an identity on this host"), "{error}");
    assert_eq!(db.get_instance_full("seat").unwrap().unwrap().pid, Some(std::process::id() as i64));
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
        assert!(Instant::now() < deadline, "timed out waiting for {}", path.display());
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
    db.conn().execute_batch("PRAGMA journal_mode=DELETE;").unwrap();
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
        conn.execute_batch("PRAGMA busy_timeout=1000; BEGIN EXCLUSIVE; UPDATE instances SET current='writer';").unwrap();
        std::fs::write(held_file, "held").unwrap();
        let _ = released.recv_timeout(Duration::from_secs(20));
        conn.execute_batch("COMMIT").unwrap();
    });
    let writer = Writer { release, thread: Some(thread) };
    let env = std::collections::HashMap::from([
        ("HCOM_PROCESS_ID".to_string(), "test-launch".to_string()),
        ("HCOM_DIR".to_string(), hcom_dir.to_string_lossy().to_string()),
    ]);
    let result = crate::launcher::launch_pty(
        "omp", &home.to_string_lossy(), &env, "seat", &[], false,
        Some(&format!("{} {{script}}", terminal.display())), false, false,
    );
    let pid = std::fs::read_to_string(&pid_file).unwrap().trim().parse::<u32>().unwrap();
    assert!(crate::pidtrack::is_alive(pid), "terminal's launched process must exist");
    drop(writer);
    assert!(result.unwrap_or_else(|e| panic!("terminal launched, bookkeeping must only warn: {e}")));
}
