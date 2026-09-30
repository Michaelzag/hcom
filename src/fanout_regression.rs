//! PostCommit fan-out regression gate (fauna review).
//!
//! Every test here uses ONLY APIs present in both 8eb0682 and the redesigned
//! head, so this file (plus its `mod` line) can be copied onto a scratch
//! 8eb0682 worktree to prove each test FAILS there and PASSES here:
//!
//! - F1: a non-`once` subscription matching life+status gets BOTH events in
//!   id order (old tree advances the cursor past the life row: "last_id skip").
//! - F2: PTY exit notifies a live request-watcher (old tree fans out after
//!   the row delete, so the waterline read misses).
//! - F2-fallback: the kill path notifies via the snapshot cursor when the row
//!   is already gone (old tree has no fallback).
//! - F4: a soft stop's wake reaches a live DELIVERY_LOOPS listener whose
//!   endpoint row was deleted in-txn (old tree looks the ports up after the
//!   delete and finds nothing).
//! - F5: the status event is durable even when a spinner grabs BEGIN
//!   IMMEDIATE the moment the commit lands while slow wakes fire (old tree
//!   inserts the status event post-commit and loses it to the lock).
//! - F7: a send riding out ~250ms of lock contention returns Ok with exactly
//!   one row (fails on trees without the send retry, e.g. f3225a3; passes on
//!   8eb0682, which already retries — expected, not a gate failure).

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serial_test::serial;

use crate::commands::send::send_message;
use crate::db::HcomDb;
use crate::db::subscriptions::create_request_watches;
use crate::delivery::cleanup_deleted_instance;
use crate::hooks::common::soft_finalize_session;
use crate::shared::{SenderIdentity, SenderKind};

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path(tag: &str) -> PathBuf {
    let id = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hcom_fanout_{}_{}_{}.db",
        std::process::id(),
        id,
        tag
    ))
}

fn open_full_db(
    tag: &str,
) -> (
    HcomDb,
    PathBuf,
    (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        crate::hooks::test_helpers::EnvGuard,
    ),
) {
    // send_message() reaches the process-global relay notification path, so
    // the ambient HCOM_DIR must live as long as the test DB.
    let env = crate::hooks::test_helpers::isolated_test_env();
    let db_path = temp_db_path(tag);
    let db = HcomDb::open_at(&db_path).unwrap();
    (db, db_path, env)
}

fn cleanup_test_db(path: PathBuf) {
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(PathBuf::from(format!("{}-wal", path.display())));
    let _ = std::fs::remove_file(PathBuf::from(format!("{}-shm", path.display())));
}

/// Bind a non-blocking localhost listener on an OS-assigned port.
fn bind_probe() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

/// Wait up to `timeout` for the listener to accept a connection.
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

/// Fill a listener's accept queue and hold it full so later connects hang
/// (SYNs are dropped, no RST) until the wake's connect timeout expires.
/// Prefill connects are bounded: the first one that cannot complete promptly
/// proves the queue is full, so setup itself can never hang. Best-effort —
/// where the kernel refuses fast instead of queueing, each queued connect
/// still costs the fan-out a round trip.
fn blackhole_listener() -> (TcpListener, Vec<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut held = Vec::new();
    for _ in 0..256 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            Ok(stream) => held.push(stream),
            Err(_) => break,
        }
    }
    (listener, held)
}

fn data_version(db: &HcomDb) -> i64 {
    db.conn()
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .unwrap()
}

/// Notification message texts addressed to `caller`, in event-id order.
fn messages_to(db: &HcomDb, caller: &str, after_id: i64) -> Vec<String> {
    let pattern = format!("%@{caller} %");
    let mut stmt = db
        .conn()
        .prepare(
            "SELECT json_extract(data, '$.text') FROM events
             WHERE type = 'message' AND id > ? AND json_extract(data, '$.text') LIKE ?
             ORDER BY id",
        )
        .unwrap();
    stmt.query_map(rusqlite::params![after_id, pattern], |row| {
        row.get::<_, Option<String>>(0)
    })
    .unwrap()
    .filter_map(|r| r.ok().flatten())
    .collect()
}

fn max_event_id(db: &HcomDb) -> i64 {
    db.conn()
        .query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// Requester `requester` (live row) watches live target `responder`.
/// Returns the request event id. Mirrors the subscriptions test helper.
fn setup_reqwatch_pair(db: &HcomDb, requester: &str, responder: &str) -> i64 {
    db.conn()
        .execute(
            "INSERT INTO instances (name, tool, last_event_id, created_at)
             VALUES (?1, 'claude', 0, 1000.0), (?2, 'antigravity', 0, 1000.0)",
            rusqlite::params![requester, responder],
        )
        .unwrap();
    let req_data = serde_json::json!({
        "from": requester,
        "sender_kind": "instance",
        "scope": "mentions",
        "text": "ping",
        "delivered_to": [responder],
        "intent": "request",
        "mentions": [responder],
    });
    let request_id = db.log_event("message", requester, &req_data).unwrap();
    create_request_watches(db, requester, request_id, &[responder.to_string()]);
    db.conn()
        .execute(
            "UPDATE instances SET last_event_id = ?1 WHERE name = ?2",
            rusqlite::params![request_id, responder],
        )
        .unwrap();
    request_id
}

/// F1: a non-`once` subscription matching life+status gets BOTH events in id
/// order across a soft stop. The old tree logs the life row in-txn but the
/// status row post-commit, so the status dispatch advances the cursor past
/// the life row and the life dispatch skips it ("last_id skip").
#[test]
#[serial]
fn fanout_f1_non_once_sub_gets_life_and_status_in_id_order() {
    let (db, db_path, _env) = open_full_db("f1");
    db.conn()
        .execute(
            "INSERT INTO instances (name, tool, status, last_event_id, created_at)
             VALUES ('luna', 'claude', 'listening', 0, 1000.0),
                    ('gora', 'claude', 'listening', 0, 1000.0)",
            [],
        )
        .unwrap();
    db.kv_set(
        "events_sub:f1both",
        Some(
            &serde_json::json!({
                "id": "f1both",
                "caller": "gora",
                "sql": "(type='status' AND instance='luna') OR (type='life' AND instance='luna')",
                "params": [],
                "last_id": 0,
            })
            .to_string(),
        ),
    )
    .unwrap();
    let baseline = max_event_id(&db);

    soft_finalize_session(&db, "luna", "f1", None, false);

    let got = messages_to(&db, "gora", baseline);
    assert_eq!(
        got.len(),
        2,
        "non-once sub must receive status AND life, got {got:?}"
    );
    assert!(
        got[0].contains("inactive"),
        "first notification is the status event, got {:?}",
        got[0]
    );
    assert!(
        got[1].contains("stopped"),
        "second notification is the life event, got {:?}",
        got[1]
    );

    cleanup_test_db(db_path);
}

/// F2: PTY exit notifies a live request-watcher. The fan-out must run BEFORE
/// the row delete so the waterline read sees the live row; the old tree fans
/// out after the commit and the watcher is skipped.
#[test]
#[serial]
fn fanout_f2_pty_exit_notifies_requester() {
    let (mut db, db_path, _env) = open_full_db("f2");
    let request_id = setup_reqwatch_pair(&db, "gora", "nabe");
    let baseline = max_event_id(&db);
    db.conn()
        .execute(
            "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
             VALUES ('pid-exit', NULL, 'nabe', 1000.0)",
            [],
        )
        .unwrap();

    cleanup_deleted_instance(&mut db, "nabe", "pid-exit");

    let got = messages_to(&db, "gora", baseline);
    assert_eq!(
        got.len(),
        1,
        "requester must be notified of the PTY stop, got {got:?}"
    );
    assert!(
        db.kv_get(&format!("events_sub:reqwatch-{request_id}-nabe"))
            .unwrap()
            .is_none(),
        "once reqwatch sub must be consumed by the notify"
    );

    cleanup_test_db(db_path);
}

/// F2-fallback: the kill path (row deleted in the same txn as the event)
/// still notifies via the event snapshot's cursor when the row is gone.
/// The old tree has no fallback, so the watcher is skipped.
#[test]
#[serial]
fn fanout_f2fb_kill_path_notifies_via_snapshot_cursor() {
    let (db, db_path, _env) = open_full_db("f2fb");
    let request_id = setup_reqwatch_pair(&db, "gora", "nabe");
    let baseline = max_event_id(&db);
    let event_data = serde_json::json!({
        "action": "stopped",
        "by": "pty",
        "reason": "killed",
        "process_id": "pid-k",
        "snapshot": {
            "name": "nabe",
            "last_event_id": request_id,
        },
    });

    let won = db
        .finalize_instance_stop("nabe", 1000.0, None, None, None, &event_data, None, None)
        .unwrap();
    assert!(won, "kill-path release must win on a fresh row");

    let got = messages_to(&db, "gora", baseline);
    assert_eq!(
        got.len(),
        1,
        "requester must be notified via the snapshot cursor, got {got:?}"
    );
    assert!(
        db.kv_get(&format!("events_sub:reqwatch-{request_id}-nabe"))
            .unwrap()
            .is_none(),
        "once reqwatch sub must be consumed by the notify"
    );

    cleanup_test_db(db_path);
}

/// F4: a soft stop's wake reaches a live DELIVERY_LOOPS listener even though
/// its endpoint row is deleted in-txn. The old tree resolves ports after the
/// delete and finds nothing, so no wake fires.
#[test]
#[serial]
fn fanout_f4_soft_stop_wake_reaches_live_listener() {
    let (db, db_path, _env) = open_full_db("f4");
    db.conn()
        .execute(
            "INSERT INTO instances (name, tool, status, last_event_id, created_at)
             VALUES ('luna', 'claude', 'listening', 0, 1000.0)",
            [],
        )
        .unwrap();
    let probe = bind_probe();
    let port = probe.local_addr().unwrap().port();
    db.upsert_notify_endpoint("luna", "pty", port).unwrap();

    soft_finalize_session(&db, "luna", "f4", None, false);

    assert!(
        await_connect(&probe, Duration::from_secs(2)),
        "live listener must receive the soft-stop wake"
    );

    cleanup_test_db(db_path);
}

/// F5: the status event is durable even when a spinner grabs BEGIN IMMEDIATE
/// the moment the commit lands while slow wakes fire. The old tree inserts
/// the status event post-commit, so the insert blocks on the spinner past
/// the 5s busy_timeout and the event is lost.
#[test]
#[serial]
fn fanout_f5_status_durable_under_post_commit_lock() {
    let (db, db_path, _env) = open_full_db("f5");
    db.conn()
        .execute(
            "INSERT INTO instances (name, tool, status, last_event_id, created_at)
             VALUES ('luna', 'claude', 'listening', 0, 1000.0)",
            [],
        )
        .unwrap();
    // Slow wakes: full accept queues hang each connect until the wake
    // timeout, stretching the post-commit window so the spinner below is
    // guaranteed to hold the write lock before any post-commit write lands.
    let mut blackholes = Vec::new();
    for _ in 0..3 {
        let (listener, held) = blackhole_listener();
        let port = listener.local_addr().unwrap().port();
        db.upsert_notify_endpoint("luna", "pty", port).unwrap();
        blackholes.push((listener, held));
    }

    let v0 = data_version(&db);
    let (grabbed_tx, grabbed_rx) = std::sync::mpsc::channel::<bool>();
    let spinner = std::thread::spawn({
        let path = db_path.clone();
        move || {
            let conn = rusqlite::Connection::open(&path).unwrap();
            let start = Instant::now();
            loop {
                let v: i64 = conn
                    .query_row("PRAGMA data_version", [], |row| row.get(0))
                    .unwrap_or(v0);
                if v != v0 {
                    break;
                }
                if start.elapsed() > Duration::from_secs(15) {
                    grabbed_tx.send(false).ok();
                    return;
                }
                std::thread::yield_now();
            }
            // Hold the write lock past the 5s SQLite busy_timeout: any
            // post-commit write racing the commit fails instead of waiting.
            conn.execute_batch("PRAGMA busy_timeout=0; BEGIN IMMEDIATE;")
                .unwrap();
            grabbed_tx.send(true).ok();
            std::thread::sleep(Duration::from_millis(5500));
            conn.execute_batch("COMMIT;").unwrap();
        }
    });

    soft_finalize_session(&db, "luna", "f5", None, false);

    assert!(
        grabbed_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("spinner reported"),
        "spinner must observe the commit"
    );
    spinner.join().expect("spinner released the lock");
    drop(blackholes);

    let status_count: i64 = db
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE type = 'status' AND instance = 'luna'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        status_count, 1,
        "status event must be durable at commit time, not inserted after it"
    );
    let life_count: i64 = db
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = 'luna'
             AND json_extract(data, '$.action') = 'stopped'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(life_count, 1, "control: the stopped event must exist");

    cleanup_test_db(db_path);
}

/// F7: a send riding out ~250ms of lock contention returns Ok with exactly
/// one row. Fails on trees without the send retry (f3225a3); passes on
/// 8eb0682, which already retries — that pass is expected, not a gate
/// failure. (Mirrors the send unit test; repeated here so the cross-tree
/// gate run covers it.)
#[test]
#[serial]
fn fanout_f7_send_succeeds_after_transient_contention() {
    let (db, db_path, _env) = open_full_db("f7");
    db.conn()
        .execute(
            "INSERT INTO instances (name, created_at) VALUES ('luna', 1000.0), ('nova', 1000.0)",
            [],
        )
        .unwrap();
    db.conn().execute_batch("PRAGMA busy_timeout=0;").unwrap();

    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn({
        let path = db_path.clone();
        move || {
            let guard = rusqlite::Connection::open(&path).unwrap();
            guard
                .execute_batch("PRAGMA busy_timeout=0; BEGIN IMMEDIATE;")
                .unwrap();
            held_tx.send(()).ok();
            std::thread::sleep(Duration::from_millis(250));
            guard.execute_batch("COMMIT;").unwrap();
        }
    });
    held_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("holder took the write lock");

    let sender = SenderIdentity {
        kind: SenderKind::External,
        name: "bigboss".into(),
        instance_data: None,
        session_id: None,
    };
    let delivered = send_message(&db, &sender, "hello", None, Some(&["nova".to_string()])).unwrap();
    holder.join().expect("holder committed");
    assert!(
        delivered.contains(&"nova".to_string()),
        "delivered={delivered:?}"
    );

    let count: i64 = db
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE type = 'message'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);

    cleanup_test_db(db_path);
}
