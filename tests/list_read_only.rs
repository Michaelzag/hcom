//! `hcom list` is a read-only view of instance lifecycle: it must never
//! stop, reap, or signal an instance, and must never release a session row.
//!
//! Both tests seed the fixture DB directly (rusqlite, real column names)
//! after letting the binary initialize the schema, then run the real binary
//! and assert the row and any live carrier survived untouched.
//!
//! Unix only: the carriers rely on process groups and /proc environ
//! enumeration, which hcom's lifecycle code compiles out elsewhere.
#![cfg(unix)]

mod support;

use std::os::unix::process::CommandExt;

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use support::Hcom;

/// Open the fixture's own database (created by the binary's first run) for
/// direct row seeding and row-survival checks.
fn fixture_db(h: &Hcom) -> rusqlite::Connection {
    rusqlite::Connection::open(h.path().join("hcom.db")).expect("open fixture hcom.db")
}

fn now_epoch_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock before epoch")
        .as_secs_f64()
}

/// Seed a LOCAL row (origin_device_id NULL, background=0) whose
/// status_time/last_stop/created_at are all two hours old — old enough that
/// every retention tier of the former janitor would have claimed it.
fn seed_stale_instance(h: &Hcom, name: &str, status: &str, pid: Option<i64>) {
    let two_hours_ago = now_epoch_f64() - 7200.0;
    fixture_db(h)
        .execute(
            "INSERT INTO instances
                 (name, tool, status, status_time, last_stop, created_at, background, pid)
             VALUES (?1, 'codex', ?2, ?3, ?3, ?4, 0, ?5)",
            rusqlite::params![name, status, two_hours_ago as i64, two_hours_ago, pid],
        )
        .expect("seed instance row");
}

/// Mirror `set_process_binding`: bind `process_id` to the instance so a
/// process holding `HCOM_PROCESS_ID=<process_id>` is a live carrier of it.
fn seed_binding(h: &Hcom, process_id: &str, session_id: &str, name: &str) {
    fixture_db(h)
        .execute(
            "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![process_id, session_id, name, now_epoch_f64()],
        )
        .expect("seed process binding");
}

fn instance_row_exists(h: &Hcom, name: &str) -> bool {
    fixture_db(h)
        .query_row(
            "SELECT COUNT(*) FROM instances WHERE name = ?1",
            rusqlite::params![name],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0
}

/// Block until `/proc/<pid>/environ` carries the binding marker: between
/// fork and exec the child still shows the parent's environ (which never
/// carries it), and a carrier that `hcom list` cannot enumerate proves
/// nothing about signalling.
#[cfg(unix)]
fn wait_for_carrier_environ(process_id: &str, pid: u32) {
    let marker = format!("HCOM_PROCESS_ID={process_id}");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ"))
            && environ
                .split(|b| *b == 0)
                .any(|entry| entry == marker.as_bytes())
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("carrier pid {pid} never exposed {marker} in /proc/environ");
}

/// A carrier of the instance: `sleep 600` in its own process group (so no
/// signal aimed at it can reach the test process), isolated env plus exactly
/// the identity markers a live session process holds.
#[cfg(unix)]
fn spawn_carrier(h: &Hcom, name: &str, process_id: &str) -> Child {
    let mut command: Command = h.external_cmd("sleep");
    command
        .arg("600")
        .env("HCOM_PROCESS_ID", process_id)
        .env("HCOM_INSTANCE_NAME", name)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command.spawn().expect("spawn carrier");
    wait_for_carrier_environ(process_id, child.id());
    child
}

/// A pid guaranteed dead: spawn a short-lived process, reap it, and wait for
/// `/proc` to drop it.
#[cfg(unix)]
fn dead_pid(h: &Hcom) -> i64 {
    let mut command: Command = h.external_cmd("sleep");
    command
        .arg("0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().expect("spawn short-lived process");
    let pid = child.id();
    child.wait().expect("reap short-lived process");
    let deadline = Instant::now() + Duration::from_secs(2);
    while std::fs::metadata(format!("/proc/{pid}")).is_ok() {
        assert!(
            Instant::now() < deadline,
            "pid {pid} still in /proc after reaping"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    i64::from(pid)
}

#[test]
#[cfg(unix)]
fn list_does_not_stop_live_idle_session() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["list"]);
    assert_eq!(code, 0, "schema-init `hcom list` failed: {stderr}");

    let name = format!("live-idle-{}", std::process::id());
    let process_id = format!("proc-live-idle-{}", std::process::id());
    // Listening LOCAL row, heartbeat two hours old: computed `stale:listening`
    // — exactly the row the former janitor's stale tier stopped.
    seed_stale_instance(&h, &name, "listening", None);
    seed_binding(&h, &process_id, "sess-live-idle", &name);

    let mut carrier = spawn_carrier(&h, &name, &process_id);

    let (code, stdout, stderr) = h.run(["list"]);
    assert_eq!(
        code, 0,
        "`hcom list` failed:\n-- stdout --\n{stdout}\n-- stderr --\n{stderr}"
    );
    let (code, json, stderr) = h.run(["list", "--json"]);
    assert_eq!(
        code, 0,
        "`hcom list --json` failed:\n-- stdout --\n{json}\n-- stderr --\n{stderr}"
    );
    let row_exists = instance_row_exists(&h, &name);
    let carrier_alive = carrier.try_wait().expect("poll carrier").is_none();
    assert!(
        row_exists && carrier_alive,
        "`hcom list` must never touch a live idle session, but did: \
         row_exists={row_exists}, carrier_alive={carrier_alive}"
    );
    assert!(
        json.contains(&name),
        "idle session row missing from `hcom list --json` output:\n{json}"
    );

    carrier.kill().expect("kill carrier");
    carrier.wait().expect("reap carrier");
}

#[test]
#[cfg(unix)]
fn list_leaves_dead_inactive_row_in_place() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["list"]);
    assert_eq!(code, 0, "schema-init `hcom list` failed: {stderr}");

    let name = format!("dead-inactive-{}", std::process::id());
    // Inactive LOCAL row, two hours old, pid provably dead, no live carrier:
    // the row the former janitor's inactive tier deleted.
    let pid = dead_pid(&h);
    seed_stale_instance(&h, &name, "inactive", Some(pid));

    let (code, stdout, stderr) = h.run(["list"]);
    assert_eq!(
        code, 0,
        "`hcom list` failed:\n-- stdout --\n{stdout}\n-- stderr --\n{stderr}"
    );

    assert!(
        instance_row_exists(&h, &name),
        "`hcom list` deleted a dead inactive session's row"
    );
}

/// Seed a LOCAL launch placeholder: session_id NULL, status `pending`,
/// context `new` — exactly `is_launching_placeholder`'s check — created ten
/// minutes ago, so it is stale for the placeholder threshold while its
/// launch carrier is still live.
fn seed_launch_placeholder(h: &Hcom, name: &str) {
    let ten_minutes_ago = now_epoch_f64() - 600.0;
    fixture_db(h)
        .execute(
            "INSERT INTO instances
                 (name, tool, status, status_context, status_time, last_stop, created_at, background)
             VALUES (?1, 'codex', 'pending', 'new', ?2, ?2, ?3, 0)",
            rusqlite::params![
                name,
                ten_minutes_ago as i64,
                ten_minutes_ago
            ],
        )
        .expect("seed launch placeholder row");
}

#[test]
#[cfg(unix)]
fn list_does_not_touch_live_launch_placeholder() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["list"]);
    assert_eq!(code, 0, "schema-init `hcom list` failed: {stderr}");

    let name = format!("live-placeholder-{}", std::process::id());
    let process_id = format!("proc-live-placeholder-{}", std::process::id());
    seed_launch_placeholder(&h, &name);
    seed_binding(&h, &process_id, "sess-live-placeholder", &name);

    let mut carrier = spawn_carrier(&h, &name, &process_id);

    let (code, stdout, stderr) = h.run(["list"]);
    assert_eq!(
        code, 0,
        "`hcom list` failed:\n-- stdout --\n{stdout}\n-- stderr --\n{stderr}"
    );
    let (code, json, stderr) = h.run(["list", "--json"]);
    assert_eq!(
        code, 0,
        "`hcom list --json` failed:\n-- stdout --\n{json}\n-- stderr --\n{stderr}"
    );

    let row_exists = instance_row_exists(&h, &name);
    let carrier_alive = carrier.try_wait().expect("poll carrier").is_none();
    assert!(
        row_exists && carrier_alive,
        "`hcom list` must never touch a live launch placeholder, but did: \
         row_exists={row_exists}, carrier_alive={carrier_alive}"
    );
    assert!(
        json.contains(&name),
        "live launch placeholder missing from `hcom list --json` output:\n{json}"
    );

    carrier.kill().expect("kill carrier");
    carrier.wait().expect("reap carrier");
}
