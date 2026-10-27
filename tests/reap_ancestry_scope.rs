//! A stale binding on a process outside the owning tree must never turn an
//! instance stop into a signal to that process. Linux-only: ancestry is /proc.

#![cfg(target_os = "linux")]

mod support;

use std::fs;
use std::io::PipeWriter;
use std::os::unix::fs::symlink;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};
use support::{Hcom, child_identity, terminate_owned_child, unique_suffix};

fn parent_pid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn process_group_id(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(2)?
        .parse()
        .ok()
}

fn live(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            stat.rsplit_once(')')
                .map(|(_, fields)| !fields.trim_start().starts_with('Z'))
        })
        .unwrap_or(false)
}

fn has_identity(pid: u32, process_id: &str) -> bool {
    let marker = format!("HCOM_PROCESS_ID={process_id}");
    fs::read(format!("/proc/{pid}/environ"))
        .ok()
        .is_some_and(|env| {
            env.split(|byte| *byte == 0)
                .any(|entry| entry == marker.as_bytes())
        })
}

fn wait_for_inside(path: &Path, owner_pid: u32, process_id: &str) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(pid) = fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
            && live(pid)
            && parent_pid(pid) == Some(owner_pid)
            && has_identity(pid, process_id)
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "owner's child never carried the expected identity"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_until_gone(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while live(pid) {
        assert!(
            Instant::now() < deadline,
            "in-tree carrier {pid} survived stop"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// A `sleep` stand-in whose comm is still `sleep`: run as
/// `"$SLEEP_BIN" -c 'read _' <&9`, it blocks on the fixture's private gate
/// pipe and exits on its own at EOF, so cleanup never signals it.
fn gated_sleep(h: &Hcom) -> PathBuf {
    let dir = h.root_path().join("gate");
    let sleep = dir.join("sleep");
    if fs::symlink_metadata(&sleep).is_err() {
        fs::create_dir_all(&dir).expect("create gate directory");
        symlink("/bin/sh", &sleep).expect("create gated sleep binary");
    }
    sleep
}

// The shell and sibling are Child handles we spawned; cleanup signals only
// them, after their spawn identity rechecks. The in-tree carrier is the
// shell's child, not ours: it blocks on the gate this struct holds the only
// write end of, so dropping the gate makes it exit on its own.
struct Carriers {
    owner: Child,
    owner_identity: Option<String>,
    outside: Child,
    outside_identity: Option<String>,
    gate: Option<PipeWriter>,
}

impl Drop for Carriers {
    fn drop(&mut self) {
        drop(self.gate.take());
        terminate_owned_child(&mut self.owner, self.owner_identity.as_deref());
        terminate_owned_child(&mut self.outside, self.outside_identity.as_deref());
    }
}

fn seed_row(h: &Hcom, name: &str, process_id: &str, pid: Option<u32>) -> rusqlite::Connection {
    let db = rusqlite::Connection::open(h.path().join("hcom.db")).expect("open isolated DB");
    db.execute(
        "INSERT INTO instances (name, tool, pid, session_id, status, status_context, status_time, created_at, last_event_id)
         VALUES (?1, 'omp', ?2, ?3, 'listening', 'start', 0, 0, 0)",
        rusqlite::params![name, pid, format!("sid-{process_id}")],
    )
    .expect("seed target row");
    db.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![process_id, format!("sid-{process_id}"), name],
    )
    .expect("seed target binding");
    db
}

fn assert_released(db: &rusqlite::Connection, name: &str) {
    let rows: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM instances WHERE name = ?1",
            [name],
            |row| row.get(0),
        )
        .expect("query target row");
    assert_eq!(rows, 0, "target row was not released");
}

fn spawn_outside(h: &Hcom, process_id: &str) -> Child {
    h.external_cmd("sleep")
        .arg("300")
        .env("HCOM_PROCESS_ID", process_id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sibling carrier standing in for gnome-session")
}

fn assert_outside_spared(h: &Hcom, carriers: &mut Carriers, name: &str) {
    let pid = carriers.outside.id();
    assert!(
        carriers
            .outside
            .try_wait()
            .expect("poll outside carrier")
            .is_none(),
        "out-of-tree carrier {pid} (gnome-session stand-in) was signalled"
    );
    let log = fs::read_to_string(h.path().join(".tmp/logs/hcom.log")).expect("read hcom log");
    let logged = log.lines().any(|line| {
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        event["level"] == "INFO"
            && event["subsystem"] == "proctruth"
            && event["event"] == "carrier_out_of_scope"
            && event["msg"].as_str().is_some_and(|msg| {
                msg.contains(&format!("pid={pid}"))
                    && msg.contains(&format!("instance={name}"))
                    && msg.contains("roots=")
            })
    });
    assert!(
        logged,
        "excluded identity carrier {pid} was not logged at Info"
    );
}

#[test]
fn stop_reaps_recorded_owner_descendant_but_spares_sibling_with_same_identity() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let name = format!("ancestry-owner-{suffix}");
    let process_id = format!("stale-desktop-{suffix}");
    let child_pid_file = h.root_path().join("owner-child.pid");
    let sleep = gated_sleep(&h);
    let (gate_rx, gate) = std::io::pipe().expect("create cleanup gate");
    let owner = h
        .external_cmd("sh")
        .args([
            "-c",
            "exec 9<&0; trap 'wait' TERM; \"$SLEEP_BIN\" -c 'read _' <&9 & echo $! > \"$CHILD_PID_FILE\"; wait",
        ])
        .env("SLEEP_BIN", &sleep)
        .env("CHILD_PID_FILE", &child_pid_file)
        .env("HCOM_PROCESS_ID", &process_id)
        .stdin(gate_rx)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn instance owner shell");
    let owner_identity = child_identity(&owner);
    let inside = wait_for_inside(&child_pid_file, owner.id(), &process_id);
    let outside = spawn_outside(&h, &process_id);
    let outside_identity = child_identity(&outside);
    let mut carriers = Carriers {
        owner,
        owner_identity,
        outside,
        outside_identity,
        gate: Some(gate),
    };
    assert_eq!(parent_pid(carriers.outside.id()), Some(std::process::id()));
    assert!(has_identity(carriers.outside.id(), &process_id));
    let db = seed_row(&h, &name, &process_id, Some(carriers.owner.id()));

    let (code, stdout, stderr) = h.run(["stop", &name]);
    assert_eq!(code, 0, "stop failed: stdout={stdout}; stderr={stderr}");
    wait_until_gone(inside);
    assert_outside_spared(&h, &mut carriers, &name);
    assert_released(&db, &name);
}

#[test]
fn stop_from_another_session_uses_live_omp_binding_owner_when_row_pid_is_null() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let name = format!("ancestry-plain-{suffix}");
    let fixture = h.root_path().join("fake-omp");
    fs::create_dir_all(&fixture).expect("create fake omp directory");
    let omp = fixture.join("omp");
    symlink("/bin/sh", &omp).expect("create fake omp binary");
    let child_pid_file = fixture.join("owner-child.pid");
    let sleep = gated_sleep(&h);
    let (gate_rx, gate) = std::io::pipe().expect("create cleanup gate");
    let owner = h
        .external_cmd("sh")
        .args([
            "-c",
            "HCOM_PROCESS_ID=\"omp-$$-$SUFFIX\" exec \"$OMP_BIN\" -c \"$OWNER_SCRIPT\"",
        ])
        .env("SUFFIX", &suffix)
        .env("OMP_BIN", &omp)
        .env(
            "OWNER_SCRIPT",
            "exec 9<&0; trap 'wait' TERM; \"$SLEEP_BIN\" -c 'read _' <&9 & echo $! > \"$CHILD_PID_FILE\"; wait",
        )
        .env("SLEEP_BIN", &sleep)
        .env("CHILD_PID_FILE", &child_pid_file)
        .stdin(gate_rx)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn minted omp owner");
    let owner_identity = child_identity(&owner);
    let process_id = format!("omp-{}-{suffix}", owner.id());
    let inside = wait_for_inside(&child_pid_file, owner.id(), &process_id);
    assert_eq!(
        fs::read_to_string(format!("/proc/{}/comm", owner.id()))
            .unwrap()
            .trim(),
        "omp"
    );
    assert!(has_identity(owner.id(), &process_id));
    let outside = spawn_outside(&h, &process_id);
    let outside_identity = child_identity(&outside);
    let mut carriers = Carriers {
        owner,
        owner_identity,
        outside,
        outside_identity,
        gate: Some(gate),
    };
    assert_eq!(parent_pid(carriers.outside.id()), Some(std::process::id()));
    assert!(has_identity(carriers.outside.id(), &process_id));
    let db = seed_row(&h, &name, &process_id, None);

    // hcom kill refuses pid-NULL rows; named stop takes the same reap path.
    let (code, stdout, stderr) = h.run(["stop", &name]);
    assert_eq!(
        code, 0,
        "cross-session stop failed: stdout={stdout}; stderr={stderr}"
    );
    wait_until_gone(inside);
    assert_outside_spared(&h, &mut carriers, &name);
    assert_released(&db, &name);
}

#[test]
fn kill_freezes_descendant_identity_before_the_owner_group_dies() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let name = format!("ancestry-reparent-{suffix}");
    let process_id = format!("reparent-binding-{suffix}");
    let child_pid_file = h.root_path().join("detached-child.pid");
    let setsid = h.resolve_external("setsid").expect("setsid binary");
    let sleep = gated_sleep(&h);
    let (gate_rx, gate) = std::io::pipe().expect("create cleanup gate");
    let owner = h
        .external_cmd("sh")
        .args([
            "-c",
            "exec 9<&0; \"$SETSID_BIN\" \"$SLEEP_BIN\" -c 'read _' <&9 & echo $! > \"$CHILD_PID_FILE\"; wait",
        ])
        .env("SETSID_BIN", setsid)
        .env("SLEEP_BIN", &sleep)
        .env("CHILD_PID_FILE", &child_pid_file)
        .env("HCOM_PROCESS_ID", &process_id)
        .process_group(0)
        .stdin(gate_rx)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn headless owner shell");
    let owner_identity = child_identity(&owner);
    let inside = wait_for_inside(&child_pid_file, owner.id(), &process_id);
    let outside = spawn_outside(&h, &process_id);
    let outside_identity = child_identity(&outside);
    let detached_deadline = Instant::now() + Duration::from_secs(10);
    while process_group_id(inside) != Some(inside) {
        assert!(
            Instant::now() < detached_deadline,
            "owned child {inside} did not escape the owner's process group"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        parent_pid(inside),
        Some(owner.id()),
        "child detached after owner died"
    );
    let mut carriers = Carriers {
        owner,
        owner_identity,
        outside,
        outside_identity,
        gate: Some(gate),
    };
    let db = seed_row(&h, &name, &process_id, Some(carriers.owner.id()));
    db.execute(
        "UPDATE instances SET background = 1 WHERE name = ?1",
        [&name],
    )
    .expect("mark headless group owner");

    // The recorded group signal kills the owner before proctruth's TERM
    // round, leaving its setsid child reparented. Its captured OS identity
    // still proves it is the child we saw before that first signal.
    let (code, stdout, stderr) = h.run(["kill", &name]);
    assert_eq!(
        code, 0,
        "headless kill failed: stdout={stdout}; stderr={stderr}"
    );
    let owner_status = carriers
        .owner
        .wait()
        .expect("wait for group-signalled owner");
    assert!(
        owner_status.signal().is_some(),
        "owner was not group-signalled: {owner_status:?}"
    );
    wait_until_gone(inside);
    assert_outside_spared(&h, &mut carriers, &name);
    assert_released(&db, &name);

    let log = fs::read_to_string(h.path().join(".tmp/logs/hcom.log")).expect("read hcom log");
    assert!(
        !log.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .is_some_and(|event| {
                    event["event"] == "carrier_out_of_scope"
                        && event["msg"]
                            .as_str()
                            .is_some_and(|msg| msg.contains(&format!("pid={inside} ")))
                })
        }),
        "previously scoped child {inside} was refused after reparenting"
    );
}
