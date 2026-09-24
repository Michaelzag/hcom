//! A detached omp broker inherits its launching session's identity, but its
//! shared daemons are not that session's carriers. A nested omp is.

#![cfg(target_os = "linux")]

mod support;

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};
use support::{Hcom, unique_suffix};

fn pid_in(path: &PathBuf) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_else(|e| panic!("read comm for {pid}: {e}"))
        .trim_end_matches('\n')
        .to_string()
}

fn parent_pid(pid: u32) -> u32 {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("read process stat");
    stat.rsplit_once(')')
        .expect("stat comm delimiter")
        .1
        .split_whitespace()
        .nth(1)
        .expect("stat ppid")
        .parse()
        .expect("parse ppid")
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

fn inherits_name(pid: u32, name: &str) -> bool {
    let marker = format!("HCOM_INSTANCE_NAME={name}");
    fs::read(format!("/proc/{pid}/environ"))
        .ok()
        .is_some_and(|env| {
            env.split(|b| *b == 0)
                .any(|entry| entry == marker.as_bytes())
        })
}

// Only signal fixture-owned pids: each pid comes from a private file written
// by our spawned shell and must still carry this test's unique identity.
struct OwnedTree {
    owner: Child,
    name: String,
    pid_files: [PathBuf; 5],
}

impl Drop for OwnedTree {
    fn drop(&mut self) {
        for path in self.pid_files.iter().rev() {
            if let Some(pid) = pid_in(path)
                && inherits_name(pid, &self.name)
            {
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            }
        }
        if self.owner.try_wait().ok().flatten().is_none() {
            let _ = self.owner.kill();
        }
        let _ = self.owner.wait();
    }
}

fn listed_pids(refusal: &str) -> HashSet<u32> {
    refusal
        .split("still alive: ")
        .nth(1)
        .unwrap_or_else(|| panic!("spawn gate did not list holders: {refusal}"))
        .split(" — ")
        .next()
        .unwrap()
        .split(", ")
        .map(|pid| pid.trim().parse().expect("listed pid"))
        .collect()
}

#[test]
fn broker_shared_daemons_are_not_owner_carriers_but_nested_omp_is() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");

    let name = format!("broker-scope-{}-{}", std::process::id(), unique_suffix());
    let process_id = format!("broker-process-{}", unique_suffix());
    let fixture = h.root_path().join("broker-fixture");
    fs::create_dir_all(&fixture).expect("create fake process tree directory");
    let omp = fixture.join("omp");
    let broker = fixture.join("omp daemon brok");
    symlink("/bin/sh", &omp).expect("fake omp binary");
    symlink("/bin/sh", &broker).expect("fake broker binary");
    let setsid = h.resolve_external("setsid").expect("setsid binary");
    let sleep = h.resolve_external("sleep").expect("sleep binary");

    let pid_files = ["broker", "nested", "tool", "daemon", "tool-sleep"]
        .map(|role| fixture.join(format!("{role}.pid")));
    let owner = h
        .external_cmd(&omp)
        .args(["-c", r#""$SETSID_BIN" "$BROKER_BIN" -c "$BROKER_SCRIPT" & wait"#])
        .env("SETSID_BIN", setsid)
        .env("BROKER_BIN", &broker)
        .env("BROKER_SCRIPT", r#"printf '%s\n' "$$" > "$BROKER_PID_FILE"; "$OMP_BIN" -c "$NESTED_SCRIPT" & "$SLEEP_BIN" 300 & printf '%s\n' "$!" > "$DAEMON_PID_FILE"; wait"#)
        .env("NESTED_SCRIPT", r#"trap 'wait' TERM; printf '%s\n' "$$" > "$NESTED_PID_FILE"; "$TOOL_BIN" -c "$TOOL_SCRIPT" & wait"#)
        .env("TOOL_SCRIPT", r#"printf '%s\n' "$$" > "$TOOL_PID_FILE"; "$SLEEP_BIN" 300 & printf '%s\n' "$!" > "$TOOL_SLEEP_PID_FILE"; wait"#)
        .env("OMP_BIN", &omp)
        .env("TOOL_BIN", "/bin/sh")
        .env("SLEEP_BIN", sleep)
        .env("BROKER_PID_FILE", &pid_files[0])
        .env("NESTED_PID_FILE", &pid_files[1])
        .env("TOOL_PID_FILE", &pid_files[2])
        .env("DAEMON_PID_FILE", &pid_files[3])
        .env("TOOL_SLEEP_PID_FILE", &pid_files[4])
        .env("HCOM_INSTANCE_NAME", &name)
        .env("HCOM_PROCESS_ID", &process_id)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn owner omp");
    let tree = OwnedTree {
        owner,
        name: name.clone(),
        pid_files,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let pids = loop {
        if let [
            Some(broker),
            Some(nested),
            Some(tool),
            Some(daemon),
            Some(tool_sleep),
        ] = tree.pid_files.each_ref().map(pid_in)
            && [broker, nested, tool, daemon, tool_sleep]
                .into_iter()
                .all(|pid| live(pid) && inherits_name(pid, &name))
        {
            break [broker, nested, tool, daemon, tool_sleep];
        }
        assert!(Instant::now() < deadline, "fake broker tree never started");
        std::thread::sleep(Duration::from_millis(50));
    };
    let [broker_pid, nested_pid, tool_pid, daemon_pid, tool_sleep_pid] = pids;
    assert_eq!(parent_pid(broker_pid), tree.owner.id());
    assert_eq!(parent_pid(nested_pid), broker_pid);
    assert_eq!(parent_pid(tool_pid), nested_pid);
    assert_eq!(parent_pid(daemon_pid), broker_pid);
    assert_eq!(parent_pid(tool_sleep_pid), tool_pid);

    let comms = [
        tree.owner.id(),
        broker_pid,
        nested_pid,
        tool_pid,
        daemon_pid,
    ]
    .map(comm);
    eprintln!("observed comms (owner, broker, nested, tool, daemon): {comms:?}");
    assert_eq!(comms, ["omp", "omp daemon brok", "omp", "sh", "sleep"]);

    // The spawn gate reports its actual carrier enumeration as a PID list.
    // No row or binding exists yet, so every eligible identity match appears.
    let (code, _, refusal) = h.run(["start", "--as", &name]);
    assert_ne!(code, 0, "live owner must refuse rebind");
    let holders = listed_pids(&refusal);
    for pid in [tree.owner.id(), nested_pid, tool_pid, tool_sleep_pid] {
        assert!(
            holders.contains(&pid),
            "carrier {pid} missing from {holders:?}"
        );
    }
    for pid in [broker_pid, daemon_pid] {
        assert!(
            !holders.contains(&pid),
            "shared daemon {pid} in {holders:?}"
        );
    }

    let db = rusqlite::Connection::open(h.path().join("hcom.db")).expect("open isolated DB");
    db.execute(
        "INSERT INTO instances (name, tool, pid, background, session_id, status, status_context, status_time, created_at, last_event_id)
         VALUES (?1, 'omp', ?2, 1, ?3, 'listening', 'start', 0, 0, 0)",
        rusqlite::params![name, tree.owner.id(), format!("sid-{process_id}")],
    )
    .expect("seed owner instance");
    db.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![process_id, format!("sid-{process_id}"), name],
    )
    .expect("seed owner binding");

    let (code, stdout, stderr) = h.run(["kill", &name]);
    assert_eq!(code, 0, "kill failed: stdout={stdout}; stderr={stderr}");
    let deadline = Instant::now() + Duration::from_secs(3);
    while live(nested_pid) || live(tool_pid) {
        assert!(
            Instant::now() < deadline,
            "nested omp/tool shell survived kill"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(live(broker_pid), "broker was signalled by owner kill");
    assert!(
        live(daemon_pid),
        "shared daemon was signalled by owner kill"
    );
}
