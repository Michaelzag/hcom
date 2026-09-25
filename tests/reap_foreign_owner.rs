//! A reap must never signal a process another live row holds. `hcom stop` and
//! `hcom kill` on a row whose bindings resolve into a foreign live seat's
//! process tree must refuse before their first signal, name the other owner,
//! and leave every process, row, and binding exactly as they were.
//! Linux-only: the identity facts and the ancestry proof are /proc.

#![cfg(target_os = "linux")]

mod support;

use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};
use support::{Hcom, unique_suffix};

fn live(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            stat.rsplit_once(')')
                .map(|(_, f)| !f.trim_start().starts_with('Z'))
        })
        .unwrap_or(false)
}

fn parent_pid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn environ_carries(pid: u32, entry: &str) -> bool {
    let marker = entry.as_bytes();
    fs::read(format!("/proc/{pid}/environ"))
        .ok()
        .is_some_and(|env| env.split(|byte| *byte == 0).any(|var| var == marker))
}

fn wait_for_child_pid(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(pid) = fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
            && live(pid)
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "fixture child never reported a live pid"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// A real process whose `/proc/<pid>/comm` is exactly `omp` and whose
/// `HCOM_PROCESS_ID` is `omp-<its pid>-<id_suffix>` — the shape
/// `carrier_tree_scope` admits as an owner root — plus one child of its own.
/// The id suffix is the caller's, so a test decides which row the carried id
/// names and which row only shares the minted pid.
fn spawn_minted_omp_seat(h: &Hcom, id_suffix: &str) -> Seat {
    let fixture = h.root_path().join("fake-omp");
    fs::create_dir_all(&fixture).expect("create fake omp directory");
    let omp = fixture.join("omp");
    symlink("/bin/sh", &omp).expect("create fake omp binary");
    let child_pid_file = fixture.join("owner-child.pid");
    let owner = h
        .external_cmd("sh")
        .args([
            "-c",
            "HCOM_PROCESS_ID=\"omp-$$-$ID_SUFFIX\" exec \"$OMP_BIN\" -c \"$OWNER_SCRIPT\"",
        ])
        .env("ID_SUFFIX", id_suffix)
        .env("OMP_BIN", &omp)
        .env(
            "OWNER_SCRIPT",
            "trap 'wait' TERM; sleep 300 & echo $! > \"$CHILD_PID_FILE\"; wait",
        )
        .env("CHILD_PID_FILE", &child_pid_file)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn minted omp seat");
    let process_id = format!("omp-{}-{id_suffix}", owner.id());
    let inside = wait_for_child_pid(&child_pid_file);
    assert_eq!(parent_pid(inside), Some(owner.id()));
    assert_eq!(
        fs::read_to_string(format!("/proc/{}/comm", owner.id()))
            .unwrap_or_default()
            .trim(),
        "omp",
        "the fixture process must look like a minted omp owner"
    );
    assert!(environ_carries(
        owner.id(),
        &format!("HCOM_PROCESS_ID={process_id}")
    ));
    Seat {
        owner,
        inside,
        process_id,
    }
}

// The seat process is a Child handle we spawned and the tree pid comes from
// that shell's private pid file. Cleanup signals the raw pid only while it
// still carries this test's unique identity, so a failing assertion can never
// kill an unrelated process.
struct Seat {
    owner: Child,
    inside: u32,
    process_id: String,
}

impl Drop for Seat {
    fn drop(&mut self) {
        if live(self.inside) && environ_carries(self.inside, &self.process_id_marker()) {
            unsafe { libc::kill(self.inside as libc::pid_t, libc::SIGKILL) };
        }
        if self.owner.try_wait().ok().flatten().is_none() {
            let _ = self.owner.kill();
        }
        let _ = self.owner.wait();
    }
}

impl Seat {
    fn process_id_marker(&self) -> String {
        format!("HCOM_PROCESS_ID={}", self.process_id)
    }

    fn assert_spared(&mut self, what: &str) {
        let pid = self.owner.id();
        assert!(
            self.owner
                .try_wait()
                .expect("poll the foreign-owned process")
                .is_none(),
            "foreign-owned pid {pid} was signalled by a {what}"
        );
        assert!(
            live(self.inside),
            "its descendant {} was signalled by a {what}",
            self.inside
        );
    }
}

fn open_db(h: &Hcom) -> rusqlite::Connection {
    rusqlite::Connection::open(h.path().join("hcom.db")).expect("open isolated DB")
}

/// One live row plus its binding epoch, seeded the way the plugin leaves a
/// seat: `listening`, local, and bound to every id the row owns.
fn seed_row(db: &rusqlite::Connection, name: &str, pid: Option<u32>, binding_ids: &[&str]) {
    db.execute(
        "INSERT INTO instances (name, tool, pid, session_id, status, status_context, status_time, created_at, last_event_id)
         VALUES (?1, 'omp', ?2, ?3, 'listening', 'start', 0, 0, 0)",
        rusqlite::params![name, pid, format!("sid-{name}")],
    )
    .expect("seed target row");
    for process_id in binding_ids {
        db.execute(
            "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
             VALUES (?1, ?2, ?3, 0)",
            rusqlite::params![process_id, format!("sid-{name}"), name],
        )
        .expect("seed target binding");
    }
}

fn rows_named(db: &rusqlite::Connection, name: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM instances WHERE name = ?1",
        [name],
        |row| row.get(0),
    )
    .expect("count rows")
}
fn binding_owner(db: &rusqlite::Connection, process_id: &str) -> Option<String> {
    db.query_row(
        "SELECT instance_name FROM process_bindings WHERE process_id = ?1",
        [process_id],
        |row| row.get(0),
    )
    .ok()
}

fn assert_intact(db: &rusqlite::Connection, rows: &[(String, String)], refused: &str) {
    for (name, process_id) in rows {
        assert_eq!(
            rows_named(db, name),
            1,
            "row '{name}' must survive a refused {refused}"
        );
        assert_eq!(
            binding_owner(db, process_id).as_deref(),
            Some(name.as_str()),
            "binding '{process_id}' must stay owned by '{name}' after a refused {refused}"
        );
    }
}

/// The sibling mint from the incident: two live rows bind two minted ids that
/// resolve to the SAME pid, the process carries the other row's id, and the
/// stopped row's own recorded pid is that same process. Both commands must
/// refuse before the group signal and the pane close, naming the live owner.
#[test]
fn stop_and_kill_refuse_a_sibling_mint_of_another_live_rows_pid() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let seat = format!("seat-{suffix}");
    let meme = format!("meme-{suffix}");
    let mut seat_process = spawn_minted_omp_seat(&h, &format!("{suffix}-seat"));
    let meme_process_id = format!("omp-{}-{suffix}-mine", seat_process.owner.id());
    let db = open_db(&h);
    seed_row(&db, &seat, None, &[&seat_process.process_id]);
    seed_row(
        &db,
        &meme,
        Some(seat_process.owner.id()),
        &[&meme_process_id],
    );
    let rows = vec![
        (seat.clone(), seat_process.process_id.clone()),
        (meme.clone(), meme_process_id.clone()),
    ];

    for command in ["stop", "kill"] {
        let (code, stdout, stderr) = h.run([command, meme.as_str()]);
        assert_ne!(
            code, 0,
            "{command} must refuse: stdout={stdout}; stderr={stderr}"
        );
        assert!(
            stderr.contains(&seat),
            "the {command} refusal must name the live owner '{seat}': {stderr}"
        );
        seat_process.assert_spared(&format!("refused {command}"));
        assert_intact(&db, &rows, command);
    }
}

/// The same two rows, but the process carries the STOPPED row's own id: the
/// exact-id arm is silent, and the refusal can only come from the minted pid
/// the other live row's sibling id names. This is the shape the incident
/// reached through a stolen pid rather than a stolen id.
#[test]
fn stop_refuses_a_pid_another_live_row_minted_under_its_own_id() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let seat = format!("seat-{suffix}");
    let meme = format!("meme-{suffix}");
    let mut owner_process = spawn_minted_omp_seat(&h, &format!("{suffix}-mine"));
    // Same pid, a different minted id, held by the other live row.
    let seat_process_id = format!("omp-{}-{suffix}-seat", owner_process.owner.id());
    let db = open_db(&h);
    // The stopped row keeps the id its own process carries, and a NULL pid:
    // the minted id is the only thing that makes the process a reap root.
    seed_row(&db, &meme, None, &[&owner_process.process_id]);
    seed_row(&db, &seat, None, &[&seat_process_id]);
    let rows = vec![
        (meme.clone(), owner_process.process_id.clone()),
        (seat.clone(), seat_process_id.clone()),
    ];

    let (code, stdout, stderr) = h.run(["stop", meme.as_str()]);
    assert_ne!(
        code, 0,
        "stop must refuse: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains(&seat),
        "the refusal must name the live owner '{seat}': {stderr}"
    );
    owner_process.assert_spared("refused stop");
    assert_intact(&db, &rows, "stop");
}

/// A carrier inside the stopped row's own tree that carries ANOTHER live row's
/// process id. The recorded pid and its own tree are clean, so the guard has
/// to reach the carrier — and must still send nothing.
#[test]
fn stop_refuses_a_carrier_carrying_another_live_rows_process_id() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let seat = format!("seat-{suffix}");
    let meme = format!("meme-{suffix}");
    let seat_process_id = format!("seat-shell-{suffix}");
    let meme_process_id = format!("meme-shell-{suffix}");
    let sleep = h.resolve_external("sleep").expect("sleep binary");
    let child_pid_file = h.root_path().join("meme-child.pid");
    // The recorded pid carries only the stopped row's own id; its child
    // carries the other live row's id and is admitted as a carrier by name.
    let owner = h
        .external_cmd("sh")
        .args([
            "-c",
            "HCOM_INSTANCE_NAME=\"$INSTANCE\" HCOM_PROCESS_ID=\"$SEAT_ID\" \"$SLEEP_BIN\" 300 & echo $! > \"$CHILD_PID_FILE\"; wait",
        ])
        .env("INSTANCE", &meme)
        .env("SEAT_ID", &seat_process_id)
        .env("SLEEP_BIN", &sleep)
        .env("CHILD_PID_FILE", &child_pid_file)
        .env("HCOM_PROCESS_ID", &meme_process_id)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the stopped row's owner shell");
    let inside = wait_for_child_pid(&child_pid_file);
    assert_eq!(parent_pid(inside), Some(owner.id()));
    let mut carriers = Carriers {
        owner,
        inside,
        markers: vec![
            format!("HCOM_PROCESS_ID={seat_process_id}"),
            format!("HCOM_INSTANCE_NAME={meme}"),
        ],
    };
    assert!(environ_carries(
        inside,
        &format!("HCOM_PROCESS_ID={seat_process_id}")
    ));
    assert!(environ_carries(
        inside,
        &format!("HCOM_INSTANCE_NAME={meme}")
    ));
    let db = open_db(&h);
    seed_row(&db, &meme, Some(carriers.owner.id()), &[&meme_process_id]);
    seed_row(&db, &seat, None, &[&seat_process_id]);
    let rows = vec![
        (meme.clone(), meme_process_id.clone()),
        (seat.clone(), seat_process_id.clone()),
    ];

    let (code, stdout, stderr) = h.run(["stop", meme.as_str()]);
    assert_ne!(
        code, 0,
        "stop must refuse: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains(&seat),
        "the refusal must name the live owner '{seat}': {stderr}"
    );
    let owner_pid = carriers.owner.id();
    assert!(
        carriers
            .owner
            .try_wait()
            .expect("poll the recorded pid")
            .is_none(),
        "the stopped row's own recorded pid {owner_pid} was signalled"
    );
    assert!(
        live(carriers.inside) && environ_carries(carriers.inside, &carriers.markers[0]),
        "the foreign-id carrier {} was signalled by a refused stop",
        carriers.inside
    );
    assert_intact(&db, &rows, "stop");
}

// The owner shell is a Child handle we spawned and the child pid comes from
// that shell's private pid file. Cleanup signals the raw pid only while it
// still carries one of this test's unique identity markers.
struct Carriers {
    owner: Child,
    inside: u32,
    markers: Vec<String>,
}

impl Drop for Carriers {
    fn drop(&mut self) {
        if live(self.inside) && self.markers.iter().any(|m| environ_carries(self.inside, m)) {
            unsafe { libc::kill(self.inside as libc::pid_t, libc::SIGKILL) };
        }
        if self.owner.try_wait().ok().flatten().is_none() {
            let _ = self.owner.kill();
        }
        let _ = self.owner.wait();
    }
}
