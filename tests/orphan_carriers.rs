//! A seat that died leaves identity carriers behind: processes its tree
//! spawned still carry `HCOM_INSTANCE_NAME=<seat>` after the user's
//! subreaper (systemd --user) adopted them. They are no evidence the seat
//! lives: `hcom kill` names them and points at `hcom stop`, which releases
//! the row and signals none of them. A live seat, an `omp` holding its
//! session transcript with a carrier child, stays held exactly as before.
//! Linux-only: ancestry and open-file facts are /proc. This test process
//! stands in for systemd --user: it is a child subreaper, so a double-forked
//! carrier lands under it rather than under init.

#![cfg(target_os = "linux")]

mod support;

use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::Once;
use std::time::{Duration, Instant};
use support::{Hcom, unique_suffix};

fn become_subreaper() {
    static SUBREAPER: Once = Once::new();
    SUBREAPER.call_once(|| {
        let (on, off): (libc::c_ulong, libc::c_ulong) = (1, 0);
        // SAFETY: prctl(PR_SET_CHILD_SUBREAPER) on this process only.
        let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, on, off, off, off) };
        assert_eq!(
            rc,
            0,
            "become the carriers' subreaper: {}",
            std::io::Error::last_os_error()
        );
    });
}

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

fn comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
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

fn dead_pid(h: &Hcom) -> u32 {
    let mut child = h.external_cmd("true").spawn().expect("spawn true");
    let pid = child.id();
    child.wait().expect("reap true");
    pid
}

fn open_db(h: &Hcom) -> rusqlite::Connection {
    rusqlite::Connection::open(h.path().join("hcom.db")).expect("open isolated DB")
}

/// The row a dead seat leaves: `listening`, no pid, its session, and one
/// minted omp binding (also its launch_context process id) whose pid is dead.
fn seed_dead_seat_row(db: &rusqlite::Connection, name: &str, session_id: &str, binding: &str) {
    db.execute(
        "INSERT INTO instances (name, tool, pid, session_id, status, status_context, status_time, created_at, last_event_id, launch_context)
         VALUES (?1, 'omp', NULL, ?2, 'listening', 'start', 0, 0, 0, ?3)",
        rusqlite::params![
            name,
            session_id,
            format!("{{\"process_id\":\"{binding}\"}}")
        ],
    )
    .expect("seed seat row");
    db.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![binding, session_id, name],
    )
    .expect("seed seat binding");
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

fn stopped_events(db: &rusqlite::Connection, name: &str) -> i64 {
    db.query_row(
        "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = ?1
         AND json_extract(data, '$.action') = 'stopped'",
        [name],
        |row| row.get(0),
    )
    .expect("count stopped events")
}

/// A carrier this test process adopted as subreaper. Cleanup signals it only
/// while it still carries this test's unique name, then reaps it.
struct Adopted {
    pid: u32,
    marker: String,
}

impl Drop for Adopted {
    fn drop(&mut self) {
        let signalled = live(self.pid) && environ_carries(self.pid, &self.marker);
        if signalled {
            // SAFETY: kill(2) on a pid that still carries this test's name.
            unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGKILL) };
        }
        if (signalled || !live(self.pid)) && parent_pid(self.pid) == Some(std::process::id()) {
            let mut status = 0;
            // SAFETY: waitpid(2) on our own (adopted) child.
            unsafe { libc::waitpid(self.pid as libc::pid_t, &mut status, 0) };
        }
    }
}

/// Double-fork a carrier of `name`: `sh` backgrounds it and exits, so the
/// carrier is reparented to this subreaper, never to a root of the row.
fn adopt_carrier(h: &Hcom, name: &str) -> Adopted {
    let sleep = h.resolve_external("sleep").expect("sleep binary");
    let pid_file = h.root_path().join(format!("carrier-{name}.pid"));
    let status = h
        .external_cmd("sh")
        .args([
            "-c",
            "HCOM_INSTANCE_NAME=\"$INSTANCE\" \"$SLEEP_BIN\" 300 & echo $! > \"$PID_FILE\"",
        ])
        .env("INSTANCE", name)
        .env("SLEEP_BIN", &sleep)
        .env("PID_FILE", &pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn the carrier's parent");
    assert!(status.success(), "carrier parent failed: {status}");
    Adopted {
        pid: wait_for_child_pid(&pid_file),
        marker: format!("HCOM_INSTANCE_NAME={name}"),
    }
}

/// A live seat: a process whose comm is exactly `omp`, holding
/// `<session_id>.jsonl` open, with a child that carries the seat's name and
/// does not hold the fd itself.
struct Seat {
    owner: Child,
    carrier: u32,
    marker: String,
}

impl Drop for Seat {
    fn drop(&mut self) {
        if live(self.carrier) && environ_carries(self.carrier, &self.marker) {
            // SAFETY: kill(2) on a pid that still carries this test's name.
            unsafe { libc::kill(self.carrier as libc::pid_t, libc::SIGKILL) };
        }
        // The owner's `wait` reaps the carrier; only then stop the owner, so
        // no zombie is handed to this subreaper.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Path::new(&format!("/proc/{}", self.carrier)).exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if self.owner.try_wait().ok().flatten().is_none() {
            let _ = self.owner.kill();
        }
        let _ = self.owner.wait();
    }
}

fn spawn_live_seat(h: &Hcom, name: &str, session_id: &str) -> Seat {
    let fixture = h.root_path().join("fake-omp");
    fs::create_dir_all(&fixture).expect("create fake omp directory");
    let omp = fixture.join("omp");
    symlink("/bin/sh", &omp).expect("create fake omp binary");
    let transcript = fixture.join(format!("{session_id}.jsonl"));
    let carrier_pid_file = fixture.join("carrier.pid");
    let sleep = h.resolve_external("sleep").expect("sleep binary");
    let owner = h
        .external_cmd("sh")
        .args(["-c", "exec \"$OMP_BIN\" -c \"$OWNER_SCRIPT\""])
        .env("OMP_BIN", &omp)
        .env(
            "OWNER_SCRIPT",
            "exec 3>>\"$TRANSCRIPT\"; HCOM_INSTANCE_NAME=\"$INSTANCE\" \"$SLEEP_BIN\" 300 3>&- & echo $! > \"$CARRIER_PID_FILE\"; wait",
        )
        .env("TRANSCRIPT", &transcript)
        .env("INSTANCE", name)
        .env("SLEEP_BIN", &sleep)
        .env("CARRIER_PID_FILE", &carrier_pid_file)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the live seat");
    let seat = Seat {
        carrier: wait_for_child_pid(&carrier_pid_file),
        owner,
        marker: format!("HCOM_INSTANCE_NAME={name}"),
    };
    assert_eq!(parent_pid(seat.carrier), Some(seat.owner.id()));
    assert_eq!(comm(seat.owner.id()), "omp", "the seat must look like omp");
    seat
}

/// The henu incident end to end: `hcom kill` names the orphan and points at
/// `hcom stop`; `hcom stop` releases row and binding with a stopped record,
/// lists the orphan it did not signal, and the orphan keeps running.
#[test]
fn stop_releases_the_henu_shape_and_leaves_its_orphan_running() {
    become_subreaper();
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let name = format!("henu-{suffix}");
    let session = format!("sid-henu-{suffix}");
    let binding = format!("omp-{}-a470463d-6617c1b8", dead_pid(&h));
    let db = open_db(&h);
    seed_dead_seat_row(&db, &name, &session, &binding);
    let carrier = adopt_carrier(&h, &name);
    let me = std::process::id();
    assert_eq!(
        parent_pid(carrier.pid),
        Some(me),
        "the carrier must be adopted by the subreaper, not a root of '{name}'"
    );

    let (code, stdout, stderr) = h.run(["kill", name.as_str()]);
    assert_ne!(
        code, 0,
        "kill must refuse: stdout={stdout}; stderr={stderr}"
    );
    let refusal = format!("{stdout}{stderr}");
    assert!(
        refusal.contains(&carrier.pid.to_string())
            && refusal.contains(&format!("hcom stop {name}")),
        "kill must name the orphan and point at stop: {refusal}"
    );
    assert_eq!(rows_named(&db, &name), 1, "a refused kill released the row");
    assert!(live(carrier.pid), "kill signalled the orphan");

    let (code, stdout, stderr) = h.run(["stop", name.as_str()]);
    assert_eq!(
        code, 0,
        "stop must release: stdout={stdout}; stderr={stderr}"
    );
    assert!(stdout.contains("Not signalled"), "{stdout}");
    let listed = format!("pid {} ({}), ppid {me}", carrier.pid, comm(carrier.pid));
    assert!(
        stdout.contains(&listed),
        "stop must list '{listed}': {stdout}"
    );
    assert_eq!(rows_named(&db, &name), 0, "the row survived the stop");
    assert_eq!(binding_owner(&db, &binding), None, "the binding survived");
    assert_eq!(stopped_events(&db, &name), 1);
    assert!(
        live(carrier.pid) && environ_carries(carrier.pid, &carrier.marker),
        "stop signalled the orphan"
    );
}

/// Regression of 0.7.38: a pid-less row with a dead minted binding whose
/// live `omp` still holds the session transcript, with a carrier child.
/// The stop refuses exactly as before and leaves everything in place.
#[test]
fn stop_still_refuses_a_live_seat_with_a_carrier_child() {
    become_subreaper();
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let name = format!("valo-{suffix}");
    let session = format!("sid-valo-{suffix}");
    let binding = format!("omp-{}-5ea7-{suffix}", dead_pid(&h));
    let db = open_db(&h);
    seed_dead_seat_row(&db, &name, &session, &binding);
    let mut seat = spawn_live_seat(&h, &name, &session);

    let (code, stdout, stderr) = h.run(["stop", name.as_str()]);
    assert_ne!(
        code, 0,
        "stop must refuse: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains("cannot prove process ownership"),
        "the refusal is the existing one: {stderr}"
    );
    assert_eq!(rows_named(&db, &name), 1, "a refused stop released the row");
    assert_eq!(binding_owner(&db, &binding).as_deref(), Some(name.as_str()));
    assert_eq!(stopped_events(&db, &name), 0);
    assert!(
        seat.owner.try_wait().expect("poll the seat").is_none(),
        "the seat's omp was signalled"
    );
    assert!(
        live(seat.carrier) && environ_carries(seat.carrier, &seat.marker),
        "the seat's carrier was signalled"
    );
}

/// A parent row with no process of its own, and `child` linked under it by
/// `parent_name`: a stop of the parent stops the child first.
fn seed_parent_of(db: &rusqlite::Connection, parent: &str, child: &str) {
    db.execute(
        "INSERT INTO instances (name, tool, pid, session_id, status, status_context, status_time, created_at, last_event_id)
         VALUES (?1, 'omp', NULL, ?2, 'listening', 'start', 0, 0, 0)",
        rusqlite::params![parent, format!("sid-{parent}")],
    )
    .expect("seed parent row");
    db.execute(
        "UPDATE instances SET parent_name = ?1 WHERE name = ?2",
        rusqlite::params![parent, child],
    )
    .expect("link the child");
}

/// A child row a dead seat left (the henu shape, one orphan carrier) under
/// a parent being stopped: the parent's stop releases the child with no
/// signal, lists the child's orphan, and succeeds.
#[test]
fn parent_stop_releases_an_orphan_only_child_and_leaves_its_orphan_running() {
    become_subreaper();
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let parent = format!("pare-{suffix}");
    let child = format!("chil-{suffix}");
    let binding = format!("omp-{}-c41d-{suffix}", dead_pid(&h));
    let db = open_db(&h);
    seed_dead_seat_row(&db, &child, &format!("sid-{child}"), &binding);
    seed_parent_of(&db, &parent, &child);
    let carrier = adopt_carrier(&h, &child);
    let me = std::process::id();
    assert_eq!(parent_pid(carrier.pid), Some(me));

    let (code, stdout, stderr) = h.run(["stop", parent.as_str()]);
    assert_eq!(
        code, 0,
        "the parent's stop must succeed: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stdout.contains(&format!("still carry {child}'s identity")),
        "stop must list the child's orphans: {stdout}"
    );
    let listed = format!("pid {} ({}), ppid {me}", carrier.pid, comm(carrier.pid));
    assert!(
        stdout.contains(&listed),
        "stop must list '{listed}': {stdout}"
    );
    assert_eq!(rows_named(&db, &parent), 0, "the parent survived its stop");
    assert_eq!(
        rows_named(&db, &child),
        0,
        "the child survived its parent's stop"
    );
    assert_eq!(
        binding_owner(&db, &binding),
        None,
        "the child's binding survived"
    );
    assert_eq!(stopped_events(&db, &child), 1);
    assert_eq!(stopped_events(&db, &parent), 1);
    assert!(
        live(carrier.pid) && environ_carries(carrier.pid, &carrier.marker),
        "the parent's stop signalled the child's orphan"
    );
}

/// A child that is a live seat (an `omp` holding its transcript, with a
/// carrier child) still fails its parent's stop exactly as before: the
/// child is rooted, so nothing is released and nothing is signalled.
#[test]
fn parent_stop_still_refuses_over_a_live_child_seat() {
    become_subreaper();
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let parent = format!("pare-{suffix}");
    let child = format!("chil-{suffix}");
    let session = format!("sid-{child}");
    let binding = format!("omp-{}-c41d-{suffix}", dead_pid(&h));
    let db = open_db(&h);
    seed_dead_seat_row(&db, &child, &session, &binding);
    seed_parent_of(&db, &parent, &child);
    let mut seat = spawn_live_seat(&h, &child, &session);

    let (code, stdout, stderr) = h.run(["stop", parent.as_str()]);
    assert_ne!(
        code, 0,
        "stop must refuse: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains(&format!("could not stop child {child}"))
            && stderr.contains("cannot prove process ownership"),
        "the refusal is the existing one: {stderr}"
    );
    assert_eq!(
        rows_named(&db, &parent),
        1,
        "a refused stop released the parent"
    );
    assert_eq!(
        rows_named(&db, &child),
        1,
        "a refused stop released the child"
    );
    assert_eq!(
        binding_owner(&db, &binding).as_deref(),
        Some(child.as_str())
    );
    assert_eq!(stopped_events(&db, &child), 0);
    assert!(
        seat.owner.try_wait().expect("poll the seat").is_none(),
        "the child seat's omp was signalled"
    );
    assert!(
        live(seat.carrier) && environ_carries(seat.carrier, &seat.marker),
        "the child seat's carrier was signalled"
    );
}

/// The henu shape with a claude tool row: resume plans never gate a claude
/// row on a session file, so the preview path is exercisable without one.
fn seed_dead_claude_row(db: &rusqlite::Connection, name: &str, session_id: &str, binding: &str) {
    db.execute(
        "INSERT INTO instances (name, tool, pid, session_id, status, status_context, status_time, created_at, last_event_id, launch_context)
         VALUES (?1, 'claude', NULL, ?2, 'listening', 'start', 0, 0, 0, ?3)",
        rusqlite::params![
            name,
            session_id,
            format!("{{\"process_id\":\"{binding}\"}}")
        ],
    )
    .expect("seed claude row");
    db.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![binding, session_id, name],
    )
    .expect("seed claude binding");
}

/// A child row nothing can prove dead or alive: no pid, no session, no
/// bindings. Its carriers classify Undetermined (fail toward keep).
fn seed_undetermined_child(db: &rusqlite::Connection, child: &str) {
    db.execute(
        "INSERT INTO instances (name, tool, pid, session_id, status, status_context, status_time, created_at, last_event_id)
         VALUES (?1, 'claude', NULL, NULL, 'listening', 'start', 0, 0, 0)",
        rusqlite::params![child],
    )
    .expect("seed undetermined child row");
}

/// Link an already-seeded child under an already-seeded parent by
/// `parent_name` ([`seed_parent_of`] also inserts the parent row).
fn link_native_child(db: &rusqlite::Connection, parent: &str, child: &str) {
    db.execute(
        "UPDATE instances SET parent_name = ?1 WHERE name = ?2",
        rusqlite::params![parent, child],
    )
    .expect("link the child");
}

/// Fix A: `hcom r` without `--go` on an orphan-only parent is a preview. It
/// classifies the stale row read-only, says `--go` will release it, and
/// writes nothing: the row, its binding and its orphans are unchanged, and
/// there is no new stopped event.
#[test]
fn resume_preview_of_orphan_only_parent_writes_nothing() {
    become_subreaper();
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let parent = format!("prev-{suffix}");
    let session = format!("sid-{parent}");
    let binding = format!("omp-{}-d34d-{suffix}", dead_pid(&h));
    let db = open_db(&h);
    seed_dead_claude_row(&db, &parent, &session, &binding);
    let carrier = adopt_carrier(&h, &parent);
    let stopped_before = stopped_events(&db, &parent);

    let out = h
        .cmd()
        .env("CLAUDECODE", "1")
        .args(["r", parent.as_str(), "--terminal", "kitty"])
        .output()
        .expect("run the resume preview");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        code, 0,
        "preview must succeed: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stdout.contains("will be released") && stdout.contains(&parent),
        "preview must say the stale row will be released: {stdout}"
    );
    assert!(
        stdout.contains(&carrier.pid.to_string()),
        "preview must name the orphan it leaves running: {stdout}"
    );
    assert_eq!(rows_named(&db, &parent), 1, "preview released the row");
    assert_eq!(
        binding_owner(&db, &binding).as_deref(),
        Some(parent.as_str()),
        "preview released the binding"
    );
    assert_eq!(
        stopped_events(&db, &parent),
        stopped_before,
        "preview wrote a stopped event"
    );
    assert!(
        live(carrier.pid) && environ_carries(carrier.pid, &carrier.marker),
        "preview signalled the orphan"
    );
}

/// Fix A, executing half: the same parent resumed for real releases its
/// stale row with no signal (the plan then fails on the missing omp session
/// file, before any launch, which is what the exit code proves).
#[test]
fn resume_executes_the_release_of_an_orphan_only_parent() {
    become_subreaper();
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let parent = format!("rexe-{suffix}");
    let session = format!("sid-{parent}");
    let binding = format!("omp-{}-e14c-{suffix}", dead_pid(&h));
    let db = open_db(&h);
    seed_dead_seat_row(&db, &parent, &session, &binding);
    let carrier = adopt_carrier(&h, &parent);

    let (code, stdout, stderr) = h.run(["r", parent.as_str()]);
    assert_ne!(
        code, 0,
        "resume must fail past the release on the missing session file: stdout={stdout}; stderr={stderr}"
    );
    let output = format!("{stdout}{stderr}");
    assert!(
        output.contains(&format!("Released '{parent}'")),
        "resume must report the release: {output}"
    );
    assert!(
        output.contains(&carrier.pid.to_string()),
        "resume must name the orphan it left running: {output}"
    );
    assert_eq!(rows_named(&db, &parent), 0, "executing resume kept the row");
    assert_eq!(
        binding_owner(&db, &binding),
        None,
        "executing resume kept the binding"
    );
    assert_eq!(stopped_events(&db, &parent), 1);
    assert!(
        live(carrier.pid) && environ_carries(carrier.pid, &carrier.marker),
        "executing resume signalled the orphan"
    );
}

/// Fix B: an orphan-only parent whose native child is a live seat refuses
/// `hcom stop`: the child row and its binding stay intact and neither the
/// seat's process nor its carrier is signalled.
#[test]
fn stop_refuses_orphan_only_parent_with_live_child() {
    become_subreaper();
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let parent = format!("parl-{suffix}");
    let child = format!("chil-{suffix}");
    let parent_session = format!("sid-{parent}");
    let session = format!("sid-{child}");
    let parent_binding = format!("omp-{}-b1a4-{suffix}", dead_pid(&h));
    let child_binding = format!("omp-{}-c41d-{suffix}", dead_pid(&h));
    let db = open_db(&h);
    seed_dead_seat_row(&db, &parent, &parent_session, &parent_binding);
    seed_dead_seat_row(&db, &child, &session, &child_binding);
    link_native_child(&db, &parent, &child);
    let carrier = adopt_carrier(&h, &parent);
    let mut seat = spawn_live_seat(&h, &child, &session);

    let (code, stdout, stderr) = h.run(["stop", parent.as_str()]);
    assert_ne!(
        code, 0,
        "stop must refuse: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains("refusing the signal-free release") && stderr.contains(&child),
        "the refusal must name the live child: {stderr}"
    );
    assert_eq!(
        rows_named(&db, &parent),
        1,
        "a refused stop released the parent"
    );
    assert_eq!(
        rows_named(&db, &child),
        1,
        "a refused stop released the child"
    );
    assert_eq!(
        binding_owner(&db, &parent_binding).as_deref(),
        Some(parent.as_str())
    );
    assert_eq!(
        binding_owner(&db, &child_binding).as_deref(),
        Some(child.as_str())
    );
    assert_eq!(stopped_events(&db, &parent), 0);
    assert_eq!(stopped_events(&db, &child), 0);
    assert!(
        live(carrier.pid) && environ_carries(carrier.pid, &carrier.marker),
        "the refused stop signalled the parent's orphan"
    );
    assert!(
        seat.owner.try_wait().expect("poll the seat").is_none(),
        "the child seat's omp was signalled"
    );
    assert!(
        live(seat.carrier) && environ_carries(seat.carrier, &seat.marker),
        "the child seat's carrier was signalled"
    );
}

/// Fix B: the same family under `hcom r` keeps today's "still active"
/// refusal and changes nothing.
#[test]
fn resume_refuses_orphan_only_parent_with_live_child() {
    become_subreaper();
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let parent = format!("parl-{suffix}");
    let child = format!("chir-{suffix}");
    let parent_session = format!("sid-{parent}");
    let session = format!("sid-{child}");
    let parent_binding = format!("omp-{}-b1a4-{suffix}", dead_pid(&h));
    let child_binding = format!("omp-{}-c41d-{suffix}", dead_pid(&h));
    let db = open_db(&h);
    seed_dead_seat_row(&db, &parent, &parent_session, &parent_binding);
    seed_dead_seat_row(&db, &child, &session, &child_binding);
    link_native_child(&db, &parent, &child);
    let carrier = adopt_carrier(&h, &parent);
    let mut seat = spawn_live_seat(&h, &child, &session);

    let (code, stdout, stderr) = h.run(["r", parent.as_str()]);
    assert_ne!(
        code, 0,
        "resume must refuse: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        format!("{stdout}{stderr}").contains(&format!("'{parent}' is still active")),
        "the refusal is today's still-active one: stdout={stdout}; stderr={stderr}"
    );
    assert_eq!(
        rows_named(&db, &parent),
        1,
        "a refused resume released the parent"
    );
    assert_eq!(
        rows_named(&db, &child),
        1,
        "a refused resume released the child"
    );
    assert_eq!(stopped_events(&db, &parent), 0);
    assert_eq!(stopped_events(&db, &child), 0);
    assert!(
        live(carrier.pid) && environ_carries(carrier.pid, &carrier.marker),
        "the refused resume signalled the parent's orphan"
    );
    assert!(
        seat.owner.try_wait().expect("poll the seat").is_none(),
        "the child seat's omp was signalled"
    );
    assert!(
        live(seat.carrier) && environ_carries(seat.carrier, &seat.marker),
        "the child seat's carrier was signalled"
    );
}

/// Fix B: a child nothing can prove dead (no pid, no session, no bindings)
/// fails the whole signal-free release toward keep, on both `hcom stop` and
/// `hcom r`.
#[test]
fn stop_and_resume_refuse_orphan_only_parent_with_undetermined_child() {
    become_subreaper();
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let parent = format!("paru-{suffix}");
    let child = format!("chiu-{suffix}");
    let parent_session = format!("sid-{parent}");
    let parent_binding = format!("omp-{}-b1a4-{suffix}", dead_pid(&h));
    let db = open_db(&h);
    seed_dead_seat_row(&db, &parent, &parent_session, &parent_binding);
    seed_undetermined_child(&db, &child);
    link_native_child(&db, &parent, &child);
    let parent_carrier = adopt_carrier(&h, &parent);
    let child_carrier = adopt_carrier(&h, &child);

    let (code, stdout, stderr) = h.run(["stop", parent.as_str()]);
    assert_ne!(
        code, 0,
        "stop must refuse: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains(&child) && stderr.contains("cannot be proven dead"),
        "the refusal must name the undetermined child: {stderr}"
    );

    let (code, stdout, stderr) = h.run(["r", parent.as_str()]);
    assert_ne!(
        code, 0,
        "resume must refuse: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        format!("{stdout}{stderr}").contains(&format!("'{parent}' is still active")),
        "the refusal is today's still-active one: stdout={stdout}; stderr={stderr}"
    );

    assert_eq!(
        rows_named(&db, &parent),
        1,
        "a refused release dropped the parent"
    );
    assert_eq!(
        rows_named(&db, &child),
        1,
        "a refused release dropped the child"
    );
    assert_eq!(
        binding_owner(&db, &parent_binding).as_deref(),
        Some(parent.as_str())
    );
    assert_eq!(stopped_events(&db, &parent), 0);
    assert_eq!(stopped_events(&db, &child), 0);
    assert!(
        live(parent_carrier.pid) && environ_carries(parent_carrier.pid, &parent_carrier.marker),
        "the refused release signalled the parent's orphan"
    );
    assert!(
        live(child_carrier.pid) && environ_carries(child_carrier.pid, &child_carrier.marker),
        "the refused release signalled the child's carrier"
    );
}

/// Fix C (ffc-7osfm): a parent stop that releases an orphan-only child and
/// then fails on a later live child still lists the released child's
/// orphans and says they were not signalled.
#[test]
fn parent_stop_reports_released_orphan_when_a_later_child_fails() {
    become_subreaper();
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated DB: {stderr}");
    let suffix = unique_suffix();
    let parent = format!("par7-{suffix}");
    let released_child = format!("chi7-{suffix}");
    let live_child = format!("chj7-{suffix}");
    let released_session = format!("sid-{released_child}");
    let live_session = format!("sid-{live_child}");
    let released_binding = format!("omp-{}-d007-{suffix}", dead_pid(&h));
    let live_binding = format!("omp-{}-1f1e-{suffix}", dead_pid(&h));
    let db = open_db(&h);
    seed_dead_seat_row(&db, &released_child, &released_session, &released_binding);
    seed_dead_seat_row(&db, &live_child, &live_session, &live_binding);
    seed_parent_of(&db, &parent, &live_child);
    // The released child hangs off the session set (stopped first); the
    // live child hangs off the native set (fails after).
    db.execute(
        "UPDATE instances SET parent_session_id = ?1 WHERE name = ?2",
        rusqlite::params![format!("sid-{parent}"), released_child],
    )
    .expect("link the released child by session");
    let orphan = adopt_carrier(&h, &released_child);
    let mut seat = spawn_live_seat(&h, &live_child, &live_session);

    let (code, stdout, stderr) = h.run(["stop", parent.as_str()]);
    assert_ne!(
        code, 0,
        "stop must fail on the live child: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains(&format!("could not stop child {live_child}")),
        "the error must name the live child: {stderr}"
    );
    assert!(
        stdout.contains(&released_child)
            && stdout.contains("Not signalled")
            && stdout.contains(&orphan.pid.to_string()),
        "the error path must still list the released child's orphan: {stdout}"
    );
    assert_eq!(
        rows_named(&db, &released_child),
        0,
        "the released child survived"
    );
    assert_eq!(
        binding_owner(&db, &released_binding),
        None,
        "the released child's binding survived"
    );
    assert_eq!(stopped_events(&db, &released_child), 1);
    assert_eq!(
        rows_named(&db, &parent),
        1,
        "a failed stop released the parent"
    );
    assert_eq!(
        rows_named(&db, &live_child),
        1,
        "a failed stop released the live child"
    );
    assert_eq!(stopped_events(&db, &parent), 0);
    assert_eq!(stopped_events(&db, &live_child), 0);
    assert!(
        live(orphan.pid) && environ_carries(orphan.pid, &orphan.marker),
        "the failed stop signalled the released child's orphan"
    );
    assert!(
        seat.owner.try_wait().expect("poll the seat").is_none(),
        "the live child's omp was signalled"
    );
    assert!(
        live(seat.carrier) && environ_carries(seat.carrier, &seat.marker),
        "the live child's carrier was signalled"
    );
}
