//! A stopped omp seat's own late `omp-start` must not resurrect its row
//! (ffc-vpqoz). omp emits `session_shutdown` before it aborts the agent, so
//! an exiting seat's plugin releases its row (`omp-stop`) and then re-runs
//! `omp-start` from the aborted turn's events. Bind Path 2 used to restore the
//! stopped snapshot for that dying process: a ghost row until the vanished
//! sweep, and `hcom stop` reporting a clean stop as failed.
//!
//! The rule under test: the automatic `omp-start` hook never restores a
//! stopped row for the very process whose stop was recorded, whoever stopped
//! it. A different process (a resume) restores, "the same process" is its
//! full incarnation (never a bare pid), and an explicit `hcom start --as`
//! from the stopped process still rejoins.
//!
//! Real processes, the `tests/omp_identity_mint.rs` way: a bash exec'd from a
//! file named `omp` is the provable OMP ancestor of every hook it runs, and
//! presents `omp-<its pid>-1-1` only to those hooks (the plugin's minted id
//! lives in its JS env, never in omp's own /proc environ). Linux only.

#![cfg(target_os = "linux")]

mod support;

use std::fs;
use std::os::unix::fs as unix_fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};
use support::{Hcom, unique_suffix};

use serde_json::{Value, json};

/// The fake omp session. Each `go-<step>` file the test creates runs that
/// step once, writing `<step>.json`, `<step>.stderr` and `<step>.code`:
/// `start` and `late-start` run the `omp-start` hook as this process,
/// `release` releases its row with `omp-stop` while it keeps running, and
/// `rejoin` runs `hcom start --as` as this process. SIGTERM plays omp's
/// signal exit: `session_shutdown` releases the row (`omp-stop`, what the
/// plugin's `releaseOwnerSync` runs), the aborted turn's events re-run
/// `omp-start`, then the process exits.
const FAKE_OMP_SCRIPT: &str = r#"
cd "$TEST_OUT_DIR" || exit 1
H() { HCOM_PROCESS_ID="omp-$$-1-1" HCOM_LAUNCHED=1 HCOM_TOOL=omp "$TEST_BIN" "$@"; }
step() {
    n=$1
    shift
    "$@" > "$n.json" 2> "$n.stderr"
    printf "%s" "$?" > "$n.code"
}
bound_name() { sed -n 's/.*"name":"\([^"]*\)".*/\1/p' start.json; }
rejoin_as() {
    local name
    name=$(bound_name)
    (cd "$TEST_CWD" && H start --as "$name")
}
on_term() {
    step exit-stop H omp-stop --name "$(bound_name)" --reason shutdown
    step exit-start H omp-start --session-id "$TEST_SID" --cwd "$TEST_CWD"
    exit 0
}
trap on_term TERM
while :; do
    for s in start late-start release rejoin; do
        [ -e "go-$s" ] && [ ! -e "$s.code" ] || continue
        case $s in
            start|late-start) step "$s" H omp-start --session-id "$TEST_SID" --cwd "$TEST_CWD" ;;
            release) step "$s" H omp-stop --name "$(bound_name)" --reason external ;;
            rejoin) step "$s" rejoin_as ;;
        esac
    done
    sleep 0.2 & wait $!
done
"#;

struct FakeOmp {
    child: Child,
    out_dir: PathBuf,
}

impl FakeOmp {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The id this process presents to its hooks.
    fn process_id(&self) -> String {
        format!("omp-{}-1-1", self.pid())
    }

    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.out_dir.join(name)).unwrap_or_default()
    }

    /// Run `step` as this process and return `(exit code, parsed JSON)`.
    fn run_step(&self, h: &Hcom, step: &str) -> (String, Value) {
        fs::write(self.out_dir.join(format!("go-{step}")), "").expect("write go file");
        self.wait_step(h, step)
    }

    fn wait_step(&self, h: &Hcom, step: &str) -> (String, Value) {
        let code_file = self.out_dir.join(format!("{step}.code"));
        h.eventually(
            &format!("fake omp step {step}"),
            Duration::from_secs(180),
            || {
                Ok(fs::read_to_string(&code_file)
                    .ok()
                    .filter(|code| !code.is_empty()))
            },
        );
        let stdout = self.read(&format!("{step}.json"));
        let parsed = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
        (self.read(&format!("{step}.code")), parsed)
    }

    fn detail(&self, step: &str) -> String {
        format!(
            "{step}: stdout={} stderr={}",
            self.read(&format!("{step}.json")).trim(),
            self.read(&format!("{step}.stderr")).trim()
        )
    }

    fn kill(&mut self) {
        unsafe {
            libc::killpg(self.child.id() as libc::pid_t, libc::SIGKILL);
        }
        let _ = self.child.wait();
    }
}

fn spawn_fake_omp(h: &Hcom, tag: &str, session_id: &str) -> FakeOmp {
    let fakebin = h.root_path().join("fakebin");
    fs::create_dir_all(&fakebin).expect("create fakebin dir");
    let omp = fakebin.join("omp");
    if !omp.exists() {
        unix_fs::symlink("/bin/bash", &omp).expect("symlink omp -> /bin/bash");
    }
    let out_dir = h.root_path().join(format!("session-{tag}"));
    fs::create_dir_all(&out_dir).expect("create session out dir");
    let script = out_dir.join("session.sh");
    fs::write(&script, FAKE_OMP_SCRIPT).expect("write session script");
    let child = h
        .external_cmd(&omp)
        .arg(&script)
        .env_remove("HCOM_PROCESS_ID")
        .env("TEST_OUT_DIR", &out_dir)
        .env("TEST_BIN", env!("CARGO_BIN_EXE_hcom"))
        .env("TEST_SID", session_id)
        .env("TEST_CWD", &h.workspace)
        .process_group(0)
        .spawn()
        .unwrap_or_else(|e| panic!("spawn fake omp {tag}: {e}"));
    h.track_cleanup_pid(child.id() as i64);
    FakeOmp { child, out_dir }
}

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

/// An isolated hcom with its schema created and plain omp sessions opted in,
/// so a provable OMP process mints its own identity.
fn plain_session_hcom() -> Hcom {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");
    fs::write(
        h.path().join("config.toml"),
        "[launch.omp]\nplain_sessions = true\n",
    )
    .expect("write isolated config.toml");
    h
}

fn open_db(h: &Hcom) -> rusqlite::Connection {
    rusqlite::Connection::open(h.path().join("hcom.db")).expect("open isolated hcom.db")
}

fn row_count(h: &Hcom, name: &str) -> i64 {
    open_db(h)
        .query_row(
            "SELECT COUNT(*) FROM instances WHERE name = ?1",
            [name],
            |r| r.get(0),
        )
        .expect("count rows")
}

fn life_count(h: &Hcom, name: &str, action: &str) -> i64 {
    open_db(h)
        .query_row(
            "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = ?1
               AND json_extract(data, '$.action') = ?2",
            [name, action],
            |r| r.get(0),
        )
        .expect("count life events")
}

fn bound_instance(h: &Hcom, process_id: &str) -> Option<String> {
    open_db(h)
        .query_row(
            "SELECT instance_name FROM process_bindings WHERE process_id = ?1",
            [process_id],
            |r| r.get(0),
        )
        .ok()
}

fn skipped_restore_logs(h: &Hcom, name: &str) -> usize {
    let log = fs::read_to_string(h.path().join(".tmp/logs/hcom.log")).unwrap_or_default();
    let needle = format!("instance={name} ");
    log.lines()
        .filter(|line| {
            line.contains("omp-start.own_stop_restore_skipped") && line.contains(&needle)
        })
        .count()
}

/// Bind `omp` to `session_id` as a plain session; returns the minted name.
fn bind(h: &Hcom, omp: &FakeOmp) -> String {
    let (code, start) = omp.run_step(h, "start");
    assert_eq!(code, "0", "{}", omp.detail("start"));
    let name = start["name"]
        .as_str()
        .unwrap_or_else(|| panic!("no name bound: {}", omp.detail("start")))
        .to_string();
    assert_eq!(
        bound_instance(h, &omp.process_id()).as_deref(),
        Some(name.as_str())
    );
    name
}

/// The late start answered success without binding anything.
fn assert_start_was_noop(omp: &FakeOmp, step: &str, code: &str, response: &Value) {
    assert_eq!(code, "0", "{}", omp.detail(step));
    assert!(
        response.get("name").is_none() && response.get("error").is_none(),
        "late omp-start bound or failed: {}",
        omp.detail(step)
    );
    assert_eq!(response["restored"], json!(false), "{}", omp.detail(step));
}

/// Boot-relative start ticks (field 22 of /proc/<pid>/stat) and the boot id:
/// the incarnation stop snapshots record beside a pid.
fn live_incarnation(pid: u32) -> (u64, String) {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("read stat");
    let after_comm = &stat[stat.rfind(')').expect("stat comm") + 2..];
    let start: u64 = after_comm
        .split_whitespace()
        .nth(19)
        .expect("stat starttime")
        .parse()
        .expect("parse starttime");
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").expect("read boot id");
    (start, boot.trim().to_string())
}

/// `hcom stop` of a bound seat from outside its tree: the stop signals the
/// seat, which runs its exit path. Returns the stop's `(code, stdout, stderr)`
/// once the seat has exited.
fn stop_seat(h: &Hcom, omp: &mut FakeOmp, name: &str) -> (i32, String, String) {
    let stop = h.run(["stop", name]);
    let exited = wait_with_deadline(&mut omp.child, Duration::from_secs(30));
    if exited.is_none() {
        omp.kill();
    }
    assert!(
        exited.is_some(),
        "the stop never signalled the seat: {stop:?}"
    );
    stop
}

#[test]
fn exiting_seat_late_start_leaves_no_row_and_stop_succeeds() {
    // The fleet-down shape (zani, mila): `hcom stop` signals the seat, whose
    // exit path releases its own row and then re-runs omp-start.
    let h = plain_session_hcom();
    let sid = format!("sid-exit-{}", unique_suffix());
    let mut omp = spawn_fake_omp(&h, "exit", &sid);
    let name = bind(&h, &omp);

    let (stop_code, stop_out, stop_err) = stop_seat(&h, &mut omp, &name);
    let (code, _) = omp.wait_step(&h, "exit-stop");
    assert_eq!(code, "0", "{}", omp.detail("exit-stop"));
    let (code, response) = omp.wait_step(&h, "exit-start");
    assert_start_was_noop(&omp, "exit-start", &code, &response);

    assert_eq!(
        stop_code, 0,
        "hcom stop reported a clean stop as failed: {stop_out} {stop_err}"
    );
    assert!(
        !format!("{stop_out}{stop_err}").contains("re-registered"),
        "{stop_out} {stop_err}"
    );
    assert_eq!(
        row_count(&h, &name),
        0,
        "the exiting seat's row was resurrected"
    );
    // A minted bind writes no `created`; a restore would.
    assert_eq!(
        life_count(&h, &name, "created"),
        0,
        "the late start restored"
    );
    assert_eq!(bound_instance(&h, &omp.process_id()), None);
    assert_eq!(skipped_restore_logs(&h, &name), 1);
}

#[test]
fn new_process_start_after_stop_restores_the_row() {
    // The resume: a different process running the stopped session restores
    // exactly as before, after the stopped process's own late start was
    // refused.
    let h = plain_session_hcom();
    let sid = format!("sid-resume-{}", unique_suffix());
    let mut first = spawn_fake_omp(&h, "resume-first", &sid);
    let name = bind(&h, &first);
    let (stop_code, stop_out, stop_err) = stop_seat(&h, &mut first, &name);
    assert_eq!(stop_code, 0, "{stop_out} {stop_err}");
    let (code, response) = first.wait_step(&h, "exit-start");
    assert_start_was_noop(&first, "exit-start", &code, &response);
    assert_eq!(row_count(&h, &name), 0);

    let mut second = spawn_fake_omp(&h, "resume-second", &sid);
    let (code, start) = second.run_step(&h, "start");
    assert_eq!(code, "0", "{}", second.detail("start"));
    assert_eq!(
        start["name"].as_str(),
        Some(name.as_str()),
        "{}",
        second.detail("start")
    );
    assert_eq!(
        row_count(&h, &name),
        1,
        "the resume did not restore the row"
    );
    assert_eq!(
        bound_instance(&h, &second.process_id()).as_deref(),
        Some(name.as_str())
    );
    assert_eq!(skipped_restore_logs(&h, &name), 1);
    second.kill();
}

#[test]
fn stopped_live_process_hook_does_not_restore_but_explicit_start_rejoins() {
    // A stop that is not the seat's own exit, of a process that keeps
    // running. On Linux an external `hcom stop` either signals the seat or
    // refuses, so the stopped-but-alive state comes from the seat's own
    // `omp-stop`, attributed afterwards to an external caller the way `hcom
    // stop` records it. Its automatic omp-start must not undo that stop; its
    // explicit `hcom start --as` rejoins as it always could.
    let h = plain_session_hcom();
    let sid = format!("sid-external-{}", unique_suffix());
    let mut omp = spawn_fake_omp(&h, "external", &sid);
    let name = bind(&h, &omp);

    let (code, _) = omp.run_step(&h, "release");
    assert_eq!(code, "0", "{}", omp.detail("release"));
    assert!(
        omp.child.try_wait().expect("poll seat").is_none(),
        "the release ended the seat"
    );
    assert_eq!(row_count(&h, &name), 0);
    let rewritten = open_db(&h)
        .execute(
            "UPDATE events SET data = json_set(data, '$.by', 'cli', '$.reason', 'external')
             WHERE type = 'life' AND instance = ?1 AND json_extract(data, '$.action') = 'stopped'",
            [&name],
        )
        .expect("attribute the stop to an external caller");
    assert_eq!(rewritten, 1);

    let (code, response) = omp.run_step(&h, "late-start");
    assert_start_was_noop(&omp, "late-start", &code, &response);
    assert_eq!(row_count(&h, &name), 0, "the hook undid the stop");
    assert_eq!(
        life_count(&h, &name, "created"),
        0,
        "the late start restored"
    );
    assert_eq!(skipped_restore_logs(&h, &name), 1);

    let (code, _) = omp.run_step(&h, "rejoin");
    assert_eq!(code, "0", "{}", omp.detail("rejoin"));
    assert_eq!(row_count(&h, &name), 1, "explicit start did not rejoin");
    assert_eq!(
        bound_instance(&h, &omp.process_id()).as_deref(),
        Some(name.as_str()),
        "the rejoined row is not bound to the stopped process"
    );
    omp.kill();
}

/// Record a stop of `name` for `session_id` by a launcher-launched seat: the
/// stop carries the launcher id, the snapshot the omp pid with `start_time`.
/// This is the shape zani's stop had; its plugin then presented a re-minted
/// `omp-<pid>-...` id, never the recorded one.
fn record_launcher_stop(h: &Hcom, name: &str, session_id: &str, pid: u32, start_time: u64) {
    let (_, boot_id) = live_incarnation(pid);
    let data = json!({
        "action": "stopped",
        "by": "session",
        "reason": "exit:shutdown",
        "process_id": "05ff6619-134c-4f05-88e3-3510b9c267ac",
        "snapshot": {
            "name": name,
            "session_id": session_id,
            "tool": "omp",
            "directory": h.workspace,
            "last_event_id": 0,
            "pid": pid,
            "pid_start_time": start_time,
            "boot_id": boot_id,
        },
    });
    open_db(h)
        .execute(
            "INSERT INTO events (timestamp, type, instance, data)
             VALUES ('2026-09-28T17:05:32.549101+00:00', 'life', ?1, ?2)",
            rusqlite::params![name, data.to_string()],
        )
        .expect("record stop");
}

#[test]
fn same_process_is_its_full_incarnation_not_its_bare_pid() {
    let h = plain_session_hcom();
    let suffix = unique_suffix();

    // Same pid, same start time: the stopped process itself, recognized
    // through the snapshot's anchor although it presents another id.
    let sid_same = format!("sid-same-{suffix}");
    let same_name = format!("same{suffix}");
    let mut same = spawn_fake_omp(&h, "same", &sid_same);
    let (start, _) = live_incarnation(same.pid());
    record_launcher_stop(&h, &same_name, &sid_same, same.pid(), start);
    let (code, response) = same.run_step(&h, "start");
    assert_start_was_noop(&same, "start", &code, &response);
    assert_eq!(row_count(&h, &same_name), 0);
    assert_eq!(skipped_restore_logs(&h, &same_name), 1);
    same.kill();

    // Same pid, different start time: a reused pid is a new process, which
    // restores the row.
    let sid_reused = format!("sid-reused-{suffix}");
    let reused_name = format!("reused{suffix}");
    let mut reused = spawn_fake_omp(&h, "reused", &sid_reused);
    let (start, _) = live_incarnation(reused.pid());
    record_launcher_stop(&h, &reused_name, &sid_reused, reused.pid(), start + 1);
    let (code, response) = reused.run_step(&h, "start");
    assert_eq!(code, "0", "{}", reused.detail("start"));
    assert_eq!(
        response["name"].as_str(),
        Some(reused_name.as_str()),
        "{}",
        reused.detail("start")
    );
    assert_eq!(row_count(&h, &reused_name), 1);
    assert_eq!(
        bound_instance(&h, &reused.process_id()).as_deref(),
        Some(reused_name.as_str())
    );
    assert_eq!(skipped_restore_logs(&h, &reused_name), 0);
    reused.kill();
}
