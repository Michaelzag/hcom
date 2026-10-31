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

const OMP_DRIVER: &str = r#"
printf '%s' "$$" > "$OUT/ready"
HCOM_LAUNCHED=1 HCOM_TOOL=omp "$BIN" omp-start --session-id "$SID" --cwd "$CWD" > "$OUT/start.json" 2> "$OUT/start.stderr"
printf '%s' "$?" > "$OUT/start.code"
while [ ! -f "$OUT/stop.request" ]; do
    sleep 0.05
done
IFS= read -r name < "$OUT/stop.request"
HCOM_LAUNCHED=1 HCOM_TOOL=omp "$BIN" omp-stop --name "$name" --reason shutdown > "$OUT/stop.json" 2> "$OUT/stop.stderr"
exit $?
"#;

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
    // Creates the schema in the isolated HCOM_DIR.
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");
    fs::write(
        h.path().join("config.toml"),
        "[launch.omp]\nplain_sessions = true\n",
    )
    .expect("write fixture-only plain session config");

    let session_id = format!("sid-{}", unique_suffix());
    let fakebin = h.root_path().join("fakebin");
    fs::create_dir_all(&fakebin).expect("create fakebin");
    let omp = fakebin.join("omp");
    unix_fs::symlink("/bin/bash", &omp).expect("symlink omp -> bash");
    let driver = fakebin.join("driver.sh");
    fs::write(&driver, OMP_DRIVER).expect("write fixture OMP driver");
    let out_dir = h.root_path().join("owner");
    fs::create_dir_all(&out_dir).expect("create owner output directory");
    let mut session = h
        .external_cmd(&omp)
        .arg("-c")
        .arg("exec env HCOM_PROCESS_ID=omp-$$-1-1 \"$TEST_OMP\" \"$TEST_DRIVER\"")
        .env("TEST_OMP", &omp)
        .env("TEST_DRIVER", &driver)
        .env("OUT", &out_dir)
        .env("BIN", env!("CARGO_BIN_EXE_hcom"))
        .env("SID", &session_id)
        .env("CWD", &h.workspace)
        .process_group(0)
        .spawn()
        .expect("spawn native OMP owner");
    h.track_cleanup_pid(session.id() as i64);
    h.eventually("native OMP ready", Duration::from_secs(30), || {
        Ok(fs::read_to_string(out_dir.join("ready"))
            .ok()
            .filter(|pid| pid == &session.id().to_string()))
    });
    assert_eq!(
        fs::read_to_string(format!("/proc/{}/comm", session.id()))
            .expect("read native OMP comm")
            .trim(),
        "omp"
    );
    let start_code = h.eventually("owner omp-start", Duration::from_secs(60), || {
        Ok(fs::read_to_string(out_dir.join("start.code"))
            .ok()
            .filter(|code| !code.is_empty()))
    });
    let start_stdout = fs::read_to_string(out_dir.join("start.json")).expect("read start response");
    let start_stderr = fs::read_to_string(out_dir.join("start.stderr")).expect("read start stderr");
    assert_eq!(start_code, "0", "{start_stdout}\n{start_stderr}");
    let start: serde_json::Value =
        serde_json::from_str(&start_stdout).expect("omp-start JSON response");
    assert!(start.get("error").is_none(), "{start}");
    assert_eq!(start["session_id"].as_str(), Some(session_id.as_str()));
    let name = start["name"].as_str().expect("minted OMP name").to_string();
    let process_id = format!("omp-{}-1-1", session.id());
    let db = rusqlite::Connection::open(h.path().join("hcom.db")).expect("open db");
    let binding: (String, String) = db
        .query_row(
            "SELECT session_id, instance_name FROM process_bindings WHERE process_id = ?1",
            [&process_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("native owner process binding");
    assert_eq!(binding, (session_id, name.clone()));
    let (runtime_pid, context): (Option<u32>, String) = db
        .query_row(
            "SELECT pid, launch_context FROM instances WHERE name = ?1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("native owner pin");
    assert_eq!(runtime_pid, Some(session.id()));
    let context: serde_json::Value = serde_json::from_str(&context).expect("launch_context JSON");
    let stat =
        fs::read_to_string(format!("/proc/{}/stat", session.id())).expect("read native OMP stat");
    let fields = &stat[stat.rfind(')').expect("stat comm closing paren") + 2..];
    let ticks = fields
        .split_whitespace()
        .nth(19)
        .expect("native start ticks");
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").expect("read native boot id");
    assert_eq!(
        context["omp_owner"],
        serde_json::json!({
            "pid": session.id(),
            "incarnation": format!("linux:{}:{ticks}", boot.trim())
        })
    );

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
    let stop_request = out_dir.join("stop.pending");
    fs::write(&stop_request, format!("{name}\n")).expect("write owner stop request");
    fs::rename(&stop_request, out_dir.join("stop.request")).expect("publish owner stop request");

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
    let stop_stdout = fs::read_to_string(out_dir.join("stop.json")).expect("read stop response");
    let stop_stderr = fs::read_to_string(out_dir.join("stop.stderr")).expect("read stop stderr");
    let stop: serde_json::Value = serde_json::from_str(&stop_stdout)
        .unwrap_or_else(|error| panic!("omp-stop JSON: {error}\n{stop_stdout}\n{stop_stderr}"));
    assert_eq!(stop["ok"], serde_json::json!(true), "{stop}\n{stop_stderr}");
    assert!(stop.get("error").is_none(), "{stop}\n{stop_stderr}");

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
