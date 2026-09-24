//! Identity minting and inherited-id trust, end to end against the real
//! binary (design `omp-identity` §1–§4).
//!
//! The rule under test: an inherited `HCOM_PROCESS_ID` binds only when its
//! provenance is proven. Launcher UUIDs require a recorded ancestor pid;
//! `omp-<pid>-...` requires a live OMP ancestor. An unanchored launcher row
//! and inherited synthetic id are never OMP identities. `HCOM_LAUNCHED=1`
//! alone proves nothing. Plain OMP sessions join only through the
//! `[launch.omp] plain_sessions` opt-in.
//!
//! Linux only: these integration tests exercise `/proc` ancestry. Windows
//! ToolHelp ancestry is covered by pure walker tests and windows-build CI;
//! macOS currently retains the explicit pre-0.7.30 passthrough.
//!
//! Carrier note: tests/ crates cannot link hcom internals (bin-only crate),
//! so carrier enumeration is observed the way `tests/omp_stop_release.rs`
//! observes it — spawn the tree, drive the CLI, and assert which spawned
//! processes got signalled by the reap.

#![cfg(target_os = "linux")]

mod support;

use std::fs;
use std::io::Write;
use std::os::unix::fs as unix_fs;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use support::{Hcom, unique_suffix};

use serde_json::{Value, json};

/// The same source file the binary embeds as `hcom::hooks::omp::PLUGIN_SOURCE`
/// (`include_str!("../../omp_plugin/hcom.ts")` in `src/hooks/omp/plugin.rs`).
/// A test-crate `include_str!` of the repo file is byte-identical to the
/// binary's embed, which is the only way to byte-compare from out-of-crate.
const PLUGIN_SOURCE: &str = include_str!("../src/omp_plugin/hcom.ts");

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

fn open_db(h: &Hcom) -> rusqlite::Connection {
    rusqlite::Connection::open(h.path().join("hcom.db")).expect("open isolated hcom.db")
}

fn count(db: &rusqlite::Connection, sql: &str, params: &[&str]) -> i64 {
    db.query_row(sql, rusqlite::params_from_iter(params.iter()), |r| r.get(0))
        .expect("count query")
}

/// A pid that is provably not a live process (so it can never be an
/// ancestor): the leaked-desktop-env id shape `omp-<dead pid>-<r>-<r>`.
fn unused_pid() -> u32 {
    (100_000u32..110_000)
        .find(|candidate| !Path::new(&format!("/proc/{candidate}")).exists())
        .expect("find an unused pid candidate")
}

/// Seed the pre-existing identity an intruder must NOT attach to: instance
/// row + session binding + process binding, all owned by `session_id`.
fn seed_identity(h: &Hcom, name: &str, session_id: &str, process_id: &str) {
    let db = open_db(h);
    db.execute(
        "INSERT INTO instances (name, tool, session_id, status, status_context, status_time, created_at, last_event_id)
         VALUES (?1, 'omp', ?2, 'listening', 'start', 0, 0, 0)",
        rusqlite::params![name, session_id],
    )
    .expect("seed instance");
    db.execute(
        "INSERT INTO session_bindings (session_id, instance_name, created_at)
         VALUES (?1, ?2, 0)",
        rusqlite::params![session_id, name],
    )
    .expect("seed session binding");
    db.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![process_id, session_id, name],
    )
    .expect("seed process binding");
}

/// The owner's row and bindings are untouched and the intruder session got
/// nothing — the shared invariant of every leaked-id refusal test.
fn assert_no_bind_and_owner_intact(
    h: &Hcom,
    intruder_sid: &str,
    seeded_name: &str,
    seeded_sid: &str,
    leaked_id: &str,
) {
    let db = open_db(h);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM session_bindings WHERE session_id = ?1",
            &[intruder_sid]
        ),
        0,
        "intruder session acquired a session binding"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM instances WHERE session_id = ?1",
            &[intruder_sid]
        ),
        0,
        "intruder session acquired an instance row"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM process_bindings WHERE process_id = ?1",
            &[leaked_id]
        ),
        1,
        "the leaked id's binding row count changed"
    );
    let (bound_sid, bound_name): (String, String) = db
        .query_row(
            "SELECT session_id, instance_name FROM process_bindings WHERE process_id = ?1",
            [leaked_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("the leaked id's binding row vanished");
    assert_eq!(
        (bound_sid.as_str(), bound_name.as_str()),
        (seeded_sid, seeded_name),
        "the leaked id's binding was re-pointed"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM instances", &[]),
        1,
        "instance count changed"
    );
    let owner_sid: String = db
        .query_row(
            "SELECT session_id FROM instances WHERE name = ?1",
            [seeded_name],
            |r| r.get(0),
        )
        .expect("owner instance row vanished");
    assert_eq!(
        owner_sid, seeded_sid,
        "owner row was re-bound to the intruder"
    );
}

/// Pipe a JSON payload to a JSON-stdin hook while the environment carries the
/// leaked identity (the lotso `.zshenv` shape: a foreign id plus
/// `HCOM_LAUNCHED=1`).
fn run_leaked_hook(h: &Hcom, hook: &str, leaked_id: &str, payload: &Value) {
    let mut cmd = h.cmd();
    cmd.arg(hook);
    cmd.env("HCOM_PROCESS_ID", leaked_id);
    cmd.env("HCOM_LAUNCHED", "1");
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {hook}: {e}"));
    {
        let mut stdin = child.stdin.take().expect("open stdin");
        stdin
            .write_all(payload.to_string().as_bytes())
            .expect("write hook payload");
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait {hook}: {e}"));
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "{hook} stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn enable_plain_sessions(h: &Hcom) {
    fs::write(
        h.path().join("config.toml"),
        "[launch.omp]\nplain_sessions = true\n",
    )
    .expect("write isolated config.toml");
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

/// Inner script of the fake omp session. Runs under the `omp`-named exec (so
/// `/proc/<pid>/comm == "omp"`), with `HCOM_PROCESS_ID=omp-<own pid>-1-1`
/// already in its own environ (set by the `env` re-exec), which makes it both
/// the provable ancestor for the id AND a carrier the /proc environ scan can
/// enumerate. Never exits on its own: the only permitted death is a reap
/// signal, which is what the carrier assertions observe.
const FAKE_OMP_SCRIPT: &str = r#"
printf "%s" "$HCOM_PROCESS_ID" > "$TEST_OUT_DIR/id.txt"
HCOM_LAUNCHED=1 HCOM_TOOL=omp "$TEST_BIN" omp-start --session-id "$TEST_SID" --cwd "$TEST_CWD" \
    > "$TEST_OUT_DIR/start.json" 2> "$TEST_OUT_DIR/start.stderr"
printf "%s" "$?" > "$TEST_OUT_DIR/start.code"
while :; do sleep 1; done
"#;

struct FakeOmpSession {
    child: Child,
    out_dir: PathBuf,
}

impl FakeOmpSession {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.out_dir.join(name)
    }

    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.file(name)).unwrap_or_default()
    }

    /// The id the session minted for itself: `omp-<own pid>-1-1`.
    fn minted_id(&self) -> String {
        format!("omp-{}-1-1", self.pid())
    }

    fn detail(&self, start: &Value) -> String {
        format!("start={start} stderr={} ", self.read("start.stderr").trim())
    }
}

/// Spawn the provable chain: a process exec'd from a file named `omp` (a
/// symlink to /bin/bash) that re-execs itself through `env` to put
/// `HCOM_PROCESS_ID=omp-$$-1-1` into its own environ ($$ survives exec, so
/// the embedded pid IS this ancestor), then runs `hcom omp-start` for
/// `session_id` and stays alive as the session's carrier.
fn spawn_provable_omp_session(h: &Hcom, tag: &str, session_id: &str) -> FakeOmpSession {
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

    let mut command = h.external_cmd(&omp);
    command
        .arg("-c")
        .arg(format!(
            "exec env HCOM_PROCESS_ID=omp-$$-1-1 {} {}",
            shell_quote(&omp),
            shell_quote(&script)
        ))
        .env("TEST_OUT_DIR", &out_dir)
        .env("TEST_BIN", env!("CARGO_BIN_EXE_hcom"))
        .env("TEST_SID", session_id)
        .env("TEST_CWD", &h.workspace)
        // Simulate plugin load inheriting a synthetic id before it replaces
        // that id with this OMP process's own minted identity at exec.
        .env("HCOM_PROCESS_ID", "pid-agy-123")
        .process_group(0);
    let child = command
        .spawn()
        .unwrap_or_else(|e| panic!("spawn fake omp session {tag}: {e}"));
    h.track_cleanup_pid(child.id() as i64);
    FakeOmpSession { child, out_dir }
}

/// Block until the session's `omp-start` run has finished writing its output
/// files, then return `(exit_code_text, parsed start.json)`.
fn wait_for_start(h: &Hcom, session: &FakeOmpSession) -> (String, Value) {
    h.eventually(
        "fake omp session's omp-start output",
        Duration::from_secs(30),
        || match fs::read_to_string(session.file("start.code")) {
            Ok(code) => Ok(Some(code)),
            Err(_) => Ok(None),
        },
    );
    let stdout = session.read("start.json");
    let start: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "start.json: {e}\nstdout={stdout}\nstderr={}",
            session.read("start.stderr")
        )
    });
    (session.read("start.code"), start)
}

#[test]
fn foreign_omp_id_does_not_attach() {
    // Rule pinned (design §1, `omp-<pid>-...` row + §1.1): the id is trusted
    // only when its pid is a live ancestor with comm == "omp", and a leaked
    // `HCOM_LAUNCHED=1` proves nothing on its own. The intruder's omp-start
    // must be refused: no row for its session, and the legitimate owner of
    // the leaked id keeps its bindings untouched.
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");

    let suffix = unique_suffix();
    let seeded_name = format!("idmint{suffix}");
    let seeded_sid = format!("sid-owner-{suffix}");
    let leaked = format!("omp-{}-1-1", unused_pid());
    seed_identity(&h, &seeded_name, &seeded_sid, &leaked);

    let intruder_sid = format!("sid-intruder-{suffix}");
    let mut cmd = h.cmd();
    cmd.args(["omp-start", "--session-id", &intruder_sid]);
    cmd.arg("--cwd").arg(h.workspace.to_string_lossy().as_ref());
    cmd.env("HCOM_PROCESS_ID", &leaked);
    cmd.env("HCOM_LAUNCHED", "1");
    let out = cmd.output().expect("run omp-start with the leaked id");
    let exit_code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // Hooks answer plugin RPC on exit 0 with an error body; accept a non-zero
    // exit too, but never a success shape for a foreign id.
    if exit_code == 0 {
        let response: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("omp-start stdout is not JSON: {e}\n{stdout}\n{stderr}"));
        assert!(
            response.get("error").is_some() && response.get("name").is_none(),
            "foreign id produced a success response: {response}"
        );
    }

    assert_no_bind_and_owner_intact(&h, &intruder_sid, &seeded_name, &seeded_sid, &leaked);
}

#[test]
fn leaked_omp_id_binds_nothing_through_claude_and_codex_hooks() {
    // Rule pinned (design §2.2): the sanitization lives in the shared
    // `hook_gate_check`, so a foreign id is treated as ABSENT for EVERY tool
    // — here the two JSON-stdin hook surfaces: claude `sessionstart` and
    // codex `codex-sessionstart`, each with the leaked desktop env
    // (`HCOM_PROCESS_ID=omp-<dead pid>-1-1` + `HCOM_LAUNCHED=1`). Neither may
    // write a binding nor attach its session to the pre-existing row.
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");

    let suffix = unique_suffix();
    let seeded_name = format!("idmint{suffix}");
    let seeded_sid = format!("sid-owner-{suffix}");
    let leaked = format!("omp-{}-1-1", unused_pid());
    seed_identity(&h, &seeded_name, &seeded_sid, &leaked);
    let cwd = h.workspace.to_string_lossy().to_string();

    // Claude SessionStart (Claude hook stdin shape: root-level snake_case).
    let claude_sid = format!("sid-claude-{suffix}");
    run_leaked_hook(
        &h,
        "sessionstart",
        &leaked,
        &json!({
            "session_id": claude_sid,
            "transcript_path": "",
            "cwd": cwd,
            "hook_event_name": "SessionStart",
            "source": "startup",
        }),
    );
    assert_no_bind_and_owner_intact(&h, &claude_sid, &seeded_name, &seeded_sid, &leaked);

    // Codex SessionStart (codex-native stdin shape: `session_id`).
    let codex_sid = format!("sid-codex-{suffix}");
    run_leaked_hook(
        &h,
        "codex-sessionstart",
        &leaked,
        &json!({
            "session_id": codex_sid,
            "cwd": cwd,
        }),
    );
    assert_no_bind_and_owner_intact(&h, &codex_sid, &seeded_name, &seeded_sid, &leaked);
}

#[test]
fn launcher_uuid_null_pid_row_refuses_leaked_claude_hook() {
    // The pre-spawn launcher row exists, but its pid is still NULL. The
    // presenting hook carries the UUID itself; carriage cannot replace the
    // missing ancestry anchor or attach to the owner's row.
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");
    let suffix = unique_suffix();
    let owner_name = format!("preanchor{suffix}");
    let owner_sid = format!("sid-preanchor-{suffix}");
    let launcher_id = "550e8400-e29b-41d4-a716-446655440000";
    seed_identity(&h, &owner_name, &owner_sid, launcher_id);
    let sid = format!("sid-leaked-preanchor-{suffix}");
    run_leaked_hook(
        &h,
        "sessionstart",
        launcher_id,
        &json!({
            "session_id": sid,
            "cwd": h.workspace,
            "hook_event_name": "SessionStart",
            "source": "startup",
        }),
    );
    assert_no_bind_and_owner_intact(&h, &sid, &owner_name, &owner_sid, launcher_id);
}

#[test]
fn inherited_synthetic_omp_id_does_not_join_without_plain_sessions() {
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");
    let sid = format!("sid-inherited-{}", unique_suffix());
    let inherited_id = "pid-agy-123";
    let mut cmd = h.cmd();
    cmd.args(["omp-start", "--session-id", &sid]);
    cmd.arg("--cwd").arg(&h.workspace);
    cmd.env("HCOM_PROCESS_ID", inherited_id);
    cmd.env("HCOM_LAUNCHED", "1");
    let out = cmd
        .output()
        .expect("run omp-start with inherited synthetic id");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let response: Value =
        serde_json::from_slice(&out.stdout).expect("refused omp-start emits JSON response");
    assert!(
        response.get("error").is_some() && response.get("name").is_none(),
        "inherited synthetic id joined without opt-in: {response}"
    );
    let db = open_db(&h);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM instances", &[]), 0);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM session_bindings WHERE session_id = ?1",
            &[sid.as_str()]
        ),
        0
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM process_bindings WHERE process_id = ?1",
            &[inherited_id]
        ),
        0
    );
}

#[test]
fn unproven_launcher_uuid_retries_as_plain_with_opt_in() {
    // Model the plugin's one retry: first present an inherited launcher UUID
    // without a row, then replace it with this OMP process's minted id.
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");
    enable_plain_sessions(&h);
    let inherited_id = "550e8400-e29b-41d4-a716-446655440000";
    let sid = format!("sid-retry-{}", unique_suffix());
    let fakebin = h.root_path().join("fakebin");
    fs::create_dir_all(&fakebin).expect("create fakebin dir");
    let omp = fakebin.join("omp");
    unix_fs::symlink("/bin/bash", &omp).expect("symlink omp -> /bin/bash");
    let out_dir = h.root_path().join("retry-session");
    fs::create_dir_all(&out_dir).expect("create retry output dir");
    let script = out_dir.join("session.sh");
    fs::write(
        &script,
        r#"
HCOM_LAUNCHED=1 HCOM_TOOL=omp "$TEST_BIN" omp-start --session-id "$TEST_SID" --cwd "$TEST_CWD" \
    > "$TEST_OUT_DIR/first.json" 2> "$TEST_OUT_DIR/first.stderr"
export HCOM_PROCESS_ID=omp-$$-1-1
printf "%s" "$HCOM_PROCESS_ID" > "$TEST_OUT_DIR/id.txt"
HCOM_LAUNCHED=1 HCOM_TOOL=omp "$TEST_BIN" omp-start --session-id "$TEST_SID" --cwd "$TEST_CWD" \
    > "$TEST_OUT_DIR/start.json" 2> "$TEST_OUT_DIR/start.stderr"
printf "%s" "$?" > "$TEST_OUT_DIR/start.code"
while :; do sleep 1; done
"#,
    )
    .expect("write retry script");
    let mut cmd = h.external_cmd(&omp);
    cmd.arg("-c")
        .arg(format!(
            "exec env HCOM_PROCESS_ID={} {} {}",
            inherited_id,
            shell_quote(&omp),
            shell_quote(&script)
        ))
        .env("TEST_OUT_DIR", &out_dir)
        .env("TEST_BIN", env!("CARGO_BIN_EXE_hcom"))
        .env("TEST_SID", &sid)
        .env("TEST_CWD", &h.workspace)
        .process_group(0);
    let child = cmd.spawn().expect("spawn fake omp retry session");
    h.track_cleanup_pid(child.id() as i64);
    let mut session = FakeOmpSession { child, out_dir };
    let (start_code, start) = wait_for_start(&h, &session);
    assert_eq!(start_code, "0", "retry exit {}", session.detail(&start));
    let first: Value =
        serde_json::from_str(&session.read("first.json")).expect("initial hook refusal JSON");
    assert_eq!(first["error"], "HCOM_PROCESS_ID not set", "{first}");
    assert!(
        first.get("name").is_none(),
        "unproven UUID bound on first attempt: {first}"
    );
    let name = start["name"].as_str().expect("plain retry bound own id");
    assert_eq!(session.read("id.txt"), session.minted_id());
    let db = open_db(&h);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM instances", &[]), 1);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM process_bindings WHERE process_id = ?1",
            &[inherited_id]
        ),
        0
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM process_bindings WHERE process_id = ?1 AND instance_name = ?2",
            &[session.minted_id().as_str(), name],
        ),
        1
    );
    drop(db);
    kill_group(&mut session.child);
}

#[test]
fn provable_omp_ancestor_is_trusted_and_reaped_as_carrier() {
    // Rule pinned (design §1, `omp-<pid>-...` row): a provable chain IS
    // honoured — the id's pid is a live ancestor whose comm is exactly "omp"
    // (a process exec'd from a file named `omp`), so the id survives
    // sanitization and binds. An untrusted id is sanitized to ABSENT before
    // the handler even with the config gate open ("HCOM_PROCESS_ID not
    // set"), so the successful bind below is itself the trust proof. The
    // follow-up external `omp-stop` reaping the ancestor proves the ancestor
    // is enumerated as a carrier of the instance (its environ carries the
    // binding id) — the same observable tests/omp_stop_release.rs uses.
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");

    // The plain-session mint arm needs the operator opt-in (design §4.1);
    // this gate is orthogonal to the trust rule pinned here.
    enable_plain_sessions(&h);

    let suffix = unique_suffix();
    let sid = format!("sid-trusted-{suffix}");
    let mut session = spawn_provable_omp_session(&h, &format!("trusted-{suffix}"), &sid);

    let (start_code, start) = wait_for_start(&h, &session);
    assert_eq!(start_code, "0", "omp-start exit {}", session.detail(&start));
    assert!(
        start.get("error").is_none(),
        "provable omp-ancestor id was refused: {}",
        session.detail(&start)
    );
    let name = start["name"]
        .as_str()
        .unwrap_or_else(|| panic!("no instance name in {start}"))
        .to_string();
    assert_eq!(start["session_id"].as_str(), Some(sid.as_str()));
    assert_eq!(session.read("id.txt"), session.minted_id());

    let db = open_db(&h);
    let bound: String = db
        .query_row(
            "SELECT name FROM instances WHERE session_id = ?1",
            [&sid],
            |r| r.get(0),
        )
        .expect("no instance row for the provable session");
    assert_eq!(bound, name);
    let bound_id: String = db
        .query_row(
            "SELECT instance_name FROM process_bindings WHERE process_id = ?1",
            [session.minted_id()],
            |r| r.get(0),
        )
        .expect("no process binding for the trusted id");
    assert_eq!(bound_id, name);
    drop(db);

    // External release: this caller carries no identity facts and the fake
    // omp is not its ancestor, so the ancestor is in signal scope only
    // through carrier enumeration.
    let (stop_code, stop_out, stop_err) =
        h.run(["omp-stop", "--name", &name, "--reason", "carrier-proof"]);
    assert_eq!(stop_code, 0, "omp-stop failed: {stop_out} {stop_err}");
    let Some(status) = wait_with_deadline(&mut session.child, Duration::from_secs(30)) else {
        kill_group(&mut session.child);
        panic!("the provable omp ancestor survived omp-stop: never reaped as a carrier");
    };
    assert!(
        status.signal().is_some(),
        "the provable omp ancestor was not signalled by the carrier reap: {status:?}"
    );

    let db = open_db(&h);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM instances WHERE name = ?1",
            &[name.as_str()]
        ),
        0,
        "row not released after the carrier reap"
    );
}

#[test]
fn plain_sessions_gate_controls_provable_chain_minting() {
    // Rules pinned (design §1.1 shape clause + §3/§4.1 opt-in):
    // - `HCOM_LAUNCHED=1` cannot prove a launch for an omp-shaped id even
    //   when the chain is fully provable (launcher ids are UUIDs), so with
    //   `plain_sessions` unset the session must NOT mint a row.
    // - With `[launch.omp] plain_sessions = true` the same provable chain
    //   mints, and two plain sessions produce two DISTINCT identities.
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");

    let suffix = unique_suffix();

    // Phase A — gate unset (fresh isolated config: absent or the written
    // default skeleton, `plain_sessions = false`; either way not opted in).
    let sid_a = format!("sid-gate-a-{suffix}");
    let mut session_a = spawn_provable_omp_session(&h, &format!("gate-a-{suffix}"), &sid_a);
    let (code_a, start_a) = wait_for_start(&h, &session_a);
    assert_eq!(code_a, "0", "omp-start exit {}", session_a.detail(&start_a));
    assert!(
        start_a.get("error").is_some() && start_a.get("name").is_none(),
        "provable chain + leaked HCOM_LAUNCHED=1 minted a row without the opt-in: {start_a}"
    );
    assert_eq!(session_a.read("id.txt"), session_a.minted_id());
    let db = open_db(&h);
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM instances", &[]),
        0,
        "a row was created with plain_sessions unset"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM session_bindings WHERE session_id = ?1",
            &[sid_a.as_str()]
        ),
        0,
        "session binding created with plain_sessions unset"
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM process_bindings WHERE process_id = ?1",
            &[session_a.minted_id().as_str()]
        ),
        0,
        "process binding created with plain_sessions unset"
    );
    drop(db);
    kill_group(&mut session_a.child);

    // Phase B — with the opt-in, plugin load replaces the inherited
    // pid-agy-123 id with each OMP process's own minted id.
    enable_plain_sessions(&h);
    // A raw inherited synthetic id is not itself admitted even with the
    // opt-in: the plugin must replace it with this process's own OMP id.
    let raw_sid = format!("sid-raw-{suffix}");
    let mut raw_hook = h.cmd();
    raw_hook.args(["omp-start", "--session-id", &raw_sid]);
    raw_hook.arg("--cwd").arg(&h.workspace);
    raw_hook.env("HCOM_PROCESS_ID", "pid-agy-123");
    raw_hook.env("HCOM_LAUNCHED", "1");
    let raw = raw_hook.output().expect("run raw synthetic omp-start");
    assert_eq!(
        raw.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&raw.stderr)
    );
    let refused: Value = serde_json::from_slice(&raw.stdout).expect("raw hook refusal JSON");
    assert!(
        refused.get("error").is_some() && refused.get("name").is_none(),
        "raw inherited synthetic id bound despite the opt-in: {refused}"
    );
    let db = open_db(&h);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM instances", &[]), 0);
    drop(db);
    let sid_b = format!("sid-gate-b-{suffix}");
    let sid_c = format!("sid-gate-c-{suffix}");
    let mut session_b = spawn_provable_omp_session(&h, &format!("gate-b-{suffix}"), &sid_b);
    let mut session_c = spawn_provable_omp_session(&h, &format!("gate-c-{suffix}"), &sid_c);

    let (code_b, start_b) = wait_for_start(&h, &session_b);
    assert_eq!(code_b, "0", "omp-start exit {}", session_b.detail(&start_b));
    assert!(
        start_b.get("error").is_none(),
        "opted-in plain session was refused: {}",
        session_b.detail(&start_b)
    );
    let name_b = start_b["name"].as_str().expect("name for session b");
    assert_eq!(start_b["session_id"].as_str(), Some(sid_b.as_str()));

    let (code_c, start_c) = wait_for_start(&h, &session_c);
    assert_eq!(code_c, "0", "omp-start exit {}", session_c.detail(&start_c));
    assert!(
        start_c.get("error").is_none(),
        "opted-in plain session was refused: {}",
        session_c.detail(&start_c)
    );
    let name_c = start_c["name"].as_str().expect("name for session c");
    assert_eq!(start_c["session_id"].as_str(), Some(sid_c.as_str()));

    assert_ne!(
        name_b, name_c,
        "two plain sessions must mint two distinct identities"
    );

    let db = open_db(&h);
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM instances", &[]),
        2,
        "expected exactly the two minted rows"
    );
    for (sid, name, session) in [(&sid_b, name_b, &session_b), (&sid_c, name_c, &session_c)] {
        let bound: String = db
            .query_row(
                "SELECT name FROM instances WHERE session_id = ?1",
                [sid.as_str()],
                |r| r.get(0),
            )
            .unwrap_or_else(|e| panic!("no row for {sid}: {e}"));
        assert_eq!(&bound, name);
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM process_bindings WHERE process_id = ?1",
                &[session.minted_id().as_str()],
            ),
            1,
            "no process binding for {name}'s trusted id"
        );
    }
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM process_bindings WHERE process_id = ?1",
            &["pid-agy-123"],
        ),
        0,
        "the inherited synthetic id must not be bound"
    );
    drop(db);

    kill_group(&mut session_b.child);
    kill_group(&mut session_c.child);
}

#[test]
fn start_hook_replaces_stale_installed_plugin() {
    // Rule pinned (design §4.2): `handle_start` refreshes a stale installed
    // plugin first thing, so the next omp session loads the hcom.ts this
    // binary embeds. The refresh runs before any identity logic, so driving
    // the hook down its refusal path (no `HCOM_PROCESS_ID`) still exercises
    // it — the gate only needs one instance row to exist.
    let h = Hcom::new();
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");

    let suffix = unique_suffix();
    // Seed one row so `hook_gate_check`'s "any instance exists" fallback
    // lets the hook through to `handle_start`.
    seed_identity(
        &h,
        &format!("plugin{suffix}"),
        &format!("sid-owner-{suffix}"),
        &format!("omp-seed-{suffix}"),
    );

    // Resolved plugin path under the fixture env: `tool_config_root()` is the
    // parent of `$HCOM_DIR` (`<root>/hcom-state` -> `<root>`), which differs
    // from `$HOME` (`<root>/home`), so `omp_plugin_dir()` is
    // `<root>/.omp/extensions` (src/hooks/omp/plugin.rs).
    let plugin_path = h
        .root_path()
        .join(".omp")
        .join("extensions")
        .join("hcom.ts");
    fs::create_dir_all(plugin_path.parent().expect("plugin dir")).expect("create plugin dir");
    // A genuine stale install is hcom-owned (carries the bootstrap marker),
    // which is what lets `install_omp_plugin` replace it instead of refusing.
    let stale = "// stale hcom plugin body (test) — must be replaced\n\
                 // customType: \"hcom-bootstrap\"\n";
    fs::write(&plugin_path, stale).expect("write stale plugin");

    let sid = format!("sid-plugin-{suffix}");
    let (hook_code, stdout, stderr) = h.run([
        "omp-start",
        "--session-id",
        &sid,
        "--cwd",
        &h.workspace.to_string_lossy(),
    ]);
    assert_eq!(hook_code, 0, "omp-start failed: {stderr}");
    let response: Value =
        serde_json::from_str(stdout.trim()).expect("omp-start returns JSON on the RPC contract");
    assert!(
        response.get("error").is_some(),
        "expected the identity-less refusal after the plugin refresh: {response}"
    );

    let installed =
        fs::read_to_string(&plugin_path).expect("plugin file present after the start hook");
    assert!(
        !installed.contains("must be replaced"),
        "stale plugin body survived the start hook"
    );
    assert!(
        installed.contains("customType: \"hcom-bootstrap\""),
        "installed plugin is missing the hcom-owned bootstrap marker"
    );
    assert_eq!(
        installed, PLUGIN_SOURCE,
        "installed plugin does not byte-match the embedded PLUGIN_SOURCE"
    );
}
