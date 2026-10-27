//! `hcom kill` signals a recorded PID only when the live process holding it is
//! verifiably the target instance's owner (hcom#106). A crashed seat whose PID
//! was reused by an unrelated process must be refused, reported with the PID
//! and an `hcom stop` pointer, and nothing in the reuser's tree signalled. A
//! genuine owner, and its tree, is still killed.
//!
//! The kill root is the recorded pre-hook launch root, the last pin before the
//! hook re-pinned the row to the interpreter: what `hcom pty` launched (the
//! PTY child), or the launcher that ran `hcom launch-anchor`. Kill retires
//! that root's tree and never signals anything above it, `hcom pty`
//! included, even when it carries the seat's HCOM_PROCESS_ID.
//!
//! Most processes here are fixture children of this test or descendants of
//! one: a stand-in OMP that registers through hcom's own `launch-anchor`
//! (which writes the native identity receipt) and binds through `omp-start`,
//! sometimes below a launcher that leads its process group, or a sentinel that
//! records any signal it receives and keeps a heartbeat. `mod real` instead
//! resumes seats through hcom's own launch paths and `hcom pty`, with
//! fixture-private tools first on PATH. PID reuse is simulated in the private
//! DB only: the reuser's PID replaces the crashed owner's number in the
//! owner's row and bindings, nothing else changes.
//!
//! Legacy rows carry no receipt and no recorded launch root; their evidence is
//! the live process's own HCOM_PROCESS_ID. Linux (`mod linux`) reads it from
//! /proc and also covers zombies and unreadable evidence; Windows and macOS
//! (`mod native`) read it natively. A legacy OMP row whose launcher is not
//! `hcom pty` loses only its owner tree, and the kill says the launcher was
//! not verified; a non-OMP row's verified PID is its root.

#![cfg(any(target_os = "linux", target_os = "macos", windows))]

mod support;

use std::time::{Duration, Instant};

use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use support::omp_owner::{db, isolated_hcom};
use support::{Hcom, unique_suffix};

const POLL: Duration = Duration::from_millis(25);

// ---------------------------------------------------------------------------
// Scene: the isolated hcom fixture plus a teardown that never hands a row PID
// to `Hcom::drop` (its `kill all` and row-PID sweep would signal it).
// ---------------------------------------------------------------------------

struct Scene {
    h: Hcom,
}

impl Scene {
    fn new() -> Self {
        Self { h: isolated_hcom() }
    }
}

impl std::ops::Deref for Scene {
    type Target = Hcom;
    fn deref(&self) -> &Hcom {
        &self.h
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        // Runs after every process wrapper declared later in the test has been
        // dropped, so every fixture process is already reaped, and before
        // `Hcom::drop`, whose `kill all` would otherwise signal whatever now
        // holds a PID this test recorded: a row PID, a launch receipt, or
        // hcom's own record of the processes it signalled. Only this private
        // state is touched.
        if let Ok(conn) = rusqlite::Connection::open(self.h.path().join("hcom.db")) {
            let _ = conn.busy_timeout(Duration::from_secs(5));
            let _ = conn.execute(
                "UPDATE instances
                    SET pid=NULL,
                        launch_context=CASE WHEN json_valid(launch_context)
                            THEN json_remove(launch_context,'$.omp_launch_pid','$.omp_launch_root')
                            ELSE launch_context END",
                [],
            );
        }
        let _ = std::fs::remove_file(self.h.path().join(".tmp/launched_pids.json"));
    }
}

fn wait_until(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

// ---------------------------------------------------------------------------
// Registration and bookkeeping
// ---------------------------------------------------------------------------

/// An hcom launch reservation: a pending `omp` row with no PID yet and the
/// launcher UUID bound to it, exactly as the launcher leaves it before the
/// launch script runs `hcom launch-anchor`.
fn launch_row(h: &Hcom, name: &str, process_id: &str) {
    let conn = db(h);
    conn.execute(
        "INSERT INTO instances (name, tool, status, status_context, created_at)
         VALUES (?1, 'omp', 'pending', 'new', 1234.5)",
        [name],
    )
    .expect("seed pending launch row");
    conn.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, NULL, ?2, 1234.5)",
        rusqlite::params![process_id, name],
    )
    .expect("seed launch process binding");
}

/// A legacy bound row, as written before any identity record existed: row,
/// process binding and session binding, recorded PID `pid`, and no launch
/// receipt or recorded launch root.
fn seed_legacy_row(h: &Hcom, name: &str, process_id: &str, pid: Option<u32>) {
    seed_bound_row(h, "omp", name, process_id, pid);
}

/// A bound `tool` row with no launch context: row, process binding and
/// session binding, recorded PID `pid`.
fn seed_bound_row(h: &Hcom, tool: &str, name: &str, process_id: &str, pid: Option<u32>) {
    let conn = db(h);
    let sid = format!("sid-{name}");
    conn.execute(
        "INSERT INTO instances (name, tool, session_id, status, status_context, status_time, created_at, last_event_id, pid)
         VALUES (?1, ?2, ?3, 'listening', 'start', 0, 0, 0, ?4)",
        rusqlite::params![name, tool, sid, pid],
    )
    .expect("seed bound row");
    conn.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![process_id, sid, name],
    )
    .expect("seed process binding");
    conn.execute(
        "INSERT INTO session_bindings (session_id, instance_name, created_at) VALUES (?1, ?2, 0)",
        rusqlite::params![sid, name],
    )
    .expect("seed session binding");
}

/// Make `name` a legacy row: drop its recorded launch root, keep the rest.
#[cfg(unix)]
fn strip_launch_root(h: &Hcom, name: &str) {
    db(h)
        .execute(
            "UPDATE instances
                SET launch_context=json_remove(launch_context,'$.omp_launch_root')
              WHERE name=?1 AND json_valid(launch_context)",
            [name],
        )
        .expect("strip the recorded launch root");
}

/// A stopped OMP seat that `hcom r` can resume: its row, its session file, and
/// a stop event whose snapshot holds the launch mode. The stopped owner really
/// existed and was reaped.
fn seed_stopped_omp(h: &Hcom, name: &str, background: bool) -> (String, std::path::PathBuf) {
    let sid = uuid::Uuid::new_v4().to_string();
    let transcript = h
        .home
        .join(".omp/agent/sessions/real")
        .join(format!("2026-10-01T00-00-00-000Z_{sid}.jsonl"));
    std::fs::create_dir_all(transcript.parent().unwrap()).expect("create session directory");
    std::fs::write(
        &transcript,
        format!(
            "{}\n",
            json!({"type": "session", "id": sid, "cwd": h.workspace})
        ),
    )
    .expect("write session file");
    let mut command = h.external_cmd(if cfg!(windows) {
        "cmd.exe"
    } else {
        "/bin/bash"
    });
    if cfg!(windows) {
        command.args(["/d", "/c", "exit 0"]);
    } else {
        command.args(["-c", "exec -a omp /bin/bash -c 'exit 0'"]);
    }
    let mut prior = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the stopped seat's owner");
    let prior_pid = prior.id();
    prior.wait().expect("reap the stopped seat's owner");
    let conn = db(h);
    conn.execute(
        "INSERT INTO instances (name,tool,session_id,status,status_context,status_time,created_at,directory,transcript_path,last_event_id,background)
         VALUES (?1,'omp',?2,'inactive','exit:0',0,CAST(strftime('%s','now') AS REAL),?3,?4,0,?5)",
        rusqlite::params![
            name,
            sid,
            h.workspace.to_string_lossy(),
            transcript.to_string_lossy(),
            i64::from(background)
        ],
    )
    .expect("seed the stopped row");
    conn.execute(
        "INSERT INTO events (timestamp,type,instance,data) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'),'life',?1,?2)",
        rusqlite::params![
            name,
            json!({
                "action": "stopped", "by": "session", "reason": "exit:normal",
                "process_id": format!("omp-{prior_pid}-5-6"),
                "snapshot": {
                    "name": name, "tool": "omp", "session_id": sid, "pid": prior_pid,
                    "directory": h.workspace, "transcript_path": transcript,
                    "background": i64::from(background), "launch_args": "", "last_event_id": 0,
                },
            })
            .to_string()
        ],
    )
    .expect("seed the stop event");
    (sid, transcript)
}

/// Put the fixture tools in `fakebin` first on every PATH a launch uses, and
/// keep the launched tool's roots inside the fixture. The launch resolves its
/// tool from hcom's own PATH and rebuilds the tool's env from a clean shell
/// plus the fixture passthrough, which hcom's own CLI env takes too. A real
/// `omp` elsewhere on PATH must never run.
fn use_fixture_tools(h: &Hcom, fakebin: &std::path::Path) {
    let inherited = |key: &str| {
        h.cmd()
            .get_envs()
            .find(|(name, _)| *name == key)
            .and_then(|(_, value)| value)
            .map(|value| value.to_os_string())
    };
    let mut paths = vec![fakebin.to_path_buf()];
    paths.extend(std::env::split_paths(
        &inherited("PATH").expect("fixture PATH"),
    ));
    h.set_launch_env(
        "PATH",
        std::env::join_paths(paths)
            .expect("join the launch PATH")
            .to_str()
            .unwrap(),
    );
    for key in [
        "HOME",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "CODEX_HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = inherited(key) {
            h.set_launch_env(key, value.to_str().unwrap());
        }
    }
    h.set_launch_env("PI_CONFIG_DIR", h.home.join(".omp").to_str().unwrap());
    h.set_launch_env(
        "PI_CODING_AGENT_DIR",
        h.home.join(".omp/agent").to_str().unwrap(),
    );
    let path = inherited("PATH").expect("launch PATH");
    let first = std::env::split_paths(&path).find(|dir| {
        ["omp", "omp.exe", "omp.cmd", "omp.bat", "omp.com"]
            .iter()
            .any(|tool| dir.join(tool).is_file())
    });
    assert_eq!(
        first.as_deref(),
        Some(fakebin),
        "safety: the launch PATH must reach the stand-in omp before any real one"
    );
}

// ---------------------------------------------------------------------------
// Hooked stand-in OMP on Unix: a step runner that runs hcom commands from
// inside its own process, so hcom anchors and binds the name to this live PID
// through the real launch-anchor and hook paths.
// ---------------------------------------------------------------------------

#[cfg(unix)]
const STEP_RUNNER: &str = r#"
cd "$TEST_CWD" || exit 1
H() { HCOM_LAUNCHED=1 HCOM_TOOL=omp "$TEST_BIN" "$@"; }
printf '%s\n%s' "$$" "$HCOM_PROCESS_ID" > "$TEST_OUT_DIR/ready"
while :; do
    for go in "$TEST_OUT_DIR"/go-*; do
        [ -e "$go" ] || continue
        step=${go##*/go-}
        [ ! -e "$TEST_OUT_DIR/$step.code" ] || continue
        . "$TEST_OUT_DIR/$step.sh" > "$TEST_OUT_DIR/$step.stdout" 2> "$TEST_OUT_DIR/$step.stderr"
        printf '%s' "$?" > "$TEST_OUT_DIR/$step.code"
    done
    sleep 0.05 & wait $!
done
"#;

/// Run `script` as step `step` inside the step runner writing to `out_dir`.
#[cfg(unix)]
fn run_step(
    h: &Hcom,
    out_dir: &std::path::Path,
    step: usize,
    script: &str,
) -> (i32, String, String) {
    std::fs::write(out_dir.join(format!("{step}.sh")), script).expect("write hook step");
    std::fs::write(out_dir.join(format!("go-{step}")), "").expect("trigger hook step");
    let code = h.eventually("hook step finished", Duration::from_secs(30), || {
        Ok(
            std::fs::read_to_string(out_dir.join(format!("{step}.code")))
                .ok()
                .filter(|text| !text.is_empty()),
        )
    });
    let read = |file: String| std::fs::read_to_string(out_dir.join(file)).unwrap_or_default();
    (
        code.parse().expect("hook step exit code"),
        read(format!("{step}.stdout")),
        read(format!("{step}.stderr")),
    )
}

/// Precondition: `launch-anchor` recorded `pid` and a native identity receipt
/// for it.
#[track_caller]
fn assert_receipt(h: &Hcom, name: &str, pid: u32, anchor: &(i32, String, String)) {
    let recorded: (Option<i64>, Option<i64>) = db(h)
        .query_row(
            "SELECT pid, CASE WHEN json_valid(launch_context)
                              THEN json_extract(launch_context,'$.omp_launch_pid.pid') END
               FROM instances WHERE name=?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        recorded,
        (Some(i64::from(pid)), Some(i64::from(pid))),
        "launch-anchor did not record {name}'s owner PID {pid} with a receipt: {anchor:?}"
    );
}

/// Simulated PID reuse in this private DB: every integer PID fact naming the
/// crashed owner's number, in the owner's row and its process bindings, plus a
/// launch receipt PID, now names `new`. Persisted identity evidence that is
/// not the bare number stays the crashed owner's, as after a real reuse.
fn reuse_pid(h: &Hcom, name: &str, old: u32, new: u32) {
    let conn = db(h);
    for (table, owner_column) in [("instances", "name"), ("process_bindings", "instance_name")] {
        let columns: Vec<String> = conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for column in columns {
            conn.execute(
                &format!(
                    "UPDATE {table} SET \"{column}\"=?1
                      WHERE {owner_column}=?2 AND typeof(\"{column}\")='integer' AND \"{column}\"=?3"
                ),
                rusqlite::params![new, name, old],
            )
            .unwrap();
        }
    }
    conn.execute(
        "UPDATE instances
            SET launch_context=json_set(launch_context,'$.omp_launch_pid.pid',?2)
          WHERE name=?1 AND json_valid(launch_context)
            AND json_extract(launch_context,'$.omp_launch_pid.pid')=?3",
        rusqlite::params![name, new, old],
    )
    .unwrap();
    assert_eq!(
        row_facts(h, name)["pid"],
        json!(new),
        "PID-reuse fixture did not renumber {name}"
    );
}

/// Row status/pid, the name its first process binding resolves to, and its
/// stop history.
fn row_facts(h: &Hcom, name: &str) -> Value {
    let conn = db(h);
    let row: Option<(Option<String>, Option<i64>)> = conn
        .query_row(
            "SELECT status, pid FROM instances WHERE name=?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .unwrap();
    let binding: Option<String> = conn
        .query_row(
            "SELECT instance_name FROM process_bindings WHERE instance_name=?1 LIMIT 1",
            [name],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    let stopped: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE type='life' AND instance=?1
               AND json_extract(data,'$.action')='stopped'",
            [name],
            |row| row.get(0),
        )
        .unwrap();
    json!({
        "row": row.is_some(),
        "status": row.as_ref().and_then(|r| r.0.clone()),
        "pid": row.as_ref().and_then(|r| r.1),
        "process_binding": binding,
        "stopped_events": stopped,
    })
}

#[track_caller]
fn assert_bound(h: &Hcom, name: &str, pid: u32, start: &(i32, String, String)) {
    let bound = row_facts(h, name);
    assert_eq!(
        (&bound["status"], &bound["pid"], &bound["process_binding"]),
        (&json!("listening"), &json!(pid), &json!(name)),
        "fixture OMP did not hook and bind {name}: start={start:?} row={bound}"
    );
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

fn kill<S: AsRef<str>>(h: &Hcom, args: &[S]) -> (i32, String) {
    let mut argv = vec!["kill"];
    argv.extend(args.iter().map(AsRef::as_ref));
    let (code, stdout, stderr) = h.run(&argv);
    (code, format!("{stdout}\n{stderr}"))
}

fn names_pid(output: &str, pid: u32) -> bool {
    let pid = pid.to_string();
    output.match_indices(&pid).any(|(at, _)| {
        let before = output[..at].chars().next_back();
        let after = output[at + pid.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_digit()) && !after.is_some_and(|c| c.is_ascii_digit())
    })
}

/// The refusal names the instance, the PID it would not signal, and points at
/// `hcom stop <name>` to clear bookkeeping.
#[track_caller]
fn assert_refusal_reported(output: &str, name: &str, pid: u32) {
    assert!(
        output.contains(&format!("hcom stop {name}")),
        "refusal for {name} lacks the `hcom stop {name}` pointer:\n{output}"
    );
    assert!(
        names_pid(output, pid),
        "refusal for {name} does not name the unverified PID {pid}:\n{output}"
    );
}

/// A refused row keeps its bookkeeping: `hcom stop` is how it is cleared.
#[track_caller]
fn assert_row_kept(h: &Hcom, name: &str, pid: u32) {
    let facts = row_facts(h, name);
    assert_eq!(
        (&facts["row"], &facts["pid"], &facts["stopped_events"]),
        (&json!(true), &json!(pid), &json!(0)),
        "refused kill changed {name}'s bookkeeping: {facts}"
    );
}

/// The genuine owner's row is torn down as before: row and bindings gone, one
/// stopped event.
#[track_caller]
fn assert_torn_down(h: &Hcom, name: &str) {
    let facts = row_facts(h, name);
    assert_eq!(
        (
            &facts["row"],
            &facts["process_binding"],
            &facts["stopped_events"]
        ),
        (&json!(false), &Value::Null, &json!(1)),
        "kill of the genuine owner {name} did not tear its row down: {facts}"
    );
}

/// A successful kill: exit 0, the seat named, and no refusal or
/// unverified-launcher report. A real PTY seat may report the plain kill, or
/// that its session shut itself down during the kill: `hcom pty` exits once
/// the root's tree is gone and races the kill's own teardown.
#[track_caller]
fn assert_kill_succeeded(code: i32, output: &str, name: &str) {
    assert!(
        !output.contains(&format!("hcom stop {name}")) && !mentions_unverified_launcher(output),
        "kill of {name} reported a refusal instead of success:\n{output}"
    );
    assert!(
        output.contains(name),
        "kill output does not name {name}:\n{output}"
    );
    assert_eq!(code, 0, "kill of {name} failed:\n{output}");
}

/// The kill could not verify the seat's launcher: it says so, exits nonzero,
/// and never prints the success (resume) hint.
#[track_caller]
fn assert_unverified_launcher(code: i32, output: &str, name: &str) {
    assert!(
        mentions_unverified_launcher(output),
        "kill of {name} did not say its launcher was not verified:\n{output}"
    );
    assert!(
        !output.contains(&format!("hcom r {name}")),
        "kill of {name} printed the success resume hint although its launcher was not \
         verified:\n{output}"
    );
    assert_ne!(
        code, 0,
        "kill of {name} exited 0 although its launcher was not verified:\n{output}"
    );
}

fn mentions_unverified_launcher(output: &str) -> bool {
    let output = output.to_lowercase();
    output.contains("launcher")
        && [
            "not verified",
            "n't verified",
            "unverified",
            "not be verified",
            "could not verify",
            "couldn't verify",
            "cannot verify",
            "can't verify",
        ]
        .iter()
        .any(|phrase| output.contains(phrase))
}

// ===========================================================================
// Linux: bash stand-in OMP, trap-recording sentinels, legacy environ evidence.
// ===========================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    use std::cell::Cell;
    use std::fs;
    use std::net::TcpListener;
    use std::os::unix::fs as unix_fs;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};

    // -----------------------------------------------------------------------
    // Owned direct children. The leader is never reaped before the final drop
    // (exit is observed with WNOWAIT), so its PID and process-group id stay
    // reserved and the drop's group SIGKILL can only reach this fixture's tree.
    // -----------------------------------------------------------------------

    struct Owned {
        child: Child,
        reaped: bool,
    }

    impl Owned {
        fn spawn(mut command: Command, what: &str) -> Self {
            command.process_group(0);
            let child = command
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {what}: {e}"));
            Self {
                child,
                reaped: false,
            }
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }

        /// Exit of the direct child without reaping it, or None while it runs.
        fn peek_exit(&self) -> Option<String> {
            if self.reaped {
                return Some("reaped".into());
            }
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            assert_eq!(
                rc,
                0,
                "waitid on fixture child {}: {}",
                self.pid(),
                std::io::Error::last_os_error()
            );
            if unsafe { info.si_pid() } == 0 {
                return None;
            }
            let status = unsafe { info.si_status() };
            Some(match info.si_code {
                libc::CLD_EXITED => format!("exit {status}"),
                _ => format!("signal {status}"),
            })
        }

        fn wait_exit(&self, timeout: Duration) -> Option<String> {
            let mut exit = None;
            wait_until(timeout, || {
                exit = self.peek_exit();
                exit.is_some()
            });
            exit
        }

        /// Abrupt death of the whole group with no cleanup, then reap, so the
        /// leader's PID is genuinely free. Returns the leader's wait status.
        fn crash(&mut self) -> Option<i32> {
            use std::os::unix::process::ExitStatusExt;
            unsafe {
                libc::killpg(self.pid() as libc::pid_t, libc::SIGKILL);
            }
            let status = self.child.wait().expect("reap crashed fixture owner");
            self.reaped = true;
            status.signal()
        }

        /// The leader alone dies by SIGKILL, with no cleanup, and is left
        /// unreaped: a zombie that still holds its PID and leads its group.
        fn die_unreaped(&self) -> Option<String> {
            unsafe {
                libc::kill(self.pid() as libc::pid_t, libc::SIGKILL);
            }
            self.wait_exit(Duration::from_secs(10))
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            unsafe {
                libc::killpg(self.pid() as libc::pid_t, libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
    }

    /// (state, pgrp) from /proc/<pid>/stat.
    fn proc_state(pid: u32) -> Option<(char, i64)> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = &stat[stat.rfind(')')? + 2..];
        let mut fields = rest.split_whitespace();
        let state = fields.next()?.chars().next()?;
        let _ppid = fields.next()?;
        let pgrp = fields.next()?.parse().ok()?;
        Some((state, pgrp))
    }

    /// A non-child member of a fixture group: alive only while it exists, is
    /// not a zombie and is still in that group (so a later PID reuser never
    /// reads as it).
    fn member_alive(pid: u32, pgid: u32) -> bool {
        matches!(proc_state(pid), Some((state, pgrp)) if state != 'Z' && pgrp == i64::from(pgid))
    }

    fn caught_signals(pid: u32) -> u64 {
        fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| {
                let mask = status
                    .lines()
                    .find_map(|line| line.strip_prefix("SigCgt:"))?;
                u64::from_str_radix(mask.trim(), 16).ok()
            })
            .unwrap_or(0)
    }

    fn mask(signals: &[libc::c_int]) -> u64 {
        signals
            .iter()
            .fold(0_u64, |mask, signal| mask | 1_u64 << (signal - 1))
    }

    fn quote(text: &str) -> String {
        format!("'{}'", text.replace('\'', "'\\''"))
    }

    fn fakebin(h: &Hcom) -> PathBuf {
        let dir = h.root_path().join("fakebin");
        fs::create_dir_all(&dir).expect("create fakebin");
        let omp = dir.join("omp");
        if !omp.exists() {
            unix_fs::symlink("/bin/bash", &omp).expect("symlink omp stand-in");
        }
        dir
    }

    /// An hcom launch script's shape: it anchors the launch first, then runs
    /// the tool as a child it waits on, not exec'd.
    const LAUNCHER: &str = r#"
HCOM_LAUNCHED=1 HCOM_TOOL=omp "$TEST_BIN" launch-anchor > "$TEST_OUT_DIR/anchor.stdout" 2> "$TEST_OUT_DIR/anchor.stderr"
printf '%s' "$?" > "$TEST_OUT_DIR/anchor.code"
"$TEST_OMP" "$TEST_RUNNER" &
wait "$!"
"#;

    /// A launcher with no hcom identity: it starts the OMP with one, then
    /// `exec`s into an idle process that never reaps it.
    const IDLE_LAUNCHER: &str = r#"
HCOM_PROCESS_ID="$TEST_PROCESS_ID" "$TEST_OMP" "$TEST_RUNNER" &
exec sleep 300
"#;

    /// How the stand-in OMP starts.
    #[derive(Clone, Copy, PartialEq)]
    enum Launch {
        /// This test's direct child, leading its own process group.
        Leader,
        /// Below [`LAUNCHER`], which leads the group and anchors the launch.
        Launcher,
        /// Below [`IDLE_LAUNCHER`], which leads the group and never reaps it.
        IdleLauncher,
    }

    struct HookOwner {
        proc: Owned,
        pid: u32,
        out_dir: PathBuf,
        process_id: String,
        next_step: Cell<usize>,
    }

    impl HookOwner {
        fn spawn(h: &Hcom, label: &str) -> Self {
            Self::start(h, label, &uuid::Uuid::new_v4().to_string(), Launch::Leader)
        }

        /// The stand-in OMP below a launcher that leads the process group, as
        /// an hcom launch runs it. `process_id`'s reservation must already
        /// exist: the launcher anchors it before it starts the OMP.
        fn spawn_launched(h: &Hcom, label: &str, process_id: &str) -> Self {
            Self::start(h, label, process_id, Launch::Launcher)
        }

        fn start(h: &Hcom, label: &str, process_id: &str, launch: Launch) -> Self {
            let omp = fakebin(h).join("omp");
            let out_dir = h.root_path().join(format!("owner-{label}"));
            fs::create_dir_all(&out_dir).expect("create owner directory");
            let runner = out_dir.join("steps.sh");
            fs::write(&runner, STEP_RUNNER).expect("write step runner");
            let mut command = match launch {
                Launch::Leader => {
                    let mut command = h.external_cmd(&omp);
                    command.arg(&runner).env("HCOM_PROCESS_ID", process_id);
                    command
                }
                Launch::Launcher => {
                    let mut command = h.external_cmd("/bin/bash");
                    command
                        .arg("-c")
                        .arg(LAUNCHER)
                        .env("TEST_OMP", &omp)
                        .env("TEST_RUNNER", &runner)
                        .env("HCOM_PROCESS_ID", process_id);
                    command
                }
                Launch::IdleLauncher => {
                    let mut command = h.external_cmd("/bin/bash");
                    command
                        .arg("-c")
                        .arg(IDLE_LAUNCHER)
                        .env("TEST_OMP", &omp)
                        .env("TEST_RUNNER", &runner)
                        .env("TEST_PROCESS_ID", process_id);
                    command
                }
            };
            command
                .env("TEST_OUT_DIR", &out_dir)
                .env("TEST_CWD", &h.workspace)
                .env("TEST_BIN", env!("CARGO_BIN_EXE_hcom"))
                .env("TERM", "dumb")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let proc = Owned::spawn(command, "fixture OMP owner");
            let ready = h.eventually("fixture OMP ready", Duration::from_secs(30), || {
                Ok(fs::read_to_string(out_dir.join("ready"))
                    .ok()
                    .filter(|text| text.lines().count() == 2))
            });
            let mut lines = ready.lines();
            let pid: u32 = lines.next().unwrap().parse().expect("fixture OMP PID");
            if launch == Launch::Leader {
                assert_eq!(pid, proc.pid(), "fixture OMP is not the direct child");
            } else {
                assert_ne!(
                    pid,
                    proc.pid(),
                    "fixture OMP must be its launcher's child, not exec'd"
                );
            }
            assert_eq!(lines.next(), Some(process_id));
            Self {
                proc,
                pid,
                out_dir,
                process_id: process_id.to_string(),
                next_step: Cell::new(0),
            }
        }

        /// The OMP's own PID: the direct child, or the launcher's child.
        fn pid(&self) -> u32 {
            self.pid
        }

        /// The direct child leads the process group: the OMP or its launcher.
        fn pgid(&self) -> u32 {
            self.proc.pid()
        }

        /// The launcher's own `hcom launch-anchor` run.
        fn launcher_anchor(&self, h: &Hcom) -> (i32, String, String) {
            let code = h.eventually("launcher anchor finished", Duration::from_secs(30), || {
                Ok(fs::read_to_string(self.out_dir.join("anchor.code"))
                    .ok()
                    .filter(|text| !text.is_empty()))
            });
            let read = |file: &str| fs::read_to_string(self.out_dir.join(file)).unwrap_or_default();
            (
                code.trim().parse().expect("anchor exit code"),
                read("anchor.stdout"),
                read("anchor.stderr"),
            )
        }

        fn run(&self, h: &Hcom, script: &str) -> (i32, String, String) {
            let step = self.next_step.get();
            self.next_step.set(step + 1);
            run_step(h, &self.out_dir, step, script)
        }

        /// Start a long-lived child in the owner's own tree and process
        /// group, carrying the owner's environment. Returns its PID.
        fn spawn_tree_child(&self, h: &Hcom) -> u32 {
            let (code, stdout, stderr) = self.run(
                h,
                "sleep 300 < /dev/null > /dev/null 2>&1 & printf '%s' \"$!\"",
            );
            assert_eq!(code, 0, "spawn owner tree child: {stdout} {stderr}");
            let pid: u32 = stdout.trim().parse().expect("owner tree child PID");
            h.eventually("owner tree child running", Duration::from_secs(10), || {
                Ok(member_alive(pid, self.pgid()).then_some(()))
            });
            pid
        }

        /// The OMP alone dies by SIGKILL, with no cleanup, and stays an
        /// unreaped zombie: its parent is this test, which only peeks at it,
        /// or an idle launcher, which never reaps.
        fn die_unreaped(&self) {
            if self.pid == self.proc.pid() {
                assert_eq!(
                    self.proc.die_unreaped().as_deref(),
                    Some("signal 9"),
                    "fixture OMP did not die by SIGKILL"
                );
            } else {
                // Not this test's child, but alive in this fixture's group up
                // to the signal, and its idle parent never reaps it, so the
                // PID cannot pass to anyone else.
                assert!(
                    member_alive(self.pid, self.pgid()),
                    "fixture OMP exited early"
                );
                unsafe {
                    libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
                }
            }
            let zombie = Some(('Z', i64::from(self.pgid())));
            assert!(
                wait_until(Duration::from_secs(10), || proc_state(self.pid) == zombie),
                "precondition: the dead OMP must stay an unreaped zombie in group {}",
                self.pgid()
            );
        }

        /// A leftover child of N's group: the owner's own child, started with
        /// a cleared environment and without the owner's open session
        /// transcript, so it carries no hcom identity. It records any signal
        /// it receives and keeps a heartbeat.
        fn spawn_leftover_child(&self, h: &Hcom) -> Leftover {
            let dir = h.root_path().join("leftover");
            let (code, stdout, stderr) = self.run(
                h,
                &format!(
                    "env -i PATH=/usr/bin:/bin /bin/bash {} {} 'HUP TERM USR1 USR2 CONT' < /dev/null > /dev/null 2>&1 9<&- & printf '%s' \"$!\"",
                    quote(&sentinel_script(h).to_string_lossy()),
                    quote(&dir.to_string_lossy()),
                ),
            );
            assert_eq!(code, 0, "spawn leftover child: {stdout} {stderr}");
            let leftover = Leftover {
                pid: stdout.trim().parse().expect("leftover PID"),
                pgid: self.pgid(),
                dir,
            };
            h.eventually("leftover child ready", Duration::from_secs(30), || {
                Ok((fs::read_to_string(leftover.dir.join("ready")).ok()
                    == Some(leftover.pid.to_string())
                    && leftover.beats() > 0
                    && member_alive(leftover.pid, leftover.pgid)
                    && caught_signals(leftover.pid) & mask(&CHILD_SIGNALS) == mask(&CHILD_SIGNALS))
                .then_some(()))
            });
            leftover
        }
    }

    /// A fresh fixture OMP registered the way an hcom launch registers it:
    /// a pending reservation, `hcom launch-anchor` run from the owner (which
    /// records its PID and native identity receipt), then `omp-start`.
    fn hooked_owner(h: &Hcom, label: &str, name: &str, endpoint: &TcpListener) -> HookOwner {
        self_anchored_owner(h, label, name, endpoint, Launch::Leader)
    }

    /// [`hooked_owner`] for an OMP started as `launch`.
    fn self_anchored_owner(
        h: &Hcom,
        label: &str,
        name: &str,
        endpoint: &TcpListener,
        launch: Launch,
    ) -> HookOwner {
        let owner = HookOwner::start(h, label, &uuid::Uuid::new_v4().to_string(), launch);
        launch_row(h, name, &owner.process_id);
        let anchor = owner.run(h, "H launch-anchor");
        assert_receipt(h, name, owner.pid(), &anchor);
        start_session(h, &owner, label, name, endpoint);
        owner
    }

    /// The launched shape: the launcher anchors the reservation (its own PID
    /// and receipt), then the OMP below it binds through `omp-start`, which
    /// must re-pin the row to the OMP.
    fn launched_owner(h: &Hcom, label: &str, name: &str, endpoint: &TcpListener) -> HookOwner {
        let process_id = uuid::Uuid::new_v4().to_string();
        launch_row(h, name, &process_id);
        let owner = HookOwner::spawn_launched(h, label, &process_id);
        let anchor = owner.launcher_anchor(h);
        assert_receipt(h, name, owner.pgid(), &anchor);
        start_session(h, &owner, label, name, endpoint);
        owner
    }

    /// `omp-start` from the owner, which keeps its session transcript open;
    /// the row must end up bound to the owner's own PID.
    fn start_session(h: &Hcom, owner: &HookOwner, label: &str, name: &str, endpoint: &TcpListener) {
        let sid = uuid::Uuid::new_v4().to_string();
        let transcript = h
            .home
            .join(".omp/agent/sessions")
            .join(label)
            .join(format!("2026-10-01T00-00-00-000Z_{sid}.jsonl"));
        fs::create_dir_all(transcript.parent().unwrap()).expect("create session directory");
        fs::write(
            &transcript,
            format!(
                "{}\n",
                json!({"type": "session", "id": sid, "cwd": h.workspace})
            ),
        )
        .expect("write session file");
        let start = owner.run(
            h,
            &format!(
                "exec 9< {transcript}; H omp-start --session-id {sid} --transcript-path {transcript} --cwd {cwd} --notify-port {port}",
                transcript = quote(&transcript.to_string_lossy()),
                sid = quote(&sid),
                cwd = quote(&h.workspace.to_string_lossy()),
                port = endpoint.local_addr().unwrap().port(),
            ),
        );
        assert_bound(h, name, owner.pid(), &start);
    }

    /// The owner dies by SIGKILL, with no stop and no cleanup.
    fn crash(h: &Hcom, owner: &mut HookOwner, name: &str) {
        let before = row_facts(h, name);
        let signal = owner.proc.crash();
        assert_eq!(
            signal,
            Some(libc::SIGKILL),
            "fixture OMP did not die by SIGKILL"
        );
        assert_eq!(
            row_facts(h, name),
            before,
            "the crash alone changed {name}'s bookkeeping"
        );
    }

    fn set_tag(h: &Hcom, name: &str, tag: &str) {
        let changed = db(h)
            .execute(
                "UPDATE instances SET tag=?2 WHERE name=?1",
                rusqlite::params![name, tag],
            )
            .unwrap();
        assert_eq!(changed, 1, "tag {name}");
    }

    // -----------------------------------------------------------------------
    // Sentinel: an owned live process outside hcom's knowledge. It traps every
    // catchable signal it can, records the signal's name and exits; SIGKILL
    // shows as death, SIGSTOP as a stalled heartbeat. Optionally it has a
    // child of its own in its process group that does the same.
    // -----------------------------------------------------------------------

    const SENTINEL_BASH: &str = r#"
dir=$1
mkdir -p "$dir"
: > "$dir/signals"
for s in $2; do
    trap "printf '%s\n' $s >> \"$dir/signals\"; exit 0" "$s"
done
if [ -n "${SENTINEL_CHILD:-}" ]; then
    SENTINEL_CHILD= /bin/bash "$0" "$dir/child" "HUP TERM USR1 USR2 CONT" &
    printf '%s' "$!" > "$dir/child.pid"
fi
mkfifo "$dir/hold" && exec 3<> "$dir/hold"
printf '%s' "$$" > "$dir/ready"
while :; do
    printf x >> "$dir/heartbeat"
    read -r -t 0.05 -u 3 || true
done
"#;

    /// Non-dumpable sentinel: its /proc environ is unreadable to same-user
    /// peers.
    const SENTINEL_PY: &str = r#"
import ctypes, os, signal, sys, time
d = sys.argv[1]
if ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:
    sys.exit(3)
open(d + "/signals", "w").close()
def record(signum, frame):
    with open(d + "/signals", "a") as f:
        f.write(signal.Signals(signum).name[3:] + "\n")
    os._exit(0)
for s in ("SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM", "SIGUSR1", "SIGUSR2", "SIGCONT"):
    signal.signal(getattr(signal, s), record)
with open(d + "/ready", "w") as f:
    f.write(str(os.getpid()))
while True:
    with open(d + "/heartbeat", "a") as f:
        f.write("x")
    time.sleep(0.05)
"#;

    const PARENT_SIGNALS: [libc::c_int; 7] = [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGCONT,
    ];
    // A background job of a non-interactive shell starts with INT/QUIT
    // ignored, which bash cannot trap.
    const CHILD_SIGNALS: [libc::c_int; 5] = [
        libc::SIGHUP,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGCONT,
    ];

    struct Sentinel {
        proc: Owned,
        dir: PathBuf,
        child: Option<u32>,
    }

    #[derive(Clone, Copy)]
    struct Beats(u64, u64);

    impl Sentinel {
        /// Bash sentinel run as `exe` (plain `/bin/bash`, or the `omp`
        /// stand-in for a process whose comm reads as OMP). Cleared env plus
        /// `env`.
        fn bash(h: &Hcom, label: &str, exe: &Path, env: &[(&str, &str)], with_child: bool) -> Self {
            let dir = h.root_path().join(format!("sentinel-{label}"));
            let script = sentinel_script(h);
            let mut command = Command::new(exe);
            command
                .arg(&script)
                .arg(&dir)
                .arg("HUP INT QUIT TERM USR1 USR2 CONT")
                .env_clear()
                .env("PATH", "/usr/bin:/bin");
            if with_child {
                command.env("SENTINEL_CHILD", "1");
            }
            Self::start(command, env, dir, with_child, "bash sentinel")
        }

        /// Python sentinel that makes itself non-dumpable before reporting
        /// ready, so no same-user reader can open its /proc environ.
        fn nondumpable(h: &Hcom, label: &str, env: &[(&str, &str)]) -> Self {
            let python = h
                .resolve_external("python3")
                .expect("python3 is required for the unreadable-environ fixture");
            let dir = h.root_path().join(format!("sentinel-{label}"));
            fs::create_dir_all(&dir).expect("create sentinel directory");
            let mut command = Command::new(python);
            command
                .arg("-c")
                .arg(SENTINEL_PY)
                .arg(&dir)
                .env_clear()
                .env("PATH", "/usr/bin:/bin");
            let sentinel = Self::start(command, env, dir, false, "non-dumpable sentinel");
            let environ = fs::read(format!("/proc/{}/environ", sentinel.pid()));
            assert!(
                matches!(&environ, Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
                "precondition: the sentinel's environ must be unreadable, got {environ:?}"
            );
            sentinel
        }

        fn start(
            mut command: Command,
            env: &[(&str, &str)],
            dir: PathBuf,
            with_child: bool,
            what: &str,
        ) -> Self {
            for (key, value) in env {
                command.env(key, value);
            }
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // A signal ignored at entry cannot be trapped; never inherit an
            // ignore.
            unsafe {
                command.pre_exec(|| {
                    for signal in PARENT_SIGNALS {
                        libc::signal(signal, libc::SIG_DFL);
                    }
                    Ok(())
                });
            }
            let proc = Owned::spawn(command, what);
            let mut sentinel = Self {
                proc,
                dir,
                child: None,
            };
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(exit) = sentinel.proc.peek_exit() {
                    panic!("{what} exited during setup: {exit}");
                }
                let parent_ready = sentinel.dir.join("ready").exists()
                    && beats(&sentinel.dir) > 0
                    && caught_signals(sentinel.pid()) & mask(&PARENT_SIGNALS)
                        == mask(&PARENT_SIGNALS);
                let child_ready = !with_child
                    || fs::read_to_string(sentinel.dir.join("child.pid"))
                        .ok()
                        .and_then(|text| text.parse::<u32>().ok())
                        .filter(|&pid| {
                            let child_dir = sentinel.dir.join("child");
                            member_alive(pid, sentinel.pid())
                                && child_dir.join("ready").exists()
                                && beats(&child_dir) > 0
                                && caught_signals(pid) & mask(&CHILD_SIGNALS)
                                    == mask(&CHILD_SIGNALS)
                        })
                        .map(|pid| sentinel.child = Some(pid))
                        .is_some();
                if parent_ready && child_ready {
                    return sentinel;
                }
                assert!(Instant::now() < deadline, "{what} never became ready");
                std::thread::sleep(POLL);
            }
        }

        fn pid(&self) -> u32 {
            self.proc.pid()
        }

        fn beats(&self) -> Beats {
            Beats(beats(&self.dir), beats(&self.dir.join("child")))
        }

        /// After a command: wait (bounded) until both heartbeats advanced at
        /// least twice, which proves any signal already sent had its trap
        /// run, or until either process is gone. Then report what the tree
        /// went through.
        fn observe(&self, before: Beats) -> Value {
            let (mut parent, mut child) = (false, false);
            wait_until(Duration::from_secs(5), || {
                let now = self.beats();
                parent = now.0 >= before.0 + 2;
                child = self.child.is_none() || now.1 >= before.1 + 2;
                let gone = self.proc.peek_exit().is_some()
                    || self.child.is_some_and(|pid| !member_alive(pid, self.pid()));
                (parent && child) || gone
            });
            let read = |path: PathBuf| fs::read_to_string(path).unwrap_or_default();
            json!({
                "alive": self.proc.peek_exit().is_none(),
                "exit": self.proc.peek_exit(),
                "heartbeat_progressed": parent,
                "signals": read(self.dir.join("signals")),
                "child": self.child.map(|pid| json!({
                    "alive": member_alive(pid, self.pid()),
                    "heartbeat_progressed": child,
                    "signals": read(self.dir.join("child/signals")),
                })),
            })
        }

        fn spared(&self) -> Value {
            json!({
                "alive": true,
                "exit": null,
                "heartbeat_progressed": true,
                "signals": "",
                "child": self.child.map(|_| json!({
                    "alive": true,
                    "heartbeat_progressed": true,
                    "signals": "",
                })),
            })
        }
    }

    fn beats(dir: &Path) -> u64 {
        fs::metadata(dir.join("heartbeat"))
            .map(|stat| stat.len())
            .unwrap_or(0)
    }

    fn sentinel_script(h: &Hcom) -> PathBuf {
        let script = h.root_path().join("sentinel.sh");
        if !script.exists() {
            fs::write(&script, SENTINEL_BASH).expect("write sentinel script");
        }
        script
    }

    /// A member of a fixture process group that is not this test's child. It
    /// counts as alive only while it exists unreaped in that group, so a
    /// later PID reuser never reads as it.
    struct Leftover {
        pid: u32,
        pgid: u32,
        dir: PathBuf,
    }

    impl Leftover {
        fn beats(&self) -> u64 {
            beats(&self.dir)
        }

        /// Wait (bounded) for two more heartbeats, which proves any signal
        /// already sent had its trap run, or for the leftover to be gone.
        fn observe(&self, before: u64) -> Value {
            let mut progressed = false;
            wait_until(Duration::from_secs(5), || {
                progressed = self.beats() >= before + 2;
                progressed || !member_alive(self.pid, self.pgid)
            });
            json!({
                "alive": member_alive(self.pid, self.pgid),
                "heartbeat_progressed": progressed,
                "signals": fs::read_to_string(self.dir.join("signals")).unwrap_or_default(),
            })
        }

        fn spared() -> Value {
            json!({"alive": true, "heartbeat_progressed": true, "signals": ""})
        }
    }

    /// Live (non-zombie) members of a process group, sorted.
    fn live_members(pgid: u32) -> Vec<u32> {
        let mut members: Vec<u32> = fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .filter(|&pid| member_alive(pid, pgid))
            .collect();
        members.sort_unstable();
        members
    }

    /// Precondition: wait (bounded) until `pgid`'s live members are exactly
    /// `expected`. The stand-in's own short-lived helpers exit on their own.
    #[track_caller]
    fn assert_live_members(pgid: u32, expected: &[u32]) {
        let mut expected = expected.to_vec();
        expected.sort_unstable();
        let mut members = Vec::new();
        let settled = wait_until(Duration::from_secs(10), || {
            members = live_members(pgid);
            members == expected
        });
        assert!(
            settled,
            "precondition: process group {pgid} must hold exactly {expected:?} alive, found \
             {members:?}"
        );
    }

    fn receipt_pid(h: &Hcom, name: &str) -> Option<i64> {
        db(h)
            .query_row(
                "SELECT CASE WHEN json_valid(launch_context)
                             THEN json_extract(launch_context,'$.omp_launch_pid.pid') END
                   FROM instances WHERE name=?1",
                [name],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn says(output: &str, phrase: &str) -> bool {
        output.to_lowercase().contains(phrase)
    }

    /// `output` says "<n> <word>…", with no digit right before `n`.
    fn says_count(output: &str, n: usize, word: &str) -> bool {
        let output = output.to_lowercase();
        let needle = format!("{n} {word}");
        output.match_indices(&needle).any(|(at, _)| {
            !output[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_digit())
        })
    }

    /// `output` says something was not signalled, in either spelling.
    fn says_not_signalled(output: &str) -> bool {
        ["not signal", "n't signal", "unsignal"]
            .iter()
            .any(|phrase| says(output, phrase))
    }

    #[track_caller]
    fn assert_owner_killed(owner: &HookOwner, output: &str) {
        let exit = owner.proc.wait_exit(Duration::from_secs(10));
        assert!(
            exit.as_deref().is_some_and(|e| e.starts_with("signal ")),
            "genuine owner {} was not terminated by a signal (exit {exit:?}):\n{output}",
            owner.pid()
        );
    }

    // -----------------------------------------------------------------------
    // Row 1 (+ row 5 mismatched receipt, row 7 reuser's child)
    // -----------------------------------------------------------------------

    #[test]
    fn kill_refuses_reused_pid_of_crashed_hooked_seat_and_its_tree() {
        let h = Scene::new();
        let endpoint = TcpListener::bind("127.0.0.1:0").expect("bind fixture endpoint");
        let name = format!("reused{}", unique_suffix());
        let mut owner = hooked_owner(&h, "reused", &name, &endpoint);
        let old = owner.pid();
        crash(&h, &mut owner, &name);
        let sentinel = Sentinel::bash(&h, "reused", Path::new("/bin/bash"), &[], true);
        reuse_pid(&h, &name, old, sentinel.pid());

        let before = sentinel.beats();
        let (code, output) = kill(&h, &[&name]);
        let observed = sentinel.observe(before);
        assert_eq!(
            observed,
            sentinel.spared(),
            "SAFETY: `hcom kill {name}` signalled the unrelated process (or its child) holding \
             the crashed owner's reused PID {}:\n{output}",
            sentinel.pid()
        );
        assert_ne!(code, 0, "refused kill exited 0:\n{output}");
        assert_refusal_reported(&output, &name, sentinel.pid());
        assert_row_kept(&h, &name, sentinel.pid());

        // The pointer works: stop clears the bookkeeping and still signals
        // nothing.
        let before = sentinel.beats();
        let (code, stdout, stderr) = h.run(["stop", name.as_str()]);
        let observed = sentinel.observe(before);
        assert_eq!(
            observed,
            sentinel.spared(),
            "`hcom stop {name}` signalled the PID reuser: {stdout} {stderr}"
        );
        assert_eq!(code, 0, "hcom stop {name}: {stdout} {stderr}");
        assert_eq!(
            row_facts(&h, &name)["row"],
            json!(false),
            "hcom stop {name} left its row"
        );
    }

    // -----------------------------------------------------------------------
    // Rows 2 + 7: the genuine live owner and its tree are still killed. With
    // no `hcom pty` above it the seat has no recorded launch root, so this is
    // a legacy OMP row whose launcher is not verified (rule 3): the owner
    // tree goes and the row is torn down, but the kill exits nonzero and
    // says the launcher was not verified. Real `hcom pty` launches (`mod
    // real`) cover the plain success.
    // -----------------------------------------------------------------------

    #[test]
    fn kill_terminates_genuine_hooked_owner_and_its_tree() {
        let h = Scene::new();
        let endpoint = TcpListener::bind("127.0.0.1:0").expect("bind fixture endpoint");
        let name = format!("genuine{}", unique_suffix());
        let owner = hooked_owner(&h, "genuine", &name, &endpoint);
        let tree_child = owner.spawn_tree_child(&h);

        let (code, output) = kill(&h, &[&name]);
        assert_owner_killed(&owner, &output);
        assert!(
            wait_until(Duration::from_secs(10), || !member_alive(
                tree_child,
                owner.pid()
            )),
            "the genuine owner's child {tree_child} survived the kill:\n{output}"
        );
        assert_unverified_launcher(code, &output, &name);
        assert_torn_down(&h, &name);
    }

    // -----------------------------------------------------------------------
    // Row 3: mixed multi-target kills signal only the genuine owner. Its row
    // is legacy too (rule 3), so neither target reports success.
    // -----------------------------------------------------------------------

    fn mixed_targets(target: &str) {
        let h = Scene::new();
        let endpoint = TcpListener::bind("127.0.0.1:0").expect("bind fixture endpoint");
        let suffix = unique_suffix();
        let genuine_name = format!("mixok{suffix}");
        let reused_name = format!("mixreused{suffix}");
        let tag = format!("kt{}", &suffix[suffix.len() - 6..]);

        let genuine = hooked_owner(&h, "mix-genuine", &genuine_name, &endpoint);
        let mut crashed = hooked_owner(&h, "mix-reused", &reused_name, &endpoint);
        let old = crashed.pid();
        crash(&h, &mut crashed, &reused_name);
        let sentinel = Sentinel::bash(&h, "mix", Path::new("/bin/bash"), &[], true);
        reuse_pid(&h, &reused_name, old, sentinel.pid());
        set_tag(&h, &genuine_name, &tag);
        set_tag(&h, &reused_name, &tag);

        let tag_target = format!("tag:{tag}");
        let args: Vec<&str> = match target {
            "all" => vec!["all"],
            "tag" => vec![tag_target.as_str()],
            "names" => vec![reused_name.as_str(), genuine_name.as_str()],
            other => unreachable!("{other}"),
        };
        let before = sentinel.beats();
        let (code, output) = kill(&h, &args[..]);
        let observed = sentinel.observe(before);
        assert_eq!(
            observed,
            sentinel.spared(),
            "SAFETY: `hcom kill {}` signalled the unrelated process (or its child) holding \
             {reused_name}'s reused PID {}:\n{output}",
            args.join(" "),
            sentinel.pid()
        );
        assert_owner_killed(&genuine, &output);
        assert_torn_down(&h, &genuine_name);
        assert!(
            mentions_unverified_launcher(&output)
                && !output.contains(&format!("hcom r {genuine_name}")),
            "`hcom kill {}` did not report {genuine_name}'s launcher as not verified, or \
             printed its success hint:\n{output}",
            args.join(" ")
        );
        assert_refusal_reported(&output, &reused_name, sentinel.pid());
        assert_row_kept(&h, &reused_name, sentinel.pid());
        assert_ne!(
            code,
            0,
            "`hcom kill {}` exited 0 with no target killed cleanly:\n{output}",
            args.join(" ")
        );
    }

    #[test]
    fn kill_all_signals_only_the_genuine_owner() {
        mixed_targets("all");
    }

    #[test]
    fn kill_tag_signals_only_the_genuine_owner() {
        mixed_targets("tag");
    }

    #[test]
    fn kill_two_names_signals_only_the_genuine_owner() {
        mixed_targets("names");
    }

    // -----------------------------------------------------------------------
    // Row 4: the recorded PID does not exist.
    // -----------------------------------------------------------------------

    #[test]
    fn kill_with_gone_pid_signals_nothing_and_cleans_up() {
        let h = Scene::new();
        let endpoint = TcpListener::bind("127.0.0.1:0").expect("bind fixture endpoint");
        let name = format!("gone{}", unique_suffix());
        let mut owner = hooked_owner(&h, "gone", &name, &endpoint);
        let old = owner.pid();
        crash(&h, &mut owner, &name);
        // Above pid_max: no process can ever hold it, so neither base nor
        // fixed hcom can reach a process this test did not create.
        let pid_max: u32 = fs::read_to_string("/proc/sys/kernel/pid_max")
            .expect("read pid_max")
            .trim()
            .parse()
            .expect("parse pid_max");
        let gone = pid_max + 1;
        assert!(!Path::new(&format!("/proc/{gone}")).exists());
        reuse_pid(&h, &name, old, gone);

        let (code, output) = kill(&h, &[&name]);
        assert!(
            !output.contains("Sent SIG"),
            "kill reported a signal to the nonexistent PID {gone}:\n{output}"
        );
        assert_eq!(code, 0, "kill of a gone owner failed:\n{output}");
        assert_torn_down(&h, &name);
    }

    // -----------------------------------------------------------------------
    // Row 4, zombie: the owner exited but is still unreaped. While it is, its
    // PID and its process-group id cannot pass to anyone else, so the live
    // members of its group are N's own leftovers; here the leftover is the
    // owner's child with a cleared environment, so it carries no hcom
    // identity. A zombie's environment cannot be read, so only a receipt can
    // verify it. An outsider that was never in the group is never signalled.
    // -----------------------------------------------------------------------

    /// An unrelated live process in its own process group.
    fn spawn_outsider(h: &Hcom) -> Sentinel {
        Sentinel::bash(h, "outsider", Path::new("/bin/bash"), &[], false)
    }

    #[track_caller]
    fn assert_outsider_spared(outsider: &Sentinel, before: Beats, name: &str, output: &str) {
        assert_eq!(
            outsider.observe(before),
            outsider.spared(),
            "SAFETY: `hcom kill {name}` signalled outsider {}, which was never in the zombie's \
             process group:\n{output}",
            outsider.pid()
        );
    }

    /// (a) The zombie leads its group and its receipt verifies it: the group
    /// is signalled, so the leftover gets TERM; normal cleanup runs.
    #[test]
    fn kill_zombie_leader_with_a_receipt_terminates_its_groups_leftovers() {
        let h = Scene::new();
        let endpoint = TcpListener::bind("127.0.0.1:0").expect("bind fixture endpoint");
        let name = format!("zombieleader{}", unique_suffix());
        let owner = hooked_owner(&h, "zombie-leader", &name, &endpoint);
        let leftover = owner.spawn_leftover_child(&h);
        let outsider = spawn_outsider(&h);
        let before_death = row_facts(&h, &name);
        owner.die_unreaped();
        assert_eq!(
            row_facts(&h, &name),
            before_death,
            "the death alone changed {name}'s bookkeeping"
        );
        assert_live_members(owner.pgid(), &[leftover.pid]);
        assert_eq!(
            receipt_pid(&h, &name),
            Some(i64::from(owner.pid())),
            "precondition: {name}'s receipt must name the zombie owner"
        );

        let before = (leftover.beats(), outsider.beats());
        let (code, output) = kill(&h, &[&name]);
        let seen = leftover.observe(before.0);
        assert_outsider_spared(&outsider, before.1, &name, &output);
        assert_eq!(
            (&seen["alive"], &seen["signals"]),
            (&json!(false), &json!("TERM\n")),
            "`hcom kill {name}` did not terminate leftover child {} of zombie leader {} with \
             TERM:\n{output}",
            leftover.pid,
            owner.pid()
        );
        assert_eq!(
            proc_state(owner.pid()),
            Some(('Z', i64::from(owner.pgid()))),
            "the zombie owner must stay an unreaped zombie"
        );
        assert!(
            says(&output, "already exited")
                && says_count(&output, 1, "leftover")
                && says(&output, "terminated"),
            "kill did not say {name}'s owner had already exited and 1 leftover process was \
             terminated:\n{output}"
        );
        assert_eq!(
            code, 0,
            "kill of a verified zombie leader failed:\n{output}"
        );
        assert_torn_down(&h, &name);
    }

    /// (b) A legacy row: no receipt, and a zombie's environment cannot be
    /// read. Nothing is signalled; the leftovers are listed, with the
    /// `hcom stop` pointer, and the kill is not reported clean.
    #[test]
    fn kill_zombie_without_a_receipt_signals_nothing_and_lists_its_leftovers() {
        let h = Scene::new();
        let name = format!("zombielegacy{}", unique_suffix());
        let owner = HookOwner::spawn(&h, "zombie-legacy");
        seed_legacy_row(&h, &name, &owner.process_id, Some(owner.pid()));
        let leftover = owner.spawn_leftover_child(&h);
        let outsider = spawn_outsider(&h);
        owner.die_unreaped();
        assert_eq!(
            receipt_pid(&h, &name),
            None,
            "precondition: a legacy row carries no receipt"
        );
        assert!(
            fs::read(format!("/proc/{}/environ", owner.pid()))
                .map(|environ| environ.is_empty())
                .unwrap_or(true),
            "precondition: a zombie's environment cannot be read"
        );
        assert_live_members(owner.pgid(), &[leftover.pid]);

        let before = (leftover.beats(), outsider.beats());
        let (code, output) = kill(&h, &[&name]);
        let seen = leftover.observe(before.0);
        assert_outsider_spared(&outsider, before.1, &name, &output);
        assert_eq!(
            seen,
            Leftover::spared(),
            "SAFETY: `hcom kill {name}` signalled leftover child {} although nothing verifies \
             zombie owner {}:\n{output}",
            leftover.pid,
            owner.pid()
        );
        assert_eq!(
            proc_state(owner.pid()),
            Some(('Z', i64::from(owner.pgid()))),
            "the zombie owner must stay an unreaped zombie"
        );
        assert!(
            names_pid(&output, leftover.pid) && says_not_signalled(&output),
            "kill did not list leftover {} as not signalled:\n{output}",
            leftover.pid
        );
        assert!(
            output.contains(&format!("hcom stop {name}")),
            "kill did not point at `hcom stop {name}`:\n{output}"
        );
        assert!(
            !output.contains("Sent SIG"),
            "kill reported a signal for an unverifiable zombie:\n{output}"
        );
        assert_ne!(
            code, 0,
            "kill claimed a clean kill of an unverifiable zombie:\n{output}"
        );
        assert_row_kept(&h, &name, owner.pid());
    }

    /// (c) The zombie is verified by its receipt but does not lead its group:
    /// the idle launcher above it does. No group is signalled; normal cleanup
    /// runs.
    #[test]
    fn kill_zombie_that_does_not_lead_its_group_signals_no_group() {
        let h = Scene::new();
        let endpoint = TcpListener::bind("127.0.0.1:0").expect("bind fixture endpoint");
        let name = format!("zombiemember{}", unique_suffix());
        let owner =
            self_anchored_owner(&h, "zombie-member", &name, &endpoint, Launch::IdleLauncher);
        let leftover = owner.spawn_leftover_child(&h);
        let outsider = spawn_outsider(&h);
        let before_death = row_facts(&h, &name);
        owner.die_unreaped();
        assert_eq!(
            row_facts(&h, &name),
            before_death,
            "the death alone changed {name}'s bookkeeping"
        );
        assert_live_members(owner.pgid(), &[owner.pgid(), leftover.pid]);
        assert_eq!(
            receipt_pid(&h, &name),
            Some(i64::from(owner.pid())),
            "precondition: {name}'s receipt must name the zombie owner"
        );

        let before = (leftover.beats(), outsider.beats());
        let (code, output) = kill(&h, &[&name]);
        let seen = leftover.observe(before.0);
        assert_outsider_spared(&outsider, before.1, &name, &output);
        assert_eq!(
            seen,
            Leftover::spared(),
            "`hcom kill {name}` signalled leftover child {} in launcher {}'s group, which zombie \
             owner {} does not lead:\n{output}",
            leftover.pid,
            owner.pgid(),
            owner.pid()
        );
        assert_eq!(
            owner.proc.peek_exit(),
            None,
            "`hcom kill {name}` signalled launcher {}, which leads the zombie's group:\n{output}",
            owner.pgid()
        );
        assert_eq!(
            proc_state(owner.pid()),
            Some(('Z', i64::from(owner.pgid()))),
            "the zombie owner must stay an unreaped zombie"
        );
        assert!(
            !output.contains("Sent SIG"),
            "kill reported a group signal for a zombie that does not lead its group:\n{output}"
        );
        assert_eq!(code, 0, "kill of a verified zombie failed:\n{output}");
        assert_torn_down(&h, &name);
    }

    // -----------------------------------------------------------------------
    // Rows 2 + 7, launched shape: a launcher leads the process group and
    // anchors the launch; the OMP is its child, and the OMP's first hook
    // re-pins the row to it. The verified owner is not its group leader. The
    // launcher is not `hcom pty`, so rule 3 applies as above.
    // -----------------------------------------------------------------------

    #[test]
    fn kill_terminates_launched_owner_that_does_not_lead_its_group() {
        let h = Scene::new();
        let endpoint = TcpListener::bind("127.0.0.1:0").expect("bind fixture endpoint");
        let name = format!("launched{}", unique_suffix());
        let owner = launched_owner(&h, "launched", &name, &endpoint);
        assert_eq!(
            proc_state(owner.pid()).map(|(_, pgrp)| pgrp),
            Some(i64::from(owner.pgid())),
            "precondition: the OMP must be in its launcher's process group"
        );
        let tree_child = owner.spawn_tree_child(&h);

        let (code, output) = kill(&h, &[&name]);
        assert!(
            wait_until(Duration::from_secs(10), || !member_alive(
                owner.pid(),
                owner.pgid()
            )),
            "launched owner {} below launcher {} survived `hcom kill {name}`:\n{output}",
            owner.pid(),
            owner.pgid()
        );
        assert!(
            wait_until(Duration::from_secs(10), || !member_alive(
                tree_child,
                owner.pgid()
            )),
            "the launched owner's child {tree_child} survived the kill:\n{output}"
        );
        assert_unverified_launcher(code, &output, &name);
        assert_torn_down(&h, &name);
    }

    // -----------------------------------------------------------------------
    // Row 5: unreadable or mismatched identity evidence signals nothing.
    // -----------------------------------------------------------------------

    #[test]
    fn kill_refuses_legacy_owner_whose_environ_is_unreadable() {
        let h = Scene::new();
        let name = format!("unread{}", unique_suffix());
        let process_id = uuid::Uuid::new_v4().to_string();
        // It even carries the bound id; unreadable evidence still proves
        // nothing.
        let sentinel = Sentinel::nondumpable(&h, "unreadable", &[("HCOM_PROCESS_ID", &process_id)]);
        seed_legacy_row(&h, &name, &process_id, Some(sentinel.pid()));

        let before = sentinel.beats();
        let (code, output) = kill(&h, &[&name]);
        let observed = sentinel.observe(before);
        assert_eq!(
            observed,
            sentinel.spared(),
            "SAFETY: `hcom kill {name}` signalled PID {} whose identity evidence is \
             unreadable:\n{output}",
            sentinel.pid()
        );
        assert_ne!(code, 0, "refused kill exited 0:\n{output}");
        assert_refusal_reported(&output, &name, sentinel.pid());
        assert_row_kept(&h, &name, sentinel.pid());
    }

    fn mismatched_process_id(case: &str) {
        let h = Scene::new();
        let suffix = unique_suffix();
        let name = format!("mismatch{suffix}");
        let process_id = uuid::Uuid::new_v4().to_string();
        let carried = if case == "another-instances-binding" {
            let other_id = uuid::Uuid::new_v4().to_string();
            seed_legacy_row(&h, &format!("other{suffix}"), &other_id, None);
            other_id
        } else {
            uuid::Uuid::new_v4().to_string()
        };
        let omp = fakebin(&h).join("omp");
        let sentinel = Sentinel::bash(
            &h,
            case,
            &omp,
            &[("HCOM_PROCESS_ID", carried.as_str())],
            false,
        );
        seed_legacy_row(&h, &name, &process_id, Some(sentinel.pid()));

        let before = sentinel.beats();
        let (code, output) = kill(&h, &[&name]);
        let observed = sentinel.observe(before);
        assert_eq!(
            observed,
            sentinel.spared(),
            "SAFETY [{case}]: `hcom kill {name}` signalled PID {} whose HCOM_PROCESS_ID is not \
             {name}'s binding:\n{output}",
            sentinel.pid()
        );
        assert_ne!(code, 0, "[{case}] refused kill exited 0:\n{output}");
        assert_refusal_reported(&output, &name, sentinel.pid());
        assert_row_kept(&h, &name, sentinel.pid());
    }

    #[test]
    fn kill_refuses_legacy_owner_carrying_another_instances_process_id() {
        mismatched_process_id("another-instances-binding");
    }

    #[test]
    fn kill_refuses_legacy_owner_carrying_an_unregistered_process_id() {
        mismatched_process_id("unregistered-id");
    }

    // -----------------------------------------------------------------------
    // Row 6: legacy rows (no persisted identity record) on Linux decide by
    // the live process's HCOM_PROCESS_ID. Both processes have comm `omp`;
    // only the carried id differs. With no recorded launch root and a
    // launcher (this test) that is not `hcom pty`, the owner tree still goes
    // but the kill must say the launcher was not verified.
    // -----------------------------------------------------------------------

    #[test]
    fn kill_legacy_row_kills_process_carrying_the_bound_process_id() {
        let h = Scene::new();
        let name = format!("legacyok{}", unique_suffix());
        let process_id = uuid::Uuid::new_v4().to_string();
        let omp = fakebin(&h).join("omp");
        let owner = Sentinel::bash(
            &h,
            "legacy-owner",
            &omp,
            &[("HCOM_PROCESS_ID", process_id.as_str())],
            false,
        );
        seed_legacy_row(&h, &name, &process_id, Some(owner.pid()));

        let (code, output) = kill(&h, &[&name]);
        let exit = owner.proc.wait_exit(Duration::from_secs(10));
        assert!(
            exit.is_some(),
            "legacy owner {} carrying {name}'s bound HCOM_PROCESS_ID survived the kill:\n{output}",
            owner.pid()
        );
        assert_unverified_launcher(code, &output, &name);
        assert_torn_down(&h, &name);
    }

    /// A non-OMP row has no launch root to record: its verified PID is the
    /// root, and the kill retires that process's tree as a plain success.
    #[test]
    fn kill_non_omp_row_retires_the_verified_process_tree() {
        let h = Scene::new();
        let name = format!("nonomp{}", unique_suffix());
        let process_id = uuid::Uuid::new_v4().to_string();
        let owner = Sentinel::bash(
            &h,
            "non-omp-owner",
            Path::new("/bin/bash"),
            &[("HCOM_PROCESS_ID", process_id.as_str())],
            true,
        );
        let child = owner.child.expect("non-OMP owner child");
        seed_bound_row(&h, "claude", &name, &process_id, Some(owner.pid()));

        let (code, output) = kill(&h, &[&name]);
        let exit = owner.proc.wait_exit(Duration::from_secs(10));
        assert!(
            exit.is_some(),
            "the verified non-OMP owner {} survived `hcom kill {name}`:\n{output}",
            owner.pid()
        );
        assert!(
            wait_until(Duration::from_secs(10), || !member_alive(
                child,
                owner.pid()
            )),
            "the non-OMP owner's child {child} survived the kill:\n{output}"
        );
        assert_kill_succeeded(code, &output, &name);
        assert_torn_down(&h, &name);
    }

    #[test]
    fn kill_legacy_row_refuses_process_without_the_bound_process_id() {
        let h = Scene::new();
        let name = format!("legacyno{}", unique_suffix());
        let process_id = uuid::Uuid::new_v4().to_string();
        let omp = fakebin(&h).join("omp");
        let sentinel = Sentinel::bash(&h, "legacy-stranger", &omp, &[], true);
        seed_legacy_row(&h, &name, &process_id, Some(sentinel.pid()));

        let before = sentinel.beats();
        let (code, output) = kill(&h, &[&name]);
        let observed = sentinel.observe(before);
        assert_eq!(
            observed,
            sentinel.spared(),
            "SAFETY: `hcom kill {name}` signalled PID {} (or its child), which does not carry \
             {name}'s bound HCOM_PROCESS_ID:\n{output}",
            sentinel.pid()
        );
        assert_ne!(code, 0, "refused kill exited 0:\n{output}");
        assert_refusal_reported(&output, &name, sentinel.pid());
        assert_row_kept(&h, &name, sentinel.pid());
    }
}

// ===========================================================================
// Windows and macOS. A Node process running a supported OMP script path is
// the owner (as tests/omp_native_owner.rs does), verified by its receipt or,
// for a legacy row, by its native HCOM_PROCESS_ID. Sentinels are Node
// processes that record any catchable signal and keep a heartbeat. Windows
// has no POSIX signals, so there the evidence is liveness and heartbeat alone.
// ===========================================================================

#[cfg(any(windows, target_os = "macos"))]
mod native {
    use super::*;

    use std::cell::Cell;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};

    /// Owner loop: runs each `step-N.json` request and answers in
    /// `step-N.json.out`. A `hook` step runs the hcom binary as this
    /// process's child; a `child` step starts a long-lived sentinel child in
    /// this owner's tree.
    const OWNER_RUNNER: &str = r#"
const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const dir = process.env.TEST_OWNER_DIR;
function answer(entry, value) {
    const out = path.join(dir, `${entry}.out`);
    fs.writeFileSync(`${out}.tmp`, JSON.stringify(value));
    fs.renameSync(`${out}.tmp`, out);
}
fs.writeFileSync(path.join(dir, 'ready.tmp'), JSON.stringify({
    pid: process.pid, ppid: process.ppid, process_id: process.env.HCOM_PROCESS_ID,
}));
fs.renameSync(path.join(dir, 'ready.tmp'), path.join(dir, 'ready'));
const born = Date.now();
setInterval(() => {
    if (fs.existsSync(path.join(dir, 'stop')) || Date.now() - born > 300000) process.exit(0);
    fs.appendFileSync(path.join(dir, 'heartbeat'), 'x');
    for (const entry of fs.readdirSync(dir)) {
        if (!/^step-\d+\.json$/.test(entry) || fs.existsSync(path.join(dir, `${entry}.out`))) continue;
        const step = JSON.parse(fs.readFileSync(path.join(dir, entry), 'utf8'));
        if (step.kind === 'child') {
            const child = spawn(process.execPath, [step.script, step.dir],
                { stdio: 'ignore', windowsHide: true });
            answer(entry, { pid: child.pid });
            continue;
        }
        const env = { ...process.env, HCOM_LAUNCHED: '1', HCOM_TOOL: 'omp' };
        if (step.name) env.HCOM_INSTANCE_NAME = step.name;
        const result = spawnSync(process.env.TEST_HCOM_BIN, step.args,
            { env, encoding: 'utf8', timeout: 15000, windowsHide: true });
        answer(entry, {
            code: result.status === null ? -1 : result.status,
            stdout: result.stdout || '',
            stderr: (result.stderr || '') + (result.error ? `\nfixture error: ${result.error.message}` : ''),
        });
    }
}, 15);
"#;

    /// Sentinel: records any catchable signal and exits; heartbeat every
    /// 50ms; optional child that does the same; exits on its own `stop` file
    /// or after 300s so it can never outlive a crashed test.
    const SENTINEL_JS: &str = r#"
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const dir = process.argv[2];
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'signals'), '');
const signals = process.platform === 'win32'
    ? ['SIGINT', 'SIGBREAK', 'SIGHUP']
    : ['SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGTERM', 'SIGUSR2', 'SIGCONT'];
for (const name of signals) {
    process.on(name, () => {
        fs.appendFileSync(path.join(dir, 'signals'), `${name.slice(3)}\n`);
        process.exit(0);
    });
}
if (process.argv[3] === 'with-child') {
    const child = spawn(process.execPath, [__filename, path.join(dir, 'child')],
        { stdio: 'ignore', windowsHide: true });
    fs.writeFileSync(path.join(dir, 'child.pid'), String(child.pid));
}
const born = Date.now();
setInterval(() => {
    if (fs.existsSync(path.join(dir, 'stop')) || Date.now() - born > 300000) process.exit(0);
    fs.appendFileSync(path.join(dir, 'heartbeat'), 'x');
}, 50);
fs.writeFileSync(path.join(dir, 'ready'), String(process.pid));
"#;

    /// The launcher of a launch: it anchors the reservation first, then runs
    /// the Node interpreter as a child it waits on, not exec'd.
    #[cfg(unix)]
    const LAUNCHER_SH: &str = r#"
HCOM_LAUNCHED=1 HCOM_TOOL=omp "$TEST_HCOM_BIN" launch-anchor > "$TEST_OWNER_DIR/anchor.stdout" 2> "$TEST_OWNER_DIR/anchor.stderr"
printf '%s' "$?" > "$TEST_OWNER_DIR/anchor.code"
"$TEST_OWNER_RUNTIME" "$TEST_OWNER_SCRIPT" &
wait "$!"
"#;

    /// Windows: the same launcher as npm's `omp.cmd` shape, run by cmd.exe.
    #[cfg(windows)]
    const LAUNCHER_CMD: &str = "@echo off\r\nsetlocal\r\nset HCOM_LAUNCHED=1\r\nset HCOM_TOOL=omp\r\n\"%TEST_HCOM_BIN%\" launch-anchor > \"%TEST_OWNER_DIR%\\anchor.stdout\" 2> \"%TEST_OWNER_DIR%\\anchor.stderr\"\r\n> \"%TEST_OWNER_DIR%\\anchor.code\" echo %ERRORLEVEL%\r\nendlocal\r\n\"%TEST_OWNER_RUNTIME%\" \"%TEST_OWNER_SCRIPT%\"\r\n";

    /// A process-group leader running [`LAUNCHER_SH`].
    #[cfg(unix)]
    fn launcher_command(h: &Hcom, _root: &Path) -> Command {
        let mut command = h.external_cmd("/bin/sh");
        command.arg("-c").arg(LAUNCHER_SH);
        command
    }

    /// cmd.exe running [`LAUNCHER_CMD`] as `omp.cmd`.
    #[cfg(windows)]
    fn launcher_command(h: &Hcom, root: &Path) -> Command {
        let shim = root.join("omp.cmd");
        fs::write(&shim, LAUNCHER_CMD).unwrap();
        let mut command = h.external_cmd("cmd.exe");
        command.args(["/d", "/c"]).arg(&shim);
        command
    }

    fn beats(dir: &Path) -> u64 {
        fs::metadata(dir.join("heartbeat"))
            .map(|stat| stat.len())
            .unwrap_or(0)
    }

    /// True once `dir`'s heartbeat stops advancing for a full second, within
    /// `timeout`. Used for processes that are not this test's children, so no
    /// PID lookup can mistake a reuser for them.
    fn heartbeat_stops(dir: &Path, timeout: Duration) -> bool {
        let mut last = (beats(dir), Instant::now());
        wait_until(timeout, || {
            let now = beats(dir);
            if now != last.0 {
                last = (now, Instant::now());
            }
            last.1.elapsed() >= Duration::from_secs(1)
        })
    }

    fn heartbeat_advances(dir: &Path, before: u64) -> bool {
        wait_until(Duration::from_secs(5), || beats(dir) >= before + 2)
    }

    /// The actual Node executable: npm's Windows entrypoint may be a shim.
    fn node(h: &Hcom) -> PathBuf {
        let resolved = h
            .external_cmd("node")
            .args(["--print", "process.execPath"])
            .output()
            .unwrap_or_else(|error| panic!("node is required; CI installs it: {error}"));
        assert!(
            resolved.status.success(),
            "node executable resolution failed: {}",
            String::from_utf8_lossy(&resolved.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(resolved.stdout).unwrap().trim());
        assert!(
            executable.is_absolute() && executable.is_file(),
            "invalid node path: {executable:?}"
        );
        executable
    }

    /// An owned direct child that stops itself through `dir/stop` (and
    /// `dir/child/stop`). Exit is read with `try_wait`; once observed, the
    /// child is reaped and never signalled again.
    struct Proc {
        child: Child,
        dir: PathBuf,
        exit: Option<String>,
    }

    impl Proc {
        fn spawn(mut command: Command, dir: PathBuf, what: &str) -> Self {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(unix)]
            command.process_group(0);
            let child = command
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {what}: {e}"));
            Self {
                child,
                dir,
                exit: None,
            }
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }

        fn exit(&mut self) -> Option<String> {
            if self.exit.is_none() {
                self.exit = self
                    .child
                    .try_wait()
                    .expect("poll fixture child")
                    .map(|status| status.to_string());
            }
            self.exit.clone()
        }

        fn wait_exit(&mut self, timeout: Duration) -> Option<String> {
            let mut exit = None;
            wait_until(timeout, || {
                exit = self.exit();
                exit.is_some()
            });
            exit
        }

        /// Abrupt death with no cleanup, then reap so the PID is free.
        fn crash(&mut self) {
            assert!(self.exit().is_none(), "fixture owner exited before crash");
            // Unreaped, so this PID and process group are still ours.
            #[cfg(unix)]
            unsafe {
                libc::killpg(self.pid() as libc::pid_t, libc::SIGKILL);
            }
            #[cfg(windows)]
            let _ = self.child.kill();
            let status = self.child.wait().expect("reap crashed fixture owner");
            self.exit = Some(status.to_string());
        }
    }

    impl Drop for Proc {
        fn drop(&mut self) {
            let _ = fs::write(self.dir.join("stop"), "");
            let _ = fs::write(self.dir.join("child").join("stop"), "");
            if self.wait_exit(Duration::from_secs(3)).is_some() {
                return;
            }
            // Still unreaped, so this PID (and on Unix its group) is ours.
            #[cfg(unix)]
            unsafe {
                libc::killpg(self.pid() as libc::pid_t, libc::SIGKILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    struct NativeOwner {
        proc: Proc,
        pid: u32,
        process_id: String,
        step: Cell<usize>,
        root: PathBuf,
    }

    impl NativeOwner {
        fn spawn(h: &Hcom, label: &str) -> Self {
            Self::start(h, label, &uuid::Uuid::new_v4().to_string(), false)
        }

        /// `launcher`: the interpreter runs below a launcher (see
        /// [`launcher_command`]); `process_id`'s reservation must already
        /// exist, because the launcher anchors it before it starts Node.
        fn start(h: &Hcom, label: &str, process_id: &str, launcher: bool) -> Self {
            let root = h.root_path().join(format!("owner-{label}"));
            let script = root.join("node_modules/@oh-my-pi/pi-coding-agent/dist/cli.js");
            fs::create_dir_all(script.parent().unwrap()).unwrap();
            fs::write(&script, OWNER_RUNNER).unwrap();
            let dir = root.join("steps");
            fs::create_dir_all(&dir).unwrap();
            let node = node(h);
            let mut command = if launcher {
                launcher_command(h, &root)
            } else {
                let mut command = h.external_cmd(&node);
                command.arg(&script);
                command
            };
            command
                .env("TEST_OWNER_RUNTIME", &node)
                .env("TEST_OWNER_SCRIPT", &script)
                .env("HCOM_PROCESS_ID", process_id)
                .env("TEST_OWNER_DIR", &dir)
                .env("TEST_HCOM_BIN", env!("CARGO_BIN_EXE_hcom"));
            let proc = Proc::spawn(command, dir.clone(), "native OMP owner");
            let ready: Value = h.eventually("native owner ready", Duration::from_secs(30), || {
                Ok(fs::read_to_string(dir.join("ready"))
                    .ok()
                    .and_then(|text| serde_json::from_str(&text).ok()))
            });
            assert_eq!(ready["process_id"], process_id);
            let pid = u32::try_from(ready["pid"].as_u64().unwrap()).unwrap();
            if launcher {
                assert_ne!(
                    pid,
                    proc.pid(),
                    "the Node interpreter must be its launcher's child, not exec'd"
                );
            } else {
                assert_eq!(pid, proc.pid(), "fixture must be the actual Node process");
            }
            Self {
                proc,
                pid,
                process_id: process_id.to_string(),
                step: Cell::new(0),
                root,
            }
        }

        fn request(&self, h: &Hcom, request: Value) -> Value {
            let step = self.step.get();
            self.step.set(step + 1);
            native_request(h, &self.proc.dir, step, request)
        }

        fn run(&self, h: &Hcom, args: &[&str], name: Option<&str>) -> (i32, String, String) {
            let out = self.request(h, json!({"kind": "hook", "args": args, "name": name}));
            (
                i32::try_from(out["code"].as_i64().unwrap()).unwrap(),
                out["stdout"].as_str().unwrap().to_string(),
                out["stderr"].as_str().unwrap().to_string(),
            )
        }

        /// The launcher's own `hcom launch-anchor` run.
        fn launcher_anchor(&self, h: &Hcom) -> (i32, String, String) {
            let code = h.eventually("launcher anchor finished", Duration::from_secs(30), || {
                Ok(fs::read_to_string(self.proc.dir.join("anchor.code"))
                    .ok()
                    .filter(|text| !text.trim().is_empty()))
            });
            let read =
                |file: &str| fs::read_to_string(self.proc.dir.join(file)).unwrap_or_default();
            (
                code.trim().parse().expect("anchor exit code"),
                read("anchor.stdout"),
                read("anchor.stderr"),
            )
        }

        /// A long-lived sentinel child in this owner's tree, carrying its
        /// environment. Returns the child's heartbeat directory.
        fn spawn_tree_child(&self, h: &Hcom) -> PathBuf {
            let script = h.root_path().join("sentinel.js");
            if !script.exists() {
                fs::write(&script, SENTINEL_JS).unwrap();
            }
            // Under the owner's step dir, so the owner's drop stops it too.
            let dir = self.proc.dir.join("child");
            self.request(h, json!({"kind": "child", "script": script, "dir": dir}));
            assert!(
                wait_until(Duration::from_secs(30), || dir.join("ready").exists()
                    && beats(&dir) > 0),
                "owner tree child never became ready"
            );
            dir
        }
    }

    /// Registered as an hcom launch registers it: a pending reservation,
    /// `hcom launch-anchor` from the owner (PID plus native identity
    /// receipt), then `omp-start`.
    fn registered_owner(h: &Hcom, label: &str, name: &str) -> NativeOwner {
        let owner = NativeOwner::spawn(h, label);
        launch_row(h, name, &owner.process_id);
        let anchor = owner.run(h, &["launch-anchor"], None);
        assert_receipt(h, name, owner.pid, &anchor);
        start_session(h, &owner, name);
        owner
    }

    /// The launched shape: the launcher anchors the reservation (its own PID
    /// and receipt); the interpreter below it binds through `omp-start`,
    /// which must re-pin the row to the interpreter.
    fn launched_owner(h: &Hcom, label: &str, name: &str) -> NativeOwner {
        let process_id = uuid::Uuid::new_v4().to_string();
        launch_row(h, name, &process_id);
        let owner = NativeOwner::start(h, label, &process_id, true);
        let anchor = owner.launcher_anchor(h);
        assert_receipt(h, name, owner.proc.pid(), &anchor);
        start_session(h, &owner, name);
        owner
    }

    /// `omp-start` from the interpreter; the row must end up bound to the
    /// interpreter's own PID.
    fn start_session(h: &Hcom, owner: &NativeOwner, name: &str) {
        let sid = uuid::Uuid::new_v4().to_string();
        let transcript = owner.root.join(format!("{sid}.jsonl"));
        let start = owner.run(
            h,
            &[
                "omp-start",
                "--session-id",
                &sid,
                "--transcript-path",
                transcript.to_str().unwrap(),
                "--cwd",
                h.workspace.to_str().unwrap(),
            ],
            Some(name),
        );
        assert_bound(h, name, owner.pid, &start);
    }

    struct Sentinel {
        proc: Proc,
    }

    impl Sentinel {
        /// A Node sentinel with a cleared environment, plus `HCOM_PROCESS_ID`
        /// when given. `omp` runs it from a supported OMP script path, so
        /// native discovery sees an OMP process; its child runs the same
        /// script and inherits the same environment.
        fn spawn(h: &Hcom, label: &str, omp: bool, process_id: Option<&str>) -> Self {
            let script = if omp {
                h.root_path()
                    .join(format!("omp-{label}"))
                    .join("node_modules/@oh-my-pi/pi-coding-agent/dist/cli.js")
            } else {
                h.root_path().join("sentinel.js")
            };
            if !script.exists() {
                fs::create_dir_all(script.parent().unwrap()).unwrap();
                fs::write(&script, SENTINEL_JS).unwrap();
            }
            let dir = h.root_path().join(format!("sentinel-{label}"));
            let mut command = Command::new(node(h));
            command.arg(&script).arg(&dir).arg("with-child").env_clear();
            #[cfg(windows)]
            for key in ["SystemRoot", "WINDIR"] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
            if let Some(process_id) = process_id {
                command.env("HCOM_PROCESS_ID", process_id);
            }
            let mut sentinel = Self {
                proc: Proc::spawn(command, dir, "native sentinel"),
            };
            let child = sentinel.proc.dir.join("child");
            let ready = wait_until(Duration::from_secs(30), || {
                sentinel.proc.dir.join("ready").exists()
                    && beats(&sentinel.proc.dir) > 0
                    && child.join("ready").exists()
                    && beats(&child) > 0
            });
            assert!(
                ready,
                "native sentinel never became ready (exit {:?})",
                sentinel.proc.exit()
            );
            sentinel
        }

        fn pid(&self) -> u32 {
            self.proc.pid()
        }

        fn beats(&self) -> (u64, u64) {
            (beats(&self.proc.dir), beats(&self.proc.dir.join("child")))
        }

        fn observe(&mut self, before: (u64, u64)) -> Value {
            let dir = self.proc.dir.clone();
            let child = dir.join("child");
            let parent_progressed = heartbeat_advances(&dir, before.0);
            let child_progressed = heartbeat_advances(&child, before.1);
            let read = |path: PathBuf| fs::read_to_string(path).unwrap_or_default();
            json!({
                "exit": self.proc.exit(),
                "heartbeat_progressed": parent_progressed,
                "signals": read(dir.join("signals")),
                "child": {
                    "heartbeat_progressed": child_progressed,
                    "signals": read(child.join("signals")),
                },
            })
        }

        fn spared() -> Value {
            json!({
                "exit": null,
                "heartbeat_progressed": true,
                "signals": "",
                "child": {"heartbeat_progressed": true, "signals": ""},
            })
        }
    }

    /// With no `hcom pty` above it this seat has no recorded launch root: a
    /// legacy OMP row whose launcher is not verified (rule 3). The owner tree
    /// goes and the row is torn down, but the kill exits nonzero and says
    /// so. Real launches (`mod real`, and the Windows omp.cmd launch below)
    /// cover the plain success.
    #[test]
    fn native_kill_terminates_genuine_registered_owner_and_its_tree() {
        let h = Scene::new();
        let name = format!("nativeok{}", unique_suffix());
        let mut owner = registered_owner(&h, "genuine", &name);
        let tree = owner.spawn_tree_child(&h);

        let (code, output) = kill(&h, &[&name]);
        let exit = owner.proc.wait_exit(Duration::from_secs(10));
        assert!(
            exit.is_some(),
            "genuine native owner {} with a receipt survived `hcom kill {name}`:\n{output}",
            owner.pid
        );
        assert!(
            heartbeat_stops(&tree, Duration::from_secs(10)),
            "the genuine native owner's tree child survived the kill:\n{output}"
        );
        assert_unverified_launcher(code, &output, &name);
        assert_torn_down(&h, &name);
    }

    #[test]
    fn native_kill_refuses_reused_pid_of_crashed_registered_owner() {
        let h = Scene::new();
        let name = format!("nativereused{}", unique_suffix());
        let mut owner = registered_owner(&h, "reused", &name);
        let old = owner.pid;
        let before_crash = row_facts(&h, &name);
        owner.proc.crash();
        assert_eq!(
            row_facts(&h, &name),
            before_crash,
            "the crash alone changed {name}'s bookkeeping"
        );
        let mut sentinel = Sentinel::spawn(&h, "reused", false, None);
        reuse_pid(&h, &name, old, sentinel.pid());

        let before = sentinel.beats();
        let (code, output) = kill(&h, &[&name]);
        let observed = sentinel.observe(before);
        assert_eq!(
            observed,
            Sentinel::spared(),
            "SAFETY: `hcom kill {name}` terminated or signalled the unrelated process (or its \
             child) holding the crashed owner's reused PID {}:\n{output}",
            sentinel.pid()
        );
        assert_ne!(code, 0, "refused kill exited 0:\n{output}");
        assert_refusal_reported(&output, &name, sentinel.pid());
        assert_row_kept(&h, &name, sentinel.pid());
    }

    // -----------------------------------------------------------------------
    // Launched shape: a launcher anchors the launch and the interpreter below
    // it re-pins the row on its first hook, so the verified owner is not the
    // launched process, and on macOS not its group leader. The launcher is
    // not `hcom pty`: rule 3 applies, and only the interpreter and its tree
    // must go.
    // -----------------------------------------------------------------------

    #[test]
    fn native_kill_terminates_launched_owner_below_its_launcher() {
        let h = Scene::new();
        let name = format!("nativelaunched{}", unique_suffix());
        let owner = launched_owner(&h, "launched", &name);
        #[cfg(unix)]
        assert_eq!(
            unsafe { libc::getpgid(owner.pid as libc::pid_t) },
            owner.proc.pid() as libc::pid_t,
            "precondition: the interpreter must be in its launcher's process group"
        );
        let tree = owner.spawn_tree_child(&h);

        let (code, output) = kill(&h, &[&name]);
        assert!(
            heartbeat_stops(&owner.proc.dir, Duration::from_secs(10)),
            "launched native owner {} below launcher {} survived `hcom kill {name}`:\n{output}",
            owner.pid,
            owner.proc.pid()
        );
        assert!(
            heartbeat_stops(&tree, Duration::from_secs(10)),
            "the launched native owner's tree child survived the kill:\n{output}"
        );
        assert_unverified_launcher(code, &output, &name);
        assert_torn_down(&h, &name);
    }

    // -----------------------------------------------------------------------
    // Legacy rows: no receipt, so the live process's own HCOM_PROCESS_ID,
    // read natively, is the only evidence. Every process runs from the OMP
    // script path; only the carried id differs. With no recorded launch root
    // and a launcher (this test) that is not `hcom pty`, the owner tree still
    // goes but the kill must say the launcher was not verified.
    // -----------------------------------------------------------------------

    #[test]
    fn native_kill_legacy_row_kills_process_carrying_the_bound_process_id() {
        let h = Scene::new();
        let name = format!("nativelegacyok{}", unique_suffix());
        let process_id = uuid::Uuid::new_v4().to_string();
        let mut owner = Sentinel::spawn(&h, "legacy-owner", true, Some(&process_id));
        seed_legacy_row(&h, &name, &process_id, Some(owner.pid()));

        let (code, output) = kill(&h, &[&name]);
        let exit = owner.proc.wait_exit(Duration::from_secs(10));
        assert!(
            exit.is_some(),
            "legacy native owner {} carrying {name}'s bound HCOM_PROCESS_ID survived the \
             kill:\n{output}",
            owner.pid()
        );
        assert!(
            heartbeat_stops(&owner.proc.dir.join("child"), Duration::from_secs(10)),
            "the legacy native owner's tree child survived the kill:\n{output}"
        );
        assert_unverified_launcher(code, &output, &name);
        assert_torn_down(&h, &name);
    }

    /// A non-OMP row has no launch root to record: its verified PID is the
    /// root, and the kill retires that process's tree as a plain success.
    #[test]
    fn native_kill_non_omp_row_retires_the_verified_process_tree() {
        let h = Scene::new();
        let name = format!("nativenonomp{}", unique_suffix());
        let process_id = uuid::Uuid::new_v4().to_string();
        let mut owner = Sentinel::spawn(&h, "non-omp-owner", false, Some(&process_id));
        seed_bound_row(&h, "claude", &name, &process_id, Some(owner.pid()));

        let (code, output) = kill(&h, &[&name]);
        let exit = owner.proc.wait_exit(Duration::from_secs(10));
        assert!(
            exit.is_some(),
            "the verified non-OMP owner {} survived `hcom kill {name}`:\n{output}",
            owner.pid()
        );
        assert!(
            heartbeat_stops(&owner.proc.dir.join("child"), Duration::from_secs(10)),
            "the non-OMP owner's child survived the kill:\n{output}"
        );
        assert_kill_succeeded(code, &output, &name);
        assert_torn_down(&h, &name);
    }

    fn native_legacy_row_refused(case: &str, carried: Option<&str>) {
        let h = Scene::new();
        let name = format!("nativelegacyno{}", unique_suffix());
        let process_id = uuid::Uuid::new_v4().to_string();
        let mut sentinel = Sentinel::spawn(&h, case, true, carried);
        seed_legacy_row(&h, &name, &process_id, Some(sentinel.pid()));

        let before = sentinel.beats();
        let (code, output) = kill(&h, &[&name]);
        let observed = sentinel.observe(before);
        assert_eq!(
            observed,
            Sentinel::spared(),
            "SAFETY [{case}]: `hcom kill {name}` terminated or signalled PID {} (or its child), \
             which does not carry {name}'s bound HCOM_PROCESS_ID:\n{output}",
            sentinel.pid()
        );
        assert_ne!(code, 0, "[{case}] refused kill exited 0:\n{output}");
        assert_refusal_reported(&output, &name, sentinel.pid());
        assert_row_kept(&h, &name, sentinel.pid());
    }

    #[test]
    fn native_kill_legacy_row_refuses_process_without_a_process_id() {
        native_legacy_row_refused("no-process-id", None);
    }

    #[test]
    fn native_kill_legacy_row_refuses_process_carrying_another_process_id() {
        let other = uuid::Uuid::new_v4().to_string();
        native_legacy_row_refused("other-process-id", Some(&other));
    }

    /// Run `request` as step `step` of the Node runner watching `dir`.
    fn native_request(h: &Hcom, dir: &Path, step: usize, request: Value) -> Value {
        let input = dir.join(format!("step-{step}.json"));
        fs::write(input.with_extension("tmp"), request.to_string()).unwrap();
        fs::rename(input.with_extension("tmp"), &input).unwrap();
        h.eventually("native owner step", Duration::from_secs(30), || {
            Ok(
                fs::read_to_string(dir.join(format!("step-{step}.json.out")))
                    .ok()
                    .and_then(|text| serde_json::from_str(&text).ok()),
            )
        })
    }

    // -----------------------------------------------------------------------
    // Windows real launch: background `hcom r` of a seat whose `omp` is an
    // npm-style `omp.cmd`. `hcom pty` launches cmd.exe (the PTY child and
    // launch root), which runs the Node interpreter the hook re-pins to and
    // then waits on its console. The kill retires cmd.exe's tree; `hcom pty`
    // above it only exits.
    // -----------------------------------------------------------------------

    /// A process this test did not spawn, held by a handle so its PID cannot
    /// be reused while the test watches it.
    #[cfg(windows)]
    struct Held {
        role: &'static str,
        pid: u32,
        handle: windows_sys::Win32::Foundation::HANDLE,
        created: u64,
    }

    // Base Cargo has no WDK feature: declare only this stable query ABI.
    #[cfg(windows)]
    #[link(name = "ntdll")]
    unsafe extern "system" {
        #[link_name = "NtQueryInformationProcess"]
        fn query_process(
            handle: windows_sys::Win32::Foundation::HANDLE,
            information_class: i32,
            information: *mut std::ffi::c_void,
            information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    #[cfg(windows)]
    impl Held {
        /// Hold `pid`, then prove it is still the expected live process: the
        /// child of `parent`, created after it, when given.
        fn open(role: &'static str, pid: u32, parent: Option<&Held>) -> Self {
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_TERMINATE,
            };
            let handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_INFORMATION
                        | PROCESS_QUERY_LIMITED_INFORMATION
                        | PROCESS_TERMINATE,
                    0,
                    pid,
                )
            };
            assert!(
                !handle.is_null(),
                "hold the {role} {pid}: {}",
                std::io::Error::last_os_error()
            );
            let mut held = Self {
                role,
                pid,
                handle,
                created: 0,
            };
            held.created = held.creation();
            assert!(held.alive(), "the {role} {pid} exited before it was held");
            if let Some(parent) = parent {
                held.assert_child_of(parent);
            }
            held
        }

        /// Hold this process's parent, proven older than this process.
        fn parent_of(role: &'static str, child: &Held) -> Self {
            let parent = Self::open(
                role,
                child
                    .parent()
                    .unwrap_or_else(|| panic!("the {} has no parent", child.role)),
                None,
            );
            child.assert_child_of(&parent);
            parent
        }

        #[track_caller]
        fn assert_child_of(&self, parent: &Held) {
            assert!(
                self.parent() == Some(parent.pid) && self.created >= parent.created,
                "the {} {} is not the child of the {} {}",
                self.role,
                self.pid,
                parent.role,
                parent.pid
            );
        }

        fn creation(&self) -> u64 {
            use windows_sys::Win32::Foundation::FILETIME;
            use windows_sys::Win32::System::Threading::GetProcessTimes;
            let mut created: FILETIME = unsafe { std::mem::zeroed() };
            let mut exited: FILETIME = unsafe { std::mem::zeroed() };
            let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
            let mut user: FILETIME = unsafe { std::mem::zeroed() };
            let read = unsafe {
                GetProcessTimes(
                    self.handle,
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user,
                )
            };
            assert!(read != 0, "creation time of the {} {}", self.role, self.pid);
            (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
        }

        fn alive(&self) -> bool {
            use windows_sys::Win32::Foundation::STILL_ACTIVE;
            use windows_sys::Win32::System::Threading::GetExitCodeProcess;
            let mut code = 0u32;
            let read = unsafe { GetExitCodeProcess(self.handle, &mut code) };
            read != 0 && code == STILL_ACTIVE as u32
        }

        /// The parent PID the kernel recorded at this process's creation.
        fn parent(&self) -> Option<u32> {
            #[repr(C)]
            struct BasicInformation {
                _exit_status: i32,
                _peb: *mut std::ffi::c_void,
                _affinity: usize,
                _base_priority: i32,
                pid: usize,
                parent_pid: usize,
            }
            let mut info: BasicInformation = unsafe { std::mem::zeroed() };
            let mut written = 0u32;
            // ProcessBasicInformation = 0.
            let status = unsafe {
                query_process(
                    self.handle,
                    0,
                    (&mut info as *mut BasicInformation).cast(),
                    std::mem::size_of::<BasicInformation>() as u32,
                    &mut written,
                )
            };
            (status >= 0 && info.pid == self.pid as usize).then_some(info.parent_pid as u32)
        }
    }

    #[cfg(windows)]
    impl Drop for Held {
        fn drop(&mut self) {
            use windows_sys::Win32::System::Threading::TerminateProcess;
            if self.alive() {
                unsafe { TerminateProcess(self.handle, 1) };
            }
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
        }
    }

    /// The `hcom r` process, killed at drop if it is still running.
    #[cfg(windows)]
    struct Resume(Child);

    #[cfg(windows)]
    impl Drop for Resume {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_background_kill_retires_the_omp_cmd_launch_tree() {
        let h = Scene::new();
        let name = format!("winseat{}", unique_suffix());
        let root = h.root_path().join("winseat");
        let steps = root.join("steps");
        let leaf_dir = root.join("leaf");
        let fakebin = root.join("fakebin");
        let script = root.join("node_modules/@oh-my-pi/pi-coding-agent/dist/cli.js");
        for dir in [&steps, &fakebin, &script.parent().unwrap().to_path_buf()] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(&script, OWNER_RUNNER).unwrap();
        let sentinel = root.join("sentinel.js");
        fs::write(&sentinel, SENTINEL_JS).unwrap();
        fs::write(
            fakebin.join("omp.cmd"),
            format!(
                "@echo off\r\n\
                 if \"%~1\"==\"--version\" (\r\n\
                 echo 1.0.0\r\n\
                 exit /b 0\r\n\
                 )\r\n\
                 set \"TEST_OWNER_DIR={steps}\"\r\n\
                 set \"TEST_HCOM_BIN={bin}\"\r\n\
                 \"{node}\" \"{script}\" %*\r\n\
                 pause >nul\r\n",
                steps = steps.display(),
                bin = env!("CARGO_BIN_EXE_hcom"),
                node = node(&h).display(),
                script = script.display(),
            ),
        )
        .unwrap();
        use_fixture_tools(&h, &fakebin);
        let (sid, transcript) = seed_stopped_omp(&h, &name, true);

        let stdout = root.join("resume.stdout");
        let stderr = root.join("resume.stderr");
        let _resume = Resume(
            h.cmd()
                .args(["r", name.as_str(), "--go"])
                .current_dir(&h.workspace)
                .stdin(Stdio::null())
                .stdout(fs::File::create(&stdout).unwrap())
                .stderr(fs::File::create(&stderr).unwrap())
                .spawn()
                .expect("spawn hcom r"),
        );
        let resume_output = || {
            format!(
                "{}\n{}",
                fs::read_to_string(&stdout).unwrap_or_default(),
                fs::read_to_string(&stderr).unwrap_or_default()
            )
        };
        // Windows CI starts two nested PowerShells before `hcom pty`, and the
        // interpreter cold-starts behind cmd.exe.
        let mut ready = Value::Null;
        assert!(
            wait_until(Duration::from_secs(120), || {
                ready = fs::read_to_string(steps.join("ready"))
                    .ok()
                    .and_then(|text| serde_json::from_str(&text).ok())
                    .unwrap_or(Value::Null);
                !ready.is_null()
            }),
            "the launched Node interpreter never started:\n{}",
            resume_output()
        );
        let pid = |value: &Value| u32::try_from(value.as_u64().unwrap()).unwrap();
        let interpreter = Held::open("interpreter", pid(&ready["pid"]), None);
        let launch_root = Held::parent_of("launch root", &interpreter);
        let pty = Held::parent_of("hcom pty", &launch_root);
        let _runner = Held::parent_of("launch runner", &pty);
        // Precondition: the pre-hook pin settled on cmd.exe, the process
        // `hcom pty` launched.
        assert!(
            wait_until(Duration::from_secs(30), || row_facts(&h, &name)["pid"]
                == json!(launch_root.pid)),
            "the pre-hook pin never settled on the PTY child {}: {}",
            launch_root.pid,
            row_facts(&h, &name)
        );
        let spawned = native_request(
            &h,
            &steps,
            0,
            json!({"kind": "child", "script": sentinel, "dir": leaf_dir}),
        );
        assert!(
            wait_until(Duration::from_secs(30), || leaf_dir.join("ready").exists()
                && beats(&leaf_dir) > 0),
            "the interpreter's leaf never became ready"
        );
        let leaf = Held::open("leaf", pid(&spawned["pid"]), Some(&interpreter));
        let hook = native_request(
            &h,
            &steps,
            1,
            json!({"kind": "hook", "name": null, "args": [
                "omp-start", "--session-id", sid, "--transcript-path", transcript,
                "--cwd", h.workspace,
            ]}),
        );
        let start = (
            i32::try_from(hook["code"].as_i64().unwrap()).unwrap(),
            hook["stdout"].as_str().unwrap().to_string(),
            hook["stderr"].as_str().unwrap().to_string(),
        );
        assert_bound(&h, &name, interpreter.pid, &start);

        let (code, output) = kill(&h, &[&name]);
        let tree = [&launch_root, &interpreter, &leaf];
        assert!(
            wait_until(Duration::from_secs(30), || tree
                .iter()
                .all(|held| !held.alive())),
            "`hcom kill {name}` left launched-tree member(s) alive: {:?}:\n{output}",
            tree.iter()
                .filter(|held| held.alive())
                .map(|held| (held.role, held.pid))
                .collect::<Vec<_>>()
        );
        assert!(
            wait_until(Duration::from_secs(30), || !pty.alive()),
            "hcom pty {} outlived its launched tree:\n{output}",
            pty.pid
        );
        assert_kill_succeeded(code, &output, &name);
        let _ = fs::write(steps.join("stop"), "");
        let _ = fs::write(leaf_dir.join("stop"), "");
    }
}

// ===========================================================================
// Real launches, Linux and macOS: `hcom r` resumes a stopped seat through
// hcom's own launch script and `hcom pty`, with fixture-private `bash` and
// `omp` first on PATH. The stand-in `omp` execs into the interpreter, as a
// real install's `omp` does, so the launch root (the PTY child, the last
// pre-hook pin) is the interpreter itself: a non-exec shell shim between
// `hcom pty` and the interpreter is refused at the hook. `hcom pty` and
// everything above the root carry the seat's HCOM_PROCESS_ID; kill never
// signals them, and `hcom pty` exits once its child is gone.
// ===========================================================================

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod real {
    use super::*;

    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Stdio};

    const LAUNCH_WAIT: Duration = Duration::from_secs(60);
    const GONE_WAIT: Duration = Duration::from_secs(15);

    /// The interpreter's step that starts its leaf: a long-lived child, in its
    /// own session where `setsid` exists, as an MCP server runs.
    const LEAF: &str = "if command -v setsid > /dev/null 2>&1; then \
        setsid sleep 300 < /dev/null > /dev/null 2>&1 & \
        else sleep 300 < /dev/null > /dev/null 2>&1 & fi; printf '%s' \"$!\"";

    fn quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
    }

    fn executable(path: &Path, text: &str) {
        fs::write(path, text).expect("write fixture tool");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("make fixture tool executable");
    }

    // -----------------------------------------------------------------------
    // A launched process this test did not spawn, held so that a later reuse
    // of its PID can never read as it or receive its signals.
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    struct Tracked {
        role: &'static str,
        pid: u32,
        fd: std::os::fd::OwnedFd,
    }

    #[cfg(target_os = "linux")]
    impl Tracked {
        /// Pin `pid` with a pidfd, then prove it is still the expected live
        /// process: the child of `parent`, when given.
        fn adopt(role: &'static str, pid: u32, parent: Option<u32>) -> Self {
            use std::os::fd::FromRawFd;
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
            assert!(
                raw >= 0,
                "pidfd_open({pid}) for the {role}: {}",
                std::io::Error::last_os_error()
            );
            let tracked = Self {
                role,
                pid,
                fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as libc::c_int) },
            };
            let ppid = tracked.ppid();
            assert!(
                tracked.alive() && parent.is_none_or(|parent| ppid == Some(parent)),
                "the {role} {pid} is not the expected live process (parent {ppid:?}, \
                 expected {parent:?})"
            );
            tracked
        }

        fn send(&self, signal: libc::c_int) -> bool {
            use std::os::fd::AsRawFd;
            let sent = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.fd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            sent == 0
        }

        /// /proc/<pid>/stat after the comm, read before the pidfd confirms
        /// its task still exists, so a reused PID never reads as this one.
        fn fields(&self) -> Option<Vec<String>> {
            let stat = fs::read_to_string(format!("/proc/{}/stat", self.pid));
            if !self.send(0) {
                return None;
            }
            let stat = stat.ok()?;
            let rest = &stat[stat.rfind(')')? + 2..];
            Some(rest.split_whitespace().map(str::to_string).collect())
        }

        fn alive(&self) -> bool {
            self.fields().is_some_and(|fields| fields[0] != "Z")
        }

        fn ppid(&self) -> Option<u32> {
            self.fields()?.get(1)?.parse().ok()
        }

        /// This process's wait status while it is an unreaped zombie (stat
        /// field 52).
        fn zombie_status(&self) -> Option<i64> {
            let fields = self.fields()?;
            if fields[0] != "Z" {
                return None;
            }
            fields.get(49)?.parse().ok()
        }
    }

    #[cfg(target_os = "macos")]
    struct Tracked {
        role: &'static str,
        pid: u32,
        birth: (u64, u64),
    }

    #[cfg(target_os = "macos")]
    fn bsd_info(pid: u32) -> Option<libc::proc_bsdinfo> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let read = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        (read == size && info.pbi_pid == pid).then_some(info)
    }

    #[cfg(target_os = "macos")]
    impl Tracked {
        /// Record `pid` with its start time, then prove it is still the
        /// expected live process: the child of `parent`, when given.
        fn adopt(role: &'static str, pid: u32, parent: Option<u32>) -> Self {
            let info = bsd_info(pid)
                .unwrap_or_else(|| panic!("the {role} {pid} exited before it was adopted"));
            assert!(
                info.pbi_status != 5 && parent.is_none_or(|parent| info.pbi_ppid == parent),
                "the {role} {pid} is not the expected live process (parent {}, expected \
                 {parent:?})",
                info.pbi_ppid
            );
            Self {
                role,
                pid,
                birth: (info.pbi_start_tvsec, info.pbi_start_tvusec),
            }
        }

        fn current(&self) -> Option<libc::proc_bsdinfo> {
            bsd_info(self.pid)
                .filter(|info| (info.pbi_start_tvsec, info.pbi_start_tvusec) == self.birth)
        }

        /// Live and not a zombie (SZOMB = 5 in Darwin's sys/proc.h).
        fn alive(&self) -> bool {
            self.current().is_some_and(|info| info.pbi_status != 5)
        }

        fn ppid(&self) -> Option<u32> {
            self.current().map(|info| info.pbi_ppid)
        }

        fn send(&self, signal: libc::c_int) -> bool {
            self.alive() && unsafe { libc::kill(self.pid as libc::pid_t, signal) } == 0
        }
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            if self.alive() {
                self.send(libc::SIGKILL);
            }
        }
    }

    // -----------------------------------------------------------------------
    // The fixture: one stopped seat, the fake tools, and `hcom r`.
    // -----------------------------------------------------------------------

    /// Fixture-private launch tools. `bash` turns the post-tool login shell
    /// (`bash -l`) into an exit and passes everything else to the real bash.
    /// `omp` is the stand-in OMP: it execs into the step runner as `omp`, so
    /// the real classifier sees argv[0] `omp`.
    fn install_tools(h: &Hcom, root: &Path, fakebin: &Path) {
        executable(
            &fakebin.join("bash"),
            "#!/bin/bash\nif [ \"$#\" -eq 1 ] && [ \"$1\" = -l ]; then exit 0; fi\nexec /bin/bash \"$@\"\n",
        );
        let runner = root.join("steps.sh");
        fs::write(&runner, STEP_RUNNER).expect("write step runner");
        executable(
            &fakebin.join("omp"),
            &format!(
                r#"#!/bin/bash
if [ "${{1:-}}" = --version ]; then printf '1.0.0\n'; exit 0; fi
out={root}/interpreter-$$
mkdir -p "$out"
export TEST_OUT_DIR="$out" TEST_CWD={cwd} TEST_BIN={bin}
exec -a omp /bin/bash {runner}
"#,
                root = quote(root),
                cwd = quote(&h.workspace),
                bin = quote(Path::new(env!("CARGO_BIN_EXE_hcom"))),
                runner = quote(&runner),
            ),
        );
    }

    /// One stopped OMP seat that `hcom r` resumes for real.
    struct Real {
        scene: Scene,
        _workspace: tempfile::TempDir,
        root: PathBuf,
        name: String,
        sid: String,
        transcript: PathBuf,
        /// The next step the launched interpreter runs.
        next_step: Cell<usize>,
    }

    /// The `hcom r` process, leading its own process group, with output in
    /// files no launched grandchild can hold open. It is never reaped before
    /// its drop, so its group is this launch's until then.
    struct Resume {
        child: Child,
        stdout: PathBuf,
        stderr: PathBuf,
    }

    impl Resume {
        fn output(&self) -> String {
            format!(
                "{}\n{}",
                fs::read_to_string(&self.stdout).unwrap_or_default(),
                fs::read_to_string(&self.stderr).unwrap_or_default()
            )
        }
    }

    impl Drop for Resume {
        fn drop(&mut self) {
            unsafe {
                libc::killpg(self.child.id() as libc::pid_t, libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
    }

    /// The launched seat: the interpreter the hook bound (the PTY child and
    /// launch root) and its leaf, with `hcom pty` and the launch script above
    /// the root.
    struct Seat {
        interpreter: Tracked,
        leaf: Tracked,
        pty: Tracked,
        script: Tracked,
    }

    impl Seat {
        #[track_caller]
        fn assert_tree_gone(&self, output: &str) {
            let tree = [&self.interpreter, &self.leaf];
            assert!(
                wait_until(GONE_WAIT, || tree.iter().all(|member| !member.alive())),
                "`hcom kill` left launched-tree member(s) alive: {:?}:\n{output}",
                tree.iter()
                    .filter(|member| member.alive())
                    .map(|member| (member.role, member.pid))
                    .collect::<Vec<_>>()
            );
        }

        #[track_caller]
        fn assert_pty_exited(&self, output: &str) {
            assert!(
                wait_until(GONE_WAIT, || !self.pty.alive()),
                "hcom pty {} outlived its launched tree:\n{output}",
                self.pty.pid
            );
        }
    }

    impl Real {
        fn new(label: &str, background: bool) -> Self {
            let mut h = isolated_hcom();
            // OMP refuses a cwd under /tmp, and resume redirects a /tmp
            // snapshot directory to a seat path outside the fixture.
            let workspace = tempfile::Builder::new()
                .prefix("hcom-kill-real-")
                .tempdir_in("/var/tmp")
                .expect("create a private workspace outside /tmp");
            h.workspace = workspace.path().to_path_buf();
            let root = h.root_path().join(format!("real-{label}"));
            let fakebin = root.join("fakebin");
            fs::create_dir_all(&fakebin).expect("create fakebin");
            install_tools(&h, &root, &fakebin);
            use_fixture_tools(&h, &fakebin);
            let name = format!("{label}{}", unique_suffix());
            let (sid, transcript) = seed_stopped_omp(&h, &name, background);
            Self {
                scene: Scene { h },
                _workspace: workspace,
                root,
                name,
                sid,
                transcript,
                next_step: Cell::new(0),
            }
        }

        fn resume(&self, args: &[&str]) -> Resume {
            let stdout = self.root.join("resume.stdout");
            let stderr = self.root.join("resume.stderr");
            let child = self
                .scene
                .cmd()
                .args(args)
                .current_dir(&self.scene.workspace)
                .stdin(Stdio::null())
                .stdout(fs::File::create(&stdout).expect("create resume stdout"))
                .stderr(fs::File::create(&stderr).expect("create resume stderr"))
                .process_group(0)
                .spawn()
                .expect("spawn hcom r");
            Resume {
                child,
                stdout,
                stderr,
            }
        }

        /// Find the launched chain, wait for the pre-hook pin to settle on
        /// the PTY child, start the interpreter's leaf, and bind the seat
        /// through the interpreter's real `omp-start`.
        fn seat(&self, resume: &Resume) -> Seat {
            let h: &Hcom = &self.scene;
            let mut found = None;
            let started = wait_until(LAUNCH_WAIT, || {
                found = fs::read_dir(&self.root)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .find_map(|entry| {
                        entry.file_name().to_str()?.strip_prefix("interpreter-")?;
                        let text = fs::read_to_string(entry.path().join("ready")).ok()?;
                        let mut lines = text.lines();
                        let pid: u32 = lines.next()?.parse().ok()?;
                        let process_id = lines.next()?.to_string();
                        Some((pid, process_id))
                    });
                found.is_some()
            });
            assert!(
                started,
                "the launched stand-in OMP never started:\n{}",
                resume.output()
            );
            let (pid, process_id) = found.unwrap();
            let interpreter = Tracked::adopt("interpreter", pid, None);
            let pty = Tracked::adopt(
                "hcom pty",
                interpreter.ppid().expect("interpreter parent"),
                None,
            );
            #[cfg(target_os = "linux")]
            {
                let argv = fs::read(format!("/proc/{}/cmdline", pty.pid)).unwrap_or_default();
                let mut argv = argv.split(|byte| *byte == 0);
                let program = argv.next().unwrap_or_default();
                assert!(
                    program.ends_with(b"hcom") && argv.next() == Some(b"pty".as_slice()),
                    "the interpreter's parent {} is not hcom pty: {:?}",
                    pty.pid,
                    String::from_utf8_lossy(program)
                );
            }
            let script =
                Tracked::adopt("launch script", pty.ppid().expect("hcom pty parent"), None);
            assert!(
                wait_until(LAUNCH_WAIT, || row_facts(h, &self.name)["pid"]
                    == json!(interpreter.pid)),
                "precondition: the pre-hook pin never settled on the PTY child {}: {}",
                interpreter.pid,
                row_facts(h, &self.name)
            );
            let run = |script: &str| self.step(pid, script);
            let (code, stdout, stderr) = run(LEAF);
            assert_eq!(code, 0, "start the interpreter's leaf: {stdout} {stderr}");
            let leaf = Tracked::adopt(
                "leaf",
                stdout.trim().parse().expect("leaf PID"),
                Some(interpreter.pid),
            );
            let start = run(&format!(
                "H omp-start --session-id {} --transcript-path {} --cwd {}",
                quote(Path::new(&self.sid)),
                quote(&self.transcript),
                quote(&h.workspace),
            ));
            assert_bound(h, &self.name, interpreter.pid, &start);
            let bound: i64 = db(h)
                .query_row(
                    "SELECT COUNT(*) FROM process_bindings WHERE process_id=?1 AND instance_name=?2",
                    rusqlite::params![process_id, self.name],
                    |row| row.get(0),
                )
                .expect("read the seat's process binding");
            assert_eq!(
                bound, 1,
                "precondition: the interpreter's HCOM_PROCESS_ID {process_id} must be {}'s binding",
                self.name
            );
            Seat {
                interpreter,
                leaf,
                pty,
                script,
            }
        }

        /// Run `script` as the next step inside the launched interpreter
        /// `interpreter`.
        fn step(&self, interpreter: u32, script: &str) -> (i32, String, String) {
            let step = self.next_step.get();
            self.next_step.set(step + 1);
            let steps = self.root.join(format!("interpreter-{interpreter}"));
            run_step(&self.scene, &steps, step, script)
        }

        fn kill(&self) -> (i32, String) {
            kill(&self.scene, &[&self.name])
        }
    }

    // -----------------------------------------------------------------------
    // A watched fixture process: it logs every catchable signal it gets,
    // exits on it, and heartbeats while it lives.
    // -----------------------------------------------------------------------

    struct Watched {
        tracked: Tracked,
        dir: PathBuf,
    }

    impl Watched {
        /// Wait for the watched process writing to `dir` to start, pin it as
        /// the child of `parent`, and on Linux wait for its signal traps.
        fn find(
            role: &'static str,
            dir: PathBuf,
            parent: u32,
            context: impl Fn() -> String,
        ) -> Self {
            let mut pid = None;
            assert!(
                wait_until(LAUNCH_WAIT, || {
                    pid = fs::read_to_string(dir.join("ready"))
                        .ok()
                        .and_then(|text| text.parse::<u32>().ok());
                    pid.is_some() && beats(&dir) > 0
                }),
                "the {role} never started:\n{}",
                context()
            );
            let tracked = Tracked::adopt(role, pid.unwrap(), Some(parent));
            #[cfg(target_os = "linux")]
            {
                let handled = [
                    libc::SIGHUP,
                    libc::SIGINT,
                    libc::SIGQUIT,
                    libc::SIGTERM,
                    libc::SIGUSR1,
                    libc::SIGUSR2,
                    libc::SIGCONT,
                ]
                .iter()
                .fold(0_u64, |mask, signal| mask | 1_u64 << (signal - 1));
                assert!(
                    wait_until(LAUNCH_WAIT, || caught(tracked.pid) & handled == handled),
                    "the {role} {} never installed its signal traps",
                    tracked.pid
                );
            }
            Self { tracked, dir }
        }

        fn beats(&self) -> u64 {
            beats(&self.dir)
        }

        /// Wait (bounded) for two more heartbeats, which proves any signal
        /// already sent had its trap run, then report what it went through.
        fn observe(&self, before: u64) -> Value {
            let mut progressed = false;
            wait_until(GONE_WAIT, || {
                progressed = self.beats() >= before + 2;
                progressed || !self.tracked.alive()
            });
            json!({
                "alive": self.tracked.alive(),
                "heartbeat_progressed": progressed,
                "signals": fs::read_to_string(self.dir.join("signals")).unwrap_or_default(),
            })
        }
    }

    // -----------------------------------------------------------------------
    // An id-carrying terminal above the launch script: hcom runs the custom
    // terminal command `env HCOM_PROCESS_ID={process_id} <terminal>
    // {script}`, and the terminal runs the launch script below it.
    // -----------------------------------------------------------------------

    fn install_terminal(real: &Real) -> PathBuf {
        let path = real.root.join("terminal.sh");
        executable(
            &path,
            &format!(
                r#"#!/bin/bash
dir={dir}
mkdir -p "$dir"
: > "$dir/signals"
for s in HUP INT QUIT TERM USR1 USR2 CONT; do
    trap "printf '%s\n' $s >> \"$dir/signals\"; exit 0" "$s"
done
( /bin/bash "$1"; printf '%s' "$?" > "$dir/script.status" ) < /dev/null > "$dir/script.out" 2>&1 &
printf '%s' "$$" > "$dir/ready"
while :; do
    printf x >> "$dir/heartbeat"
    sleep 0.05
done
"#,
                dir = quote(&real.root.join("terminal")),
            ),
        );
        path
    }

    fn find_terminal(real: &Real, resume: &Resume, seat: &Seat) -> Watched {
        let terminal = Watched::find(
            "terminal",
            real.root.join("terminal"),
            resume.child.id(),
            || resume.output(),
        );
        // Precondition: the launch script runs below the terminal.
        let subshell = seat.script.ppid().expect("launch script parent");
        assert_eq!(
            parent_pid(subshell),
            Some(terminal.tracked.pid),
            "precondition: the launch script {} must run below the terminal {}",
            seat.script.pid,
            terminal.tracked.pid
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            carried_process_id(terminal.tracked.pid),
            Some(bound_process_id(real)),
            "precondition: the terminal must carry the seat's HCOM_PROCESS_ID"
        );
        terminal
    }

    fn beats(dir: &Path) -> u64 {
        fs::metadata(dir.join("heartbeat"))
            .map(|stat| stat.len())
            .unwrap_or(0)
    }

    #[cfg(target_os = "linux")]
    fn caught(pid: u32) -> u64 {
        fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| {
                let mask = status
                    .lines()
                    .find_map(|line| line.strip_prefix("SigCgt:"))?;
                u64::from_str_radix(mask.trim(), 16).ok()
            })
            .unwrap_or(0)
    }

    /// A live process's parent, read without holding it: only for a process
    /// that is known to be alive, such as one waiting on a tracked child.
    #[cfg(target_os = "linux")]
    fn parent_pid(pid: u32) -> Option<u32> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat[stat.rfind(')')? + 2..]
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    }

    #[cfg(target_os = "macos")]
    fn parent_pid(pid: u32) -> Option<u32> {
        bsd_info(pid).map(|info| info.pbi_ppid)
    }

    /// The HCOM_PROCESS_ID in `pid`'s environment.
    #[cfg(target_os = "linux")]
    fn carried_process_id(pid: u32) -> Option<String> {
        let environ = fs::read(format!("/proc/{pid}/environ")).ok()?;
        environ
            .split(|byte| *byte == 0)
            .find_map(|entry| entry.strip_prefix(b"HCOM_PROCESS_ID="))
            .map(|value| String::from_utf8_lossy(value).into_owned())
    }

    /// The process id the seat's binding holds.
    #[cfg(target_os = "linux")]
    fn bound_process_id(real: &Real) -> String {
        db(&real.scene)
            .query_row(
                "SELECT process_id FROM process_bindings WHERE instance_name=?1",
                [&real.name],
                |row| row.get(0),
            )
            .expect("read the seat's process binding")
    }

    // -----------------------------------------------------------------------
    // Rule 1: a genuine kill retires the launched tree and nothing above it.
    // -----------------------------------------------------------------------

    /// A PTY launch in an id-carrying terminal. On Linux the launch script is
    /// stopped across the kill so `hcom pty`'s exit status survives as a
    /// zombie's: it must have exited, not died by a signal. `hcom pty`
    /// catches SIGTERM, SIGHUP and SIGINT and then exits normally, so this
    /// proves no fatal signal (SIGKILL or any uncaught one) reached it, not
    /// that none was sent.
    #[test]
    fn pty_kill_retires_the_launched_tree_and_spares_every_ancestor() {
        let real = Real::new("terminal", false);
        let terminal = install_terminal(&real);
        let command = format!(
            "env HCOM_PROCESS_ID={{process_id}} {} {{script}}",
            terminal.display()
        );
        // A lone foreground resume runs in the current terminal unless told
        // otherwise; `--no-run-here` sends it through the custom terminal.
        let resume = real.resume(&[
            "r",
            &real.name,
            "--terminal",
            &command,
            "--no-run-here",
            "--go",
        ]);
        let seat = real.seat(&resume);
        let terminal = find_terminal(&real, &resume, &seat);
        #[cfg(target_os = "linux")]
        assert!(seat.script.send(libc::SIGSTOP), "stop the launch script");
        let before = terminal.beats();

        let (code, output) = real.kill();
        seat.assert_tree_gone(&output);
        seat.assert_pty_exited(&output);
        #[cfg(target_os = "linux")]
        {
            let status = seat.pty.zombie_status();
            assert!(
                status.is_some_and(|status| status & 0x7f == 0),
                "SAFETY: hcom pty {} died by a signal (wait status {status:?}) instead of \
                 exiting once its child was gone:\n{output}",
                seat.pty.pid
            );
            assert!(seat.script.send(libc::SIGCONT), "resume the launch script");
        }
        assert_eq!(
            terminal.observe(before),
            json!({"alive": true, "heartbeat_progressed": true, "signals": ""}),
            "SAFETY: `hcom kill` signalled the id-carrying terminal {} above the \
             launch:\n{output}",
            terminal.tracked.pid
        );
        let status = terminal.dir.join("script.status");
        assert!(
            wait_until(GONE_WAIT, || status.exists()),
            "the launch script never finished:\n{output}"
        );
        assert_eq!(
            fs::read_to_string(&status).unwrap(),
            "0",
            "SAFETY: the launch script above hcom pty did not exit 0 (128+n means signal \
             n):\n{output}"
        );
        assert_kill_succeeded(code, &output, &real.name);
    }

    /// A background launch (`hcom r N --go`).
    #[test]
    fn background_kill_retires_the_launched_tree() {
        let real = Real::new("background", true);
        let resume = real.resume(&["r", &real.name, "--go"]);
        let seat = real.seat(&resume);

        let (code, output) = real.kill();
        seat.assert_tree_gone(&output);
        seat.assert_pty_exited(&output);
        assert_kill_succeeded(code, &output, &real.name);
    }

    /// A legacy row (no recorded launch root) whose launcher is `hcom pty`
    /// itself: the interpreter is the PTY child, so its root is verified
    /// without a record.
    #[test]
    fn legacy_kill_under_hcom_pty_retires_the_launched_tree() {
        let real = Real::new("legacypty", true);
        let resume = real.resume(&["r", &real.name, "--go"]);
        let seat = real.seat(&resume);
        strip_launch_root(&real.scene, &real.name);

        let (code, output) = real.kill();
        seat.assert_tree_gone(&output);
        seat.assert_pty_exited(&output);
        assert_kill_succeeded(code, &output, &real.name);
    }

    // -----------------------------------------------------------------------
    // OMP workers under the seat (Linux). OMP starts a worker in its own
    // session with a copy of its whole environment, so the worker, and
    // anything the worker starts, carries the seat's HCOM_PROCESS_ID. One
    // worker, the daemon broker, serves every seat. It is marked by
    // `__omp_worker_daemon_broker` as the first argument to OMP's script, or
    // by the process name `omp daemon brok`.
    // -----------------------------------------------------------------------

    /// A watched process's body, run as `bash watch.sh <dir>` or sourced.
    #[cfg(target_os = "linux")]
    const WATCH: &str = r#"dir=$1
mkdir -p "$dir"
: > "$dir/signals"
for s in HUP INT QUIT TERM USR1 USR2 CONT; do
    trap "printf '%s\n' $s >> \"$dir/signals\"; exit 0" "$s"
done
printf '%s' "$$" > "$dir/ready"
while [ "$SECONDS" -lt 300 ]; do
    printf x >> "$dir/heartbeat"
    sleep 0.05
done
"#;

    /// One worker the interpreter started, and the worker's own child.
    #[cfg(target_os = "linux")]
    struct Worker {
        process: Watched,
        child: Watched,
    }

    #[cfg(target_os = "linux")]
    impl Worker {
        fn find(real: &Real, seat: &Seat, role: &'static str) -> Self {
            let dir = real.root.join("workers").join(role);
            let process = Watched::find(role, dir.clone(), seat.interpreter.pid, String::new);
            let child = Watched::find(
                "worker child",
                dir.join("child"),
                process.tracked.pid,
                String::new,
            );
            let id = bound_process_id(real);
            for member in [&process, &child] {
                assert_eq!(
                    carried_process_id(member.tracked.pid).as_deref(),
                    Some(id.as_str()),
                    "precondition: the {role}'s {} {} must carry the seat's HCOM_PROCESS_ID",
                    member.tracked.role,
                    member.tracked.pid
                );
            }
            let pid = process.tracked.pid as libc::pid_t;
            assert_eq!(
                unsafe { libc::getsid(pid) },
                pid,
                "precondition: the {role} {pid} must lead its own session"
            );
            Self { process, child }
        }

        /// The worker's argv and process name.
        fn identity(&self) -> (Vec<String>, String) {
            let pid = self.process.tracked.pid;
            let argv = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            (
                argv.split(|byte| *byte == 0)
                    .filter(|arg| !arg.is_empty())
                    .map(|arg| String::from_utf8_lossy(arg).into_owned())
                    .collect(),
                comm.trim_end_matches('\n').to_string(),
            )
        }

        #[track_caller]
        fn assert_gone(&self, output: &str) {
            let members = [&self.process.tracked, &self.child.tracked];
            assert!(
                wait_until(GONE_WAIT, || members.iter().all(|member| !member.alive())),
                "`hcom kill` left the seat's {} (or its child) alive: {:?}:\n{output}",
                self.process.tracked.role,
                members
                    .iter()
                    .filter(|member| member.alive())
                    .map(|member| (member.role, member.pid))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// Start the seat's workers from inside its interpreter, each with a
    /// child of its own: the broker marked by its argument, the broker
    /// marked by its name, OMP's LSP multiplexer, and an OMP process that
    /// names the broker selector anywhere but as the script's first
    /// argument. Returns the path of OMP's stand-in script.
    #[cfg(target_os = "linux")]
    fn start_workers(real: &Real, seat: &Seat) -> String {
        let watch = real.root.join("watch.sh");
        fs::write(&watch, WATCH).expect("write the watched body");
        // A background job of a non-interactive shell ignores SIGINT and
        // SIGQUIT, and bash cannot trap a signal ignored at entry, so every
        // disposition is reset first.
        let worker = format!(
            r#"[ -z "${{WORKER_TITLE:-}}" ] || printf '%s' "$WORKER_TITLE" > "/proc/$$/comm"
env --default-signal /bin/bash {watch} "$WORKER/child" < /dev/null > /dev/null 2>&1 &
. {watch} "$WORKER"
"#,
            watch = quote(&watch),
        );
        let cli = real
            .root
            .join("node_modules/@oh-my-pi/pi-coding-agent/dist/cli.js");
        fs::create_dir_all(cli.parent().unwrap()).expect("create the OMP package");
        fs::write(&cli, &worker).expect("write OMP's stand-in script");
        let titled = real.root.join("worker.sh");
        fs::write(&titled, &worker).expect("write the titled worker");
        let start = |role: &str, env: &str, command: String| {
            format!(
                "WORKER={dir} {env} setsid env --default-signal {command} \
                 < /dev/null > /dev/null 2>&1 &\n",
                dir = quote(&real.root.join("workers").join(role)),
            )
        };
        let bun = |args: &str| {
            format!(
                "/bin/bash -c 'exec -a bun /bin/bash \"$@\"' bun {} {args}",
                quote(&cli)
            )
        };
        let script = [
            start("broker-by-argument", "", bun("__omp_worker_daemon_broker")),
            start(
                "broker-by-name",
                "WORKER_TITLE='omp daemon broker'",
                format!("/bin/bash {}", quote(&titled)),
            ),
            start("lsp-mux", "", bun("__omp_worker_lsp_mux")),
            start(
                "late-selector",
                "",
                bun("--worker __omp_worker_daemon_broker"),
            ),
        ]
        .concat();
        let (code, stdout, stderr) = real.step(seat.interpreter.pid, &script);
        assert_eq!(code, 0, "start the seat's workers: {stdout} {stderr}");
        cli.to_string_lossy().into_owned()
    }

    /// OMP's shared daemon broker can sit under the seat that started it,
    /// carrying that seat's HCOM_PROCESS_ID, but it serves every seat: the
    /// kill leaves either marked broker and everything under it alone, and
    /// still succeeds. Every other worker under the seat is the seat's.
    #[cfg(target_os = "linux")]
    #[test]
    fn kill_spares_the_shared_daemon_broker_and_everything_under_it() {
        let real = Real::new("broker", true);
        let resume = real.resume(&["r", &real.name, "--go"]);
        let seat = real.seat(&resume);
        let cli = start_workers(&real, &seat);
        let by_argument = Worker::find(&real, &seat, "broker-by-argument");
        let by_name = Worker::find(&real, &seat, "broker-by-name");
        let lsp_mux = Worker::find(&real, &seat, "lsp-mux");
        let late = Worker::find(&real, &seat, "late-selector");
        let omp = |args: &[&str]| {
            ["bun", cli.as_str()]
                .iter()
                .chain(args)
                .map(|arg| arg.to_string())
                .collect::<Vec<_>>()
        };
        let bash = "bash".to_string();
        assert_eq!(
            by_argument.identity(),
            (omp(&["__omp_worker_daemon_broker"]), bash.clone()),
            "precondition: the argument-marked broker carries only its argument mark"
        );
        let (argv, comm) = by_name.identity();
        assert!(
            comm == "omp daemon brok" && !argv.iter().any(|arg| arg.starts_with("__omp_worker_")),
            "precondition: the name-marked broker carries only its name mark: {argv:?} {comm:?}"
        );
        assert_eq!(
            lsp_mux.identity(),
            (omp(&["__omp_worker_lsp_mux"]), bash.clone()),
            "precondition: the LSP multiplexer is an OMP worker that is not the broker"
        );
        assert_eq!(
            late.identity(),
            (omp(&["--worker", "__omp_worker_daemon_broker"]), bash),
            "precondition: the late selector is not the script's first argument"
        );
        let spared = [
            &by_argument.process,
            &by_argument.child,
            &by_name.process,
            &by_name.child,
        ];
        let before: Vec<u64> = spared.iter().map(|member| member.beats()).collect();

        let (code, output) = real.kill();
        seat.assert_tree_gone(&output);
        lsp_mux.assert_gone(&output);
        late.assert_gone(&output);
        seat.assert_pty_exited(&output);
        for (member, before) in spared.into_iter().zip(before) {
            assert_eq!(
                member.observe(before),
                json!({"alive": true, "heartbeat_progressed": true, "signals": ""}),
                "SAFETY: `hcom kill` signalled the shared broker's tree: {} {} ({}):\n{output}",
                member.tracked.role,
                member.tracked.pid,
                member.dir.display()
            );
        }
        assert_kill_succeeded(code, &output, &real.name);
    }
}
