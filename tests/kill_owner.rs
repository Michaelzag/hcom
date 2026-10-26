//! `hcom kill` signals a recorded PID only when the live process holding it is
//! verifiably the target instance's owner (hcom#106). A crashed seat whose PID
//! was reused by an unrelated process must be refused, reported with the PID
//! and an `hcom stop` pointer, and nothing in the reuser's tree signalled. A
//! genuine owner, and its tree, is still killed.
//!
//! Every process here is a fixture child of this test: a stand-in OMP that
//! registers through hcom's own `launch-anchor` (which writes the native
//! identity receipt) and binds through `omp-start`, or a sentinel that records
//! any signal it receives and keeps a heartbeat. PID reuse is simulated in the
//! private DB only: the reuser's PID replaces the crashed owner's number in
//! the owner's row and bindings, nothing else changes.
//!
//! Linux cases (`mod linux`) also cover legacy rows without a receipt, whose
//! evidence is the live process's HCOM_PROCESS_ID in /proc environ. Windows and
//! macOS (`mod native`) have no such fallback: kill trusts the receipt only,
//! so they prove a genuine receipt still kills and a reused PID is refused.

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
        // dropped, and before `Hcom::drop`. Only this private DB is touched.
        if let Ok(conn) = rusqlite::Connection::open(self.h.path().join("hcom.db")) {
            let _ = conn.busy_timeout(Duration::from_secs(5));
            let _ = conn.execute("UPDATE instances SET pid=NULL", []);
        }
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

    // -----------------------------------------------------------------------
    // Hooked stand-in OMP: a step runner that runs hcom commands from inside
    // its own process, so hcom anchors and binds the name to this live PID
    // through the real launch-anchor and hook paths.
    // -----------------------------------------------------------------------

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

    struct HookOwner {
        proc: Owned,
        out_dir: PathBuf,
        process_id: String,
        next_step: Cell<usize>,
    }

    impl HookOwner {
        fn spawn(h: &Hcom, label: &str) -> Self {
            let omp = fakebin(h).join("omp");
            let out_dir = h.root_path().join(format!("owner-{label}"));
            fs::create_dir_all(&out_dir).expect("create owner directory");
            let runner = out_dir.join("steps.sh");
            fs::write(&runner, STEP_RUNNER).expect("write step runner");
            let process_id = uuid::Uuid::new_v4().to_string();
            let mut command = h.external_cmd(&omp);
            command
                .arg(&runner)
                .env("HCOM_PROCESS_ID", &process_id)
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
            assert_eq!(
                lines.next().unwrap().parse::<u32>().ok(),
                Some(proc.pid()),
                "fixture OMP is not the direct child"
            );
            assert_eq!(lines.next(), Some(process_id.as_str()));
            Self {
                proc,
                out_dir,
                process_id,
                next_step: Cell::new(0),
            }
        }

        fn pid(&self) -> u32 {
            self.proc.pid()
        }

        fn run(&self, h: &Hcom, script: &str) -> (i32, String, String) {
            let step = self.next_step.get();
            self.next_step.set(step + 1);
            fs::write(self.out_dir.join(format!("{step}.sh")), script).expect("write hook step");
            fs::write(self.out_dir.join(format!("go-{step}")), "").expect("trigger hook step");
            let code = h.eventually("hook step finished", Duration::from_secs(30), || {
                Ok(
                    fs::read_to_string(self.out_dir.join(format!("{step}.code")))
                        .ok()
                        .filter(|text| !text.is_empty()),
                )
            });
            (
                code.parse().expect("hook step exit code"),
                fs::read_to_string(self.out_dir.join(format!("{step}.stdout"))).unwrap_or_default(),
                fs::read_to_string(self.out_dir.join(format!("{step}.stderr"))).unwrap_or_default(),
            )
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
                Ok(member_alive(pid, self.pid()).then_some(()))
            });
            pid
        }
    }

    /// A fresh fixture OMP registered the way an hcom launch registers it:
    /// a pending reservation, `hcom launch-anchor` run from the owner (which
    /// records its PID and native identity receipt), then `omp-start`.
    fn hooked_owner(h: &Hcom, label: &str, name: &str, endpoint: &TcpListener) -> HookOwner {
        let owner = HookOwner::spawn(h, label);
        launch_row(h, name, &owner.process_id);
        let anchor = owner.run(h, "H launch-anchor");
        assert_receipt(h, name, owner.pid(), &anchor);
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
        owner
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

    /// A legacy bound row, as written before any identity record existed:
    /// row, process binding and session binding, recorded PID `pid`.
    fn seed_legacy_row(h: &Hcom, name: &str, process_id: &str, pid: Option<u32>) {
        let conn = db(h);
        let sid = format!("sid-{name}");
        conn.execute(
            "INSERT INTO instances (name, tool, session_id, status, status_context, status_time, created_at, last_event_id, pid)
             VALUES (?1, 'omp', ?2, 'listening', 'start', 0, 0, 0, ?3)",
            rusqlite::params![name, sid, pid],
        )
        .expect("seed legacy row");
        conn.execute(
            "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
             VALUES (?1, ?2, ?3, 0)",
            rusqlite::params![process_id, sid, name],
        )
        .expect("seed legacy process binding");
        conn.execute(
            "INSERT INTO session_bindings (session_id, instance_name, created_at) VALUES (?1, ?2, 0)",
            rusqlite::params![sid, name],
        )
        .expect("seed legacy session binding");
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
            let script = h.root_path().join("sentinel.sh");
            if !script.exists() {
                fs::write(&script, SENTINEL_BASH).expect("write sentinel script");
            }
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
    // Rows 2 + 7: the genuine live owner and its tree are still killed.
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
        assert_eq!(code, 0, "kill of the genuine owner failed:\n{output}");
        assert_torn_down(&h, &name);
    }

    // -----------------------------------------------------------------------
    // Row 3: mixed multi-target kills signal only the genuine owner.
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
        let (_code, output) = kill(&h, &args[..]);
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
        assert_refusal_reported(&output, &reused_name, sentinel.pid());
        assert_row_kept(&h, &reused_name, sentinel.pid());
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
    // only the carried id differs.
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
        assert_eq!(code, 0, "kill of the legacy owner failed:\n{output}");
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
// Windows and macOS: the receipt is the only evidence. A Node process running
// a supported OMP script path is the owner (as tests/omp_native_owner.rs
// does); sentinels are Node processes that record any catchable signal and
// keep a heartbeat. Windows has no POSIX signals, so there the evidence is
// liveness and heartbeat alone.
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
    pid: process.pid, process_id: process.env.HCOM_PROCESS_ID,
}));
fs.renameSync(path.join(dir, 'ready.tmp'), path.join(dir, 'ready'));
const born = Date.now();
setInterval(() => {
    if (fs.existsSync(path.join(dir, 'stop')) || Date.now() - born > 300000) process.exit(0);
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
            let root = h.root_path().join(format!("owner-{label}"));
            let script = root.join("node_modules/@oh-my-pi/pi-coding-agent/dist/cli.js");
            fs::create_dir_all(script.parent().unwrap()).unwrap();
            fs::write(&script, OWNER_RUNNER).unwrap();
            let dir = root.join("steps");
            fs::create_dir_all(&dir).unwrap();
            let process_id = uuid::Uuid::new_v4().to_string();
            let mut command = h.external_cmd(node(h));
            command
                .arg(&script)
                .env("HCOM_PROCESS_ID", &process_id)
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
            assert_eq!(pid, proc.pid(), "fixture must be the actual Node process");
            Self {
                proc,
                pid,
                process_id,
                step: Cell::new(0),
                root,
            }
        }

        fn request(&self, h: &Hcom, request: Value) -> Value {
            let step = self.step.get();
            self.step.set(step + 1);
            let input = self.proc.dir.join(format!("step-{step}.json"));
            fs::write(input.with_extension("tmp"), request.to_string()).unwrap();
            fs::rename(input.with_extension("tmp"), &input).unwrap();
            h.eventually("native owner step", Duration::from_secs(30), || {
                Ok(
                    fs::read_to_string(self.proc.dir.join(format!("step-{step}.json.out")))
                        .ok()
                        .and_then(|text| serde_json::from_str(&text).ok()),
                )
            })
        }

        fn run(&self, h: &Hcom, args: &[&str], name: Option<&str>) -> (i32, String, String) {
            let out = self.request(h, json!({"kind": "hook", "args": args, "name": name}));
            (
                i32::try_from(out["code"].as_i64().unwrap()).unwrap(),
                out["stdout"].as_str().unwrap().to_string(),
                out["stderr"].as_str().unwrap().to_string(),
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
        owner
    }

    struct Sentinel {
        proc: Proc,
    }

    impl Sentinel {
        fn spawn(h: &Hcom, label: &str) -> Self {
            let script = h.root_path().join("sentinel.js");
            if !script.exists() {
                fs::write(&script, SENTINEL_JS).unwrap();
            }
            let dir = h.root_path().join(format!("sentinel-{label}"));
            // Cleared environment: no HCOM identity of any kind.
            let mut command = Command::new(node(h));
            command.arg(&script).arg(&dir).arg("with-child").env_clear();
            #[cfg(windows)]
            for key in ["SystemRoot", "WINDIR"] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
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
        assert_eq!(
            code, 0,
            "kill of the genuine native owner failed:\n{output}"
        );
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
        let mut sentinel = Sentinel::spawn(&h, "reused");
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
}
