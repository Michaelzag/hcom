//! A launch that is slow but alive is `launch pending`, not a refusal
//! (ffc-47uy6). `hcom r <name> --go` used to print a refusal-shaped line and
//! exit 2 whenever its readiness wait ran out — luvo's resume came up 54.8 s
//! after the launch on a box at loadavg ~165, and fleet read the rc as a dead
//! seat. A timed-out wait on a live TOOL is a warning with exit 0; a launch
//! whose tool is actually gone still fails loudly.
//!
//! "Alive" is deliberately about the tool, not about the pid hcom records.
//! That pid is a WRAPPER: a detached background runner, or the generated
//! terminal script's shell, which ends in `exec bash -l` and so deliberately
//! outlives the tool. Treating the wrapper as proof is exactly how a launch
//! whose tool died before its first hook came to be reported as pending.
//!
//! Real processes throughout, the `tests/launch_anchor.rs` way: a fake `claude`
//! first on PATH is what hcom really spawns, driven by a generated launch
//! script. No real tool and no network are involved. The fake tool holds itself
//! open by sleeping and releases by exiting, so a test can stop exactly the
//! processes it started.

#![cfg(target_os = "linux")]

mod support;

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use support::Hcom;

/// Marks the fake tool started, so a test can wait for a launch that is
/// genuinely under way rather than racing the spawn.
const STARTED: &str = "started";
/// Exits the fake tool immediately instead of sleeping.
const EXIT_NOW: &str = "exit-now";
/// Marks the fake tool's `sessionstart` hook as fired. Its absence is how a
/// test proves the tool died BEFORE binding — the case that must not be
/// laundered into a pending launch by a surviving wrapper shell.
const BOUND: &str = "bound";

fn open_db(h: &Hcom) -> rusqlite::Connection {
    rusqlite::Connection::open(h.path().join("hcom.db")).expect("open isolated hcom.db")
}

fn init(h: &Hcom) {
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "status failed: {stderr}");
}

/// Install a fake `claude` that binds its seat with the real `sessionstart`
/// hook, then either stays up (the slow-start case) or exits at once (the
/// dying-launch case). `HCOM_INSTANCE_NAME`/`HCOM_PROCESS_ID` come from the
/// launch env the launcher hands it, so the hook binds the row hcom created.
fn install_fake_claude(h: &Hcom) -> (PathBuf, PathBuf) {
    install_fake_claude_binding(h, true)
}

/// `bind` chooses whether the fake fires its `sessionstart` hook before it
/// settles down to wait. A LAUNCH that binds is the luvo shape: a live, bound
/// seat that simply has not reported ready inside the window. A launch that
/// does NOT bind is the dying-tool shape, and the fake exits at once instead.
///
/// A launch announces a FRESH session id: its row is minted with none, so the
/// id the hook announces is the one that binds it. A RESUME is the opposite —
/// the row's session id is pre-set from the stopped snapshot — so the resumed
/// fake must announce that same id or its hook lands on no row at all; that
/// is [`install_fake_claude_seeded`].
fn install_fake_claude_binding(h: &Hcom, bind: bool) -> (PathBuf, PathBuf) {
    install_fake_claude_with(h, None, bind, 0)
}

/// The RESUMED fake: a `claude` whose first hook re-announces `session_id`, the
/// id the resume pre-set on the stopped row, so the `sessionstart` hook binds
/// THAT row instead of minting an unbound alias. Its hooks fire after
/// `delay_secs`, past the resume window, so the wait under test runs out
/// while the tool is live and the `ready` life event lands only afterwards.
fn install_fake_claude_seeded(h: &Hcom, session_id: &str, delay_secs: u64) -> (PathBuf, PathBuf) {
    install_fake_claude_with(h, Some(session_id), true, delay_secs)
}

/// Build the fake `claude`. `session_id` picks what its hooks announce (None
/// mints a fresh id per run), `bind` whether they fire at all, and
/// `delay_secs` how long the fake stays silent first.
fn install_fake_claude_with(
    h: &Hcom,
    session_id: Option<&str>,
    bind: bool,
    delay_secs: u64,
) -> (PathBuf, PathBuf) {
    let fakebin = h.root_path().join("fakebin");
    let out = h.root_path().join("fake-claude");
    fs::create_dir_all(&fakebin).expect("create fakebin");
    fs::create_dir_all(&out).expect("create fake claude out dir");
    let bin = env!("CARGO_BIN_EXE_hcom");
    // The wait is a bounded `read`, not a `sleep` poll: a `sleep` child would
    // be a grandchild of the launch wrapper, inheriting its pipes, and a
    // leaked one holding a pipe is what turns a finished test into a hang.
    // The test's own `EXIT_NOW` marker is what actually releases the tool.
    let hook = if bind {
        // A FRESH session id when the caller named none, and the SEEDED one
        // when it did. A resume pre-sets the row's session id from the
        // snapshot before the tool is spawned, so only re-announcing that
        // exact id lands the hook on the resumed row: a fresh id has no
        // binding, no owner, and no transcript, and the hook refuses to guess.
        //
        // `sessionstart` fires AT ONCE (luvo's tool binds its seat right
        // away; an unbound row is failed by hcom's own 30 s placeholder
        // finalizer, a different and already-correct behaviour). What runs
        // late is the `ready` report: the fake stays silent for
        // `delay_secs` — past the resume window — before its `Notification`
        // hook emits the `ready` life event, so the wait under test runs out
        // on a live, bound, not-yet-ready seat.
        let announce = match session_id {
            Some(seeded) => format!(r#"sid='{seeded}'"#, seeded = seeded),
            None => format!(
                r#"sid="sid-readiness-{tag}-$$-$(date +%s%N)""#,
                tag = std::process::id()
            ),
        };
        format!(
            r#"{announce}
printf '{{"session_id":"%s","cwd":"%s","hook_event_name":"SessionStart","source":"startup"}}' "$sid" "$PWD" \
  | '{bin}' sessionstart > /dev/null 2>&1
if [ '{delay_secs}' -gt 0 ]; then
  end=$((SECONDS + {delay_secs}))
  while [ $SECONDS -lt $end ]; do
    read -t 0.2 < /dev/zero || true
  done
fi
printf '{{"session_id":"%s","cwd":"%s","hook_event_name":"Notification","message":"ready"}}' "$sid" "$PWD" \
  | '{bin}' notify > /dev/null 2>&1
touch '{out}/'{bound}"#,
            announce = announce,
            delay_secs = delay_secs,
            out = out.display(),
            bin = bin,
            bound = BOUND,
        )
    } else {
        String::new()
    };
    let script = format!(
        r#"#!/bin/bash
touch '{out}/'{started}
if [ -e '{out}/'{exit_now} ]; then
  exit 0
fi
{hook}
while [ ! -e '{out}/'{exit_now} ]; do
  read -t 0.2 || true
done
"#,
        out = out.display(),
        started = STARTED,
        exit_now = EXIT_NOW,
        hook = hook,
    );
    let claude = fakebin.join("claude");
    fs::write(&claude, script).expect("write fake claude");
    fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).expect("chmod fake claude");
    (fakebin, out)
}

/// `h.cmd()` with the fake tool dir first on PATH and the AI-tool marker that
/// arms hcom's inline readiness wait and the exit code under test. The marker
/// is stripped from the launched child's env, so the tool still sees a clean
/// environment.
fn launch_cmd(h: &Hcom, fakebin: &Path) -> Command {
    let mut cmd = h.cmd();
    let inherited: OsString = cmd
        .get_envs()
        .find(|(key, _)| *key == "PATH")
        .and_then(|(_, value)| value.map(|v| v.to_os_string()))
        .unwrap_or_default();
    let mut entries = vec![fakebin.to_path_buf()];
    entries.extend(std::env::split_paths(&inherited));
    cmd.env("PATH", std::env::join_paths(entries).expect("join PATH"));
    cmd.env("OMPCODE", "1");
    cmd.stdin(Stdio::null());
    cmd
}

/// Run a command to completion, returning `(exit code, stdout, stderr)`.
fn run_bounded(mut cmd: Command, label: &str) -> (i32, String, String) {
    let collected = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {label}: {e}"))
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait {label}: {e}"));
    (
        collected.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&collected.stdout).into_owned(),
        String::from_utf8_lossy(&collected.stderr).into_owned(),
    )
}

fn alive(pid: i64) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// The ppid of `pid`, or None when it is gone or unparseable — the same
/// `/proc/<pid>/stat` field hcom's own process-tree walk reads.
fn ppid_of(pid: i64) -> Option<i64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

/// Every live pid at or below `root`, `root` included, in breadth-first order.
/// The test-side mirror of the walk the fix performs, so a test can assert on
/// what a wrapper is actually hiding.
fn live_descendants(root: i64) -> Vec<i64> {
    let all = live_pids();
    let mut out = vec![root];
    let mut frontier = vec![root];
    while !frontier.is_empty() {
        let next: Vec<i64> = all
            .iter()
            .copied()
            .filter(|pid| {
                !out.contains(pid) && ppid_of(*pid).is_some_and(|p| frontier.contains(&p))
            })
            .collect();
        if next.is_empty() {
            break;
        }
        out.extend(next.iter().copied());
        frontier = next;
    }
    out
}

/// Every pid currently in `/proc`.
fn live_pids() -> Vec<i64> {
    fs::read_dir("/proc")
        .expect("read /proc")
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i64>().ok())
        .collect()
}

/// Whether any live process at or below `root` is the fake `claude`, by the
/// exact name the launcher exec'd it under.
///
/// The fake is a `#!/bin/bash` script, so `/proc/<pid>/comm` reads `bash` —
/// but the LAUNCHER replaces the command with the resolved absolute path
/// (`/…/fakebin/claude`) before running it, so that path is in the argv of the
/// process that ran it. Matching the path is therefore both exact and immune to
/// a real `claude` anywhere else on the box.
fn live_tool_under(root: i64, fakebin: &Path) -> Option<i64> {
    let needle = fakebin.join("claude").to_string_lossy().into_owned();
    live_descendants(root).into_iter().find(|pid| {
        fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| {
            cmdline
                .split(|b| *b == 0)
                .any(|arg| arg == needle.as_bytes())
        })
    })
}

/// Poll `cond` (which yields the value to return) until it produces one or the
/// deadline passes, then return it.
fn wait_until<T>(label: &str, deadline: Duration, mut cond: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(value) = cond() {
            return value;
        }
        if start.elapsed() >= deadline {
            panic!("timed out waiting for {label}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The seat this run actually launched: the newest row that is not one of the
/// snapshots this test seeded. `sole_instance_name` would otherwise return a
/// seeded seat whenever a resume also created one.
fn launched_seat_name(h: &Hcom) -> Option<String> {
    let db = open_db(h);
    let mut stmt = db
        .prepare(
            "SELECT name FROM instances \
             WHERE name NOT LIKE 'seeded-%' AND name NOT LIKE ':%' \
             ORDER BY created_at",
        )
        .ok()?;
    stmt.query_map([], |r| r.get::<_, String>(0))
        .ok()?
        .filter_map(Result::ok)
        .next()
}

fn row_pid(h: &Hcom, name: &str) -> Option<i64> {
    open_db(h)
        .query_row("SELECT pid FROM instances WHERE name = ?1", [name], |r| {
            r.get(0)
        })
        .ok()
}

/// The binding facts about a seat's row: its `session_id` and whether a hook
/// has bound it. `hooks_bound` reads the `session_bindings` table the way
/// `hcom list --json` computes it (`db.has_session_binding`), not a column.
struct RowBinding {
    session_id: Option<String>,
    hooks_bound: bool,
}

fn instance_row(h: &Hcom, name: &str) -> Option<RowBinding> {
    let db = open_db(h);
    let session_id: Option<String> = db
        .query_row(
            "SELECT session_id FROM instances WHERE name = ?1",
            [name],
            |r| r.get(0),
        )
        .ok()
        .flatten();
    let session_id = session_id?;
    let hooks_bound: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM session_bindings WHERE instance_name = ?1)",
            [name],
            |r| r.get(0),
        )
        .unwrap_or(false);
    Some(RowBinding {
        session_id: Some(session_id),
        hooks_bound,
    })
}

/// The live case from the bead: the tool is up but has not reported ready when
/// the 10 s window elapses. The launch must exit 0 saying `launch pending`,
/// and must never say anything a caller could read as a refusal.
#[test]
fn a_late_ready_live_launch_is_pending_and_exits_zero() {
    let h = Hcom::new();
    init(&h);
    let (fakebin, out) = install_fake_claude(&h);

    // `-p` is the detached background shape: hcom records the runner's pid on
    // the row, returns immediately, and then waits for readiness — the exact
    // sequence the inline wait and its exit code hang off.
    let (code, stdout, stderr) = run_bounded(
        {
            let mut cmd = launch_cmd(&h, &fakebin);
            cmd.args(["claude", "-p", "hi", "--go"]);
            cmd
        },
        "hcom launch",
    );

    wait_until("the fake tool to start", Duration::from_secs(30), || {
        out.join(STARTED).exists().then_some(())
    });
    // The window has elapsed by now, so the launched TOOL is still running:
    // exactly the luvo case (ready long after the wait gave up).
    let name = launched_seat_name(&h).expect("the launch created a seat");
    let pid = row_pid(&h, &name).expect("the launcher recorded a pid");
    h.track_cleanup_pid(pid);
    assert!(alive(pid), "recorded pid {pid} is not live");
    let tool_pid = live_tool_under(pid, &fakebin).unwrap_or_else(|| {
        panic!("no live tool under the recorded pid {pid}\nstdout={stdout}\nstderr={stderr}")
    });
    h.track_cleanup_pid(tool_pid);

    assert_eq!(
        code, 0,
        "a live launch past its readiness window is not a failure\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("Launch pending"),
        "stdout must name the pending launch:\n{stdout}"
    );
    assert!(
        stdout.contains("still starting after"),
        "stdout must name the late readiness:\n{stdout}"
    );
    assert!(
        !stdout.to_lowercase().contains("refused"),
        "a live launch is never reported as refused:\n{stdout}"
    );
    assert!(
        !stdout.contains("Launch failed"),
        "a live launch is not a failure:\n{stdout}"
    );
    assert!(
        stdout.contains("tool process") && stdout.contains(" alive"),
        "the pending line must report a live TOOL, not the wrapper:\n{stdout}"
    );

    // The fake tool loops until told to stop, so release it here. Left running
    // it would still carry the seat's name into every later test in this
    // binary, and hcom's name generator can hand any test the same name.
    fs::write(out.join(EXIT_NOW), "").expect("stop the fake tool");
}

/// The other half of the contract: a launch whose process is gone before ready
/// is a real failure and must still exit non-zero, naming the failure.
#[test]
fn a_launch_whose_process_dies_before_ready_fails() {
    let h = Hcom::new();
    init(&h);
    let (fakebin, out) = install_fake_claude_binding(&h, false);
    // The tool starts and exits at once: a launch that got under way and died.
    fs::write(out.join(EXIT_NOW), "").expect("arm the dying tool");

    let (code, stdout, stderr) = run_bounded(
        {
            let mut cmd = launch_cmd(&h, &fakebin);
            cmd.args(["claude", "-p", "hi", "--go"]);
            cmd
        },
        "hcom launch",
    );

    assert_ne!(
        code, 0,
        "a launch whose process died must not exit 0\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("Launch failed"),
        "stdout must name the failure:\n{stdout}"
    );
    assert!(
        !stdout.contains("Launch pending"),
        "a dead launch is never pending:\n{stdout}"
    );
}

/// A resume gets the longer window: restoring a large session is legitimately
/// slower than a fresh launch (luvo was ready 54.8 s in). Both windows are read
/// off real runs, each from the `Waiting up to Ns` line the CLI itself prints.
/// The seat is a stopped snapshot seeded the way a real stop leaves it, and
/// the fake tool exits at once so the launch returns and the wait completes.
#[test]
fn a_resume_waits_longer_than_a_fresh_launch() {
    let h = Hcom::new();
    init(&h);
    let (fakebin, out) = install_fake_claude(&h);

    // The fresh-launch window, observed on the real launch path rather than
    // re-derived from a constant.
    let fresh_wait =
        announced_wait_secs(&launch_cmd(&h, &fakebin), &["claude", "-p", "hi", "--go"]);
    assert_eq!(fresh_wait, 10, "a fresh launch keeps the 10 s window");

    let name = seed_stopped_claude(&h, "seeded-lave");
    fs::write(out.join(EXIT_NOW), "").expect("arm the immediate-exit tool");
    let resume_wait =
        announced_wait_secs(&launch_cmd(&h, &fakebin), &["r", &name, "-p", "hi", "--go"]);
    assert!(
        resume_wait > fresh_wait,
        "a resume must wait longer than a fresh launch: {resume_wait}s vs {fresh_wait}s"
    );
    assert_eq!(resume_wait, 30, "the resume window is 30 s");
}

/// Run a command and return the inline readiness window it announced, parsed
/// from its own `Waiting up to Ns for launch readiness...` line. The exit code
/// is deliberately not asserted: these runs end in a dead launch (the fake tool
/// exits), and only the announced window is under test.
fn announced_wait_secs(base: &Command, args: &[&str]) -> u64 {
    let mut cmd = Command::new(base.get_program());
    cmd.args(base.get_args());
    for (key, value) in base.get_envs() {
        match value {
            Some(value) => {
                cmd.env(key, value);
            }
            None => {
                cmd.env_remove(key);
            }
        }
    }
    cmd.args(args);
    let (_, stdout, stderr) = run_bounded(cmd, "hcom readiness wait");
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("Waiting up to "))
        .and_then(|rest| rest.split('s').next())
        .and_then(|secs| secs.trim().parse().ok())
        .unwrap_or_else(|| {
            panic!("no readiness window announced\nstdout={stdout}\nstderr={stderr}")
        })
}

/// The same dead launch through the OTHER launch shape, which is where a
/// pid-only liveness check goes wrong: the new-window script ends with
/// `exec bash -l`, so a tool that dies before its first hook leaves the
/// recorded anchor pid alive with no agent behind it. That is still a failed
/// launch, and must not be laundered into a pending one by the surviving shell.
#[test]
fn a_new_window_launch_whose_tool_dies_before_binding_fails() {
    let h = Hcom::new();
    init(&h);
    let (fakebin, out) = install_fake_claude_binding(&h, false);
    // Start, then die before the `sessionstart` hook: the seat never binds.
    fs::write(out.join(EXIT_NOW), "").expect("arm the dying tool");

    let (code, stdout, stderr) = run_bounded(
        {
            // A custom terminal command IS the new-window shape: hcom writes the
            // launch script, `bash` runs it, and the script's trailing
            // `exec bash -l` keeps that shell alive after the tool is gone.
            let mut cmd = launch_cmd(&h, &fakebin);
            cmd.env("HCOM_TERMINAL", "bash {script}");
            cmd.args(["claude", "--go"]);
            cmd
        },
        "hcom launch (new window)",
    );

    // The tool ran and exited before it ever bound a seat.
    assert!(
        out.join(STARTED).exists(),
        "the fake tool never ran\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        !out.join(BOUND).exists(),
        "the tool must die before its first hook, or this proves nothing"
    );

    assert_ne!(
        code, 0,
        "a tool that died before binding is not a pending launch\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("Launch failed"),
        "stdout must name the failure:\n{stdout}"
    );
    assert!(
        !stdout.contains("Launch pending"),
        "a launch whose tool never started is never pending:\n{stdout}"
    );
}

/// The bead's own end-to-end case, on the command it happened on: `hcom r
/// <name> --go` whose readiness window runs out while the resumed TOOL is
/// still alive. The resume must exit 0 saying `launch pending` — the rc=2 that
/// made fleet treat luvo's working seat as a failure is exactly what this pins
/// down.
#[test]
fn a_resume_that_is_late_but_alive_is_pending_not_refused() {
    let h = Hcom::new();
    init(&h);
    // `luvo` is the bead's seat name; hcom's own name generator uses the same
    // ordinary names, so this one carries a prefix it never mints.
    let session_id = "sid-resume-seeded-luvo".to_string();
    // The resumed tool re-announces the SEEDED session id (what the resume
    // pre-set on the row) and binds at once, but reports ready only after the
    // 30 s resume window has passed — the shape luvo actually had: alive,
    // bound, late to report, and so unproven to the wait, never refused.
    let (fakebin, out) = install_fake_claude_seeded(&h, &session_id, 35);
    let name = seed_stopped_claude(&h, "seeded-luvo");
    assert_eq!(name, "seeded-luvo");

    let (code, stdout, stderr) = run_bounded(
        {
            let mut cmd = launch_cmd(&h, &fakebin);
            cmd.args(["r", &name, "-p", "hi", "--go"]);
            cmd
        },
        "hcom r",
    );

    // The resume ran to completion, so the tool either started or never did.
    assert!(
        out.join(STARTED).exists(),
        "resume produced no launched tool\nstdout={stdout}\nstderr={stderr}"
    );
    // The fake fires `sessionstart` at once and delays only its `ready`
    // report, so the seat binds even though the wait already gave up: the
    // real resume shape. The marker proves the fixture actually followed it.
    wait_until(
        "the resumed tool to bind its seat",
        Duration::from_secs(30),
        || out.join(BOUND).exists().then_some(()),
    );
    // The 30 s resume window has elapsed and the resumed TOOL is still
    // running, so the launch is pending — not failed, and never refused. A
    // resume reuses the seat's own row, so the name to read is the seeded one.
    let pid = row_pid(&h, &name).expect("the resume recorded a pid");
    h.track_cleanup_pid(pid);
    assert!(alive(pid), "resumed pid {pid} is not live");
    let tool_pid = live_tool_under(pid, &fakebin).unwrap_or_else(|| {
        panic!("no live tool under the resumed pid {pid}\nstdout={stdout}\nstderr={stderr}")
    });
    h.track_cleanup_pid(tool_pid);

    assert_eq!(
        code, 0,
        "a live resume past its readiness window is not a failure\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("Launch pending"),
        "stdout must name the pending resume:\n{stdout}"
    );
    assert!(
        !stdout.to_lowercase().contains("refused"),
        "a live resume is never reported as refused:\n{stdout}"
    );
    assert!(
        !stdout.contains("Launch failed"),
        "a live resume is not a failure:\n{stdout}"
    );
    // The seat bound on the SAME row the resume was issued against, with the
    // SAME session id the stop snapshot carried — a resume must never mint a
    // second row or a fresh session alias under the tool.
    let row = instance_row(&h, &name).unwrap_or_else(|| {
        panic!("the resumed seat's row disappeared\nstdout={stdout}\nstderr={stderr}")
    });
    assert_eq!(
        row.session_id.as_deref(),
        Some(session_id.as_str()),
        "the resumed row must keep the seeded session id\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        row.hooks_bound,
        "the resumed seat must end up hook-bound\nstdout={stdout}\nstderr={stderr}"
    );

    // Release the fake tool: it would otherwise still be carrying the seat's
    // name when the next test in this binary runs.
    fs::write(out.join(EXIT_NOW), "").expect("stop the fake tool");
}

/// Seed a `claude` seat as a real stop leaves it: an inactive row plus the
/// `life.stopped` event carrying its snapshot, which is what `hcom r` plans
/// from. No pid — a live anchor would make the resume refuse.
fn seed_stopped_claude(h: &Hcom, name: &str) -> String {
    let session_id = format!("sid-resume-{name}");
    let workspace = h.workspace.to_string_lossy().into_owned();
    let db = open_db(h);
    // `created_at` is NOW, not epoch 1. A resume does NOT re-arm the row as
    // a fresh placeholder: it pre-sets the row's `session_id` from the
    // stopped snapshot before the tool is spawned, so the row is never a
    // session-less placeholder and the 30 s unbound-placeholder finalizer
    // cannot touch it. `created_at` still seeds the row's own age, so it must
    // be current for the resume's wait to see a row inside its budget rather
    // than one already hours old.
    db.execute(
        "INSERT INTO instances (name, tool, session_id, status, status_context,
                                status_time, created_at, last_event_id)
         VALUES (?1, 'claude', ?2, 'inactive', 'exit:0', 0,
                 CAST(strftime('%s', 'now') AS REAL), 0)",
        rusqlite::params![name, session_id],
    )
    .expect("seed stopped instance");
    let snapshot = serde_json::json!({
        "action": "stopped",
        "by": "session",
        "reason": "exit:normal",
        "process_id": null,
        "snapshot": {
            "tool": "claude",
            "session_id": session_id,
            "directory": workspace,
            "background": 0,
            "last_event_id": 0,
        },
    });
    db.execute(
        "INSERT INTO events (timestamp, type, instance, data)
         VALUES (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'life', ?1, ?2)",
        rusqlite::params![name, snapshot.to_string()],
    )
    .expect("seed stopped event");
    name.to_string()
}
