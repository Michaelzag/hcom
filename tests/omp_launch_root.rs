//! A real OMP launch records its PTY child as `omp_launch_root` (#106).
//!
//! The fixture `omp` stands in for a native launcher: it execs into a non-OMP
//! launcher process (the PTY child), which starts the interpreter, a child
//! with the exact `omp` argv0 the owner classifier recognizes. The interpreter
//! waits on a file gate, then runs the real omp-start hook, which re-pins the
//! row's owner to the interpreter. The root must name the PTY child before
//! and after that re-pin. Every process belongs to the fixture; nothing
//! reaches a model, a terminal application or the operator's hcom state.

#![cfg(target_os = "linux")]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use support::Hcom;
use support::omp_owner::{db, isolated_hcom};

const WAIT: Duration = Duration::from_secs(30);

fn wait_until<T>(mut poll: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(value) = poll() {
            return Some(value);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn stat_fields(pid: i64) -> Option<Vec<String>> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(
        stat.rsplit_once(')')?
            .1
            .split_whitespace()
            .map(str::to_string)
            .collect(),
    )
}

fn parent_of(pid: i64) -> Option<i64> {
    stat_fields(pid)?.get(1)?.parse().ok()
}

fn comm(pid: i64) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// The native identity hcom records on Linux, read straight from procfs.
fn native_identity(pid: i64) -> Option<String> {
    let ticks = stat_fields(pid)?.get(19)?.clone();
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    Some(format!("linux:{}:{ticks}", boot_id.trim()))
}

/// /var/tmp avoids OMP's real /tmp cwd redirect; every root stays the fixture's.
fn fixture() -> (Hcom, tempfile::TempDir) {
    let workspace = tempfile::Builder::new()
        .prefix("hcom-omp-root-")
        .tempdir_in("/var/tmp")
        .expect("create private non-/tmp OMP workspace");
    let mut h = isolated_hcom();
    h.workspace = workspace.path().to_path_buf();
    (h, workspace)
}

/// Fixture-private launch PATH. `omp` execs into the launcher script (the PTY
/// child), which starts the interpreter and waits for it. The interpreter
/// announces `<pid>.started`, waits for `<pid>.hook`, runs the real omp-start
/// once and records its exit code, then waits for `<pid>.exit`.
fn install_fake_omp(h: &Hcom, sid: &str, transcript: &Path) -> PathBuf {
    let fakebin = h.root_path().join("fakebin");
    let out = h.root_path().join("omp-root");
    fs::create_dir_all(&fakebin).unwrap();
    fs::create_dir_all(&out).unwrap();
    // Only the generated post-tool login shell exits; `bash {script}` passes through.
    executable(
        &fakebin.join("bash"),
        "#!/bin/bash\nif [ \"$#\" -eq 1 ] && [ \"$1\" = -l ]; then exit 0; fi\nexec /bin/bash \"$@\"\n",
    );
    let interpreter = out.join("interpreter.sh");
    fs::write(
        &interpreter,
        format!(
            r#"out={out}
mkfifo "$out/wait-$$" || exit 1
exec 9<> "$out/wait-$$"
printf '%s\n' "$PPID" > "$out/$$.started"
end=$((SECONDS + 90))
while [ ! -e "$out/$$.hook" ] && [ ! -e "$out/$$.exit" ] && [ "$SECONDS" -lt "$end" ]; do
    read -r -t 0.05 -u 9 || true
done
if [ -e "$out/$$.hook" ]; then
    {bin} omp-start --session-id '{sid}' --transcript-path {transcript} --cwd {cwd} > "$out/$$.stdout" 2> "$out/$$.stderr"
    printf '%s' "$?" > "$out/$$.code"
fi
while [ ! -e "$out/$$.exit" ] && [ "$SECONDS" -lt "$end" ]; do
    read -r -t 0.05 -u 9 || true
done
"#,
            out = quote(&out),
            bin = quote(Path::new(env!("CARGO_BIN_EXE_hcom"))),
            transcript = quote(transcript),
            cwd = quote(&h.workspace),
        ),
    )
    .unwrap();
    let launcher = out.join("launcher.sh");
    fs::write(
        &launcher,
        format!("( exec -a omp /bin/bash {} \"$@\" )\n", quote(&interpreter)),
    )
    .unwrap();
    // A file named `omp` is itself an OMP by comm. exec keeps the PTY child's
    // PID but makes it a non-OMP launcher, so the interpreter is the only OMP.
    executable(
        &fakebin.join("omp"),
        &format!(
            "#!/bin/bash\nif [ \"${{1:-}}\" = --version ]; then printf '1.0.0\\n'; exit 0; fi\nexec -a omp-launcher /bin/bash {} \"$@\"\n",
            quote(&launcher)
        ),
    );
    let command = h.cmd();
    let inherited = |key: &str| {
        command
            .get_envs()
            .find(|(name, _)| *name == key)
            .and_then(|(_, value)| value)
            .map(|value| value.to_str().unwrap().to_string())
    };
    let mut paths = vec![fakebin];
    paths.extend(std::env::split_paths(
        &inherited("PATH").expect("fixture PATH"),
    ));
    h.set_launch_env(
        "PATH",
        std::env::join_paths(paths).unwrap().to_str().unwrap(),
    );
    for key in [
        "HOME",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "CODEX_HOME",
    ] {
        if let Some(value) = inherited(key) {
            h.set_launch_env(key, &value);
        }
    }
    h.set_launch_env("PI_CONFIG_DIR", h.home.join(".omp").to_str().unwrap());
    h.set_launch_env(
        "PI_CODING_AGENT_DIR",
        h.home.join(".omp/agent").to_str().unwrap(),
    );
    out
}

/// The launch CLI is retained unreaped. Detached tools use private exit gates
/// and the fixture's hcom teardown, never borrowed PIDs or process-group signals.
struct Launch {
    child: Child,
    identity: Option<String>,
    out: PathBuf,
}

impl Launch {
    fn start(h: &Hcom, label: &str, args: &[&str], out: &Path) -> Self {
        let child = h
            .cmd()
            .args(args)
            .current_dir(&h.workspace)
            .stdin(Stdio::null())
            .stdout(fs::File::create(h.root_path().join(format!("{label}.stdout"))).unwrap())
            .stderr(fs::File::create(h.root_path().join(format!("{label}.stderr"))).unwrap())
            .process_group(0)
            .spawn()
            .unwrap();
        let identity = support::child_identity(&child);
        Self {
            child,
            identity,
            out: out.to_path_buf(),
        }
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.out) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "started")
                {
                    let _ = fs::write(path.with_extension("exit"), "");
                }
            }
        }
        support::terminate_owned_child(&mut self.child, self.identity.as_deref());
    }
}

#[derive(Debug)]
struct Seat {
    pid: Option<i64>,
    receipt: Option<Value>,
    root: Option<Value>,
}

fn omp_seat(h: &Hcom) -> Option<(String, Seat)> {
    let (name, pid, context): (String, Option<i64>, Option<String>) = db(h)
        .query_row(
            "SELECT name, pid, launch_context FROM instances WHERE tool = 'omp'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .ok()?;
    let context = context
        .filter(|text| !text.is_empty())
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .unwrap_or(Value::Null);
    Some((
        name,
        Seat {
            pid,
            receipt: context.get("omp_launch_pid").cloned(),
            root: context.get("omp_launch_root").cloned(),
        },
    ))
}

#[test]
fn a_real_omp_launch_roots_at_its_pty_child_across_the_hook_repin() {
    for (mode, mode_args) in [
        ("new-window", &["--terminal", "bash {script}"][..]),
        ("background", &["--headless"][..]),
    ] {
        let (h, workspace) = fixture();
        let sid = uuid::Uuid::new_v4().to_string();
        let transcript = h
            .home
            .join(".omp/agent/sessions/launch-root")
            .join(format!("2026-10-01T00-00-00-000Z_{sid}.jsonl"));
        fs::create_dir_all(transcript.parent().unwrap()).unwrap();
        fs::write(
            &transcript,
            format!(
                "{}\n",
                json!({"type": "session", "id": sid, "cwd": h.workspace})
            ),
        )
        .unwrap();
        let out = install_fake_omp(&h, &sid, &transcript);
        let mut args = vec!["omp"];
        args.extend_from_slice(mode_args);
        args.push("--go");
        let launch = Launch::start(&h, mode, &args, &out);

        // The interpreter's parent is the PTY child: the launcher exec'd from `omp`.
        let interpreter = wait_until(|| {
            fs::read_dir(&out).ok()?.flatten().find_map(|entry| {
                let path = entry.path();
                let pid: i64 = path.file_stem()?.to_str()?.parse().ok()?;
                (path.extension()? == "started").then_some(pid)
            })
        })
        .unwrap_or_else(|| {
            panic!(
                "{mode}: fixture interpreter never started: {}",
                fs::read_to_string(h.root_path().join(format!("{mode}.stderr")))
                    .unwrap_or_default()
            )
        });
        let child = parent_of(interpreter).unwrap();
        let pty = parent_of(child).unwrap();
        let root = json!({"pid": child, "identity": native_identity(child).unwrap()});
        let (name, before) = wait_until(|| {
            omp_seat(&h).filter(|(_, seat)| seat.pid == Some(child) && seat.root.is_some())
        })
        .unwrap_or_else(|| panic!("{mode}: the PTY child pin never landed: {:?}", omp_seat(&h)));

        fs::write(out.join(format!("{interpreter}.hook")), "").unwrap();
        let code = wait_until(|| fs::read_to_string(out.join(format!("{interpreter}.code"))).ok());
        let after = omp_seat(&h).map(|(_, seat)| seat);
        let hook_stderr =
            fs::read_to_string(out.join(format!("{interpreter}.stderr"))).unwrap_or_default();
        let topology = (comm(pty), comm(child), comm(interpreter));
        let _ = h.run(["kill", &name]);
        fs::write(out.join(format!("{interpreter}.exit")), "").unwrap();
        drop(launch);
        drop(h);
        drop(workspace);

        assert_eq!(
            topology,
            ("hcom".to_string(), "bash".to_string(), "bash".to_string()),
            "{mode}: expected hcom pty -> launcher -> interpreter"
        );
        assert_eq!(
            before.root.as_ref(),
            Some(&root),
            "{mode}: {name}'s root is not its PTY child"
        );
        assert_eq!(
            before
                .receipt
                .as_ref()
                .and_then(|receipt| receipt.get("pid")),
            Some(&json!(child)),
            "{mode}: the child pin's receipt names another PID"
        );
        assert_eq!(
            code.as_deref(),
            Some("0"),
            "{mode}: hook failed: {hook_stderr}"
        );
        let after = after.expect("hooked row");
        assert_eq!(
            after.pid,
            Some(interpreter),
            "{mode}: the first hook did not re-pin the owner to the interpreter"
        );
        assert_eq!(
            after
                .receipt
                .as_ref()
                .and_then(|receipt| receipt.get("pid")),
            Some(&json!(interpreter)),
            "{mode}: the owner receipt did not follow the re-pin"
        );
        assert_eq!(
            after.root.as_ref(),
            Some(&root),
            "{mode}: the hook re-pin rewrote the launch root"
        );
    }
}
