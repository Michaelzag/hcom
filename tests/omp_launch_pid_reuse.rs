//! Real resume launches whose OMP process has not reached its first hook.
//!
//! The fixture tool only waits on file-step gates and calls the real omp-start
//! hook. Direct children remain retained with birth identities; detached tools
//! exit through private file gates and fixture-local hcom teardown.

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
use support::omp_owner::{db, full_state, isolated_hcom};

const PROCESS_WAIT: Duration = Duration::from_secs(10);

fn wait_until<T>(timeout: Duration, mut poll: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
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

fn alive(pid: i64) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| stat.rsplit_once(')').map(|(_, tail)| tail.to_string()))
        .and_then(|tail| tail.split_whitespace().next().map(str::to_string))
        .is_some_and(|state| state != "Z" && state != "X")
}

fn start_ticks(pid: i64) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 22, counting from field 3 (state) after the parenthesized comm.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)
        .map(str::to_string)
}

fn live_tool_under(root: i64, tool: i64) -> bool {
    let recognized = fs::read(format!("/proc/{tool}/cmdline"))
        .is_ok_and(|argv| argv.split(|byte| *byte == 0).next() == Some(b"omp".as_slice()));
    if !recognized || !alive(tool) {
        return false;
    }
    let mut pid = tool;
    for _ in 0..32 {
        if pid == root {
            return true;
        }
        let Some(parent) = fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat.rsplit_once(')').map(|(_, tail)| tail.to_string()))
            .and_then(|tail| tail.split_whitespace().nth(1)?.parse::<i64>().ok())
        else {
            return false;
        };
        if parent <= 1 || parent == pid {
            return false;
        }
        pid = parent;
    }
    false
}

fn row_pid(h: &Hcom, name: &str) -> Option<i64> {
    db(h)
        .query_row("SELECT pid FROM instances WHERE name=?1", [name], |row| {
            row.get(0)
        })
        .ok()
        .flatten()
}

fn launch_context(h: &Hcom, name: &str) -> Value {
    let text: String = db(h)
        .query_row(
            "SELECT launch_context FROM instances WHERE name=?1",
            [name],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn quote(value: &Path) -> String {
    format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
}

fn executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// /var/tmp avoids OMP's real /tmp cwd redirect without touching /build/<seat>.
/// HOME, HCOM_DIR and all tool/config files still belong to this Hcom fixture.
fn fixture() -> (Hcom, tempfile::TempDir) {
    let workspace = tempfile::Builder::new()
        .prefix("hcom-omp-launch-")
        .tempdir_in("/var/tmp")
        .expect("create private non-/tmp OMP workspace");
    let mut h = isolated_hcom();
    h.workspace = workspace.path().to_path_buf();
    (h, workspace)
}

fn install_fake_omp(h: &Hcom, sid: &str, transcript: &Path) -> PathBuf {
    let fakebin = h.root_path().join("fakebin");
    let out = h.root_path().join("omp-launch");
    fs::create_dir_all(&fakebin).unwrap();
    fs::create_dir_all(&out).unwrap();
    // Fixture-private only. The actual `bash {script}` invocation is passed
    // straight through; only the generated post-tool login shell exits.
    executable(
        &fakebin.join("bash"),
        "#!/bin/bash\nif [ \"$#\" -eq 1 ] && [ \"$1\" = -l ]; then exit 0; fi\nexec /bin/bash \"$@\"\n",
    );
    let runner = out.join("runner.sh");
    fs::write(&runner, format!(r#"out={out}
if [ "$HOME" != {home} ] || [ "$HCOM_DIR" != {hcom_dir} ]; then
    printf 'fixture environment escaped: HOME=%s HCOM_DIR=%s\n' "$HOME" "$HCOM_DIR" > "$out/environment-error"
    exit 97
fi
exec 9<> "$out/wait-$$"
printf '%s\n%s\n%s\n%s\n%s\n' "$$" "$PPID" "$HCOM_PROCESS_ID" "$HOME" "$HCOM_DIR" > "$out/$$.started"
end=$((SECONDS + 90))
while [ ! -e "$out/$$.hook" ] && [ ! -e "$out/$$.exit" ] && [ "$SECONDS" -lt "$end" ]; do
    read -r -t 0.05 -u 9 || true
done
if [ -e "$out/$$.hook" ]; then
    : > "$out/$$.hook-called"
    {bin} omp-start --session-id '{sid}' --transcript-path {transcript} --cwd {cwd} > "$out/$$.stdout" 2> "$out/$$.stderr"
    printf '%s' "$?" > "$out/$$.code"
fi
while [ ! -e "$out/$$.exit" ] && [ "$SECONDS" -lt "$end" ]; do
    read -r -t 0.05 -u 9 || true
done
"#,
        out = quote(&out), bin = quote(Path::new(env!("CARGO_BIN_EXE_hcom"))),
        transcript = quote(transcript), cwd = quote(&h.workspace),
        home = quote(&h.home), hcom_dir = quote(h.path()),
    )).unwrap();
    // A shebang-only Bash script is not an OMP owner. exec preserves this
    // PID but gives the real classifier the exact recognized argv[0] `omp`.
    executable(
        &fakebin.join("omp"),
        &format!(
            r#"#!/bin/bash
if [ "${{1:-}}" = --version ]; then printf '1.0.0\n'; exit 0; fi
out={out}
mkfifo "$out/wait-$$" || exit 1
exec -a omp /bin/bash {runner} "$@"
"#,
            out = quote(&out),
            runner = quote(&runner)
        ),
    );
    // CI rebuilds the child env from a clean shell. Persist fixture roots and
    // PATH through the existing fixture passthrough, not just the parent CLI.
    let command = h.cmd();
    let inherited = command
        .get_envs()
        .find(|(key, _)| *key == "PATH")
        .and_then(|(_, value)| value)
        .unwrap();
    let mut paths = vec![fakebin];
    paths.extend(std::env::split_paths(inherited));
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
        if let Some((_, Some(value))) = command.get_envs().find(|(name, _)| *name == key) {
            h.set_launch_env(key, value.to_str().unwrap());
        }
    }
    h.set_launch_env("PI_CONFIG_DIR", h.home.join(".omp").to_str().unwrap());
    h.set_launch_env(
        "PI_CODING_AGENT_DIR",
        h.home.join(".omp/agent").to_str().unwrap(),
    );
    out
}

fn seed_stopped_omp(h: &Hcom, name: &str) -> (String, PathBuf) {
    let sid = uuid::Uuid::new_v4().to_string();
    let transcript = h
        .home
        .join(".omp/agent/sessions/pre-hook")
        .join(format!("2026-10-01T00-00-00-000Z_{sid}.jsonl"));
    fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    fs::write(
        &transcript,
        format!(
            "{}\n",
            json!({"type":"session", "id":sid, "cwd":h.workspace})
        ),
    )
    .unwrap();
    // The historical owner really existed and was reaped. Its old snapshot
    // cannot provide birth evidence for either of the new pre-hook launches.
    let mut prior = h
        .external_cmd("/bin/bash")
        .args(["-c", "exec -a omp /bin/bash -c 'exit 0'"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    let prior_pid = i64::from(prior.id());
    prior.wait().unwrap();
    assert!(!alive(prior_pid), "historical fixture owner did not exit");
    let conn = db(h);
    conn.execute(
        "INSERT INTO instances (name,tool,session_id,status,status_context,status_time,created_at,directory,transcript_path,last_event_id)
         VALUES (?1,'omp',?2,'inactive','exit:0',0,CAST(strftime('%s','now') AS REAL),?3,?4,0)",
        rusqlite::params![name,sid,h.workspace.to_string_lossy(),transcript.to_string_lossy()],
    ).unwrap();
    conn.execute(
        "INSERT INTO events (timestamp,type,instance,data) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'),'life',?1,?2)",
        rusqlite::params![name,json!({
            "action":"stopped", "by":"session", "reason":"exit:normal",
            "process_id":format!("omp-{prior_pid}-5-6"),
            "snapshot":{"name":name, "tool":"omp", "session_id":sid, "pid":prior_pid,
                "directory":h.workspace, "transcript_path":transcript, "background":0,
                "launch_args":"", "last_event_id":0}
        }).to_string()],
    ).unwrap();
    (sid, transcript)
}

#[derive(Debug)]
struct CommandOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

/// File-backed output cannot be held open by a terminal grandchild. The
/// deadline bounds even a buggy launch that never returns.
struct PrivateCommand {
    child: Child,
    identity: Option<String>,
    out: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
    deadline: Instant,
}

impl PrivateCommand {
    fn start(h: &Hcom, label: &str, args: &[&str]) -> Self {
        let stdout = h.root_path().join(format!("{label}.stdout"));
        let stderr = h.root_path().join(format!("{label}.stderr"));
        let child = h
            .cmd()
            .args(args)
            .current_dir(&h.workspace)
            .stdin(Stdio::null())
            .stdout(fs::File::create(&stdout).unwrap())
            .stderr(fs::File::create(&stderr).unwrap())
            .process_group(0)
            .spawn()
            .unwrap();
        let identity = support::child_identity(&child);
        Self {
            child,
            identity,
            out: h.root_path().join("omp-launch"),
            stdout,
            stderr,
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }

    fn resume(h: &Hcom, label: &str, name: &str) -> Self {
        Self::start(
            h,
            label,
            &["r", name, "--terminal", "bash {script}", "--go"],
        )
    }

    // Release detached tools before callers can drop Hcom's temporary tree,
    // including a failed first-tool pin or a timed-out launch.
    fn stop(&mut self) {
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
        support::terminate_owned_child_group(&mut self.child, self.identity.as_deref());
    }

    fn finish(&mut self) -> CommandOutput {
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= self.deadline {
                self.stop();
                break None;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        CommandOutput {
            code: status.and_then(|status| status.code()).unwrap_or(-1),
            stdout: fs::read_to_string(&self.stdout).unwrap_or_default(),
            stderr: format!(
                "{}{}",
                fs::read_to_string(&self.stderr).unwrap_or_default(),
                if status.is_none() {
                    "\nfixture command deadline exceeded"
                } else {
                    ""
                }
            ),
        }
    }
}

impl Drop for PrivateCommand {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug)]
struct Tool {
    pid: i64,
    launcher_id: String,
    home: String,
    hcom_dir: String,
}

fn wait_for_tool(
    _h: &Hcom,
    out: &Path,
    launch: &mut PrivateCommand,
    previous: Option<i64>,
) -> Option<Tool> {
    wait_until(PROCESS_WAIT, || {
        let tool = fs::read_dir(out).ok()?.flatten().find_map(|entry| {
            let path = entry.path();
            if path.extension()?.to_str()? != "started" {
                return None;
            }
            let text = fs::read_to_string(path).ok()?;
            let mut fields = text.lines();
            let pid = fields.next()?.parse().ok()?;
            if Some(pid) == previous {
                return None;
            }
            let _parent: i64 = fields.next()?.parse().ok()?;
            let tool = Tool {
                pid,
                launcher_id: fields.next()?.to_string(),
                home: fields.next()?.to_string(),
                hcom_dir: fields.next()?.to_string(),
            };
            Some(tool)
        });
        if tool.is_some() || launch.child.try_wait().ok().flatten().is_some() {
            Some(tool)
        } else {
            None
        }
    })
    .flatten()
}

fn first_tool(h: Hcom, name: &str, out: &Path, launch: &mut PrivateCommand) -> (Hcom, Tool, i64) {
    let tool = wait_for_tool(&h, out, launch, None);
    // The wrapper pins itself before its child, so the OMP's marker can appear
    // while the row still names the wrapper. Observe the settled child pin;
    // its receipt, where one is written, lands in the same write.
    let pin = tool.as_ref().and_then(|tool| {
        wait_until(PROCESS_WAIT, || {
            (row_pid(&h, name) == Some(tool.pid)).then_some(tool.pid)
        })
    });
    match (tool, pin) {
        (Some(tool), Some(pin)) => (h, tool, pin),
        (tool, pin) => {
            launch.stop();
            let result = launch.finish();
            drop(h);
            panic!(
                "fixture OMP did not start with a row pin: tool={tool:?}, pin={pin:?}, {result:?}"
            );
        }
    }
}

fn exit_first_tool(tool: &Tool, pin: i64, launch: &mut PrivateCommand) -> (CommandOutput, bool) {
    // The tool is a detached grandchild, not an owned Child. Ask the fixture
    // script to exit without its hook, preserving the stale pre-hook row.
    fs::write(launch.out.join(format!("{}.exit", tool.pid)), "").unwrap();
    launch.deadline = Instant::now() + PROCESS_WAIT;
    let result = launch.finish();
    let gone = wait_until(PROCESS_WAIT, || {
        (!alive(tool.pid) && !alive(pin)).then_some(())
    })
    .is_some();
    (result, gone)
}

#[derive(Debug)]
struct Binding {
    row_sid: Option<String>,
    row_pid: Option<i64>,
    process_sid: Option<String>,
    process_name: Option<String>,
    session_name: Option<String>,
    instances: i64,
    tool_alive: bool,
    hook: Option<Value>,
    hook_code: Option<i32>,
    hook_stderr: String,
}

fn bind_second(h: &Hcom, name: &str, sid: &str, out: &Path, tool: Option<&Tool>) -> Binding {
    if let Some(tool) = tool {
        fs::write(out.join(format!("{}.hook", tool.pid)), "").unwrap();
        wait_until(PROCESS_WAIT, || {
            out.join(format!("{}.code", tool.pid))
                .exists()
                .then_some(())
        });
    }
    let conn = db(h);
    let row_sid = conn
        .query_row(
            "SELECT session_id FROM instances WHERE name=?1",
            [name],
            |row| row.get(0),
        )
        .ok()
        .flatten();
    let launcher_id = tool.map(|tool| tool.launcher_id.as_str()).unwrap_or("");
    let (process_sid, process_name, session_name) = conn
        .query_row(
            "SELECT (SELECT session_id FROM process_bindings WHERE process_id=?1),
                (SELECT instance_name FROM process_bindings WHERE process_id=?1),
                (SELECT instance_name FROM session_bindings WHERE session_id=?2)",
            rusqlite::params![launcher_id, sid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let (hook, hook_code, hook_stderr) = tool
        .map(|tool| {
            (
                fs::read_to_string(out.join(format!("{}.stdout", tool.pid)))
                    .ok()
                    .and_then(|text| serde_json::from_str(&text).ok()),
                fs::read_to_string(out.join(format!("{}.code", tool.pid)))
                    .ok()
                    .and_then(|text| text.parse().ok()),
                fs::read_to_string(out.join(format!("{}.stderr", tool.pid))).unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    Binding {
        row_sid,
        row_pid: row_pid(h, name),
        process_sid,
        process_name,
        session_name,
        instances: conn
            .query_row("SELECT COUNT(*) FROM instances", [], |row| row.get(0))
            .unwrap(),
        tool_alive: tool.is_some_and(|tool| alive(tool.pid)),
        hook,
        hook_code,
        hook_stderr,
    }
}

fn cleanup_launch(launch: &mut PrivateCommand) -> CommandOutput {
    // The hook and live owner have already been observed. A custom terminal
    // waits for its tool, so cleanup exit status is not launch-success proof.
    launch.stop();
    launch.finish()
}

fn assert_binding(
    binding: &Binding,
    tool: Option<&Tool>,
    name: &str,
    sid: &str,
    launch: &CommandOutput,
) {
    // Binding is the main assertion: test 1 deliberately reads no new receipt.
    assert_eq!(
        binding.session_name.as_deref(),
        Some(name),
        "second resume did not bind {name}: {binding:?}; CLI={launch:?}"
    );
    let tool = tool.expect("second resume did not start OMP");
    assert_eq!(
        binding.hook_code,
        Some(0),
        "{} {binding:?}",
        binding.hook_stderr
    );
    let hook = binding
        .hook
        .as_ref()
        .expect("real omp-start produced no JSON");
    assert_eq!(hook["name"], name, "{binding:?}");
    assert!(hook.get("error").is_none(), "{binding:?}");
    assert_eq!(binding.row_sid.as_deref(), Some(sid), "{binding:?}");
    assert_eq!(binding.process_sid.as_deref(), Some(sid), "{binding:?}");
    assert_eq!(binding.process_name.as_deref(), Some(name), "{binding:?}");
    assert_eq!(
        binding.row_pid,
        Some(tool.pid),
        "second hook did not pin its actual owner: {binding:?}"
    );
    assert!(
        binding.tool_alive,
        "second OMP was not live when observed: {binding:?}"
    );
    assert_eq!(
        binding.instances, 1,
        "resume minted a duplicate name: {binding:?}"
    );
}

#[test]
fn a_second_resume_binds_after_the_first_omp_dies_before_its_hook() {
    let (h, workspace) = fixture();
    let name = "prehookdead";
    let (sid, transcript) = seed_stopped_omp(&h, name);
    let out = install_fake_omp(&h, &sid, &transcript);
    let mut first = PrivateCommand::resume(&h, "first", name);
    let (h, c1, pin) = first_tool(h, name, &out, &mut first);
    let first_was_live = alive(pin) && live_tool_under(pin, c1.pid);
    let no_first_hook = !out.join(format!("{}.hook-called", c1.pid)).exists();
    let (first_result, first_exited) = exit_first_tool(&c1, pin, &mut first);
    let dead_pin = row_pid(&h, name);
    let no_hook_after_death = !out.join(format!("{}.hook-called", c1.pid)).exists();
    let first_bound: bool = db(&h)
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM session_bindings WHERE instance_name=?1)",
            [name],
            |row| row.get(0),
        )
        .unwrap();
    let mut second = PrivateCommand::resume(&h, "second", name);
    let c2 = wait_for_tool(&h, &out, &mut second, Some(c1.pid));
    let binding = bind_second(&h, name, &sid, &out, c2.as_ref());
    let second_cli_alive = second.child.try_wait().unwrap().is_none();
    let second_result = cleanup_launch(&mut second);
    drop(second);
    drop(first);
    drop(h);
    drop(workspace);
    assert!(
        first_was_live,
        "first real resume did not pin a live wrapper above OMP: {c1:?}"
    );
    assert!(
        no_first_hook && no_hook_after_death && !first_bound,
        "first OMP bound before its hook gate"
    );
    assert!(
        first_exited,
        "owned first wrapper/tool did not exit: {first_result:?}"
    );
    assert_eq!(
        dead_pin,
        Some(pin),
        "pre-hook death removed the PID needed for this regression"
    );
    assert_binding(&binding, c2.as_ref(), name, &sid, &second_result);
    assert!(
        second_cli_alive,
        "C2 was not observed inside its live real CLI launch: {second_result:?}"
    );
    assert_ne!(
        c2.as_ref().unwrap().pid,
        c1.pid,
        "second launch reused the first fixture process"
    );
    assert_eq!(c2.as_ref().unwrap().home, c1.home);
    assert_eq!(c2.as_ref().unwrap().hcom_dir, c1.hcom_dir);
}

// Full-CLI no-steal proof only: a real C1 carrier is visible to the early
// spawn guards (`check_spawn_allowed`'s live-holder refusal, the fresh
// launch-binding guard), so this second resume may be refused before the
// launch-pin verdict is ever reached. Its refusal therefore does not by
// itself prove `OmpLaunchPin::Held` for a matching live pin; that proof is
// the direct core coverage in `instance_binding::tests`:
// `omp_launch_pin_matching_live_receipt_is_held` and
// `prepare_own_omp_reservation_matching_live_pin_is_held_and_leaves_state_untouched`.
// What this case pins is the end-to-end contract through every guard: no
// steal, and no state change.
#[test]
fn a_live_matching_pre_hook_owner_cannot_be_stolen_by_another_resume() {
    let (h, workspace) = fixture();
    let name = "prehooklive";
    let (sid, transcript) = seed_stopped_omp(&h, name);
    let out = install_fake_omp(&h, &sid, &transcript);
    let mut first = PrivateCommand::resume(&h, "first", name);
    let (h, c1, pin) = first_tool(h, name, &out, &mut first);
    let receipt = launch_context(&h, name)["omp_launch_pid"].clone();
    let before = full_state(&h);
    let mut second = PrivateCommand::resume(&h, "second", name);
    let refused = second.finish();
    let after = full_state(&h);
    let c1_live = alive(pin) && live_tool_under(pin, c1.pid);
    let no_hook = !out.join(format!("{}.hook-called", c1.pid)).exists();
    let (_, first_exited) = exit_first_tool(&c1, pin, &mut first);
    drop(second);
    drop(first);
    drop(h);
    drop(workspace);
    assert!(
        receipt.is_object(),
        "real launch did not persist its birth receipt: {receipt}"
    );
    assert_eq!(
        receipt["pid"].as_i64(),
        Some(pin),
        "receipt was not correlated to the actual launch pin: {receipt}"
    );
    assert!(
        receipt["identity"]
            .as_str()
            .is_some_and(|identity| !identity.is_empty()),
        "receipt lost native birth identity: {receipt}"
    );
    assert!(
        refused.code > 0,
        "live matching owner was stolen or the command failed to refuse: {refused:?}"
    );
    assert_eq!(
        after, before,
        "refused resume changed the row, UUID or session bindings: {refused:?}"
    );
    assert!(
        c1_live && no_hook,
        "first pre-hook owner did not stay alive and unbound"
    );
    assert!(first_exited, "owned first wrapper/tool did not exit");
}

struct Sentinel {
    child: Child,
    identity: Option<String>,
    heartbeat: PathBuf,
    signals: PathBuf,
}

impl Sentinel {
    fn spawn(h: &Hcom) -> Self {
        let out = h
            .root_path()
            .join(format!("sentinel-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&out).unwrap();
        let heartbeat = out.join("heartbeat");
        let signals = out.join("signals");
        let script = r#"
: > "$FIXTURE_SIGNALS"
for signal in HUP INT QUIT TERM USR1 USR2 CONT; do
    trap "printf '%s\\n' '$signal' >> \"\$FIXTURE_SIGNALS\"" "$signal"
done
while :; do
    printf x >> "$FIXTURE_HEARTBEAT"
    read -r -t 0.05 || true
done
"#;
        let child = h
            .external_cmd("/bin/bash")
            .args(["-c", script])
            .env_remove("HCOM_PROCESS_ID")
            .env_remove("HCOM_INSTANCE_NAME")
            .env_remove("HCOM_TOOL")
            .env_remove("HCOM_LAUNCHED")
            .env("FIXTURE_HEARTBEAT", &heartbeat)
            .env("FIXTURE_SIGNALS", &signals)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let identity = support::child_identity(&child);
        let sentinel = Self {
            child,
            identity,
            heartbeat,
            signals,
        };
        wait_until(PROCESS_WAIT, || {
            (sentinel.beats() > 0 && sentinel.signals.exists()).then_some(())
        })
        .expect("owned sentinel did not start");
        sentinel
    }

    fn pid(&self) -> i64 {
        i64::from(self.child.id())
    }

    fn beats(&self) -> u64 {
        fs::metadata(&self.heartbeat)
            .map(|stat| stat.len())
            .unwrap_or(0)
    }

    fn observation(&self, before: u64) -> (bool, bool, String) {
        let progressed = wait_until(Duration::from_secs(2), || {
            (self.beats() > before).then_some(())
        })
        .is_some();
        (
            alive(self.pid()),
            progressed,
            fs::read_to_string(&self.signals).unwrap(),
        )
    }
}

impl Drop for Sentinel {
    fn drop(&mut self) {
        support::terminate_owned_child_group(&mut self.child, self.identity.as_deref());
    }
}

#[test]
fn a_reused_live_pid_with_a_mismatched_launch_identity_is_replaceable() {
    let (h, workspace) = fixture();
    let name = "prehookreuse";
    let (sid, transcript) = seed_stopped_omp(&h, name);
    let out = install_fake_omp(&h, &sid, &transcript);
    let mut first = PrivateCommand::resume(&h, "first", name);
    let (h, c1, pin) = first_tool(h, name, &out, &mut first);
    let context = launch_context(&h, name);
    let receipt = context
        .get("omp_launch_pid")
        .filter(|receipt| receipt.is_object())
        .cloned();
    let c1_ticks = start_ticks(pin);
    let (_, first_exited) = exit_first_tool(&c1, pin, &mut first);
    let Some(receipt) = receipt else {
        drop(first);
        drop(h);
        drop(workspace);
        panic!("real C1 launch did not persist omp_launch_pid: {context}");
    };
    // A new unrelated process must also have a different kernel birth tick;
    // retry a same-tick spawn rather than parse or manufacture the receipt.
    let sentinel = wait_until(PROCESS_WAIT, || {
        let candidate = Sentinel::spawn(&h);
        (start_ticks(candidate.pid()) != c1_ticks).then_some(candidate)
    })
    .expect("could not create an unrelated process born after C1");
    // Explicit PID-reuse boundary: preserve every production-owned receipt
    // field, including row/binding epochs and C1's opaque birth identity.
    db(&h).execute(
        "UPDATE instances SET pid=?2, launch_context=json_set(launch_context,'$.omp_launch_pid.pid',?2) WHERE name=?1",
        rusqlite::params![name,sentinel.pid()],
    ).unwrap();
    let reused = launch_context(&h, name)["omp_launch_pid"].clone();
    let beats = sentinel.beats();
    let mut second = PrivateCommand::resume(&h, "second", name);
    let c2 = wait_for_tool(&h, &out, &mut second, Some(c1.pid));
    let binding = bind_second(&h, name, &sid, &out, c2.as_ref());
    let second_cli_alive = second.child.try_wait().unwrap().is_none();
    let untouched = sentinel.observation(beats);
    let second_result = cleanup_launch(&mut second);
    let sentinel_pid = sentinel.pid();
    drop(second);
    drop(first);
    drop(sentinel);
    drop(h);
    drop(workspace);
    assert!(first_exited, "owned first wrapper/tool did not exit");
    assert_eq!(
        receipt["pid"].as_i64(),
        Some(pin),
        "did not capture C1's genuine receipt: {receipt}"
    );
    assert!(
        receipt["identity"]
            .as_str()
            .is_some_and(|identity| !identity.is_empty()),
        "missing C1 native identity: {receipt}"
    );
    assert!(
        c1_ticks.is_some(),
        "could not read C1's owned kernel birth tick"
    );
    let mut expected = receipt;
    expected["pid"] = json!(sentinel_pid);
    assert_eq!(
        reused, expected,
        "PID-reuse fixture changed more than the correlated PID"
    );
    assert_binding(&binding, c2.as_ref(), name, &sid, &second_result);
    assert!(
        second_cli_alive,
        "C2 was not observed inside its live real CLI launch: {second_result:?}"
    );
    assert_eq!(
        untouched,
        (true, true, String::new()),
        "PID reuse signaled, killed or left the unrelated process stopped"
    );
}

#[test]
fn stop_clears_a_live_unverifiable_pre_hook_reservation_without_signaling_then_resume_binds() {
    let (h, workspace) = fixture();
    let name = "prehookstop";
    let (sid, transcript) = seed_stopped_omp(&h, name);
    let out = install_fake_omp(&h, &sid, &transcript);
    let mut first = PrivateCommand::resume(&h, "first", name);
    let (h, c1, pin) = first_tool(h, name, &out, &mut first);
    let (_, first_exited) = exit_first_tool(&c1, pin, &mut first);
    let sentinel = Sentinel::spawn(&h);
    // An older whole-context rewrite drops the unknown receipt. A live PID
    // without it is legacy/unverifiable, never a matching or mismatched birth.
    db(&h).execute(
        "UPDATE instances SET pid=?2, launch_context=json_remove(launch_context,'$.omp_launch_pid') WHERE name=?1",
        rusqlite::params![name,sentinel.pid()],
    ).unwrap();
    // Age this launch's private (NULL-session) process binding far past the
    // placeholder window, before the baseline snapshot. Inside that window
    // the fresh-binding guard refuses a second resume with its own error
    // before the Held bail can surface; this receipt-less legacy pin has no
    // correlated receipt epoch to keep in step, and the sentinel carries no
    // hcom env for `check_spawn_allowed` to refuse on, so the refusal below
    // can only be the launch-pin Held verdict asserted on its stderr.
    let aged_bindings = db(&h).execute(
        "UPDATE process_bindings SET updated_at = updated_at - 3600.0 WHERE instance_name=?1 AND session_id IS NULL",
        rusqlite::params![name],
    ).unwrap();
    let reservation: (String,String,String,i64) = db(&h).query_row(
        "SELECT status,status_context,session_id,(SELECT COUNT(*) FROM session_bindings WHERE instance_name=?1) FROM instances WHERE name=?1",
        [name], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).unwrap();
    let missing = launch_context(&h, name).get("omp_launch_pid").is_none();
    let before = full_state(&h);
    let beats = sentinel.beats();
    let mut held = PrivateCommand::resume(&h, "held", name);
    let refused = held.finish();
    let after = full_state(&h);
    let held_untouched = sentinel.observation(beats);
    let beats = sentinel.beats();
    let mut stop = PrivateCommand::start(&h, "stop", &["stop", name]);
    let stopped = stop.finish();
    let cleared: (i64, i64, i64, i64) = db(&h)
        .query_row(
            "SELECT (SELECT COUNT(*) FROM instances WHERE name=?1),
                (SELECT COUNT(*) FROM process_bindings WHERE instance_name=?1),
                (SELECT COUNT(*) FROM session_bindings WHERE instance_name=?1),
                (SELECT COUNT(*) FROM notify_endpoints WHERE instance=?1)",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let stop_untouched = sentinel.observation(beats);
    let mut second = PrivateCommand::resume(&h, "second", name);
    let c2 = wait_for_tool(&h, &out, &mut second, Some(c1.pid));
    let binding = bind_second(&h, name, &sid, &out, c2.as_ref());
    let second_cli_alive = second.child.try_wait().unwrap().is_none();
    let final_untouched = sentinel.observation(sentinel.beats());
    let second_result = cleanup_launch(&mut second);
    drop(second);
    drop(stop);
    drop(held);
    drop(first);
    drop(sentinel);
    drop(h);
    drop(workspace);
    assert!(first_exited, "owned first wrapper/tool did not exit");
    assert_eq!(
        reservation,
        ("inactive".into(), "new".into(), sid.clone(), 0),
        "fixture was not an unbound pre-hook reservation"
    );
    assert!(missing, "fixture did not drop its launch receipt");
    assert!(
        refused.code > 0,
        "missing receipt authorized another resume or failed to refuse: {refused:?}"
    );
    assert!(
        aged_bindings >= 1,
        "fixture aged no private NULL-session launch binding"
    );
    assert!(
        refused.stderr.contains("unhooked OMP launch reservation")
            && refused
                .stderr
                .contains("is live and has no verifiable launch receipt"),
        "aged receipt-less resume was refused by an earlier guard, not the launch-pin Held verdict: {refused:?}"
    );
    assert_eq!(
        after, before,
        "held legacy resume changed state: {refused:?}"
    );
    assert_eq!(
        held_untouched,
        (true, true, String::new()),
        "held resume disturbed the unverifiable PID"
    );
    assert_eq!(
        stopped.code, 0,
        "bookkeeping-only stop refused: {stopped:?}"
    );
    let output = format!("{}{}", stopped.stdout, stopped.stderr)
        .to_ascii_lowercase()
        .replace("signalled", "signaled");
    assert!(
        output.contains("no process signaled") || output.contains("no process was signaled"),
        "stop did not explicitly report that no process was signaled: {stopped:?}"
    );
    assert_eq!(
        cleared,
        (0, 0, 0, 0),
        "stop retained reservation bookkeeping"
    );
    assert_eq!(
        stop_untouched,
        (true, true, String::new()),
        "bookkeeping-only stop disturbed the unrelated PID"
    );
    assert_binding(&binding, c2.as_ref(), name, &sid, &second_result);
    assert!(
        second_cli_alive,
        "C2 was not observed inside its live real CLI launch: {second_result:?}"
    );
    assert_eq!(
        final_untouched,
        (true, true, String::new()),
        "post-stop resume disturbed the unrelated PID"
    );
}
