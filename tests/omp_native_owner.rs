//! Native argv discovery and OMP ownership through the real isolated hcom CLI.
//!
//! Node and Bun run an exact supported OMP script without a seat process title:
//! native argv must identify them. Bun workers also exercise its real title
//! rewrite, which may erase argv and leave only the reserved kernel comm.
//! No model application, provider, live service, or physical Mac is involved.

#![cfg(any(windows, target_os = "macos"))]

mod support;

use std::cell::Cell;
use std::fs;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use support::omp_owner::{db, full_state, isolated_hcom};
use support::{Hcom, unique_suffix};

// Nested invocations use the same script path and actual runtime executable.
// Node remains untitled. Bun worker mode performs OMP's source-pinned rename.
const NODE_RUNNER: &str = r#"
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// These bounds apply only to failure context, never to the executed command.
function boundedText(value, limit = 512) {
    const text = String(value);
    return { value: text.slice(0, limit), truncated: text.length > limit };
}

function boundedArgs(values, limit) {
    return {
        values: values.slice(0, limit).map(value => boundedText(value)),
        truncated: values.length > limit,
    };
}

const beforeRewrite = {
    exec_path: boundedText(process.execPath, 1024),
    argv: boundedArgs(process.argv, 8),
    title: boundedText(process.title, 128),
};

if (process.versions.bun && process.argv[2] === '__omp_worker_daemon_broker') {
    process.title = 'omp daemon broker';
}
const hopFacts = {
    pid: process.pid, ppid: process.ppid,
    before_rewrite: beforeRewrite,
    after_rewrite: {
        exec_path: boundedText(process.execPath, 1024),
        argv: boundedArgs(process.argv, 8),
        title: boundedText(process.title, 128),
    },
};

function execute(step) {
    const diagnostics = {
        runtime: boundedText(step.fixture.runtime, 32),
        script_mode: boundedText(step.fixture.script_mode, 32),
        resolved_exec: boundedText(step.fixture.resolved_exec, 1024),
        launcher_shim: boundedText(step.fixture.launcher_shim || '', 64),
        step: step.step,
        route_original: boundedArgs(step.route, 4),
        args: boundedArgs(step.args, 16),
        hops: [{ ...hopFacts, route_remaining: boundedArgs(step.via || [], 4) }],
        hops_truncated: false,
    };
    if (step.via && step.via.length) {
        const [mode, ...rest] = step.via;
        const selectors = mode === 'worker' ? ['__omp_worker_daemon_broker'] : [];
        const child = spawnSync(process.execPath, [__filename, ...selectors], {
            env: { ...process.env, TEST_OWNER_ONESHOT: JSON.stringify({ ...step, via: rest }) },
            encoding: 'utf8', timeout: 20000, windowsHide: true,
        });
        try {
            if (child.error || child.status !== 0) {
                throw new Error(`nested runtime fixture failed: ${child.error || `exit ${child.status}, signal ${child.signal}`}`);
            }
            const output = JSON.parse(child.stdout);
            const hops = [diagnostics.hops[0], ...output.diagnostics.hops];
            output.diagnostics.hops = hops.slice(0, 4);
            output.diagnostics.hops_truncated ||= hops.length > 4;
            return output;
        } catch (error) {
            diagnostics.fixture_error = boundedText(error.message, 2048);
            return { code: -1, stdout: child.stdout || '', stderr: child.stderr || '',
                     caller_pid: process.pid, diagnostics };
        }
    }
    const env = { ...process.env, HCOM_LAUNCHED: '1', HCOM_TOOL: 'omp', ...step.env };
    if (step.own_id) {
        env.HCOM_PROCESS_ID = `omp-${process.pid}-native-fixture`;
        delete env.HCOM_INSTANCE_NAME;
    }
    diagnostics.submitted_env = {
        HCOM_PROCESS_ID: boundedText(env.HCOM_PROCESS_ID || '', 128),
        HCOM_TOOL: boundedText(env.HCOM_TOOL, 32),
        HCOM_LAUNCHED: boundedText(env.HCOM_LAUNCHED, 32),
        instance_name_present: Object.prototype.hasOwnProperty.call(env, 'HCOM_INSTANCE_NAME'),
    };
    const result = spawnSync(process.env.TEST_HCOM_BIN, step.args, {
        env, encoding: 'utf8', timeout: 15000, windowsHide: true,
    });
    if (result.error || result.status === null) {
        diagnostics.fixture_error = boundedText(
            result.error ? result.error.message : `hook terminated by signal ${result.signal}`, 2048);
    }
    return { code: result.status === null ? -1 : result.status,
             stdout: result.stdout || '', stderr: result.stderr || '',
             caller_pid: process.pid, diagnostics };
}

if (process.env.TEST_OWNER_ONESHOT) {
    process.stdout.write(JSON.stringify(execute(JSON.parse(process.env.TEST_OWNER_ONESHOT))));
} else {
    const dir = process.env.TEST_OWNER_DIR;
    if (!process.env.HCOM_PROCESS_ID) {
        process.env.HCOM_PROCESS_ID = `omp-${process.pid}-native-fixture`;
    }
    fs.writeFileSync(path.join(dir, 'ready'), JSON.stringify({
        pid: process.pid, process_id: process.env.HCOM_PROCESS_ID,
    }));
    const timer = setInterval(() => {
        if (fs.existsSync(path.join(dir, 'stop'))) {
            clearInterval(timer);
            return;
        }
        for (const entry of fs.readdirSync(dir)) {
            if (!/^step-\d+\.json$/.test(entry)) continue;
            const output = path.join(dir, `${entry}.out`);
            if (fs.existsSync(output)) continue;
            const step = JSON.parse(fs.readFileSync(path.join(dir, entry), 'utf8'));
            const result = execute(step);
            fs.writeFileSync(`${output}.tmp`, JSON.stringify(result));
            fs.renameSync(`${output}.tmp`, output);
        }
    }, 15);
}
"#;

#[derive(Deserialize)]
struct HookOutput {
    code: i32,
    stdout: String,
    stderr: String,
    caller_pid: u32,
    diagnostics: Value,
}

impl HookOutput {
    fn json(&self) -> Value {
        assert!(
            self.diagnostics.get("fixture_error").is_none(),
            "native fixture failed: {} {} diagnostics={}",
            self.stdout,
            self.stderr,
            self.diagnostics
        );
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "hook JSON: {error}; stdout={} stderr={} diagnostics={}",
                self.stdout, self.stderr, self.diagnostics
            )
        })
    }

    fn ok(&self) -> Value {
        assert_eq!(
            self.code, 0,
            "{} {} diagnostics={}",
            self.stdout, self.stderr, self.diagnostics
        );
        let body = self.json();
        assert!(
            body.get("error").is_none(),
            "{body}: {} diagnostics={}",
            self.stderr,
            self.diagnostics
        );
        body
    }

    fn refused(&self) {
        assert_eq!(
            self.code, 0,
            "{} {} diagnostics={}",
            self.stdout, self.stderr, self.diagnostics
        );
        let body = self.json();
        assert!(
            body.get("error").is_some(),
            "hook was admitted: {body}; diagnostics={}",
            self.diagnostics
        );
        assert!(
            body.get("name").is_none(),
            "refusal bound a name: {body}; diagnostics={}",
            self.diagnostics
        );
    }

    fn cli_refused(&self) {
        assert!(
            self.diagnostics.get("fixture_error").is_none(),
            "native fixture failed: {} {} diagnostics={}",
            self.stdout,
            self.stderr,
            self.diagnostics
        );
        assert_ne!(
            self.code, 0,
            "CLI was admitted: {} {} diagnostics={}",
            self.stdout, self.stderr, self.diagnostics
        );
    }
}

struct NativeOwner {
    child: Child,
    dir: PathBuf,
    pid: u32,
    process_id: String,
    step: Cell<usize>,
    fixture: Value,
}

impl NativeOwner {
    fn spawn(h: &Hcom, runtime: &str, script_basename: bool, shim_name: Option<&str>) -> Self {
        let fixture = h.root_path().join("native owner ü fixture");
        let script = if script_basename {
            fixture.join("bin/omp")
        } else {
            fixture.join("node_modules/@oh-my-pi/pi-coding-agent/dist/cli.js")
        };
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::write(&script, NODE_RUNNER).unwrap();
        let dir = fixture.join("steps");
        fs::create_dir_all(&dir).unwrap();
        // npm's Windows Bun entrypoint may itself be a .cmd shim. Ask the
        // isolated runtime for its real executable, then launch that directly.
        let resolved = h
            .external_cmd(runtime)
            .args(["--print", "process.execPath"])
            .output()
            .unwrap_or_else(|error| panic!("{runtime} is required; CI installs it: {error}"));
        assert!(
            resolved.status.success(),
            "{runtime} executable resolution failed: {}",
            String::from_utf8_lossy(&resolved.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(resolved.stdout).unwrap().trim());
        assert!(
            executable.is_absolute() && executable.is_file(),
            "invalid runtime path: {executable:?}"
        );
        let mut command = if let Some(shim_name) = shim_name {
            let shim = fixture.join(shim_name);
            fs::write(
                &shim,
                "@echo off\r\n\"%TEST_OWNER_RUNTIME%\" \"%TEST_OWNER_SCRIPT%\"\r\n",
            )
            .unwrap();
            let mut command = h.external_cmd("cmd.exe");
            command.args(["/d", "/c"]).arg(&shim);
            command
        } else {
            let mut command = h.external_cmd(&executable);
            command.arg(&script);
            command
        };
        let process_id = uuid::Uuid::new_v4().to_string();
        command
            .env("TEST_OWNER_RUNTIME", &executable)
            .env("TEST_OWNER_SCRIPT", &script)
            .env("HCOM_PROCESS_ID", &process_id)
            .env("TEST_OWNER_DIR", &dir)
            .env("TEST_HCOM_BIN", env!("CARGO_BIN_EXE_hcom"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        command.process_group(0);
        let child = command
            .spawn()
            .expect("spawn native interpreted OMP fixture");
        h.track_cleanup_pid(i64::from(child.id()));
        let ready: Value = h.eventually(
            "native interpreter owner ready",
            Duration::from_secs(30),
            || {
                Ok(fs::read_to_string(dir.join("ready"))
                    .ok()
                    .and_then(|text| serde_json::from_str(&text).ok()))
            },
        );
        assert_eq!(ready["process_id"], process_id);
        let pid = u32::try_from(ready["pid"].as_u64().unwrap()).unwrap();
        if shim_name.is_some() {
            assert_ne!(
                pid,
                child.id(),
                "cmd fixture must retain a distinct shim PID"
            );
        } else {
            assert_eq!(pid, child.id(), "fixture must be the actual Node process");
        }
        Self {
            child,
            dir,
            pid,
            process_id,
            step: Cell::new(0),
            fixture: json!({
                "runtime": runtime,
                "script_mode": if script_basename { "bin/omp" } else { "package/cli.js" },
                "resolved_exec": executable,
                "launcher_shim": shim_name,
            }),
        }
    }

    fn request(
        &self,
        h: &Hcom,
        args: &[&str],
        via: &[&str],
        name: Option<&str>,
        own_id: bool,
    ) -> HookOutput {
        let step = self.step.get();
        self.step.set(step + 1);
        let request = json!({
            "fixture": self.fixture,
            "step": step,
            "route": via,
            "args": args,
            "via": via,
            "own_id": own_id,
            "env": name.map(|name| json!({"HCOM_INSTANCE_NAME": name})).unwrap_or_else(|| json!({})),
        });
        let input = self.dir.join(format!("step-{step}.json"));
        fs::write(input.with_extension("tmp"), request.to_string()).unwrap();
        fs::rename(input.with_extension("tmp"), &input).unwrap();
        h.eventually(
            "native owner hook finished",
            Duration::from_secs(30),
            || {
                Ok(
                    fs::read_to_string(self.dir.join(format!("step-{step}.json.out")))
                        .ok()
                        .and_then(|text| serde_json::from_str(&text).ok()),
                )
            },
        )
    }

    fn run(&self, h: &Hcom, args: &[&str], name: &str) -> HookOutput {
        self.request(h, args, &[], Some(name), false)
    }

    fn assert_alive(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "native owner exited: next_step={}",
            self.step.get()
        );
    }
}

impl Drop for NativeOwner {
    fn drop(&mut self) {
        let _ = fs::write(self.dir.join("stop"), "");
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(15));
        }
        if self.child.try_wait().ok().flatten().is_none() {
            #[cfg(unix)]
            unsafe {
                libc::killpg(self.child.id() as libc::pid_t, libc::SIGKILL);
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn seed_row(
    h: &Hcom,
    owner: &NativeOwner,
    name: &str,
    sid: Option<&str>,
    anchor: u32,
    bound: bool,
) {
    let conn = db(h);
    let path = transcript(h, sid.unwrap_or("fresh-session"));
    conn.execute(
        "INSERT INTO instances (name,tool,session_id,pid,status,status_context,created_at,directory,transcript_path,last_event_id,name_announced)
         VALUES (?1,'omp',?2,?3,?4,?5,1234.5,?6,?7,0,?8)",
        rusqlite::params![name, sid, anchor, if bound { "listening" } else { "pending" },
            if bound { "start" } else { "new" }, h.workspace.to_string_lossy(),
            if bound { path.to_string_lossy().into_owned() } else { String::new() }, i64::from(bound)],
    ).unwrap();
    conn.execute(
        "INSERT INTO process_bindings (process_id,session_id,instance_name,updated_at) VALUES (?1,?2,?3,1234.5)",
        rusqlite::params![owner.process_id, if bound { sid } else { None }, name],
    ).unwrap();
    if let Some(sid) = sid.filter(|_| bound) {
        conn.execute(
            "INSERT INTO session_bindings (session_id,instance_name,created_at) VALUES (?1,?2,1234.5)",
            rusqlite::params![sid, name],
        ).unwrap();
    }
}

fn seed_message(h: &Hcom, name: &str) -> i64 {
    let conn = db(h);
    conn.execute(
        "INSERT INTO events (timestamp,type,instance,data) VALUES ('2026-10-01T01:02:03+00:00','message','native-fixture',?1)",
        [json!({"from":"native-fixture","text":"native owner unread sentinel","intent":"inform","scope":"mentions","mentions":[name],"delivered_to":[name]}).to_string()],
    ).unwrap();
    conn.last_insert_rowid()
}

fn transcript(h: &Hcom, sid: &str) -> PathBuf {
    h.workspace.join(format!("{sid}.jsonl"))
}

fn start_args<'a>(sid: &'a str, path: &'a str, cwd: &'a str) -> [&'a str; 7] {
    [
        "omp-start",
        "--session-id",
        sid,
        "--transcript-path",
        path,
        "--cwd",
        cwd,
    ]
}

fn assert_bound(h: &Hcom, owner: &NativeOwner, name: &str, sid: &str, path: &Path) {
    let conn = db(h);
    let row: (String, i64, String, String, f64) = conn.query_row(
        "SELECT session_id,pid,transcript_path,directory,created_at FROM instances WHERE name=?1", [name],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).unwrap();
    assert_eq!(
        row,
        (
            sid.into(),
            i64::from(owner.pid),
            path.to_string_lossy().into_owned(),
            h.workspace.to_string_lossy().into_owned(),
            1234.5
        )
    );
    let bindings: (String, String) = conn.query_row(
        "SELECT p.instance_name,s.instance_name FROM process_bindings p JOIN session_bindings s ON s.session_id=p.session_id WHERE p.process_id=?1 AND p.session_id=?2",
        rusqlite::params![owner.process_id, sid], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(bindings, (name.into(), name.into()));
}

#[test]
fn interpreted_legacy_owner_can_first_read_stop_and_start_without_a_receipt() {
    for (runtime, script_basename) in ["node", "bun"]
        .into_iter()
        .flat_map(|runtime| [false, true].map(|script_basename| (runtime, script_basename)))
    {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let name = format!("native{suffix}");
        let sid = format!("sid-native-{suffix}");
        let mut owner = NativeOwner::spawn(&h, runtime, script_basename, None);
        seed_row(&h, &owner, &name, Some(&sid), owner.pid, true);
        let unread = seed_message(&h, &name);
        let before = full_state(&h);
        let first = owner.run(&h, &["omp-read", "--name", &name, "--check"], &name);
        assert_eq!(
            (first.code, first.stdout.trim()),
            (0, "true"),
            "{}",
            first.stderr
        );
        assert_eq!(
            full_state(&h),
            before,
            "first read required a new ownership receipt"
        );
        let mail = owner.run(&h, &["omp-read", "--name", &name], &name).ok();
        assert_eq!(mail[0]["event_id"], unread);
        assert_eq!(mail[0]["message"], "native owner unread sentinel");
        owner
            .run(
                &h,
                &[
                    "omp-read",
                    "--name",
                    &name,
                    "--ack",
                    "--up-to",
                    &unread.to_string(),
                ],
                &name,
            )
            .ok();
        owner
            .run(
                &h,
                &["omp-stop", "--name", &name, "--soft", "--reason", "restart"],
                &name,
            )
            .ok();
        let path = transcript(&h, &sid);
        let start = start_args(&sid, path.to_str().unwrap(), h.workspace.to_str().unwrap());
        assert_eq!(owner.run(&h, &start, &name).ok()["name"], name);
        assert_bound(&h, &owner, &name, &sid, &path);
        let conn = db(&h);
        let endpoint = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        conn.execute(
            "INSERT INTO notify_endpoints (instance,kind,port,updated_at) VALUES (?1,'plugin',?2,1234.5)",
            rusqlite::params![name, endpoint.local_addr().unwrap().port()],
        ).unwrap();
        let identity = || -> (String, i64, String, f64, String, String, i64) {
            conn.query_row(
                "SELECT name,pid,session_id,created_at,transcript_path,directory,last_event_id FROM instances WHERE name=?1",
                [&name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            ).unwrap()
        };
        let status = || -> (String, String) {
            conn.query_row(
                "SELECT status,status_context FROM instances WHERE name=?1",
                [&name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
        };
        let stopped_events = || -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM events WHERE type='life' AND instance=?1 AND json_extract(data,'$.action')='stopped'",
                [&name],
                |row| row.get(0),
            ).unwrap()
        };
        let before_identity = identity();
        assert_eq!(before_identity.6, unread, "acknowledged cursor was lost");
        assert_eq!(status(), ("listening".into(), "start".into()));
        let stopped_before = stopped_events();
        let before_hard = full_state(&h);
        let hard_stop = owner.run(
            &h,
            &["omp-stop", "--name", &name, "--reason", "shutdown"],
            &name,
        );
        hard_stop.ok();

        // 0291a7b deliberately keeps an own off-Linux release as a soft stop:
        // preserve the live owner's resume handle, not Linux's full deletion.
        assert_eq!(
            identity(),
            before_identity,
            "native soft fallback changed row identity/cursor: {}",
            hard_stop.diagnostics
        );
        assert_eq!(
            status(),
            ("inactive".into(), "exit:shutdown".into()),
            "native hard stop did not soft-stop the row: {}",
            hard_stop.diagnostics
        );
        let bound_name: Option<String> = conn
            .query_row(
                "SELECT instance_name FROM process_bindings WHERE process_id=?1",
                [&owner.process_id],
                |row| row.get(0),
            )
            .unwrap();
        // The resume authority is the UUID/name binding; don't pin its SID
        // or update timestamp as part of the retained-binding contract.
        assert_eq!(bound_name.as_deref(), Some(name.as_str()));
        let cleared: (i64, i64) = conn
            .query_row(
                "SELECT
                (SELECT COUNT(*) FROM session_bindings WHERE instance_name=?1),
                (SELECT COUNT(*) FROM notify_endpoints WHERE instance=?1)",
                [&name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(cleared, (0, 0), "soft fallback left live delivery bindings");
        assert_eq!(
            stopped_events(),
            stopped_before + 1,
            "hard self-stop must add exactly one stopped event: {}",
            hard_stop.diagnostics
        );
        let stopped_data: String = conn.query_row(
            "SELECT data FROM events WHERE type='life' AND instance=?1 AND json_extract(data,'$.action')='stopped' ORDER BY id DESC LIMIT 1",
            [&name],
            |row| row.get(0),
        ).unwrap();
        let stopped: Value = serde_json::from_str(&stopped_data).unwrap();
        assert_eq!(stopped["reason"], "exit:shutdown");
        assert_eq!(stopped["by"], "session");
        assert_eq!(stopped.get("process_id"), Some(&Value::Null));
        assert_eq!(stopped["snapshot"]["name"], name);
        assert_eq!(stopped["snapshot"]["created_at"], before_identity.3);
        assert_eq!(stopped["snapshot"]["last_event_id"], before_identity.6);
        let after_hard = full_state(&h);
        assert!(
            after_hard["events"].starts_with(&before_hard["events"]),
            "soft fallback rewrote existing event history: {}",
            hard_stop.diagnostics
        );
        owner.assert_alive();

        // 0291a7b also makes the already-inactive hard self-stop a no-op.
        let repeat = owner.run(
            &h,
            &["omp-stop", "--name", &name, "--reason", "shutdown"],
            &name,
        );
        repeat.ok();
        assert_eq!(
            full_state(&h),
            after_hard,
            "inactive self-stop changed full state: {}",
            repeat.diagnostics
        );
        owner.assert_alive();

        let reclaim = owner.request(&h, &["start", "--as", &name], &["seat"], Some(&name), false);
        reclaim.cli_refused();
        assert_ne!(
            reclaim.caller_pid, owner.pid,
            "reclaim must run in the real child seat"
        );
        assert_eq!(
            full_state(&h),
            after_hard,
            "child reclaimed the stopped owner's UUID or added a claim: {}",
            reclaim.diagnostics
        );
        owner.assert_alive();

        let resumed_sid = format!("sid-resumed-{suffix}");
        let resumed_path = transcript(&h, &resumed_sid);
        let resumed_start = start_args(
            &resumed_sid,
            resumed_path.to_str().unwrap(),
            h.workspace.to_str().unwrap(),
        );
        let resumed = owner.run(&h, &resumed_start, &name);
        assert_eq!(resumed.ok()["name"], name);
        assert_bound(&h, &owner, &name, &resumed_sid, &resumed_path);
        assert_eq!(
            status(),
            ("listening".into(), "start".into()),
            "same native owner did not resume listening: {}",
            resumed.diagnostics
        );
        assert_eq!(
            identity().6,
            before_identity.6,
            "same-owner resume reset the old cursor: {}",
            resumed.diagnostics
        );
        owner.assert_alive();
    }
}

#[test]
#[cfg(windows)]
fn windows_cmd_shim_legacy_fresh_and_preset_resume_pin_the_actual_interpreter() {
    for (runtime, shape) in ["node", "bun"]
        .into_iter()
        .flat_map(|runtime| ["legacy", "fresh", "preset-resume"].map(|shape| (runtime, shape)))
    {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let name = format!("shim{suffix}");
        let sid = format!("sid-shim-{suffix}");
        let shim_name = if shape == "preset-resume" {
            "omp.bat"
        } else {
            "omp.cmd"
        };
        let mut owner = NativeOwner::spawn(&h, runtime, false, Some(shim_name));
        let bound = shape == "legacy";
        let preset_sid = (shape != "fresh").then_some(sid.as_str());
        seed_row(&h, &owner, &name, preset_sid, owner.child.id(), bound);
        if bound {
            let unread = seed_message(&h, &name);
            let before = full_state(&h);
            let first = owner.run(&h, &["omp-read", "--name", &name, "--check"], &name);
            assert_eq!(
                (first.code, first.stdout.trim()),
                (0, "true"),
                "{}",
                first.stderr
            );
            assert_eq!(
                full_state(&h),
                before,
                "shim legacy first read required a receipt"
            );
            assert_eq!(
                owner.run(&h, &["omp-read", "--name", &name], &name).ok()[0]["event_id"],
                unread
            );
            owner
                .run(
                    &h,
                    &["omp-stop", "--name", &name, "--soft", "--reason", "restart"],
                    &name,
                )
                .ok();
        }
        let path = transcript(&h, &sid);
        let start = start_args(&sid, path.to_str().unwrap(), h.workspace.to_str().unwrap());
        assert_eq!(
            owner.run(&h, &start, &name).ok()["name"],
            name,
            "shape={shape}"
        );
        assert_bound(&h, &owner, &name, &sid, &path);
        let before = full_state(&h);
        let child = owner.request(
            &h,
            &["omp-stop", "--name", &name],
            &["seat"],
            Some(&name),
            false,
        );
        assert_eq!(
            full_state(&h),
            before,
            "nested actual seat borrowed shim identity"
        );
        child.refused();
        owner.assert_alive();
    }
}

#[test]
fn descendant_and_shared_worker_cannot_borrow_an_older_native_omp_owner() {
    for runtime in ["node", "bun"] {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let name = format!("guard{suffix}");
        let sid = format!("sid-guard-{suffix}");
        let mut owner = NativeOwner::spawn(&h, runtime, false, None);
        seed_row(&h, &owner, &name, Some(&sid), owner.pid, true);
        let unread = seed_message(&h, &name);
        let next_sid = format!("sid-child-{suffix}");
        let path = transcript(&h, &next_sid);
        // Preserve the issue's poisoned current metadata, absent incoming
        // binding, and a restorable different name. A trusted inherited UUID
        // must not reach the repair/adoption path and replace the live seat.
        let wrong_sid = format!("sid-poison-{suffix}");
        let previous_name = format!("previous{suffix}");
        let missing = h.root_path().join("missing-project");
        let conn = db(&h);
        conn.execute(
            "UPDATE instances SET session_id=?2,directory=?3,transcript_path=?4,status='active',name_announced=0 WHERE name=?1",
            rusqlite::params![name, wrong_sid, missing.to_string_lossy(), missing.join("lost.jsonl").to_string_lossy()],
        ).unwrap();
        conn.execute(
            "DELETE FROM session_bindings WHERE instance_name=?1",
            [&name],
        )
        .unwrap();
        conn.execute(
            "UPDATE process_bindings SET session_id=?2 WHERE process_id=?1",
            rusqlite::params![owner.process_id, wrong_sid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events (timestamp,type,instance,data) VALUES ('2026-09-01T00:00:00+00:00','life',?1,?2)",
            rusqlite::params![previous_name, json!({
                "action":"stopped","by":"session","reason":"exit:shutdown",
                "process_id":uuid::Uuid::new_v4().to_string(),
                "snapshot":{"name":previous_name,"session_id":next_sid,"tool":"omp",
                    "directory":h.workspace,"transcript_path":path,"created_at":1000.0,
                    "last_event_id":0,"name_announced":1}
            }).to_string()],
        ).unwrap();
        drop(conn);
        let up_to = unread.to_string();
        let mut commands = vec![
            start_args(
                &next_sid,
                path.to_str().unwrap(),
                h.workspace.to_str().unwrap(),
            )
            .to_vec(),
        ];
        commands.extend([
            vec![
                "omp-status",
                "--name",
                &name,
                "--status",
                "active",
                "--context",
                "borrowed",
            ],
            vec!["omp-read", "--name", &name],
            vec!["omp-read", "--name", &name, "--check"],
            vec!["omp-read", "--name", &name, "--format"],
            vec!["omp-read", "--name", &name, "--ack", "--up-to", &up_to],
            vec![
                "omp-beforetool",
                "--name",
                &name,
                "--tool",
                "bash",
                "--input-json",
                "{\"command\":\"pwd\"}",
            ],
            vec![
                "omp-role",
                "--name",
                &name,
                "--session-id",
                &wrong_sid,
                "--role",
                "conductor",
            ],
            vec![
                "omp-stop", "--name", &name, "--soft", "--reason", "borrowed",
            ],
            vec!["omp-stop", "--name", &name, "--reason", "borrowed"],
        ]);
        for via in [&["seat"][..], &["worker"][..], &["worker", "seat"][..]] {
            for args in &commands {
                let before = full_state(&h);
                let result = owner.request(&h, args, via, Some(&name), false);
                assert_eq!(
                    full_state(&h),
                    before,
                    "native descendant/worker mutated full snapshot: runtime={runtime}, via={via:?}, args={args:?}; {} {}",
                    result.stdout,
                    result.stderr
                );
                result.refused();
                owner.assert_alive();
            }
            let before = full_state(&h);
            let explicit = owner.request(&h, &["start", "--as", &name], via, Some(&name), false);
            assert_eq!(
                full_state(&h),
                before,
                "native descendant reclaimed explicit --as owner"
            );
            explicit.cli_refused();
        }
        // A real new seat below that worker can use its own minted PID, without
        // authenticating the older owner's UUID or crossing the worker barrier.
        let own_sid = format!("sid-own-child-{suffix}");
        let own_path = transcript(&h, &own_sid);
        let own = owner.request(
            &h,
            &start_args(
                &own_sid,
                own_path.to_str().unwrap(),
                h.workspace.to_str().unwrap(),
            ),
            &["worker", "seat"],
            None,
            true,
        );
        let child_name = own.ok()["name"].as_str().unwrap().to_string();
        assert_ne!(child_name, name);
        let child_pid: u32 = db(&h)
            .query_row(
                "SELECT pid FROM instances WHERE name=?1",
                [&child_name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            child_pid, own.caller_pid,
            "new seat below worker did not pin its own actual runtime PID"
        );
        let own_id = format!("omp-{}-native-fixture", own.caller_pid);
        let own_bindings: (Option<String>, Option<String>, Option<String>) = db(&h)
            .query_row(
                "SELECT
                    (SELECT session_id FROM process_bindings WHERE process_id = ?1),
                    (SELECT instance_name FROM process_bindings WHERE process_id = ?1),
                    (SELECT instance_name FROM session_bindings WHERE session_id = ?2)",
                rusqlite::params![own_id, own_sid],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            own_bindings,
            (Some(own_sid), Some(child_name.clone()), Some(child_name)),
            "new seat below worker did not bind its own session and process"
        );
        assert_eq!(
            owner
                .run(&h, &["omp-read", "--name", &name, "--check"], &name)
                .stdout
                .trim(),
            "true"
        );
    }
}

#[test]
#[cfg(windows)]
fn arbitrary_already_bound_cmd_wrapper_is_not_a_native_omp_shim() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("ambiguous{suffix}");
    let sid = format!("sid-ambiguous-{suffix}");
    let owner = NativeOwner::spawn(&h, "node", false, Some("other.cmd"));
    seed_row(&h, &owner, &name, Some(&sid), owner.child.id(), true);
    seed_message(&h, &name);
    let before = full_state(&h);
    let result = owner.run(&h, &["omp-read", "--name", &name, "--check"], &name);
    assert_eq!(
        full_state(&h),
        before,
        "arbitrary bound wrapper received the native shim exception"
    );
    result.refused();
}

#[cfg(windows)]
mod windows_reservation_stop {
    use super::*;

    const SENTINEL_RUNNER: &str = r#"
const fs = require('node:fs');
fs.writeFileSync(process.env.FIXTURE_SIGNALS, '');
for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(name, () => fs.appendFileSync(process.env.FIXTURE_SIGNALS, `${name}\n`));
}
const timer = setInterval(() => fs.appendFileSync(process.env.FIXTURE_HEARTBEAT, 'x'), 25);
setTimeout(() => clearInterval(timer), 90000);
"#;

    struct Sentinel<'a> {
        child: Child,
        h: &'a Hcom,
        name: String,
        heartbeat: PathBuf,
        signals: PathBuf,
    }

    impl<'a> Sentinel<'a> {
        fn spawn(h: &'a Hcom, name: &str) -> Self {
            let heartbeat = h.root_path().join("unrelated-heartbeat");
            let signals = h.root_path().join("unrelated-signals");
            // A direct unrelated Node child, not an OMP script, launcher,
            // PowerShell host or hcom resume. external_cmd clears ambient env.
            let child = h
                .external_cmd("node")
                .args(["-e", SENTINEL_RUNNER])
                .env("FIXTURE_HEARTBEAT", &heartbeat)
                .env("FIXTURE_SIGNALS", &signals)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn owned unrelated sentinel");
            Self {
                child,
                h,
                name: name.to_owned(),
                heartbeat,
                signals,
            }
        }

        fn beats(&self) -> u64 {
            fs::metadata(&self.heartbeat).map_or(0, |stat| stat.len())
        }

        fn assert_untouched(&mut self, before: u64) {
            self.h.eventually(
                "unrelated sentinel heartbeat progresses",
                Duration::from_secs(10),
                || Ok((self.beats() > before && self.signals.exists()).then_some(())),
            );
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "bookkeeping-only stop terminated the unrelated native child"
            );
            assert_eq!(fs::read_to_string(&self.signals).unwrap(), "");
        }
    }

    impl Drop for Sentinel<'_> {
        fn drop(&mut self) {
            // Hcom::Drop must never reopen a numeric PID from this row and
            // signal the unrelated sentinel, including on assertion unwind.
            // Clear only our private fixture's exact PID after observations;
            // cleanup itself always uses the original owned Child handle.
            let _ = db(self.h).execute(
                "UPDATE instances SET pid=NULL WHERE name=?1 AND pid=?2",
                rusqlite::params![self.name, self.child.id()],
            );
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn native_windows_stop_releases_unhooked_reservation_without_signaling() {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let name = format!("directstop{suffix}");
        let sid = uuid::Uuid::new_v4().to_string();
        let process_id = uuid::Uuid::new_v4().to_string();
        let mut sentinel = Sentinel::spawn(&h, &name);
        sentinel.assert_untouched(0);
        let conn = db(&h);
        conn.execute(
            "INSERT INTO instances
             (name,tool,session_id,pid,status,status_context,created_at,last_event_id,launch_context)
             VALUES (?1,'omp',?2,?3,'inactive','new',1234.5,0,'{}')",
            rusqlite::params![name, sid, sentinel.child.id()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO process_bindings
             (process_id,session_id,instance_name,updated_at) VALUES (?1,NULL,?2,1234.5)",
            rusqlite::params![process_id, name],
        )
        .unwrap();
        let reservation: (String, String, String, i64, i64, i64) = conn
            .query_row(
                "SELECT status,status_context,session_id,
                    json_type(launch_context,'$.omp_launch_pid') IS NULL,
                    (SELECT COUNT(*) FROM process_bindings WHERE process_id=?2
                        AND instance_name=?1 AND session_id IS NULL),
                    (SELECT COUNT(*) FROM session_bindings WHERE session_id=?3 OR instance_name=?1)
                 FROM instances WHERE name=?1",
                rusqlite::params![name, process_id, sid],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            reservation,
            ("inactive".into(), "new".into(), sid.clone(), 1, 1, 0),
            "direct stop fixture must be eligible and never hooked"
        );
        let before = sentinel.beats();
        let (code, stdout, stderr) = h.run(["stop", &name]);
        assert_eq!(code, 0, "{stdout} {stderr}");
        let output = format!("{stdout}{stderr}")
            .to_ascii_lowercase()
            .replace("signalled", "signaled");
        assert!(
            output.contains("no process signaled") || output.contains("no process was signaled"),
            "stop must explicitly report bookkeeping-only release: {stdout} {stderr}"
        );
        let cleared: (i64, i64, i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM instances WHERE name=?1),
                    (SELECT COUNT(*) FROM process_bindings WHERE instance_name=?1 OR process_id=?2),
                    (SELECT COUNT(*) FROM session_bindings WHERE instance_name=?1 OR session_id=?3),
                    (SELECT COUNT(*) FROM notify_endpoints WHERE instance=?1)",
                rusqlite::params![name, process_id, sid],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(cleared, (0, 0, 0, 0), "reservation bookkeeping survived");
        sentinel.assert_untouched(before);
        // No resume/C2 assertion: this is deliberately a direct stop proof.
    }
}

// hcom#107: the PowerShell launch lifecycle fixture is known red on Windows
// independently of this change. Keep its three consumer proofs on macOS;
// Windows instead runs real native-child pin units and the direct stop above.
#[cfg(target_os = "macos")]
mod macos_pre_hook {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const PROCESS_WAIT: Duration = Duration::from_secs(30);

    // Frozen native lifecycle fixture: the real launcher starts an actual
    // Node/Bun package script. Its first hook waits for the test's file gate.
    const LAUNCH_RUNNER: &str = r#"
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
if (process.argv[2] === '--version') {
    process.stdout.write('1.0.0\n');
} else {
    const out = process.env.TEST_LAUNCH_DIR;
    if (process.env.HOME !== process.env.TEST_LAUNCH_HOME
        || process.env.HCOM_DIR !== process.env.TEST_LAUNCH_HCOM_DIR) {
        fs.writeFileSync(path.join(out, 'environment-error'), 'fixture environment escaped');
        process.exit(97);
    }
    const started = path.join(out, `${process.pid}.started`);
    fs.writeFileSync(`${started}.tmp`, JSON.stringify({
        pid: process.pid, ppid: process.ppid,
        process_id: process.env.HCOM_PROCESS_ID || '',
        home: process.env.HOME || '', hcom_dir: process.env.HCOM_DIR || '',
    }));
    fs.renameSync(`${started}.tmp`, started);
    const deadline = Date.now() + 90000;
    let hooked = false;
    const timer = setInterval(() => {
        if (Date.now() >= deadline || fs.existsSync(path.join(out, `${process.pid}.exit`))) {
            clearInterval(timer);
            return;
        }
        if (!hooked && fs.existsSync(path.join(out, `${process.pid}.hook`))) {
            hooked = true;
            fs.writeFileSync(path.join(out, `${process.pid}.hook-called`), '');
            const result = spawnSync(process.env.TEST_HCOM_BIN, [
                'omp-start', '--session-id', process.env.TEST_LAUNCH_SID,
                '--transcript-path', process.env.TEST_LAUNCH_TRANSCRIPT,
                '--cwd', process.env.TEST_LAUNCH_CWD,
            ], { encoding: 'utf8', timeout: 15000 });
            fs.writeFileSync(path.join(out, `${process.pid}.stdout`), result.stdout || '');
            fs.writeFileSync(path.join(out, `${process.pid}.stderr`),
                result.stderr || (result.error ? String(result.error) : ''));
            fs.writeFileSync(path.join(out, `${process.pid}.code`),
                String(result.status === null ? -1 : result.status));
        }
    }, 15);
}
"#;

    const SENTINEL_RUNNER: &str = r#"
const fs = require('node:fs');
fs.writeFileSync(process.env.FIXTURE_SIGNALS, '');
for (const name of ['SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGTERM', 'SIGUSR1', 'SIGUSR2', 'SIGCONT']) {
    process.on(name, () => fs.appendFileSync(process.env.FIXTURE_SIGNALS, `${name}\n`));
}
setInterval(() => fs.appendFileSync(process.env.FIXTURE_HEARTBEAT, 'x'), 25);
"#;

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
        pid > 1
            && (unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
    }

    fn row_pid(h: &Hcom, name: &str) -> Option<i64> {
        db(h)
            .query_row("SELECT pid FROM instances WHERE name=?1", [name], |row| {
                row.get(0)
            })
            .ok()
            .flatten()
    }

    fn launch_receipt(h: &Hcom, name: &str) -> Option<Value> {
        let text: Option<String> = db(h)
            .query_row(
                "SELECT launch_context FROM instances WHERE name=?1",
                [name],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        let context: Value = serde_json::from_str(text.as_deref()?).ok()?;
        context
            .get("omp_launch_pid")
            .cloned()
            .filter(Value::is_object)
    }

    // Preserve receipt correlation while moving beyond the placeholder window.
    fn age_launch_bindings(h: &Hcom, name: &str, secs: f64) -> Vec<(String, f64)> {
        let mut conn = db(h);
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let bindings: Vec<(String, f64)> = tx
            .prepare(
                "SELECT process_id,updated_at FROM process_bindings WHERE instance_name=?1 AND session_id IS NULL",
            )
            .unwrap()
            .query_map([name], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let aged: Vec<(String, f64)> = bindings
            .into_iter()
            .map(|(process_id, updated_at)| {
                let aged_at = updated_at - secs;
                assert_eq!(
                    tx.execute(
                        "UPDATE process_bindings SET updated_at=?4 WHERE process_id=?1 AND instance_name=?2 AND updated_at=?3 AND session_id IS NULL",
                        rusqlite::params![process_id, name, updated_at, aged_at],
                    )
                    .unwrap(),
                    1
                );
                (process_id, aged_at)
            })
            .collect();
        let receipt_process: Option<String> = tx
            .query_row(
                "SELECT json_extract(launch_context,'$.omp_launch_pid.process_id') FROM instances WHERE name=?1",
                [name],
                |row| row.get(0),
            )
            .unwrap();
        if let Some(process_id) = receipt_process {
            let (_, aged_at) = aged
                .iter()
                .find(|(id, _)| *id == process_id)
                .expect("receipt must retain its NULL-session launch binding");
            assert_eq!(
                tx.execute(
                    "UPDATE instances SET launch_context=json_set(launch_context,'$.omp_launch_pid.binding_updated_at_bits',?2) WHERE name=?1",
                    rusqlite::params![name, format!("{:016x}", aged_at.to_bits())],
                )
                .unwrap(),
                1
            );
        }
        tx.commit().unwrap();
        aged
    }

    fn resolved_runtime(h: &Hcom, runtime: &str) -> PathBuf {
        let resolved = h
            .external_cmd(runtime)
            .args(["--print", "process.execPath"])
            .output()
            .unwrap();
        assert!(
            resolved.status.success(),
            "{runtime}: {}",
            String::from_utf8_lossy(&resolved.stderr)
        );
        let executable = PathBuf::from(String::from_utf8(resolved.stdout).unwrap().trim());
        assert!(executable.is_absolute() && executable.is_file());
        executable
    }

    fn launch_fixture() -> (Hcom, tempfile::TempDir) {
        // Avoid OMP's /tmp cwd redirect without using a seat build directory.
        let workspace = tempfile::Builder::new()
            .prefix("hcom-omp-launch-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let mut h = isolated_hcom();
        h.workspace = workspace.path().to_path_buf();
        (h, workspace)
    }

    fn quote(value: &Path) -> String {
        format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
    }

    fn executable_file(path: &Path, script: &str) {
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn install_fake_omp(h: &Hcom, runtime: &str, sid: &str, transcript: &Path) -> PathBuf {
        let fakebin = h.root_path().join("fakebin");
        let out = h.root_path().join("omp-launch");
        fs::create_dir_all(&fakebin).unwrap();
        fs::create_dir_all(&out).unwrap();
        let script = h
            .root_path()
            .join("omp-package/node_modules/@oh-my-pi/pi-coding-agent/dist/cli.js");
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::write(&script, LAUNCH_RUNNER).unwrap();
        let runtime_exe = resolved_runtime(h, runtime);
        executable_file(
            &fakebin.join("bash"),
            "#!/bin/bash\nif [ \"$#\" -eq 1 ] && [ \"$1\" = -l ]; then exit 0; fi\nexec /bin/bash \"$@\"\n",
        );
        executable_file(
            &fakebin.join("omp"),
            &format!(
                "#!/bin/sh\nexec {} {} \"$@\"\n",
                quote(&runtime_exe),
                quote(&script)
            ),
        );
        // Persist only the existing fixture allowlist through CI's clean shell.
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
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "TEMP",
            "TMP",
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
        h.set_launch_env("TEST_OWNER_RUNTIME", runtime_exe.to_str().unwrap());
        h.set_launch_env("TEST_OWNER_SCRIPT", script.to_str().unwrap());
        h.set_launch_env("TEST_LAUNCH_DIR", out.to_str().unwrap());
        h.set_launch_env("TEST_HCOM_BIN", env!("CARGO_BIN_EXE_hcom"));
        h.set_launch_env("TEST_LAUNCH_SID", sid);
        h.set_launch_env("TEST_LAUNCH_TRANSCRIPT", transcript.to_str().unwrap());
        h.set_launch_env("TEST_LAUNCH_CWD", h.workspace.to_str().unwrap());
        h.set_launch_env("TEST_LAUNCH_HOME", h.home.to_str().unwrap());
        h.set_launch_env("TEST_LAUNCH_HCOM_DIR", h.path().to_str().unwrap());
        out
    }

    fn seed_stopped_omp(h: &Hcom, runtime: &str, name: &str) -> (String, PathBuf) {
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
        let mut prior = h
            .external_cmd(resolved_runtime(h, runtime))
            .args(["--print", "process.pid"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let prior_pid = i64::from(prior.id());
        h.track_cleanup_pid(prior_pid);
        prior.wait().unwrap();
        assert!(!alive(prior_pid), "historical fixture owner did not exit");
        let conn = db(h);
        conn.execute(
            "INSERT INTO instances (name,tool,session_id,status,status_context,status_time,created_at,directory,transcript_path,last_event_id,background)
             VALUES (?1,'omp',?2,'inactive','exit:0',0,CAST(strftime('%s','now') AS REAL),?3,?4,0,0)",
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

    struct PrivateCommand {
        child: Child,
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
            h.track_cleanup_pid(i64::from(child.id()));
            Self {
                child,
                stdout,
                stderr,
                deadline: Instant::now() + Duration::from_secs(90),
            }
        }

        fn resume(h: &Hcom, label: &str, name: &str) -> Self {
            Self::start(
                h,
                label,
                &["r", name, "--terminal", "bash {script}", "--go"],
            )
        }

        fn kill_owned(&mut self) {
            unsafe {
                libc::killpg(self.child.id() as libc::pid_t, libc::SIGKILL);
            }
            let _ = self.child.kill();
        }

        fn finish(&mut self) -> CommandOutput {
            let status = loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    break Some(status);
                }
                if Instant::now() >= self.deadline {
                    self.kill_owned();
                    let _ = self.child.wait();
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
            self.kill_owned();
            let _ = self.child.wait();
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
        h: &Hcom,
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
                let started: Value = serde_json::from_str(&fs::read_to_string(path).ok()?).ok()?;
                let pid = started["pid"].as_i64()?;
                if Some(pid) == previous {
                    return None;
                }
                h.track_cleanup_pid(pid);
                h.track_cleanup_pid(started["ppid"].as_i64()?);
                Some(Tool {
                    pid,
                    launcher_id: started["process_id"].as_str()?.to_string(),
                    home: started["home"].as_str()?.to_string(),
                    hcom_dir: started["hcom_dir"].as_str()?.to_string(),
                })
            });
            if tool.is_some() || launch.child.try_wait().unwrap().is_some() {
                Some(tool)
            } else {
                None
            }
        })
        .flatten()
    }

    fn first_tool(h: &Hcom, name: &str, out: &Path, launch: &mut PrivateCommand) -> (Tool, i64) {
        let tool = wait_for_tool(h, out, launch, None);
        let pin = tool.as_ref().and_then(|tool| {
            wait_until(PROCESS_WAIT, || {
                (row_pid(h, name) == Some(tool.pid)
                    && launch_receipt(h, name).and_then(|receipt| receipt["pid"].as_i64())
                        == Some(tool.pid))
                .then_some(tool.pid)
            })
        });
        match (tool, pin) {
            (Some(tool), Some(pin)) => (tool, pin),
            (tool, pin) => {
                let state = h.diagnostics();
                launch.kill_owned();
                let result = launch.finish();
                panic!(
                    "fixture launch did not settle: tool={tool:?}, pin={pin:?}, {result:?}\n{state}"
                );
            }
        }
    }

    fn kill_first_tool(
        tool: &Tool,
        pin: i64,
        launch: &mut PrivateCommand,
    ) -> (CommandOutput, bool) {
        unsafe {
            libc::kill(tool.pid as libc::pid_t, libc::SIGKILL);
        }
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
                    fs::read_to_string(out.join(format!("{}.stderr", tool.pid)))
                        .unwrap_or_default(),
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

    fn cleanup_launch(
        out: &Path,
        tool: Option<&Tool>,
        launch: &mut PrivateCommand,
    ) -> CommandOutput {
        if let Some(tool) = tool {
            let _ = fs::write(out.join(format!("{}.exit", tool.pid)), "");
        }
        launch.deadline = Instant::now() + PROCESS_WAIT;
        launch.finish()
    }

    fn assert_binding(
        binding: &Binding,
        tool: Option<&Tool>,
        name: &str,
        sid: &str,
        launch: &CommandOutput,
    ) {
        assert_eq!(
            binding.session_name.as_deref(),
            Some(name),
            "second resume did not bind {name}: {binding:?}; CLI={launch:?}"
        );
        let tool = tool.expect("second resume did not start OMP");
        assert_eq!(binding.hook_code, Some(0), "{}", binding.hook_stderr);
        let hook = binding
            .hook
            .as_ref()
            .expect("real omp-start produced no JSON");
        assert_eq!(hook["name"], name, "{binding:?}");
        assert!(hook.get("error").is_none(), "{binding:?}");
        assert_eq!(binding.row_sid.as_deref(), Some(sid), "{binding:?}");
        assert_eq!(binding.process_sid.as_deref(), Some(sid), "{binding:?}");
        assert_eq!(binding.process_name.as_deref(), Some(name), "{binding:?}");
        assert_eq!(binding.row_pid, Some(tool.pid), "{binding:?}");
        assert!(binding.tool_alive, "{binding:?}");
        assert_eq!(
            binding.instances, 1,
            "resume minted a duplicate: {binding:?}"
        );
    }

    struct Sentinel {
        child: Child,
        heartbeat: PathBuf,
        signals: PathBuf,
    }

    impl Sentinel {
        fn spawn(h: &Hcom, runtime: &str) -> Self {
            let out = h
                .root_path()
                .join(format!("sentinel-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&out).unwrap();
            let heartbeat = out.join("heartbeat");
            let signals = out.join("signals");
            let script = out.join("sentinel.js");
            fs::write(&script, SENTINEL_RUNNER).unwrap();
            let child = h
                .external_cmd(resolved_runtime(h, runtime))
                .arg(&script)
                .env_remove("HCOM_PROCESS_ID")
                .env_remove("HCOM_INSTANCE_NAME")
                .env_remove("HCOM_TOOL")
                .env_remove("HCOM_LAUNCHED")
                .env("FIXTURE_HEARTBEAT", &heartbeat)
                .env("FIXTURE_SIGNALS", &signals)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .unwrap();
            h.track_cleanup_pid(i64::from(child.id()));
            let sentinel = Self {
                child,
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
            fs::metadata(&self.heartbeat).map_or(0, |stat| stat.len())
        }

        fn observation(&mut self, before: u64) -> (bool, bool, String) {
            let progressed = wait_until(Duration::from_secs(2), || {
                (self.beats() > before).then_some(())
            })
            .is_some();
            (
                self.child.try_wait().unwrap().is_none(),
                progressed,
                fs::read_to_string(&self.signals).unwrap(),
            )
        }
    }

    impl Drop for Sentinel {
        fn drop(&mut self) {
            unsafe {
                libc::killpg(self.child.id() as libc::pid_t, libc::SIGKILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn native_pre_hook_dead_pin_can_resume_and_bind() {
        for runtime in ["node", "bun"] {
            let (h, workspace) = launch_fixture();
            let name = format!("prehookdead{}", unique_suffix());
            let (sid, transcript) = seed_stopped_omp(&h, runtime, &name);
            let out = install_fake_omp(&h, runtime, &sid, &transcript);
            let mut first = PrivateCommand::resume(&h, "first", &name);
            let (c1, pin) = first_tool(&h, &name, &out, &mut first);
            let receipt = launch_receipt(&h, &name);
            let first_was_live = alive(pin) && alive(c1.pid);
            let no_first_hook = !out.join(format!("{}.hook-called", c1.pid)).exists();
            let (first_result, first_exited) = kill_first_tool(&c1, pin, &mut first);
            let dead_pin = row_pid(&h, &name);
            let no_hook_after_death = !out.join(format!("{}.hook-called", c1.pid)).exists();
            let first_bound: bool = db(&h)
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM session_bindings WHERE instance_name=?1)",
                    [&name],
                    |row| row.get(0),
                )
                .unwrap();
            let mut second = PrivateCommand::resume(&h, "second", &name);
            let c2 = wait_for_tool(&h, &out, &mut second, Some(c1.pid));
            let binding = bind_second(&h, &name, &sid, &out, c2.as_ref());
            let second_cli_alive = second.child.try_wait().unwrap().is_none();
            let second_result = cleanup_launch(&out, c2.as_ref(), &mut second);
            drop(second);
            drop(first);
            drop(h);
            drop(workspace);

            let receipt = receipt.expect("real launch persisted no omp_launch_pid receipt");
            assert_eq!(receipt["pid"].as_i64(), Some(pin), "{receipt}");
            assert!(
                receipt["identity"]
                    .as_str()
                    .is_some_and(|identity| identity.starts_with("apple:")),
                "runtime={runtime}: receipt lost its native birth identity: {receipt}"
            );
            assert!(first_was_live, "runtime={runtime}: first pin was not live");
            assert!(
                no_first_hook && no_hook_after_death && !first_bound,
                "runtime={runtime}: first OMP bound before its hook gate"
            );
            assert!(
                first_exited,
                "runtime={runtime}: first tool did not exit: {first_result:?}"
            );
            assert_eq!(dead_pin, Some(pin), "pre-hook death lost the launch pin");
            assert_binding(&binding, c2.as_ref(), &name, &sid, &second_result);
            assert!(
                second_cli_alive,
                "runtime={runtime}: C2 real launch CLI was not live: {second_result:?}"
            );
            let c2 = c2.as_ref().unwrap();
            assert_ne!(c2.pid, c1.pid, "second launch reused the first tool");
            assert_eq!(c2.home, c1.home);
            assert_eq!(c2.hcom_dir, c1.hcom_dir);
        }
    }

    #[test]
    fn native_pre_hook_live_matching_pin_is_held() {
        for runtime in ["node", "bun"] {
            let (h, workspace) = launch_fixture();
            let name = format!("prehooklive{}", unique_suffix());
            let (sid, transcript) = seed_stopped_omp(&h, runtime, &name);
            let out = install_fake_omp(&h, runtime, &sid, &transcript);
            let mut first = PrivateCommand::resume(&h, "first", &name);
            let (c1, pin) = first_tool(&h, &name, &out, &mut first);
            let receipt = launch_receipt(&h, &name);
            let aged = age_launch_bindings(&h, &name, 3600.0);
            let aged_receipt = launch_receipt(&h, &name);
            let before = full_state(&h);
            let mut second = PrivateCommand::resume(&h, "second", &name);
            let refused = second.finish();
            let after = full_state(&h);
            let c1_live = alive(pin) && alive(c1.pid);
            let no_hook = !out.join(format!("{}.hook-called", c1.pid)).exists();
            let (_, first_exited) = kill_first_tool(&c1, pin, &mut first);
            drop(second);
            drop(first);
            drop(h);
            drop(workspace);

            let receipt = receipt.expect("real launch persisted no birth receipt");
            assert_eq!(receipt["pid"].as_i64(), Some(pin), "{receipt}");
            assert!(
                receipt["identity"]
                    .as_str()
                    .is_some_and(|identity| identity.starts_with("apple:")),
                "runtime={runtime}: receipt lost its native birth identity: {receipt}"
            );
            let aged_epoch = receipt["process_id"]
                .as_str()
                .and_then(|id| aged.iter().find(|(process_id, _)| process_id == id))
                .expect("receipt binding was not aged past the placeholder window");
            let mut expected_receipt = receipt.clone();
            expected_receipt["binding_updated_at_bits"] =
                json!(format!("{:016x}", aged_epoch.1.to_bits()));
            assert_eq!(aged_receipt.as_ref(), Some(&expected_receipt));
            assert!(refused.code > 0, "runtime={runtime}: {refused:?}");
            assert!(
                refused.stderr.contains("unhooked OMP launch reservation")
                    && refused
                        .stderr
                        .contains("is still the running launch process"),
                "runtime={runtime}: refusal did not reach the held pin verdict: {refused:?}"
            );
            assert_eq!(after, before, "refused resume changed state: {refused:?}");
            assert!(c1_live && no_hook, "first owner did not remain pre-hook");
            assert!(first_exited, "owned first tool did not exit");
        }
    }

    #[test]
    fn native_stop_releases_unhooked_reservation_without_signaling_then_resume_binds() {
        for runtime in ["node", "bun"] {
            let (h, workspace) = launch_fixture();
            let name = format!("prehookstop{}", unique_suffix());
            let (sid, transcript) = seed_stopped_omp(&h, runtime, &name);
            let out = install_fake_omp(&h, runtime, &sid, &transcript);
            let mut first = PrivateCommand::resume(&h, "first", &name);
            let (c1, pin) = first_tool(&h, &name, &out, &mut first);
            let (_, first_exited) = kill_first_tool(&c1, pin, &mut first);
            let mut sentinel = Sentinel::spawn(&h, runtime);
            // Simulate an older whole-context writer dropping the unknown key.
            // A live PID without a receipt is unverifiable, never mismatched.
            db(&h).execute(
                "UPDATE instances SET pid=?2, launch_context=json_remove(launch_context,'$.omp_launch_pid') WHERE name=?1",
                rusqlite::params![name,sentinel.pid()],
            ).unwrap();
            let aged = age_launch_bindings(&h, &name, 3600.0);
            let reservation: (String, String, String, i64) = db(&h).query_row(
                "SELECT status,status_context,session_id,(SELECT COUNT(*) FROM session_bindings WHERE instance_name=?1) FROM instances WHERE name=?1",
                [&name], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            ).unwrap();
            let missing = launch_receipt(&h, &name).is_none();
            let before = full_state(&h);
            let beats = sentinel.beats();
            let mut held = PrivateCommand::resume(&h, "held", &name);
            let refused = held.finish();
            let after = full_state(&h);
            let held_untouched = sentinel.observation(beats);
            let beats = sentinel.beats();
            let mut stop = PrivateCommand::start(&h, "stop", &["stop", &name]);
            let stopped = stop.finish();
            let cleared: (i64, i64, i64, i64) = db(&h)
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM instances WHERE name=?1),
                    (SELECT COUNT(*) FROM process_bindings WHERE instance_name=?1),
                    (SELECT COUNT(*) FROM session_bindings WHERE instance_name=?1),
                    (SELECT COUNT(*) FROM notify_endpoints WHERE instance=?1)",
                    [&name],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            let stop_untouched = sentinel.observation(beats);
            let mut second = PrivateCommand::resume(&h, "second", &name);
            let c2 = wait_for_tool(&h, &out, &mut second, Some(c1.pid));
            let binding = bind_second(&h, &name, &sid, &out, c2.as_ref());
            let second_cli_alive = second.child.try_wait().unwrap().is_none();
            let final_beats = sentinel.beats();
            let final_untouched = sentinel.observation(final_beats);
            let second_result = cleanup_launch(&out, c2.as_ref(), &mut second);
            drop(second);
            drop(stop);
            drop(held);
            drop(first);
            drop(sentinel);
            drop(h);
            drop(workspace);

            assert!(first_exited, "owned first tool did not exit");
            assert_eq!(
                reservation,
                ("inactive".into(), "new".into(), sid.clone(), 0)
            );
            assert!(missing, "fixture retained its launch receipt");
            assert!(!aged.is_empty(), "fixture had no launch UUID binding");
            assert!(refused.code > 0, "runtime={runtime}: {refused:?}");
            assert!(
                refused.stderr.contains("unhooked OMP launch reservation")
                    && refused
                        .stderr
                        .contains("is live and has no verifiable launch receipt"),
                "runtime={runtime}: refusal did not reach the held pin verdict: {refused:?}"
            );
            assert_eq!(after, before, "held legacy resume changed state");
            assert_eq!(held_untouched, (true, true, String::new()));
            assert_eq!(stopped.code, 0, "runtime={runtime}: {stopped:?}");
            let output = format!("{}{}", stopped.stdout, stopped.stderr)
                .to_ascii_lowercase()
                .replace("signalled", "signaled");
            assert!(
                output.contains("no process signaled")
                    || output.contains("no process was signaled"),
                "stop did not explicitly report no process was signaled: {stopped:?}"
            );
            assert_eq!(
                cleared,
                (0, 0, 0, 0),
                "stop retained reservation bookkeeping"
            );
            assert_eq!(stop_untouched, (true, true, String::new()));
            assert_binding(&binding, c2.as_ref(), &name, &sid, &second_result);
            assert!(
                second_cli_alive,
                "runtime={runtime}: C2 real launch CLI was not live: {second_result:?}"
            );
            assert_eq!(final_untouched, (true, true, String::new()));
        }
    }
}
