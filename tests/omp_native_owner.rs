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

if (process.versions.bun && process.argv[2] === '__omp_worker_daemon_broker') {
    process.title = 'omp daemon broker';
}

function execute(step) {
    if (step.via && step.via.length) {
        const [mode, ...rest] = step.via;
        const selectors = mode === 'worker' ? ['__omp_worker_daemon_broker'] : [];
        const child = spawnSync(process.execPath, [__filename, ...selectors], {
            env: { ...process.env, TEST_OWNER_ONESHOT: JSON.stringify({ ...step, via: rest }) },
            encoding: 'utf8', timeout: 20000, windowsHide: true,
        });
        if (child.error || child.status !== 0) {
            throw new Error(`nested runtime fixture failed: ${child.error || child.stderr}`);
        }
        return JSON.parse(child.stdout);
    }
    const env = { ...process.env, HCOM_LAUNCHED: '1', HCOM_TOOL: 'omp', ...step.env };
    if (step.own_id) {
        env.HCOM_PROCESS_ID = `omp-${process.pid}-native-fixture`;
        delete env.HCOM_INSTANCE_NAME;
    }
    const result = spawnSync(process.env.TEST_HCOM_BIN, step.args, {
        env, encoding: 'utf8', timeout: 15000, windowsHide: true,
    });
    if (result.error) throw result.error;
    return { code: result.status, stdout: result.stdout, stderr: result.stderr,
             caller_pid: process.pid };
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
}

impl HookOutput {
    fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "hook JSON: {error}; stdout={} stderr={}",
                self.stdout, self.stderr
            )
        })
    }

    fn ok(&self) -> Value {
        assert_eq!(self.code, 0, "{} {}", self.stdout, self.stderr);
        let body = self.json();
        assert!(body.get("error").is_none(), "{body}: {}", self.stderr);
        body
    }

    fn refused(&self) {
        assert_eq!(self.code, 0, "{} {}", self.stdout, self.stderr);
        let body = self.json();
        assert!(body.get("error").is_some(), "hook was admitted: {body}");
        assert!(body.get("name").is_none(), "refusal bound a name: {body}");
    }
}

struct NativeOwner {
    child: Child,
    dir: PathBuf,
    pid: u32,
    process_id: String,
    step: Cell<usize>,
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
            "native owner exited"
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
        owner
            .run(
                &h,
                &["omp-stop", "--name", &name, "--reason", "shutdown"],
                &name,
            )
            .ok();
        let remaining: i64 = db(&h)
            .query_row(
                "SELECT COUNT(*) FROM instances WHERE name=?1",
                [&name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0, "native legacy owner could not release itself");
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
            assert_ne!(
                explicit.code, 0,
                "native descendant reclaimed owner: {}",
                explicit.stdout
            );
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
