//! Nearest-OMP ownership against the real fixture-local hcom binary.
//!
//! The processes named `omp` below are Bash stand-ins, not reproductions with
//! the actual application. They have real kernel PIDs and, where requested,
//! hold a persistent session file open. File-step synchronization keeps each
//! hook below the same live owner without depending on a TTY, transcript
//! discovery, or file descriptors as authentication evidence.

#![cfg(target_os = "linux")]

mod support;

use std::cell::Cell;
use std::fs;
use std::io::{ErrorKind, Read};
use std::net::TcpListener;
use std::os::unix::fs as unix_fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::omp_owner::{CONFIG, db, full_state, isolated_hcom};
use support::{Hcom, unique_suffix};

fn launcher_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

const STEP_RUNNER: &str = r#"
cd "$TEST_CWD" || exit 1
H() { HCOM_LAUNCHED=1 HCOM_TOOL=omp "$TEST_BIN" "$@"; }
export -f H
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

struct HookOutput {
    code: i32,
    stdout: String,
    stderr: String,
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
        assert!(body.get("error").is_some(), "hook was not refused: {body}");
        assert!(body.get("name").is_none(), "refusal bound a name: {body}");
    }
}

/// One process-step runner; `wrapped` keeps a non-OMP launcher above the
/// persistent OMP. The row may legitimately retain that earlier anchor PID.
struct HookProcess {
    child: Child,
    out_dir: PathBuf,
    owner_pid: u32,
    process_id: String,
    next_step: Cell<usize>,
}

impl HookProcess {
    fn spawn(h: &Hcom, tag: &str, executable: &str, id: Option<&str>, wrapped: bool) -> Self {
        let fakebin = h.root_path().join("fakebin");
        fs::create_dir_all(&fakebin).expect("create fakebin");
        for name in ["omp", executable] {
            let path = fakebin.join(name);
            if !path.exists() {
                unix_fs::symlink("/bin/bash", path).expect("symlink fixture executable");
            }
        }
        let out_dir = h.root_path().join(format!("process-{tag}"));
        fs::create_dir_all(&out_dir).expect("create process output directory");
        let worker = matches!(
            executable,
            "__omp_worker_daemon" | "__omp_worker_daemon_broker"
        );
        let runner = if worker {
            // Bash stand-in for the installed Bun script's reserved worker
            // entrypoint, including the startup race where comm is still omp.
            h.root_path().join("@oh-my-pi/pi-coding-agent/dist/cli.js")
        } else {
            out_dir.join("steps.sh")
        };
        fs::create_dir_all(runner.parent().unwrap()).expect("create runner directory");
        fs::write(&runner, STEP_RUNNER).expect("write process-step runner");
        let mut command = h.external_cmd(if wrapped {
            PathBuf::from("/bin/bash")
        } else {
            fakebin.join(executable)
        });
        command.arg("-c").arg(if wrapped {
            // Do not exec the launcher: its distinct PID is the early anchor.
            "\"$TEST_OMP\" \"$TEST_RUNNER\" & child=$!; wait \"$child\""
        } else if worker {
            "exec -a bun \"$TEST_OMP\" \"$TEST_RUNNER\" \"$TEST_WORKER_MODE\""
        } else {
            "exec env HCOM_PROCESS_ID=\"${HCOM_PROCESS_ID:-omp-$$-1-1}\" \"$TEST_EXECUTABLE\" \"$TEST_RUNNER\""
        });
        command
            .env("TEST_EXECUTABLE", fakebin.join(executable))
            .env("TEST_OMP", fakebin.join("omp"))
            .env("TEST_RUNNER", &runner)
            .env("TEST_WORKER_MODE", executable)
            .env("TEST_OUT_DIR", &out_dir)
            .env("TEST_CWD", &h.workspace)
            .env("TEST_BIN", env!("CARGO_BIN_EXE_hcom"))
            .env("TERM", "dumb")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        if let Some(id) = id {
            command.env("HCOM_PROCESS_ID", id);
        }
        let child = command.spawn().expect("spawn fixture hook process");
        h.track_cleanup_pid(child.id() as i64);
        let ready = h.eventually("hook process ready", Duration::from_secs(30), || {
            Ok(fs::read_to_string(out_dir.join("ready"))
                .ok()
                .filter(|text| text.lines().count() == 2))
        });
        let mut lines = ready.lines();
        let owner_pid = lines.next().unwrap().parse().expect("owner PID");
        let process_id = lines.next().unwrap().to_string();
        Self {
            child,
            out_dir,
            owner_pid,
            process_id,
            next_step: Cell::new(0),
        }
    }

    fn run(&self, h: &Hcom, script: &str) -> HookOutput {
        let step = self.next_step.get();
        self.next_step.set(step + 1);
        trigger_step(&self.out_dir, step, script);
        wait_step(h, &self.out_dir, step)
    }

    fn descendant(&self, h: &Hcom, script: &str) -> HookOutput {
        self.run(
            h,
            &format!(
                "\"$TEST_OMP\" -c {}",
                quote(&format!("{script}; code=$?; exit \"$code\""))
            ),
        )
    }

    fn assert_alive(&mut self) {
        assert!(
            self.child.try_wait().expect("poll owner process").is_none(),
            "owner exited"
        );
        assert!(
            Path::new(&format!("/proc/{}", self.owner_pid)).exists(),
            "OMP owner vanished"
        );
    }
}

fn trigger_step(out_dir: &Path, step: usize, script: &str) {
    fs::write(out_dir.join(format!("{step}.sh")), script).expect("write hook step");
    fs::write(out_dir.join(format!("go-{step}")), "").expect("trigger hook step");
}

fn wait_step(h: &Hcom, out_dir: &Path, step: usize) -> HookOutput {
    let code = h.eventually("hook step finished", Duration::from_secs(30), || {
        Ok(fs::read_to_string(out_dir.join(format!("{step}.code")))
            .ok()
            .filter(|text| !text.is_empty()))
    });
    HookOutput {
        code: code.parse().expect("hook exit code"),
        stdout: fs::read_to_string(out_dir.join(format!("{step}.stdout"))).unwrap(),
        stderr: fs::read_to_string(out_dir.join(format!("{step}.stderr"))).unwrap(),
    }
}

fn sibling_omps(h: &Hcom, wrapper: &HookProcess) -> [(PathBuf, u32); 2] {
    let dirs = [
        h.root_path().join("sibling-left"),
        h.root_path().join("sibling-right"),
    ];
    for dir in &dirs {
        fs::create_dir_all(dir).expect("create sibling process directory");
    }
    wrapper.run(h, &format!(
        "TEST_OUT_DIR={} \"$TEST_OMP\" \"$TEST_RUNNER\" &\nTEST_OUT_DIR={} \"$TEST_OMP\" \"$TEST_RUNNER\" &\nprintf '%s' '{{\"ok\":true}}'",
        quote(&dirs[0].to_string_lossy()), quote(&dirs[1].to_string_lossy()),
    )).ok();
    dirs.map(|dir| {
        let pid = h.eventually("sibling OMP ready", Duration::from_secs(30), || {
            Ok(fs::read_to_string(dir.join("ready")).ok().and_then(|text| {
                (text.lines().nth(1) == Some(wrapper.process_id.as_str()))
                    .then(|| text.lines().next().unwrap().parse::<u32>().unwrap())
            }))
        });
        (dir, pid)
    })
}

impl Drop for HookProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            unsafe {
                libc::killpg(self.child.id() as libc::pid_t, libc::SIGKILL);
            }
        }
        let _ = self.child.wait();
    }
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn probe() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture-local endpoint");
    listener.set_nonblocking(true).unwrap();
    listener
}

fn discard_setup_wakes(listener: &TcpListener) {
    loop {
        match listener.accept() {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => return,
            Err(error) => panic!("drain legitimate setup wake: {error}"),
        }
    }
}

#[track_caller]
fn assert_no_wake(listeners: &[&TcpListener]) {
    let deadline = Instant::now() + Duration::from_millis(75);
    loop {
        for listener in listeners {
            match listener.accept() {
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                mut other => {
                    // Acceptance is already a violation. This single bounded read
                    // diagnoses it; it cannot turn it into a passing observation.
                    let caller = std::panic::Location::caller();
                    let receiver_pid = std::process::id();
                    let receiver_tid = unsafe { libc::syscall(libc::SYS_gettid) };
                    let thread = std::thread::current();
                    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH);
                    let local_addr = listener.local_addr();
                    let accepted_peer = other.as_ref().ok().map(|(_, peer)| *peer);
                    let observation = match &mut other {
                        Ok((stream, _)) => {
                            if let Err(error) = stream.set_nonblocking(false) {
                                format!("read setup error (blocking mode): {error}")
                            } else if let Err(error) =
                                stream.set_read_timeout(Some(Duration::from_millis(20)))
                            {
                                format!("read setup error (20ms timeout): {error}")
                            } else {
                                let mut prefix = [0_u8; 64];
                                match stream.read(&mut prefix) {
                                    Ok(length) => {
                                        let status =
                                            if length == 0 { "EOF" } else { "data-prefix" };
                                        let digest = Sha256::digest(&prefix[..length]);
                                        let mut digest_hex = String::with_capacity(64);
                                        for byte in digest.iter() {
                                            use std::fmt::Write as _;
                                            write!(&mut digest_hex, "{byte:02x}")
                                                .expect("writing to a String cannot fail");
                                        }
                                        format!(
                                            "{status} length_read={length} prefix_limit=64 sha256={digest_hex}"
                                        )
                                    }
                                    Err(error)
                                        if matches!(
                                            error.kind(),
                                            ErrorKind::WouldBlock | ErrorKind::TimedOut
                                        ) =>
                                    {
                                        format!(
                                            "timeout read_timeout_ms=20 prefix_limit=64: {error}"
                                        )
                                    }
                                    Err(error) => format!("read error prefix_limit=64: {error}"),
                                }
                            }
                        }
                        Err(error) => format!("accept error (no stream to read): {error}"),
                    };
                    panic!(
                        "rejected hook woke a fixture endpoint: receiver_pid={receiver_pid} \
                         receiver_linux_tid={receiver_tid} thread_name={:?} caller={}:{} \
                         unix_timestamp={timestamp:?} listener_local_addr={local_addr:?} \
                         accepted_peer_addr={accepted_peer:?} \
                         accept_result_type=Result<(TcpStream,SocketAddr),std::io::Error> \
                         accept_result={other:?} bounded_read={observation}",
                        thread.name(),
                        caller.file(),
                        caller.line(),
                    );
                }
            }
        }
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn seed_launch(h: &Hcom, owner: &HookProcess, name: &str) {
    let db = db(h);
    db.execute(
        "INSERT INTO instances (name, tool, status, status_context, created_at, pid) VALUES (?1, 'omp', 'pending', 'new', 1234.5, ?2)",
        rusqlite::params![name, owner.child.id()],
    ).unwrap();
    db.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at) VALUES (?1, NULL, ?2, 1234.5)",
        rusqlite::params![owner.process_id, name],
    ).unwrap();
}

fn start_command(sid: &str, transcript: &Path, cwd: &Path, endpoint: &TcpListener) -> String {
    format!(
        "H omp-start --session-id {} --transcript-path {} --cwd {} --notify-port {}",
        quote(sid),
        quote(&transcript.to_string_lossy()),
        quote(&cwd.to_string_lossy()),
        endpoint.local_addr().unwrap().port()
    )
}

fn assert_bound(h: &Hcom, owner: &HookProcess, name: &str, sid: &str, path: &Path, cwd: &Path) {
    let db = db(h);
    let row: (String, String, String, i64) = db
        .query_row(
            "SELECT session_id, transcript_path, directory, pid FROM instances WHERE name = ?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        row,
        (
            sid.into(),
            path.to_string_lossy().into_owned(),
            cwd.to_string_lossy().into_owned(),
            owner.owner_pid as i64
        )
    );
    let bindings: (String, String) = db.query_row(
        "SELECT p.instance_name, s.instance_name FROM process_bindings p JOIN session_bindings s ON s.session_id = p.session_id WHERE p.process_id = ?1 AND p.session_id = ?2",
        rusqlite::params![owner.process_id, sid], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(bindings, (name.into(), name.into()));
}

fn assert_released_history(h: &Hcom, name: &str, process_id: &str) -> Value {
    let conn = db(h);
    let retained: (i64, i64, i64, i64) = conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM instances WHERE name=?1),
                (SELECT COUNT(*) FROM process_bindings WHERE instance_name=?1),
                (SELECT COUNT(*) FROM session_bindings WHERE instance_name=?1),
                (SELECT COUNT(*) FROM notify_endpoints WHERE instance=?1)",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(retained, (0, 0, 0, 0), "release retained owner state");
    let data: String = conn
        .query_row(
            "SELECT data FROM events WHERE type='life' AND instance=?1
               AND json_extract(data,'$.action')='stopped' ORDER BY id DESC LIMIT 1",
            [name],
            |row| row.get(0),
        )
        .unwrap();
    let stopped: Value = serde_json::from_str(&data).unwrap();
    assert_eq!(stopped["process_id"], process_id);
    assert_eq!(stopped["snapshot"]["tool"], "omp");
    stopped
}

fn seed_message(h: &Hcom, name: &str, from: &str, text: &str, scope: &str, thread: &str) -> i64 {
    let db = db(h);
    db.execute(
        "INSERT INTO events (timestamp, type, instance, data) VALUES ('2026-10-01T01:02:03+00:00', 'message', ?1, ?2)",
        rusqlite::params![from, json!({"from": from, "text": text, "intent": "inform", "scope": scope, "mentions": [name], "delivered_to": [name], "thread": thread}).to_string()],
    ).unwrap();
    db.last_insert_rowid()
}

fn refused_commands(name: &str, sid: &str, up_to: i64) -> Vec<String> {
    let name = quote(name);
    vec![
        format!(
            "H omp-status --name {name} --status listening --context borrowed --detail foreign"
        ),
        format!("H omp-read --name {name}"),
        format!("H omp-read --name {name} --check"),
        format!("H omp-read --name {name} --format"),
        format!("H omp-read --name {name} --ack --up-to {up_to}"),
        format!(
            "H omp-beforetool --name {name} --tool bash --input-json '{{\"command\":\"pwd\",\"intent\":\"foreign work\"}}'"
        ),
        format!(
            "H omp-role --name {name} --session-id {} --role conductor",
            quote(sid)
        ),
        format!("H omp-stop --name {name} --soft --reason borrowed"),
        format!("H omp-stop --name {name} --reason borrowed"),
    ]
}

#[test]
fn descendant_omp_cannot_borrow_live_owner_uuid() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("owner{suffix}");
    let sid = format!("sid-owner-{suffix}");
    let incoming_sid = format!("sid-previous-{suffix}");
    let mut owner = HookProcess::spawn(&h, "uuid-owner", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &owner, &name);
    let own_endpoint = probe();
    let foreign_endpoint = probe();
    let transcript = h.workspace.join(format!("{sid}.jsonl"));
    fs::write(
        &transcript,
        json!({"type": "session", "id": sid, "cwd": h.workspace}).to_string(),
    )
    .unwrap();
    owner
        .run(
            &h,
            &format!(
                "exec 9< {}; export HCOM_INSTANCE_NAME={}; {}",
                quote(&transcript.to_string_lossy()),
                quote(&name),
                start_command(&sid, &transcript, &h.workspace, &own_endpoint)
            ),
        )
        .ok();
    assert_bound(&h, &owner, &name, &sid, &transcript, &h.workspace);

    // The issue's poisoned current row, no incoming session binding, and an
    // older, restorable real-session snapshot. The base trusts any OMP in
    // the UUID's ancestry, reaches Path 2, restores this different name and
    // moves bindings/endpoints off the live owner. Assert the complete state
    // BEFORE checking its error response so that is the failing invariant.
    let previous_name = format!("previous{suffix}");
    let wrong_sid = format!("sid-poison-{suffix}");
    let missing = h.root_path().join("deleted-project");
    let conn = db(&h);
    conn.execute("UPDATE instances SET session_id=?2, directory=?3, transcript_path=?4, status='active', name_announced=0 WHERE name=?1",
        rusqlite::params![name, wrong_sid, missing.to_string_lossy(), missing.join("lost.jsonl").to_string_lossy()]).unwrap();
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
    conn.execute("INSERT INTO events (timestamp,type,instance,data) VALUES ('2026-09-01T00:00:00+00:00','life',?1,?2)",
        rusqlite::params![previous_name, json!({"action":"stopped","by":"session","reason":"exit:shutdown","process_id":launcher_id(),"snapshot":{"name":previous_name,"session_id":incoming_sid,"tool":"omp","directory":h.workspace,"transcript_path":transcript,"created_at":1000.0,"last_event_id":0,"name_announced":1}}).to_string()]).unwrap();
    let delegate = format!("delegate{suffix}");
    conn.execute("INSERT INTO instances (name, tool, session_id, status, created_at) VALUES (?1,'omp',?2,'listening',1235.5)", rusqlite::params![delegate, format!("sid-delegate-{suffix}")]).unwrap();
    let refused_sender = format!("sender{suffix}");
    conn.execute("INSERT INTO instances (name,tool,session_id,status,created_at) VALUES (?1,'omp',?2,'listening',1236.5)", rusqlite::params![refused_sender, format!("sid-sender-{suffix}")]).unwrap();
    drop(conn);
    fs::write(
        h.path().join("config.toml"),
        format!("{CONFIG}\n[delivery.conductor]\ndelegate = \"{delegate}\"\nleads = []\n"),
    )
    .unwrap();
    owner
        .run(
            &h,
            &format!(
                "H omp-role --name {} --session-id {} --role conductor",
                quote(&name),
                quote(&wrong_sid)
            ),
        )
        .ok();
    seed_message(
        &h,
        &name,
        "broadcast-fixture",
        "skip without advancing",
        "broadcast",
        "",
    );
    let refused = seed_message(
        &h,
        &name,
        &refused_sender,
        "forward only for the genuine owner",
        "mentions",
        "",
    );
    let thread = format!("owner-thread-{suffix}");
    let unread = seed_message(
        &h,
        &name,
        &delegate,
        "owner unread sentinel",
        "mentions",
        &thread,
    );
    let foreign_cwd = h.root_path().join("descendant-project");
    fs::create_dir_all(&foreign_cwd).unwrap();
    let foreign_path = foreign_cwd.join(format!("{incoming_sid}.jsonl"));
    assert!(!foreign_path.exists());
    let mut commands = vec![start_command(
        &incoming_sid,
        &foreign_path,
        &foreign_cwd,
        &foreign_endpoint,
    )];
    commands.extend(refused_commands(&name, &wrong_sid, unread));
    for command in commands {
        let before = full_state(&h);
        let output = owner.descendant(&h, &command);
        assert_eq!(
            full_state(&h),
            before,
            "descendant changed persistent state: {command}; stdout={} stderr={}",
            output.stdout,
            output.stderr
        );
        output.refused();
        assert_no_wake(&[&own_endpoint, &foreign_endpoint]);
        owner.assert_alive();
    }
    // Positive control for the exact role/forward/tip candidates above:
    // these are consuming operations when the genuine owner reaches them.
    let formatted = owner.run(&h, &format!("H omp-read --name {} --format", quote(&name)));
    assert_eq!(
        formatted.code, 0,
        "{} {}",
        formatted.stdout, formatted.stderr
    );
    assert!(
        formatted.stdout.contains("owner unread sentinel"),
        "{}",
        formatted.stdout
    );
    let conn = db(&h);
    let cursor: i64 = conn
        .query_row(
            "SELECT last_event_id FROM instances WHERE name=?1",
            [&name],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        cursor, refused,
        "genuine governed read did not consume its refused prefix"
    );
    let forwarded: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE type='message' AND json_extract(data,'$.delivery_forward_of')=?1",
        [refused], |row| row.get(0),
    ).unwrap();
    assert_eq!(forwarded, 1, "forwarding candidate was not exercised");
    let tip: String = conn
        .query_row(
            "SELECT value FROM kv WHERE key=?1",
            [format!("tip:{name}:recv:thread:{thread}")],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tip, "1", "format candidate did not mark its thread tip");
}

#[test]
fn early_wrapper_uuid_allows_one_omp_but_not_its_descendant() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("wrapped{suffix}");
    let sid = format!("sid-wrapper-{suffix}");
    let mut owner = HookProcess::spawn(&h, "early-wrapper", "omp", Some(&launcher_id()), true);
    assert_ne!(owner.owner_pid, owner.child.id());
    seed_launch(&h, &owner, &name);
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    assert!(!path.exists());
    let start = start_command(&sid, &path, &h.workspace, &endpoint);
    assert_eq!(owner.run(&h, &start).ok()["name"], name);
    assert_bound(&h, &owner, &name, &sid, &path, &h.workspace);
    let before = full_state(&h);
    let output = owner.descendant(&h, &start);
    assert_eq!(
        full_state(&h),
        before,
        "nested OMP borrowed the early wrapper UUID"
    );
    output.refused();
    assert_no_wake(&[&endpoint]);
    owner.assert_alive();
}

#[test]
fn inherited_minted_identity_rejects_descendant_hooks() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let sid = format!("sid-minted-{suffix}");
    let mut owner = HookProcess::spawn(&h, "minted-owner", "omp", None, false);
    assert_eq!(owner.process_id, format!("omp-{}-1-1", owner.owner_pid));
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    let response = owner
        .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
        .ok();
    let name = response["name"]
        .as_str()
        .expect("minted owner name")
        .to_string();
    owner.run(&h, &format!("export HCOM_INSTANCE_NAME={}", quote(&name)));
    let unread = seed_message(
        &h,
        &name,
        "fixture-sender",
        "unread minted payload",
        "mentions",
        "",
    );
    let incoming = format!("sid-minted-child-{suffix}");
    let mut commands = vec![start_command(
        &incoming,
        &h.workspace.join("child.jsonl"),
        &h.workspace,
        &endpoint,
    )];
    commands.extend(refused_commands(&name, &sid, unread));
    for command in commands {
        let before = full_state(&h);
        let output = owner.descendant(&h, &command);
        assert_eq!(
            full_state(&h),
            before,
            "descendant borrowed minted identity: {command}"
        );
        output.refused();
        assert_no_wake(&[&endpoint]);
        owner.assert_alive();
    }
}

#[test]
fn genuine_owner_repairs_poisoned_metadata_and_transitions_without_a_file() {
    for wrong_binding in [false, true] {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let name = format!("repair{suffix}");
        let sid = format!("sid-repair-{suffix}");
        let mut owner = HookProcess::spawn(&h, "repair-owner", "omp", Some(&launcher_id()), false);
        seed_launch(&h, &owner, &name);
        let endpoint = probe();
        let path = h.workspace.join(format!("{sid}.jsonl"));
        fs::write(&path, "{\"type\":\"session\"}\n").unwrap();
        owner
            .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
            .ok();
        let deleted = h.root_path().join("deleted-directory");
        fs::create_dir_all(&deleted).unwrap();
        let lost = deleted.join("deleted.jsonl");
        fs::write(&lost, "{}").unwrap();
        fs::remove_file(&lost).unwrap();
        fs::remove_dir(&deleted).unwrap();
        let wrong_sid = format!("sid-wrong-{suffix}");
        let conn = db(&h);
        conn.execute("UPDATE instances SET session_id=?2, directory=?3, transcript_path=?4, last_event_id=17, name_announced=1 WHERE name=?1",
            rusqlite::params![name, wrong_sid, deleted.to_string_lossy(), lost.to_string_lossy()]).unwrap();
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
        if wrong_binding {
            conn.execute("INSERT INTO session_bindings (session_id,instance_name,created_at) VALUES (?1,?2,1234.5)", rusqlite::params![wrong_sid, name]).unwrap();
        }
        drop(conn);
        assert_eq!(
            owner
                .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
                .ok()["name"],
            name
        );
        assert_bound(&h, &owner, &name, &sid, &path, &h.workspace);
        let metadata: (f64, i64, i64) = db(&h)
            .query_row(
                "SELECT created_at,last_event_id,name_announced FROM instances WHERE name=?1",
                [&name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            metadata,
            (1234.5, 17, 1),
            "repair replaced identity or consumed mail"
        );
        let next_sid = format!("sid-transition-{suffix}");
        let next_cwd = h.root_path().join("next-project");
        fs::create_dir_all(&next_cwd).unwrap();
        let next_path = next_cwd.join(format!("{next_sid}.jsonl"));
        assert!(!next_path.exists());
        // This runner has null stdio, no PTY and no session FD. Only process
        // identity authorizes the owner's explicit new session metadata.
        db(&h)
            .execute("UPDATE instances SET background=1 WHERE name=?1", [&name])
            .unwrap();
        let transition = format!(
            "test ! -t 0 && {}",
            start_command(&next_sid, &next_path, &next_cwd, &endpoint)
        );
        assert_eq!(owner.run(&h, &transition).ok()["name"], name);
        assert_bound(&h, &owner, &name, &next_sid, &next_path, &next_cwd);
        assert!(
            !next_path.exists(),
            "hook created a transcript to prove ownership"
        );
        owner.assert_alive();
    }
}

#[test]
fn genuine_owner_can_poll_ack_softstop_release_and_not_resurrect() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let sid = format!("sid-lifecycle-{suffix}");
    let mut owner = HookProcess::spawn(&h, "lifecycle-owner", "omp", None, false);
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    let start = start_command(&sid, &path, &h.workspace, &endpoint);
    let response = owner.run(&h, &start).ok();
    let name = response["name"]
        .as_str()
        .expect("lifecycle owner name")
        .to_string();
    let unread = seed_message(
        &h,
        &name,
        "fixture-sender",
        "owner lifecycle payload",
        "mentions",
        "",
    );
    owner
        .run(
            &h,
            &format!(
                "H omp-status --name {} --status active --context owner-work",
                quote(&name)
            ),
        )
        .ok();
    let check = owner.run(&h, &format!("H omp-read --name {} --check", quote(&name)));
    assert_eq!((check.code, check.stdout.trim()), (0, "true"));
    let mail = owner
        .run(&h, &format!("H omp-read --name {}", quote(&name)))
        .ok();
    assert_eq!(mail[0]["event_id"], unread);
    assert_eq!(mail[0]["message"], "owner lifecycle payload");
    let formatted = owner.run(&h, &format!("H omp-read --name {} --format", quote(&name)));
    assert_eq!(formatted.code, 0);
    assert!(
        formatted.stdout.contains("owner lifecycle payload"),
        "{}",
        formatted.stdout
    );
    assert_eq!(
        owner
            .run(
                &h,
                &format!("H omp-read --name {} --ack --up-to {unread}", quote(&name))
            )
            .ok()["acked_to"],
        unread
    );
    let check = owner.run(&h, &format!("H omp-read --name {} --check", quote(&name)));
    assert_eq!((check.code, check.stdout.trim()), (0, "false"));
    owner
        .run(
            &h,
            &format!(
                "H omp-beforetool --name {} --tool bash --input-json '{{\"command\":\"pwd\"}}'",
                quote(&name)
            ),
        )
        .ok();
    owner
        .run(
            &h,
            &format!(
                "H omp-role --name {} --session-id {} --role conductor",
                quote(&name),
                quote(&sid)
            ),
        )
        .ok();
    assert_eq!(
        owner
            .run(
                &h,
                &format!(
                    "H omp-stop --name {} --soft --reason shutdown",
                    quote(&name)
                )
            )
            .ok()["soft"],
        true
    );
    let retained: i64 = db(&h).query_row("SELECT COUNT(*) FROM instances i JOIN process_bindings p ON p.instance_name=i.name WHERE i.name=?1 AND i.status='inactive'", [&name], |r| r.get(0)).unwrap();
    assert_eq!(retained, 1, "soft stop did not retain the owner binding");
    owner
        .run(
            &h,
            &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
        )
        .ok();
    let released: i64 = db(&h)
        .query_row(
            "SELECT COUNT(*) FROM instances WHERE name=?1",
            [&name],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(released, 0);
    owner.assert_alive();
    let before = full_state(&h);
    let late = owner.run(&h, &start);
    assert_eq!(
        full_state(&h),
        before,
        "late own-start resurrected released state"
    );
    assert_eq!(late.ok()["restored"], false);
}

#[test]
fn canonical_live_adoption_and_stopped_resume_use_legitimate_process_identity() {
    for state in ["live", "soft-stopped", "released"] {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let name = format!("canonical{suffix}");
        let sid = format!("sid-canonical-{suffix}");
        let first = HookProcess::spawn(&h, "canonical-first", "omp", Some(&launcher_id()), false);
        seed_launch(&h, &first, &name);
        let endpoint = probe();
        let path = h.workspace.join(format!("{sid}.jsonl"));
        first
            .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
            .ok();
        if state == "soft-stopped" {
            first
                .run(
                    &h,
                    &format!("H omp-stop --name {} --soft --reason restart", quote(&name)),
                )
                .ok();
        } else if state == "released" {
            first
                .run(
                    &h,
                    &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
                )
                .ok();
        }
        drop(first);
        let second = HookProcess::spawn(&h, "canonical-second", "omp", None, false);
        let result = second
            .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
            .ok();
        assert_eq!(
            result["name"], name,
            "dead owner's canonical session was not adopted (state={state})"
        );
        let bound: String = db(&h)
            .query_row(
                "SELECT instance_name FROM process_bindings WHERE process_id=?1 AND session_id=?2",
                rusqlite::params![second.process_id, sid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(bound, name);
        assert_bound(&h, &second, &name, &sid, &path, &h.workspace);
        let count: i64 = db(&h)
            .query_row("SELECT COUNT(*) FROM instances", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "adoption minted a replacement identity");
    }
}

#[test]
fn shared_worker_stale_uuid_or_name_cannot_mutate_an_unrelated_owner() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("workerowner{suffix}");
    let sid = format!("sid-workerowner-{suffix}");
    let mut owner = HookProcess::spawn(&h, "worker-owner", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &owner, &name);
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    owner
        .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
        .ok();
    let unread = seed_message(
        &h,
        &name,
        "fixture-sender",
        "worker must not consume",
        "mentions",
        "",
    );
    for executable in ["__omp_worker_daemon", "__omp_worker_daemon_broker"] {
        let worker = HookProcess::spawn(&h, executable, executable, Some(&owner.process_id), false);
        for name_only in [false, true] {
            for unrelated_omp in [false, true] {
                let mut commands = vec![start_command(
                    &format!("sid-worker-child-{suffix}"),
                    &h.workspace.join("worker-child.jsonl"),
                    &h.workspace,
                    &endpoint,
                )];
                commands.extend(refused_commands(&name, &sid, unread));
                for command in commands {
                    let script = format!(
                        "export HCOM_INSTANCE_NAME={}; {}; {command}",
                        quote(&name),
                        if name_only {
                            "unset HCOM_PROCESS_ID"
                        } else {
                            "export HCOM_PROCESS_ID=\"$TEST_STALE_ID\""
                        }
                    );
                    // The runner's environment is fixture-owned. This value
                    // is explicitly restored after each name-only request.
                    let script = format!("TEST_STALE_ID={}; {script}", quote(&owner.process_id));
                    let before = full_state(&h);
                    let output = if unrelated_omp {
                        worker.descendant(&h, &script)
                    } else {
                        worker.run(&h, &script)
                    };
                    assert_eq!(
                        full_state(&h),
                        before,
                        "worker mutated another owner: {executable}, name_only={name_only}, unrelated_omp={unrelated_omp}, {command}"
                    );
                    output.refused();
                    assert_no_wake(&[&endpoint]);
                    owner.assert_alive();
                }
            }
        }
    }
}

#[test]
fn direct_non_omp_without_id_or_with_only_anchor_pid_cannot_mutate_owner() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("directowner{suffix}");
    let sid = format!("sid-direct-{suffix}");
    let mut owner = HookProcess::spawn(&h, "direct-owner", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &owner, &name);
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    owner
        .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
        .ok();
    for anchor_env in [false, true] {
        let before = full_state(&h);
        let mut command = h.cmd();
        command.args(["omp-stop", "--name", &name]);
        command.env("HCOM_INSTANCE_NAME", &name);
        if anchor_env {
            command.env("HCOM_ANCHOR_PID", owner.owner_pid.to_string());
        }
        let result = command.output().unwrap();
        assert_eq!(
            full_state(&h),
            before,
            "direct unproven caller changed owner state"
        );
        HookOutput {
            code: result.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
        }
        .refused();
        assert_no_wake(&[&endpoint]);
        owner.assert_alive();
    }
}

#[test]
fn authenticated_owner_cannot_address_another_instances_name() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("namedowner{suffix}");
    let other = format!("namedother{suffix}");
    let sid = format!("sid-named-{suffix}");
    let owner = HookProcess::spawn(&h, "named-owner", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &owner, &name);
    let endpoint = probe();
    owner
        .run(
            &h,
            &start_command(
                &sid,
                &h.workspace.join("named.jsonl"),
                &h.workspace,
                &endpoint,
            ),
        )
        .ok();
    db(&h).execute("INSERT INTO instances (name,tool,session_id,status,created_at) VALUES (?1,'omp',?2,'active',1235.5)", rusqlite::params![other, format!("sid-other-{suffix}")]).unwrap();
    let unread = seed_message(
        &h,
        &other,
        "fixture-sender",
        "other owner's payload",
        "mentions",
        "",
    );
    for command in refused_commands(&other, &format!("sid-other-{suffix}"), unread) {
        let before = full_state(&h);
        let result = owner.run(&h, &command);
        assert_eq!(
            full_state(&h),
            before,
            "valid identity mutated a different --name: {command}"
        );
        result.refused();
        assert_no_wake(&[&endpoint]);
    }
}

#[test]
fn descendant_explicit_start_cannot_reclaim_live_or_soft_stopped_owner() {
    for launcher in [true, false] {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let sid = format!("sid-explicit-{suffix}");
        let id = launcher.then(launcher_id);
        let mut owner = HookProcess::spawn(&h, "explicit-owner", "omp", id.as_deref(), false);
        let endpoint = probe();
        let path = h.workspace.join(format!("{sid}.jsonl"));
        let expected = format!("explicit{suffix}");
        if launcher {
            seed_launch(&h, &owner, &expected);
        }
        let bound = owner
            .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
            .ok();
        let name = bound["name"]
            .as_str()
            .expect("explicit owner name")
            .to_string();
        if !launcher {
            // A fresh plain mint now pins its actual owner. Seed the PID-less
            // row plain mints left through 0.7.60, so the launcherless pass
            // still covers that owner history.
            db(&h)
                .execute("UPDATE instances SET pid=NULL WHERE name=?1", [&name])
                .unwrap();
        }
        owner.run(&h, &format!("export HCOM_INSTANCE_NAME={}", quote(&name)));
        seed_message(
            &h,
            &name,
            "fixture-sender",
            "do not consume during reclaim",
            "mentions",
            "",
        );
        for state in ["live", "soft-stopped", "released"] {
            if state == "soft-stopped" {
                owner
                    .run(
                        &h,
                        &format!("H omp-stop --name {} --soft --reason restart", quote(&name)),
                    )
                    .ok();
                discard_setup_wakes(&endpoint);
            } else if state == "released" {
                owner
                    .run(
                        &h,
                        &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
                    )
                    .ok();
                discard_setup_wakes(&endpoint);
                let stopped = assert_released_history(&h, &name, &owner.process_id);
                if !launcher {
                    assert!(
                        stopped["snapshot"]["pid"].is_null(),
                        "the launcherless regression must cover PID-less owner history"
                    );
                }
            }
            // Use the binary directly: neither tool hints nor dropping the
            // inherited ID grants a child the stopped parent's identity.
            for tool in ["omp", "claude", ""] {
                let environment = if tool.is_empty() {
                    "env -u HCOM_TOOL HCOM_LAUNCHED=1".to_string()
                } else {
                    format!("env HCOM_TOOL={tool} HCOM_LAUNCHED=1")
                };
                for identity in ["inherited", "absent", "own-minted"] {
                    let identity_env = match identity {
                        "absent" => "env -u HCOM_PROCESS_ID",
                        "own-minted" => "env HCOM_PROCESS_ID=omp-$$-3-4",
                        _ => "env",
                    };
                    let command = format!(
                        "{identity_env} {environment} \"$TEST_BIN\" start --as {}",
                        quote(&name),
                    );
                    let before = full_state(&h);
                    let output = owner.descendant(&h, &command);
                    assert_eq!(
                        full_state(&h),
                        before,
                        "descendant explicit start changed owner state: launcher={launcher}, state={state}, tool={tool}, identity={identity}; {} {}",
                        output.stdout,
                        output.stderr
                    );
                    assert_ne!(
                        output.code, 0,
                        "descendant explicit start was admitted: {}",
                        output.stdout
                    );
                    assert_no_wake(&[&endpoint]);
                    owner.assert_alive();
                }
            }
        }
        let rejoin = owner.run(&h, &format!("H start --as {}", quote(&name)));
        assert_eq!(
            rejoin.code, 0,
            "genuine owner could not explicitly rejoin: {} {}",
            rejoin.stdout, rejoin.stderr
        );
        let bound: String = db(&h)
            .query_row(
                "SELECT instance_name FROM process_bindings WHERE process_id=?1 AND session_id=?2",
                rusqlite::params![owner.process_id, sid],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(bound, name);
    }
}

#[test]
fn a_fresh_omp_can_reclaim_a_released_pidless_owner_only_after_it_exits() {
    for identity in ["absent", "own-minted"] {
        let h = isolated_hcom();
        let sid = format!("sid-dead-reclaim-{}", unique_suffix());
        let owner = HookProcess::spawn(&h, "dead-reclaim-owner", "omp", None, false);
        let endpoint = probe();
        let path = h.workspace.join(format!("{sid}.jsonl"));
        let response = owner
            .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
            .ok();
        let name = response["name"].as_str().unwrap().to_string();
        let cursor = seed_message(&h, &name, "fixture-sender", "already read", "mentions", "");
        seed_message(&h, &name, "fixture-sender", "still unread", "mentions", "");
        db(&h)
            .execute(
                "UPDATE instances SET pid=NULL,last_event_id=?2 WHERE name=?1",
                rusqlite::params![name, cursor],
            )
            .unwrap();
        owner
            .run(
                &h,
                &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
            )
            .ok();
        let stopped = assert_released_history(&h, &name, &owner.process_id);
        assert!(stopped["snapshot"]["pid"].is_null());
        assert_eq!(stopped["snapshot"]["session_id"], sid);
        assert_eq!(stopped["snapshot"]["last_event_id"], cursor);
        let dead_pid = owner.owner_pid;
        // Drop kills and reaps only this fixture's owned process group.
        drop(owner);
        assert!(!Path::new(&format!("/proc/{dead_pid}")).exists());
        let mut fresh = HookProcess::spawn(&h, "dead-reclaim-fresh", "omp", None, false);
        let identity_env = match identity {
            "absent" => "env -u HCOM_PROCESS_ID",
            _ => "env",
        };
        let result = fresh.run(
            &h,
            &format!(
                "{identity_env} HCOM_TOOL=omp HCOM_LAUNCHED=1 \"$TEST_BIN\" start --as {}",
                quote(&name)
            ),
        );
        assert_eq!(
            result.code, 0,
            "dead PID-less owner reclaim failed: identity={identity}; {} {}",
            result.stdout, result.stderr
        );
        let conn = db(&h);
        let row: (String, i64, Option<i64>, String) = conn
            .query_row(
                "SELECT session_id,last_event_id,pid,transcript_path FROM instances WHERE name=?1",
                [&name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(row.0, sid);
        assert_eq!(row.1, cursor);
        assert_ne!(
            row.2,
            Some(i64::from(dead_pid)),
            "restored a dead owner pid"
        );
        assert_eq!(row.3, path.to_string_lossy().into_owned());
        let session_owner: String = conn
            .query_row(
                "SELECT instance_name FROM session_bindings WHERE session_id=?1",
                [&sid],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(session_owner, name);
        let mut query = conn
            .prepare("SELECT process_id,session_id,instance_name FROM process_bindings ORDER BY process_id")
            .unwrap();
        let bindings: Vec<(String, String, String)> = query
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let expected = if identity == "absent" {
            Vec::new()
        } else {
            vec![(fresh.process_id.clone(), sid.clone(), name.clone())]
        };
        assert_eq!(
            bindings, expected,
            "reclaim bound an old or unrelated process id"
        );
        let data: String = conn
            .query_row(
                "SELECT data FROM events WHERE type='life' AND instance=?1
                   AND json_extract(data,'$.reason')='reclaim' ORDER BY id DESC LIMIT 1",
                [&name],
                |row| row.get(0),
            )
            .unwrap();
        let reclaimed: Value = serde_json::from_str(&data).unwrap();
        assert_eq!(reclaimed["anchor"]["restored"], false);
        fresh.assert_alive();
    }
}

#[test]
fn an_independent_omp_cannot_reclaim_a_live_released_owner_with_an_incarnation() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("releasedtuple{suffix}");
    let sid = format!("sid-released-tuple-{suffix}");
    let mut owner = HookProcess::spawn(&h, "tuple-owner", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &owner, &name);
    let endpoint = probe();
    owner
        .run(
            &h,
            &start_command(
                &sid,
                &h.workspace.join(format!("{sid}.jsonl")),
                &h.workspace,
                &endpoint,
            ),
        )
        .ok();
    owner
        .run(
            &h,
            &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
        )
        .ok();
    let stopped = assert_released_history(&h, &name, &owner.process_id);
    assert_eq!(stopped["snapshot"]["pid"], owner.owner_pid);
    assert!(stopped["snapshot"]["pid_start_time"].as_u64().is_some());
    assert!(
        stopped["snapshot"]["boot_id"]
            .as_str()
            .is_some_and(|boot| !boot.is_empty())
    );
    discard_setup_wakes(&endpoint);
    let mut foreign = HookProcess::spawn(&h, "tuple-foreign", "omp", None, false);
    for identity_env in ["env -u HCOM_PROCESS_ID", "env"] {
        let before = full_state(&h);
        let result = foreign.run(
            &h,
            &format!(
                "{identity_env} HCOM_TOOL=omp HCOM_LAUNCHED=1 \"$TEST_BIN\" start --as {}",
                quote(&name)
            ),
        );
        assert_eq!(
            full_state(&h),
            before,
            "independent caller changed a live historical owner: {identity_env}; {} {}",
            result.stdout,
            result.stderr
        );
        assert_ne!(result.code, 0, "independent caller reclaimed a live owner");
        assert_no_wake(&[&endpoint]);
        owner.assert_alive();
        foreign.assert_alive();
    }
}

#[test]
fn live_released_owner_with_incarnation_refuses_a_hook_recreation() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("releasedhook{suffix}");
    let sid = format!("sid-released-hook-{suffix}");
    let mut owner = HookProcess::spawn(
        &h,
        "released-hook-owner",
        "omp",
        Some(&launcher_id()),
        false,
    );
    seed_launch(&h, &owner, &name);
    let endpoint = probe();
    let foreign_endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    assert_eq!(
        owner
            .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
            .ok()["name"],
        name
    );
    owner
        .run(
            &h,
            &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
        )
        .ok();
    let stopped = assert_released_history(&h, &name, &owner.process_id);
    assert_eq!(stopped["snapshot"]["pid"], owner.owner_pid);
    assert!(stopped["snapshot"]["pid_start_time"].as_u64().is_some());
    assert!(
        stopped["snapshot"]["boot_id"]
            .as_str()
            .is_some_and(|boot| !boot.is_empty())
    );
    owner.assert_alive();
    let mut foreign = HookProcess::spawn(&h, "released-hook-foreign", "omp", None, false);
    discard_setup_wakes(&endpoint);
    let before = full_state(&h);
    let output = foreign.run(
        &h,
        &start_command(&sid, &path, &h.workspace, &foreign_endpoint),
    );
    assert_eq!(
        full_state(&h),
        before,
        "independent hook recreated a live released owner: {} {}",
        output.stdout,
        output.stderr
    );
    output.refused();
    assert_no_wake(&[&endpoint, &foreign_endpoint]);
    owner.assert_alive();
    foreign.assert_alive();
}

#[test]
fn older_session_hook_cannot_reclaim_name_released_by_a_newer_live_owner() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("newestlive{suffix}");
    let first_sid = format!("sid-older-live-{suffix}");
    let second_sid = format!("sid-newer-live-{suffix}");
    let first_path = h.workspace.join(format!("{first_sid}.jsonl"));
    let second_path = h.workspace.join(format!("{second_sid}.jsonl"));
    let first_endpoint = probe();
    let second_endpoint = probe();
    let incoming_endpoint = probe();

    let mut first = HookProcess::spawn(&h, "older-live-first", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &first, &name);
    assert_eq!(
        first
            .run(
                &h,
                &start_command(&first_sid, &first_path, &h.workspace, &first_endpoint),
            )
            .ok()["name"],
        name
    );
    assert_bound(&h, &first, &name, &first_sid, &first_path, &h.workspace);
    first
        .run(
            &h,
            &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
        )
        .ok();
    let first_stop = assert_released_history(&h, &name, &first.process_id);
    assert_eq!(first_stop["snapshot"]["session_id"], first_sid);
    assert_eq!(first_stop["snapshot"]["pid"], first.owner_pid);
    assert!(first_stop["snapshot"]["pid_start_time"].as_u64().is_some());
    assert!(
        first_stop["snapshot"]["boot_id"]
            .as_str()
            .is_some_and(|boot| !boot.is_empty())
    );
    let first_event_id: i64 = db(&h)
        .query_row(
            "SELECT id FROM events WHERE type='life' AND instance=?1
               AND json_extract(data,'$.action')='stopped' ORDER BY id DESC LIMIT 1",
            [&name],
            |row| row.get(0),
        )
        .unwrap();
    let first_pid = first.owner_pid;
    trigger_step(&first.out_dir, first.next_step.get(), "exit 0");
    let first_exit = h.eventually("older owner exited", Duration::from_secs(30), || {
        Ok(first.child.try_wait().expect("reap older owner"))
    });
    assert!(first_exit.success(), "older owner did not exit normally");
    assert!(!Path::new(&format!("/proc/{first_pid}")).exists());
    drop(first);

    let mut second = HookProcess::spawn(&h, "older-live-second", "omp", None, false);
    let initial = second
        .run(
            &h,
            &start_command(&second_sid, &second_path, &h.workspace, &second_endpoint),
        )
        .ok();
    let initial_name = initial["name"].as_str().unwrap();
    assert_ne!(initial_name, name);
    assert_bound(
        &h,
        &second,
        initial_name,
        &second_sid,
        &second_path,
        &h.workspace,
    );
    // The existing process binding supplies S2 to --as; the following
    // ordinary hook pins its new name to P2 rather than P1's dead anchor.
    let reclaim = second.run(&h, &format!("H start --as {}", quote(&name)));
    assert_eq!(
        reclaim.code, 0,
        "newer owner could not reclaim the dead owner's name: {} {}",
        reclaim.stdout, reclaim.stderr
    );
    let reclaimed: (String, String, String) = db(&h)
        .query_row(
            "SELECT i.session_id,p.instance_name,s.instance_name FROM instances i
               JOIN process_bindings p ON p.instance_name=i.name AND p.session_id=i.session_id
               JOIN session_bindings s ON s.session_id=i.session_id
               WHERE i.name=?1 AND p.process_id=?2",
            rusqlite::params![name, second.process_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        reclaimed,
        (second_sid.clone(), name.clone(), name.clone()),
        "--as did not transfer P2's existing session and bindings to N"
    );
    assert_eq!(
        second
            .run(
                &h,
                &start_command(&second_sid, &second_path, &h.workspace, &second_endpoint),
            )
            .ok()["name"],
        name
    );
    assert_bound(&h, &second, &name, &second_sid, &second_path, &h.workspace);
    second
        .run(
            &h,
            &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
        )
        .ok();
    let second_stop = assert_released_history(&h, &name, &second.process_id);
    assert_eq!(second_stop["snapshot"]["session_id"], second_sid);
    assert_eq!(second_stop["snapshot"]["pid"], second.owner_pid);
    assert!(second_stop["snapshot"]["pid_start_time"].as_u64().is_some());
    assert!(
        second_stop["snapshot"]["boot_id"]
            .as_str()
            .is_some_and(|boot| !boot.is_empty())
    );
    let latest_by_name: (i64, String, String) = db(&h)
        .query_row(
            "SELECT id,instance,data FROM events WHERE type='life' AND instance=?1
               AND json_extract(data,'$.action')='stopped' ORDER BY id DESC LIMIT 1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert!(latest_by_name.0 > first_event_id);
    assert_eq!(latest_by_name.1, name);
    assert_eq!(
        serde_json::from_str::<Value>(&latest_by_name.2).unwrap(),
        second_stop
    );
    let latest_by_first_session: (i64, String, String) = db(&h)
        .query_row(
            "SELECT id,instance,data FROM events WHERE type='life'
               AND json_extract(data,'$.action')='stopped'
               AND json_extract(data,'$.snapshot.session_id')=?1 ORDER BY id DESC LIMIT 1",
            [&first_sid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(latest_by_first_session.0, first_event_id);
    assert_eq!(latest_by_first_session.1, name);
    assert_eq!(
        serde_json::from_str::<Value>(&latest_by_first_session.2).unwrap(),
        first_stop
    );
    second.assert_alive();

    let caller = HookProcess::spawn(&h, "older-live-caller", "omp", None, false);
    assert_eq!(caller.process_id, format!("omp-{}-1-1", caller.owner_pid));
    discard_setup_wakes(&first_endpoint);
    discard_setup_wakes(&second_endpoint);
    let before = full_state(&h);
    let output = caller.run(
        &h,
        &start_command(&first_sid, &first_path, &h.workspace, &incoming_endpoint),
    );
    let after = full_state(&h);
    let second_still_alive = second
        .child
        .try_wait()
        .expect("poll newer released owner")
        .is_none()
        && Path::new(&format!("/proc/{}", second.owner_pid)).exists();
    // Reap both private fixtures before the intentionally failing base
    // assertion; retain the post-hook state and liveness observation.
    drop(caller);
    drop(second);
    assert_eq!(
        after, before,
        "older session's dead history stole a newer live owner's released name: {} {}",
        output.stdout, output.stderr
    );
    output.refused();
    assert_no_wake(&[&first_endpoint, &second_endpoint, &incoming_endpoint]);
    assert!(
        second_still_alive,
        "newer released owner exited during the hook"
    );
}

#[test]
fn older_session_hook_can_resume_after_the_newest_released_owner_exits() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("newestdead{suffix}");
    let first_sid = format!("sid-older-dead-{suffix}");
    let second_sid = format!("sid-newer-dead-{suffix}");
    let first_path = h.workspace.join(format!("{first_sid}.jsonl"));
    let second_path = h.workspace.join(format!("{second_sid}.jsonl"));
    let first_endpoint = probe();
    let second_endpoint = probe();
    let incoming_endpoint = probe();

    let mut first = HookProcess::spawn(&h, "older-dead-first", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &first, &name);
    assert_eq!(
        first
            .run(
                &h,
                &start_command(&first_sid, &first_path, &h.workspace, &first_endpoint),
            )
            .ok()["name"],
        name
    );
    assert_bound(&h, &first, &name, &first_sid, &first_path, &h.workspace);
    first
        .run(
            &h,
            &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
        )
        .ok();
    let first_stop = assert_released_history(&h, &name, &first.process_id);
    assert_eq!(first_stop["snapshot"]["session_id"], first_sid);
    assert_eq!(first_stop["snapshot"]["pid"], first.owner_pid);
    assert!(first_stop["snapshot"]["pid_start_time"].as_u64().is_some());
    assert!(
        first_stop["snapshot"]["boot_id"]
            .as_str()
            .is_some_and(|boot| !boot.is_empty())
    );
    let first_event_id: i64 = db(&h)
        .query_row(
            "SELECT id FROM events WHERE type='life' AND instance=?1
               AND json_extract(data,'$.action')='stopped' ORDER BY id DESC LIMIT 1",
            [&name],
            |row| row.get(0),
        )
        .unwrap();
    let first_pid = first.owner_pid;
    trigger_step(&first.out_dir, first.next_step.get(), "exit 0");
    let first_exit = h.eventually("older owner exited", Duration::from_secs(30), || {
        Ok(first.child.try_wait().expect("reap older owner"))
    });
    assert!(first_exit.success(), "older owner did not exit normally");
    assert!(!Path::new(&format!("/proc/{first_pid}")).exists());
    drop(first);

    let mut second = HookProcess::spawn(&h, "older-dead-second", "omp", None, false);
    let initial = second
        .run(
            &h,
            &start_command(&second_sid, &second_path, &h.workspace, &second_endpoint),
        )
        .ok();
    let initial_name = initial["name"].as_str().unwrap();
    assert_ne!(initial_name, name);
    assert_bound(
        &h,
        &second,
        initial_name,
        &second_sid,
        &second_path,
        &h.workspace,
    );
    let reclaim = second.run(&h, &format!("H start --as {}", quote(&name)));
    assert_eq!(
        reclaim.code, 0,
        "newer owner could not reclaim the dead owner's name: {} {}",
        reclaim.stdout, reclaim.stderr
    );
    let reclaimed: (String, String, String) = db(&h)
        .query_row(
            "SELECT i.session_id,p.instance_name,s.instance_name FROM instances i
               JOIN process_bindings p ON p.instance_name=i.name AND p.session_id=i.session_id
               JOIN session_bindings s ON s.session_id=i.session_id
               WHERE i.name=?1 AND p.process_id=?2",
            rusqlite::params![name, second.process_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        reclaimed,
        (second_sid.clone(), name.clone(), name.clone()),
        "--as did not transfer P2's existing session and bindings to N"
    );
    assert_eq!(
        second
            .run(
                &h,
                &start_command(&second_sid, &second_path, &h.workspace, &second_endpoint),
            )
            .ok()["name"],
        name
    );
    assert_bound(&h, &second, &name, &second_sid, &second_path, &h.workspace);
    second
        .run(
            &h,
            &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
        )
        .ok();
    let second_stop = assert_released_history(&h, &name, &second.process_id);
    assert_eq!(second_stop["snapshot"]["session_id"], second_sid);
    assert_eq!(second_stop["snapshot"]["pid"], second.owner_pid);
    assert!(second_stop["snapshot"]["pid_start_time"].as_u64().is_some());
    assert!(
        second_stop["snapshot"]["boot_id"]
            .as_str()
            .is_some_and(|boot| !boot.is_empty())
    );
    let latest_by_name: (i64, String, String) = db(&h)
        .query_row(
            "SELECT id,instance,data FROM events WHERE type='life' AND instance=?1
               AND json_extract(data,'$.action')='stopped' ORDER BY id DESC LIMIT 1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert!(latest_by_name.0 > first_event_id);
    assert_eq!(latest_by_name.1, name);
    assert_eq!(
        serde_json::from_str::<Value>(&latest_by_name.2).unwrap(),
        second_stop
    );
    let latest_by_first_session: (i64, String, String) = db(&h)
        .query_row(
            "SELECT id,instance,data FROM events WHERE type='life'
               AND json_extract(data,'$.action')='stopped'
               AND json_extract(data,'$.snapshot.session_id')=?1 ORDER BY id DESC LIMIT 1",
            [&first_sid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(latest_by_first_session.0, first_event_id);
    assert_eq!(latest_by_first_session.1, name);
    assert_eq!(
        serde_json::from_str::<Value>(&latest_by_first_session.2).unwrap(),
        first_stop
    );
    let second_pid = second.owner_pid;
    trigger_step(&second.out_dir, second.next_step.get(), "exit 0");
    let second_exit = h.eventually("newer owner exited", Duration::from_secs(30), || {
        Ok(second.child.try_wait().expect("reap newer owner"))
    });
    assert!(second_exit.success(), "newer owner did not exit normally");
    assert!(!Path::new(&format!("/proc/{second_pid}")).exists());
    drop(second);

    let caller = HookProcess::spawn(&h, "older-dead-caller", "omp", None, false);
    assert_eq!(caller.process_id, format!("omp-{}-1-1", caller.owner_pid));
    let restored = caller
        .run(
            &h,
            &start_command(&first_sid, &first_path, &h.workspace, &incoming_endpoint),
        )
        .ok();
    assert_eq!(restored["name"], name);
    assert_bound(&h, &caller, &name, &first_sid, &first_path, &h.workspace);
    let counts: (i64, i64, i64) = db(&h)
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM instances),
                (SELECT COUNT(*) FROM process_bindings),
                (SELECT COUNT(*) FROM session_bindings)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        counts,
        (1, 1, 1),
        "resume duplicated or retained an old owner"
    );
}

#[test]
fn child_own_minted_identity_cannot_recreate_a_released_parent() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("releasedparent{suffix}");
    let sid = format!("sid-released-parent-{suffix}");
    let mut parent = HookProcess::spawn(&h, "released-parent", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &parent, &name);
    let parent_endpoint = probe();
    let child_endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    assert_eq!(
        parent
            .run(
                &h,
                &start_command(&sid, &path, &h.workspace, &parent_endpoint),
            )
            .ok()["name"],
        name
    );
    parent
        .run(
            &h,
            &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
        )
        .ok();
    let stopped = assert_released_history(&h, &name, &parent.process_id);
    assert_eq!(stopped["snapshot"]["pid"], parent.owner_pid);
    assert!(stopped["snapshot"]["pid_start_time"].as_u64().is_some());
    assert!(
        stopped["snapshot"]["boot_id"]
            .as_str()
            .is_some_and(|boot| !boot.is_empty())
    );
    parent.assert_alive();
    let child_cwd = h.root_path().join("released-parent-child");
    fs::create_dir_all(&child_cwd).unwrap();
    let child_path = child_cwd.join(format!("{sid}.jsonl"));
    discard_setup_wakes(&parent_endpoint);
    let before = full_state(&h);
    let output = parent.descendant(
        &h,
        &format!(
            "cd {} || exit 1; export HCOM_PROCESS_ID=omp-$$-7-8; {}",
            quote(&child_cwd.to_string_lossy()),
            start_command(&sid, &child_path, &child_cwd, &child_endpoint),
        ),
    );
    assert_eq!(
        full_state(&h),
        before,
        "child's valid new identity recreated its live released parent: {} {}",
        output.stdout,
        output.stderr
    );
    output.refused();
    assert_no_wake(&[&parent_endpoint, &child_endpoint]);
    parent.assert_alive();
}

#[test]
fn historical_omp_reclaim_refuses_unknown_evidence_without_a_refused_id() {
    for evidence in [
        "missing-owner",
        "malformed-owner",
        "malformed-minted-id",
        "partial-incarnation",
        "malformed-incarnation",
        "pidless-stored-minted",
        "stored-minted-without-tool",
        "unreadable-json",
    ] {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let name = format!("unknownhistory{suffix}");
        let sid = format!("sid-unknown-history-{suffix}");
        let mut owner = HookProcess::spawn(&h, "history-owner", "omp", None, false);
        let endpoint = probe();
        let mut snapshot = json!({
            "name": name,
            "session_id": sid,
            "tool": "omp",
            "directory": h.workspace,
            "transcript_path": h.workspace.join(format!("{sid}.jsonl")),
            "created_at": 1000.0,
            "last_event_id": 0,
            "name_announced": 1,
            "pid": null,
        });
        let mut stored_id = Some(owner.process_id.as_str());
        match evidence {
            "missing-owner" => stored_id = None,
            "malformed-owner" => snapshot["pid"] = json!(-1),
            "malformed-minted-id" => stored_id = Some("omp-not-a-pid-1-1"),
            "partial-incarnation" => {
                snapshot["pid"] = json!(owner.owner_pid);
                snapshot["pid_start_time"] = json!(7);
            }
            "malformed-incarnation" => {
                snapshot["pid"] = json!(owner.owner_pid);
                snapshot["pid_start_time"] = json!("not-a-start-time");
                snapshot["boot_id"] = json!("fixture-boot");
            }
            "stored-minted-without-tool" => {
                snapshot.as_object_mut().unwrap().remove("tool");
            }
            "pidless-stored-minted" | "unreadable-json" => {}
            _ => unreachable!(),
        }
        let conn = db(&h);
        conn.execute(
            "INSERT INTO events (timestamp,type,instance,data) VALUES ('2026-09-01T00:00:00+00:00','life',?1,?2)",
            rusqlite::params![name, json!({
                "action": "stopped",
                "by": "session",
                "reason": "exit:shutdown",
                "process_id": stored_id,
                "snapshot": snapshot,
            }).to_string()],
        ).unwrap();
        if evidence == "unreadable-json" {
            conn.execute(
                "UPDATE events SET data='{' WHERE id=?1",
                [conn.last_insert_rowid()],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO notify_endpoints (instance,kind,port,updated_at) VALUES (?1,'plugin',?2,1234.5)",
            rusqlite::params![name, endpoint.local_addr().unwrap().port()],
        ).unwrap();
        drop(conn);
        let mut caller = HookProcess::spawn(&h, "history-caller", "omp", None, false);
        for identity_env in ["env -u HCOM_PROCESS_ID", "env"] {
            let before = full_state(&h);
            let result = caller.run(
                &h,
                &format!(
                    "{identity_env} HCOM_TOOL=omp HCOM_LAUNCHED=1 \"$TEST_BIN\" start --as {}",
                    quote(&name)
                ),
            );
            assert_eq!(
                full_state(&h),
                before,
                "unproved historical OMP reclaim changed state: {evidence}, {identity_env}; {} {}",
                result.stdout,
                result.stderr
            );
            assert_ne!(
                result.code, 0,
                "unproved historical OMP reclaim was admitted: {evidence}"
            );
            assert_no_wake(&[&endpoint]);
            owner.assert_alive();
            caller.assert_alive();
        }
    }
}

#[test]
fn shared_worker_with_omp_comm_cannot_authenticate_its_launcher_uuid() {
    for executable in ["__omp_worker_daemon", "__omp_worker_daemon_broker"] {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let name = format!("daemon{suffix}");
        let sid = format!("sid-daemon-{suffix}");
        let mut worker =
            HookProcess::spawn(&h, "script-worker", executable, Some(&launcher_id()), false);
        assert_eq!(
            fs::read_to_string(format!("/proc/{}/comm", worker.owner_pid))
                .unwrap()
                .trim(),
            "omp",
            "fixture must exercise the worker's pre-rename comm",
        );
        seed_launch(&h, &worker, &name);
        let endpoint = probe();
        let unread = seed_message(
            &h,
            &name,
            "fixture-sender",
            "daemon is not a seat",
            "mentions",
            "",
        );
        let mut commands = vec![start_command(
            &sid,
            &h.workspace.join("daemon.jsonl"),
            &h.workspace,
            &endpoint,
        )];
        commands.extend(refused_commands(&name, &sid, unread));
        for command in commands {
            let before = full_state(&h);
            let output = worker.run(&h, &command);
            assert_eq!(
                full_state(&h),
                before,
                "shared script worker was treated as an OMP seat: {executable}, {command}"
            );
            output.refused();
            assert_no_wake(&[&endpoint]);
            worker.assert_alive();
        }
    }
}

#[test]
fn legacy_bound_owners_need_no_new_receipt_before_their_first_hook() {
    for shape in ["gnome-seat", "canonical-resume", "headless", "pty-only"] {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let name = format!("legacy{suffix}");
        let sid = format!("sid-legacy-{suffix}");
        let mut owner = HookProcess::spawn(&h, shape, "omp", Some(&launcher_id()), false);
        let endpoint = probe();
        let path = h.workspace.join(format!("{sid}.jsonl"));
        fs::write(
            &path,
            json!({"type":"session","id":sid,"cwd":h.workspace}).to_string(),
        )
        .unwrap();
        let conn = db(&h);
        // Seed only the pre-guard schema's ordinary row and bindings. No
        // omp-start or registration has run for this process after upgrade.
        conn.execute(
            "INSERT INTO instances (name,tool,session_id,pid,status,status_context,created_at,directory,transcript_path,background,terminal_preset_effective,launch_context)
             VALUES (?1,'omp',?2,?3,'listening','start',1234.5,?4,?5,?6,?7,?8)",
            rusqlite::params![
                name, sid, owner.owner_pid, h.workspace.to_string_lossy(), path.to_string_lossy(),
                i64::from(shape == "headless"),
                if shape == "gnome-seat" { "gnome-terminal" } else { "" },
                if shape == "gnome-seat" { "{\"launch_mode\":\"new-window\",\"terminal\":\"gnome-terminal\"}" } else { "{}" },
            ],
        ).unwrap();
        conn.execute(
            "INSERT INTO process_bindings (process_id,session_id,instance_name,updated_at) VALUES (?1,?2,?3,1234.5)",
            rusqlite::params![owner.process_id, sid, name],
        ).unwrap();
        conn.execute(
            "INSERT INTO session_bindings (session_id,instance_name,created_at) VALUES (?1,?2,1234.5)",
            rusqlite::params![sid, name],
        ).unwrap();
        if shape == "pty-only" {
            conn.execute(
                "INSERT INTO notify_endpoints (instance,kind,port,updated_at) VALUES (?1,'pty',?2,1234.5)",
                rusqlite::params![name, endpoint.local_addr().unwrap().port()],
            ).unwrap();
        }
        drop(conn);
        let unread = seed_message(
            &h,
            &name,
            "fixture-sender",
            "legacy pending payload",
            "mentions",
            "",
        );
        let before = full_state(&h);
        let first = owner.run(&h, &format!("H omp-read --name {} --check", quote(&name)));
        assert_eq!(
            (first.code, first.stdout.trim()),
            (0, "true"),
            "legacy first hook failed for {shape}: {}",
            first.stderr
        );
        assert_eq!(
            full_state(&h),
            before,
            "legacy first read required a receipt or changed state for {shape}"
        );
        let mail = owner
            .run(&h, &format!("H omp-read --name {}", quote(&name)))
            .ok();
        assert_eq!(
            mail[0]["event_id"], unread,
            "legacy {shape} could not read its pending mail"
        );
        assert_eq!(
            owner
                .run(
                    &h,
                    &format!("H omp-read --name {} --ack --up-to {unread}", quote(&name))
                )
                .ok()["acked_to"],
            unread
        );
        owner
            .run(
                &h,
                &format!(
                    "H omp-stop --name {} --soft --reason shutdown",
                    quote(&name)
                ),
            )
            .ok();
        owner
            .run(
                &h,
                &format!("H omp-stop --name {} --reason shutdown", quote(&name)),
            )
            .ok();
        let remaining: i64 = db(&h)
            .query_row(
                "SELECT COUNT(*) FROM instances WHERE name=?1",
                [&name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0, "legacy {shape} could not release its own row");
        owner.assert_alive();
    }
}

#[test]
fn explicit_name_cannot_move_another_owners_live_row_to_a_safe_target() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("renameowner{suffix}");
    let target = format!("renametarget{suffix}");
    let sid = format!("sid-renameowner-{suffix}");
    let mut owner = HookProcess::spawn(&h, "rename-owner", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &owner, &name);
    let endpoint = probe();
    owner
        .run(
            &h,
            &start_command(
                &sid,
                &h.workspace.join("rename-owner.jsonl"),
                &h.workspace,
                &endpoint,
            ),
        )
        .ok();
    db(&h).execute(
        "INSERT INTO events (timestamp,type,instance,data) VALUES ('2026-09-01T00:00:00+00:00','life',?1,?2)",
        rusqlite::params![target, json!({
            "action":"stopped","by":"session","reason":"exit:shutdown",
            "snapshot":{"name":target,"tool":"omp","directory":h.workspace,"session_id":format!("sid-target-{suffix}"),"last_event_id":0}
        }).to_string()],
    ).unwrap();
    for identity_env in ["env -u HCOM_PROCESS_ID", "env HCOM_PROCESS_ID=omp-$$-5-6"] {
        let command = format!(
            "{identity_env} HCOM_TOOL=omp \"$TEST_BIN\" --name {} start --as {}",
            quote(&name),
            quote(&target),
        );
        let before = full_state(&h);
        let output = owner.descendant(&h, &command);
        assert_eq!(
            full_state(&h),
            before,
            "explicit --name moved the live owner to a safe target: {} {}",
            output.stdout,
            output.stderr
        );
        assert_ne!(output.code, 0, "explicit --name borrowed a different owner");
        assert_no_wake(&[&endpoint]);
        owner.assert_alive();
    }
}

#[test]
fn genuine_minted_owner_can_explicitly_rejoin_a_pidless_row() {
    let h = isolated_hcom();
    let sid = format!("sid-pidless-{}", unique_suffix());
    let mut owner = HookProcess::spawn(&h, "pidless-owner", "omp", None, false);
    let expected = format!("pidless{}", unique_suffix());
    seed_launch(&h, &owner, &expected);
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    let response = owner
        .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
        .ok();
    let name = response["name"].as_str().expect("PIDless owner name");
    assert_eq!(name, expected);
    db(&h)
        .execute("UPDATE instances SET pid=NULL WHERE name=?1", [name])
        .unwrap();
    let result = owner.run(&h, &format!("H start --as {}", quote(name)));
    assert_eq!(
        result.code, 0,
        "genuine minted owner lost its PIDless binding: {} {}",
        result.stdout, result.stderr
    );
    let binding: String = db(&h)
        .query_row(
            "SELECT instance_name FROM process_bindings WHERE process_id=?1 AND session_id=?2",
            rusqlite::params![owner.process_id, sid],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(binding, name);
    owner.assert_alive();
}

#[test]
fn already_bound_wrapper_uuid_without_an_owner_pid_is_refused() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("legacywrapper{suffix}");
    let sid = format!("sid-legacywrapper-{suffix}");
    let mut owner = HookProcess::spawn(&h, "bound-wrapper", "omp", Some(&launcher_id()), true);
    seed_launch(&h, &owner, &name);
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    let conn = db(&h);
    // Unlike an initial placeholder, this pre-guard row already has a real
    // session but lost the launcher-to-OMP PID handoff. Its wrapper PID alone
    // cannot choose which OMP under that shared wrapper owns the row.
    conn.execute(
        "UPDATE instances SET session_id=?2,status='listening',status_context='start',directory=?3,transcript_path=?4 WHERE name=?1",
        rusqlite::params![name, sid, h.workspace.to_string_lossy(), path.to_string_lossy()],
    ).unwrap();
    conn.execute(
        "UPDATE process_bindings SET session_id=?2 WHERE process_id=?1",
        rusqlite::params![owner.process_id, sid],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO session_bindings (session_id,instance_name,created_at) VALUES (?1,?2,1234.5)",
        rusqlite::params![sid, name],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO notify_endpoints (instance,kind,port,updated_at) VALUES (?1,'pty',?2,1234.5)",
        rusqlite::params![name, endpoint.local_addr().unwrap().port()],
    )
    .unwrap();
    drop(conn);
    let unread = seed_message(
        &h,
        &name,
        "fixture-sender",
        "ambiguous wrapper must not consume",
        "mentions",
        "",
    );
    let mut commands = vec![start_command(&sid, &path, &h.workspace, &endpoint)];
    commands.extend(refused_commands(&name, &sid, unread));
    for command in commands {
        let before = full_state(&h);
        let output = owner.run(&h, &command);
        assert_eq!(
            full_state(&h),
            before,
            "ambiguous bound wrapper was silently reauthorized: {command}"
        );
        output.refused();
        assert_no_wake(&[&endpoint]);
        owner.assert_alive();
    }
}

#[test]
fn sibling_omp_first_bind_has_one_winner_and_the_loser_cannot_retry() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("claim{suffix}");
    let mut wrapper = HookProcess::spawn(
        &h,
        "claim-wrapper",
        "launcher-wrapper",
        Some(&launcher_id()),
        false,
    );
    let siblings = sibling_omps(&h, &wrapper);
    assert_ne!(siblings[0].1, siblings[1].1);
    for (_, pid) in &siblings {
        assert_eq!(
            fs::read_to_string(format!("/proc/{pid}/comm"))
                .unwrap()
                .trim(),
            "omp"
        );
    }
    seed_launch(&h, &wrapper, &name);
    let cursor = seed_message(
        &h,
        &name,
        "fixture-sender",
        "already consumed before first bind",
        "mentions",
        "",
    );
    let unread = seed_message(
        &h,
        &name,
        "fixture-sender",
        "retain this unread race payload",
        "mentions",
        "",
    );
    let payload: String = db(&h)
        .query_row("SELECT data FROM events WHERE id=?1", [unread], |row| {
            row.get(0)
        })
        .unwrap();
    db(&h)
        .execute(
            "UPDATE instances SET last_event_id=?2,name_announced=1 WHERE name=?1",
            rusqlite::params![name, cursor],
        )
        .unwrap();
    let endpoints = [probe(), probe()];
    let sids = [format!("sid-left-{suffix}"), format!("sid-right-{suffix}")];
    let cwds = [
        h.root_path().join("left-project"),
        h.root_path().join("right-project"),
    ];
    for cwd in &cwds {
        fs::create_dir_all(cwd).unwrap();
    }
    let paths = [cwds[0].join("left.jsonl"), cwds[1].join("right.jsonl")];
    let commands = [
        start_command(&sids[0], &paths[0], &cwds[0], &endpoints[0]),
        start_command(&sids[1], &paths[1], &cwds[1], &endpoints[1]),
    ];
    let barrier = h.root_path().join("release-first-bind");
    for index in 0..2 {
        trigger_step(
            &siblings[index].0,
            0,
            &format!(
                "while [ ! -e {} ]; do sleep 0.01; done; {}",
                quote(&barrier.to_string_lossy()),
                commands[index],
            ),
        );
    }
    fs::write(&barrier, "").expect("release sibling first-bind barrier");
    let outputs = [
        wait_step(&h, &siblings[0].0, 0),
        wait_step(&h, &siblings[1].0, 0),
    ];
    let results = [outputs[0].json(), outputs[1].json()];
    let winners: Vec<usize> = (0..2)
        .filter(|index| results[*index]["name"] == name)
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "expected exactly one first-bind winner: {results:?}"
    );
    let winner = winners[0];
    let loser = 1 - winner;
    outputs[winner].ok();
    outputs[loser].refused();
    let assert_winner = || {
        let conn = db(&h);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM instances", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "losing first bind minted or restored another row");
        let row: (String, String, String, i64) = conn
            .query_row(
                "SELECT session_id,transcript_path,directory,pid FROM instances WHERE name=?1",
                [&name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                sids[winner].clone(),
                paths[winner].to_string_lossy().into_owned(),
                cwds[winner].to_string_lossy().into_owned(),
                siblings[winner].1 as i64,
            ),
            "winning row contains the losing sibling's metadata or wrapper PID"
        );
        let binding: (String, String) = conn
            .query_row(
                "SELECT session_id,instance_name FROM process_bindings WHERE process_id=?1",
                [&wrapper.process_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(binding, (sids[winner].clone(), name.clone()));
        let mut statement = conn.prepare("SELECT session_id FROM session_bindings WHERE instance_name=?1 ORDER BY session_id").unwrap();
        let sessions = statement
            .query_map([&name], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            sessions,
            vec![sids[winner].clone()],
            "losing session obtained a binding"
        );
        let mut statement = conn
            .prepare("SELECT port FROM notify_endpoints WHERE instance=?1 ORDER BY port")
            .unwrap();
        let ports = statement
            .query_map([&name], |row| row.get::<_, u16>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            ports,
            vec![endpoints[winner].local_addr().unwrap().port()],
            "losing endpoint was registered"
        );
        let retained: (f64, i64, i64) = conn
            .query_row(
                "SELECT created_at,last_event_id,name_announced FROM instances WHERE name=?1",
                [&name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            retained,
            (1234.5, cursor, 1),
            "race replaced the incarnation or consumed unread mail"
        );
        let still_unread: String = conn
            .query_row("SELECT data FROM events WHERE id=?1", [unread], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(still_unread, payload, "race rewrote the unread event");
    };
    assert_winner();
    assert_no_wake(&[&endpoints[0], &endpoints[1]]);
    let before = full_state(&h);
    trigger_step(&siblings[loser].0, 1, &commands[loser]);
    let retry = wait_step(&h, &siblings[loser].0, 1);
    assert_eq!(
        full_state(&h),
        before,
        "losing sibling changed the winning incarnation on retry"
    );
    retry.refused();
    assert_no_wake(&[&endpoints[0], &endpoints[1]]);
    trigger_step(&siblings[winner].0, 1, &commands[winner]);
    assert_eq!(wait_step(&h, &siblings[winner].0, 1).ok()["name"], name);
    assert_winner();
    wrapper.assert_alive();
    for (_, pid) in &siblings {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("sibling OMP survived");
        let state = stat[stat.rfind(')').unwrap() + 2..]
            .split_whitespace()
            .next();
        assert_ne!(state, Some("Z"), "sibling OMP was signalled");
    }
}

#[test]
fn preset_resume_sid_does_not_prevent_the_recorded_owners_first_hook() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("preset{suffix}");
    let sid = format!("sid-preset-{suffix}");
    let mut owner = HookProcess::spawn(&h, "preset-wrapper", "omp", Some(&launcher_id()), true);
    seed_launch(&h, &owner, &name);
    // The launcher already knows the resume SID and has recorded its actual
    // OMP child. NULL in process_bindings still means this is the first hook;
    // the preset row SID must not turn that ordinary launch into a refusal.
    db(&h)
        .execute(
            "UPDATE instances SET session_id=?2,pid=?3 WHERE name=?1",
            rusqlite::params![name, sid, owner.owner_pid],
        )
        .unwrap();
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    assert!(!path.exists());
    let response = owner
        .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
        .ok();
    assert_eq!(response["name"], name);
    assert_bound(&h, &owner, &name, &sid, &path, &h.workspace);
    owner.assert_alive();
}

#[test]
fn wrapper_handoff_keeps_the_actual_owner_pid_on_the_canonical_row() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let placeholder = format!("launch{suffix}");
    let canonical = format!("canonicalpin{suffix}");
    let sid = format!("sid-canonicalpin-{suffix}");
    let mut owner = HookProcess::spawn(
        &h,
        "canonical-pin-wrapper",
        "omp",
        Some(&launcher_id()),
        true,
    );
    seed_launch(&h, &owner, &placeholder);
    let conn = db(&h);
    // An unowned inactive canonical row is a legitimate resume target. The
    // launch placeholder's wrapper PID must not overwrite its final OMP pin
    // when the binding/runtime state is moved to this different name.
    conn.execute(
        "INSERT INTO instances (name,tool,session_id,status,status_context,created_at,last_event_id,name_announced,pid)
         VALUES (?1,'omp',?2,'inactive','stopped',2345.5,42,1,NULL)",
        rusqlite::params![canonical,sid],
    ).unwrap();
    conn.execute(
        "INSERT INTO session_bindings (session_id,instance_name,created_at) VALUES (?1,?2,2345.5)",
        rusqlite::params![sid, canonical],
    )
    .unwrap();
    drop(conn);
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    let command = start_command(&sid, &path, &h.workspace, &endpoint);
    assert_eq!(owner.run(&h, &command).ok()["name"], canonical);
    assert_bound(&h, &owner, &canonical, &sid, &path, &h.workspace);
    let metadata: (f64, i64, i64) = db(&h)
        .query_row(
            "SELECT created_at,last_event_id,name_announced FROM instances WHERE name=?1",
            [&canonical],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        metadata,
        (2345.5, 42, 1),
        "handoff replaced the canonical identity"
    );
    assert_eq!(owner.run(&h, &command).ok()["name"], canonical);
    assert_bound(&h, &owner, &canonical, &sid, &path, &h.workspace);
    owner.assert_alive();
}

#[test]
fn child_own_minted_identity_cannot_recover_the_inactive_parents_name() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let sid = format!("sid-inactive-parent-{suffix}");
    let mut parent = HookProcess::spawn(&h, "inactive-name-parent", "omp", None, false);
    let parent_endpoint = probe();
    let child_endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    let response = parent
        .run(
            &h,
            &start_command(&sid, &path, &h.workspace, &parent_endpoint),
        )
        .ok();
    let name = response["name"]
        .as_str()
        .expect("inactive parent name")
        .to_string();
    db(&h)
        .execute(
            "UPDATE instances SET pid=?2 WHERE name=?1",
            rusqlite::params![name, parent.owner_pid],
        )
        .unwrap();
    seed_message(
        &h,
        &name,
        "fixture-sender",
        "inactive parent's unread payload",
        "mentions",
        "",
    );
    parent
        .run(
            &h,
            &format!(
                "export HCOM_INSTANCE_NAME={}; H omp-stop --name {} --soft --reason restart",
                quote(&name),
                quote(&name),
            ),
        )
        .ok();
    discard_setup_wakes(&parent_endpoint);
    let child_cwd = h.root_path().join("inactive-name-child");
    fs::create_dir_all(&child_cwd).unwrap();
    let child_sid = format!("sid-inactive-child-{suffix}");
    let child_path = child_cwd.join(format!("{child_sid}.jsonl"));
    let before = full_state(&h);
    let output = parent.descendant(
        &h,
        &format!(
            "export HCOM_PROCESS_ID=omp-$$-7-8; {}",
            start_command(&child_sid, &child_path, &child_cwd, &child_endpoint),
        ),
    );
    assert_eq!(
        full_state(&h),
        before,
        "child's valid new identity recovered the inactive parent or minted a fallback: {} {}",
        output.stdout,
        output.stderr
    );
    output.refused();
    assert_no_wake(&[&parent_endpoint, &child_endpoint]);
    parent.assert_alive();
}

#[test]
fn child_own_minted_identity_cannot_take_the_live_parents_canonical_sid() {
    for soft_stopped in [false, true] {
        let h = isolated_hcom();
        let suffix = unique_suffix();
        let sid = format!("sid-known-parent-{suffix}");
        let mut parent = HookProcess::spawn(&h, "known-sid-parent", "omp", None, false);
        let parent_endpoint = probe();
        let child_endpoint = probe();
        let path = h.workspace.join(format!("{sid}.jsonl"));
        let response = parent
            .run(
                &h,
                &start_command(&sid, &path, &h.workspace, &parent_endpoint),
            )
            .ok();
        let name = response["name"]
            .as_str()
            .expect("canonical parent name")
            .to_string();
        db(&h)
            .execute(
                "UPDATE instances SET pid=?2 WHERE name=?1",
                rusqlite::params![name, parent.owner_pid],
            )
            .unwrap();
        parent.run(&h, &format!("export HCOM_INSTANCE_NAME={}", quote(&name)));
        seed_message(
            &h,
            &name,
            "fixture-sender",
            "known-SID parent unread payload",
            "mentions",
            "",
        );
        if soft_stopped {
            parent
                .run(
                    &h,
                    &format!("H omp-stop --name {} --soft --reason restart", quote(&name)),
                )
                .ok();
            discard_setup_wakes(&parent_endpoint);
        }
        let child_cwd = h.root_path().join("known-sid-child");
        fs::create_dir_all(&child_cwd).unwrap();
        let child_path = child_cwd.join(format!("{sid}.jsonl"));
        let before = full_state(&h);
        let output = parent.descendant(
            &h,
            &format!(
                "export HCOM_PROCESS_ID=omp-$$-9-10; {}",
                start_command(&sid, &child_path, &child_cwd, &child_endpoint),
            ),
        );
        assert_eq!(
            full_state(&h),
            before,
            "valid child ID replaced or repinned the live canonical parent (soft_stopped={soft_stopped}): {} {}",
            output.stdout,
            output.stderr
        );
        output.refused();
        assert_no_wake(&[&parent_endpoint, &child_endpoint]);
        parent.assert_alive();
    }
}

#[test]
fn genuine_inactive_owner_recovers_its_missing_binding_without_a_new_identity() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let sid = format!("sid-reentry-parent-{suffix}");
    let mut owner = HookProcess::spawn(&h, "inactive-reentry-owner", "omp", None, false);
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    let response = owner
        .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
        .ok();
    let name = response["name"]
        .as_str()
        .expect("reentry owner name")
        .to_string();
    let cursor = seed_message(
        &h,
        &name,
        "fixture-sender",
        "consumed before reentry",
        "mentions",
        "",
    );
    let unread = seed_message(
        &h,
        &name,
        "fixture-sender",
        "preserve across genuine reentry",
        "mentions",
        "",
    );
    db(&h)
        .execute(
            "UPDATE instances SET pid=?3,last_event_id=?2,name_announced=1 WHERE name=?1",
            rusqlite::params![name, cursor, owner.owner_pid],
        )
        .unwrap();
    let metadata: (f64, i64, i64) = db(&h)
        .query_row(
            "SELECT created_at,last_event_id,name_announced FROM instances WHERE name=?1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let payload: String = db(&h)
        .query_row("SELECT data FROM events WHERE id=?1", [unread], |row| {
            row.get(0)
        })
        .unwrap();
    owner
        .run(
            &h,
            &format!(
                "export HCOM_INSTANCE_NAME={}; H omp-stop --name {} --soft --reason restart",
                quote(&name),
                quote(&name),
            ),
        )
        .ok();
    db(&h)
        .execute(
            "DELETE FROM process_bindings WHERE process_id=?1",
            [&owner.process_id],
        )
        .unwrap();
    let next_sid = format!("sid-reentry-next-{suffix}");
    let next_cwd = h.root_path().join("reentry-project");
    fs::create_dir_all(&next_cwd).unwrap();
    let next_path = next_cwd.join(format!("{next_sid}.jsonl"));
    let result = owner
        .run(
            &h,
            &start_command(&next_sid, &next_path, &next_cwd, &endpoint),
        )
        .ok();
    assert_eq!(
        result["name"], name,
        "genuine owner minted a replacement instead of recovering"
    );
    assert_bound(&h, &owner, &name, &next_sid, &next_path, &next_cwd);
    let retained: (f64, i64, i64) = db(&h)
        .query_row(
            "SELECT created_at,last_event_id,name_announced FROM instances WHERE name=?1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        retained, metadata,
        "reentry changed incarnation, cursor or announcement state"
    );
    let retained_payload: String = db(&h)
        .query_row("SELECT data FROM events WHERE id=?1", [unread], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        retained_payload, payload,
        "reentry rewrote the unread event"
    );
    let count: i64 = db(&h)
        .query_row("SELECT COUNT(*) FROM instances", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "genuine reentry left a replacement row");
    owner.assert_alive();
}

#[test]
fn fresh_own_minted_plain_seat_below_an_owner_pins_its_own_actual_pid() {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("olderowner{suffix}");
    let sid = format!("sid-older-owner-{suffix}");
    let mut owner = HookProcess::spawn(&h, "older-owner", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &owner, &name);
    let endpoint = probe();
    let path = h.workspace.join(format!("{sid}.jsonl"));
    owner
        .run(&h, &start_command(&sid, &path, &h.workspace, &endpoint))
        .ok();
    assert_bound(&h, &owner, &name, &sid, &path, &h.workspace);
    seed_message(
        &h,
        &name,
        "fixture-sender",
        "older owner's unread payload",
        "mentions",
        "",
    );
    let older_rows = || {
        let conn = db(&h);
        [
            "SELECT * FROM instances WHERE name=?1",
            "SELECT * FROM process_bindings WHERE instance_name=?1 ORDER BY process_id",
            "SELECT * FROM session_bindings WHERE instance_name=?1 ORDER BY session_id",
            "SELECT * FROM notify_endpoints WHERE instance=?1 ORDER BY kind",
        ]
        .map(|sql| {
            let mut query = conn.prepare(sql).unwrap();
            let columns = query.column_count();
            query
                .query_map([&name], |row| {
                    (0..columns)
                        .map(|column| row.get::<_, rusqlite::types::Value>(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        })
    };
    let older = older_rows();
    // A real new seat below the older owner: its own OMP process presents
    // its own minted ID, no inherited name, and a session nothing has bound.
    let seat_sid = format!("sid-plain-seat-{suffix}");
    let seat_cwd = h.root_path().join("plain-seat");
    fs::create_dir_all(&seat_cwd).unwrap();
    let seat_path = seat_cwd.join(format!("{seat_sid}.jsonl"));
    let seat_endpoint = probe();
    let seat_pid_file = h.root_path().join("plain-seat.pid");
    let output = owner.descendant(
        &h,
        &format!(
            "printf '%s' \"$$\" > {}; export HCOM_PROCESS_ID=omp-$$-5-6; {}",
            quote(&seat_pid_file.to_string_lossy()),
            start_command(&seat_sid, &seat_path, &seat_cwd, &seat_endpoint),
        ),
    );
    let started = output.ok();
    let seat_name = started["name"]
        .as_str()
        .expect("fresh plain seat name")
        .to_string();
    let seat_pid: u32 = fs::read_to_string(&seat_pid_file)
        .unwrap()
        .parse()
        .expect("seat PID");
    let seat_id = format!("omp-{seat_pid}-5-6");
    // Capture as stored, NULL PID included; assert once the fixture is gone.
    let conn = db(&h);
    let row: (String, String, String, Option<i64>) = conn
        .query_row(
            "SELECT session_id, transcript_path, directory, pid FROM instances WHERE name = ?1",
            [&seat_name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let bindings: (Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT
                (SELECT session_id FROM process_bindings WHERE process_id = ?1),
                (SELECT instance_name FROM process_bindings WHERE process_id = ?1),
                (SELECT instance_name FROM session_bindings WHERE session_id = ?2)",
            rusqlite::params![seat_id, seat_sid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    drop(conn);
    let older_after = older_rows();
    let check = owner.run(&h, &format!("H omp-read --name {} --check", quote(&name)));
    let older_mail = (check.code, check.stdout.trim().to_string());
    owner.assert_alive();
    // Release every fixture first: a failed pin then reports the captured
    // evidence itself, not the host-wide diagnostics of a live fixture.
    drop(owner);
    drop(endpoint);
    drop(seat_endpoint);
    drop(h);
    assert_ne!(seat_name, name, "the seat took the owner's identity");
    assert_eq!(
        row,
        (
            seat_sid.clone(),
            seat_path.to_string_lossy().into_owned(),
            seat_cwd.to_string_lossy().into_owned(),
            Some(i64::from(seat_pid))
        ),
        "fresh plain seat did not pin its own actual OMP PID"
    );
    assert_eq!(
        bindings,
        (Some(seat_sid), Some(seat_name.clone()), Some(seat_name)),
        "fresh plain seat did not bind its session and process"
    );
    assert_eq!(
        older_after, older,
        "the fresh seat changed the older owner's state"
    );
    assert_eq!(
        older_mail,
        (0, "true".to_string()),
        "the older owner's unread mail did not survive"
    );
}

/// Bounded command text for the comparable outcome line.
fn bounded(text: &str) -> String {
    const LIMIT: usize = 2000;
    match text.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}...[{} bytes total]", &text[..cut], text.len()),
        None => text.to_string(),
    }
}

/// Every stored fact of one hooked OMP owner: its row (including a parsed
/// launch receipt), its SID-bound process binding, its canonical session
/// binding and its stop history.
fn hooked_facts(h: &Hcom, name: &str, process_id: &str, sid: &str) -> Value {
    let conn = db(h);
    type Row = (
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: Option<Row> = conn
        .query_row(
            "SELECT status, status_context, pid, session_id, directory, transcript_path,
                    CASE WHEN json_valid(launch_context)
                         THEN launch_context -> '$.omp_launch_pid' END
               FROM instances WHERE name=?1",
            [name],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .unwrap();
    let row = row.map(
        |(status, context, pid, row_sid, directory, transcript, receipt)| {
            let receipt = receipt.map(|receipt| {
                serde_json::from_str::<Value>(&receipt).expect("launch receipt JSON")
            });
            json!({
                "status": status,
                "context": context,
                "pid": pid,
                "sid": row_sid,
                "directory": directory,
                "transcript": transcript,
                "receipt": receipt,
            })
        },
    );
    let process_binding: Option<(Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT instance_name, session_id FROM process_bindings WHERE process_id=?1",
            [process_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .unwrap();
    let session_binding = conn
        .query_row(
            "SELECT instance_name FROM session_bindings WHERE session_id=?1",
            [sid],
            |row| row.get::<_, String>(0),
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
        "row": row,
        "process_binding": process_binding,
        "session_binding": session_binding,
        "stopped_events": stopped,
    })
}

/// Private launch PATH: an `omp` that only records its invocation and exits,
/// and a post-tool login shell that exits at once. A resume that passes every
/// guard reaches only these, never an installed OMP or a terminal
/// application. CI rebuilds the child env, so the fixture roots are persisted
/// through the same passthrough the real launch tests use.
fn inert_launch_path(h: &Hcom) -> PathBuf {
    let bin = h.root_path().join("inert-launch-bin");
    fs::create_dir_all(&bin).expect("create inert launch directory");
    let launches = h.root_path().join("inert-launches");
    for (tool, script) in [
        (
            "omp",
            format!(
                "#!/bin/bash\nif [ \"${{1:-}}\" = --version ]; then printf '1.0.0\\n'; exit 0; fi\nprintf '%s\\n' \"$$\" >> {}\n",
                quote(&launches.to_string_lossy())
            ),
        ),
        (
            "bash",
            "#!/bin/bash\nif [ \"$#\" -eq 1 ] && [ \"$1\" = -l ]; then exit 0; fi\nexec /bin/bash \"$@\"\n"
                .to_string(),
        ),
    ] {
        let path = bin.join(tool);
        fs::write(&path, script).expect("write inert launch tool");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("make inert launch tool executable");
    }
    let command = h.cmd();
    let inherited = |key: &str| {
        command
            .get_envs()
            .find(|(name, _)| *name == key)
            .and_then(|(_, value)| value)
            .map(|value| value.to_os_string())
    };
    let mut paths = vec![bin];
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
            h.set_launch_env(key, value.to_str().unwrap());
        }
    }
    h.set_launch_env("PI_CONFIG_DIR", h.home.join(".omp").to_str().unwrap());
    h.set_launch_env(
        "PI_CODING_AGENT_DIR",
        h.home.join(".omp/agent").to_str().unwrap(),
    );
    launches
}

/// Every catchable signal the unrelated process traps, records and exits on.
const UNRELATED_HANDLED_SIGNALS: [libc::c_int; 7] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGCONT,
];

/// Owned live process with no hcom identity: a cleared environment, its own
/// process group, a heartbeat, and a handler for every catchable signal that
/// records the signal and exits. SIGKILL shows as death, SIGSTOP as a stalled
/// heartbeat. It is never registered for raw-PID cleanup; its drop detaches
/// the private row from its PID before reaping it, so neither `Hcom::drop`'s
/// `kill all` nor its row-PID sweep can signal it or a later PID reuser.
struct UnrelatedProcess<'a> {
    h: &'a Hcom,
    row: String,
    child: Child,
    heartbeat: PathBuf,
    signals: PathBuf,
}

impl<'a> UnrelatedProcess<'a> {
    fn spawn(h: &'a Hcom, row: &str) -> Self {
        let out = h.root_path().join("unrelated-process");
        fs::create_dir_all(&out).expect("create unrelated process directory");
        let heartbeat = out.join("heartbeat");
        let signals = out.join("signals");
        let script = r#"
: > "$FIXTURE_SIGNALS"
for signal in HUP INT QUIT TERM USR1 USR2 CONT; do
    trap "printf '%s\\n' $signal >> \"\$FIXTURE_SIGNALS\"; exit 0" "$signal"
done
while :; do
    printf x >> "$FIXTURE_HEARTBEAT"
    read -r -t 0.05 || true
done
"#;
        let mut command = Command::new("/bin/bash");
        command
            .args(["-c", script])
            .env_clear()
            .env("FIXTURE_HEARTBEAT", &heartbeat)
            .env("FIXTURE_SIGNALS", &signals)
            .current_dir(&out)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        // Bash cannot trap a signal ignored at entry; never inherit an ignore.
        unsafe {
            command.pre_exec(|| {
                for signal in UNRELATED_HANDLED_SIGNALS {
                    libc::signal(signal, libc::SIG_DFL);
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("spawn unrelated process");
        let unrelated = Self {
            h,
            row: row.to_string(),
            child,
            heartbeat,
            signals,
        };
        let handled = UNRELATED_HANDLED_SIGNALS
            .iter()
            .fold(0_u64, |mask, signal| mask | 1_u64 << (signal - 1));
        h.eventually(
            "unrelated process heartbeat with every handler installed",
            Duration::from_secs(30),
            || {
                Ok((unrelated.beats() > 0
                    && unrelated.signals.exists()
                    && (unrelated.caught_signals() & handled) == handled)
                    .then_some(()))
            },
        );
        unrelated
    }

    /// The kernel's caught-signal mask, so readiness proves every trap is live.
    fn caught_signals(&self) -> u64 {
        fs::read_to_string(format!("/proc/{}/status", self.child.id()))
            .ok()
            .and_then(|status| {
                let mask = status
                    .lines()
                    .find_map(|line| line.strip_prefix("SigCgt:"))?;
                u64::from_str_radix(mask.trim(), 16).ok()
            })
            .unwrap_or(0)
    }

    fn pid(&self) -> i64 {
        i64::from(self.child.id())
    }

    fn beats(&self) -> u64 {
        fs::metadata(&self.heartbeat)
            .map(|stat| stat.len())
            .unwrap_or(0)
    }

    fn observe(&mut self, before: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(2);
        let progressed = loop {
            if self.beats() > before {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        let exit = self.child.try_wait().expect("poll unrelated process");
        json!({
            "alive": exit.is_none(),
            "exit": exit.map(|status| status.to_string()),
            "heartbeat_progressed": progressed,
            "signals": fs::read_to_string(&self.signals).unwrap_or_default(),
        })
    }

    /// Clear only the private row's PID, and only while it still names this
    /// process. A resume may already have released or replaced the row.
    fn clear_row_pid(&self) -> rusqlite::Result<usize> {
        let conn = rusqlite::Connection::open(self.h.path().join("hcom.db"))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute(
            "UPDATE instances SET pid=NULL WHERE name=?1 AND pid=?2",
            rusqlite::params![self.row, self.pid()],
        )
    }
}

impl Drop for UnrelatedProcess<'_> {
    fn drop(&mut self) {
        // Unwind path too: never hand Hcom::drop a row PID naming this process.
        let _ = self.clear_row_pid();
        // Not yet reaped, so this PID is still exactly our own child.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One fresh scenario per command: a real hooked OMP owner dies by SIGKILL
/// without any cleanup, an unrelated live process takes its numeric PID, then
/// one real bounded CLI command addresses the name. The labeled outcome line
/// is emitted before any assertion or teardown, for base comparison.
fn crashed_hooked_owner_reused_pid(command: &str) -> Value {
    let h = isolated_hcom();
    let suffix = unique_suffix();
    let name = format!("crashed{suffix}");
    let sid = uuid::Uuid::new_v4().to_string();
    // Launcher identity is a UUID, as hcom launches mint it; it encodes no PID.
    let mut owner = HookProcess::spawn(&h, "crashed-owner", "omp", Some(&launcher_id()), false);
    seed_launch(&h, &owner, &name);
    let endpoint = probe();
    let transcript = h
        .home
        .join(".omp/agent/sessions/crashed")
        .join(format!("2026-10-01T00-00-00-000Z_{sid}.jsonl"));
    fs::create_dir_all(transcript.parent().unwrap()).expect("create private session directory");
    fs::write(
        &transcript,
        format!(
            "{}\n",
            json!({"type": "session", "id": sid, "cwd": h.workspace})
        ),
    )
    .expect("write private session file");
    let start = owner.run(
        &h,
        &format!(
            "exec 9< {}; {}",
            quote(&transcript.to_string_lossy()),
            start_command(&sid, &transcript, &h.workspace, &endpoint)
        ),
    );
    let bound = hooked_facts(&h, &name, &owner.process_id, &sid);

    // Abrupt death of the OMP alone: no omp-stop, no PTY proxy or launcher
    // cleanup. Reaping it makes its PID genuinely free.
    owner.child.kill().expect("SIGKILL the fixture OMP");
    let crash = owner.child.wait().expect("reap the fixture OMP");
    let crashed = hooked_facts(&h, &name, &owner.process_id, &sid);

    let mut unrelated = UnrelatedProcess::spawn(&h, &name);
    // PID reuse, simulated in this private DB only: the kernel cannot be made
    // to hand the dead OMP's PID to the unrelated process, so the stored PID
    // facts move to it instead. `instances.pid` is the only column holding the
    // OMP's number: the UUID launcher identity encodes none, and the canonical
    // and SID-bound bindings carry no PID. Renumbering it, plus a surviving
    // launch receipt's `pid` only if that names the OMP, leaves exactly what a
    // real reuse would: every PID fact names a live process with no hcom
    // identity. No receipt is minted, no stop snapshot written, no env faked.
    let renumbered = db(&h)
        .execute(
            "UPDATE instances
                SET pid=?2,
                    launch_context=CASE WHEN json_valid(launch_context) THEN
                        CASE WHEN json_extract(launch_context,'$.omp_launch_pid.pid')=?3
                             THEN json_set(launch_context,'$.omp_launch_pid.pid',?2)
                             ELSE launch_context END
                        ELSE launch_context END
              WHERE name=?1 AND pid=?3",
            rusqlite::params![name, unrelated.pid(), i64::from(owner.owner_pid)],
        )
        .unwrap();
    let reused = hooked_facts(&h, &name, &owner.process_id, &sid);

    let launches = inert_launch_path(&h);
    let args: Vec<&str> = if command == "r" {
        vec!["r", name.as_str(), "--terminal", "bash {script}", "--go"]
    } else {
        vec![command, name.as_str()]
    };
    let before = unrelated.beats();
    let (code, stdout, stderr) = h.run(&args);
    let spared = unrelated.observe(before);
    let after = hooked_facts(&h, &name, &owner.process_id, &sid);
    let outcome = json!({
        "command": command,
        "args": args,
        "name": name,
        "sid": sid,
        "cwd": h.workspace,
        "transcript": transcript,
        "process_id": owner.process_id,
        "owner_pid": owner.owner_pid,
        "owner_child_pid": owner.child.id(),
        "start": {
            "code": start.code,
            "stdout": bounded(&start.stdout),
            "stderr": bounded(&start.stderr),
        },
        "bound": bound,
        "crash": {"signal": crash.signal(), "status": crash.to_string()},
        "crashed": crashed,
        "unrelated_pid": unrelated.pid(),
        "renumbered_rows": renumbered,
        "reused": reused,
        "result": {"code": code, "stdout": bounded(&stdout), "stderr": bounded(&stderr)},
        "after": after,
        "unrelated": spared,
        "inert_omp_invocations": fs::read_to_string(&launches)
            .map(|text| text.lines().count())
            .unwrap_or(0),
    });
    eprintln!("HOOKED_PID_REUSE_OUTCOME {outcome}");
    unrelated
        .clear_row_pid()
        .expect("detach the private row from the unrelated PID before teardown");
    outcome
}

#[track_caller]
fn assert_unrelated_reused_pid_spared(outcome: &Value) {
    let command = outcome["command"].as_str().unwrap_or_default();
    // The consumer-visible invariant, checked first and never softened.
    assert_eq!(
        outcome["unrelated"],
        json!({"alive": true, "exit": null, "heartbeat_progressed": true, "signals": ""}),
        "SAFETY: `hcom {command}` signaled, killed or stalled an unrelated live process \
         holding the crashed OMP's former PID: {outcome}"
    );
    // Preconditions: without them the spared observation would be vacuous.
    let owner = &outcome["owner_pid"];
    assert_eq!(
        *owner, outcome["owner_child_pid"],
        "fixture OMP was not the owned direct child: {outcome}"
    );
    let bound = &outcome["bound"];
    let receipt = &bound["row"]["receipt"];
    assert!(
        receipt.is_null() || receipt["pid"] == *owner,
        "launch receipt names another process: {outcome}"
    );
    assert_eq!(
        *bound,
        json!({
            "row": {
                "status": "listening",
                "context": "start",
                "pid": owner,
                "sid": outcome["sid"],
                "directory": outcome["cwd"],
                "transcript": outcome["transcript"],
                "receipt": receipt,
            },
            "process_binding": [outcome["name"], outcome["sid"]],
            "session_binding": outcome["name"],
            "stopped_events": 0,
        }),
        "fixture OMP did not reach the fully bound hooked state: {outcome}"
    );
    assert_eq!(
        outcome["crash"]["signal"],
        libc::SIGKILL,
        "fixture OMP did not die by SIGKILL: {outcome}"
    );
    assert_eq!(
        outcome["crashed"], *bound,
        "the crash alone changed the hooked owner's state or recorded a stop: {outcome}"
    );
    let mut expected = bound.clone();
    expected["row"]["pid"] = outcome["unrelated_pid"].clone();
    if !receipt.is_null() {
        expected["row"]["receipt"]["pid"] = outcome["unrelated_pid"].clone();
    }
    assert_eq!(
        outcome["renumbered_rows"], 1,
        "PID-reuse fixture did not renumber the owner row: {outcome}"
    );
    assert_eq!(
        outcome["reused"], expected,
        "PID-reuse fixture changed more than the crashed OMP's numeric PID: {outcome}"
    );
}

#[test]
fn crashed_hooked_owner_reused_pid_resume_spares_unrelated_process() {
    let outcome = crashed_hooked_owner_reused_pid("r");
    assert_unrelated_reused_pid_spared(&outcome);
    // A live recorded PID still roots the hooked row, so resume must refuse
    // before any launch and leave the row and both bindings exactly as found.
    assert_ne!(
        outcome["result"]["code"], 0,
        "resume did not refuse the live-rooted hooked row: {outcome}"
    );
    assert_eq!(
        outcome["after"], outcome["reused"],
        "refused resume changed the hooked row or its bindings: {outcome}"
    );
    assert_eq!(
        outcome["inert_omp_invocations"], 0,
        "refused resume still launched OMP: {outcome}"
    );
}

#[test]
fn crashed_hooked_owner_reused_pid_stop_spares_unrelated_process() {
    let outcome = crashed_hooked_owner_reused_pid("stop");
    assert_unrelated_reused_pid_spared(&outcome);
    assert_eq!(
        outcome["result"]["code"], 0,
        "stop of the crashed hooked row failed: {outcome}"
    );
    let after = &outcome["after"];
    assert_eq!(
        (
            &after["row"],
            &after["process_binding"],
            &after["session_binding"]
        ),
        (&Value::Null, &Value::Null, &Value::Null),
        "stop retained the crashed owner's bookkeeping: {outcome}"
    );
}
