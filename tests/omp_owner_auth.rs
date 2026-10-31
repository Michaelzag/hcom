//! Native OMP owner authentication through the compiled CLI, without an OMP install.
//! Every process, database, endpoint, and hook HOME belongs to an isolated Hcom fixture.

#![cfg(target_os = "linux")]

mod support;

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs as unix_fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::Duration;

use rusqlite::{Connection, params, types::Value as SqlValue};
use serde_json::{Value, json};
use support::Hcom;

// Source requests in the OMP shell itself, not in another bash/subshell: that
// would put a different OMP between the CLI and the owner being authenticated.
// The nested actor really execs a second `omp`, and remains below its owner.
const DRIVER: &str = r#"
out=$1
H() {
    local id=$1
    shift
    HCOM_PROCESS_ID="$id" HCOM_LAUNCHED=1 HCOM_TOOL=omp "$TEST_BIN" "$@"
}
nested() {
    HCOM_PROCESS_ID="$1" "$TEST_OMP" "$TEST_DRIVER" "$2" &
    printf '{"pid":%s}\n' "$!"
}
printf '%s' "$$" > "$out/ready"
step=0
while :; do
    request="$out/$step.request"
    if [ -f "$request" ]; then
        . "$request" > "$out/$step.json" 2> "$out/$step.stderr"
        printf '%s' "$?" > "$out/$step.code"
        step=$((step + 1))
    else
        sleep 0.05
    fi
done
"#;

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("UTF-8 fixture path")
}

struct OmpClient {
    pid: u32,
    out_dir: PathBuf,
    next_step: usize,
}

impl OmpClient {
    fn minted_id(&self) -> String {
        format!("omp-{}-1-1", self.pid)
    }

    fn wait_ready(&self, h: &Hcom) {
        h.eventually("fake OMP exec", Duration::from_secs(30), || {
            Ok(fs::read_to_string(self.out_dir.join("ready"))
                .ok()
                .filter(|pid| pid == &self.pid.to_string()))
        });
        assert_eq!(
            fs::read_to_string(format!("/proc/{}/comm", self.pid))
                .expect("read real OMP comm")
                .trim(),
            "omp"
        );
    }

    fn request_output(&mut self, h: &Hcom, script: &str) -> (String, String, String) {
        let step = self.next_step;
        self.next_step += 1;
        let pending = self.out_dir.join(format!("{step}.pending"));
        fs::write(&pending, script).expect("write fixture request");
        fs::rename(&pending, self.out_dir.join(format!("{step}.request")))
            .expect("publish complete request");
        let code = h.eventually("fake OMP CLI response", Duration::from_secs(60), || {
            Ok(
                fs::read_to_string(self.out_dir.join(format!("{step}.code")))
                    .ok()
                    .filter(|code| !code.is_empty()),
            )
        });
        let stdout =
            fs::read_to_string(self.out_dir.join(format!("{step}.json"))).expect("read CLI stdout");
        let stderr = fs::read_to_string(self.out_dir.join(format!("{step}.stderr")))
            .expect("read CLI stderr");
        (code, stdout, stderr)
    }

    fn request(&mut self, h: &Hcom, script: &str) -> Value {
        let (code, stdout, stderr) = self.request_output(h, script);
        assert_eq!(code, "0", "{script}\nstdout={stdout}\nstderr={stderr}");
        serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
            panic!("CLI response is not JSON: {error}\n{script}\nstdout={stdout}\nstderr={stderr}")
        })
    }

    fn run(&mut self, h: &Hcom, process_id: &str, args: &[String]) -> Value {
        let args = args
            .iter()
            .map(|arg| quote(arg))
            .collect::<Vec<_>>()
            .join(" ");
        self.request(h, &format!("H {} {args}\n", quote(process_id)))
    }

    fn spawn_nested(&mut self, h: &Hcom, borrowed_id: &str) -> OmpClient {
        let out_dir = self.out_dir.join("nested");
        fs::create_dir_all(&out_dir).expect("create nested actor directory");
        let result = self.request(
            h,
            &format!(
                "nested {} {}\n",
                quote(borrowed_id),
                quote(path_text(&out_dir))
            ),
        );
        let nested = OmpClient {
            pid: u32::try_from(result["pid"].as_u64().expect("nested pid"))
                .expect("native pid fits u32"),
            out_dir,
            next_step: 0,
        };
        nested.wait_ready(h);
        assert_ne!(nested.pid, self.pid);
        assert_ne!(live_incarnation(nested.pid), live_incarnation(self.pid));
        let status = fs::read_to_string(format!("/proc/{}/status", nested.pid))
            .expect("read nested process parent");
        let ppid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .expect("native PPid")
            .trim()
            .parse::<u32>()
            .expect("parse PPid");
        assert_eq!(ppid, self.pid, "nested OMP is not the owner's real child");
        nested
    }
}

struct FakeOmp {
    child: Child,
    client: OmpClient,
}

impl FakeOmp {
    fn spawn(h: &Hcom, tag: &str) -> Self {
        let fakebin = h.root_path().join("fakebin");
        fs::create_dir_all(&fakebin).expect("create fakebin");
        let omp = fakebin.join("omp");
        if !omp.exists() {
            unix_fs::symlink("/bin/bash", &omp).expect("symlink omp -> bash");
        }
        let driver = fakebin.join("driver.sh");
        fs::write(&driver, DRIVER).expect("write fixture OMP driver");
        let out_dir = h.root_path().join(format!("actor-{tag}"));
        fs::create_dir_all(&out_dir).expect("create actor directory");
        let child = h
            .external_cmd(&omp)
            .arg("-c")
            .arg(format!(
                "exec env HCOM_PROCESS_ID=omp-$$-1-1 {} {} {}",
                quote(path_text(&omp)),
                quote(path_text(&driver)),
                quote(path_text(&out_dir))
            ))
            .env("TEST_BIN", env!("CARGO_BIN_EXE_hcom"))
            .env("TEST_OMP", &omp)
            .env("TEST_DRIVER", &driver)
            .env("HCOM_RELAY_ENABLED", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn isolated fake OMP");
        h.track_cleanup_pid(child.id() as i64);
        let actor = Self {
            client: OmpClient {
                pid: child.id(),
                out_dir,
                next_step: 0,
            },
            child,
        };
        actor.client.wait_ready(h);
        assert_eq!(
            unsafe { libc::getpgid(actor.client.pid as i32) },
            actor.client.pid as i32
        );
        actor
    }
}

impl Drop for FakeOmp {
    fn drop(&mut self) {
        // This unreaped child was created with process_group(0). Never address
        // a caller/ancestor's group, even if setup failed before the assertion.
        let pid = self.child.id() as libc::pid_t;
        if pid > 1 && unsafe { libc::getpgid(pid) } == pid {
            unsafe {
                libc::killpg(pid, libc::SIGKILL);
            }
        } else {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn fixture() -> Hcom {
    let h = Hcom::new();
    fs::write(
        h.path().join("config.toml"),
        "[launch.omp]\nplain_sessions = true\n[relay]\nenabled = false\n",
    )
    .expect("write fixture-only config");
    let (code, stdout, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize fixture DB: {stdout} {stderr}");
    h
}

fn open_db(h: &Hcom) -> Connection {
    let db = Connection::open(h.path().join("hcom.db")).expect("open fixture DB");
    db.busy_timeout(Duration::from_secs(5))
        .expect("fixture busy timeout");
    db
}

fn live_incarnation(pid: u32) -> String {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("read native stat");
    let fields = &stat[stat.rfind(')').expect("stat comm closing paren") + 2..];
    let ticks = fields
        .split_whitespace()
        .nth(19)
        .expect("native start ticks");
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").expect("read native boot id");
    format!("linux:{}:{ticks}", boot.trim())
}

fn assert_owner_pin(h: &Hcom, name: &str, pid: u32) {
    let (runtime_pid, context): (Option<u32>, String) = open_db(h)
        .query_row(
            "SELECT pid, launch_context FROM instances WHERE name = ?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("owner runtime and launch_context");
    assert_eq!(
        runtime_pid,
        Some(pid),
        "runtime pid must be the genuine OMP owner"
    );
    let context: Value = serde_json::from_str(&context).expect("launch_context JSON");
    assert_eq!(
        context["omp_owner"],
        json!({"pid": pid, "incarnation": live_incarnation(pid)})
    );
}

// SELECT * intentionally captures every instance column (including its cursor),
// every binding/endpoint, message delivery JSON, status/life events, and role/
// delivery-policy KV. A failed authentication may not alter any of these planes.
fn persistent_state(h: &Hcom) -> Vec<(&'static str, Vec<Vec<SqlValue>>)> {
    let db = open_db(h);
    [
        "instances",
        "session_bindings",
        "process_bindings",
        "notify_endpoints",
        "events",
        "kv",
    ]
    .into_iter()
    .map(|table| {
        let mut statement = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .expect("prepare full-table snapshot");
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get::<_, SqlValue>(column))
                    .collect()
            })
            .expect("snapshot fixture table")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("read complete snapshot");
        (table, rows)
    })
    .collect()
}

fn paths(h: &Hcom, tag: &str) -> (PathBuf, PathBuf) {
    let cwd = h.workspace.join(tag);
    fs::create_dir_all(&cwd).expect("create real fixture cwd");
    let transcript = cwd.join("transcript.jsonl");
    fs::write(&transcript, "").expect("create real fixture transcript");
    (cwd, transcript)
}

fn start_args(session: &str, cwd: &Path, transcript: &Path, port: u16) -> Vec<String> {
    [
        "omp-start",
        "--session-id",
        session,
        "--cwd",
        path_text(cwd),
        "--transcript-path",
        path_text(transcript),
        "--notify-port",
        &port.to_string(),
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn lifecycle_requests(
    start: Vec<String>,
    name: &str,
    owner_session: &str,
    ack_to: i64,
) -> Vec<Vec<String>> {
    let ack_to = ack_to.to_string();
    let mut requests = vec![start];
    requests.extend(
        [
            vec![
                "omp-stop",
                "--name",
                name,
                "--soft",
                "--reason",
                "borrowed-owner",
            ],
            vec![
                "omp-status",
                "--name",
                name,
                "--status",
                "active",
                "--context",
                "tool:bash",
                "--detail",
                "borrowed mutation",
            ],
            vec!["omp-read", "--name", name, "--ack", "--up-to", &ack_to],
            vec![
                "omp-beforetool",
                "--name",
                name,
                "--tool",
                "bash",
                "--input-json",
                r#"{"command":"true","i":"borrowed mutation"}"#,
            ],
            vec![
                "omp-role",
                "--name",
                name,
                "--session-id",
                owner_session,
                "--role",
                "worker",
            ],
        ]
        .into_iter()
        .map(|args| args.into_iter().map(str::to_owned).collect::<Vec<_>>()),
    );
    requests
}

fn assert_refused_unchanged(h: &Hcom, actor: &mut OmpClient, id: &str, args: &[String]) {
    let before = persistent_state(h);
    let result = actor.run(h, id, args);
    assert!(
        result["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()),
        "expected JSON ownership refusal for {args:?}: {result}"
    );
    assert_ne!(
        result.get("transient"),
        Some(&json!(true)),
        "auth refusal must be terminal: {result}"
    );
    for field in ["name", "ok", "decision", "acked", "acked_to", "role"] {
        assert!(
            result.get(field).is_none(),
            "refusal included success field {field}: {result}"
        );
    }
    assert_eq!(
        persistent_state(h),
        before,
        "persistent mutation after refusal: {args:?}"
    );
}

fn seed_message(h: &Hcom, name: &str, text: &str) -> i64 {
    let db = open_db(h);
    db.execute(
        "INSERT INTO events (timestamp, type, instance, data)
         VALUES (datetime('now'), 'message', 'fixture-peer', ?1)",
        [
            json!({"from": "fixture-peer", "text": text, "delivered_to": [name],
            "scope": "mentions", "mentions": [name], "exact_targets": [name]})
            .to_string(),
        ],
    )
    .expect("seed fixture-only message event");
    db.last_insert_rowid()
}

fn unread_ids(h: &Hcom, name: &str) -> Vec<i64> {
    let db = open_db(h);
    let mut statement = db
        .prepare(
            "SELECT e.id FROM events e JOIN instances i ON i.name = ?1
         WHERE e.type = 'message' AND e.id > i.last_event_id
           AND EXISTS (SELECT 1 FROM json_each(e.data, '$.delivered_to') d WHERE d.value = i.name)
         ORDER BY e.id",
        )
        .expect("prepare unread fixture messages");
    statement
        .query_map([name], |row| row.get(0))
        .expect("query unread messages")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("read unread ids")
}

fn bind_owner(h: &Hcom, owner: &mut OmpClient, session: &str, port: u16) -> String {
    let (cwd, transcript) = paths(h, session);
    let id = owner.minted_id();
    let result = owner.run(h, &id, &start_args(session, &cwd, &transcript, port));
    assert!(
        result.get("error").is_none(),
        "real owner start failed: {result}"
    );
    assert_eq!(result["session_id"], session);
    let name = result["name"]
        .as_str()
        .expect("real owner identity name")
        .to_owned();
    assert_owner_pin(h, &name, owner.pid);
    assert_binding(h, &id, &name, session);
    assert_plugin_endpoint(h, &name, port);
    name
}

#[test]
fn nested_omp_cannot_mutate_owner_via_minted_id_or_launcher_alias() {
    let h = fixture();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve owner plugin port");
    let port = listener.local_addr().expect("local plugin address").port();
    let mut owner = FakeOmp::spawn(&h, "owner");
    let owner_session = "owner-session";
    let name = bind_owner(&h, &mut owner.client, owner_session, port);
    let id = owner.client.minted_id();
    let unread = seed_message(
        &h,
        &name,
        "must remain unread after borrowed acknowledgements",
    );
    assert_eq!(unread_ids(&h, &name), vec![unread]);
    let mut nested = owner.client.spawn_nested(&h, &id);
    let (cwd, transcript) = paths(&h, "nested-session");
    let borrowed_listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("reserve borrowed plugin port");
    let borrowed_port = borrowed_listener
        .local_addr()
        .expect("borrowed plugin address")
        .port();
    let requests = lifecycle_requests(
        start_args("nested-session", &cwd, &transcript, borrowed_port),
        &name,
        owner_session,
        unread,
    );
    for request in &requests {
        assert_refused_unchanged(&h, &mut nested, &id, request);
    }

    // A launcher UUID is an alias for this actually authenticated row, not a
    // fake null-pid seed. Its recorded owner really is the nested OMP's ancestor.
    let alias = "550e8400-e29b-41d4-a716-446655440000";
    let db = open_db(&h);
    db.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, ?2, ?3, 0)",
        params![alias, owner_session, name],
    )
    .expect("fixture launcher alias for authenticated owner");
    let cursor: i64 = db
        .query_row(
            "SELECT last_event_id FROM instances WHERE name = ?1",
            [&name],
            |row| row.get(0),
        )
        .expect("owner cursor before authenticated alias proof");
    drop(db);
    let alias_ack = [
        "omp-read",
        "--name",
        &name,
        "--ack",
        "--up-to",
        &cursor.to_string(),
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let authenticated_alias = owner.client.run(&h, alias, &alias_ack);
    assert_eq!(authenticated_alias, json!({"acked_to": cursor}));
    for request in &requests {
        assert_refused_unchanged(&h, &mut nested, alias, request);
    }
    assert_eq!(unread_ids(&h, &name), vec![unread]);
    assert_owner_pin(&h, &name, owner.client.pid);
}

#[test]
fn mismatched_native_owner_incarnation_refuses_without_persistent_mutation() {
    let h = fixture();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve plugin port");
    let port = listener.local_addr().expect("local plugin address").port();
    let mut owner = FakeOmp::spawn(&h, "owner");
    let name = bind_owner(&h, &mut owner.client, "owner-session", port);
    let id = owner.client.minted_id();
    let unread = seed_message(&h, &name, "same pid is not the same native incarnation");
    let db = open_db(&h);
    let context: String = db
        .query_row(
            "SELECT launch_context FROM instances WHERE name = ?1",
            [&name],
            |row| row.get(0),
        )
        .expect("read authenticated owner pin");
    let mut context: Value = serde_json::from_str(&context).expect("owner pin JSON");
    let native = live_incarnation(owner.client.pid);
    let (prefix, ticks) = native.rsplit_once(':').expect("native token start ticks");
    let forged = format!(
        "{prefix}:{}",
        ticks.parse::<u64>().expect("parse native ticks") + 1
    );
    assert_ne!(forged, native);
    assert_eq!(context["omp_owner"]["pid"], owner.client.pid);
    context["omp_owner"]["incarnation"] = json!(forged);
    db.execute(
        "UPDATE instances SET launch_context = ?1 WHERE name = ?2",
        params![context.to_string(), name],
    )
    .expect("fixture-only incarnation tampering");
    drop(db);
    let (cwd, transcript) = paths(&h, "mismatched-session");
    for request in lifecycle_requests(
        start_args("mismatched-session", &cwd, &transcript, port),
        &name,
        "owner-session",
        unread,
    ) {
        assert_refused_unchanged(&h, &mut owner.client, &id, &request);
    }
    assert_eq!(unread_ids(&h, &name), vec![unread]);
}

fn assert_metadata(
    h: &Hcom,
    name: &str,
    session: &str,
    cwd: &Path,
    transcript: &Path,
    cursor: i64,
) {
    let actual: (String, String, String, String, i64) = open_db(h)
        .query_row(
            "SELECT session_id, directory, transcript_path, status, last_event_id
         FROM instances WHERE name = ?1",
            [name],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("read current owner metadata");
    assert_eq!(
        actual,
        (
            session.to_owned(),
            path_text(cwd).to_owned(),
            path_text(transcript).to_owned(),
            "listening".to_owned(),
            cursor,
        )
    );
}

fn assert_binding(h: &Hcom, id: &str, name: &str, session: &str) {
    let db = open_db(h);
    let actual: (String, String) = db
        .query_row(
            "SELECT session_id, instance_name FROM process_bindings WHERE process_id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read owner process binding");
    assert_eq!(actual, (session.to_owned(), name.to_owned()));
    let bound: String = db
        .query_row(
            "SELECT instance_name FROM session_bindings WHERE session_id = ?1",
            [session],
            |row| row.get(0),
        )
        .expect("read owner session binding");
    assert_eq!(bound, name);
}

fn assert_plugin_endpoint(h: &Hcom, name: &str, port: u16) {
    let actual: i64 = open_db(h)
        .query_row(
            "SELECT port FROM notify_endpoints WHERE instance = ?1 AND kind = 'plugin'",
            [name],
            |row| row.get(0),
        )
        .expect("read owner plugin endpoint");
    assert_eq!(actual, i64::from(port));
}

#[test]
fn same_owner_repairs_session_and_replays_inactive_start_with_notify_endpoint() {
    let h = fixture();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve owner plugin port");
    let port = listener.local_addr().expect("local plugin address").port();
    let mut owner = FakeOmp::spawn(&h, "owner");
    let name = bind_owner(&h, &mut owner.client, "initial-session", port);
    let id = owner.client.minted_id();
    let consumed = seed_message(
        &h,
        &name,
        "already acknowledged before the session transition",
    );
    let ack = [
        "omp-read",
        "--name",
        &name,
        "--ack",
        "--up-to",
        &consumed.to_string(),
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let result = owner.client.run(&h, &id, &ack);
    assert_eq!(result, json!({"acked_to": consumed}));
    let pending = seed_message(&h, &name, "must stay unread across repair and replay");
    assert_eq!(unread_ids(&h, &name), vec![pending]);

    let session = "genuine-new-session";
    let (cwd, transcript) = paths(&h, session);
    let args = start_args(session, &cwd, &transcript, port);
    let transitioned = owner.client.run(&h, &id, &args);
    assert!(
        transitioned.get("error").is_none(),
        "owner switch failed: {transitioned}"
    );
    assert_eq!(transitioned["name"], name);
    assert_eq!(transitioned["session_id"], session);
    assert_metadata(&h, &name, session, &cwd, &transcript, consumed);
    assert_binding(&h, &id, &name, session);
    assert_plugin_endpoint(&h, &name, port);
    assert_owner_pin(&h, &name, owner.client.pid);
    assert_eq!(unread_ids(&h, &name), vec![pending]);

    // Keep the genuine native owner pin and both bindings. Poison just the row
    // metadata, so this start must repair it rather than echoing cached success.
    let db = open_db(&h);
    db.execute(
        "UPDATE instances SET session_id = 'fixture-poisoned-session',
             directory = '/fixture-poisoned-directory',
             transcript_path = '/fixture-poisoned-transcript' WHERE name = ?1",
        [&name],
    )
    .expect("fixture-only metadata poisoning");
    let poisoned: (String, String, String) = db
        .query_row(
            "SELECT session_id, directory, transcript_path FROM instances WHERE name = ?1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("observe poisoned metadata");
    assert_eq!(
        poisoned,
        (
            "fixture-poisoned-session".to_owned(),
            "/fixture-poisoned-directory".to_owned(),
            "/fixture-poisoned-transcript".to_owned(),
        )
    );
    drop(db);
    let repaired = owner.client.run(&h, &id, &args);
    assert!(
        repaired.get("error").is_none(),
        "owner repair failed: {repaired}"
    );
    assert_eq!(repaired["name"], name);
    assert_eq!(repaired["session_id"], session);
    assert_metadata(&h, &name, session, &cwd, &transcript, consumed);
    assert_binding(&h, &id, &name, session);
    assert_plugin_endpoint(&h, &name, port);
    assert_owner_pin(&h, &name, owner.client.pid);
    assert_eq!(unread_ids(&h, &name), vec![pending]);

    // #124: deterministically represent the postcommit readiness gap. This is
    // idempotent replay proof, NOT a claim that a process was killed in that gap.
    let db = open_db(&h);
    db.execute(
        "UPDATE instances SET status = 'inactive', status_context = 'fixture-postcommit-gap'
         WHERE name = ?1",
        [&name],
    )
    .expect("fixture-only inactive gap");
    db.execute(
        "DELETE FROM notify_endpoints WHERE instance = ?1 AND kind = 'plugin'",
        [&name],
    )
    .expect("fixture-only missing endpoint");
    let gap: (String, i64) = db
        .query_row(
            "SELECT status, (SELECT COUNT(*) FROM notify_endpoints
             WHERE instance = ?1 AND kind = 'plugin') FROM instances WHERE name = ?1",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("observe readiness gap");
    assert_eq!(gap, ("inactive".to_owned(), 0));
    drop(db);

    let replayed = owner.client.run(&h, &id, &args);
    assert!(
        replayed.get("error").is_none(),
        "owner replay failed: {replayed}"
    );
    assert_eq!(replayed["name"], name);
    assert_eq!(replayed["session_id"], session);
    assert_metadata(&h, &name, session, &cwd, &transcript, consumed);
    assert_binding(&h, &id, &name, session);
    assert_plugin_endpoint(&h, &name, port);
    assert_owner_pin(&h, &name, owner.client.pid);
    assert_eq!(unread_ids(&h, &name), vec![pending]);
    let identities: i64 = open_db(&h)
        .query_row("SELECT COUNT(*) FROM instances", [], |row| row.get(0))
        .expect("count identities after replay");
    assert_eq!(
        identities, 1,
        "same-owner replay minted a duplicate identity"
    );
}

#[test]
fn historical_reclaim_refuses_nested_borrower_but_restores_native_owner() {
    let h = fixture();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve owner plugin port");
    let port = listener.local_addr().expect("local plugin address").port();
    let mut owner = FakeOmp::spawn(&h, "owner");
    let session = "historical-owner-session";
    let name = bind_owner(&h, &mut owner.client, session, port);
    let id = owner.client.minted_id();
    let consumed = seed_message(&h, &name, "acknowledged before the historical stop");
    let ack = [
        "omp-read",
        "--name",
        &name,
        "--ack",
        "--up-to",
        &consumed.to_string(),
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let acked = owner.client.run(&h, &id, &ack);
    assert_eq!(acked, json!({"acked_to": consumed}));
    let pending = seed_message(&h, &name, "unread across historical reclaim");

    // Release through the actual owner's child CLI so its ancestry is excluded
    // from termination and remains alive for the historical reclaim attempts.
    let stop = ["omp-stop", "--name", &name, "--reason", "external"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let stopped = owner.client.run(&h, &id, &stop);
    assert_eq!(stopped, json!({"ok": true}));
    let db = open_db(&h);
    let stopped: String = db
        .query_row(
            "SELECT data FROM events WHERE type = 'life' AND instance = ?1
           AND json_extract(data, '$.action') = 'stopped' ORDER BY id DESC LIMIT 1",
            [&name],
            |row| row.get(0),
        )
        .expect("genuine stopped snapshot");
    let stopped: Value = serde_json::from_str(&stopped).expect("stopped event JSON");
    assert_eq!(stopped["process_id"], id);
    assert_eq!(stopped["snapshot"]["pid"], owner.client.pid);
    let native = live_incarnation(owner.client.pid);
    let (boot, ticks) = native
        .strip_prefix("linux:")
        .expect("native Linux identity")
        .rsplit_once(':')
        .expect("native boot and ticks");
    assert_eq!(
        stopped["snapshot"]["pid_start_time"],
        ticks.parse::<u64>().unwrap()
    );
    assert_eq!(stopped["snapshot"]["boot_id"], boot);
    assert_eq!(stopped["snapshot"]["last_event_id"], consumed);
    let released: (i64, i64, i64) = db
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM instances WHERE name = ?1),
                (SELECT COUNT(*) FROM process_bindings WHERE instance_name = ?1),
                (SELECT COUNT(*) FROM session_bindings WHERE instance_name = ?1)",
            [&name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read released owner state");
    assert_eq!(released, (0, 0, 0));
    drop(db);

    let mut nested = owner.client.spawn_nested(&h, &id);
    let cwd = h.workspace.join(session);
    let request = format!(
        "cd {} && H {} start --as {}\n",
        quote(path_text(&cwd)),
        quote(&id),
        quote(&name),
    );
    let before = persistent_state(&h);
    let (code, stdout, stderr) = nested.request_output(&h, &request);
    assert_ne!(
        code, "0",
        "nested historical borrower succeeded: {stdout} {stderr}"
    );
    assert!(
        !stderr.trim().is_empty(),
        "historical refusal omitted its diagnostic: {stdout}"
    );
    assert_eq!(
        persistent_state(&h),
        before,
        "borrowed historical reclaim mutated fixture state"
    );

    // Explicit same-owner rejoin is allowed, unlike an exiting owner's late
    // automatic omp-start. This is the actual plaintext CLI, not a hook RPC.
    let (code, stdout, stderr) = owner.client.request_output(&h, &request);
    assert_eq!(
        code, "0",
        "native owner historical restore failed: {stdout} {stderr}"
    );
    assert_owner_pin(&h, &name, owner.client.pid);
    assert_binding(&h, &id, &name, session);
    let actual: (String, String, String, String, i64) = open_db(&h)
        .query_row(
            "SELECT tool, session_id, directory, transcript_path, last_event_id
         FROM instances WHERE name = ?1",
            [&name],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("native owner restored metadata");
    assert_eq!(
        actual,
        (
            "omp".to_owned(),
            session.to_owned(),
            path_text(&cwd).to_owned(),
            path_text(&cwd.join("transcript.jsonl")).to_owned(),
            consumed,
        )
    );
    let trusted = owner.client.run(&h, &id, &ack);
    assert_eq!(
        trusted,
        json!({"acked_to": consumed}),
        "restored alias lost native hook trust"
    );
    assert_eq!(unread_ids(&h, &name), vec![pending]);
    let identities: i64 = open_db(&h)
        .query_row("SELECT COUNT(*) FROM instances", [], |row| row.get(0))
        .expect("count historical restored identities");
    assert_eq!(
        identities, 1,
        "historical owner restore minted a duplicate identity"
    );
}

#[test]
fn foreign_presenter_cannot_bind_borrowed_omp_owner_id() {
    let h = fixture();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve owner plugin port");
    let port = listener.local_addr().expect("local plugin address").port();
    let mut owner = FakeOmp::spawn(&h, "owner");
    let name = bind_owner(&h, &mut owner.client, "owner-session", port);
    let id = owner.client.minted_id();
    let unread = seed_message(&h, &name, "foreign presenter must not consume owner mail");
    let mut nested = owner.client.spawn_nested(&h, &id);
    let foreign_session = "foreign-codex-session";
    let (cwd, _) = paths(&h, foreign_session);
    let payload = nested.out_dir.join("foreign-sessionstart.json");
    fs::write(
        &payload,
        json!({"session_id": foreign_session, "cwd": cwd}).to_string(),
    )
    .expect("write valid isolated Codex sessionstart payload");
    let request = format!(
        "HCOM_PROCESS_ID={} HCOM_LAUNCHED=1 HCOM_TOOL=codex \
         \"$TEST_BIN\" codex-sessionstart < {}\n",
        quote(&id),
        quote(path_text(&payload)),
    );
    let before = persistent_state(&h);
    let (code, stdout, stderr) = nested.request_output(&h, &request);
    // Generic JSON-stdin hooks can intentionally refuse with exit 0 and empty
    // stdout. No hook-RPC JSON error requirement applies to this presenter.
    assert_eq!(
        persistent_state(&h),
        before,
        "foreign presenter changed owner state: exit={code} stdout={stdout} stderr={stderr}",
    );
    let db = open_db(&h);
    let attached: i64 = db
        .query_row(
            "SELECT (SELECT COUNT(*) FROM instances WHERE session_id = ?1)
             + (SELECT COUNT(*) FROM session_bindings WHERE session_id = ?1)
             + (SELECT COUNT(*) FROM process_bindings WHERE session_id = ?1)",
            [foreign_session],
            |row| row.get(0),
        )
        .expect("query foreign presenter bindings");
    assert_eq!(
        attached, 0,
        "foreign presenter acquired a persistent identity"
    );
    assert_eq!(unread_ids(&h, &name), vec![unread]);
    assert_owner_pin(&h, &name, owner.client.pid);
}
