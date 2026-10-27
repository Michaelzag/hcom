//! A remote `hcom kill <name>:<DEVICE>` reports the executing host's verified
//! outcome. Two fixture devices, a caller and an executor, each with its own
//! isolated HOME/HCOM_DIR/TMPDIR, sync through a loopback MQTT v5 broker owned
//! by this test. The real `hcom kill` CLI runs on the caller against a row
//! seeded on the executor, whose relay worker runs the kill. A partial result
//! (seat launcher not verified) and a refusal must reach the caller as a
//! nonzero exit carrying the executor's warning; only a clean kill prints the
//! success report.
//!
//! The relay setup follows `relay_worker_reconnect.rs`: managed mode, so hcom
//! itself never spawns a worker, `relay new --broker mqtt://127.0.0.1:<port>`,
//! and `relay-worker` children this test starts and reaps. Unlike that file's
//! broker, which only answers CONNECT, this one routes: SUBSCRIBE with
//! wildcards, QoS 1 PUBLISH with PUBACK, and retained state, which is what
//! the relay needs to carry a device's state snapshot and an RPC round trip.
//!
//! Every process here is a child of this test: both relay workers, the owner
//! stand-ins and the PID-reuse sentinel. Nothing reaches a real broker, HOME
//! or hcom state.
#![cfg(target_os = "linux")]

mod support;

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs as unix_fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use support::{Hcom, unique_suffix};

const POLL: Duration = Duration::from_millis(25);
const READY_TIMEOUT: Duration = Duration::from_secs(15);
/// Both workers connect, push and import the other's retained snapshot.
const SYNC_TIMEOUT: Duration = Duration::from_secs(30);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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
// Loopback MQTT v5 broker: enough of the protocol for two relay workers and
// the CLI's ephemeral publisher. Subscriptions are granted at QoS 0, so every
// routed message goes out at QoS 0 and needs no acknowledgement tracking.
// ---------------------------------------------------------------------------

struct Session {
    id: u64,
    writer: TcpStream,
    filters: Vec<String>,
}

#[derive(Default)]
struct BrokerState {
    retained: BTreeMap<String, Vec<u8>>,
    sessions: Vec<Session>,
}

impl BrokerState {
    fn send(&self, id: u64, packet: &[u8]) -> bool {
        self.sessions
            .iter()
            .find(|session| session.id == id)
            .is_some_and(|session| (&session.writer).write_all(packet).is_ok())
    }

    fn route(&self, topic: &str, payload: &[u8]) {
        let packet = publish_packet(false, topic, payload);
        for session in &self.sessions {
            if session.filters.iter().any(|f| topic_matches(f, topic)) {
                let _ = (&session.writer).write_all(&packet);
            }
        }
    }
}

struct Broker {
    port: u16,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<BrokerState>>,
    threads: Arc<Mutex<Vec<JoinHandle<()>>>>,
    accept: Option<JoinHandle<()>>,
}

impl Broker {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture broker");
        listener
            .set_nonblocking(true)
            .expect("fixture broker nonblocking");
        let port = listener.local_addr().expect("fixture broker addr").port();
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(BrokerState::default()));
        let threads = Arc::new(Mutex::new(Vec::new()));
        let accept = {
            let (stop, state, threads) = (stop.clone(), state.clone(), threads.clone());
            std::thread::spawn(move || {
                let mut next_id = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let Ok((stream, _)) = listener.accept() else {
                        std::thread::sleep(POLL);
                        continue;
                    };
                    let _ = stream.set_nonblocking(false);
                    let Ok(writer) = stream.try_clone() else {
                        continue;
                    };
                    let _ = writer.set_write_timeout(Some(Duration::from_secs(5)));
                    next_id += 1;
                    let id = next_id;
                    lock(&state).sessions.push(Session {
                        id,
                        writer,
                        filters: Vec::new(),
                    });
                    let state = state.clone();
                    lock(&threads).push(std::thread::spawn(move || serve(id, stream, &state)));
                }
            })
        };
        Self {
            port,
            stop,
            state,
            threads,
            accept: Some(accept),
        }
    }

    fn url(&self) -> String {
        format!("mqtt://127.0.0.1:{}", self.port)
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        for session in &lock(&self.state).sessions {
            let _ = session.writer.shutdown(Shutdown::Both);
        }
        let handles = std::mem::take(&mut *lock(&self.threads));
        for handle in handles {
            let _ = handle.join();
        }
    }
}

fn serve(id: u64, mut stream: TcpStream, state: &Mutex<BrokerState>) {
    while let Ok((header, body)) = read_packet(&mut stream) {
        if handle_packet(id, header, &body, state).is_none() {
            break;
        }
    }
    lock(state).sessions.retain(|session| session.id != id);
    let _ = stream.shutdown(Shutdown::Both);
}

/// One client packet. `None` ends the session: DISCONNECT, a malformed
/// packet, or anything this broker does not speak.
fn handle_packet(id: u64, header: u8, body: &[u8], state: &Mutex<BrokerState>) -> Option<()> {
    let mut state = lock(state);
    let mut cur = Cursor { buf: body, at: 0 };
    match header >> 4 {
        // CONNECT -> CONNACK: no session present, success, no properties.
        1 => state.send(id, &[0x20, 0x03, 0x00, 0x00, 0x00]).then_some(()),
        // PUBLISH
        3 => {
            let qos = (header >> 1) & 0x03;
            let topic = cur.string()?;
            let packet_id = match qos {
                0 => None,
                1 => Some(cur.u16()?),
                _ => return None,
            };
            let properties = cur.varint()?;
            cur.take(properties)?;
            let payload = cur.rest();
            if let Some(packet_id) = packet_id {
                let [hi, lo] = packet_id.to_be_bytes();
                state.send(id, &[0x40, 0x02, hi, lo]).then_some(())?;
            }
            if header & 0x01 == 1 {
                if payload.is_empty() {
                    state.retained.remove(&topic);
                } else {
                    state.retained.insert(topic.clone(), payload.to_vec());
                }
            }
            state.route(&topic, payload);
            Some(())
        }
        // PUBACK from a client: everything routed is QoS 0, nothing to track.
        4 => Some(()),
        // SUBSCRIBE -> SUBACK granting QoS 0, then the matching retained set.
        8 => {
            let packet_id = cur.u16()?;
            let properties = cur.varint()?;
            cur.take(properties)?;
            let mut filters = Vec::new();
            while !cur.done() {
                filters.push(cur.string()?);
                cur.take(1)?;
            }
            let mut suback = packet_id.to_be_bytes().to_vec();
            suback.push(0x00);
            suback.extend(filters.iter().map(|_| 0x00));
            state.send(id, &packet(0x90, &suback)).then_some(())?;
            let retained: Vec<Vec<u8>> = state
                .retained
                .iter()
                .filter(|(topic, _)| filters.iter().any(|f| topic_matches(f, topic)))
                .map(|(topic, payload)| publish_packet(true, topic, payload))
                .collect();
            for publish in retained {
                state.send(id, &publish).then_some(())?;
            }
            state
                .sessions
                .iter_mut()
                .find(|session| session.id == id)?
                .filters
                .extend(filters);
            Some(())
        }
        // UNSUBSCRIBE -> UNSUBACK
        10 => {
            let packet_id = cur.u16()?;
            let properties = cur.varint()?;
            cur.take(properties)?;
            let mut filters = Vec::new();
            while !cur.done() {
                filters.push(cur.string()?);
            }
            let mut unsuback = packet_id.to_be_bytes().to_vec();
            unsuback.push(0x00);
            unsuback.extend(filters.iter().map(|_| 0x00));
            state
                .sessions
                .iter_mut()
                .find(|session| session.id == id)?
                .filters
                .retain(|f| !filters.contains(f));
            state.send(id, &packet(0xB0, &unsuback)).then_some(())
        }
        // PINGREQ -> PINGRESP
        12 => state.send(id, &[0xD0, 0x00]).then_some(()),
        _ => None,
    }
}

fn read_packet(stream: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte)?;
    let header = byte[0];
    let mut len = 0usize;
    for shift in [0, 7, 14, 21] {
        stream.read_exact(&mut byte)?;
        len |= usize::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            let mut body = vec![0; len];
            stream.read_exact(&mut body)?;
            return Ok((header, body));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "malformed MQTT remaining length",
    ))
}

fn packet(header: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![header];
    let mut len = body.len();
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out.extend_from_slice(body);
    out
}

/// A QoS 0 PUBLISH with no properties.
fn publish_packet(retain: bool, topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut body = (topic.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(topic.as_bytes());
    body.push(0x00);
    body.extend_from_slice(payload);
    packet(0x30 | u8::from(retain), &body)
}

fn topic_matches(filter: &str, topic: &str) -> bool {
    let mut levels = topic.split('/');
    for part in filter.split('/') {
        match part {
            "#" => return true,
            "+" => {
                if levels.next().is_none() {
                    return false;
                }
            }
            exact => {
                if levels.next() != Some(exact) {
                    return false;
                }
            }
        }
    }
    levels.next().is_none()
}

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let slice = self.buf.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(slice)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn string(&mut self) -> Option<String> {
        let len = usize::from(self.u16()?);
        String::from_utf8(self.take(len)?.to_vec()).ok()
    }

    fn varint(&mut self) -> Option<usize> {
        let mut value = 0usize;
        for shift in [0, 7, 14, 21] {
            let byte = self.take(1)?[0];
            value |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.buf[self.at..];
        self.at = self.buf.len();
        rest
    }

    fn done(&self) -> bool {
        self.at >= self.buf.len()
    }
}

// ---------------------------------------------------------------------------
// Fixture devices
// ---------------------------------------------------------------------------

fn db(h: &Hcom) -> Connection {
    let conn = Connection::open(h.path().join("hcom.db")).expect("open fixture database");
    conn.busy_timeout(Duration::from_secs(5))
        .expect("fixture database busy timeout");
    conn
}

fn log_tail(h: &Hcom) -> String {
    let log = fs::read_to_string(h.path().join(".tmp/logs/hcom.log")).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

struct Device {
    h: Hcom,
    worker: Option<Child>,
}

impl Device {
    /// Managed mode, as in the reconnect tests: hcom never spawns a relay
    /// worker by itself, so the only workers are the ones this test starts
    /// and reaps, and a managed worker never auto-exits mid-test.
    fn new() -> Self {
        let h = Hcom::new();
        let (code, stdout, stderr) = h.run(["config", "relay_worker_managed", "true"]);
        assert_eq!(code, 0, "set managed: {stdout} {stderr}");
        Self { h, worker: None }
    }

    fn run(&self, args: &[&str]) -> (i32, String) {
        let (code, stdout, stderr) = self.h.run(args);
        (code, format!("{stdout}\n{stderr}"))
    }

    fn start_worker(&mut self) {
        let pid_file = self.h.path().join(".tmp/relay.pid");
        let mut command = self.h.cmd();
        command
            .arg("relay-worker")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let deadline = Instant::now() + READY_TIMEOUT;
        // A binary copied moments ago can briefly read as busy while a
        // concurrent test's fork still holds the write fd.
        let child = loop {
            match command.spawn() {
                Ok(child) => break child,
                Err(e)
                    if e.kind() == io::ErrorKind::ExecutableFileBusy
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(POLL);
                }
                Err(e) => panic!("spawn relay-worker: {e}"),
            }
        };
        let pid = child.id();
        let worker = self.worker.insert(child);
        let ready = wait_until(READY_TIMEOUT, || {
            fs::read_to_string(&pid_file)
                .ok()
                .and_then(|text| text.trim().parse::<u32>().ok())
                == Some(pid)
                || worker.try_wait().ok().flatten().is_some()
        });
        let exited = worker.try_wait().expect("poll relay-worker");
        assert!(
            ready && exited.is_none(),
            "relay-worker {pid} never became ready (exit {exited:?})\n{}",
            log_tail(&self.h)
        );
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            let _ = worker.kill();
            let _ = worker.wait();
        }
        // `Hcom::drop` runs `kill all`, which acts on every row PID. By now each
        // fixture process is reaped, so a recorded PID may already belong to
        // somebody else, and a mirrored remote row would send a kill over a
        // relay that is gone. Only this fixture's private state is touched.
        if let Ok(conn) = Connection::open(self.h.path().join("hcom.db")) {
            let _ = conn.busy_timeout(Duration::from_secs(5));
            let _ = conn.execute("UPDATE instances SET pid=NULL", []);
            let _ = conn.execute(
                "DELETE FROM instances WHERE COALESCE(origin_device_id, '') != ''",
                [],
            );
        }
    }
}

/// Caller and executor joined to one relay group on the fixture broker.
/// Field order is drop order: both devices (and their workers) go before the
/// broker.
struct Pair {
    caller: Device,
    executor: Device,
    _broker: Broker,
}

impl Pair {
    fn new() -> Self {
        let broker = Broker::start();
        let caller = Device::new();
        let executor = Device::new();
        let (code, output) = caller.run(&["relay", "new", "--broker", &broker.url()]);
        assert_eq!(code, 0, "caller relay new: {output}");
        let token = output
            .lines()
            .find_map(|line| line.trim().strip_prefix("On other devices: hcom relay connect "))
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or_else(|| panic!("no join token in `relay new` output:\n{output}"))
            .to_owned();
        let (code, output) = executor.run(&["relay", "connect", &token]);
        assert_eq!(code, 0, "executor relay connect: {output}");
        Self {
            caller,
            executor,
            _broker: broker,
        }
    }

    /// Start both workers after the executor's rows are seeded, so its first
    /// pushed snapshot already carries them.
    fn start_workers(&mut self) {
        self.caller.start_worker();
        self.executor.start_worker();
    }

    /// The executor's `base` row as the caller mirrors it: `<base>:<DEVICE>`.
    fn remote_target(&self, base: &str) -> String {
        let conn = db(&self.caller.h);
        let mut target = None;
        wait_until(SYNC_TIMEOUT, || {
            target = conn
                .query_row(
                    "SELECT name FROM instances
                      WHERE COALESCE(origin_device_id, '') != '' AND name LIKE ?1 || ':%'",
                    [base],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .unwrap_or(None);
            target.is_some()
        });
        target.unwrap_or_else(|| {
            panic!(
                "caller never mirrored the executor's row {base}\n{}",
                self.diagnostics()
            )
        })
    }

    fn kill(&self, target: &str) -> (i32, String) {
        self.caller.run(&["kill", target])
    }

    fn diagnostics(&self) -> String {
        format!(
            "--- caller hcom.log ---\n{}\n--- executor hcom.log ---\n{}",
            log_tail(&self.caller.h),
            log_tail(&self.executor.h)
        )
    }
}

/// A legacy bound row on the executor: row, process binding and session
/// binding, recorded PID `pid`, and no launch context, so no identity receipt
/// and no `omp_launch_root`.
fn seed_row(h: &Hcom, name: &str, tool: &str, process_id: &str, pid: u32) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    // status_time is integer epoch seconds, as hcom writes it.
    let status_time = now as i64;
    let conn = db(h);
    let sid = format!("sid-{name}");
    conn.execute(
        "INSERT INTO instances (name, tool, session_id, status, status_context, status_time, created_at, last_event_id, pid)
         VALUES (?1, ?2, ?3, 'listening', 'start', ?4, ?5, 0, ?6)",
        rusqlite::params![name, tool, sid, status_time, now, pid],
    )
    .expect("seed legacy row");
    conn.execute(
        "INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![process_id, sid, name, now],
    )
    .expect("seed legacy process binding");
    conn.execute(
        "INSERT INTO session_bindings (session_id, instance_name, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![sid, name, now],
    )
    .expect("seed legacy session binding");
}

/// The success report of a remote kill, in any of its rendered forms.
fn reports_success(output: &str) -> bool {
    output.contains("Sent SIGTERM to process group")
        || output.contains("already terminated")
        || output.contains("To resume: hcom r")
}

/// Whether the executor still holds `name`'s row and any process binding.
fn bookkeeping(h: &Hcom, name: &str) -> Value {
    let conn = db(h);
    let count = |sql: &str| -> i64 {
        conn.query_row(sql, [name], |row| row.get(0))
            .expect("read executor bookkeeping")
    };
    json!({
        "row": count("SELECT COUNT(*) FROM instances WHERE name=?1"),
        "process_bindings": count("SELECT COUNT(*) FROM process_bindings WHERE instance_name=?1"),
    })
}

fn torn_down() -> Value {
    json!({"row": 0, "process_bindings": 0})
}

// ---------------------------------------------------------------------------
// Owner stand-ins and sentinels: a bash loop that records every trapped
// signal and keeps a heartbeat. The direct child is never reaped before the
// final drop (exit is observed with WNOWAIT), so its PID and process group
// stay reserved and the drop's group SIGKILL only reaches this fixture.
// ---------------------------------------------------------------------------

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

const PARENT_SIGNALS: [libc::c_int; 7] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGCONT,
];
// A background job of a non-interactive shell starts with INT/QUIT ignored,
// which bash cannot trap.
const CHILD_SIGNALS: [libc::c_int; 5] = [
    libc::SIGHUP,
    libc::SIGTERM,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGCONT,
];

fn mask(signals: &[libc::c_int]) -> u64 {
    signals
        .iter()
        .fold(0_u64, |mask, signal| mask | 1_u64 << (signal - 1))
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

/// A non-child member of a fixture group: alive only while it exists, is not
/// a zombie and is still in that group, so a later PID reuser never reads as
/// it.
fn member_alive(pid: u32, pgid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some(close) = stat.rfind(')') else {
        return false;
    };
    let mut fields = stat[close + 2..].split_whitespace();
    let state = fields.next().and_then(|s| s.chars().next());
    let pgrp = fields.nth(1).and_then(|s| s.parse::<i64>().ok());
    matches!((state, pgrp), (Some(state), Some(pgrp)) if state != 'Z' && pgrp == i64::from(pgid))
}

fn beats(dir: &Path) -> u64 {
    fs::metadata(dir.join("heartbeat"))
        .map(|stat| stat.len())
        .unwrap_or(0)
}

/// A stand-in whose comm reads as `omp`: `/bin/bash` run through a symlink
/// named `omp`.
fn omp_standin(h: &Hcom) -> PathBuf {
    let dir = h.root_path().join("fakebin");
    fs::create_dir_all(&dir).expect("create fakebin");
    let omp = dir.join("omp");
    if !omp.exists() {
        unix_fs::symlink("/bin/bash", &omp).expect("symlink omp stand-in");
    }
    omp
}

/// Birth identity of `pid`: its start time in clock ticks since boot, field
/// 22 of /proc/<pid>/stat. Readable for a zombie too.
fn start_ticks(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat[stat.rfind(')')? + 2..]
        .split_whitespace()
        .nth(19)
        .map(str::to_owned)
}

struct Sentinel {
    child: Child,
    /// Start ticks captured right after spawn, rechecked before the group
    /// kill in `Drop`.
    birth: Option<String>,
    dir: PathBuf,
    sub: Option<u32>,
}

impl Sentinel {
    /// Bash sentinel run as `exe`, in its own process group, with a cleared
    /// environment plus `env`. `with_child` adds a child in the same group.
    fn spawn(h: &Hcom, label: &str, exe: &Path, env: &[(&str, &str)], with_child: bool) -> Self {
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
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        if with_child {
            command.env("SENTINEL_CHILD", "1");
        }
        for (key, value) in env {
            command.env(key, value);
        }
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
        let child = command
            .spawn()
            .unwrap_or_else(|e| panic!("spawn sentinel {label}: {e}"));
        let birth = start_ticks(child.id());
        let mut sentinel = Self {
            child,
            birth,
            dir,
            sub: None,
        };
        assert!(
            sentinel.birth.is_some(),
            "sentinel {label}: could not read the birth identity of PID {}",
            sentinel.pid()
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(exit) = sentinel.peek_exit() {
                panic!("sentinel {label} exited during setup: {exit}");
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
                            && caught_signals(pid) & mask(&CHILD_SIGNALS) == mask(&CHILD_SIGNALS)
                    })
                    .map(|pid| sentinel.sub = Some(pid))
                    .is_some();
            if parent_ready && child_ready {
                return sentinel;
            }
            assert!(
                Instant::now() < deadline,
                "sentinel {label} never became ready"
            );
            std::thread::sleep(POLL);
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Exit of the direct child without reaping it, or None while it runs.
    fn peek_exit(&self) -> Option<String> {
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
            "waitid on sentinel {}: {}",
            self.pid(),
            io::Error::last_os_error()
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

    fn beats(&self) -> (u64, u64) {
        (beats(&self.dir), beats(&self.dir.join("child")))
    }

    /// After a command: wait (bounded) until both heartbeats advanced at
    /// least twice, which proves any signal already sent had its trap run, or
    /// until either process is gone. Then report what the tree went through.
    fn observe(&self, before: (u64, u64)) -> Value {
        let (mut parent, mut child) = (false, false);
        wait_until(Duration::from_secs(5), || {
            let now = self.beats();
            parent = now.0 >= before.0 + 2;
            child = self.sub.is_none() || now.1 >= before.1 + 2;
            let gone = self.peek_exit().is_some()
                || self.sub.is_some_and(|pid| !member_alive(pid, self.pid()));
            (parent && child) || gone
        });
        let read = |path: PathBuf| fs::read_to_string(path).unwrap_or_default();
        json!({
            "alive": self.peek_exit().is_none(),
            "heartbeat_progressed": parent,
            "signals": read(self.dir.join("signals")),
            "child": self.sub.map(|pid| json!({
                "alive": member_alive(pid, self.pid()),
                "heartbeat_progressed": child,
                "signals": read(self.dir.join("child/signals")),
            })),
        })
    }

    fn spared(&self) -> Value {
        json!({
            "alive": true,
            "heartbeat_progressed": true,
            "signals": "",
            "child": self.sub.map(|_| json!({
                "alive": true,
                "heartbeat_progressed": true,
                "signals": "",
            })),
        })
    }
}

impl Drop for Sentinel {
    /// Kill the group only while it is provably this sentinel's: the leader
    /// is still unreaped (so its PID and group id cannot be reused), it was
    /// born when spawn recorded, and it still leads its own group. Otherwise
    /// signal the owned child alone. Then reap.
    fn drop(&mut self) {
        let pid = self.pid() as libc::pid_t;
        // waitid with WNOWAIT succeeds only while the child is ours and not
        // yet reaped, running or zombie; it never reaps.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let unreaped = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } == 0;
        let owned_group = unreaped
            && self.birth.is_some()
            && start_ticks(self.pid()) == self.birth
            && unsafe { libc::getpgid(pid) } == pid;
        if owned_group {
            unsafe {
                libc::killpg(pid, libc::SIGKILL);
            }
        } else {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The fixture terminal preset the executor's row was launched under. Its
/// close command records the pane id it was asked to close, then fails.
const PANE_PRESET: &str = "rkfail";

/// Pre-upgrade pane ownership for the executor's row `name`: the preset in
/// the row, the pane ids in its launch context (no identity or root receipt),
/// and the launch receipt in exactly the shape `write_terminal_id` writes,
/// naming `receipt_preset`. The real `closeable_terminal_id` gate decides
/// whether the kill may close the pane. Returns (close marker, pane id,
/// close script).
fn seed_pane(
    h: &Hcom,
    name: &str,
    process_id: &str,
    receipt_preset: &str,
) -> (PathBuf, String, PathBuf) {
    let marker = h.root_path().join("pane-close-attempt");
    let script = h.root_path().join("close-pane.sh");
    fs::write(
        &script,
        format!("printf '%s' \"$1\" > '{}'\nexit 1\n", marker.display()),
    )
    .expect("write failing close script");
    let mut config = fs::OpenOptions::new()
        .append(true)
        .open(h.path().join("config.toml"))
        .expect("open executor config");
    write!(
        config,
        "\n[terminal.presets.{PANE_PRESET}]\nopen = 'sh {{script}}'\nclose = 'sh {} {{pane_id}}'\n",
        script.display()
    )
    .expect("add the failing fixture preset");
    let pane_id = format!("rkpane-{}", unique_suffix());
    let updated = db(h)
        .execute(
            "UPDATE instances SET terminal_preset_effective=?2, launch_context=?3 WHERE name=?1",
            rusqlite::params![
                name,
                PANE_PRESET,
                json!({"process_id": process_id, "terminal_id": pane_id}).to_string()
            ],
        )
        .expect("record the row's pane");
    assert_eq!(updated, 1, "no executor row {name} to give a pane");
    let owners = h.path().join(".tmp/terminal_owners");
    fs::create_dir_all(&owners).expect("create terminal owner receipts");
    fs::write(
        owners.join(process_id),
        json!({
            "instance_name": name,
            "process_id": process_id,
            "preset": receipt_preset,
            "terminal_id": pane_id,
        })
        .to_string(),
    )
    .expect("write the launch receipt");
    (marker, pane_id, script)
}

/// Rule 3 on the executor: a legacy OMP row whose live owner carries the bound
/// HCOM_PROCESS_ID, with no `hcom pty` ancestor and no `omp_launch_root`, in a
/// pane its launch receipt proves it owns. The owner tree is terminated but
/// the seat launcher is not verified, and closing the pane fails. With
/// `receipt_matches` false the receipt names another preset, so no close may
/// be attempted.
fn unverified_launcher_kill(label: &str, receipt_matches: bool) {
    let mut pair = Pair::new();
    let base = format!("{label}{}", unique_suffix());
    let process_id = uuid::Uuid::new_v4().to_string();
    let omp = omp_standin(&pair.executor.h);
    let owner = Sentinel::spawn(
        &pair.executor.h,
        "unverified-owner",
        &omp,
        &[("HCOM_PROCESS_ID", process_id.as_str())],
        false,
    );
    seed_row(&pair.executor.h, &base, "omp", &process_id, owner.pid());
    let receipt_preset = if receipt_matches {
        PANE_PRESET
    } else {
        "rkother"
    };
    let (marker, pane_id, script) =
        seed_pane(&pair.executor.h, &base, &process_id, receipt_preset);
    pair.start_workers();
    let target = pair.remote_target(&base);

    let (code, output) = pair.kill(&target);
    let exit = owner.wait_exit(Duration::from_secs(10));
    assert!(
        exit.is_some(),
        "the executor left owner {} of {base} alive after `hcom kill {target}`:\n{output}\n{}",
        owner.pid(),
        pair.diagnostics()
    );
    assert_eq!(
        bookkeeping(&pair.executor.h, &base),
        torn_down(),
        "the executor did not tear down {base} after killing its owner tree"
    );
    assert!(
        !reports_success(&output),
        "`hcom kill {target}` printed a clean success the executor did not confirm:\n{output}"
    );
    assert!(
        output.contains("launcher not verified"),
        "`hcom kill {target}` lost the executor's launcher warning:\n{output}\n{}",
        pair.diagnostics()
    );
    assert_ne!(
        code, 0,
        "`hcom kill {target}` exited 0 on an unverified launcher:\n{output}"
    );

    let attempted = fs::read_to_string(&marker).ok();
    let script = script.display().to_string();
    let retry = output
        .lines()
        .find(|line| line.contains(&script) && line.contains(&pane_id));
    if receipt_matches {
        assert_eq!(
            attempted.as_deref(),
            Some(pane_id.as_str()),
            "the executor never tried to close {base}'s owned pane {pane_id}:\n{output}\n{}",
            pair.diagnostics()
        );
        assert!(
            output.contains("but pane remains"),
            "`hcom kill {target}` did not report that pane {pane_id} remains:\n{output}"
        );
        assert!(
            retry.is_some(),
            "`hcom kill {target}` lost the executor's pane retry command `sh {script} {pane_id}`:\n{output}"
        );
    } else {
        assert_eq!(
            attempted, None,
            "SAFETY: the executor closed pane {pane_id} that {base}'s receipt does not own:\n{output}"
        );
        assert!(
            retry.is_none() && !output.contains("pane remains"),
            "`hcom kill {target}` offered a pane retry for a pane it does not own:\n{output}"
        );
    }
}

#[test]
fn remote_kill_reports_unverified_launcher_as_failure() {
    unverified_launcher_kill("rkwarn", true);
}

/// The control: the same kill, but the launch receipt names another preset.
/// The real ownership gate refuses the pane, so nothing is closed and no
/// retry is offered; the launcher warning and failure still come through.
#[test]
fn remote_kill_attempts_no_close_without_a_matching_pane_receipt() {
    unverified_launcher_kill("rknopane", false);
}

/// The executor's row names a PID now held by an unrelated live process that
/// carries no bound HCOM_PROCESS_ID, as after a crash and PID reuse. The
/// executor refuses; the caller gets a nonzero exit and the `hcom stop`
/// pointer, and the sentinel and its child are never signalled.
#[test]
fn remote_kill_reports_refusal_and_spares_pid_reuser() {
    let mut pair = Pair::new();
    let base = format!("rkreuse{}", unique_suffix());
    let process_id = uuid::Uuid::new_v4().to_string();
    let omp = omp_standin(&pair.executor.h);
    let sentinel = Sentinel::spawn(&pair.executor.h, "pid-reuser", &omp, &[], true);
    seed_row(&pair.executor.h, &base, "omp", &process_id, sentinel.pid());
    pair.start_workers();
    let target = pair.remote_target(&base);

    let before = sentinel.beats();
    let (code, output) = pair.kill(&target);
    let observed = sentinel.observe(before);
    assert_eq!(
        observed,
        sentinel.spared(),
        "SAFETY: `hcom kill {target}` signalled PID reuser {} (or its child) on the executor:\n{output}",
        sentinel.pid()
    );
    assert!(
        !reports_success(&output),
        "`hcom kill {target}` printed a clean success for a refused kill:\n{output}"
    );
    assert!(
        output.contains(&format!("hcom stop {base}")),
        "`hcom kill {target}` lost the `hcom stop` pointer:\n{output}\n{}",
        pair.diagnostics()
    );
    assert_ne!(code, 0, "refused remote kill exited 0:\n{output}");
    let kept: Option<Option<i64>> = db(&pair.executor.h)
        .query_row("SELECT pid FROM instances WHERE name=?1", [&base], |row| {
            row.get(0)
        })
        .optional()
        .expect("read executor row");
    assert_eq!(
        kept,
        Some(Some(i64::from(sentinel.pid()))),
        "the refused kill changed the executor's bookkeeping for {base}"
    );
}

/// A clean kill on the executor: a non-OMP legacy row whose live owner carries
/// the bound HCOM_PROCESS_ID. The caller exits 0 with the success report.
#[test]
fn remote_kill_reports_clean_success() {
    let mut pair = Pair::new();
    let base = format!("rkclean{}", unique_suffix());
    let process_id = uuid::Uuid::new_v4().to_string();
    let owner = Sentinel::spawn(
        &pair.executor.h,
        "clean-owner",
        Path::new("/bin/bash"),
        &[("HCOM_PROCESS_ID", process_id.as_str())],
        false,
    );
    seed_row(&pair.executor.h, &base, "claude", &process_id, owner.pid());
    pair.start_workers();
    let target = pair.remote_target(&base);

    let (code, output) = pair.kill(&target);
    let exit = owner.wait_exit(Duration::from_secs(10));
    assert!(
        exit.is_some(),
        "the executor left owner {} of {base} alive after `hcom kill {target}`:\n{output}\n{}",
        owner.pid(),
        pair.diagnostics()
    );
    assert_eq!(
        bookkeeping(&pair.executor.h, &base),
        torn_down(),
        "the executor did not tear down {base} after a clean kill"
    );
    assert_eq!(
        code,
        0,
        "clean remote kill of {target} failed:\n{output}\n{}",
        pair.diagnostics()
    );
    assert!(
        output.contains("Sent SIGTERM to process group"),
        "clean remote kill of {target} printed no success report:\n{output}"
    );
}
