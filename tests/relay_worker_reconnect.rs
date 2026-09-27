//! Relay worker MQTT reconnect: a broker that drops the session after CONNACK
//! must be survived by the same worker process — reconnect with visible
//! `relay.disconnected` / `relay.reconnect_attempt` / `relay.connected` log
//! events, a live `hcom relay` status while disconnected, and no restart.
//! Shutdown arriving while the worker is in reconnect backoff still exits.
#![cfg(unix)]

mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use support::Hcom;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

const READY_TIMEOUT: Duration = Duration::from_secs(15);
/// Generous bound for broker-driven event sequences (reconnect cycles ride
/// rumqttc's 1s+ retry pacing).
const EVENT_TIMEOUT: Duration = Duration::from_secs(60);

/// A worker child that is always killed and reaped when the test ends.
struct Worker {
    child: Child,
}

impl Worker {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn is_running(&mut self) -> bool {
        self.child.try_wait().expect("poll worker").is_none()
    }

    fn wait_exit(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll worker") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn pid_file(h: &Hcom) -> PathBuf {
    h.hcom_dir.join(".tmp").join("relay.pid")
}

fn read_pid_file(h: &Hcom) -> Option<u32> {
    std::fs::read_to_string(pid_file(h))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Launch `relay-worker` from `cmd` and wait until its pidfile names it.
fn start_worker(h: &Hcom, mut cmd: Command) -> Worker {
    cmd.arg("relay-worker")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Own process group, so the fixture's group sweep also reaps it.
    #[cfg(unix)]
    cmd.process_group(0);
    let deadline = Instant::now() + READY_TIMEOUT;
    // A binary copied moments ago can briefly read as busy: a concurrent
    // test's fork may hold the copy's write fd until that child execs.
    let child = loop {
        match cmd.spawn() {
            Ok(child) => break child,
            Err(e)
                if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("spawn relay-worker: {e}"),
        }
    };
    h.track_cleanup_pid(i64::from(child.id()));
    let mut worker = Worker { child };

    loop {
        if read_pid_file(h) == Some(worker.pid()) {
            return worker;
        }
        if let Some(status) = worker.child.try_wait().expect("poll worker") {
            panic!("relay-worker exited before becoming ready: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "relay-worker (PID {}) never wrote its pidfile",
            worker.pid()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ── Fake broker ─────────────────────────────────────────────────────

/// Minimal MQTT v5 broker for the reconnect tests: reads the CONNECT packet,
/// answers a bare CONNACK, then closes the socket — "the broker drops the
/// session after CONNACK". The whole listener can be stopped (every connect
/// is refused — a broker outage) and restarted on the same port.
struct FakeBroker {
    port: u16,
    stop: Arc<AtomicBool>,
    accept_thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeBroker {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake broker");
        let port = listener.local_addr().expect("fake broker addr").port();
        let mut broker = Self {
            port,
            stop: Arc::new(AtomicBool::new(false)),
            accept_thread: None,
        };
        broker.listen_on(listener);
        broker
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn listen_on(&mut self, listener: TcpListener) {
        self.stop.store(false, Ordering::Relaxed);
        let stop = Arc::clone(&self.stop);
        self.accept_thread = Some(std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("fake broker nonblocking");
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => drop_session_after_connack(stream),
                    Err(_) => std::thread::sleep(Duration::from_millis(25)),
                }
            }
        }));
    }

    /// Kill the broker: the listener goes away and every connect is refused.
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.accept_thread.take() {
            let _ = t.join();
        }
    }

    /// Bring the broker back on the same port.
    fn restart(&mut self) {
        self.stop();
        let listener = TcpListener::bind(("127.0.0.1", self.port)).expect("rebind fake broker");
        self.listen_on(listener);
    }
}

impl Drop for FakeBroker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.accept_thread.take() {
            let _ = t.join();
        }
    }
}

/// Answer CONNECT with CONNACK (MQTT v5, no properties), then close — every
/// accepted session is dropped right after the handshake.
fn drop_session_after_connack(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 2048];
    let mut saw_connect = false;
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 {
            break;
        }
        // CONNECT is the first packet on the wire (type 0x10).
        if buf[0] == 0x10 {
            saw_connect = true;
            break;
        }
    }
    if saw_connect {
        // CONNACK: type 0x20, remaining length 3, ack flags 0, reason code 0,
        // property length 0.
        let _ = stream.write_all(&[0x20, 0x03, 0x00, 0x00, 0x00]);
        let _ = stream.flush();
    }
    drop(stream);
}

// ── Log assertions ──────────────────────────────────────────────────

fn read_log(h: &Hcom) -> String {
    std::fs::read_to_string(h.hcom_dir.join(".tmp").join("logs").join("hcom.log"))
        .unwrap_or_default()
}

fn event_count(log: &str, event: &str) -> usize {
    log.matches(&format!("\"event\":\"{event}\"")).count()
}

fn wait_for<F: Fn(&str) -> bool>(h: &Hcom, what: &str, timeout: Duration, cond: F) {
    let deadline = Instant::now() + timeout;
    loop {
        let log = read_log(h);
        if cond(&log) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}\n--- log ---\n{log}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ── Fixture setup ───────────────────────────────────────────────────

/// Point the isolated hcom at the fake broker. `relay new` starts a worker of
/// its own, so it runs under managed mode (which never spawns) and the test
/// then takes ownership of the worker process in unmanaged mode — the mode
/// the reported bug was in.
fn configure_relay(h: &Hcom, port: u16) {
    let (code, stdout, stderr) = h.run(["config", "relay_worker_managed", "true"]);
    assert_eq!(code, 0, "set managed: stdout={stdout} stderr={stderr}");
    let (code, stdout, stderr) = h.run([
        "relay",
        "new",
        "--broker",
        &format!("mqtt://127.0.0.1:{port}"),
    ]);
    assert_eq!(code, 0, "relay new: stdout={stdout} stderr={stderr}");
    let (code, stdout, stderr) = h.run(["config", "relay_worker_managed", "false"]);
    assert_eq!(code, 0, "unset managed: stdout={stdout} stderr={stderr}");
}

// ── Tests ───────────────────────────────────────────────────────────

/// A broker that drops the session right after CONNACK must be survived by
/// the same worker process: it logs the disconnect epoch, retries visibly,
/// reconnects (with downtime), shows `reconnecting (...)` in `hcom relay`
/// status during a full outage, and comes back when the broker does — with
/// no process restart at any point.
#[cfg(unix)]
#[test]
fn broker_drop_after_connack_reconnects_same_worker() {
    let h = Hcom::new();
    let mut broker = FakeBroker::start();
    configure_relay(&h, broker.port());
    let mut worker = start_worker(&h, h.cmd());
    let pid = worker.pid();

    // First session connects.
    wait_for(&h, "first MQTT connect", EVENT_TIMEOUT, |log| {
        event_count(log, "relay.connected") >= 1
    });

    // The broker drops each session after CONNACK: the same worker must log
    // the disconnect epoch and reach `connected` again — repeatedly.
    wait_for(&h, "reconnect after broker drop", EVENT_TIMEOUT, |log| {
        event_count(log, "relay.connected") >= 3
    });
    let log = read_log(&h);
    assert!(
        event_count(&log, "relay.disconnected") >= 1,
        "no disconnect epoch logged\n{log}"
    );
    assert!(
        event_count(&log, "relay.reconnect_attempt") >= 1,
        "no reconnect attempt logged\n{log}"
    );
    assert!(
        log.contains("attempt ") && log.contains("next in "),
        "reconnect attempts carry no attempt count / next delay\n{log}"
    );
    assert_eq!(
        event_count(&log, "relay_worker.start"),
        1,
        "worker restarted instead of reconnecting\n{log}"
    );
    assert_eq!(read_pid_file(&h), Some(pid), "worker pid changed");
    assert!(worker.is_running(), "worker died across broker drops");

    // Full outage: the worker keeps retrying and the status must show the
    // live retry state instead of a frozen first error.
    let attempts_before = event_count(&read_log(&h), "relay.reconnect_attempt");
    broker.stop();
    wait_for(&h, "retry attempts during outage", EVENT_TIMEOUT, |log| {
        event_count(log, "relay.reconnect_attempt") >= attempts_before + 2
    });
    let (code, stdout, stderr) = h.run(["relay", "status"]);
    assert_eq!(code, 0, "relay status: stdout={stdout} stderr={stderr}");
    assert!(
        stdout.contains("reconnecting (attempt") && stdout.contains("last error:"),
        "status must show live reconnect state during the outage: {stdout}"
    );
    assert!(worker.is_running(), "worker died during broker outage");

    // Broker back: the same worker reaches `connected` again.
    let connected_before = event_count(&read_log(&h), "relay.connected");
    broker.restart();
    wait_for(&h, "reconnect after broker restart", EVENT_TIMEOUT, |log| {
        event_count(log, "relay.connected") > connected_before
    });
    assert_eq!(
        event_count(&read_log(&h), "relay_worker.start"),
        1,
        "worker restarted instead of reconnecting"
    );
    assert_eq!(read_pid_file(&h), Some(pid), "worker pid changed");
    assert!(worker.is_running(), "worker died across the outage");
}

/// Shutdown arriving while the worker is in reconnect backoff exits the
/// process promptly — the reconnect loop must not swallow SIGTERM or loop.
#[cfg(unix)]
#[test]
fn shutdown_during_reconnect_backoff_exits() {
    let h = Hcom::new();
    let mut broker = FakeBroker::start();
    configure_relay(&h, broker.port());
    let mut worker = start_worker(&h, h.cmd());
    wait_for(&h, "first MQTT connect", EVENT_TIMEOUT, |log| {
        event_count(log, "relay.connected") >= 1
    });

    // Kill the broker: the worker enters its reconnect retry backoff.
    broker.stop();
    wait_for(&h, "reconnect attempts", EVENT_TIMEOUT, |log| {
        event_count(log, "relay.reconnect_attempt") >= 2
    });

    let rc = unsafe { nix::libc::kill(worker.pid() as i32, nix::libc::SIGTERM) };
    assert_eq!(rc, 0, "SIGTERM delivery failed");
    // The graceful stop publishes a tombstone and waits up to 5s for its
    // PUBACK; anything well past that means the signal was swallowed by a
    // loop instead of ending the process.
    let status = worker
        .wait_exit(Duration::from_secs(15))
        .expect("relay-worker did not exit within 15s of SIGTERM during backoff");
    assert!(status.success(), "status={status}");
    assert!(!pid_file(&h).exists(), "pidfile left behind after SIGTERM");
}
