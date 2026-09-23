//! Relay-worker lifetime: the lock-held singleton, prompt shutdown, managed
//! mode, and binary-replacement exit. No broker: every worker starts in
//! managed mode on a fresh HCOM_DIR, so with relay unconfigured (or a connect
//! that cannot succeed) it idles while holding the singleton lock.

mod support;

#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::Hcom;

const READY_TIMEOUT: Duration = Duration::from_secs(5);

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

fn set_managed(h: &Hcom) {
    let (code, stdout, stderr) = h.run(["config", "relay_worker_managed", "true"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
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

#[test]
fn second_worker_refused_while_first_holds_lock() {
    let h = Hcom::new();
    set_managed(&h);
    let mut a = start_worker(&h, h.cmd());

    let (code, stdout, stderr) = h.run(["relay-worker"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    assert!(
        stderr.contains(&format!("already running (PID {})", a.pid())),
        "stderr={stderr}"
    );
    assert!(
        a.is_running(),
        "first worker must survive the refused start"
    );
    assert_eq!(read_pid_file(&h), Some(a.pid()));
}

#[test]
fn stale_pidfile_with_live_unrelated_pid_does_not_block_start() {
    let h = Hcom::new();
    set_managed(&h);
    // The test process is alive and is not a relay worker.
    std::fs::create_dir_all(pid_file(&h).parent().unwrap()).unwrap();
    std::fs::write(pid_file(&h), std::process::id().to_string()).unwrap();

    let mut worker = start_worker(&h, h.cmd());
    assert!(worker.is_running());

    let (code, stdout, stderr) = h.run(["relay", "daemon", "status"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        stdout.contains(&format!("Daemon: running (PID {}, managed)", worker.pid())),
        "stdout={stdout}"
    );
}

#[cfg(unix)]
#[test]
fn sigterm_exits_promptly_and_removes_pidfile() {
    let h = Hcom::new();
    set_managed(&h);
    let mut worker = start_worker(&h, h.cmd());

    let rc = unsafe { nix::libc::kill(worker.pid() as i32, nix::libc::SIGTERM) };
    assert_eq!(rc, 0, "SIGTERM delivery failed");
    let status = worker
        .wait_exit(Duration::from_secs(3))
        .expect("relay-worker did not exit within 3s of SIGTERM");
    assert!(status.success(), "status={status}");
    assert!(!pid_file(&h).exists(), "pidfile left behind after SIGTERM");
}

#[test]
fn managed_daemon_start_without_worker_fails_and_spawns_nothing() {
    let h = Hcom::new();
    set_managed(&h);

    let (code, stdout, stderr) = h.run(["relay", "daemon", "start"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    assert!(
        stderr.contains("relay worker is managed by a service manager")
            && stderr.contains("start it there"),
        "stderr={stderr}"
    );
    assert!(!pid_file(&h).exists(), "daemon start spawned a worker");

    let (code, stdout, stderr) = h.run(["relay", "daemon", "stop"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    assert!(
        stderr.contains("relay worker is managed by a service manager")
            && stderr.contains("stop it there"),
        "stderr={stderr}"
    );

    // The lock is free: a worker started now comes up immediately.
    let mut worker = start_worker(&h, h.cmd());
    assert!(worker.is_running());
}

#[cfg(unix)]
#[test]
fn replaced_binary_makes_worker_exit() {
    let h = Hcom::new();
    set_managed(&h);

    let bin_dir = h.root_path().join("bin-copy");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let running = bin_dir.join("hcom");
    std::fs::copy(env!("CARGO_BIN_EXE_hcom"), &running).unwrap();

    // Run the copy itself: no HCOM_DEV_ROOT, or it would re-exec into the
    // cargo-built binary and the copy would not be the running image.
    let worker_cmd = |h: &Hcom| {
        let mut cmd = h.external_cmd(&running);
        cmd.env_remove("HCOM_DEV_ROOT");
        cmd
    };

    // Negative control: an untouched binary keeps the worker running.
    let mut worker = start_worker(&h, worker_cmd(&h));
    assert!(
        worker.wait_exit(Duration::from_secs(3)).is_none(),
        "worker exited although its binary was not replaced"
    );

    let replacement = bin_dir.join("hcom.new");
    std::fs::copy(env!("CARGO_BIN_EXE_hcom"), &replacement).unwrap();
    std::fs::rename(&replacement, &running).unwrap();

    let status = worker
        .wait_exit(Duration::from_secs(3))
        .expect("relay-worker did not exit within 3s of binary replacement");
    assert!(status.success(), "status={status}");
    assert!(!pid_file(&h).exists(), "pidfile left behind after exit");
}

#[test]
fn managed_reset_refuses_while_worker_runs() {
    let h = Hcom::new();
    set_managed(&h);
    let mut worker = start_worker(&h, h.cmd());
    let db = h.hcom_dir.join("hcom.db");
    assert!(db.exists(), "worker never created hcom.db");

    let (code, stdout, stderr) = h.run(["reset"]);
    assert_ne!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        stderr.contains("relay worker is managed by a service manager")
            && stderr.contains("systemctl --user stop hcom-relay")
            && stderr.contains("rerun hcom reset"),
        "stderr={stderr}"
    );
    assert!(db.exists(), "refused reset archived hcom.db");
    assert!(
        worker.wait_exit(Duration::from_secs(2)).is_none(),
        "refused reset stopped the managed worker"
    );
    let (code, stdout, stderr) = h.run(["relay", "daemon", "status"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        stdout.contains(&format!("Daemon: running (PID {}, managed)", worker.pid())),
        "worker no longer holds the lock: stdout={stdout}"
    );
}

/// Unix only: on Windows `hcom reset` cannot clear hcom.db at all. The reset
/// process keeps its own connection (and hcom.db-wal handle) open across the
/// delete, and SQLite opens without FILE_SHARE_DELETE, so the delete fails
/// with os error 32 whether or not a worker ever ran. Pre-existing, not
/// relay-worker behavior.
#[cfg(unix)]
#[test]
fn managed_reset_proceeds_without_worker() {
    let h = Hcom::new();
    set_managed(&h);

    let (code, stdout, stderr) = h.run(["reset"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        !stderr.contains("relay worker is managed"),
        "stderr={stderr}"
    );
    assert!(!pid_file(&h).exists(), "managed reset spawned a worker");
}

/// Linux only. Windows' graceful request rarely reaches a console-less worker,
/// so there the stop legitimately waits out the grace and force-kills; and
/// this test is the worker's parent, so the exited worker stays a zombie that
/// only /proc distinguishes from a live process.
#[cfg(target_os = "linux")]
#[test]
fn unmanaged_daemon_stop_stops_running_worker() {
    let h = Hcom::new();
    // Start managed so the worker idles without a broker, then hand it to hcom.
    set_managed(&h);
    let mut worker = start_worker(&h, h.cmd());
    let (code, stdout, stderr) = h.run(["config", "relay_worker_managed", "false"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    let started = Instant::now();
    let (code, stdout, stderr) = h.run(["relay", "daemon", "stop"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("Daemon stopped"), "stdout={stdout}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "stop took {:?}: it waited out the grace period",
        started.elapsed()
    );
    let status = worker
        .wait_exit(Duration::from_secs(1))
        .expect("worker still running after daemon stop");
    assert!(status.success(), "status={status}");
    assert!(!pid_file(&h).exists(), "pidfile left behind after stop");
}

/// A managed worker whose connect keeps failing retries in its idle loop; it
/// is alive and holds the lock, so status must not call it stale.
#[test]
fn managed_connect_retry_keeps_heartbeat_fresh() {
    let h = Hcom::new();
    set_managed(&h);
    // Enabled with no PSK: every connect attempt fails before any network I/O.
    for (key, value) in [("relay_id", "retry-test"), ("relay_enabled", "true")] {
        let (code, stdout, stderr) = h.run(["config", key, value]);
        assert_eq!(code, 0, "{key}: stdout={stdout} stderr={stderr}");
    }
    let mut worker = start_worker(&h, h.cmd());

    // Past HEARTBEAT_STALE_SECS (10s) since the startup heartbeat.
    std::thread::sleep(Duration::from_secs(12));
    assert!(worker.is_running(), "worker exited while retrying connect");

    let (code, stdout, stderr) = h.run(["relay", "status"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(!stdout.contains("stale"), "stdout={stdout}");
    // The state word is colored; match it and the detail separately.
    assert!(
        stdout.contains("starting")
            && stdout.contains(&format!("(PID {}, awaiting connect)", worker.pid())),
        "stdout={stdout}"
    );
}
