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

// ── Singleton-lock safety for `hcom reset` ─────────────────────────────
//
// `hcom reset` copies and unlinks hcom.db. A worker — running, or started
// mid-reset by a service manager or a hook — that opens the database in that
// window corrupts the archive and the live state. These tests hold
// `.tmp/relay.lock` the way a worker does and check that reset contends
// with it: refuses while it is held, and holds it itself across the surgery.

/// The worker singleton lock file. Only the unix-gated lock-survival test
/// names it directly; the other helpers resolve the path themselves.
#[cfg(unix)]
fn lock_file(h: &Hcom) -> PathBuf {
    h.hcom_dir.join(".tmp").join("relay.lock")
}

/// Open the singleton lock file with the worker's exact open flags (create,
/// never truncate, read+write). Locks are per open file description (per
/// handle on Windows), so a fresh open contends like a fresh process.
fn open_lock_file_at(hcom_dir: &std::path::Path) -> std::fs::File {
    let path = hcom_dir.join(".tmp").join("relay.lock");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

fn open_lock_file(h: &Hcom) -> std::fs::File {
    open_lock_file_at(&h.hcom_dir)
}

/// Exclusive whole-file lock, the worker's primitive: flock(LOCK_EX) on Unix,
/// LockFileEx on Windows. Mirrors `sys::fs::lock_exclusive` — kept here
/// because integration tests cannot link the hcom binary's internals.
fn lock_exclusive(file: &std::fs::File) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: flock on a valid fd; return value is checked.
        let ret = unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX) };
        assert_eq!(ret, 0, "flock(LOCK_EX) failed");
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx};
        use windows_sys::Win32::System::IO::OVERLAPPED;

        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: valid handle for the file's lifetime; whole-file range.
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle() as HANDLE,
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        assert_ne!(ok, 0, "LockFileEx failed");
    }
}

/// Non-blocking exclusive attempt, flock(LOCK_EX|LOCK_NB). True when acquired;
/// false when held elsewhere. Unix only: its only caller is the unix-gated
/// db-surgery test.
#[cfg(unix)]
fn try_lock_exclusive(file: &std::fs::File) -> bool {
    use std::os::unix::io::AsRawFd;
    loop {
        // SAFETY: flock on a valid fd; return value is checked.
        let ret =
            unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) };
        if ret == 0 {
            return true;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(code) if code == nix::libc::EINTR => continue,
            Some(code) if code == nix::libc::EWOULDBLOCK || code == nix::libc::EAGAIN => {
                return false;
            }
            _ => panic!("flock(LOCK_EX|LOCK_NB) failed"),
        }
    }
}

/// Hold the singleton lock until the returned handle drops, the way a running
/// worker holds it. Every contender under test runs in another process, so
/// the contention is real.
fn hold_singleton_lock(h: &Hcom) -> std::fs::File {
    let file = open_lock_file(h);
    lock_exclusive(&file);
    file
}

/// Seed one real conversation (a reset event) so "archived / not archived"
/// assertions bite. The exit code is not asserted: on Windows the db-clear
/// half of reset cannot work at all (ffc-gt11n), but the fresh-db bootstrap
/// still logs the event.
fn seed_conversation(h: &Hcom) {
    let _ = h.run(["reset"]);
    let conn = rusqlite::Connection::open(h.hcom_dir.join("hcom.db")).expect("open seeded db");
    let events: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .expect("count seeded events");
    assert!(events > 0, "setup: conversation not seeded");
}

/// hcom.db and its sidecars as bytes; None = absent.
fn db_snapshot(h: &Hcom) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    ["hcom.db", "hcom.db-wal", "hcom.db-shm"]
        .into_iter()
        .map(|name| {
            let path = h.hcom_dir.join(name);
            let bytes = std::fs::read(&path).ok();
            (path, bytes)
        })
        .collect()
}

/// Archive session dirs reset created (none = the database was not archived).
fn session_archives(h: &Hcom) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(h.hcom_dir.join("archive"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("session-"))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Reset must refuse — non-zero, touching nothing — while anything holds the
/// worker singleton lock, even with no recorded worker: the gap a freshly
/// restarted worker (or one a hook spawned) sits in. Unmanaged reset used to
/// ignore the lock entirely and archive the database under it.
#[test]
fn unmanaged_reset_refuses_while_singleton_lock_held() {
    let h = Hcom::new();
    seed_conversation(&h);
    assert!(!pid_file(&h).exists(), "setup: a worker is recorded");

    let _held = hold_singleton_lock(&h);
    let before = db_snapshot(&h);

    let (code, stdout, stderr) = h.run(["reset"]);
    assert_ne!(
        code, 0,
        "reset proceeded while the singleton lock was held: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("relay worker is running") && stderr.contains("rerun hcom reset"),
        "unclear refusal: stderr={stderr}"
    );
    assert_eq!(db_snapshot(&h), before, "refused reset modified hcom.db");
    assert!(
        session_archives(&h).is_empty(),
        "refused reset archived the database"
    );
}

/// Same contract in managed mode, with the managed refusal text: the service
/// manager's worker holds hcom.db open and would be restarted mid-archive, so
/// reset must refuse and point at the manager.
#[test]
fn managed_reset_refuses_while_singleton_lock_held() {
    let h = Hcom::new();
    set_managed(&h);
    seed_conversation(&h);

    let _held = hold_singleton_lock(&h);
    let before = db_snapshot(&h);

    let (code, stdout, stderr) = h.run(["reset"]);
    assert_ne!(
        code, 0,
        "reset proceeded while the singleton lock was held: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("relay worker is managed by a service manager")
            && stderr.contains("systemctl --user stop hcom-relay")
            && stderr.contains("rerun hcom reset"),
        "unclear refusal: stderr={stderr}"
    );
    assert_eq!(db_snapshot(&h), before, "refused reset modified hcom.db");
    assert!(
        session_archives(&h).is_empty(),
        "refused reset archived the database"
    );
}

/// The check-then-act race itself: managed reset's one-time free-lock probe
/// passes, then a replacement worker takes the lock and reopens hcom.db while
/// reset copies and unlinks it. Reset must hold the lock across the whole
/// surgery, so a contender fired mid-archive — this test's holder, released
/// to run when the archive copy starts — can only acquire afterwards and
/// never see the pre-reset database.
///
/// Unix only: clearing hcom.db at all is unix-only for now (ffc-gt11n, same
/// gate as `managed_reset_proceeds_without_worker`).
#[cfg(unix)]
#[test]
fn managed_reset_holds_singleton_lock_across_db_surgery() {
    let h = Hcom::new();
    set_managed(&h);
    seed_conversation(&h);

    // Widen the archive-copy window so the race is reliably observable: reset
    // copies hcom.db before unlinking it, and the holder fires when the copy
    // starts.
    let db_path = h.hcom_dir.join("hcom.db");
    {
        let conn = rusqlite::Connection::open(&db_path).expect("open seeded db");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS race_filler (b BLOB);
             INSERT INTO race_filler VALUES (zeroblob(67108864));",
        )
        .expect("widen seeded db");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("fold widened db into the main file");
    }
    let original_len = std::fs::metadata(&db_path).expect("stat widened db").len();
    assert!(
        original_len > 64 * 1024 * 1024,
        "setup: database not widened: {original_len} bytes"
    );

    // The "service-manager replacement": notice the archive copy starting —
    // strictly after reset's gate — then take the singleton lock the way a
    // freshly restarted worker would and look at hcom.db.
    let hcom_dir = h.hcom_dir.clone();
    let holder = std::thread::spawn(move || {
        let archive = hcom_dir.join("archive");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let started = std::fs::read_dir(&archive)
                .map(|rd| rd.filter_map(|e| e.ok()).next().is_some())
                .unwrap_or(false);
            if started {
                break;
            }
            assert!(Instant::now() < deadline, "reset never created an archive");
            std::thread::sleep(Duration::from_micros(100));
        }
        // Worker-style bounded retry. Longer than the worker's 3s only so a
        // loaded box cannot flunk the acquisition the assertions below need;
        // the property under test is what the lock excludes, not its patience.
        let file = open_lock_file_at(&hcom_dir);
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if try_lock_exclusive(&file) {
                // None when hcom.db is gone at acquisition.
                return std::fs::metadata(hcom_dir.join("hcom.db"))
                    .ok()
                    .map(|m| m.len());
            }
            assert!(
                Instant::now() < deadline,
                "singleton lock never became free"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    });

    let (code, stdout, stderr) = h.run(["reset"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        !session_archives(&h).is_empty(),
        "setup: reset did not archive the database"
    );

    let len_at_acquisition = holder.join().expect("holder thread panicked");
    assert_ne!(
        len_at_acquisition,
        Some(original_len),
        "a contender took the singleton lock and found the pre-reset hcom.db in place: \
         the lock is not held across the archive/unlink"
    );
}

/// Reset must never delete or replace the singleton lock file: removing a
/// held lock's path lets the next worker lock a fresh inode and run as a
/// second singleton.
///
/// Unix only: clearing hcom.db at all is unix-only for now (ffc-gt11n, same
/// gate as `managed_reset_proceeds_without_worker`).
#[cfg(unix)]
#[test]
fn relay_lock_file_survives_reset() {
    use std::os::unix::fs::MetadataExt;

    let h = Hcom::new();
    seed_conversation(&h);

    // Create the lock file the way a running worker does, then let it go.
    drop(hold_singleton_lock(&h));
    let meta = std::fs::metadata(lock_file(&h)).expect("stat lock file");
    let identity = (meta.dev(), meta.ino());

    let (code, stdout, stderr) = h.run(["reset"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    let meta = std::fs::metadata(lock_file(&h)).expect("reset deleted the singleton lock file");
    assert_eq!(
        (meta.dev(), meta.ino()),
        identity,
        "reset replaced the singleton lock file"
    );
}

/// A worker that cannot take the singleton lock must exit without opening or
/// creating hcom.db. Real worker binary; the held lock stands in for reset's
/// hold (a real reset holds it only across its database surgery — too narrow
/// to time a worker start inside).
#[test]
fn worker_start_while_singleton_lock_held_exits_without_touching_db() {
    let h = Hcom::new();
    let _held = hold_singleton_lock(&h);

    let mut cmd = h.cmd();
    let output = cmd
        .arg("relay-worker")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run relay-worker");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
    assert!(stderr.contains("already running"), "stderr={stderr}");
    assert!(
        !h.hcom_dir.join("hcom.db").exists(),
        "refused worker start created hcom.db"
    );
    assert!(
        !h.hcom_dir.join("hcom.db-wal").exists(),
        "refused worker start created hcom.db-wal"
    );
    assert!(
        !pid_file(&h).exists(),
        "refused worker start wrote a pidfile"
    );
}
