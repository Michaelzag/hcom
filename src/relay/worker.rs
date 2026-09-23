//! Relay worker process — manages the MQTT relay as a standalone process.
//!
//! Entry point for `hcom relay-worker`. Handles the singleton lock, PID file,
//! signal handling, auto-exit watchdog, and relay lifecycle.
//!
//! Singleton: a worker holds an exclusive lock on `.tmp/relay.lock` for its
//! whole lifetime. Liveness is decided by that lock, never by whether the
//! pidfile's PID exists — a stale pidfile naming a reused PID must not block a
//! start or report "running". The pidfile only says *which* process holds it.
//!
//! Auto-spawn: `ensure_worker()` checks config, the lock, and instance count
//! before spawning a new relay-worker process. With `relay_worker_managed` a
//! service manager owns the worker and hcom never spawns it.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::config::HcomConfig;
use crate::db::HcomDb;
use crate::log;
use crate::relay::client::RelayCommand;

// ── PID file helpers ────────────────────────────────────────────────

fn pid_file_path() -> PathBuf {
    crate::paths::hcom_dir().join(".tmp").join("relay.pid")
}

fn spawn_lock_path() -> PathBuf {
    crate::paths::hcom_dir()
        .join(".tmp")
        .join("relay.spawn.lock")
}

/// Worker singleton lock. Held exclusively by the running worker for its whole
/// lifetime. Never deleted by anything: removing a flock'd path lets a second
/// worker lock a fresh inode and breaks mutual exclusion.
fn worker_lock_path() -> PathBuf {
    crate::paths::hcom_dir().join(".tmp").join("relay.lock")
}

/// Write this process's PID. Only the lock holder calls this.
fn write_pid_file() {
    crate::paths::atomic_write(&pid_file_path(), &std::process::id().to_string());
    // Seed heartbeat alongside the pidfile so readers in the startup window
    // (before the main loop starts ticking) don't see lock-held + no-heartbeat
    // and falsely declare the worker dead.
    if let Ok(db) = HcomDb::open() {
        super::write_worker_heartbeat(&db);
    }
}

/// Parse the pidfile without consulting the lock.
fn parse_pid_file() -> Option<u32> {
    let content = std::fs::read_to_string(pid_file_path()).ok()?;
    content.trim().parse().ok()
}

/// PID of the lock holder, or None when no worker holds the lock (a pidfile
/// left behind then is just stale; the next worker overwrites it). Also None
/// in the holder's startup window before it writes the pidfile. Never deletes
/// the pidfile.
fn read_pid_file() -> Option<u32> {
    if worker_lock_held() {
        parse_pid_file()
    } else {
        None
    }
}

/// Remove PID file and clear heartbeat KV.
fn remove_pid_file() {
    let _ = std::fs::remove_file(pid_file_path());
    if let Ok(db) = HcomDb::open() {
        super::clear_worker_heartbeat(&db);
    }
}

/// Whether a worker holds the singleton lock. Probes with a shared lock once,
/// so concurrent probes never see each other as the holder; the worker's
/// startup retry rides over a probe's brief hold.
fn worker_lock_held() -> bool {
    let file = match std::fs::File::open(worker_lock_path()) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(e) => {
            log::log_warn("relay", "relay_worker.lock_probe_err", &format!("{e}"));
            return false;
        }
    };
    match crate::sys::fs::try_lock_shared(&file) {
        // Got it: nobody holds it exclusively. Dropping `file` releases it.
        Ok(true) => false,
        Ok(false) => true,
        Err(e) => {
            log::log_warn("relay", "relay_worker.lock_probe_err", &format!("{e}"));
            false
        }
    }
}

/// Check if a relay-worker process is currently running (holds the lock).
pub fn is_relay_worker_running() -> bool {
    worker_lock_held()
}

/// Pure pidfile observer for `derive_relay_health`. Never mutates the pidfile
/// — derivation must be side-effect free (every status render would otherwise
/// be a hidden state transition).
///
/// Returns:
///   None             — no pidfile on disk
///   Some(pid,true)   — pidfile present, a worker holds the lock
///   Some(pid,false)  — pidfile present, no worker holds the lock (stale)
pub fn observe_pid_file() -> Option<(u32, bool)> {
    let pid = parse_pid_file()?;
    Some((pid, worker_lock_held()))
}

/// Identity of the running binary, for noticing it was replaced on disk
/// (reinstall, `cargo install`, package upgrade). A replaced worker exits
/// cleanly so the next spawn — or the service manager — runs the new binary.
#[cfg(unix)]
struct BinaryIdentity {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
impl BinaryIdentity {
    /// None when the binary can't be inspected (e.g. it already shows as
    /// "(deleted)"): the check is then disabled, never a reason to exit.
    fn capture() -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let captured = std::env::current_exe().and_then(|path| {
            let meta = std::fs::metadata(&path)?;
            Ok(Self {
                dev: meta.dev(),
                ino: meta.ino(),
                path,
            })
        });
        match captured {
            Ok(id) => Some(id),
            Err(e) => {
                log::log_warn(
                    "relay",
                    "relay_worker.binary_identity_err",
                    &format!("binary replacement check disabled: {e}"),
                );
                None
            }
        }
    }

    /// True when the path now names a different file (or none). A `touch` or
    /// chmod keeps (dev, ino), so this never fires on an untouched binary;
    /// transient errors other than NotFound are not treated as replacement.
    fn replaced(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(&self.path) {
            Ok(m) => (m.dev(), m.ino()) != (self.dev, self.ino),
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

/// Binary replacement is only detected on Unix; elsewhere this is a no-op.
/// Uninhabited: `capture` always returns None, so no value ever exists.
#[cfg(not(unix))]
enum BinaryIdentity {}

#[cfg(not(unix))]
impl BinaryIdentity {
    fn capture() -> Option<Self> {
        None
    }

    fn replaced(&self) -> bool {
        match *self {}
    }

    fn path(&self) -> &std::path::Path {
        match *self {}
    }
}

/// Log and report binary replacement.
fn binary_replaced(binary: Option<&BinaryIdentity>) -> bool {
    match binary {
        Some(b) if b.replaced() => {
            log::log_info(
                "relay",
                "relay_worker.binary_replaced",
                &format!("path={}", b.path().display()),
            );
            true
        }
        _ => false,
    }
}

// ── Drop guard for PID file cleanup ─────────────────────────────────

struct PidFileGuard;

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        remove_pid_file();
    }
}

// ── Worker entry point ──────────────────────────────────────────────

/// Attempts × interval for taking the singleton lock at startup. Liveness
/// probes hold a shared lock for microseconds; retrying rides over them.
const LOCK_ATTEMPTS: u32 = 30;
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Managed idle loop: how often config is re-read while waiting for relay to
/// become enabled (or to retry a failed connect).
const IDLE_CONFIG_RELOAD_TICKS: u32 = 5;

/// Take the singleton lock, retrying briefly over concurrent probes.
fn acquire_worker_lock(file: &std::fs::File) -> std::io::Result<bool> {
    for attempt in 0..LOCK_ATTEMPTS {
        if crate::sys::fs::try_lock_exclusive(file)? {
            return Ok(true);
        }
        if attempt + 1 < LOCK_ATTEMPTS {
            std::thread::sleep(LOCK_RETRY_INTERVAL);
        }
    }
    Ok(false)
}

/// Run the relay-worker process. Called from router dispatch.
pub fn run() -> i32 {
    let lock_path = worker_lock_path();
    if let Some(parent) = lock_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!("Error: Failed to create {}: {e}", parent.display());
        return 1;
    }
    let lock_file = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: Failed to open {}: {e}", lock_path.display());
            return 1;
        }
    };
    match acquire_worker_lock(&lock_file) {
        Ok(true) => {}
        Ok(false) => {
            match parse_pid_file() {
                Some(pid) => eprintln!("relay-worker already running (PID {pid})"),
                None => eprintln!("relay-worker already running (PID unknown)"),
            }
            return 1;
        }
        Err(e) => {
            eprintln!("Error: Failed to lock {}: {e}", lock_path.display());
            return 1;
        }
    }

    // Only the lock holder writes the pidfile. `_pid_guard` is declared after
    // `lock_file`, so drop order (reverse of declaration) removes the pidfile
    // first and releases the lock last — a new worker can never lock while our
    // pidfile removal is still pending and have its own pidfile deleted.
    write_pid_file();
    let _pid_guard = PidFileGuard;

    let binary = BinaryIdentity::capture();

    // Install shutdown-signal handlers (set AtomicBool on terminate/interrupt)
    // before config load / connect so the managed idle phase honours them too.
    // The watchdog thread checks this flag every second once connected.
    let shutdown = Arc::new(AtomicBool::new(false));
    crate::sys::signal::register_term(&shutdown);
    crate::sys::signal::register_int(&shutdown);

    log::log_info(
        "relay",
        "relay_worker.start",
        &format!("pid={}", std::process::id()),
    );

    // Load config
    let mut config = match HcomConfig::load(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to load config: {e}");
            return 1;
        }
    };
    let managed = config.relay_worker_managed;

    // A managed worker never exits for "relay disabled" or a failed connect:
    // that would crashloop the service manager. It idles holding the lock and
    // re-reads config until relay is enabled and connect succeeds.
    let (relay, connection, cmd_tx) = loop {
        if !super::is_relay_enabled(&config) {
            if !managed {
                eprintln!("Error: Relay not configured or disabled");
                return 1;
            }
            log::log_info(
                "relay",
                "relay_worker.idle",
                "relay not configured or disabled; waiting",
            );
            match managed_idle(&shutdown, binary.as_ref(), true) {
                Some(c) => config = c,
                None => return 0,
            }
            continue;
        }

        match super::client::MqttRelay::connect(&config) {
            Ok(r) => break r,
            Err(e) if managed => {
                log::log_warn("relay", "relay_worker.connect_err", &e.to_string());
                match managed_idle(&shutdown, binary.as_ref(), false) {
                    Some(c) => config = c,
                    None => return 0,
                }
            }
            Err(e) => {
                eprintln!("Error: Failed to connect: {e}");
                return 1;
            }
        }
    };

    // Bind TCP notify listener for CLI → daemon push wake.
    // CLI callers (hcom send, hooks) connect to trigger immediate push.
    let notify_port = setup_notify_listener(&cmd_tx);

    // Spawn auto-exit watchdog thread (also monitors shutdown flag)
    let cmd_tx_watchdog = cmd_tx;
    std::thread::spawn(move || {
        auto_exit_watchdog(cmd_tx_watchdog, shutdown, binary, managed);
    });

    // Run relay event loop (blocks until shutdown)
    relay.run(connection);

    // Clear notify port so CLI callers stop trying to connect
    if notify_port.is_some()
        && let Ok(db) = HcomDb::open()
    {
        super::safe_kv_set(&db, "relay_daemon_port", None);
    }

    log::log_info("relay", "relay_worker.stop", "exited cleanly");
    0
}

/// Managed-mode wait: tick every second checking the shutdown flag and binary
/// replacement; re-read config every few seconds. Returns the fresh config to
/// (re)try connecting with, or None when the worker should exit cleanly.
///
/// `until_enabled` — return as soon as a reload shows relay enabled (idle
/// because disabled). When false (retrying a failed connect) the fresh config
/// is returned on the first reload whatever it says, so the caller re-decides.
fn managed_idle(
    shutdown: &AtomicBool,
    binary: Option<&BinaryIdentity>,
    until_enabled: bool,
) -> Option<HcomConfig> {
    let mut tick = 0u32;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        if shutdown.load(Ordering::Relaxed) {
            log::log_info("relay", "relay_worker.stop", "shutdown while idle");
            return None;
        }
        if binary_replaced(binary) {
            return None;
        }
        tick += 1;
        if !tick.is_multiple_of(IDLE_CONFIG_RELOAD_TICKS) {
            continue;
        }
        match HcomConfig::load(None) {
            Ok(c) if !until_enabled || super::is_relay_enabled(&c) => return Some(c),
            Ok(_) => {}
            Err(e) => {
                log::log_warn("relay", "relay_worker.config_err", &e.to_string());
            }
        }
    }
}

/// Bind TCP listener on random port for CLI→daemon push notifications.
/// Stores port in KV `relay_daemon_port`. Returns port on success.
fn setup_notify_listener(cmd_tx: &std::sync::mpsc::Sender<RelayCommand>) -> Option<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();

    // Store port in DB so CLI callers can find us
    if let Ok(db) = HcomDb::open() {
        super::safe_kv_set(&db, "relay_daemon_port", Some(&port.to_string()));
    }

    log::log_info(
        "relay",
        "relay_worker.notify_listen",
        &format!("port={}", port),
    );

    // Spawn thread to accept connections and send Push commands.
    // Each incoming TCP connection (no data, just connect+close) triggers a push.
    let cmd_tx = cmd_tx.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(conn) => {
                    drop(conn); // Close immediately — connection itself is the signal
                    if cmd_tx.send(RelayCommand::Push).is_err() {
                        break; // Relay shut down
                    }
                }
                Err(_) => break,
            }
        }
    });

    Some(port)
}

/// Watchdog ticks: shutdown and binary replacement are checked every tick;
/// the sweep + instance check runs every `SWEEP_EVERY_TICKS` ticks.
const WATCHDOG_TICK: Duration = Duration::from_secs(1);
const SWEEP_EVERY_TICKS: u32 = 30;

/// Watchdog: every second, send Shutdown if a shutdown signal arrived or the
/// binary was replaced on disk. Every 30s, check if any local instances
/// exist; if none for 2 consecutive checks, send Shutdown.
///
/// When relay is enabled and configured, the worker stays alive even with zero
/// local instances so it can receive remote RPCs (e.g. the first `launch` on a
/// fresh device). A managed worker never auto-exits on zero instances: its
/// lifetime belongs to the service manager.
///
/// The same 30s tick also runs the vanished-instance sweep: this worker lives in
/// its own detached process (outside any session cgroup), so it is the one
/// place that can notice a harness that died without a `stopped` event —
/// e.g. a systemd-oomd cgroup kill that takes the in-cgroup event writer
/// with it. Normal exits release their row first, so they never double-fire.
fn auto_exit_watchdog(
    cmd_tx: std::sync::mpsc::Sender<RelayCommand>,
    shutdown: Arc<AtomicBool>,
    binary: Option<BinaryIdentity>,
    managed: bool,
) {
    let mut consecutive_empty = 0u32;
    let mut db = HcomDb::open().ok();
    let mut tick = 0u32;

    loop {
        std::thread::sleep(WATCHDOG_TICK);

        if shutdown.load(Ordering::Relaxed) || binary_replaced(binary.as_ref()) {
            let _ = cmd_tx.send(RelayCommand::Shutdown);
            return;
        }

        tick = tick.wrapping_add(1);
        if !tick.is_multiple_of(SWEEP_EVERY_TICKS) {
            continue;
        }

        // Re-open DB if previous connection failed
        if db.is_none() {
            db = HcomDb::open().ok();
        }

        if let Some(ref d) = db {
            let swept = crate::proctruth::sweep_vanished_instances(d);
            if !swept.is_empty() {
                log::log_info(
                    "relay",
                    "relay_worker.vanished_swept",
                    &format!("released without stopped event: {}", swept.join(", ")),
                );
            }
        }

        let count = match &db {
            Some(d) => local_instance_count(d),
            None => {
                consecutive_empty = 0;
                continue;
            }
        };
        if count == 0 {
            // Keep the worker alive when relay is enabled so it can accept
            // remote RPCs (launch, config, etc.) on a device with no agents yet.
            if managed || relay_enabled_in_config() {
                consecutive_empty = 0;
                continue;
            }

            consecutive_empty += 1;
            if consecutive_empty >= 2 {
                log::log_info(
                    "relay",
                    "relay_worker.auto_exit",
                    "no local instances for 2 checks",
                );
                let _ = cmd_tx.send(RelayCommand::Shutdown);
                return;
            }
        } else {
            consecutive_empty = 0;
        }
    }
}

/// Check if relay is enabled in the current config (non-empty relay_id + relay_enabled flag).
fn relay_enabled_in_config() -> bool {
    HcomConfig::load(None)
        .map(|c| super::is_relay_enabled(&c))
        .unwrap_or(false)
}

/// Count active local (non-remote) instances.
/// Mirrors the filter in ensure_worker(true) so the watchdog exits when no syncable
/// instances remain, not merely when all instances are stopped/dead.
fn local_instance_count(db: &HcomDb) -> i64 {
    db.conn()
        .query_row(
            "SELECT COUNT(*) FROM instances \
             WHERE COALESCE(origin_device_id, '') = '' \
             AND status NOT IN ('stopped', 'dead')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0)
}

// ── Auto-spawn ──────────────────────────────────────────────────────

/// Guidance printed when hcom refuses to start a managed worker itself.
pub const MANAGED_START_HINT: &str = "relay worker is managed by a service manager (relay_worker_managed=true); start it there, e.g. systemctl --user start hcom-relay";
/// Guidance printed when hcom refuses to stop a managed worker itself.
pub const MANAGED_STOP_HINT: &str = "relay worker is managed by a service manager (relay_worker_managed=true); stop it there, e.g. systemctl --user stop hcom-relay";

/// How long a spawner keeps the spawn lock waiting for its child to take the
/// worker lock, so a concurrent spawner doesn't launch a redundant child.
const SPAWN_SETTLE_POLLS: u32 = 25;
const SPAWN_SETTLE_INTERVAL: Duration = Duration::from_millis(20);

/// Spawn the relay-worker process (caller must check preconditions).
/// Detaches via setsid() so the worker survives terminal close.
/// Returns true if spawned successfully, false if managed, already running,
/// or spawn failed.
fn do_spawn(config: &HcomConfig) -> bool {
    // A service manager owns a managed worker: no hcom path ever spawns one.
    if config.relay_worker_managed {
        log::log_info(
            "relay",
            "relay_worker.spawn_skipped_managed",
            "relay_worker_managed=true",
        );
        return false;
    }

    let lock_path = spawn_lock_path();
    if let Some(parent) = lock_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        log::log_warn(
            "relay",
            "relay_worker.spawn_lock_mkdir_err",
            &format!("{e}"),
        );
        return false;
    }

    let lock_file = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
    {
        Ok(file) => file,
        Err(e) => {
            log::log_warn("relay", "relay_worker.spawn_lock_open_err", &format!("{e}"));
            return false;
        }
    };

    if let Err(err) = crate::sys::fs::lock_exclusive(&lock_file) {
        log::log_warn("relay", "relay_worker.spawn_lock_err", &format!("{err}"));
        return false;
    }

    if is_relay_worker_running() {
        return false;
    }

    // Pre-warm device_id in the parent so the spawned worker reads the same
    // UUID we'd report from this process. Without this, the worker and any
    // concurrent CLI (hcom relay status, etc.) can race read_device_uuid on
    // a fresh HCOM_DIR and end up with different UUIDs — causing the worker's
    // published short_id to disagree with what `relay status` displays.
    if super::read_device_uuid().is_none() {
        log::log_warn(
            "relay",
            "relay_worker.device_id_unwritable",
            "could not create device_id file before spawn",
        );
        return false;
    }

    let binary = match std::env::current_exe() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut cmd = Command::new(&binary);
    cmd.arg("relay-worker")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Detach into its own session so it survives parent terminal close (no
    // SIGHUP) and, on Windows, doesn't inherit the parent's stdio handles
    // (which would otherwise keep any caller piping hcom's output from ever
    // observing EOF). The child writes its own pidfile once it holds the
    // worker lock; the parent never does.
    match crate::sys::process::spawn_detached(&mut cmd) {
        Ok(child) => {
            log::log_info(
                "relay",
                "relay_worker.spawned",
                &format!("pid={}", child.id()),
            );
            // Still holding the spawn lock: wait briefly for the child to take
            // the worker lock so a concurrent spawner sees it running instead
            // of launching a redundant child (which the lock would refuse).
            for _ in 0..SPAWN_SETTLE_POLLS {
                if is_relay_worker_running() {
                    break;
                }
                std::thread::sleep(SPAWN_SETTLE_INTERVAL);
            }
            true
        }
        Err(e) => {
            log::log_warn("relay", "relay_worker.spawn_err", &format!("{}", e));
            false
        }
    }
}

/// Ensure the relay worker is running.
///
/// `require_instances` — if true, only spawn when active local instances exist
/// (auto-spawn from hooks/send/TUI: no-op when nothing to sync). Fire-and-forget:
/// no readiness wait, events push on the worker's next cycle.
///
/// If false, spawns whenever relay is enabled (relay connect/new/on, daemon start).
/// On the explicit command path, polls until the notify port is live (max 500ms)
/// even when the worker was already running, to handle the startup window before
/// port bind.
///
/// Returns true if the worker is running (and port-ready when require_instances=false).
pub fn ensure_worker(require_instances: bool) -> bool {
    let config = match HcomConfig::load(None) {
        Ok(c) => c,
        Err(_) => return false,
    };

    if !super::is_relay_enabled(&config) {
        return false;
    }

    if require_instances {
        // Auto-spawn path: fire-and-forget, no readiness check.
        if is_relay_worker_running() {
            return true;
        }
        let db = match HcomDb::open() {
            Ok(db) => db,
            Err(_) => return false,
        };
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM instances \
                 WHERE COALESCE(origin_device_id, '') = '' \
                 AND status NOT IN ('stopped', 'dead')",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if count == 0 {
            return false;
        }
        return do_spawn(&config);
    }

    // Explicit command path: ensure running AND port-ready.
    if is_relay_worker_running() {
        // Process exists but may be in startup window before port bind.
        if poll_until_ready(300) {
            return true;
        }
        // The existing worker may have exited while we were polling (for
        // example, a user just stopped it or it hit watchdog exit). In that
        // case, fall through and try to spawn a fresh worker.
        if is_relay_worker_running() {
            return false;
        }
    }
    if !do_spawn(&config) {
        // TOCTOU: another process may have spawned between our check and do_spawn().
        if is_relay_worker_running() {
            return poll_until_ready(300);
        }
        return false;
    }
    poll_until_ready(500)
}

/// Spawn the relay worker if relay is enabled and not already running.
/// Fire-and-forget: no instance check, no readiness wait.
/// Used by trigger_push() when no daemon is running, so events push on the
/// worker's first cycle instead of sitting in the DB indefinitely.
pub fn try_spawn_worker() {
    let config = match HcomConfig::load(None) {
        Ok(c) => c,
        Err(_) => return,
    };
    if super::is_relay_enabled(&config) {
        do_spawn(&config);
    }
}

/// Poll until the worker's TCP notify port is in KV and accepting connections.
/// Opens DB once before the loop to avoid repeated open overhead.
/// Returns true if ready within timeout_ms, false on timeout.
pub fn poll_until_ready(timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    let deadline = std::time::Duration::from_millis(timeout_ms);
    let db = HcomDb::open().ok();

    while start.elapsed() < deadline {
        if let Some(ref db) = db
            && let Some(port_str) = super::safe_kv_get(db, "relay_daemon_port")
            && let Ok(port) = port_str.trim().parse::<u16>()
        {
            use std::net::{SocketAddr, TcpStream};
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            if TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(50)).is_ok() {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
    false
}

/// Return the PID of the running relay worker, or None if not running.
pub fn relay_worker_pid() -> Option<u32> {
    read_pid_file()
}

/// PID of the lock holder, waiting up to 1s for it to write its pidfile when
/// the lock is held but the pidfile isn't there yet (startup window). None
/// when no worker holds the lock.
pub fn wait_for_worker_pid() -> Option<u32> {
    for _ in 0..20 {
        if !is_relay_worker_running() {
            return None;
        }
        if let Some(pid) = parse_pid_file() {
            return Some(pid);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    read_pid_file()
}

/// Poll every 100ms until no worker holds the lock. True if it was released
/// within `timeout`.
pub fn wait_for_worker_exit(timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if !is_relay_worker_running() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Remove a stale relay worker PID file (for post-SIGKILL cleanup). A no-op
/// while a worker holds the lock: the pidfile is then its, not stale.
pub fn remove_relay_pid_file() {
    if !worker_lock_held() {
        remove_pid_file();
    }
}

/// Stop a running relay-worker by sending SIGTERM to the PID from PID file.
pub fn stop_relay_worker() -> bool {
    if let Some(pid) = wait_for_worker_pid()
        && crate::sys::process::terminate(pid)
    {
        log::log_info("relay", "relay_worker.stopped", &format!("pid={}", pid));
        return true;
    }
    false
}

/// Whether config says a service manager owns the worker.
pub fn worker_managed() -> bool {
    HcomConfig::load(None)
        .map(|c| c.relay_worker_managed)
        .unwrap_or(false)
}

/// Stop the relay worker and block until it exits, escalating to a force-kill
/// if the graceful request does not take effect within ~5s. Removes a stale
/// PID file once the worker is gone.
///
/// Unlike [`stop_relay_worker`], this *guarantees* termination. Callers with no
/// other backstop must use this: [`terminate`](crate::sys::process::terminate)
/// is best-effort and on Windows may not be delivered when the worker shares no
/// console with the caller, so a bare `stop_relay_worker` could leave the worker
/// running (the auto-exit watchdog only winds down when no local instances
/// remain).
///
/// Managed mode: SIGTERM only — no wait, no force-kill, no pidfile removal.
/// The service manager restarts the worker, which then idles if relay is now
/// disabled.
pub fn stop_relay_worker_blocking() {
    if worker_managed() {
        let _ = stop_relay_worker();
        return;
    }

    let Some(pid) = wait_for_worker_pid() else {
        return;
    };

    if crate::sys::process::terminate(pid) {
        log::log_info("relay", "relay_worker.stopped", &format!("pid={}", pid));
    }
    if wait_for_worker_exit(Duration::from_secs(5)) {
        remove_relay_pid_file();
        return;
    }

    // Graceful request did not take effect in time; force-kill so a wedged
    // worker cannot survive a relay reset/off.
    crate::sys::process::kill(pid);
    wait_for_worker_exit(Duration::from_secs(1));
    remove_relay_pid_file();
}

/// Restart a service-managed worker: SIGTERM the lock holder and wait for the
/// service manager to bring up a new one. Returns the new worker's PID.
pub fn restart_managed_worker(timeout: Duration) -> Result<u32, String> {
    let Some(old) = wait_for_worker_pid() else {
        return Err(MANAGED_START_HINT.to_string());
    };
    if !crate::sys::process::terminate(old) {
        return Err(format!(
            "could not signal relay worker (PID {old}): {}",
            std::io::Error::last_os_error()
        ));
    }
    log::log_info(
        "relay",
        "relay_worker.restart_requested",
        &format!("pid={old}"),
    );

    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(pid) = read_pid_file()
            && pid != old
        {
            return Ok(pid);
        }
    }
    Err(format!(
        "relay worker (PID {old}) was stopped but the service manager did not restart it; check systemctl --user status hcom-relay"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::test_helpers::isolated_test_env;
    use serial_test::serial;

    #[test]
    fn test_pid_file_path() {
        crate::config::Config::init();
        let path = pid_file_path();
        assert!(path.to_string_lossy().contains("relay.pid"));
    }

    fn hold_worker_lock() -> std::fs::File {
        let path = worker_lock_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert!(crate::sys::fs::try_lock_exclusive(&file).unwrap());
        file
    }

    #[test]
    #[serial]
    fn lock_probe_tracks_holder_not_pidfile() {
        let (_dir, _hcom_dir, _home, _guard) = isolated_test_env();
        // Stale pidfile naming a live, unrelated process (this test) and no
        // lock holder: nothing is running.
        std::fs::create_dir_all(pid_file_path().parent().unwrap()).unwrap();
        std::fs::write(pid_file_path(), std::process::id().to_string()).unwrap();
        assert!(!is_relay_worker_running());
        assert_eq!(read_pid_file(), None);
        assert_eq!(observe_pid_file(), Some((std::process::id(), false)));
        // Readers never delete the pidfile.
        assert!(pid_file_path().exists());

        let lock = hold_worker_lock();
        assert!(is_relay_worker_running());
        assert_eq!(read_pid_file(), Some(std::process::id()));
        assert_eq!(observe_pid_file(), Some((std::process::id(), true)));
        // A held lock's pidfile is never removed as "stale".
        remove_relay_pid_file();
        assert!(pid_file_path().exists());

        drop(lock);
        assert!(!is_relay_worker_running());
        remove_relay_pid_file();
        assert!(!pid_file_path().exists());
    }
}
