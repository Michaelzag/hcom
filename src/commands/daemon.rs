//! Relay daemon process management.
//!
//! Accessed via `hcom relay daemon [start|stop|restart|status]`.
//! Manages the `hcom relay-worker` background process for MQTT relay.
//!
//! With `relay_worker_managed=true` a service manager (systemd) owns the
//! worker: `start`/`stop` refuse and point at it, `restart` SIGTERMs the
//! worker and waits for the manager to bring up a new one, and `hcom reset`
//! refuses while it runs.

use std::thread;
use std::time::Duration;

use crate::relay::worker;

/// How long `restart` waits for the service manager to bring a new worker up.
const MANAGED_RESTART_TIMEOUT: Duration = Duration::from_secs(15);

fn pid_label(pid: Option<u32>, managed: bool) -> String {
    let pid = pid.map_or_else(|| "PID unknown".to_string(), |p| format!("PID {p}"));
    if managed {
        format!(" ({pid}, managed)")
    } else {
        format!(" ({pid})")
    }
}

pub(crate) fn daemon_status() -> i32 {
    let managed = worker::worker_managed();
    if worker::is_relay_worker_running() {
        let pid = worker::wait_for_worker_pid();
        println!("Daemon: running{}", pid_label(pid, managed));
    } else if managed {
        println!("Daemon not running (managed: start it with your service manager)");
    } else {
        println!("Daemon not running");
    }
    0
}

pub(crate) fn daemon_start() -> i32 {
    if worker::worker_managed() {
        if worker::is_relay_worker_running() {
            let pid = worker::wait_for_worker_pid();
            println!("Daemon already running{}", pid_label(pid, true));
            return 0;
        }
        eprintln!("{}", worker::MANAGED_START_HINT);
        return 1;
    }

    let was_running = worker::is_relay_worker_running();
    if worker::ensure_worker(false) {
        let pid = worker::relay_worker_pid();
        let pid_str = pid.map(|p| format!(" (PID {p})")).unwrap_or_default();
        if was_running {
            println!("Daemon already running{pid_str}");
        } else {
            println!("Daemon started{pid_str}");
        }
        0
    } else {
        // ensure_worker may have timed out on readiness — check if process actually started
        if worker::is_relay_worker_running() {
            let pid = worker::relay_worker_pid();
            let pid_str = pid.map(|p| format!(" (PID {p})")).unwrap_or_default();
            println!("Daemon started{pid_str} (notify port not yet ready)");
            0
        } else {
            eprintln!("Failed to start daemon (relay disabled or config error)");
            1
        }
    }
}

/// `hcom relay daemon stop`. Refuses when a service manager owns the worker.
pub(crate) fn daemon_stop() -> i32 {
    if worker::worker_managed() {
        eprintln!("{}", worker::MANAGED_STOP_HINT);
        return 1;
    }
    stop_unmanaged()
}

/// Gate for `hcom reset`, checked before it touches anything. A running
/// managed worker holds hcom.db open, and its service manager would restart
/// it mid-archive, so reset refuses and points at the manager. False (after
/// printing why) when reset must not proceed.
pub(crate) fn reset_permitted() -> bool {
    if worker::worker_managed() && worker::is_relay_worker_running() {
        eprintln!("{}", worker::MANAGED_RESET_HINT);
        return false;
    }
    true
}

/// Stop the worker for `hcom reset`. Unmanaged: same as `daemon stop`.
/// Managed: nothing to do — [`reset_permitted`] already refused a running one.
pub(crate) fn stop_worker_for_reset() -> i32 {
    if worker::worker_managed() {
        return 0;
    }
    stop_unmanaged()
}

fn stop_unmanaged() -> i32 {
    let Some(daemon) = worker::WorkerProcess::running() else {
        println!("Daemon not running");
        return 0;
    };
    let pid = daemon.pid();
    println!("Requested daemon shutdown (PID {pid})");
    match daemon.stop() {
        worker::WorkerStop::AlreadyGone | worker::WorkerStop::Stopped => {
            println!("Daemon stopped");
            0
        }
        worker::WorkerStop::Killed => {
            println!("Daemon did not exit in time, forcing termination");
            println!("Daemon killed");
            0
        }
        worker::WorkerStop::Survived => {
            eprintln!("Force-kill failed: daemon (PID {pid}) still running, PID file retained");
            1
        }
    }
}

fn daemon_restart() -> i32 {
    if !worker::worker_managed() {
        daemon_stop();
        thread::sleep(Duration::from_millis(500));
        return daemon_start();
    }

    match worker::restart_managed_worker(MANAGED_RESTART_TIMEOUT) {
        Ok(pid) => {
            if worker::poll_until_ready(500) {
                println!("Daemon restarted (PID {pid}, managed)");
            } else {
                println!("Daemon restarted (PID {pid}, managed) (notify port not yet ready)");
            }
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

pub fn cmd_daemon(argv: &[String]) -> i32 {
    let subcmd = argv.first().map(|s| s.as_str()).unwrap_or("status");

    match subcmd {
        "status" => daemon_status(),
        "start" => daemon_start(),
        "stop" => daemon_stop(),
        "restart" => daemon_restart(),
        other => {
            eprintln!("Unknown daemon subcommand: {other}");
            eprintln!("Usage: hcom relay daemon [status|start|stop|restart]");
            eprintln!(
                "With relay_worker_managed=true a service manager owns the worker: start/stop refuse, restart signals it and waits for the manager."
            );
            1
        }
    }
}
