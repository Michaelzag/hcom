//! `hcom launch-anchor`: internal, run by generated launch scripts before
//! they start the tool.
//!
//! The trust gate accepts a launcher process id only when its row records a
//! pid that is an ancestor of the hook presenting it. A new-window or
//! background launch hands the tool to a script the launcher does not wait
//! on, so the script records itself: this command's parent IS the script,
//! and the script is the tool's ancestor (or the tool itself, after `exec`).
//!
//! It takes no pid argument and no arguments at all: the only pid it can
//! record is its own parent's. It records only on the row bound to the
//! caller's launcher-shaped `HCOM_PROCESS_ID`, and only while that row has no
//! pid yet. Everything else is refused and changes nothing.

use crate::db::HcomDb;
use crate::log::log_info;

/// Exit 0 when the anchor was recorded, 1 when refused.
pub fn run(args: &[String]) -> i32 {
    if !args.is_empty() {
        log_info("launch_anchor", "refused", "unexpected arguments");
        return 1;
    }
    let process_id = std::env::var("HCOM_PROCESS_ID").unwrap_or_default();
    if !crate::proctruth::is_launcher_process_id(&process_id) {
        log_info("launch_anchor", "refused", "no launcher process id");
        return 1;
    }
    let Some(parent) = parent_pid() else {
        log_info("launch_anchor", "refused", "parent pid unavailable");
        return 1;
    };
    let db = match HcomDb::open() {
        Ok(db) => db,
        Err(e) => {
            log_info("launch_anchor", "refused", &format!("db open failed: {e}"));
            return 1;
        }
    };
    let Ok(Some(instance)) = db.get_process_binding(&process_id) else {
        log_info("launch_anchor", "refused", "process id has no binding");
        return 1;
    };
    match db.set_instance_pid_if_unset(&instance, parent) {
        Ok(true) => {
            log_info(
                "launch_anchor",
                "recorded",
                &format!("instance={instance} pid={parent}"),
            );
            0
        }
        Ok(false) => {
            log_info(
                "launch_anchor",
                "refused",
                &format!("instance={instance} already anchored"),
            );
            1
        }
        Err(e) => {
            log_info("launch_anchor", "refused", &format!("db write failed: {e}"));
            1
        }
    }
}

#[cfg(unix)]
fn parent_pid() -> Option<u32> {
    // SAFETY: getppid has no preconditions and cannot fail.
    u32::try_from(unsafe { libc::getppid() })
        .ok()
        .filter(|&pid| pid > 1)
}

#[cfg(windows)]
fn parent_pid() -> Option<u32> {
    crate::sys::process::snapshot_parents(false)?
        .get(&std::process::id())
        .map(|entry| entry.parent_pid)
        .filter(|&pid| pid != 0)
}
