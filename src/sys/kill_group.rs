//! Read-only process-group snapshots for owners that can no longer be queried.
//!
//! Membership is not ownership evidence. Callers must authenticate the persisted
//! owner's incarnation separately before deciding whether any signal is safe.

#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_PROCESS_COUNT: usize = 65_536;
#[cfg(target_os = "linux")]
const MAX_STAT_BYTES: usize = 8_192;

/// List the live members of exactly `pgid`, without signaling any process.
/// A bounded snapshot must complete before any members are returned.
pub(crate) fn live_members(pgid: u32) -> Result<Vec<u32>, &'static str> {
    #[cfg(target_os = "linux")]
    {
        linux_members(std::path::Path::new("/proc"), pgid)
    }
    #[cfg(target_os = "macos")]
    {
        apple_members(pgid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pgid;
        Err("unsupported")
    }
}

#[cfg(target_os = "linux")]
fn linux_members(proc_root: &std::path::Path, pgid: u32) -> Result<Vec<u32>, &'static str> {
    use std::io::Read;

    use super::process::{proc_stat_group_id, proc_stat_is_dead};

    let entries = std::fs::read_dir(proc_root).map_err(|_| "could not read process directory")?;
    let mut members = Vec::new();
    let mut stat = Vec::with_capacity(512);
    let mut stat_path = proc_root.to_path_buf();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_PROCESS_COUNT {
            return Err("process directory exceeds the safety limit");
        }
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        stat_path.clear();
        stat_path.push(proc_root);
        stat_path.push(name);
        stat_path.push("stat");
        let Ok(file) = std::fs::File::open(&stat_path) else {
            // Exits race this scan. Inaccessible entries are also skipped;
            // neither condition authorizes a PID absent from the snapshot.
            continue;
        };
        stat.clear();
        if file
            .take((MAX_STAT_BYTES + 1) as u64)
            .read_to_end(&mut stat)
            .is_err()
        {
            continue;
        }
        if stat.len() > MAX_STAT_BYTES {
            return Err("process stat exceeds the safety limit");
        }
        // comm can contain non-UTF-8 bytes. Replacing those bytes preserves
        // the ASCII fields parsed after its final closing parenthesis.
        let stat = String::from_utf8_lossy(&stat);
        if proc_stat_group_id(&stat) == Some(pgid) && !proc_stat_is_dead(&stat) {
            members.push(pid);
        }
    }
    members.sort_unstable();
    members.dedup();
    Ok(members)
}

// Unlike proc_listpids, proc_listpgrppids returns a PID count, not byte count.
#[cfg(any(target_os = "macos", test))]
fn apple_pid_count(read: i32, capacity: usize) -> Result<usize, &'static str> {
    let read = usize::try_from(read).map_err(|_| "could not read process group")?;
    if read > capacity {
        return Err("could not read process group");
    }
    Ok(read)
}

#[cfg(target_os = "macos")]
fn apple_members(pgid: u32) -> Result<Vec<u32>, &'static str> {
    let pgid = libc::pid_t::try_from(pgid)
        .ok()
        .filter(|pgid| *pgid > 0)
        .ok_or("invalid process group")?;
    let mut pids = vec![0_u32; 128];
    loop {
        let bytes = std::mem::size_of_val(pids.as_slice()) as libc::c_int;
        // SAFETY: u32 and Apple's pid_t have the same size and alignment.
        // pids provides `bytes` writable storage, and a positive group ID
        // selects only the requested group. This API sends no signal.
        let read = unsafe { libc::proc_listpgrppids(pgid, pids.as_mut_ptr().cast(), bytes) };
        let count = apple_pid_count(read, pids.len())?;
        if count == pids.len() {
            // A full buffer may be truncated. Retry with more room, but never
            // return a possibly partial group at the hard cap.
            if pids.len() >= MAX_PROCESS_COUNT {
                return Err("process group exceeds the safety limit");
            }
            pids.resize((pids.len() * 2).min(MAX_PROCESS_COUNT), 0);
            continue;
        }
        pids.truncate(count);
        // Reuse the native result buffer instead of copying the snapshot.
        // The shared native state probe recognizes zombies; an unreadable
        // state is unknown, not positive death evidence.
        pids.retain(|pid| {
            *pid > 0 && *pid <= libc::pid_t::MAX as u32 && !super::process::is_definitely_dead(*pid)
        });
        pids.sort_unstable();
        pids.dedup();
        return Ok(pids);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::super::process::{proc_stat_group_id, proc_stat_is_dead, proc_stat_is_zombie};
    use super::*;

    #[test]
    fn linux_stat_normal_line() {
        let stat = "42 (sleep) S 1 42 42 0 -1 4194304";
        assert_eq!(proc_stat_group_id(stat), Some(42));
        assert!(!proc_stat_is_dead(stat));
    }

    #[test]
    fn linux_stat_comm_contains_spaces_and_parentheses() {
        let stat = "42 (worker ) Z ( inside) R 1 73 42 0 -1 4194304";
        assert_eq!(proc_stat_group_id(stat), Some(73));
        assert!(!proc_stat_is_dead(stat));
    }

    #[test]
    fn linux_stat_zombie_and_dead_states() {
        for (stat, zombie) in [
            ("42 (sleep) Z 1 42 42", true),
            ("42 (sleep) X 1 42 42", false),
            ("42 (sleep) x 1 42 42", false),
        ] {
            assert_eq!(proc_stat_group_id(stat), Some(42));
            assert!(proc_stat_is_dead(stat), "{stat}");
            assert_eq!(proc_stat_is_zombie(stat), zombie, "{stat}");
        }
    }

    #[test]
    fn linux_stat_malformed_lines_are_rejected() {
        for stat in [
            "",
            "42 (sleep S 1 42",
            "42 (sleep) ",
            "42 (sleep) S 1",
            "42 (sleep) S 1 nope",
            "42 (sleep) S nope 42",
            "42 (sleep) SS 1 42",
        ] {
            assert_eq!(proc_stat_group_id(stat), None, "{stat:?}");
        }
    }

    #[test]
    fn linux_scan_skips_dead_malformed_and_unreadable_entries() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        for (pid, stat) in [
            ("30", "30 (sleep) S 1 42 42"),
            ("9", "9 (space ) inside) R 1 42 42"),
            ("0009", "9 (duplicate) R 1 42 42"),
            ("12", "12 (other group) S 1 12 12"),
            ("20", "20 (zombie) Z 1 42 42"),
            ("21", "21 (dead) X 1 42 42"),
            ("22", "22 (malformed) S 1 nope"),
            ("not-a-pid", "23 (sleep) S 1 42 42"),
        ] {
            let directory = root.path().join(pid);
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("stat"), stat).unwrap();
        }
        // Missing and unreadable stat entries don't invalidate the other PIDs.
        std::fs::create_dir(root.path().join("24")).unwrap();
        std::fs::create_dir_all(root.path().join("25/stat")).unwrap();
        assert_eq!(linux_members(root.path(), 42), Ok(vec![9, 30]));
        assert_eq!(linux_members(root.path(), 100), Ok(vec![]));
    }

    #[test]
    fn linux_scan_requires_a_readable_process_directory() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        assert!(linux_members(&root.path().join("missing"), 42).is_err());
    }

    #[test]
    fn linux_scan_rejects_a_stat_over_the_hard_cap() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let directory = root.path().join("42");
        std::fs::create_dir(&directory).unwrap();
        let mut stat = b"42 (sleep) S 1 42 42".to_vec();
        stat.resize(MAX_STAT_BYTES + 1, b' ');
        std::fs::write(directory.join("stat"), stat).unwrap();
        assert!(linux_members(root.path(), 42).is_err());
    }

    #[test]
    fn linux_live_members_finds_its_own_child_group() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn own process-group fixture");
        let pid = child.id();
        let members = live_members(pid);
        // Only this test's own child receives a signal. Reap it before any
        // assertions so an enumeration failure doesn't leave a fixture behind.
        let killed = child.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait().expect("reap own fixture").is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "fixture did not exit in time");
            std::thread::sleep(Duration::from_millis(10));
        }
        killed.expect("kill own fixture");
        assert_eq!(members, Ok(vec![pid]));
    }
}

#[cfg(all(test, not(any(target_os = "linux", target_os = "macos"))))]
mod tests {
    #[test]
    fn live_members_is_unsupported() {
        assert_eq!(super::live_members(42), Err("unsupported"));
    }
}

#[cfg(test)]
mod apple_tests {
    use super::apple_pid_count;

    #[test]
    fn native_group_result_is_a_pid_count_not_a_byte_count() {
        assert_eq!(apple_pid_count(3, 128), Ok(3));
        assert_eq!(apple_pid_count(128, 128), Ok(128));
        assert_eq!(apple_pid_count(0, 128), Ok(0));
        assert!(apple_pid_count(-1, 128).is_err());
        assert!(apple_pid_count(129, 128).is_err());
    }
}
