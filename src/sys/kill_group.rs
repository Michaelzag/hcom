//! Read-only process-group snapshots for owners that can no longer be queried.
//!
//! Membership is not ownership evidence. Callers must authenticate the persisted
//! owner's incarnation separately before deciding whether any signal is safe.

use super::process::KillState;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_PROCESS_COUNT: usize = 65_536;
#[cfg(target_os = "linux")]
const MAX_STAT_BYTES: usize = 8_192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub pid: u32,
    pub identity: String,
    pub state: KillState,
}

/// List only the live members of exactly `pgid`, without signaling a process.
pub(crate) fn live_members(pgid: u32) -> Result<Vec<u32>, String> {
    capture_members(pgid).map(live_pids)
}

fn live_pids(members: Vec<Member>) -> Vec<u32> {
    members
        .into_iter()
        .filter_map(|member| (member.state == KillState::Live).then_some(member.pid))
        .collect()
}

/// Capture live and exiting group members with their native incarnations.
/// Unknown states or missing identities fail the snapshot, never omit a member.
pub(crate) fn capture_members(pgid: u32) -> Result<Vec<Member>, String> {
    #[cfg(target_os = "linux")]
    {
        linux_members(std::path::Path::new("/proc"), pgid, |pid, stat| {
            capture_member(
                pid,
                || super::process::kill_state(pid),
                || super::process::proc_stat_identity(stat),
                || super::process::identity(pid),
            )
        })
    }
    #[cfg(target_os = "macos")]
    {
        apple_members(pgid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pgid;
        Err("unsupported".into())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn capture_member(
    pid: u32,
    mut state_of: impl FnMut() -> KillState,
    captured_identity: impl FnOnce() -> Option<String>,
    current_identity: impl FnOnce() -> Option<String>,
) -> Result<Option<Member>, String> {
    let state = match state_of() {
        KillState::Gone => return Ok(None),
        KillState::Unknown => {
            if state_of() == KillState::Gone {
                return Ok(None);
            }
            return Err(format!("process-group member {pid} state is unknown"));
        }
        state @ (KillState::Live | KillState::Exiting) => state,
    };
    let Some(identity) = captured_identity() else {
        if state_of() == KillState::Gone {
            return Ok(None);
        }
        return Err(format!("process-group member {pid} identity is unreadable"));
    };
    match current_identity() {
        // The recorded incarnation ended while the group was being read.
        Some(current) if current != identity => Ok(None),
        Some(_) => Ok(Some(Member {
            pid,
            identity,
            state,
        })),
        None if state_of() == KillState::Gone => Ok(None),
        None => Err(format!("process-group member {pid} identity is unreadable")),
    }
}

#[cfg(target_os = "linux")]
fn linux_members(
    proc_root: &std::path::Path,
    pgid: u32,
    mut capture: impl FnMut(u32, &str) -> Result<Option<Member>, String>,
) -> Result<Vec<Member>, String> {
    use std::io::Read;

    use super::process::proc_stat_group_id;

    let entries = std::fs::read_dir(proc_root).map_err(|_| "could not read process directory")?;
    let mut members = Vec::new();
    let mut stat = Vec::with_capacity(512);
    let mut stat_path = proc_root.to_path_buf();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_PROCESS_COUNT {
            return Err("process directory exceeds the safety limit".into());
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
            return Err("process stat exceeds the safety limit".into());
        }
        // comm can contain non-UTF-8 bytes. Replacing those bytes preserves
        // the ASCII fields parsed after its final closing parenthesis.
        let stat = String::from_utf8_lossy(&stat);
        if proc_stat_group_id(&stat) != Some(pgid) {
            continue;
        }
        if let Some(member) = capture(pid, &stat)? {
            members.push(member);
        }
    }
    members.sort_unstable_by_key(|member| member.pid);
    members.dedup_by_key(|member| member.pid);
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
fn apple_members(pgid: u32) -> Result<Vec<Member>, String> {
    let native_pgid = libc::pid_t::try_from(pgid)
        .ok()
        .filter(|pgid| *pgid > 0)
        .ok_or("invalid process group")?;
    let mut pids = vec![0_u32; 128];
    loop {
        let bytes = std::mem::size_of_val(pids.as_slice()) as libc::c_int;
        // SAFETY: u32 and Apple's pid_t have the same size and alignment.
        // pids provides `bytes` writable storage, and a positive group ID
        // selects only the requested group. This API sends no signal.
        let read = unsafe { libc::proc_listpgrppids(native_pgid, pids.as_mut_ptr().cast(), bytes) };
        let count = apple_pid_count(read, pids.len())?;
        if count == pids.len() {
            // A full buffer may be truncated. Retry with more room, but never
            // return a possibly partial group at the hard cap.
            if pids.len() >= MAX_PROCESS_COUNT {
                return Err("process group exceeds the safety limit".into());
            }
            pids.resize((pids.len() * 2).min(MAX_PROCESS_COUNT), 0);
            continue;
        }
        pids.truncate(count);
        let mut members = Vec::with_capacity(count);
        for pid in pids {
            if pid == 0 || pid > libc::pid_t::MAX as u32 {
                continue;
            }
            let info = super::process::process_info_apple(pid).filter(|info| info.pbi_pid == pid);
            let Some(info) = info else {
                // A missing BSD receipt is unknown unless the shared state
                // reader can positively confirm that the member has gone.
                let _ = capture_member(
                    pid,
                    || super::process::kill_state(pid),
                    || None,
                    || super::process::identity(pid),
                )?;
                continue;
            };
            if info.pbi_pgid != pgid {
                continue;
            }
            if let Some(member) = capture_member(
                pid,
                || super::process::kill_state(pid),
                || super::process::apple_info_identity(&info),
                || super::process::identity(pid),
            )? {
                members.push(member);
            }
        }
        members.sort_unstable_by_key(|member| member.pid);
        members.dedup_by_key(|member| member.pid);
        return Ok(members);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::super::process::{proc_stat_group_id, proc_stat_is_dead, proc_stat_is_zombie};
    use super::*;

    fn kill_and_reap_child(child: &mut std::process::Child) {
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
    }

    fn fixture_member(pid: u32, state: KillState) -> Result<Option<Member>, String> {
        capture_member(
            pid,
            || state,
            || Some(format!("linux:fixture:{pid}")),
            || Some(format!("linux:fixture:{pid}")),
        )
    }

    #[test]
    fn an_exiting_member_requires_a_native_identity() {
        let result = capture_member(42, || KillState::Exiting, || None, || None);
        assert!(result.unwrap_err().contains("42"));
    }

    #[test]
    fn a_process_reused_during_capture_is_omitted() {
        let result = capture_member(
            42,
            || KillState::Live,
            || Some("linux:fixture:1".into()),
            || Some("linux:fixture:2".into()),
        );
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn a_busy_exit_during_capture_is_not_an_unknown_member() {
        for initial in [KillState::Unknown, KillState::Live] {
            let mut first = Some(initial);
            let result = capture_member(
                42,
                || first.take().unwrap_or(KillState::Gone),
                || None,
                || None,
            );
            assert_eq!(result, Ok(None));
        }
        let mut first = true;
        let result = capture_member(
            42,
            || {
                if std::mem::take(&mut first) {
                    KillState::Live
                } else {
                    KillState::Gone
                }
            },
            || Some("linux:fixture:1".into()),
            || None,
        );
        assert_eq!(result, Ok(None));
    }

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
    fn linux_capture_retains_exiting_members_but_live_view_excludes_them() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        for (pid, stat) in [
            ("30", "30 (sleep) S 1 42 42"),
            ("31", "31 (live worker) Z 1 42 42"),
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
        let capture = |pid, _stat: &str| {
            fixture_member(
                pid,
                match pid {
                    12 => KillState::Unknown,
                    20 => KillState::Exiting,
                    21 => KillState::Gone,
                    _ => KillState::Live,
                },
            )
        };
        let members = linux_members(root.path(), 42, capture).unwrap();
        let states: Vec<_> = members
            .iter()
            .map(|member| (member.pid, member.state))
            .collect();
        assert_eq!(
            states,
            vec![
                (9, KillState::Live),
                (20, KillState::Exiting),
                (30, KillState::Live),
                (31, KillState::Live),
            ]
        );
        assert_eq!(live_pids(members), vec![9, 30, 31]);
        assert_eq!(linux_members(root.path(), 100, capture), Ok(vec![]));
    }

    #[test]
    fn linux_scan_refuses_an_unknown_member_thread_set() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let directory = root.path().join("31");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("stat"), "31 (leader) Z 1 42 42").unwrap();
        let error = linux_members(root.path(), 42, |pid, _| {
            fixture_member(pid, KillState::Unknown)
        })
        .unwrap_err();
        assert!(error.contains("31"));
    }

    #[test]
    fn linux_scan_requires_a_readable_process_directory() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let missing = root.path().join("missing");
        assert!(
            linux_members(&missing, 42, |pid, _| {
                fixture_member(pid, KillState::Live)
            })
            .is_err()
        );
    }

    #[test]
    fn linux_scan_rejects_a_stat_over_the_hard_cap() {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let directory = root.path().join("42");
        std::fs::create_dir(&directory).unwrap();
        let mut stat = b"42 (sleep) S 1 42 42".to_vec();
        stat.resize(MAX_STAT_BYTES + 1, b' ');
        std::fs::write(directory.join("stat"), stat).unwrap();
        assert!(
            linux_members(root.path(), 42, |pid, _| {
                fixture_member(pid, KillState::Live)
            })
            .is_err()
        );
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
        let identity = super::super::process::identity(pid);
        let captured = capture_members(pid);
        let members = live_members(pid);
        // Only this test's own child receives a signal. Reap it before any
        // assertions so an enumeration failure doesn't leave a fixture behind.
        kill_and_reap_child(&mut child);
        assert_eq!(
            captured,
            Ok(vec![Member {
                pid,
                identity: identity.expect("owned fixture identity"),
                state: KillState::Live,
            }])
        );
        assert_eq!(members, Ok(vec![pid]));
    }

    #[test]
    fn linux_live_members_keeps_a_zombie_leader_with_a_live_thread() {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let script = r"
import ctypes, sys, threading, time
threading.Thread(target=time.sleep, args=(30,), daemon=True).start()
time.sleep(0.1)
ctypes.CDLL(None).syscall(int(sys.argv[1]), 0)
";
        let mut child = Command::new("python3")
            .args(["-I", "-S", "-B", "-c", script])
            .arg(libc::SYS_exit.to_string())
            .env("HOME", home.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn own zombie-leader fixture");
        let pid = child.id();
        let stat_path = format!("/proc/{pid}/stat");
        let task_path = format!("/proc/{pid}/task");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut leader_exited = false;
        while Instant::now() < deadline {
            let zombie = std::fs::read_to_string(&stat_path)
                .ok()
                .is_some_and(|stat| proc_stat_is_zombie(&stat));
            let two_threads = std::fs::read_dir(&task_path)
                .map(|entries| entries.filter_map(Result::ok).count() == 2)
                .unwrap_or(false);
            if zombie && two_threads {
                leader_exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let members = live_members(pid);
        kill_and_reap_child(&mut child);
        assert!(leader_exited, "fixture did not expose its live worker");
        assert_eq!(members, Ok(vec![pid]));
    }
}

#[cfg(all(test, not(any(target_os = "linux", target_os = "macos"))))]
mod tests {
    #[test]
    fn live_members_is_unsupported() {
        assert_eq!(super::live_members(42), Err("unsupported".into()));
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
