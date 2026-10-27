//! Process-control primitives: liveness, termination, and session/group setup.
//!
//! Unix uses `libc`/`nix` signals and `setsid`; Windows uses the Win32 process
//! and job-object APIs. See the module-level docs in [`crate::sys`].

use std::process::Command;

#[cfg(unix)]
pub(crate) const TERM_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const KILL_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
pub(crate) const POLL_STEP: std::time::Duration = std::time::Duration::from_millis(100);

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use super::kill_tree_linux::ProcState as KillState;

#[cfg(all(test, target_os = "linux"))]
pub(crate) use super::kill_tree_linux::{KillTreeTestEvent, scoped_kill_tree_test_hook};

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillState {
    Gone,
    #[cfg(unix)]
    Exiting,
    Live,
    Unknown,
}

fn identity_start(identity: &str) -> Option<(&str, u128)> {
    if let Some(value) = identity.strip_prefix("linux:") {
        let (boot, ticks) = value.split_once(':')?;
        if boot.is_empty() || ticks.contains(':') {
            return None;
        }
        let ticks = ticks.parse::<u64>().ok()?;
        return Some((&identity[..identity.rfind(':')?], u128::from(ticks)));
    }
    if let Some(value) = identity.strip_prefix("apple:") {
        let (seconds, micros) = value.split_once(':')?;
        let seconds = seconds.parse::<u64>().ok()?;
        let micros = micros
            .parse::<u64>()
            .ok()
            .filter(|&value| value < 1_000_000)?;
        return Some((
            "apple",
            u128::from(seconds) * 1_000_000 + u128::from(micros),
        ));
    }
    let ticks = identity.strip_prefix("windows:")?.parse::<u64>().ok()?;
    Some(("windows", u128::from(ticks)))
}

pub(crate) fn identity_precedes(parent: &str, child: &str) -> bool {
    match (identity_start(parent), identity_start(child)) {
        (Some((parent_domain, parent)), Some((child_domain, child))) => {
            parent_domain == child_domain && parent <= child
        }
        _ => false,
    }
}

pub(crate) fn creation_time(pid: u32) -> Option<u128> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        process_start_ticks(pid).map(u128::from)
    }
    #[cfg(target_os = "macos")]
    {
        let info = process_info_apple(pid)?;
        (info.pbi_start_tvusec < 1_000_000).then_some(
            u128::from(info.pbi_start_tvsec) * 1_000_000 + u128::from(info.pbi_start_tvusec),
        )
    }
    #[cfg(windows)]
    {
        creation_ticks_win(pid).map(u128::from)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        windows
    )))]
    {
        let _ = pid;
        None
    }
}

#[cfg(unix)]
pub(crate) fn parent_pid(pid: u32) -> Option<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let (_, mut fields) = proc_stat_fields(&stat)?;
        fields.next()?.parse::<u32>().ok().filter(|&pid| pid > 0)
    }
    #[cfg(target_os = "macos")]
    {
        process_info_apple(pid)
            .map(|info| info.pbi_ppid)
            .filter(|&pid| pid > 0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Stable identity for one PID incarnation.
///
/// PIDs are reusable, so liveness checks for persisted ownership records must
/// compare the process creation time as well as the numeric PID.
pub fn identity(pid: u32) -> Option<String> {
    process_identity_platform(pid)
}

/// Process creation time as Unix epoch seconds. Unknown start times fail
/// closed when authenticating an on-disk ownership record.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn start_epoch(pid: u32) -> Option<f64> {
    let ticks = process_start_ticks(pid)?;
    // Android app domains cannot read /proc/stat. Sample the same boot epoch
    // from clocks available on both Android and Linux instead.
    let mut realtime = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut boottime = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Boottime first: a pause biases the start later, so authentication fails closed.
    // SAFETY: both pointers name writable timespec buffers.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boottime) } != 0
        || unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut realtime) } != 0
    {
        return None;
    }
    let boot = (realtime.tv_sec - boottime.tv_sec) as f64
        + (realtime.tv_nsec - boottime.tv_nsec) as f64 / 1_000_000_000.0;
    // SAFETY: sysconf reads the system clock-tick frequency.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (hz > 0).then(|| boot + ticks as f64 / hz as f64)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub fn start_epoch(pid: u32) -> Option<f64> {
    let info = process_info_apple(pid)?;
    Some(info.pbi_start_tvsec as f64 + info.pbi_start_tvusec as f64 / 1_000_000.0)
}

#[cfg(windows)]
pub fn start_epoch(pid: u32) -> Option<f64> {
    // FILETIME counts 100ns ticks since 1601, not the Unix epoch.
    let ticks = creation_ticks_win(pid)?.checked_sub(116_444_736_000_000_000)?;
    Some(ticks as f64 / 10_000_000.0)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "ios",
    target_os = "macos",
    windows
)))]
pub fn start_epoch(_pid: u32) -> Option<f64> {
    None
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn process_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    proc_stat_start_ticks(&stat)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn proc_stat_fields(stat: &str) -> Option<(u8, std::str::SplitWhitespace<'_>)> {
    let (head, fields) = stat.rsplit_once(") ")?;
    let (pid, _) = head.split_once(" (")?;
    if pid.parse::<u32>().ok()? == 0 {
        return None;
    }
    let mut fields = fields.split_whitespace();
    let state = fields.next()?.as_bytes();
    (state.len() == 1 && state[0].is_ascii_alphabetic()).then(|| (state[0], fields))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) fn proc_stat_start_ticks(stat: &str) -> Option<u64> {
    let (_, mut fields) = proc_stat_fields(stat)?;
    fields.nth(18)?.parse().ok()
}

/// Build the native identity from the same stat record that supplied PGID.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) fn proc_stat_identity(stat: &str) -> Option<String> {
    let ticks = proc_stat_start_ticks(stat)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let boot = boot.trim();
    (!boot.is_empty()).then(|| format!("linux:{boot}:{ticks}"))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) fn proc_stat_is_zombie(stat: &str) -> bool {
    proc_stat_fields(stat).is_some_and(|(state, _)| state == b'Z')
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) fn proc_stat_is_dead(stat: &str) -> bool {
    proc_stat_fields(stat).is_some_and(|(state, _)| matches!(state, b'Z' | b'X' | b'x'))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) fn proc_stat_group_id(stat: &str) -> Option<u32> {
    let (_, mut fields) = proc_stat_fields(stat)?;
    fields.next()?.parse::<u32>().ok()?;
    fields
        .next()?
        .parse::<u32>()
        .ok()
        .filter(|&group| group != 0)
}

/// One incarnation of `pid` on this host: its boot-relative start time in
/// clock ticks (`/proc/<pid>/stat` field 22) and the host boot id
/// (`/proc/sys/kernel/random/boot_id`). A reused pid differs in the start
/// time; a reboot differs in the boot id. None when the process is gone or
/// procfs is unreadable, and on targets without procfs.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn procfs_start_identity(pid: u32) -> Option<(u64, String)> {
    let start_ticks = process_start_ticks(pid)?;
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty() {
        return None;
    }
    Some((start_ticks, boot_id.to_string()))
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn procfs_start_identity(_pid: u32) -> Option<(u64, String)> {
    None
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn process_identity_platform(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    proc_stat_identity(&stat)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn process_identity_platform(pid: u32) -> Option<String> {
    let info = process_info_apple(pid)?;
    if info.pbi_pid != pid {
        return None;
    }
    apple_info_identity(&info)
}

/// Use the same BSD record for group membership and its native birth receipt.
#[cfg(any(target_os = "ios", target_os = "macos"))]
pub(crate) fn apple_info_identity(info: &libc::proc_bsdinfo) -> Option<String> {
    (info.pbi_pid != 0 && info.pbi_start_tvusec < 1_000_000)
        .then(|| format!("apple:{}:{}", info.pbi_start_tvsec, info.pbi_start_tvusec))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub(crate) fn process_info_apple(pid: u32) -> Option<libc::proc_bsdinfo> {
    // SAFETY: `info` is a correctly sized writable proc_bsdinfo buffer and
    // proc_pidinfo only fills it for the queried PID.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let read = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            // PROC_PIDTBSDINFO arg=1 also finds unreaped zombies. Their
            // start time still identifies the receipt; liveness is separate.
            1,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    (read == size).then_some(info)
}

/// One positive PID's `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID, pid)` reply.
/// The run state and exit flag decide lifecycle; tests also keep diagnostics.
#[cfg(all(
    target_os = "macos",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
struct AppleProcStateReply {
    /// The requested PID.
    #[cfg(test)]
    pid: libc::pid_t,
    /// The `sysctl` return code.
    #[cfg(test)]
    ret: libc::c_int,
    /// Raw errno, read immediately and only when `ret` is nonzero.
    #[cfg(test)]
    errno: Option<i32>,
    /// The length `sysctl` left in `oldlenp`.
    #[cfg(test)]
    returned_bytes: usize,
    /// `kp_proc.p_pid`, decoded only from a successful reply of one whole record.
    #[cfg(test)]
    decoded_pid: Option<libc::pid_t>,
    /// `kp_proc.p_stat`, kept only from a successful reply of one whole record
    /// whose `p_pid` is the requested PID.
    state: Option<libc::c_char>,
    flags: Option<libc::c_int>,
    absent: bool,
}

#[cfg(all(
    target_os = "macos",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
impl AppleProcStateReply {
    /// Positive exit evidence: the requested PID's own record says `SZOMB`.
    fn is_zombie(&self) -> bool {
        self.state == Some(libc::SZOMB as libc::c_char)
    }

    fn lifecycle(&self) -> KillState {
        // XNU bsd/sys/proc.h:183: P_WEXIT is kept in extern_proc.p_flag.
        const P_WEXIT: libc::c_int = 0x0000_2000;
        if self.absent || self.is_zombie() {
            KillState::Gone
        } else if let (Some(_), Some(flags)) = (self.state, self.flags) {
            if flags & P_WEXIT != 0 {
                KillState::Exiting
            } else {
                KillState::Live
            }
        } else {
            KillState::Unknown
        }
    }
}

/// Read native BSD state and P_WEXIT from the existing kinfo_proc query.
/// SZOMB is positive death; P_WEXIT is only irreversible exit-in-progress.
///
/// Only the leading fields of the record are declared; the rest stays opaque.
/// `struct kinfo_proc` starts with `struct extern_proc kp_proc`
/// (bsd/sys/sysctl.h:978-979), which starts with the `p_un` union of two
/// pointers and a `timeval`, then `p_vmspace`, `p_sigacts`, `p_flag`,
/// `p_stat`, and `p_pid` (bsd/sys/proc.h:102-117). The whole record is
/// 0x288 = 648 bytes on both arm64 and x86_64: golang/sys f5cb0306ac0e
/// generates `SizeofKinfoProc = C.sizeof_struct_kinfo_proc`
/// (unix/types_darwin.go:359-367) as 0x288 in unix/ztypes_darwin_arm64.go:740
/// and unix/ztypes_darwin_amd64.go:740. No other Apple ABI is verified, so
/// other Apple targets get no reader and their zombies stay unknown.
#[cfg(all(
    target_os = "macos",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
fn process_state_apple(pid: libc::pid_t) -> AppleProcStateReply {
    const KINFO_PROC_BYTES: usize = 648;

    #[repr(C)]
    union AppleProcStart {
        links: [*mut libc::c_void; 2],
        started: libc::timeval,
    }

    #[repr(C)]
    struct AppleExternProcPrefix {
        p_un: AppleProcStart,
        p_vmspace: *mut libc::c_void,
        p_sigacts: *mut libc::c_void,
        p_flag: libc::c_int,
        p_stat: libc::c_char,
        p_pid: libc::pid_t,
    }

    #[repr(C)]
    struct AppleKinfoProcBuffer {
        kp_proc: AppleExternProcPrefix,
        opaque: [u8; KINFO_PROC_BYTES - std::mem::size_of::<AppleExternProcPrefix>()],
    }

    const _: () = {
        assert!(std::mem::size_of::<AppleProcStart>() == 16);
        assert!(std::mem::size_of::<AppleExternProcPrefix>() == 48);
        assert!(std::mem::align_of::<AppleExternProcPrefix>() == 8);
        assert!(std::mem::size_of::<AppleKinfoProcBuffer>() == KINFO_PROC_BYTES);
    };

    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let mut record = std::mem::MaybeUninit::<AppleKinfoProcBuffer>::uninit();
    let mut len = KINFO_PROC_BYTES;
    // SAFETY: `mib` is a four-element read-only query, `record` is a writable
    // stack buffer of exactly `len` bytes, and a null `newp` with a zero
    // `newlen` sets nothing.
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            record.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    // Test builds keep errno for the fixture's diagnostic. Read it immediately,
    // and only when the call failed.
    let errno = if ret == 0 {
        None
    } else {
        std::io::Error::last_os_error().raw_os_error()
    };
    let mut reply = AppleProcStateReply {
        #[cfg(test)]
        pid,
        #[cfg(test)]
        ret,
        #[cfg(test)]
        errno,
        #[cfg(test)]
        returned_bytes: len,
        #[cfg(test)]
        decoded_pid: None,
        state: None,
        flags: None,
        absent: (ret == 0 && len == 0) || errno == Some(libc::ESRCH),
    };
    // An error, an empty reply (no such PID), or any other length leaves the
    // buffer unread. A buffer too small for a whole record fails with ENOMEM
    // rather than receiving part of one (kern_sysctl.c:923-926).
    if ret == 0 && len == KINFO_PROC_BYTES {
        // SAFETY: XNU zeroes each whole record, fills it, and copies all of it
        // out (kern_sysctl.c:804-829), so a successful reply of exactly one
        // record initialized every byte of `record`.
        let kp_proc = unsafe { &record.assume_init_ref().kp_proc };
        #[cfg(test)]
        {
            reply.decoded_pid = Some(kp_proc.p_pid);
        }
        reply.state = (kp_proc.p_pid == pid).then_some(kp_proc.p_stat);
        reply.flags = (kp_proc.p_pid == pid).then_some(kp_proc.p_flag);
    }
    reply
}

#[cfg(windows)]
fn process_identity_platform(pid: u32) -> Option<String> {
    creation_ticks_win(pid).map(|ticks| format!("windows:{ticks}"))
}

/// Process creation time in FILETIME ticks (100 ns units), or `None` when the
/// process cannot be opened for query — it has exited, or it is not ours.
///
/// Serves both the process identity above (a PID is only unique alongside the
/// creation time of the incarnation holding it) and the parent/child link check
/// in [`kill_tree_win_checked`].
#[cfg(windows)]
pub(crate) fn creation_ticks_win(pid: u32) -> Option<u64> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: the handle is opened query-only, every FILETIME pointer is
    // valid, and the handle is closed before returning.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let ticks = creation_ticks_from_handle(handle);
        CloseHandle(handle);
        ticks
    }
}

#[cfg(windows)]
fn creation_ticks_from_handle(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    let mut created: FILETIME = unsafe { std::mem::zeroed() };
    let mut exited: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    // SAFETY: the output buffers are valid; Windows validates the handle.
    let ok = unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) };
    (ok != 0).then_some(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos"
    ))
))]
fn process_identity_platform(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let started = String::from_utf8(output.stdout).ok()?;
    let started = started.trim();
    (!started.is_empty()).then(|| format!("unix:{started}"))
}

/// Whether `pid` still names the same process incarnation as `identity`.
pub fn has_identity(pid: u32, expected: &str) -> bool {
    identity(pid).as_deref() == Some(expected)
}

/// Whether a process with the given PID is currently alive.
///
/// Unix: `kill(pid, 0)`, treating `EPERM` (the process exists but is owned by
/// another user) as alive. Windows: `OpenProcess` followed by
/// `GetExitCodeProcess` — a live handle alone isn't proof of life, since the
/// process object stays valid as long as any handle (ours, or a job object's)
/// is open even after the process has exited. A failure to open with
/// `ERROR_ACCESS_DENIED` also means the process exists.
pub fn is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: kill(pid, 0) sends no signal; it only checks for existence.
        let Ok(pid) = checked_pid(pid) else {
            return false;
        };
        let ret = unsafe { libc::kill(pid, 0) };
        if ret == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, GetLastError, STILL_ACTIVE,
        };
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: query-only access mask; the handle is closed before returning.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if !handle.is_null() {
                let mut exit_code = 0u32;
                let ok = GetExitCodeProcess(handle, &mut exit_code) != 0;
                CloseHandle(handle);
                return ok && exit_code == STILL_ACTIVE as u32;
            }
            GetLastError() == ERROR_ACCESS_DENIED
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_gone_confirmed(pid: u32) -> bool {
    if std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|stat| proc_stat_is_dead(&stat))
    {
        return true;
    }
    let Ok(pid) = checked_pid(pid) else {
        return false;
    };
    // A hidden or unavailable procfs entry is not death while kill0 finds it.
    // SAFETY: one positive representable PID and signal zero are read-only.
    (unsafe { libc::kill(pid, 0) }) != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// Native lifecycle proof. Exiting cannot run user code but isn't confirmed
/// gone until the kernel has finished the whole process/thread set.
pub(crate) fn kill_state(pid: u32) -> KillState {
    if pid == 0 || i32::try_from(pid).is_err() {
        return KillState::Unknown;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        match super::kill_tree_linux::linux_state(pid, None) {
            KillState::Gone if !linux_gone_confirmed(pid) => KillState::Unknown,
            state => state,
        }
    }
    #[cfg(all(
        target_os = "macos",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        let Ok(pid) = checked_pid(pid) else {
            return KillState::Unknown;
        };
        process_state_apple(pid).lifecycle()
    }
    #[cfg(windows)]
    {
        if is_definitely_dead(pid) {
            KillState::Gone
        } else if creation_ticks_win(pid).is_some() {
            KillState::Live
        } else {
            KillState::Unknown
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        windows,
        all(
            target_os = "macos",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    )))]
    {
        if is_definitely_dead(pid) {
            KillState::Gone
        } else {
            KillState::Unknown
        }
    }
}

/// Positive evidence that a PID has exited or no longer exists. Probe failures
/// are unknown, not death; unlike `is_alive`, this is safe for releasing a
/// persisted owner's identity.
pub fn is_definitely_dead(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        let Ok(pid) = checked_pid(pid) else {
            return false;
        };
        // SAFETY: a positive PID and signal zero query one process, never a
        // process group, without delivering a signal.
        let ret = unsafe { libc::kill(pid, 0) };
        if ret != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return true;
        }
        // A zombie leader can still front live threads. Only the complete
        // native process state supplies additional positive death evidence.
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            super::kill_tree_linux::linux_state(pid as u32, None) == KillState::Gone
                && linux_gone_confirmed(pid as u32)
        }
        #[cfg(all(
            target_os = "macos",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ))]
        {
            process_state_apple(pid).lifecycle() == KillState::Gone
        }
        #[cfg(not(any(
            target_os = "android",
            target_os = "linux",
            all(
                target_os = "macos",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )
        )))]
        {
            false
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, STILL_ACTIVE,
        };
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: query-only access; an opened handle is closed exactly once,
        // and GetExitCodeProcess receives a writable exit-code buffer.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return GetLastError() == ERROR_INVALID_PARAMETER;
            }
            let mut exit_code = 0u32;
            let ok = GetExitCodeProcess(handle, &mut exit_code) != 0;
            CloseHandle(handle);
            ok && exit_code != STILL_ACTIVE as u32
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}
/// Whether the native state positively identifies an unreaped zombie.
pub(crate) fn is_zombie(pid: u32) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        super::kill_tree_linux::linux_is_zombie(pid)
    }
    #[cfg(all(
        target_os = "macos",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        i32::try_from(pid)
            .ok()
            .is_some_and(|pid| process_state_apple(pid).is_zombie())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        all(
            target_os = "macos",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    )))]
    {
        let _ = pid;
        false
    }
}

pub(crate) fn group_id(pid: u32) -> Option<u32> {
    #[cfg(unix)]
    {
        let pid = i32::try_from(pid).ok().filter(|&pid| pid > 0)?;
        // SAFETY: getpgid queries one positive PID and sends no signal.
        u32::try_from(unsafe { libc::getpgid(pid) }).ok()
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

pub(crate) fn is_zombie_group_leader(pid: u32) -> bool {
    is_zombie(pid) && group_id(pid) == Some(pid)
}

/// Only a receipt-matching unreaped leader can authorize its leftover PGID.
#[cfg(unix)]
fn signal_zombie_group(pid: u32, expected: &str, force: bool) -> Result<GroupSignal, &'static str> {
    if !is_zombie_group_leader(pid) || !has_identity(pid, expected) {
        return Err("zombie group leader identity changed or became unreadable");
    }
    signal_group(pid, if force { libc::SIGKILL } else { libc::SIGTERM })
        .map_err(|_| "zombie group leader PID is not signalable")
}

/// Forcefully terminate a process by PID. Best-effort; returns whether the
/// request was delivered.
///
/// Unix: `SIGKILL`. Windows: `TerminateProcess`.
pub fn kill(pid: u32) -> bool {
    #[cfg(unix)]
    {
        signal_pid(pid, libc::SIGKILL).is_ok_and(|result| result == GroupSignal::Sent)
    }
    #[cfg(windows)]
    {
        terminate_win(pid)
    }
}

/// Request graceful termination of a process by PID. Best-effort; returns
/// whether the request was delivered. Like Unix `SIGTERM`, this only *asks* the
/// process to exit — it does not force it. Callers that need a guarantee must
/// wait and then escalate to [`kill`].
///
/// Unix: `SIGTERM`. Windows: `CTRL_BREAK_EVENT` to the target's process group
/// (see [`request_shutdown_win`]), which mirrors the SIGTERM-sets-a-flag model.
pub fn terminate(pid: u32) -> bool {
    #[cfg(unix)]
    {
        signal_pid(pid, libc::SIGTERM).is_ok_and(|result| result == GroupSignal::Sent)
    }
    #[cfg(windows)]
    {
        request_shutdown_win(pid)
    }
}

/// Outcome of signalling a process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupSignal {
    /// The signal was delivered.
    Sent,
    /// No such process/group exists (already gone).
    NotFound,
    /// The caller lacks permission to signal the group.
    #[cfg(unix)]
    PermissionDenied,
    /// Any other failure.
    #[cfg(unix)]
    Other,
}

/// Native termination failures retain PIDs as data for local and relay reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KillError {
    Refused(String),
    Survivors(Vec<u32>),
    Unconfirmed { reason: String, survivors: Vec<u32> },
}

impl KillError {
    pub(crate) fn reason(&self) -> &str {
        match self {
            Self::Refused(reason) | Self::Unconfirmed { reason, .. } => reason,
            Self::Survivors(_) => "processes survived termination",
        }
    }
}

impl From<String> for KillError {
    fn from(reason: String) -> Self {
        Self::Refused(reason)
    }
}

impl From<&str> for KillError {
    fn from(reason: &str) -> Self {
        Self::Refused(reason.to_owned())
    }
}

impl std::fmt::Display for KillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => f.write_str(reason),
            Self::Survivors(pids) => write!(f, "survivor PIDs: {}", format_pids(pids)),
            Self::Unconfirmed { reason, survivors } => {
                write!(f, "{reason}; survivor PIDs: {}", format_pids(survivors))
            }
        }
    }
}

/// Lines a report names before it summarizes the rest as a count.
pub(crate) const UNSIGNALED_CARRIER_LIMIT: usize = 10;

/// ID-carrying processes a verified kill left unsignaled because they sit
/// under an excluded launcher or terminal ancestor. Informational only: they
/// are neither survivors nor a refusal and never change the kill's outcome.
/// `entries` names at most the first [`UNSIGNALED_CARRIER_LIMIT`]; `total`
/// counts every unique such candidate.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub(crate) struct UnsignaledCarriers {
    pub(crate) entries: Vec<UnsignaledCarrier>,
    pub(crate) total: usize,
}

/// One unsignaled carrier and the excluded ancestor that holds it.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct UnsignaledCarrier {
    pub(crate) launcher_pid: u32,
    pub(crate) launcher_comm: String,
    pub(crate) pid: u32,
    pub(crate) comm: String,
}

/// Authorization can race exit or PID reuse. Only the captured incarnation's
/// live failure blocks termination; a gone incarnation remains a tree anchor.
fn authorize_captured<T: PartialEq>(
    pid: u32,
    expected: &T,
    mut observe: impl FnMut(u32) -> Option<T>,
    mut definitely_dead: impl FnMut(u32) -> bool,
    authorize: impl FnOnce(u32) -> Result<(), KillError>,
) -> Result<bool, KillError> {
    if definitely_dead(pid) || observe(pid).is_some_and(|current| &current != expected) {
        return Ok(false);
    }
    let outcome = authorize(pid);
    if definitely_dead(pid) {
        return Ok(false);
    }
    match observe(pid) {
        Some(current) if &current != expected => Ok(false),
        Some(_) => outcome.map(|_| true),
        None => Err(outcome.err().unwrap_or_else(|| KillError::Unconfirmed {
            reason: "captured process identity is unreadable".into(),
            survivors: vec![pid],
        })),
    }
}

#[cfg(windows)]
fn authorize_windows_member(
    pid: u32,
    expected: Option<u64>,
    authorize: &mut impl FnMut(u32) -> Result<(), KillError>,
) -> Result<bool, KillError> {
    if is_definitely_dead(pid) {
        return Ok(false);
    }
    let expected = expected.ok_or_else(|| KillError::Unconfirmed {
        reason: "captured process identity is unreadable".into(),
        survivors: vec![pid],
    })?;
    authorize_captured(
        pid,
        &expected,
        creation_ticks_win,
        is_definitely_dead,
        authorize,
    )
}

/// Send a graceful termination request to a process group by PID.
///
/// Linux: `killpg(SIGTERM)`. The headless stop path is the only consumer, and
/// it exists on Linux alone: macOS and Windows terminate the verified tree
/// through [`terminate_group_verified`] instead, which has no group signal to
/// fall back on.
#[cfg(target_os = "linux")]
pub fn terminate_group(pid: u32) -> GroupSignal {
    signal_group_unix(pid, libc::SIGTERM)
}

/// Terminate the verified seat root, `(pid, expected identity)`, through
/// exactly one native tree helper. A helper returns success only after all
/// captured incarnations are gone. `not_signaled` receives the ID-carrying
/// processes the Linux helper left unsignaled under an excluded ancestor, on
/// success and failure alike; the other platforms leave it untouched.
pub(crate) fn terminate_group_verified(
    (pid, expected): (u32, &str),
    binding_ids: &[String],
    excluded: &[u32],
    process_id_of: impl FnMut(u32) -> super::process_args::EnvRead,
    eligible: impl FnMut(u32) -> bool,
    mut authorize: impl FnMut(u32) -> Result<(), KillError>,
    not_signaled: &mut UnsignaledCarriers,
) -> Result<GroupSignal, KillError> {
    if is_definitely_dead(pid) {
        return Ok(GroupSignal::NotFound);
    }
    if !has_identity(pid, expected) {
        return Err("PID identity changed or became unreadable before tree capture".into());
    }
    if !authorize_captured(
        pid,
        &true,
        |pid| identity(pid).map(|current| current == expected),
        is_definitely_dead,
        &mut authorize,
    )? {
        return Ok(GroupSignal::NotFound);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        super::kill_tree_linux::terminate(
            (pid, expected),
            binding_ids,
            excluded,
            process_id_of,
            eligible,
            authorize,
            not_signaled,
        )
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (binding_ids, process_id_of, not_signaled);
        super::kill_tree_apple::terminate(pid, expected, excluded, eligible, authorize)
    }
    #[cfg(windows)]
    {
        let _ = (binding_ids, process_id_of, not_signaled);
        let mut eligible = eligible;
        let ticks = expected
            .strip_prefix("windows:")
            .and_then(|ticks| ticks.parse::<u64>().ok())
            .ok_or("recorded Windows process creation time is unreadable")?;
        let mut captured = Vec::new();
        let outcome = kill_tree_win_with_identity(
            pid,
            Some(ticks),
            &mut captured,
            excluded,
            &mut eligible,
            &mut authorize,
        );
        let deadline = std::time::Instant::now() + KILL_WAIT;
        loop {
            let survivors: Vec<u32> = captured
                .iter()
                .filter_map(|&(pid, expected)| {
                    if is_definitely_dead(pid)
                        || expected
                            .zip(creation_ticks_win(pid))
                            .is_some_and(|(old, now)| old != now)
                    {
                        None
                    } else {
                        Some(pid)
                    }
                })
                .collect();
            if survivors.is_empty() {
                return outcome.map(|(result, _)| result);
            }
            if std::time::Instant::now() >= deadline {
                return Err(match outcome {
                    Ok(_) => KillError::Survivors(survivors),
                    Err(reason) => KillError::Unconfirmed {
                        reason: reason.reason().to_owned(),
                        survivors,
                    },
                });
            }
            std::thread::sleep(POLL_STEP);
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        windows
    )))]
    {
        let _ = (
            binding_ids,
            excluded,
            process_id_of,
            eligible,
            authorize,
            not_signaled,
        );
        Err("verified process-tree termination is unsupported on this platform".into())
    }
}

fn format_pids(pids: &[u32]) -> String {
    pids.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A captured zombie-group member. A late refusal fences it: it's never
/// signaled, but it stays a survivor until it's gone.
#[cfg(unix)]
struct ZombieTarget {
    member: super::kill_group::Member,
    fenced: bool,
}

/// The captured incarnation's state, or None once it's Gone or reused.
#[cfg(unix)]
fn zombie_target_state(member: &super::kill_group::Member) -> Option<KillState> {
    match kill_state(member.pid) {
        KillState::Gone => None,
        _ if identity(member.pid).is_some_and(|current| current != member.identity) => None,
        state => Some(state),
    }
}

#[cfg(unix)]
fn zombie_survivors(targets: &[ZombieTarget]) -> Vec<(u32, KillState)> {
    targets
        .iter()
        .filter_map(|target| {
            zombie_target_state(&target.member).map(|state| (target.member.pid, state))
        })
        .collect()
}

/// Whether `member`, or a group member above it, is protected: the caller's
/// chain, the leader's ancestry, or a shared broker. None if unverifiable.
#[cfg(unix)]
fn zombie_member_protected(
    member: u32,
    group: &[u32],
    excluded: &[u32],
    ancestors: &[u32],
    eligible: &mut impl FnMut(u32) -> bool,
) -> Option<bool> {
    let mut current = member;
    let mut start = creation_time(current)?;
    for _ in 0..=group.len() {
        if excluded.contains(&current) || ancestors.contains(&current) || !eligible(current) {
            return Some(true);
        }
        let parent = parent_pid(current)?;
        if !group.contains(&parent) {
            return Some(false);
        }
        let parent_start = creation_time(parent)?;
        if parent_start > start {
            // A younger process reused the parent's PID: no longer its parent.
            return Some(false);
        }
        current = parent;
        start = parent_start;
    }
    None
}

/// Capture the zombie leader's current group. Protected members and their
/// group subtrees stay out and forbid killpg; only an all-Live group exactly
/// matching the unfenced capture may be signaled as a group.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn capture_zombie_members(
    pid: u32,
    expected: &str,
    excluded: &[u32],
    ancestors: &mut Vec<u32>,
    eligible: &mut impl FnMut(u32) -> bool,
    authorize: &mut impl FnMut(u32) -> Result<(), KillError>,
    targets: &mut Vec<ZombieTarget>,
    failure: &mut Option<KillError>,
) -> Result<bool, KillError> {
    if !is_zombie_group_leader(pid) || !has_identity(pid, expected) {
        return Err("zombie group leader identity changed or became unreadable".into());
    }
    let late = !targets.is_empty() || failure.is_some();
    let mut current = pid;
    let mut child_start = creation_time(current).ok_or("zombie creation time is unreadable")?;
    let mut seen = [0u32; 1024];
    seen[0] = current;
    let mut depth = 1;
    loop {
        let parent = parent_pid(current).ok_or("zombie owner's ancestry is unreadable")?;
        if parent <= 1 {
            break;
        }
        if depth == seen.len() || seen[..depth].contains(&parent) {
            return Err("zombie owner's ancestry is cyclic or too deep".into());
        }
        let parent_start = creation_time(parent).ok_or("zombie ancestor identity is unreadable")?;
        if parent_start > child_start {
            return Err("zombie owner's ancestry contains a reused parent PID".into());
        }
        if !ancestors.contains(&parent) {
            ancestors.push(parent);
        }
        seen[depth] = parent;
        depth += 1;
        current = parent;
        child_start = parent_start;
    }
    let members = super::kill_group::capture_members(pid)?;
    let group: Vec<u32> = members.iter().map(|member| member.pid).collect();
    let mut group_safe = true;
    for member in members {
        group_safe &= member.state == KillState::Live;
        let known = targets.iter().any(|target| {
            target.member.pid == member.pid && target.member.identity == member.identity
        });
        match zombie_member_protected(member.pid, &group, excluded, ancestors, eligible) {
            Some(true) => {
                group_safe = false;
                continue;
            }
            Some(false) => {}
            None => {
                group_safe = false;
                if known || zombie_target_state(&member).is_none() {
                    continue;
                }
                let error = KillError::Unconfirmed {
                    reason: "not signaled: process ancestry unreadable".into(),
                    survivors: vec![member.pid],
                };
                if !late {
                    return Err(error);
                }
                failure.get_or_insert(error);
                targets.push(ZombieTarget {
                    member,
                    fenced: true,
                });
                continue;
            }
        }
        if known {
            continue;
        }
        // Exiting members can't run user code: authorization is moot for them.
        let fenced = member.state == KillState::Live
            && match authorize_captured(
                member.pid,
                &member.identity,
                identity,
                is_definitely_dead,
                &mut *authorize,
            ) {
                Ok(_) => false,
                Err(error) if !late => return Err(error),
                Err(error) => {
                    failure.get_or_insert(error);
                    true
                }
            };
        targets.push(ZombieTarget { member, fenced });
    }
    if group_safe {
        // Authorization can race group changes: recheck the exact membership.
        group_safe = super::kill_group::capture_members(pid)?
            .iter()
            .all(|member| {
                member.state == KillState::Live
                    && targets.iter().any(|target| {
                        !target.fenced
                            && target.member.pid == member.pid
                            && target.member.identity == member.identity
                    })
            });
    }
    if !is_zombie_group_leader(pid) || !has_identity(pid, expected) {
        return Err("zombie group leader identity changed during capture".into());
    }
    Ok(group_safe)
}

/// Group-signal a safe group, else signal each unfenced captured Live member
/// after rechecking its incarnation and authorization.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn signal_zombie_targets(
    pid: u32,
    expected: &str,
    group_safe: bool,
    force: bool,
    targets: &mut [ZombieTarget],
    authorize: &mut impl FnMut(u32) -> Result<(), KillError>,
    failure: &mut Option<KillError>,
) {
    let sig = if force { libc::SIGKILL } else { libc::SIGTERM };
    let grouped = group_safe && signal_zombie_group(pid, expected, force).is_ok();
    for target in targets.iter_mut().filter(|target| !target.fenced) {
        if (grouped && group_id(target.member.pid) == Some(pid))
            || kill_state(target.member.pid) != KillState::Live
        {
            continue;
        }
        match authorize_captured(
            target.member.pid,
            &target.member.identity,
            identity,
            is_definitely_dead,
            &mut *authorize,
        ) {
            Ok(true) => {
                let _ = signal_pid(target.member.pid, sig);
            }
            Ok(false) => {}
            Err(error) => {
                failure.get_or_insert(error);
                target.fenced = true;
            }
        }
    }
}

/// A receipt-matching unreaped leader authorizes only its captured leftovers.
/// Protected group members disable killpg, not the safe per-PID fallback.
/// Exiting members are tracked, never signaled, and must be gone by the end.
pub(crate) fn terminate_zombie_group_verified(
    pid: u32,
    expected: &str,
    excluded: &[u32],
    mut eligible: impl FnMut(u32) -> bool,
    mut authorize: impl FnMut(u32) -> Result<(), KillError>,
) -> Result<usize, KillError> {
    #[cfg(unix)]
    {
        let mut targets = Vec::new();
        let mut ancestors = Vec::new();
        let mut failure = None;
        let mut group_safe = capture_zombie_members(
            pid,
            expected,
            excluded,
            &mut ancestors,
            &mut eligible,
            &mut authorize,
            &mut targets,
            &mut failure,
        )?;
        let terminated =
            |targets: &[ZombieTarget]| targets.iter().filter(|target| !target.fenced).count();
        'rounds: for (force, budget) in [(false, TERM_WAIT), (true, KILL_WAIT)] {
            if zombie_survivors(&targets).is_empty() {
                break 'rounds;
            }
            signal_zombie_targets(
                pid,
                expected,
                group_safe,
                force,
                &mut targets,
                &mut authorize,
                &mut failure,
            );
            let deadline = std::time::Instant::now() + budget;
            loop {
                if zombie_survivors(&targets).is_empty() {
                    let before = targets.len();
                    // The leader may be reaped once its group empties; then no
                    // late member can join a group this kill could signal.
                    if !is_zombie_group_leader(pid) {
                        break 'rounds;
                    }
                    group_safe = capture_zombie_members(
                        pid,
                        expected,
                        excluded,
                        &mut ancestors,
                        &mut eligible,
                        &mut authorize,
                        &mut targets,
                        &mut failure,
                    )
                    .map_err(|error| KillError::Unconfirmed {
                        reason: error.reason().to_owned(),
                        survivors: zombie_survivors(&targets)
                            .into_iter()
                            .map(|(pid, _)| pid)
                            .collect(),
                    })?;
                    if targets.len() == before {
                        break 'rounds;
                    }
                    signal_zombie_targets(
                        pid,
                        expected,
                        group_safe,
                        force,
                        &mut targets[before..],
                        &mut authorize,
                        &mut failure,
                    );
                }
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(POLL_STEP);
            }
        }
        let survivors = zombie_survivors(&targets);
        if survivors.is_empty() {
            return Ok(terminated(&targets));
        }
        let pids: Vec<u32> = survivors.iter().map(|&(pid, _)| pid).collect();
        let exiting: Vec<u32> = survivors
            .iter()
            .filter(|(_, state)| *state == KillState::Exiting)
            .map(|&(pid, _)| pid)
            .collect();
        let note = if exiting.is_empty() {
            String::new()
        } else {
            format!(" (still exiting: {})", format_pids(&exiting))
        };
        Err(match failure {
            Some(error) => KillError::Unconfirmed {
                reason: format!("{}{note}", error.reason()),
                survivors: pids,
            },
            None if !note.is_empty() => KillError::Unconfirmed {
                reason: format!("processes did not finish exiting by the deadline{note}"),
                survivors: pids,
            },
            None => KillError::Survivors(pids),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, expected, excluded, &mut eligible, &mut authorize);
        Err("zombie process groups are unsupported on this platform".into())
    }
}

/// Forcefully kill a process group by PID.
///
/// Unix: `killpg(SIGKILL)`. Windows has no process groups in the POSIX sense, so
/// this terminates the target PID **and all of its descendants** via a process
/// snapshot ([`kill_tree_win`]). This matters because hcom records the PID of
/// the launcher (e.g. the background `powershell` host), and the real agent runs
/// as its child; killing only the recorded PID would orphan the agent.
pub fn kill_group(pid: u32) -> GroupSignal {
    #[cfg(unix)]
    {
        signal_group_unix(pid, libc::SIGKILL)
    }
    #[cfg(windows)]
    {
        kill_tree_win(pid)
    }
}

/// The only conversion from a persisted/native PID to a signal target.
/// PID 0 and negative values address groups; init is never a kill target.
#[cfg(any(unix, test))]
pub(crate) fn checked_pid(pid: u32) -> Result<i32, KillError> {
    i32::try_from(pid)
        .ok()
        .filter(|&pid| pid > 1)
        .ok_or_else(|| KillError::Refused(format!("PID {pid} is not a signalable process ID")))
}

#[cfg(unix)]
fn signal_result(ret: libc::c_int) -> GroupSignal {
    if ret == 0 {
        return GroupSignal::Sent;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => GroupSignal::NotFound,
        Some(libc::EPERM) => GroupSignal::PermissionDenied,
        _ => GroupSignal::Other,
    }
}

/// Signal exactly one positive process after checked PID conversion.
#[cfg(unix)]
pub(crate) fn signal_pid(pid: u32, sig: libc::c_int) -> Result<GroupSignal, KillError> {
    let pid = checked_pid(pid)?;
    // SAFETY: checked_pid admits only one positive non-init process ID.
    Ok(signal_result(unsafe { libc::kill(pid, sig) }))
}

/// Signal exactly one positive process group after checked PGID conversion.
#[cfg(unix)]
pub(crate) fn signal_group(pgid: u32, sig: libc::c_int) -> Result<GroupSignal, KillError> {
    let pgid = checked_pid(pgid)?;
    // SAFETY: checked_pid admits only one positive non-init process group ID.
    Ok(signal_result(unsafe { libc::killpg(pgid, sig) }))
}

#[cfg(unix)]
fn signal_group_unix(pid: u32, sig: libc::c_int) -> GroupSignal {
    signal_group(pid, sig).unwrap_or(GroupSignal::Other)
}

/// Test-only numeric signal to a `Child` this test still owns. The `&Child`
/// borrow keeps std from reaping it, and `waitid(WNOWAIT)` proves the PID is
/// still our unreaped child, so it cannot have been reused. The identity
/// captured at spawn must still match, and a group signal additionally
/// requires the child to lead its own group. Any failed proof sends nothing.
#[cfg(all(test, unix))]
pub(crate) fn signal_owned_test_child(
    child: &std::process::Child,
    expected: &str,
    signal: i32,
    group: bool,
) -> Result<(), String> {
    let pid = child.id();
    let raw = checked_pid(pid).map_err(|error| error.to_string())?;
    if expected.is_empty() {
        return Err(format!("child {pid}: empty expected spawn identity"));
    }
    // SAFETY: waitid fills this writable siginfo buffer; WNOWAIT never reaps.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: P_PID selects only this child, and info is writable.
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            raw as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if waited != 0 {
        let error = std::io::Error::last_os_error();
        return Err(format!("child {pid} is not an unreaped child: {error}"));
    }
    match identity(pid) {
        Some(current) if current == expected => {}
        Some(current) => {
            return Err(format!(
                "child {pid} identity changed: expected {expected}, found {current}"
            ));
        }
        None => return Err(format!("child {pid} identity unreadable")),
    }
    let sent = if group {
        // SAFETY: getpgid only queries the group of this positive child PID.
        let pgid = unsafe { libc::getpgid(raw) };
        if pgid != raw {
            return Err(format!("child {pid} does not lead its group (pgid {pgid})"));
        }
        signal_group(pid, signal)
    } else {
        signal_pid(pid, signal)
    }
    .map_err(|error| error.to_string())?;
    match sent {
        GroupSignal::Sent => Ok(()),
        other => Err(format!("signal {signal} to child {pid}: {other:?}")),
    }
}

/// Replace the current process with the given command.
///
/// Unix uses `exec()` and only returns (an error) on failure. Windows has no
/// `exec`, so it spawns the command, waits, and exits with the child's status
/// code — likewise not returning on success.
pub fn exec_replace(mut cmd: Command) -> std::io::Error {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.exec()
    }
    #[cfg(windows)]
    {
        match cmd.status() {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(e) => e,
        }
    }
}

/// Kill a child process together with its process group.
///
/// Unix: `killpg(SIGKILL)` on the child's group (set up via [`detach_session`]),
/// falling back to `Child::kill` if the group signal fails. Windows: terminates
/// the child's whole process tree ([`kill_tree_win`]).
pub fn kill_child_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;

        if let Ok(raw_pid) = i32::try_from(child.id())
            && killpg(Pid::from_raw(raw_pid), Signal::SIGKILL).is_ok()
        {
            return;
        }
    }

    #[cfg(windows)]
    {
        // kill_tree_win_checked terminates `child` itself (with the hcom-kill
        // sentinel exit code 130, via terminate_win) and its whole descendant
        // tree. If root's own termination is confirmed, return rather than
        // falling through to child.kill() below: TerminateProcess only
        // requests termination asynchronously, so a second call racing the
        // first can overwrite the sentinel exit code with a different one,
        // corrupting the EXIT_WAS_KILLED check that reads it back.
        //
        // If root's termination was NOT confirmed, it may just be that the
        // fresh-by-PID OpenProcess inside terminate_win failed for a reason
        // other than "already gone" (a handle-table limit, or AV/EDR hooking
        // around freshly-opened handles, for instance) — fall through to
        // child.kill() as a retry via the handle Command already has open,
        // which a failing OpenProcess-by-PID wouldn't affect.
        let (_, root_terminated) = kill_tree_win_checked(child.id());
        if root_terminated {
            return;
        }
    }

    let _ = child.kill();
}

/// Put a not-yet-spawned [`Command`] into its own session / process group, so
/// the resulting child can be signalled as a group and is detached from the
/// parent's controlling terminal.
///
/// Unix: `setsid()` via a `pre_exec` hook. Windows: `CREATE_NEW_PROCESS_GROUP`
/// combined with `CREATE_NO_WINDOW`, so the child neither shares the parent's
/// console nor dies when that console closes.
pub fn detach_session(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid() runs in the child between fork and exec and is
        // async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
}

/// Keep the caller's open descriptors out of a launched seat.
///
/// hcom is usually run from inside another agent's shell tool, and that agent
/// may hold files open without `O_CLOEXEC` (omp/bun keeps its transcript open
/// for append). Without this, every descriptor >= 3 crosses the exec into the
/// runner, the PTY wrapper and the new seat's whole process tree. hcom passes
/// no descriptor above stderr to a seat, so everything >= 3 is dropped.
///
/// The descriptors are marked close-on-exec rather than closed: `Command`
/// reports an exec failure to the parent through a CLOEXEC pipe that must stay
/// open until the exec itself, and for [`exec_replace`] a failed exec leaves
/// hcom running with its own descriptors intact.
///
/// Unix: a `pre_exec` hook calling `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`
/// on Linux/Android, falling back to `fcntl(FD_CLOEXEC)` over every possible
/// descriptor where that syscall is unavailable. Windows: no-op; std creates
/// children with handle inheritance on, but only handles explicitly marked
/// inheritable cross, and [`spawn_detached`] already strips the std handles.
pub fn close_inherited_fds(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Resolved in the parent: the hook itself must not allocate or take
        // locks, and sysconf is not async-signal-safe. Clamped so a huge
        // RLIMIT_NOFILE cannot turn the fallback loop into a stall.
        // SAFETY: sysconf only reads a limit.
        let open_max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
        let max_fd = if open_max <= 0 {
            1024
        } else {
            open_max.min(1 << 20) as libc::c_int
        };
        // SAFETY: the hook only issues close_range/fcntl syscalls, both
        // async-signal-safe, and touches no Rust-managed state.
        unsafe {
            command.pre_exec(move || {
                mark_cloexec_from(3, max_fd);
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    let _ = command;
}

/// Set `FD_CLOEXEC` on every descriptor `>= first`. Async-signal-safe.
#[cfg(unix)]
fn mark_cloexec_from(first: libc::c_int, max_fd: libc::c_int) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
        // SAFETY: raw close_range syscall with scalar arguments; on kernels
        // older than 5.11 it fails with ENOSYS/EINVAL and we fall through.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first as libc::c_uint,
                libc::c_uint::MAX,
                CLOSE_RANGE_CLOEXEC,
            )
        };
        if ret == 0 {
            return;
        }
    }
    for fd in first..max_fd {
        // SAFETY: fcntl on an arbitrary descriptor number; EBADF for closed
        // slots is expected and ignored.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
}

/// Best-effort graceful shutdown request on Windows, the analogue of Unix
/// `SIGTERM`: it asks the target to exit but does not force it.
///
/// Sends `CTRL_BREAK_EVENT` to the target's process group. Processes spawned via
/// [`detach_session`] use `CREATE_NEW_PROCESS_GROUP`, so their process-group id
/// equals their PID, and a process that has registered a handler (see
/// `sys::signal::register_term`) sets its shutdown flag in response.
///
/// Delivery only reaches a process that shares the caller's console. A relay
/// worker spawned from a different console (the common case) does not receive
/// it, and this returns `false`; the caller's wait + [`kill`] fallback then
/// terminates it. This matches Unix, where `SIGTERM` likewise only *requests*
/// shutdown and callers escalate to `SIGKILL`.
#[cfg(windows)]
fn request_shutdown_win(pid: u32) -> bool {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
    // SAFETY: plain FFI call, no pointers; the process-group id is the target
    // PID (valid because detach_session uses CREATE_NEW_PROCESS_GROUP).
    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) != 0 }
}

#[cfg(windows)]
fn terminate_win(pid: u32) -> bool {
    terminate_win_matching(pid, None)
}

#[cfg(windows)]
fn terminate_win_matching(pid: u32, expected: Option<u64>) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
    };
    // Query and terminate through ONE handle: even a PID reused between the
    // OpenProcess and TerminateProcess calls cannot redirect the termination.
    let access = PROCESS_TERMINATE
        | if expected.is_some() {
            PROCESS_QUERY_LIMITED_INFORMATION
        } else {
            0
        };
    unsafe {
        let handle = OpenProcess(access, 0, pid);
        if handle.is_null() {
            return false;
        }
        if expected.is_some_and(|ticks| creation_ticks_from_handle(handle) != Some(ticks)) {
            CloseHandle(handle);
            return false;
        }
        // Exit code 130 (128 + SIGINT) is the hcom sentinel for "externally
        // killed via hcom kill". The pty proxy reads this back from child.wait()
        // to set EXIT_WAS_KILLED before the delivery thread records exit status.
        let ok = TerminateProcess(handle, 130) != 0;
        CloseHandle(handle);
        ok
    }
}

/// Snapshot every live process's parent link via `CreateToolhelp32Snapshot`,
/// retrying once on transient failure. Read executable names only for identity
/// proof (`with_exe_names`); kill-tree rescans need links but not names.
///
/// Returns `None` if the snapshot could not be taken even after the retry.
#[cfg(windows)]
pub(crate) struct ProcessSnapshot {
    pub parent_pid: u32,
    pub exe_name: Option<String>,
}

#[cfg(windows)]
pub(crate) fn snapshot_parents(
    with_exe_names: bool,
) -> Option<std::collections::HashMap<u32, ProcessSnapshot>> {
    use std::collections::HashMap;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    let mut parents: HashMap<u32, ProcessSnapshot> = HashMap::new();
    // SAFETY: snapshot handle is closed before returning; the PROCESSENTRY32W is
    // fully initialized (dwSize set) before the enumeration calls.
    unsafe {
        let mut snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            // Snapshot can fail transiently under high load; retry once.
            snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        }
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let exe_name = if with_exe_names {
                    let name_end = entry
                        .szExeFile
                        .iter()
                        .position(|&ch| ch == 0)
                        .unwrap_or(entry.szExeFile.len());
                    String::from_utf16(&entry.szExeFile[..name_end])
                        .ok()
                        .filter(|name| !name.is_empty())
                } else {
                    None
                };
                parents.insert(
                    entry.th32ProcessID,
                    ProcessSnapshot {
                        parent_pid: entry.th32ParentProcessID,
                        exe_name,
                    },
                );
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    Some(parents)
}

/// Spawn a detached child without leaking the caller's captured stdio handles.
///
/// On Windows, `Command` must enable handle inheritance for explicitly supplied
/// child stdio (for example a background log file). Without an explicit handle
/// list, that can also inherit the hcom CLI's own stdout/stderr pipes. A caller
/// using `Command::output()` then waits forever for EOF after hcom exits because
/// the long-lived agent still owns duplicate pipe handles.
pub fn spawn_detached(command: &mut Command) -> std::io::Result<std::process::Child> {
    detach_session(command);

    #[cfg(not(windows))]
    {
        command.spawn()
    }

    #[cfg(windows)]
    {
        use std::sync::{Mutex, OnceLock};
        use windows_sys::Win32::Foundation::{
            GetHandleInformation, HANDLE_FLAG_INHERIT, SetHandleInformation,
        };
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };

        static SPAWN_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = SPAWN_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        let mut restored = Vec::new();
        for kind in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            // SAFETY: GetStdHandle returns a borrowed process handle. We only
            // query/change its inheritance flag and restore it before returning.
            unsafe {
                let handle = GetStdHandle(kind);
                if handle.is_null() {
                    continue;
                }
                let mut flags = 0;
                if GetHandleInformation(handle, &mut flags) != 0
                    && flags & HANDLE_FLAG_INHERIT != 0
                    && SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) != 0
                {
                    restored.push(handle);
                }
            }
        }

        let child = command.spawn();
        for handle in restored {
            // SAFETY: these are the same live borrowed standard handles whose
            // inheritance flag was cleared above.
            unsafe {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            }
        }
        child
    }
}

/// Whether `child` can really be a child of `parent`, judged by creation time.
///
/// A process cannot be older than the process that created it, so a candidate
/// whose creation time precedes its claimed parent's is a stale parent link:
/// the recorded parent PID belonged to a process that has since exited and had
/// its PID recycled by the (younger) process now holding it. Windows keeps
/// reporting the numeric PID of the original parent, so the orphan looks like a
/// child of whatever inherited that number.
///
/// `None` on either side means the process could not be opened for query, so
/// the link can neither be confirmed nor disproved — those are accepted, which
/// leaves the pre-existing behaviour untouched wherever this check has nothing
/// to say. A process we cannot query is one we generally cannot terminate
/// either.
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) fn child_link_is_plausible(parent_ticks: Option<u64>, child_ticks: Option<u64>) -> bool {
    match (parent_ticks, child_ticks) {
        (Some(parent), Some(child)) => child >= parent,
        _ => true,
    }
}

/// Number of extra re-scan rounds run after the initial kill pass, to catch
/// descendants spawned after the first snapshot (see [`kill_tree_win_checked`]).
#[cfg(windows)]
const RESCAN_ROUNDS: u32 = 2;

/// Delay between re-scan rounds, giving the OS a moment to start tearing down
/// what was just killed before the next snapshot is taken.
#[cfg(windows)]
const RESCAN_DELAY: std::time::Duration = std::time::Duration::from_millis(75);

/// Terminate `root` and all of its descendants.
///
/// Windows has no process groups, so the only general way to "kill the agent and
/// its children" by PID from an unrelated process is to walk the parent/child
/// links in a process snapshot. The full descendant set is collected from a
/// single snapshot *before* any termination, so killing a parent can't strand a
/// child behind a now-stale parent PID (Windows does not reparent orphans).
///
/// Returns `Sent` if the root was present (and termination was attempted),
/// `NotFound` if no live process had the root PID. Like `killpg`, individual
/// termination failures are best-effort and don't change the result.
///
/// Caveat: PID reuse can make a parent link stale, the same theoretical race
/// `taskkill /T` carries. Links that claim a *pre-existing* process as a child
/// are rejected on creation time (see `child_link_is_plausible`), which covers
/// the direction that can reach a long-lived bystander; what remains is a
/// straggler spawned by whoever recycled a PID this walk already terminated.
#[cfg(windows)]
fn kill_tree_win(root: u32) -> GroupSignal {
    kill_tree_win_checked(root).0
}

/// Same as [`kill_tree_win`], but also reports whether `root`'s own
/// `terminate_win` call specifically succeeded (as opposed to just "root was
/// found in the snapshot"). `kill_tree_win`'s `Sent` doesn't distinguish
/// these — every descendant's individual termination result is discarded —
/// so [`kill_child_group`] uses this directly to decide whether a retry via
/// its own already-open `Child` handle is worthwhile.
///
/// Re-scan for stragglers: a single snapshot is inherently a point-in-time
/// view, so a process spawned by any tree member *after* the snapshot but
/// *before* that member is terminated is invisible to the first pass and would
/// otherwise survive. Unix's `killpg` doesn't have this problem for
/// already-existing group members — the kernel delivers the signal to the
/// whole group atomically — but Windows has no equivalent primitive, so after
/// the first kill pass this takes a couple of follow-up snapshots, each time
/// looking for new processes parented by *any* previously-known tree member
/// (not just `root`, since mid-tree descendants can keep spawning children of
/// their own even after `root` is gone) and killing those too. This narrows
/// the race window considerably but, being fundamentally snapshot-based, does
/// not eliminate it: a straggler spawned after the very last re-scan's
/// snapshot can still escape.
#[cfg(windows)]
fn kill_tree_win_checked(root: u32) -> (GroupSignal, bool) {
    kill_tree_win_with_identity(root, None, &mut Vec::new(), &[], &mut |_| true, &mut |_| {
        Ok(())
    })
    .unwrap_or((GroupSignal::NotFound, false))
}

/// Collect `root` and all its descendants (BFS over the snapshot's parent
/// links), rejecting any candidate that is older than the tree member
/// claiming it: that link is stale, not a real parent/child edge (see
/// `child_link_is_plausible`). Creation times are read through `ticks`.
/// A `verified` walk skips an ineligible child with its subtree and hands
/// each child it cannot attribute (an unreadable time on either side, or a
/// parent no longer its cached incarnation) to `unresolved`, never to the
/// tree. Returns the tree, root first, and the deepest member's depth.
#[cfg(windows)]
fn capture_tree_win(
    root: u32,
    parents: &std::collections::HashMap<u32, ProcessSnapshot>,
    ticks: &mut std::collections::HashMap<u32, Option<u64>>,
    verified: bool,
    eligible: &mut impl FnMut(u32) -> bool,
    mut unresolved: impl FnMut(u32, Option<u64>),
) -> (Vec<u32>, usize) {
    let mut tree = vec![root];
    let mut depth = 0;
    let mut level_end = 1;
    let mut i = 0;
    while i < tree.len() {
        if i == level_end {
            depth += 1;
            level_end = tree.len();
        }
        let current = tree[i];
        let parent_ticks = *ticks
            .entry(current)
            .or_insert_with(|| creation_ticks_win(current));
        for (&pid, entry) in parents {
            let ppid = entry.parent_pid;
            if ppid != current || tree.contains(&pid) {
                continue;
            }
            if verified && !eligible(pid) {
                continue;
            }
            let child_ticks = *ticks.entry(pid).or_insert_with(|| creation_ticks_win(pid));
            if verified
                && (parent_ticks.is_none()
                    || child_ticks.is_none()
                    || creation_ticks_win(current) != parent_ticks)
            {
                unresolved(pid, child_ticks);
                continue;
            }
            if child_link_is_plausible(parent_ticks, child_ticks) {
                tree.push(pid);
            }
        }
        i += 1;
    }
    (tree, depth)
}

#[cfg(windows)]
fn kill_tree_win_with_identity(
    root: u32,
    expected: Option<u64>,
    captured: &mut Vec<(u32, Option<u64>)>,
    excluded: &[u32],
    eligible: &mut impl FnMut(u32) -> bool,
    authorize: &mut impl FnMut(u32) -> Result<(), KillError>,
) -> Result<(GroupSignal, bool), KillError> {
    if expected.is_some() && !eligible(root) {
        return Err("verified root is an ineligible shared process; no signal sent".into());
    }
    if let Some(expected) = expected
        && !excluded.contains(&root)
    {
        captured.push((root, Some(expected)));
    }
    if let Some(expected) = expected {
        match creation_ticks_win(root) {
            Some(current) if current == expected => {}
            Some(_) => return Ok((GroupSignal::NotFound, false)),
            None if is_definitely_dead(root) => return Ok((GroupSignal::NotFound, false)),
            None => return Err("verified root identity is unreadable before tree capture".into()),
        }
    }
    let Some(parents) = snapshot_parents(false) else {
        if expected.is_some() {
            // A verified kill must not signal a partial tree and claim success.
            return Err("verified process-tree snapshot is unreadable; no signal sent".into());
        }
        // Still can't enumerate descendants; kill only the root. Any
        // surviving descendants will be reaped when the job object
        // closes. This still reports `Sent` (not a distinct "partial"
        // result) — `GroupSignal`/`KillResult` are a flat success/
        // not-found/permission-denied/other set consumed by ~15 call
        // sites across the CLI kill-reporting path and the relay JSON
        // protocol (see commands/kill.rs, relay/control.rs); threading a
        // new "partial" variant through all of them is a larger, separate
        // change. Logging at least makes this rare degraded path visible
        // instead of leaving zero trace anywhere.
        crate::log::log_error(
            "native",
            "win.kill_tree",
            &format!(
                "CreateToolhelp32Snapshot failed twice; killing root pid {root} only, \
                 descendants may be left running until the job object reaps them"
            ),
        );
        let ok = terminate_win_matching(root, expected);
        return Ok((
            if ok {
                GroupSignal::Sent
            } else {
                GroupSignal::NotFound
            },
            ok,
        ));
    };

    if !parents.contains_key(&root) {
        if expected.is_some() && !is_definitely_dead(root) {
            return Err("live verified root is missing from the process-tree snapshot".into());
        }
        return Ok((GroupSignal::NotFound, false));
    }

    // Creation times are cached per PID, and the cache is what makes the check
    // hold up across the re-scan rounds below: it keeps each tree member's time
    // as read while that member was still alive, so a candidate is always
    // compared against the incarnation this walk actually decided to kill.
    let mut ticks: std::collections::HashMap<u32, Option<u64>> = std::collections::HashMap::new();
    if let Some(expected) = expected {
        ticks.insert(root, Some(expected));
    }
    let (mut tree, _) = capture_tree_win(
        root,
        &parents,
        &mut ticks,
        expected.is_some(),
        eligible,
        |pid, child_ticks| {
            if !excluded.contains(&pid) {
                captured.push((pid, child_ticks));
            }
        },
    );
    if expected.is_some() {
        captured.extend(
            tree.iter()
                .filter(|&&pid| pid != root && !excluded.contains(&pid))
                .map(|&pid| (pid, ticks.get(&pid).copied().flatten())),
        );
    }
    if let Some(expected) = expected {
        match creation_ticks_win(root) {
            Some(current) if current == expected => {}
            Some(_) => return Ok((GroupSignal::NotFound, false)),
            None if is_definitely_dead(root) => return Ok((GroupSignal::NotFound, false)),
            None => {
                return Err("verified root identity is unreadable before tree termination".into());
            }
        }
    }
    if expected.is_some() {
        for &(pid, start) in captured.iter() {
            authorize_windows_member(pid, start, authorize)?;
        }
    }

    // Terminate children before parents (deepest first) so a parent can't spawn
    // a new child after we've passed it.
    let mut root_terminated = false;
    for &pid in tree.iter().rev() {
        if excluded.contains(&pid) {
            continue;
        }
        if expected.is_some() {
            if !eligible(pid) {
                continue;
            }
            if !authorize_windows_member(pid, ticks.get(&pid).copied().flatten(), authorize)? {
                continue;
            }
        }
        let ok = if expected.is_some() {
            ticks
                .get(&pid)
                .copied()
                .flatten()
                .is_some_and(|ticks| terminate_win_matching(pid, Some(ticks)))
        } else {
            terminate_win(pid)
        };
        if pid == root {
            root_terminated = ok;
        }
    }

    // Re-scan for stragglers spawned between the snapshot and their parent's
    // termination (see doc comment above).
    //
    // This widens (but does not introduce in kind) the PID-reuse race already
    // called out on `kill_tree_win_checked`: each extra round is another
    // `terminate_win` -> sleep -> re-snapshot cycle, so there's more elapsed
    // time in which a PID this function just terminated could be recycled by
    // an unrelated process that happens to be parented under another PID
    // still in `tree`. The creation-time check applies here too, against the
    // times cached while each tree member was alive, so nothing older than the
    // member claiming it can be swept up; a process spawned *by* whoever
    // recycled such a PID is younger and still passes. `KillOnDropJob` (see
    // `pty::win::job`) remains the backstop that reaps the real tree regardless.
    //
    // Always run all RESCAN_ROUNDS —
    // round N finding nothing new doesn't mean a straggler can't still appear
    // before round N+1's snapshot, so stopping early would defeat the point of
    // having more than one round. Within a round, expand `tree` to a fixed
    // point (mirroring the initial BFS above) rather than a single pass, so a
    // straggler and *its own* child that both first appear in the same
    // snapshot are both caught in that round regardless of HashMap iteration
    // order.
    for _ in 0..RESCAN_ROUNDS {
        std::thread::sleep(RESCAN_DELAY);
        let Some(parents) = snapshot_parents(false) else {
            if expected.is_some() {
                return Err("late-fork process-tree snapshot is unreadable".into());
            }
            break;
        };
        let before = tree.len();
        loop {
            let start_len = tree.len();
            for (&pid, entry) in &parents {
                let ppid = entry.parent_pid;
                if !tree.contains(&ppid) || tree.contains(&pid) {
                    continue;
                }
                if expected.is_some() && !eligible(pid) {
                    continue;
                }
                let parent_ticks = *ticks
                    .entry(ppid)
                    .or_insert_with(|| creation_ticks_win(ppid));
                let child_ticks = *ticks.entry(pid).or_insert_with(|| creation_ticks_win(pid));
                // A newly observed child cannot be attributed through a dead
                // or reused parent PID. The wrapper's kernel job object still
                // owns genuine children independently of these numeric links.
                if expected.is_some()
                    && (parent_ticks.is_none()
                        || child_ticks.is_none()
                        || creation_ticks_win(ppid) != parent_ticks)
                {
                    if child_ticks.is_none() && !excluded.contains(&pid) && !is_definitely_dead(pid)
                    {
                        captured.push((pid, None));
                    }
                    continue;
                }
                if child_link_is_plausible(parent_ticks, child_ticks) {
                    tree.push(pid);
                    if expected.is_some() && !excluded.contains(&pid) {
                        captured.push((pid, child_ticks));
                    }
                }
            }
            if tree.len() == start_len {
                break;
            }
        }
        if expected.is_some() {
            for &pid in &tree[before..] {
                if !excluded.contains(&pid) {
                    authorize_windows_member(pid, ticks.get(&pid).copied().flatten(), authorize)?;
                }
            }
        }
        // Kill only the newly discovered stragglers (deepest-first isn't
        // load-bearing here since these are freshly discovered leaves relative
        // to the known tree, but iterating in reverse discovery order costs
        // nothing and keeps the same "children before parents" spirit).
        for &pid in tree[before..].iter().rev() {
            if excluded.contains(&pid) {
                continue;
            }
            if expected.is_some() {
                if !eligible(pid) {
                    continue;
                }
                if !authorize_windows_member(pid, ticks.get(&pid).copied().flatten(), authorize)? {
                    continue;
                }
                if let Some(ticks) = ticks.get(&pid).copied().flatten() {
                    terminate_win_matching(pid, Some(ticks));
                }
            } else {
                terminate_win(pid);
            }
        }
    }

    Ok((GroupSignal::Sent, root_terminated))
}

/// Bounds of a captured headless tree, the same as on Linux and macOS.
#[cfg(windows)]
const MAX_TREE_DEPTH: usize = 128;
#[cfg(windows)]
const MAX_TREE_PROCESSES: usize = 4_096;

/// The verified `root` and every descendant one snapshot links to it, root
/// first, each with its native `windows:<creation ticks>` identity, through
/// the same walk the verified kill captures with. Read-only: nothing is
/// signaled. `root` must hold `expected` both before and after the capture;
/// an edge it cannot attribute, or a tree past the depth or size limit,
/// refuses the whole capture instead of returning part of the tree.
#[cfg(windows)]
pub(crate) fn headless_tree_members(
    root: u32,
    expected: &str,
) -> Result<Vec<(u32, String)>, KillError> {
    let expected_ticks = expected
        .strip_prefix("windows:")
        .and_then(|ticks| ticks.parse::<u64>().ok())
        .ok_or("recorded Windows process creation time is unreadable")?;
    if creation_ticks_win(root) != Some(expected_ticks) {
        return Err("root identity changed or became unreadable before tree capture".into());
    }
    let parents = snapshot_parents(false).ok_or("verified process-tree snapshot is unreadable")?;
    if !parents.contains_key(&root) {
        return Err("verified root is missing from the process-tree snapshot".into());
    }
    let mut ticks = std::collections::HashMap::from([(root, Some(expected_ticks))]);
    let mut unresolved = Vec::new();
    let (tree, depth) =
        capture_tree_win(root, &parents, &mut ticks, true, &mut |_| true, |pid, _| {
            unresolved.push(pid)
        });
    if !unresolved.is_empty() {
        return Err(KillError::Unconfirmed {
            reason: "process-tree edge is unreadable or its parent was reused".into(),
            survivors: unresolved,
        });
    }
    if depth > MAX_TREE_DEPTH {
        return Err("verified root's process tree exceeds the depth limit".into());
    }
    if tree.len() > MAX_TREE_PROCESSES {
        return Err("verified root's process tree exceeds the size limit".into());
    }
    if creation_ticks_win(root) != Some(expected_ticks) {
        return Err("root identity changed or became unreadable after tree capture".into());
    }
    tree.into_iter()
        .map(|pid| match ticks.get(&pid).copied().flatten() {
            Some(created) => Ok((pid, format!("windows:{created}"))),
            None => Err(KillError::Unconfirmed {
                reason: "captured process identity is unreadable".into(),
                survivors: vec![pid],
            }),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_targets_reject_group_init_and_unrepresentable_pids() {
        let invalid = [0, 1, i32::MAX as u32 + 1, u32::MAX];
        for pid in invalid {
            assert!(checked_pid(pid).is_err(), "pid {pid}");
            // Signal zero: even a regressed guard would deliver nothing.
            #[cfg(unix)]
            {
                assert!(signal_pid(pid, 0).is_err(), "pid {pid}");
                assert!(signal_group(pid, 0).is_err(), "group {pid}");
            }
        }
        assert_eq!(checked_pid(2), Ok(2));
        assert_eq!(checked_pid(i32::MAX as u32), Ok(i32::MAX));
    }

    #[test]
    fn captured_authorization_distinguishes_live_unreadable_from_exit_and_reuse() {
        use std::cell::Cell;
        let unreadable = KillError::Unconfirmed {
            reason: "not signaled: identity unreadable".into(),
            survivors: vec![42],
        };
        for (after, dead, expected) in [
            (Some(7), false, Err(unreadable.clone())),
            (Some(7), true, Ok(false)), // A zombie retains its creation time.
            (None, true, Ok(false)),    // Reaped between listing and argv read.
            (Some(8), false, Ok(false)), // Another process reused the PID.
            (None, false, Err(unreadable.clone())), // No proof of death or reuse.
        ] {
            let authorized = Cell::new(false);
            let result = authorize_captured(
                42,
                &7,
                |_| if authorized.get() { after } else { Some(7) },
                |_| authorized.get() && dead,
                |_| {
                    authorized.set(true);
                    Err(unreadable.clone())
                },
            );
            assert_eq!(result, expected, "after={after:?}, dead={dead}");
        }
        assert_eq!(
            authorize_captured(42, &7, |_| Some(7), |_| false, |_| Ok(())),
            Ok(true)
        );
        assert_eq!(
            authorize_captured(
                42,
                &7,
                |_| Some(8),
                |_| false,
                |_| panic!("a reused PID must never reach authorization")
            ),
            Ok(false)
        );
    }

    #[test]
    fn test_is_alive_current_process() {
        assert!(is_alive(std::process::id()));
    }

    #[test]
    fn test_is_alive_dead_process() {
        assert!(!is_alive(99_999_999));
    }

    #[cfg(unix)]
    #[test]
    fn test_is_definitely_dead_rejects_group_and_unrepresentable_pids() {
        assert!(!is_definitely_dead(0));
        assert!(!is_definitely_dead(u32::MAX));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn test_is_definitely_dead_observes_only_an_exited_fixture() {
        #[cfg(unix)]
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        #[cfg(windows)]
        let mut child = spawn_long_lived_child();
        let pid = child.id();
        let live_probe = is_definitely_dead(pid);
        #[cfg(unix)]
        child.kill().unwrap();
        #[cfg(windows)]
        kill_child_group(&mut child);
        child.wait().unwrap();
        let exited_probe = is_definitely_dead(pid);
        assert!(!live_probe, "a live fixture must not be declared dead");
        assert!(exited_probe, "an exited fixture must be positively dead");
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[test]
    fn test_proc_stat_requires_an_exact_zombie_state() {
        for (stat, zombie) in [
            ("42 (fixture) Z 1 2 3", true),
            ("42 (fixture ) Z inside) Z 1 2 3", true),
            ("42 (fixture ) Z inside) S 1 2 3", false),
            ("42 (fixture) R 1 2 3", false),
            ("42 (fixture) Zz 1 2 3", false),
            ("42 (fixture) ", false),
            ("42 (fixture Z", false),
            ("", false),
        ] {
            assert_eq!(proc_stat_is_zombie(stat), zombie, "{stat:?}");
        }
    }

    #[cfg(any(
        target_os = "android",
        target_os = "linux",
        all(
            target_os = "macos",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    ))]
    #[test]
    fn test_is_definitely_dead_observes_an_unreaped_fixture() {
        let scratch = tempfile::tempdir().unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "read -r line"])
            .env_clear()
            .env("HOME", scratch.path())
            .env("HCOM_DIR", scratch.path())
            .env("TMPDIR", scratch.path())
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let expected_identity = identity(pid).expect("live fixture identity");
        drop(child.stdin.take());
        // SAFETY: waitid fills this writable siginfo buffer for our child.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            // WNOWAIT synchronizes exit without reaping, unlike Child::wait.
            // SAFETY: P_PID selects only our fixture, and info is writable.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if result == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                child.wait().unwrap();
                panic!("waitid for exited fixture: {error}");
            }
        }
        // SAFETY: signal zero only queries this fixture's positive PID.
        let probe_pid = checked_pid(pid).expect("spawned child has a signalable PID");
        let kill_result = unsafe { libc::kill(probe_pid, 0) };
        let dead_probe = is_definitely_dead(pid);
        let zombie_identity = identity(pid);
        // Keep the kernel's raw reply while the zombie still exists.
        #[cfg(target_os = "macos")]
        let native_reply = process_state_apple(probe_pid);
        // Reap before asserting so even a failed probe leaves no zombie behind.
        child.wait().unwrap();
        assert_eq!(kill_result, 0, "an unreaped fixture still exists for kill0");
        #[cfg(target_os = "macos")]
        assert!(
            native_reply.is_zombie(),
            "kern.proc.pid must read the unreaped fixture as SZOMB: \
             pid={} ret={} errno={:?} returned_bytes={} decoded_pid={:?} state={:?}",
            native_reply.pid,
            native_reply.ret,
            native_reply.errno,
            native_reply.returned_bytes,
            native_reply.decoded_pid,
            native_reply.state
        );
        assert!(dead_probe, "an unreaped zombie is positively dead");
        assert_eq!(
            zombie_identity.as_deref(),
            Some(expected_identity.as_str()),
            "the unreaped PID must retain its receipt-verifiable start time"
        );
    }

    #[test]
    fn test_process_identity_is_stable_for_current_process() {
        let pid = std::process::id();
        let first = identity(pid).expect("current process must have a start identity");
        assert_eq!(identity(pid).as_deref(), Some(first.as_str()));
        assert!(has_identity(pid, &first));
        assert!(!has_identity(pid, "a different process incarnation"));
    }

    #[test]
    fn test_process_identity_is_absent_for_dead_pid() {
        assert!(identity(u32::MAX).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn start_epoch_matches_proc_boot_time() {
        let pid = std::process::id();
        let boot: f64 = std::fs::read_to_string("/proc/stat")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("btime "))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: sysconf reads the system clock-tick frequency.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        assert!(hz > 0);
        let expected = boot + process_start_ticks(pid).unwrap() as f64 / hz as f64;
        let started = start_epoch(pid).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        assert!(started <= now, "process start {started} is after {now}");
        assert!(
            (started - expected).abs() < 1.0,
            "clock-based start {started} differs from /proc/stat start {expected}"
        );
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[test]
    fn test_linux_process_identity_includes_boot_id() {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let identity = identity(std::process::id()).unwrap();
        assert!(identity.contains(boot_id.trim()));
    }

    /// Open `/dev/null` the way omp/bun opens its transcript: without
    /// `O_CLOEXEC`, so a plain fork+exec hands it to the child.
    #[cfg(unix)]
    fn open_inheritable_fd() -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        // SAFETY: open with a NUL-terminated literal path; result checked.
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_APPEND) };
        assert!(fd > 2, "open(/dev/null) failed or returned stdio: {fd}");
        // SAFETY: fd is a fresh descriptor this test owns.
        unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }
    }

    /// Which of `fds` are open in a `sh` spawned from `command`, as seen by
    /// the shell itself (`/dev/fd` resolves to the process running `test`).
    #[cfg(unix)]
    fn fds_open_in_child(mut command: Command, fds: &[i32]) -> Vec<(i32, bool)> {
        let list = fds
            .iter()
            .map(|fd| fd.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let output = command
            .arg("-c")
            .arg(format!(
                "for fd in {list}; do if [ -e /dev/fd/$fd ]; then echo $fd open; else echo $fd closed; fi; done"
            ))
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn sh");
        assert!(output.status.success(), "sh failed: {output:?}");
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| {
                let (fd, state) = line.split_once(' ').unwrap();
                (fd.parse().unwrap(), state == "open")
            })
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn close_inherited_fds_keeps_caller_descriptors_out_of_the_child() {
        use std::os::fd::AsRawFd;
        let leaked = open_inheritable_fd();
        let fd = leaked.as_raw_fd();

        // Control: without the helper the descriptor does cross the exec, so
        // the assertion below is not vacuous.
        let plain = fds_open_in_child(Command::new("sh"), &[fd]);
        assert_eq!(plain, vec![(fd, true)], "test fd must be inheritable");

        let mut command = Command::new("sh");
        close_inherited_fds(&mut command);
        let seen = fds_open_in_child(command, &[0, 1, 2, fd]);
        assert_eq!(
            seen,
            vec![(0, true), (1, true), (2, true), (fd, false)],
            "launched child must keep stdio and drop the caller's fd {fd}"
        );
        // The helper acts in the child only; the caller keeps its descriptor.
        // SAFETY: F_GETFD on a descriptor this test owns.
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn close_inherited_fds_still_reports_exec_failure() {
        // Command reports a failed exec through a CLOEXEC pipe >= 3; closing
        // it in pre_exec would turn a missing binary into a spawned child.
        let mut command = Command::new("/nonexistent/hcom-close-inherited-fds");
        close_inherited_fds(&mut command);
        let err = command
            .spawn()
            .expect_err("exec of a missing binary must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    // Reproduces the bug fixed above: the process object stays valid (and
    // OpenProcess succeeds) as long as any handle is open, even after the
    // process has exited. Holding `child` past `wait()` keeps its handle
    // open while we probe the same PID with our own OpenProcess call.
    #[cfg(windows)]
    #[test]
    fn test_is_alive_false_for_exited_process_with_handle_still_open() {
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert!(
            !is_alive(pid),
            "an open handle to an already-exited process must not count as alive"
        );
        drop(child);
    }

    /// A child that stays alive until something kills it, so tests that kill it
    /// are testing the kill rather than racing the child's own exit.
    ///
    /// Not `timeout`: it refuses to run at all when stdin is redirected ("ERROR:
    /// Input redirection is not supported"), which is how every test harness
    /// runs it, and then exits within milliseconds. `ping` reads no input. All
    /// three stdio handles are detached so nothing the child prints lands in the
    /// test output and nothing it does depends on how the harness was invoked.
    #[cfg(windows)]
    fn spawn_long_lived_child() -> std::process::Child {
        std::process::Command::new("cmd")
            .args(["/C", "ping -n 31 127.0.0.1"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    // Reproduces the bug fixed above: kill_tree_win's terminate_win writes the
    // hcom-kill sentinel exit code 130. A trailing child.kill() (a second,
    // competing TerminateProcess on the same PID) could overwrite it before
    // the OS settles on a final exit code.
    #[cfg(windows)]
    #[test]
    fn test_kill_child_group_preserves_sentinel_exit_code() {
        let mut child = spawn_long_lived_child();
        kill_child_group(&mut child);
        let status = child.wait().unwrap();
        assert_eq!(
            status.code(),
            Some(130),
            "kill_child_group must not let a second kill overwrite the hcom-kill sentinel"
        );
    }

    #[cfg(windows)]
    #[test]
    fn child_link_plausibility_rejects_candidates_older_than_their_claimed_parent() {
        assert!(
            !child_link_is_plausible(Some(500), Some(499)),
            "a process created before its claimed parent cannot be its child"
        );
        assert!(child_link_is_plausible(Some(500), Some(500)));
        assert!(child_link_is_plausible(Some(500), Some(501)));
        // Unqueryable on either side: nothing to disprove, so the link stands
        // and the walk behaves as it did before the check existed.
        assert!(child_link_is_plausible(None, Some(1)));
        assert!(child_link_is_plausible(Some(500), None));
    }

    // The case that matters in practice, against real `GetProcessTimes` data: a
    // stale parent link pointing at a freshly spawned PID would otherwise offer
    // up long-lived bystanders — here the test runner itself — as descendants
    // to terminate.
    #[cfg(windows)]
    #[test]
    fn a_fresh_child_never_adopts_a_process_that_predates_it() {
        let mut child = spawn_long_lived_child();
        let claimed_parent = creation_ticks_win(child.id());
        let bystander = creation_ticks_win(std::process::id());
        kill_child_group(&mut child);
        let _ = child.wait();

        assert!(claimed_parent.is_some(), "spawned child must be queryable");
        assert!(bystander.is_some(), "our own process must be queryable");
        assert!(
            !child_link_is_plausible(claimed_parent, bystander),
            "a process that predates the PID claiming it must not join the kill tree"
        );
    }

    /// SIGNAL-target test, not a survival claim (on Windows the shared broker
    /// still ends with its launching seat's job, hcom#108): with the broker
    /// marked ineligible, the verified tree walk never targets it or its
    /// child, and still terminates the rest of the tree.
    #[cfg(windows)]
    #[test]
    fn verified_windows_tree_never_targets_an_ineligible_broker_subtree() {
        use std::time::{Duration, Instant};
        // The broker stand-in and its child exit on their own (~11s), so this
        // test never signals a process it did not spawn itself.
        let mut root = Command::new("cmd")
            .args([
                "/D",
                "/C",
                "start /B cmd /D /C ping -n 12 127.0.0.2 >NUL & start /B ping -n 60 127.0.0.3 >NUL & ping -n 60 127.0.0.1 >NUL",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let root_pid = root.id();
        let carries = |pid: u32, needle: &[u8]| {
            crate::sys::process_args::command_line(pid)
                .is_some_and(|argv| argv.windows(needle.len()).any(|part| part == needle))
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        let (broker, broker_child, normal) = loop {
            let snapshot = snapshot_parents(false).expect("process snapshot");
            let children = |parent: u32| {
                snapshot
                    .iter()
                    .filter(|(_, entry)| entry.parent_pid == parent)
                    .map(|(&pid, _)| pid)
                    .collect::<Vec<_>>()
            };
            let below_root = children(root_pid);
            let broker = below_root
                .iter()
                .copied()
                .find(|&pid| carries(pid, b"127.0.0.2"));
            let normal = below_root
                .iter()
                .copied()
                .find(|&pid| carries(pid, b"127.0.0.3"));
            if let (Some(broker), Some(normal)) = (broker, normal)
                && let Some(&child) = children(broker).first()
            {
                break (broker, child, normal);
            }
            assert!(Instant::now() < deadline, "fixture tree never formed");
            std::thread::sleep(Duration::from_millis(50));
        };
        let broker_ticks = creation_ticks_win(broker).expect("broker creation time");
        let child_ticks = creation_ticks_win(broker_child).expect("broker child creation time");
        let root_ticks = creation_ticks_win(root_pid).expect("root creation time");

        let mut captured = Vec::new();
        let mut authorized = Vec::new();
        let outcome = kill_tree_win_with_identity(
            root_pid,
            Some(root_ticks),
            &mut captured,
            &[],
            &mut |pid| pid != broker,
            &mut |pid| {
                authorized.push(pid);
                Ok(())
            },
        );
        let broker_untouched = creation_ticks_win(broker) == Some(broker_ticks);
        let child_untouched = creation_ticks_win(broker_child) == Some(child_ticks);
        let _ = root.wait();

        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(
            broker_untouched && child_untouched,
            "the broker subtree was terminated"
        );
        for pid in [broker, broker_child] {
            assert!(!authorized.contains(&pid), "PID {pid} was a signal target");
            assert!(
                !captured.iter().any(|&(captured, _)| captured == pid),
                "PID {pid} was captured"
            );
        }
        assert!(
            authorized.contains(&normal),
            "the rest of the tree was not targeted"
        );
        let gone = Instant::now() + Duration::from_secs(5);
        while !is_definitely_dead(normal) {
            assert!(Instant::now() < gone, "the non-broker child survived");
            std::thread::sleep(Duration::from_millis(50));
        }
        // Let the broker stand-in finish by itself rather than signal it.
        let settled = Instant::now() + Duration::from_secs(30);
        while !(is_definitely_dead(broker) && is_definitely_dead(broker_child)) {
            assert!(Instant::now() < settled, "the broker stand-in never exited");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
