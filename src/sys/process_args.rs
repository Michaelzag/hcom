//! Native command-line and environment reads for process-owner authentication.
//!
//! Command-line reads expose only counted argv, never the environment.
//! Environment reads distinguish an absent key from unreadable process data.

#[cfg(any(target_os = "macos", test))]
mod apple;
#[cfg(any(windows, test))]
mod windows;

/// A native environment read never treats an unverifiable block as absence.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EnvRead {
    Present(String),
    Absent,
    Unreadable,
}

/// Read one variable from a process using the native environment layout.
///
/// Linux callers use `/proc` separately; unsupported platforms fail closed.
pub(crate) fn read_process_env_var(pid: u32, key: &str) -> EnvRead {
    #[cfg(target_os = "macos")]
    {
        apple::read_env_var(pid, key)
    }
    #[cfg(windows)]
    {
        windows::read_env_var(pid, key)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (pid, key);
        EnvRead::Unreadable
    }
}

/// Read at most 1 MiB of exact argv bytes from the native process API.
#[cfg(any(target_os = "macos", windows))]
pub(crate) fn command_line(pid: u32) -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        apple::read(pid)
    }
    #[cfg(windows)]
    {
        windows::read(pid)
    }
}

#[cfg(all(test, not(any(target_os = "macos", windows))))]
#[test]
fn unsupported_environment_reader_fails_closed_for_live_and_missing_processes() {
    for pid in [std::process::id(), u32::MAX] {
        assert_eq!(read_process_env_var(pid, "HCOM_PROCESS_ID"), EnvRead::Unreadable);
    }
}
