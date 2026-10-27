//! Kernel command-line reads used for process-owner authentication.
//!
//! Successful reads contain only NUL-delimited argv with a terminal NUL, never
//! the process environment. Unreadable, malformed, or oversized data is unknown.

#[cfg(any(target_os = "macos", test))]
mod apple;
#[cfg(windows)]
mod windows;

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
