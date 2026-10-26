//! Native command-line and environment reads for process-owner authentication.
//!
//! Command-line reads expose only NUL-delimited argv, never the environment.
//! Environment reads distinguish an absent key from unreadable process data.

#[cfg(any(target_os = "macos", test))]
mod apple;
#[cfg(any(windows, test))]
mod windows;

#[cfg(any(target_os = "linux", target_os = "android", test))]
const MAX_PROC_CMDLINE_BYTES: usize = 1024 * 1024;

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
///
/// Empty, unreadable, malformed or oversized command lines return `None`.
pub(crate) fn command_line(pid: u32) -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        apple::read(pid)
    }
    #[cfg(windows)]
    {
        windows::read(pid)
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let file = std::fs::File::open(format!("/proc/{pid}/cmdline")).ok()?;
        let mut reader = std::io::Read::take(file, (MAX_PROC_CMDLINE_BYTES + 1) as u64);
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut buffer).ok()?;
        parse_proc_cmdline(&buffer)?;
        Some(buffer)
    }
    #[cfg(not(any(
        target_os = "macos",
        windows,
        target_os = "linux",
        target_os = "android"
    )))]
    {
        let _ = pid;
        None
    }
}

/// `/proc` already supplies argv framing; keep its exact bytes after checking
/// the bound and final NUL. Empty cmdlines cannot identify a process wrapper.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_proc_cmdline(buffer: &[u8]) -> Option<&[u8]> {
    (!buffer.is_empty() && buffer.len() <= MAX_PROC_CMDLINE_BYTES && buffer.last() == Some(&0))
        .then_some(buffer)
}

#[cfg(test)]
mod proc_cmdline_tests {
    use super::*;

    #[test]
    fn rejects_empty_kernel_thread_or_zombie_cmdlines_and_missing_nuls() {
        for bytes in [b"".as_slice(), b"node", b"node\0script.js"] {
            assert_eq!(parse_proc_cmdline(bytes), None);
        }
    }

    #[test]
    fn keeps_terminated_argv_with_empty_arguments_and_non_utf8_bytes() {
        let bytes = b"node\0\0script with spaces\0\xff\0\0";
        let argv = parse_proc_cmdline(bytes)
            .expect("valid kernel argv")
            .strip_suffix(&[0])
            .expect("one terminal NUL")
            .split(|byte| *byte == 0)
            .collect::<Vec<_>>();
        assert_eq!(
            argv,
            [b"node".as_slice(), b"", b"script with spaces", b"\xff", b""]
        );
    }

    #[test]
    fn accepts_the_cap_and_rejects_one_byte_over_it() {
        let mut bytes = vec![b'x'; MAX_PROC_CMDLINE_BYTES];
        bytes[MAX_PROC_CMDLINE_BYTES - 1] = 0;
        assert!(parse_proc_cmdline(&bytes).is_some());
        bytes.push(0);
        assert_eq!(parse_proc_cmdline(&bytes), None);
    }
}

#[cfg(all(test, not(any(target_os = "macos", windows))))]
#[test]
fn unsupported_environment_reader_fails_closed_for_live_and_missing_processes() {
    for pid in [std::process::id(), u32::MAX] {
        assert_eq!(
            read_process_env_var(pid, "HCOM_PROCESS_ID"),
            EnvRead::Unreadable
        );
    }
}
