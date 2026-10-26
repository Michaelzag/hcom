//! Read-only macOS argv and environment discovery through `KERN_PROCARGS2`.
//!
//! LP64 Darwin returns a native-endian `int` argc, an executable path with
//! eight-byte alignment padding, then argc NUL-terminated arguments followed
//! by the environment. Both readers share the counted argv boundary.

use super::EnvRead;

const MAX_ARGS_BYTES: usize = 1024 * 1024;
const MAX_ENV_VALUE_BYTES: usize = 256;
const ARGC_BYTES: usize = std::mem::size_of::<i32>();
const LP64_ALIGNMENT: usize = 8;

// XNU xnu-11215.81.4, bsd/sys/proc_info.h:104.
#[cfg(target_os = "macos")]
const PROC_FLAG_LP64: u32 = 0x10;

#[cfg(target_os = "macos")]
pub(super) fn read(pid: u32) -> Option<Vec<u8>> {
    parse(read_buffer(pid)?)
}

#[cfg(target_os = "macos")]
pub(super) fn read_env_var(pid: u32, key: &str) -> EnvRead {
    match read_buffer(pid) {
        Some(buffer) => parse_env(&buffer, key),
        None => EnvRead::Unreadable,
    }
}

#[cfg(target_os = "macos")]
fn read_buffer(pid: u32) -> Option<Vec<u8>> {
    let native_pid = libc::c_int::try_from(pid).ok().filter(|pid| *pid > 0)?;
    let info = crate::sys::process::process_info_apple(pid)?;
    if info.pbi_flags & PROC_FLAG_LP64 == 0 {
        return None;
    }
    let capacity = argument_capacity()?;
    let mut buffer = Vec::<u8>::new();
    buffer.try_reserve_exact(capacity).ok()?;
    let mut length = capacity;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, native_pid];
    // SAFETY: the MIB is a valid read-only process-argument query. `buffer`
    // has capacity for `length` bytes, and sysctl reports the initialized byte
    // count through `length`. No bytes are exposed before that count is checked.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    // An undersized KERN_PROCARGS2 query can succeed with a tail slice and a
    // saturated length. Equality cannot prove that the reply starts at its
    // executable path, so reject it before interpreting any returned bytes.
    if result != 0 || length >= capacity {
        return None;
    }
    // SAFETY: a successful sysctl initialized exactly the checked byte count.
    unsafe { buffer.set_len(length) };
    Some(buffer)
}

#[cfg(target_os = "macos")]
fn argument_capacity() -> Option<usize> {
    // KERN_ARGMAX supplies Darwin's capacity for KERN_PROCARGS2. Cache only a
    // successfully queried runtime limit, never process facts. OnceLock avoids
    // memoizing a transient syscall failure as LazyLock<Option<_>> would.
    static ARG_MAX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    if let Some(capacity) = ARG_MAX.get() {
        return Some(*capacity);
    }
    let mut arg_max: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&arg_max);
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: sysctl writes at most one c_int into `arg_max`; both the MIB and
    // the writable size pointer remain valid for the call. Null newp is read-only.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            (&mut arg_max as *mut libc::c_int).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || length != std::mem::size_of_val(&arg_max) {
        return None;
    }
    let capacity = usize::try_from(arg_max).ok()?;
    if capacity <= ARGC_BYTES || capacity > MAX_ARGS_BYTES {
        return None;
    }
    let _ = ARG_MAX.set(capacity);
    Some(capacity)
}

fn argv_range(buffer: &[u8]) -> Option<std::ops::Range<usize>> {
    if buffer.len() > MAX_ARGS_BYTES {
        return None;
    }
    let argc = i32::from_ne_bytes(buffer.get(..ARGC_BYTES)?.try_into().ok()?);
    let argc = usize::try_from(argc).ok().filter(|argc| *argc > 0)?;
    let executable_length = buffer
        .get(ARGC_BYTES..)?
        .iter()
        .position(|byte| *byte == 0)?;
    if executable_length == 0 {
        return None;
    }
    let path_bytes = executable_length.checked_add(1)?;
    let after_executable = ARGC_BYTES.checked_add(path_bytes)?;
    // XNU xnu-11215.81.4 kern_exec.c:520-536,5876-5885 stores the 16-byte
    // executable_path= prefix plus path, pads to the target pointer width,
    // then starts argv. kern_sysctl.c:1423-1424,1597-1600 strips that prefix
    // and prepends argc. With the target verified LP64, the boundary is
    // sizeof(argc) + align_up(path_bytes, 8), not the next nonzero byte.
    let aligned_path = path_bytes.checked_add(LP64_ALIGNMENT - 1)? & !(LP64_ALIGNMENT - 1);
    let start = ARGC_BYTES.checked_add(aligned_path)?;
    if buffer
        .get(after_executable..start)?
        .iter()
        .any(|byte| *byte != 0)
        || *buffer.get(start)? == 0
    {
        return None;
    }
    // Even an empty argument needs its own NUL. Reject impossible counts before
    // walking them, and require a terminator for every counted argument.
    if argc > buffer.len().checked_sub(start)? {
        return None;
    }
    let mut end = start;
    for _ in 0..argc {
        let length = buffer.get(end..)?.iter().position(|byte| *byte == 0)?;
        end = end.checked_add(length)?.checked_add(1)?;
    }
    Some(start..end)
}

fn parse(mut buffer: Vec<u8>) -> Option<Vec<u8>> {
    let std::ops::Range { start, end } = argv_range(&buffer)?;
    // Compact in place instead of allocating/copying into a second argv Vec.
    // Truncation discards the header, padding and the entire unexamined env tail.
    buffer.copy_within(start..end, 0);
    buffer.truncate(end.checked_sub(start)?);
    Some(buffer)
}

/// Find only the requested key; the tail is not exclusively environment data.
fn parse_env(buffer: &[u8], key: &str) -> EnvRead {
    let Some(argv) = argv_range(buffer) else {
        return EnvRead::Unreadable;
    };
    let mut remaining = &buffer[argv.end..];
    if remaining.is_empty() {
        return EnvRead::Unreadable;
    }
    // XNU xnu-11215.81.4 kern_exec.c:6074-6086 aligns envv before applev,
    // possibly without any NUL padding. Applev uses kernel-defined keys
    // (6104-6164; formatted at 6240-6246,6276-6295,6309-6316), none of which
    // is HCOM_PROCESS_ID. Env precedes applev, so its first exact match wins.
    // Do not decode unrelated applev strings or scan past an empty separator.
    while !remaining.is_empty() {
        let terminator = remaining.iter().position(|byte| *byte == 0);
        let entry = &remaining[..terminator.unwrap_or(remaining.len())];
        if entry.is_empty() {
            break;
        }
        if let Some(value) = entry
            .strip_prefix(key.as_bytes())
            .and_then(|suffix| suffix.strip_prefix(b"="))
        {
            if terminator.is_none() || value.len() > MAX_ENV_VALUE_BYTES {
                return EnvRead::Unreadable;
            }
            return match std::str::from_utf8(value) {
                Ok(value) => EnvRead::Present(value.to_owned()),
                Err(_) => EnvRead::Unreadable,
            };
        }
        let Some(terminator) = terminator else {
            break;
        };
        remaining = &remaining[terminator + 1..];
    }
    EnvRead::Absent
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_buffer(argc: i32, body: &[u8]) -> Vec<u8> {
        let mut buffer = argc.to_ne_bytes().to_vec();
        buffer.extend_from_slice(body);
        buffer
    }

    #[test]
    fn parser_extracts_counted_argv_without_environment() {
        let buffer = native_buffer(
            3,
            b"/usr/local/bin/node\0\0\0\0\0node\0/fixture path/@oh-my-pi/pi-coding-agent/dist/cli.js\0prompt with spaces\0ENV_FIXTURE=not-an-argument\0\xffunterminated-env",
        );
        assert_eq!(
            parse(buffer),
            Some(
                b"node\0/fixture path/@oh-my-pi/pi-coding-agent/dist/cli.js\0prompt with spaces\0"
                    .to_vec()
            )
        );
    }

    #[test]
    fn parser_accepts_no_extra_padding_and_exact_argument_boundary() {
        assert_eq!(
            parse(native_buffer(2, b"/bin/sh\0sh\0omp\0")),
            Some(b"sh\0omp\0".to_vec())
        );
    }

    #[test]
    fn parser_keeps_empty_arguments_and_non_utf8_bytes() {
        assert_eq!(
            parse(native_buffer(
                4,
                b"/bin/node\0\0\0\0\0\0\0node\0\0\xff\0\0ENV=fixture\0"
            )),
            Some(b"node\0\0\xff\0\0".to_vec())
        );
    }

    #[test]
    fn parser_preserves_spaces_and_unicode() {
        assert_eq!(
            parse(native_buffer(
                2,
                "/bin/node\0\0\0\0\0\0\0node\0/fixture path/雪 λ.js\0".as_bytes()
            )),
            Some("node\0/fixture path/雪 λ.js\0".as_bytes().to_vec())
        );
    }

    #[test]
    fn parser_uses_exact_lp64_padding_for_every_path_residue() {
        // Expected padding comes from XNU's LP64 string-area layout, including
        // the path's own NUL, rather than the parser's alignment expression.
        for (path_length, padding_length) in [
            (1, 6),
            (2, 5),
            (3, 4),
            (4, 3),
            (5, 2),
            (6, 1),
            (7, 0),
            (8, 7),
        ] {
            let mut body = vec![b'x'; path_length];
            body.resize(path_length + 1 + padding_length, 0);
            body.extend_from_slice(b"node\0script.js\0ENV_FIXTURE=not-an-argument\0");
            assert_eq!(
                parse(native_buffer(2, &body)),
                Some(b"node\0script.js\0".to_vec()),
                "executable path length {path_length}"
            );
        }
    }

    #[test]
    fn parser_rejects_nonzero_or_truncated_alignment_padding() {
        assert!(parse(native_buffer(1, b"/bin/node\0BADPADnode\0")).is_none());
        assert!(parse(native_buffer(1, b"/bin/node\0\0\0")).is_none());
    }

    #[test]
    fn parser_rejects_empty_argv0_before_omp_like_environment() {
        assert!(parse(native_buffer(1, b"/bin/sh\0\0omp\0ENV_FIXTURE=value\0")).is_none());
        assert!(
            parse(native_buffer(
                2,
                b"/bin/sh\0\0script.js\0omp\0ENV_FIXTURE=value\0"
            ))
            .is_none()
        );
    }

    #[test]
    fn parser_rejects_empty_or_truncated_argc() {
        let header = 1_i32.to_ne_bytes();
        for length in 0..ARGC_BYTES {
            assert!(parse(header[..length].to_vec()).is_none());
        }
    }

    #[test]
    fn parser_rejects_nonpositive_or_unreasonable_argc() {
        for argc in [0, -1, i32::MIN, i32::MAX, 8] {
            assert!(parse(native_buffer(argc, b"/bin/node\0\0\0\0\0\0\0node\0")).is_none());
        }
    }

    #[test]
    fn parser_rejects_missing_or_empty_executable_path() {
        for body in [b"/bin/node".as_slice(), b"\0node\0", b"/bin/node\0\0\0"] {
            assert!(parse(native_buffer(1, body)).is_none());
        }
    }

    #[test]
    fn parser_rejects_unterminated_or_missing_counted_arguments() {
        for (argc, body) in [
            (1, b"/bin/node\0\0\0\0\0\0\0node".as_slice()),
            (2, b"/bin/node\0\0\0\0\0\0\0node\0script-without-nul"),
            (3, b"/bin/node\0\0\0\0\0\0\0node\0script\0"),
        ] {
            assert!(parse(native_buffer(argc, body)).is_none());
        }
    }

    #[test]
    fn parser_rejects_oversize_even_when_argv_is_short() {
        let mut buffer = native_buffer(1, b"/bin/node\0\0\0\0\0\0\0node\0");
        buffer.resize(MAX_ARGS_BYTES + 1, 0);
        assert!(parse(buffer).is_none());
    }

    #[test]
    fn parser_accepts_capacity_limit_without_exposing_env_padding() {
        let mut buffer = native_buffer(1, b"/bin/node\0\0\0\0\0\0\0node\0ENV=fixture\0");
        buffer.resize(MAX_ARGS_BYTES, 0);
        assert_eq!(parse(buffer), Some(b"node\0".to_vec()));
    }

    #[test]
    fn environment_parser_matches_exact_keys_and_keeps_first_value() {
        let buffer = native_buffer(
            2,
            b"/bin/sh\0sh\0HCOM_PROCESS_ID=argv-is-not-env\0HCOM_PROCESS_ID_X=prefix\0hcom_process_id=lowercase\0HCOM_PROCESS_ID=owner=with=equals\0HCOM_PROCESS_ID=later\0\0",
        );
        assert_eq!(
            parse_env(&buffer, "HCOM_PROCESS_ID"),
            EnvRead::Present("owner=with=equals".into())
        );
        assert_eq!(parse_env(&buffer, "MISSING"), EnvRead::Absent);
        assert_eq!(
            parse_env(&buffer, "hcom_process_id"),
            EnvRead::Present("lowercase".into())
        );
    }

    #[test]
    fn environment_parser_handles_apple_strings_with_or_without_a_separator() {
        // XNU may need no alignment padding between envv and applev.
        const APPLE_STRINGS: &[u8] =
            b"pfz=0xffff\0stack_guard=\0\xff\xfe\0malloc_entropy=\xff\xf0\0ptr_munge=0x1234\0main_stack=0x1000\0\0\0";
        for separator in [b"".as_slice(), b"\0"] {
            // The strings before applev occupy exactly 64 bytes after argc.
            let mut buffer = native_buffer(
                2,
                b"/bin/node\0\0\0\0\0\0\0node\0script.js\0HCOM_PROCESS_ID=owner\0OTHER=abcd\0",
            );
            buffer.extend_from_slice(separator);
            buffer.extend_from_slice(APPLE_STRINGS);
            assert_eq!(
                parse_env(&buffer, "HCOM_PROCESS_ID"),
                EnvRead::Present("owner".into())
            );

            let mut buffer = native_buffer(
                2,
                b"/bin/node\0\0\0\0\0\0\0node\0script.js\0HCOM_PROCESS_ID_X=owner\0OTHER=ab\0",
            );
            buffer.extend_from_slice(separator);
            buffer.extend_from_slice(APPLE_STRINGS);
            assert_eq!(parse_env(&buffer, "HCOM_PROCESS_ID"), EnvRead::Absent);
        }
    }

    #[test]
    fn environment_parser_does_not_scan_past_an_empty_string() {
        let buffer = native_buffer(
            1,
            b"/bin/sh\0sh\0OTHER=value\0\0HCOM_PROCESS_ID=not-an-env-entry\0\xff\0\0",
        );
        assert_eq!(parse_env(&buffer, "HCOM_PROCESS_ID"), EnvRead::Absent);
    }

    #[test]
    fn environment_parser_accepts_empty_value_and_empty_environment() {
        let buffer = native_buffer(1, b"/bin/sh\0sh\0HCOM_PROCESS_ID=\0");
        assert_eq!(
            parse_env(&buffer, "HCOM_PROCESS_ID"),
            EnvRead::Present(String::new())
        );
        assert_eq!(
            parse_env(&native_buffer(1, b"/bin/sh\0sh\0\0"), "HCOM_PROCESS_ID"),
            EnvRead::Absent
        );
    }

    #[test]
    fn environment_parser_does_not_match_a_prefix_or_case_variant() {
        let buffer = native_buffer(
            1,
            b"/bin/sh\0sh\0HCOM_PROCESS_ID_X=prefix\0hcom_process_id=lowercase\0",
        );
        assert_eq!(parse_env(&buffer, "HCOM_PROCESS_ID"), EnvRead::Absent);
    }

    #[test]
    fn environment_parser_rejects_truncated_or_invalid_matching_entries() {
        for body in [
            b"/bin/sh\0sh\0HCOM_PROCESS_ID=trunc".as_slice(),
            b"/bin/sh\0sh\0HCOM_PROCESS_ID=\xff\0",
            b"/bin/sh\0sh\0",
        ] {
            assert_eq!(
                parse_env(&native_buffer(1, body), "HCOM_PROCESS_ID"),
                EnvRead::Unreadable
            );
        }
    }

    #[test]
    fn environment_parser_skips_unrelated_non_utf8_and_non_environment_strings() {
        let buffer = native_buffer(
            1,
            b"/bin/sh\0sh\0\xff\0not-an-assignment\0HCOM_PROCESS_ID=owner\0",
        );
        assert_eq!(
            parse_env(&buffer, "HCOM_PROCESS_ID"),
            EnvRead::Present("owner".into())
        );
        for tail in [
            b"TAIL=missing-nul".as_slice(),
            b"TAIL=\xff\0",
            b"\0TAIL=after-end\0",
        ] {
            let mut buffer = native_buffer(1, b"/bin/sh\0sh\0HCOM_PROCESS_ID=owner\0");
            buffer.extend_from_slice(tail);
            assert_eq!(
                parse_env(&buffer, "HCOM_PROCESS_ID"),
                EnvRead::Present("owner".into())
            );
        }
        assert_eq!(
            parse_env(
                &native_buffer(1, b"/bin/sh\0sh\0not-an-assignment\0\xff"),
                "HCOM_PROCESS_ID"
            ),
            EnvRead::Absent
        );
    }

    #[test]
    fn environment_parser_bounds_the_matching_value_in_bytes() {
        for (value, expected) in [
            ("x".repeat(MAX_ENV_VALUE_BYTES), true),
            ("x".repeat(MAX_ENV_VALUE_BYTES + 1), false),
            ("雪".repeat(MAX_ENV_VALUE_BYTES / 3 + 1), false),
        ] {
            let mut buffer = native_buffer(1, b"/bin/sh\0sh\0HCOM_PROCESS_ID=");
            buffer.extend_from_slice(value.as_bytes());
            buffer.push(0);
            let actual = parse_env(&buffer, "HCOM_PROCESS_ID");
            if expected {
                assert_eq!(actual, EnvRead::Present(value));
            } else {
                assert_eq!(actual, EnvRead::Unreadable);
            }
        }
    }

    #[test]
    fn environment_parser_rejects_oversize_and_impossible_argument_count() {
        let mut buffer = native_buffer(1, b"/bin/sh\0sh\0HCOM_PROCESS_ID=owner\0");
        buffer.resize(MAX_ARGS_BYTES + 1, 0);
        assert_eq!(parse_env(&buffer, "HCOM_PROCESS_ID"), EnvRead::Unreadable);
        assert_eq!(
            parse_env(
                &native_buffer(i32::MAX, b"/bin/sh\0sh\0HCOM_PROCESS_ID=owner\0"),
                "HCOM_PROCESS_ID"
            ),
            EnvRead::Unreadable
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_read_own_child_keeps_spaces_unicode_and_empty_arguments() {
        use std::process::{Child, Command, Stdio};

        struct OwnedChild(Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let root = tempfile::tempdir().expect("create isolated argv fixture");
        for directory in [
            "home",
            "hcom",
            "tmp",
            "xdg/config",
            "xdg/cache",
            "xdg/data",
            "xdg/state",
            "xdg/runtime",
            "xdg/config-dirs",
            "xdg/data-dirs",
        ] {
            std::fs::create_dir_all(root.path().join(directory)).expect("create fixture directory");
        }
        std::fs::write(
            root.path().join("hcom/config.toml"),
            "[relay]\nenabled = false\n",
        )
        .expect("disable fixture relay");
        let arguments = [
            "-c",
            "IFS= read -r fixture",
            "fixture with spaces",
            "雪 λ",
            "",
        ];
        // Only a shell builtin runs; the open stdin pipe keeps this owned child
        // alive without descendants, production state or any external service.
        let child = OwnedChild(
            Command::new("/bin/sh")
                .args(arguments)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", root.path().join("home"))
                .env("HCOM_DIR", root.path().join("hcom"))
                .env("TMPDIR", root.path().join("tmp"))
                .env("XDG_CONFIG_HOME", root.path().join("xdg/config"))
                .env("XDG_CACHE_HOME", root.path().join("xdg/cache"))
                .env("XDG_DATA_HOME", root.path().join("xdg/data"))
                .env("XDG_STATE_HOME", root.path().join("xdg/state"))
                .env("XDG_RUNTIME_DIR", root.path().join("xdg/runtime"))
                .env("XDG_CONFIG_DIRS", root.path().join("xdg/config-dirs"))
                .env("XDG_DATA_DIRS", root.path().join("xdg/data-dirs"))
                .env("HCOM_ARGV_FIXTURE_ENV", "must-not-be-an-argument")
                .current_dir(root.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn isolated argv fixture"),
        );
        let actual = read(child.0.id());
        drop(child);
        let mut expected = b"/bin/sh\0".to_vec();
        for argument in arguments {
            expected.extend_from_slice(argument.as_bytes());
            expected.push(0);
        }
        assert_eq!(actual, Some(expected));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_read_own_child_environment_handles_every_tail_alignment() {
        use std::process::{Command, Stdio};

        let root = tempfile::tempdir().expect("create isolated environment fixture");
        for padding in 0..LP64_ALIGNMENT {
            let mut child = Command::new("/bin/sh")
                .args(["-c", "IFS= read -r fixture"])
                .env_clear()
                .env("HOME", root.path())
                .env("TMPDIR", root.path())
                .env("HCOM_PROCESS_ID", "native-bound-process")
                .env("HCOM_TEST_EMPTY", "")
                .env("HCOM_ENV_PADDING", "x".repeat(padding))
                .current_dir(root.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn isolated environment fixture");
            let present = read_env_var(child.id(), "HCOM_PROCESS_ID");
            let empty = read_env_var(child.id(), "HCOM_TEST_EMPTY");
            let absent = read_env_var(child.id(), "hcom_process_id");
            let _ = child.kill();
            let _ = child.wait();
            assert_eq!(
                present,
                EnvRead::Present("native-bound-process".into()),
                "environment padding {padding}"
            );
            assert_eq!(empty, EnvRead::Present(String::new()));
            assert_eq!(absent, EnvRead::Absent);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_read_invalid_or_absent_pid_fails_closed() {
        assert!(read(0).is_none());
        assert!(read(u32::MAX).is_none());
        assert!(read(i32::MAX as u32).is_none());
    }
}
