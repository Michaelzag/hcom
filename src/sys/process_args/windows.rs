//! Native argv of another Windows process.
//!
//! `NtQueryInformationProcess(ProcessCommandLineInformation)` (Windows 8.1+)
//! has the kernel copy the target's command line into a caller buffer as a
//! `UNICODE_STRING` header followed by the text. It needs only
//! `PROCESS_QUERY_LIMITED_INFORMATION`: no PEB walk, no `ReadProcessMemory`.
//! `CommandLineToArgvW` then splits that text with the OS quoting rules, the
//! ones the MSVC CRT and Rust's std `Command` use, so argv matches what the
//! process itself parsed.

use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, LocalFree, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
    STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;
use windows_sys::core::PWSTR;

/// Cap on both the kernel query buffer and the returned argv bytes.
const MAX_BYTES: usize = 1 << 20;
const HEADER: usize = size_of::<UNICODE_STRING>();

/// NUL-delimited UTF-8 argv of `pid`, one NUL after every argument, or `None`
/// when the process can't be opened or queried, or the reply is malformed or
/// over [`MAX_BYTES`]. Unpaired UTF-16 surrogates become U+FFFD.
pub(super) fn read(pid: u32) -> Option<Vec<u8>> {
    let (buf, written) = query_command_line(&Process::open(pid)?)?;
    argv_from(&buf, written)
}

/// Query handle closed on drop.
struct Process(HANDLE);

impl Process {
    fn open(pid: u32) -> Option<Self> {
        // SAFETY: plain FFI call with a query-only access mask; a null
        // result means no handle was opened.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        // Lazy: a guard built from NULL would CloseHandle(NULL) on drop.
        (!handle.is_null()).then(|| Process(handle))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: `open` wraps only a non-null OpenProcess handle, and it is
        // closed exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// `CommandLineToArgvW` block released with `LocalFree` on drop.
struct LocalArgv(*mut PWSTR);

impl Drop for LocalArgv {
    fn drop(&mut self) {
        // SAFETY: the pointer came from CommandLineToArgvW, which documents
        // LocalFree as its release, and is freed exactly once.
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

/// Two-phase kernel query: size probe, then one read into an 8-aligned,
/// zero-initialized buffer of exactly that size. A command line that grew
/// between the calls fails the second call and yields `None`.
fn query_command_line(process: &Process) -> Option<(Vec<u64>, usize)> {
    let mut needed = 0u32;
    // SAFETY: zero-length probe with a null buffer; the kernel writes only
    // the u32 `needed`.
    let status = unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if !matches!(
        status,
        STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_TOO_SMALL | STATUS_BUFFER_OVERFLOW
    ) {
        return None;
    }
    let needed_bytes = needed as usize;
    if !(HEADER..=MAX_BYTES).contains(&needed_bytes) {
        return None;
    }
    let words = needed_bytes.div_ceil(size_of::<u64>());
    let mut buf = Vec::new();
    buf.try_reserve_exact(words).ok()?;
    buf.resize(words, 0u64);
    let mut written = 0u32;
    // SAFETY: `buf` is a writable allocation of at least `needed` bytes,
    // aligned for UNICODE_STRING (u64 alignment), and outlives the call.
    let status = unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessCommandLineInformation,
            buf.as_mut_ptr().cast(),
            needed,
            &mut written,
        )
    };
    if status < 0 {
        return None;
    }
    let written = written as usize;
    (written <= needed_bytes).then_some((buf, written))
}

/// The query buffer as UTF-16 units, so the command line is reached by
/// bounds-checked indexing rather than through the header's raw pointer.
fn units(buf: &[u64]) -> &[u16] {
    // SAFETY: the u64 storage is initialized, at least u16-aligned, every bit
    // pattern is a valid u16, and the length covers exactly the same bytes
    // for the borrow's lifetime.
    unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u16>(), buf.len() * 4) }
}

/// Validated location of the command line inside the query buffer.
#[derive(Debug, PartialEq)]
struct CommandLine {
    /// Text range in UTF-16 units of [`units`], NUL excluded.
    text: std::ops::Range<usize>,
    /// The unit at `text.end` is a NUL inside the kernel-written bytes.
    terminated: bool,
}

/// Check the `UNICODE_STRING` the kernel wrote at the start of `buf` and
/// locate its text. `written` is the byte count the kernel reported. The
/// header's `Buffer` must point past the header, at an even offset, with
/// `Length` bytes of text inside `written`; `Length` must be even, non-zero,
/// no more than `MaximumLength`, and the text must hold no NUL (it would cut
/// `CommandLineToArgvW` short and drop arguments).
fn command_line(buf: &[u64], written: usize) -> Option<CommandLine> {
    if written < HEADER || written > buf.len().checked_mul(size_of::<u64>())? {
        return None;
    }
    // SAFETY: at least HEADER initialized bytes exist at the start of `buf`,
    // u64 alignment satisfies UNICODE_STRING, and any bits are a valid
    // header value. The header's `Buffer` is only compared, never followed.
    let header = unsafe { buf.as_ptr().cast::<UNICODE_STRING>().read() };
    let len = usize::from(header.Length);
    if len == 0 || !len.is_multiple_of(2) || len > usize::from(header.MaximumLength) {
        return None;
    }
    let offset = (header.Buffer as usize).checked_sub(buf.as_ptr() as usize)?;
    if offset < HEADER || !offset.is_multiple_of(2) {
        return None;
    }
    let end = offset.checked_add(len)?;
    if end > written {
        return None;
    }
    let units = units(buf);
    let text = offset / 2..end / 2;
    if units[text.clone()].contains(&0) {
        return None;
    }
    let terminated =
        usize::from(header.MaximumLength) >= len + 2 && end + 2 <= written && units[text.end] == 0;
    Some(CommandLine { text, terminated })
}

/// Validate the kernel reply and split it into argv, NUL-terminating a copy
/// only when the kernel didn't leave a terminator in place.
fn argv_from(buf: &[u64], written: usize) -> Option<Vec<u8>> {
    let line = command_line(buf, written)?;
    let units = units(buf);
    if line.terminated {
        return split(&units[line.text.start..=line.text.end]);
    }
    let text = &units[line.text];
    let mut copy = Vec::new();
    copy.try_reserve_exact(text.len() + 1).ok()?;
    copy.extend_from_slice(text);
    copy.push(0);
    split(&copy)
}

/// Split a NUL-terminated, non-empty command line with `CommandLineToArgvW`.
/// Callers never pass empty text: for an empty string the OS substitutes the
/// CURRENT process's executable path.
fn split(cmd: &[u16]) -> Option<Vec<u8>> {
    let (&0, text) = cmd.split_last()? else {
        return None;
    };
    if text.is_empty() {
        return None;
    }
    let mut argc = 0i32;
    // SAFETY: `cmd` is NUL-terminated and outlives the call; `argc` is a
    // writable i32.
    let argv = unsafe { CommandLineToArgvW(cmd.as_ptr(), &mut argc) };
    if argv.is_null() {
        return None;
    }
    let argv = LocalArgv(argv);
    // Every argument consumes at least one unit of the text.
    let argc = usize::try_from(argc)
        .ok()
        .filter(|&n| n > 0 && n <= text.len())?;
    // SAFETY: CommandLineToArgvW returned `argc` argument pointers in one
    // block that stays allocated until `argv` drops at the end of this scope.
    let pointers = unsafe { std::slice::from_raw_parts(argv.0, argc) };
    let mut out = Vec::new();
    out.try_reserve(text.len() + argc).ok()?;
    for &arg in pointers {
        if arg.is_null() {
            return None;
        }
        // An argument is a rewrite of part of the text and never longer than
        // it, so its NUL lies within `text.len()` units of its start.
        // SAFETY: each argument is a NUL-terminated string inside the argv
        // block; the scan stops at its first NUL.
        let len = (0..=text.len()).find(|&i| unsafe { *arg.add(i) } == 0)?;
        // SAFETY: the `len` units before that NUL were just read in bounds.
        push_arg(&mut out, unsafe { std::slice::from_raw_parts(arg, len) })?;
    }
    Some(out)
}

/// Append one argument as UTF-8 plus its NUL, refusing to grow `out` past
/// [`MAX_BYTES`].
fn push_arg(out: &mut Vec<u8>, arg: &[u16]) -> Option<()> {
    for ch in char::decode_utf16(arg.iter().copied()) {
        let ch = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
        // Keep room for this argument's NUL.
        if out.len() + ch.len_utf8() + 1 > MAX_BYTES {
            return None;
        }
        out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
    }
    if out.len() + 1 > MAX_BYTES {
        return None;
    }
    out.push(0);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    const FIXTURE_ENV: &str = "HCOM_TEST_ARGV_FIXTURE";

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// Split `push_arg`/`read` output back into owned arguments.
    fn args_of(bytes: &[u8]) -> Vec<String> {
        let (&0, body) = bytes.split_last().expect("argv bytes") else {
            panic!("argv bytes must end with NUL");
        };
        body.split(|&b| b == 0)
            .map(|arg| String::from_utf8(arg.to_vec()).expect("UTF-8 argv"))
            .collect()
    }

    /// Write a header whose `Buffer` holds the absolute address `addr`.
    fn set_header(buf: &mut [u64], length: u16, maximum: u16, addr: usize) {
        let header = UNICODE_STRING {
            Length: length,
            MaximumLength: maximum,
            Buffer: addr as PWSTR,
        };
        // SAFETY: `buf` holds at least HEADER bytes, aligned for the header.
        unsafe { buf.as_mut_ptr().cast::<UNICODE_STRING>().write(header) };
    }

    /// A buffer laid out like the kernel's reply: header, text, then the NUL
    /// (or a non-NUL unit when `terminated` is false). Returns the buffer
    /// and the byte count the kernel would report.
    fn reply(text: &[u16], terminated: bool) -> (Vec<u64>, usize) {
        let bytes = HEADER + (text.len() + 1) * 2;
        let mut buf = vec![0u64; bytes.div_ceil(8)];
        let start = HEADER / 2;
        // SAFETY: same storage reinterpretation as `units`, mutably.
        let all = unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u16>(), buf.len() * 4)
        };
        all[start..start + text.len()].copy_from_slice(text);
        all[start + text.len()] = if terminated { 0 } else { u16::from(b'X') };
        let len = (text.len() * 2) as u16;
        let base = buf.as_ptr() as usize;
        set_header(&mut buf, len, len + 2, base + HEADER);
        (buf, bytes)
    }

    /// Child half of `reads_own_spawned_child_argv`: only does anything when
    /// that test runs this binary with FIXTURE_ENV set.
    #[test]
    #[ignore = "fixture child spawned by reads_own_spawned_child_argv"]
    fn argv_fixture_child() {
        if std::env::var_os(FIXTURE_ENV).is_some() {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn reads_own_spawned_child_argv() {
        let exe = std::env::current_exe().unwrap();
        let home = tempfile::tempdir().unwrap();
        let test_path = module_path!().split_once("::").unwrap().1;
        let fixture = format!("{test_path}::argv_fixture_child");
        // libtest takes the payload as extra --exact filters that match no
        // test, so the child runs only the parked fixture.
        let payload = [
            "with space",
            r"C:\dir with space\trailing\",
            r#"quote"inside"#,
            r"back\\slash",
            "ünïcødé ✓ 𝄞",
            "",
        ];
        let mut command = Command::new(&exe);
        command
            .args(["--exact", "--ignored", "--test-threads=1", &fixture])
            .args(payload)
            .env_clear()
            .env(FIXTURE_ENV, "1")
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("TEMP", home.path())
            .env("TMP", home.path())
            .env("HCOM_DIR", home.path().join(".hcom"))
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_DATA_HOME", home.path().join("data"))
            .env("XDG_STATE_HOME", home.path().join("state"))
            .env("XDG_CACHE_HOME", home.path().join("cache"))
            .env("XDG_RUNTIME_DIR", home.path().join("runtime"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        let mut child = command.spawn().unwrap();
        let got = read(child.id());
        let _ = child.kill();
        let _ = child.wait();

        let mut expected = vec![
            exe.to_string_lossy().into_owned(),
            "--exact".to_owned(),
            "--ignored".to_owned(),
            "--test-threads=1".to_owned(),
            fixture,
        ];
        expected.extend(payload.iter().map(|arg| (*arg).to_owned()));
        assert_eq!(args_of(&got.expect("own child argv")), expected);
    }

    #[test]
    fn unopenable_pids_are_none() {
        use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, GetLastError};
        // OpenProcess documents refusing PID 0, the System Idle Process, with
        // ERROR_INVALID_PARAMETER. That error must survive `read`: a guard
        // built from the NULL handle would CloseHandle(NULL) on drop, which
        // overwrites it with ERROR_INVALID_HANDLE (and raises an exception
        // under a debugger).
        assert_eq!(read(0), None);
        // SAFETY: reads this thread's last-error value.
        assert_eq!(unsafe { GetLastError() }, ERROR_INVALID_PARAMETER);
        // Far past any PID the kernel hands out.
        assert_eq!(read(!3_u32), None);
    }

    #[test]
    fn os_quoting_rules_split_interpreter_command_lines() {
        // A program path with spaces, a script path with spaces, and the
        // backslash-quote rules for a later argument.
        let line = r#""C:\Program Files\nodejs\node.exe" "C:\npm dir\omp" a\\\"b "c d\\" """#;
        let mut cmd = wide(line);
        cmd.push(0);
        assert_eq!(
            args_of(&split(&cmd).unwrap()),
            [
                r"C:\Program Files\nodejs\node.exe",
                r"C:\npm dir\omp",
                r#"a\"b"#,
                r"c d\",
                "",
            ]
        );
    }

    #[test]
    fn split_refuses_empty_or_unterminated_text() {
        // Empty text would make the OS report this process's own exe path.
        assert_eq!(split(&[0]), None);
        assert_eq!(split(&[]), None);
        assert_eq!(split(&wide("omp")), None);
    }

    #[test]
    fn kernel_reply_is_read_in_place_or_terminated_copy() {
        let text = wide(r#"node "C:\x y\cli.js""#);
        let (buf, written) = reply(&text, true);
        let line = command_line(&buf, written).unwrap();
        assert!(line.terminated);
        assert_eq!(&units(&buf)[line.text.clone()], &text[..]);
        assert_eq!(
            args_of(&argv_from(&buf, written).unwrap()),
            ["node", r"C:\x y\cli.js"]
        );

        // No NUL after the text: the copy path must give the same argv.
        let (buf, written) = reply(&text, false);
        assert!(!command_line(&buf, written).unwrap().terminated);
        assert_eq!(
            args_of(&argv_from(&buf, written).unwrap()),
            ["node", r"C:\x y\cli.js"]
        );

        // A NUL the kernel didn't report as written doesn't count.
        let (buf, written) = reply(&text, true);
        assert!(!command_line(&buf, written - 2).unwrap().terminated);
        // Nor does one outside MaximumLength.
        let (mut buf, written) = reply(&text, true);
        let len = (text.len() * 2) as u16;
        let base = buf.as_ptr() as usize;
        set_header(&mut buf, len, len, base + HEADER);
        assert!(!command_line(&buf, written).unwrap().terminated);
    }

    #[test]
    fn malformed_kernel_replies_are_rejected() {
        let text = wide("omp --resume");
        let len = (text.len() * 2) as u16;
        let (buf, written) = reply(&text, true);
        assert!(
            command_line(&buf, written).is_some(),
            "control reply is valid"
        );
        assert_eq!(command_line(&buf, HEADER - 1), None, "short header");
        assert_eq!(
            command_line(&buf, buf.len() * 8 + 1),
            None,
            "written past buffer"
        );

        // Rewrite the header of a valid reply; `addr` maps the buffer's base
        // address to the header's `Buffer` value.
        let with_header = |length: u16, maximum: u16, addr: &dyn Fn(usize) -> usize| {
            let (mut buf, written) = reply(&text, true);
            let base = buf.as_ptr() as usize;
            set_header(&mut buf, length, maximum, addr(base));
            command_line(&buf, written)
        };
        let text_at = |offset: usize| move |base: usize| base.wrapping_add(offset);
        assert_eq!(with_header(0, 2, &text_at(HEADER)), None, "zero length");
        assert_eq!(
            with_header(len - 1, len + 2, &text_at(HEADER)),
            None,
            "odd length"
        );
        assert_eq!(
            with_header(len, len - 2, &text_at(HEADER)),
            None,
            "length over maximum"
        );
        assert_eq!(with_header(len, len + 2, &|_| 0), None, "null buffer");
        assert_eq!(
            with_header(len, len + 2, &|base| base - 2),
            None,
            "before buffer"
        );
        assert_eq!(
            with_header(len, len + 2, &text_at(0)),
            None,
            "overlaps header"
        );
        assert_eq!(
            with_header(len, len + 2, &text_at(HEADER + 1)),
            None,
            "misaligned"
        );
        assert_eq!(
            with_header(len, len + 2, &text_at(HEADER + 4)),
            None,
            "runs past written"
        );
        assert_eq!(
            with_header(len, len + 2, &|_| usize::MAX - 1),
            None,
            "offset overflow"
        );

        let mut nul_inside = text.clone();
        nul_inside[3] = 0;
        let (buf, written) = reply(&nul_inside, true);
        assert_eq!(command_line(&buf, written), None, "embedded NUL");
    }

    #[test]
    fn arguments_are_nul_delimited_utf8_with_lossy_surrogates() {
        let mut out = Vec::new();
        push_arg(&mut out, &wide("node")).unwrap();
        push_arg(&mut out, &[]).unwrap();
        push_arg(&mut out, &[u16::from(b'a'), 0xD800, u16::from(b'b')]).unwrap();
        assert_eq!(out, b"node\0\0a\xEF\xBF\xBDb\0");
    }

    #[test]
    fn argv_bytes_stop_at_one_mebibyte() {
        let mut out = Vec::new();
        let fits = vec![u16::from(b'a'); MAX_BYTES - 1];
        push_arg(&mut out, &fits).unwrap();
        assert_eq!(out.len(), MAX_BYTES);
        assert_eq!(push_arg(&mut out, &[]), None);

        let mut out = Vec::new();
        assert_eq!(push_arg(&mut out, &vec![u16::from(b'a'); MAX_BYTES]), None);
    }
}
