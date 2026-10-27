//! Native argv and environment of another Windows process.
//!
//! `NtQueryInformationProcess(ProcessCommandLineInformation)` (Windows 8.1+)
//! has the kernel copy the target's command line into a caller buffer as a
//! `UNICODE_STRING` header followed by the text. It needs only
//! `PROCESS_QUERY_LIMITED_INFORMATION`: no PEB walk, no `ReadProcessMemory`.
//! `CommandLineToArgvW` then splits that text with the OS quoting rules, the
//! ones the MSVC CRT and Rust's std `Command` use, so argv matches what the
//! process itself parsed.
//!
//! Environment reads separately walk the same-bitness PEB using a read-only
//! process handle. Every remote read must complete before a value is trusted.

use super::EnvRead;

#[cfg(windows)]
use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessBasicInformation, ProcessCommandLineInformation,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, LocalFree, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
    STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;
#[cfg(windows)]
use windows_sys::core::PWSTR;

/// Cap on both the kernel query buffer and the returned argv bytes.
const MAX_BYTES: usize = 1 << 20;
#[cfg(windows)]
const HEADER: usize = size_of::<UNICODE_STRING>();

// PE/COFF machine IDs reported by IsWow64Process2.
const MACHINE_UNKNOWN: u16 = 0;
const MACHINE_I386: u16 = 0x014c;
const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_ARMNT: u16 = 0x01c4;
const MACHINE_ARM64: u16 = 0xaa64;

#[cfg(all(windows, target_arch = "x86"))]
const COMPILED_MACHINE: u16 = MACHINE_I386;
#[cfg(all(windows, target_arch = "x86_64"))]
const COMPILED_MACHINE: u16 = MACHINE_AMD64;
#[cfg(all(windows, target_arch = "arm"))]
const COMPILED_MACHINE: u16 = MACHINE_ARMNT;
#[cfg(all(windows, target_arch = "aarch64"))]
const COMPILED_MACHINE: u16 = MACHINE_ARM64;
#[cfg(all(
    windows,
    not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))
))]
const COMPILED_MACHINE: u16 = MACHINE_UNKNOWN;

/// NUL-delimited UTF-8 argv of `pid`, one NUL after every argument, or `None`
/// when the process can't be opened or queried, or the reply is malformed or
/// over [`MAX_BYTES`]. Unpaired UTF-16 surrogates become U+FFFD.
#[cfg(windows)]
pub(super) fn read(pid: u32) -> Option<Vec<u8>> {
    let (buf, written) = query_command_line(&Process::open(pid)?)?;
    argv_from(&buf, written)
}

/// Query handle closed on drop.
#[cfg(windows)]
struct Process(HANDLE);

#[cfg(windows)]
impl Process {
    fn open(pid: u32) -> Option<Self> {
        Self::open_with_access(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    }

    fn open_with_access(pid: u32, access: u32) -> Option<Self> {
        // SAFETY: plain FFI call with read-only query/VM access; a null
        // result means no handle was opened.
        let handle = unsafe { OpenProcess(access, 0, pid) };
        // Lazy: a guard built from NULL would CloseHandle(NULL) on drop.
        (!handle.is_null()).then(|| Process(handle))
    }
}

#[cfg(windows)]
impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: `open` wraps only a non-null OpenProcess handle, and it is
        // closed exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// Windows NT's native PEB and Vista+ RTL_USER_PROCESS_PARAMETERS layouts,
// as declared in System Informer's phnt ntpebteb.h / ntrtl.h. Pointer-sized
// fields use the caller's width only after both effective machines match it.
#[cfg(all(windows, target_pointer_width = "64"))]
const PEB_PROCESS_PARAMETERS: usize = 0x20;
#[cfg(all(windows, target_pointer_width = "32"))]
const PEB_PROCESS_PARAMETERS: usize = 0x10;
#[cfg(all(windows, target_pointer_width = "64"))]
const PARAMETERS_ENVIRONMENT: usize = 0x80;
#[cfg(all(windows, target_pointer_width = "32"))]
const PARAMETERS_ENVIRONMENT: usize = 0x48;
#[cfg(all(windows, target_pointer_width = "64"))]
const PARAMETERS_ENVIRONMENT_SIZE: usize = 0x3f0;
#[cfg(all(windows, target_pointer_width = "32"))]
const PARAMETERS_ENVIRONMENT_SIZE: usize = 0x290;

/// The public winternl.h PROCESS_BASIC_INFORMATION, all fields pointer-sized.
#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct BasicInformation {
    reserved1: usize,
    peb_base_address: usize,
    reserved2: [usize; 2],
    unique_process_id: usize,
    reserved3: usize,
}

#[cfg(windows)]
type QueryProcessMachines = unsafe extern "system" fn(HANDLE, *mut u16, *mut u16) -> i32;

// Existing windows-sys features don't expose Diagnostics::Debug or LibraryLoader.
// Keep these read-only imports local to this reader.
#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "ReadProcessMemory"]
    fn read_process_memory(
        process: HANDLE,
        base: *const std::ffi::c_void,
        buffer: *mut std::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
    #[link_name = "GetModuleHandleA"]
    fn get_module_handle(name: *const u8) -> HANDLE;
    #[link_name = "GetProcAddress"]
    fn get_proc_address(
        module: HANDLE,
        name: *const u8,
    ) -> Option<unsafe extern "system" fn() -> isize>;
}

#[cfg(windows)]
fn process_machine_matches(process: &Process) -> bool {
    // SAFETY: both names are static NUL-terminated ASCII. kernel32 is already
    // loaded by this executable; GetModuleHandle doesn't transfer ownership.
    let module = unsafe { get_module_handle(c"kernel32.dll".as_ptr().cast()) };
    if module.is_null() {
        return false;
    }
    // SAFETY: `module` is a live module and the export name is NUL-terminated.
    let Some(query) = (unsafe { get_proc_address(module, c"IsWow64Process2".as_ptr().cast()) })
    else {
        // Older Windows without this export cannot prove the target's machine.
        return false;
    };
    // SAFETY: this named kernel32 export has the IsWow64Process2 ABI.
    let query = unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, QueryProcessMachines>(query)
    };
    // SAFETY: GetCurrentProcess returns this process's valid pseudo-handle.
    let current = unsafe { GetCurrentProcess() };
    machine_layout_matches(
        query_process_machines(query, current),
        query_process_machines(query, process.0),
        COMPILED_MACHINE,
    )
}

#[cfg(windows)]
fn query_process_machines(query: QueryProcessMachines, process: HANDLE) -> Option<(u16, u16)> {
    let mut machine = MACHINE_UNKNOWN;
    let mut native = MACHINE_UNKNOWN;
    // SAFETY: the function pointer was resolved by its exact export name;
    // both outputs are writable USHORTs and `process` is a live handle.
    (unsafe { query(process, &mut machine, &mut native) } != 0).then_some((machine, native))
}

fn machine_layout_matches(
    current: Option<(u16, u16)>,
    target: Option<(u16, u16)>,
    compiled: u16,
) -> bool {
    if !matches!(
        compiled,
        MACHINE_I386 | MACHINE_AMD64 | MACHINE_ARMNT | MACHINE_ARM64
    ) {
        return false;
    }
    let effective = |query: Option<(u16, u16)>| {
        let (process, native) = query?;
        if !matches!(
            native,
            MACHINE_I386 | MACHINE_AMD64 | MACHINE_ARMNT | MACHINE_ARM64
        ) {
            return None;
        }
        Some(if process == MACHINE_UNKNOWN {
            native
        } else {
            process
        })
    };
    matches!(
        (effective(current), effective(target)),
        (Some(current), Some(target)) if current == target && current == compiled
    )
}

#[cfg(windows)]
pub(super) fn read_env_var(pid: u32, key: &str) -> EnvRead {
    match read_environment(pid) {
        Some(buffer) => parse_env(&buffer, buffer.len() * size_of::<u16>(), key),
        None => EnvRead::Unreadable,
    }
}

#[cfg(windows)]
fn read_environment(pid: u32) -> Option<Vec<u16>> {
    let process =
        Process::open_with_access(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)?;
    if !process_machine_matches(&process) {
        return None;
    }
    let mut basic = BasicInformation::default();
    let mut written = 0;
    // SAFETY: the native-width output buffer matches PROCESS_BASIC_INFORMATION;
    // its size and reported write count are checked before using its PEB.
    let status = unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessBasicInformation,
            (&mut basic as *mut BasicInformation).cast(),
            size_of::<BasicInformation>() as u32,
            &mut written,
        )
    };
    if status < 0
        || written as usize != size_of::<BasicInformation>()
        || basic.peb_base_address == 0
        || !basic.peb_base_address.is_multiple_of(align_of::<usize>())
    {
        return None;
    }
    let parameters = read_pointer(
        &process,
        basic.peb_base_address.checked_add(PEB_PROCESS_PARAMETERS)?,
    )?;
    if parameters == 0 || !parameters.is_multiple_of(align_of::<usize>()) {
        return None;
    }
    let environment = read_pointer(&process, parameters.checked_add(PARAMETERS_ENVIRONMENT)?)?;
    let size = read_pointer(
        &process,
        parameters.checked_add(PARAMETERS_ENVIRONMENT_SIZE)?,
    )?;
    if environment == 0 || !environment.is_multiple_of(size_of::<u16>()) {
        return None;
    }
    if size == 0 {
        return read_environment_chunks(&process, environment);
    }
    if !(4..=MAX_BYTES).contains(&size) || !size.is_multiple_of(size_of::<u16>()) {
        return None;
    }
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(size / size_of::<u16>()).ok()?;
    buffer.resize(size / size_of::<u16>(), 0);
    read_units(&process, environment, &mut buffer)?;
    Some(buffer)
}

#[cfg(windows)]
fn read_pointer(process: &Process, address: usize) -> Option<usize> {
    let mut bytes = [0; size_of::<usize>()];
    read_memory(process, address, &mut bytes)?;
    Some(usize::from_ne_bytes(bytes))
}

#[cfg(windows)]
fn read_memory(process: &Process, address: usize, buffer: &mut [u8]) -> Option<()> {
    if address == 0 {
        return None;
    }
    address.checked_add(buffer.len())?;
    let mut read = 0;
    // SAFETY: the remote address is never dereferenced locally. The writable
    // buffer covers exactly the requested size and stays live through the call.
    let result = unsafe {
        read_process_memory(
            process.0,
            address as *const std::ffi::c_void,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut read,
        )
    };
    (result != 0 && read == buffer.len()).then_some(())
}

#[cfg(windows)]
fn read_units(process: &Process, address: usize, buffer: &mut [u16]) -> Option<()> {
    // SAFETY: a mutable byte view covers the same initialized u16 storage,
    // and every resulting bit pattern remains a valid u16.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast(), size_of_val(buffer)) };
    read_memory(process, address, bytes)
}

#[cfg(windows)]
fn read_environment_chunks(process: &Process, environment: usize) -> Option<Vec<u16>> {
    // Align each small read so it cannot straddle Windows' page boundaries.
    // A short or failed chunk is still unreadable, even if it held a match.
    const CHUNK_BYTES: usize = 256;
    let mut buffer = Vec::new();
    while buffer.len() * size_of::<u16>() < MAX_BYTES {
        let read_bytes = buffer.len() * size_of::<u16>();
        let address = environment.checked_add(read_bytes)?;
        let count =
            (CHUNK_BYTES - address % CHUNK_BYTES).min(MAX_BYTES - read_bytes) / size_of::<u16>();
        let start = buffer.len();
        buffer.try_reserve(count).ok()?;
        buffer.resize(start + count, 0);
        read_units(process, address, &mut buffer[start..])?;
        if let Some(end) = buffer[start.saturating_sub(1)..]
            .windows(2)
            .position(|pair| pair == [0, 0])
        {
            buffer.truncate(start.saturating_sub(1) + end + 2);
            return Some(buffer);
        }
    }
    None
}

/// `CommandLineToArgvW` block released with `LocalFree` on drop.
#[cfg(windows)]
struct LocalArgv(*mut PWSTR);

#[cfg(windows)]
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
#[cfg(windows)]
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
#[cfg(windows)]
fn units(buf: &[u64]) -> &[u16] {
    // SAFETY: the u64 storage is initialized, at least u16-aligned, every bit
    // pattern is a valid u16, and the length covers exactly the same bytes
    // for the borrow's lifetime.
    unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u16>(), buf.len() * 4) }
}

/// Validated location of the command line inside the query buffer.
#[cfg(windows)]
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
#[cfg(windows)]
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
#[cfg(windows)]
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
#[cfg(windows)]
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
#[cfg(windows)]
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

/// Check the claimed byte count, complete UTF-16 entries and the double NUL.
/// Keep only the first matching slice until the rest of the block is trusted.
fn parse_env(block: &[u16], claimed_bytes: usize, key: &str) -> EnvRead {
    if !(4..=MAX_BYTES).contains(&claimed_bytes)
        || !claimed_bytes.is_multiple_of(size_of::<u16>())
        || claimed_bytes / size_of::<u16>() > block.len()
    {
        return EnvRead::Unreadable;
    }
    let block = &block[..claimed_bytes / size_of::<u16>()];
    let Some(end) = block.windows(2).position(|pair| pair == [0, 0]) else {
        return EnvRead::Unreadable;
    };
    let mut value = None;
    if end != 0 {
        for entry in block[..end].split(|unit| *unit == 0) {
            if entry.is_empty() {
                return EnvRead::Unreadable;
            }
            if value.is_none()
                && let Some(separator) = entry.iter().position(|unit| *unit == u16::from(b'='))
                && env_key_matches(&entry[..separator], key)
            {
                value = Some(&entry[separator + 1..]);
            } else if char::decode_utf16(entry.iter().copied()).any(|character| character.is_err())
            {
                return EnvRead::Unreadable;
            }
        }
    }
    match value {
        Some(value) => match String::from_utf16(value) {
            Ok(value) => EnvRead::Present(value),
            Err(_) => EnvRead::Unreadable,
        },
        None => EnvRead::Absent,
    }
}

fn env_key_matches(name: &[u16], key: &str) -> bool {
    let lowercase = |unit| {
        if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
            unit + u16::from(b'a' - b'A')
        } else {
            unit
        }
    };
    name.iter()
        .copied()
        .map(lowercase)
        .eq(key.encode_utf16().map(lowercase))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    const FIXTURE_ENV: &str = "HCOM_TEST_ARGV_FIXTURE";

    #[test]
    fn native_environment_layout_uses_the_callers_pointer_width() {
        let pointer = size_of::<usize>();
        assert_eq!(size_of::<BasicInformation>(), 6 * pointer);
        assert_eq!(
            std::mem::offset_of!(BasicInformation, peb_base_address),
            pointer
        );
        assert_eq!(
            std::mem::offset_of!(BasicInformation, unique_process_id),
            4 * pointer
        );
        let expected = if pointer == 8 {
            (0x20, 0x80, 0x3f0)
        } else {
            (0x10, 0x48, 0x290)
        };
        assert_eq!(
            (
                PEB_PROCESS_PARAMETERS,
                PARAMETERS_ENVIRONMENT,
                PARAMETERS_ENVIRONMENT_SIZE
            ),
            expected
        );
    }

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

#[cfg(test)]
mod env_tests {
    use super::*;

    fn parse(text: &str, key: &str) -> EnvRead {
        let block: Vec<u16> = text.encode_utf16().collect();
        parse_env(&block, block.len() * size_of::<u16>(), key)
    }

    #[test]
    fn environment_parser_reads_values_and_keeps_the_first_match() {
        assert_eq!(
            parse(
                "=C:=C:\\fixture\0OTHER=unrelated\0HCOM_PROCESS_ID=owner=雪 𝄞\0HCOM_PROCESS_ID=later\0\0",
                "HCOM_PROCESS_ID"
            ),
            EnvRead::Present("owner=雪 𝄞".into())
        );
    }

    #[test]
    fn environment_parser_reports_absence_and_rejects_key_prefixes() {
        assert_eq!(
            parse(
                "HCOM_PROCESS_ID_X=prefix\0OTHER=unrelated\0\0",
                "HCOM_PROCESS_ID"
            ),
            EnvRead::Absent
        );
        assert_eq!(parse("\0\0", "HCOM_PROCESS_ID"), EnvRead::Absent);
    }

    #[test]
    fn environment_parser_compares_ascii_case_insensitively() {
        assert_eq!(
            parse(
                "hCoM_pRoCeSs_Id=first\0HCOM_PROCESS_ID=second\0\0",
                "HCOM_PROCESS_ID"
            ),
            EnvRead::Present("first".into())
        );
        assert_eq!(parse("KEY_Ä=value\0\0", "key_ä"), EnvRead::Absent);
    }

    #[test]
    fn environment_parser_accepts_empty_values() {
        assert_eq!(
            parse("HCOM_PROCESS_ID=\0\0", "HCOM_PROCESS_ID"),
            EnvRead::Present(String::new())
        );
    }

    #[test]
    fn environment_parser_rejects_truncation_even_after_a_match() {
        for text in [
            "HCOM_PROCESS_ID=truncated",
            "HCOM_PROCESS_ID=owner\0TAIL=truncated",
            "HCOM_PROCESS_ID=owner\0",
            "\0",
            "",
        ] {
            assert_eq!(parse(text, "HCOM_PROCESS_ID"), EnvRead::Unreadable);
        }
        let block: Vec<u16> = "HCOM_PROCESS_ID=owner\0\0".encode_utf16().collect();
        assert_eq!(
            parse_env(
                &block,
                (block.len() + 1) * size_of::<u16>(),
                "HCOM_PROCESS_ID"
            ),
            EnvRead::Unreadable
        );
        assert_eq!(
            parse_env(
                &block,
                (block.len() - 1) * size_of::<u16>(),
                "HCOM_PROCESS_ID"
            ),
            EnvRead::Unreadable
        );
    }

    #[test]
    fn environment_parser_rejects_invalid_utf16_anywhere_before_the_end() {
        for invalid in [0xd800, 0xdc00] {
            let mut block: Vec<u16> = "HCOM_PROCESS_ID=owner\0TAIL=".encode_utf16().collect();
            block.extend([invalid, 0, 0]);
            assert_eq!(
                parse_env(&block, block.len() * size_of::<u16>(), "HCOM_PROCESS_ID"),
                EnvRead::Unreadable
            );
            let mut block: Vec<u16> = "HCOM_PROCESS_ID=".encode_utf16().collect();
            block.extend([invalid, 0, 0]);
            assert_eq!(
                parse_env(&block, block.len() * size_of::<u16>(), "HCOM_PROCESS_ID"),
                EnvRead::Unreadable
            );
        }
    }

    #[test]
    fn environment_parser_rejects_oversize_and_misaligned_claims() {
        let block: Vec<u16> = "HCOM_PROCESS_ID=owner\0\0".encode_utf16().collect();
        for claim in [MAX_BYTES + 2, usize::MAX, 0, 2, block.len() * 2 - 1] {
            assert_eq!(
                parse_env(&block, claim, "HCOM_PROCESS_ID"),
                EnvRead::Unreadable
            );
        }
    }
}

#[cfg(test)]
mod machine_tests {
    use super::*;

    #[test]
    fn equal_native_machines_match_the_compiled_layout() {
        for machine in [MACHINE_I386, MACHINE_AMD64, MACHINE_ARMNT, MACHINE_ARM64] {
            let native = Some((MACHINE_UNKNOWN, machine));
            assert!(machine_layout_matches(native, native, machine));
        }
    }

    #[test]
    fn wow64_pairs_must_match_each_other_and_the_compiled_machine() {
        let native = Some((MACHINE_UNKNOWN, MACHINE_AMD64));
        let wow64 = Some((MACHINE_I386, MACHINE_AMD64));
        assert!(machine_layout_matches(wow64, wow64, MACHINE_I386));
        assert!(!machine_layout_matches(native, wow64, MACHINE_AMD64));
        assert!(!machine_layout_matches(wow64, native, MACHINE_I386));
        assert!(!machine_layout_matches(wow64, wow64, MACHINE_AMD64));
    }

    #[test]
    fn arm_emulation_cannot_confuse_equal_wow64_bools_with_equal_machines() {
        let native = Some((MACHINE_UNKNOWN, MACHINE_ARM64));
        for machine in [MACHINE_I386, MACHINE_ARMNT, MACHINE_AMD64] {
            let emulated = Some((machine, MACHINE_ARM64));
            assert!(!machine_layout_matches(native, emulated, MACHINE_ARM64));
            assert!(!machine_layout_matches(emulated, native, machine));
            assert!(machine_layout_matches(emulated, emulated, machine));
        }
    }

    #[test]
    fn unknown_or_failed_machine_queries_refuse_the_layout() {
        let native = Some((MACHINE_UNKNOWN, MACHINE_AMD64));
        for unknown in [
            None,
            Some((MACHINE_UNKNOWN, MACHINE_UNKNOWN)),
            Some((MACHINE_I386, MACHINE_UNKNOWN)),
            Some((0xffff, MACHINE_AMD64)),
            Some((MACHINE_UNKNOWN, 0xffff)),
        ] {
            assert!(!machine_layout_matches(native, unknown, MACHINE_AMD64));
            assert!(!machine_layout_matches(unknown, native, MACHINE_AMD64));
        }
        assert!(!machine_layout_matches(native, native, MACHINE_UNKNOWN));
    }
}
