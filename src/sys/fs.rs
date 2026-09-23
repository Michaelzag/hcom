//! Filesystem primitives that differ across platforms: Unix permission bits and
//! stable on-disk file identity.

use std::fs::File;
use std::io;
use std::path::Path;

/// Create a new file restricted to the owner (`0o600` on Unix), failing if it
/// already exists. On Windows the file is created with default ACLs (no Unix
/// mode); profile-local files are already private. This is a no-op gap if
/// `HCOM_DIR`/`HOME` is redirected to a location shared with other accounts —
/// secrets written there won't be owner-restricted on Windows. Real ACL
/// restriction (`SetNamedSecurityInfo`) is deferred to a later batch; this is
/// a deliberate, tracked gap, not an oversight.
pub fn create_private_new(path: &Path) -> io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Acquire a blocking exclusive lock on an open file. The lock is released when
/// the file handle is closed (dropped).
///
/// Unix: `flock(LOCK_EX)`, retrying on `EINTR`. Windows: `LockFileEx` with
/// `LOCKFILE_EXCLUSIVE_LOCK` over the whole file.
pub fn lock_exclusive(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        loop {
            // SAFETY: flock on a valid fd; return value is checked.
            let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if ret == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx};
        use windows_sys::Win32::System::IO::OVERLAPPED;

        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: valid handle for the file's lifetime; whole-file range.
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle() as HANDLE,
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Try to take an exclusive lock on an open file without blocking. Returns
/// `Ok(true)` when acquired, `Ok(false)` when another handle holds a
/// conflicting lock. The lock is released when the file handle is closed
/// (dropped).
///
/// Unix: `flock(LOCK_EX|LOCK_NB)`, retrying on `EINTR`. Windows: `LockFileEx`
/// with `LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY` over the whole file.
pub fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    try_lock(file, true)
}

/// Try to take a shared lock on an open file without blocking. Returns
/// `Ok(true)` when acquired, `Ok(false)` when another handle holds an
/// exclusive lock. Shared holders never conflict with each other, so
/// concurrent liveness probes don't see one another as the holder. The lock
/// is released when the file handle is closed (dropped).
///
/// Unix: `flock(LOCK_SH|LOCK_NB)`, retrying on `EINTR`. Windows: `LockFileEx`
/// with `LOCKFILE_FAIL_IMMEDIATELY` over the whole file.
pub fn try_lock_shared(file: &File) -> io::Result<bool> {
    try_lock(file, false)
}

fn try_lock(file: &File, exclusive: bool) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let op = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        } | libc::LOCK_NB;
        loop {
            // SAFETY: flock on a valid fd; return value is checked.
            let ret = unsafe { libc::flock(file.as_raw_fd(), op) };
            if ret == 0 {
                return Ok(true);
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
                    return Ok(false);
                }
                _ => return Err(err),
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION, HANDLE};
        use windows_sys::Win32::Storage::FileSystem::{
            LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
        };
        use windows_sys::Win32::System::IO::OVERLAPPED;

        let flags = if exclusive {
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
        } else {
            LOCKFILE_FAIL_IMMEDIATELY
        };
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: valid handle for the file's lifetime; whole-file range.
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle() as HANDLE,
                flags,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if ok != 0 {
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            // FAIL_IMMEDIATELY on a synchronous handle can report IO_PENDING
            // instead of LOCK_VIOLATION; both mean "held elsewhere".
            Some(code)
                if code == ERROR_LOCK_VIOLATION as i32 || code == ERROR_IO_PENDING as i32 =>
            {
                Ok(false)
            }
            _ => Err(err),
        }
    }
}

/// Whether `path` is a Unix-domain socket. Always false on Windows, which has
/// no filesystem socket node type.
pub fn is_socket(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(path)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// Restrict a file to owner-only read/write (`0o600` on Unix).
///
/// No-op on Windows, where Unix mode bits do not apply and files created under
/// the user's profile are already private by default. Same caveat as
/// `create_private_new`: a shared `HCOM_DIR`/`HOME` location isn't actually
/// locked down on Windows until real ACL restriction is implemented.
pub fn set_private(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Restrict a directory to owner-only access (`0o700` on Unix).
///
/// No-op on Windows, where Unix mode bits do not apply. Same caveat as
/// `set_private`: a shared `HCOM_DIR`/`HOME` location isn't actually locked
/// down on Windows until real ACL restriction is implemented.
pub fn set_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Mark a file as executable (`0o755` on Unix).
///
/// No-op on Windows, where executability is determined by file extension rather
/// than a mode bit.
pub fn set_executable(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Stable identity of a file on disk, used to detect replacement (atomic
/// rename/swap) of a path that keeps the same name.
///
/// Unix: the inode number. Windows: the `nFileIndex` from
/// `GetFileInformationByHandle`. Returns 0 when the file cannot be inspected.
pub fn file_id(path: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).map(|m| m.ino()).unwrap_or(0)
    }
    #[cfg(windows)]
    {
        file_id_win(path).unwrap_or(0)
    }
}

#[cfg(windows)]
fn file_id_win(path: &Path) -> Option<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = std::fs::File::open(path).ok()?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `file` owns a valid handle for the duration of the call and
    // `info` is a properly sized output buffer.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
    if ok == 0 {
        return None;
    }
    Some(((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(path: &Path) -> File {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    #[test]
    fn try_lock_exclusive_conflicts_with_held_exclusive_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let a = open(&path);
        let b = open(&path);
        assert!(try_lock_exclusive(&a).unwrap());
        assert!(!try_lock_exclusive(&b).unwrap());
        drop(a);
        assert!(try_lock_exclusive(&b).unwrap());
    }

    #[test]
    fn try_lock_shared_holders_do_not_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let a = open(&path);
        let b = open(&path);
        assert!(try_lock_shared(&a).unwrap());
        assert!(try_lock_shared(&b).unwrap());
        // A shared holder blocks an exclusive taker.
        let c = open(&path);
        assert!(!try_lock_exclusive(&c).unwrap());
    }

    #[test]
    fn try_lock_shared_fails_while_exclusive_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let a = open(&path);
        let b = open(&path);
        assert!(try_lock_exclusive(&a).unwrap());
        assert!(!try_lock_shared(&b).unwrap());
        drop(a);
        assert!(try_lock_shared(&b).unwrap());
    }
}
