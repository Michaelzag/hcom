//! Working-directory guard for omp launches.
//!
//! omp refuses to start when its cwd is under `/tmp` (exit 2 at
//! session_start: `/tmp` is a RAM tmpfs on the fleet). hcom must not hand it
//! one. An explicit `--dir` under `/tmp` is refused; a directory inherited
//! from a resume snapshot is redirected to `/build/<seat>/tmp`.

use std::path::{Component, Path, PathBuf};

const DEFAULT_BUILD_ROOT: &str = "/build";

fn build_root() -> std::borrow::Cow<'static, str> {
    std::env::var("HCOM_BUILD_ROOT")
        .ok()
        .filter(|value| !value.is_empty())
        .map(std::borrow::Cow::Owned)
        .unwrap_or(std::borrow::Cow::Borrowed(DEFAULT_BUILD_ROOT))
}

/// Check `dir` against the omp `/tmp` start guard.
///
/// Dirs outside `/tmp` come back byte-identical. Under `/tmp`, `explicit`
/// (user-supplied `--dir`) is refused with a message naming the guard;
/// otherwise `/build/<seat>/tmp` is created and returned instead.
pub fn guard_launch_dir(dir: &str, seat: Option<&str>, explicit: bool) -> Result<String, String> {
    let build_root = build_root();
    guard_launch_dir_in(dir, seat, explicit, Path::new(build_root.as_ref()))
}

fn guard_launch_dir_in(
    dir: &str,
    seat: Option<&str>,
    explicit: bool,
    build_root: &Path,
) -> Result<String, String> {
    if !is_under_tmp(Path::new(dir)) {
        return Ok(dir.to_string());
    }
    let target = redirect_target(build_root, seat);
    if explicit {
        return Err(format!(
            "--dir {dir} is under /tmp: omp refuses to start with cwd under /tmp \
             (omp /tmp start guard). Use a directory like {} instead.",
            target.display()
        ));
    }
    std::fs::create_dir_all(&target).map_err(|e| {
        format!(
            "directory {dir} is under /tmp (omp /tmp start guard) and the redirect \
             target {} could not be created: {e}",
            target.display()
        )
    })?;
    Ok(target.to_string_lossy().into_owned())
}

/// `<build_root>/<seat>/tmp`, or `<build_root>/tmp` when the seat is missing
/// or is not a single plain path segment.
fn redirect_target(build_root: &Path, seat: Option<&str>) -> PathBuf {
    let seat = seat.filter(|s| {
        !s.contains(['/', '\\'])
            && matches!(
                Path::new(s).components().collect::<Vec<_>>().as_slice(),
                [Component::Normal(_)]
            )
    });
    match seat {
        Some(seat) => build_root.join(seat).join("tmp"),
        None => build_root.join("tmp"),
    }
}

/// Whether `dir` resolves to `/tmp` or something beneath it. Compared
/// component-wise, so `/tmpfoo` does not match; `/tmp` itself is also
/// resolved so a symlinked `/tmp` (macOS `/private/tmp`) is caught. A path
/// that can't be resolved (doesn't exist) is judged as written.
#[cfg(unix)]
fn is_under_tmp(dir: &Path) -> bool {
    let tmp = Path::new("/tmp");
    let resolved = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let tmp_resolved = tmp.canonicalize().unwrap_or_else(|_| tmp.to_path_buf());
    resolved.starts_with(tmp) || resolved.starts_with(&tmp_resolved)
}

#[cfg(not(unix))]
fn is_under_tmp(_dir: &Path) -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn explicit_tmp_dir_is_refused_naming_the_guard() {
        let root = tempfile::tempdir().unwrap();
        let err = guard_launch_dir_in("/tmp", Some("nuzi"), true, root.path()).unwrap_err();
        assert!(err.contains("omp /tmp start guard"), "{err}");
        assert!(
            err.contains(&format!("{}/nuzi/tmp", root.path().display())),
            "{err}"
        );
        assert!(
            !root.path().join("nuzi").exists(),
            "explicit refusal must not create dirs"
        );
    }

    #[test]
    fn snapshot_tmp_dir_redirects_to_seat_build_tmp() {
        let root = tempfile::tempdir().unwrap();
        let got = guard_launch_dir_in("/tmp", Some("nuzi"), false, root.path()).unwrap();
        let want = root.path().join("nuzi").join("tmp");
        assert_eq!(got, want.to_string_lossy());
        assert!(want.is_dir());
    }

    #[test]
    fn nested_and_trailing_tmp_paths_are_caught() {
        let root = tempfile::tempdir().unwrap();
        for dir in ["/tmp/", "/tmp/does-not-exist/x", "/tmp/../tmp"] {
            assert!(
                guard_launch_dir_in(dir, Some("nuzi"), true, root.path()).is_err(),
                "{dir}"
            );
        }
    }

    #[test]
    fn non_tmp_dirs_pass_through_byte_identical() {
        // tempdir() may itself live under /tmp (CI), so use the crate root.
        let root = tempfile::tempdir().unwrap();
        let dir = env!("CARGO_MANIFEST_DIR");
        let with_slash = format!("{dir}/");
        // `/tmp/..` resolves to `/`, which is not under /tmp.
        for d in [
            dir.to_string(),
            with_slash,
            "/tmpfoo".into(),
            "/tmp/..".into(),
        ] {
            assert_eq!(
                guard_launch_dir_in(&d, Some("nuzi"), true, root.path()).unwrap(),
                d
            );
            assert_eq!(
                guard_launch_dir_in(&d, Some("nuzi"), false, root.path()).unwrap(),
                d
            );
        }
    }

    #[test]
    fn seat_with_separators_is_not_interpreted() {
        let root = tempfile::tempdir().unwrap();
        for seat in ["../esc", "a/b", "..", "", "."] {
            let got = guard_launch_dir_in("/tmp", Some(seat), false, root.path()).unwrap();
            assert_eq!(got, root.path().join("tmp").to_string_lossy(), "{seat:?}");
        }
        let got = guard_launch_dir_in("/tmp", None, false, root.path()).unwrap();
        assert_eq!(got, root.path().join("tmp").to_string_lossy());
    }

    #[test]
    fn redirect_fails_loudly_when_target_cannot_be_created() {
        let root = tempfile::tempdir().unwrap();
        let blocker = root.path().join("file");
        std::fs::write(&blocker, "").unwrap();
        let err = guard_launch_dir_in("/tmp", Some("nuzi"), false, &blocker).unwrap_err();
        assert!(err.contains("could not be created"), "{err}");
    }
}
