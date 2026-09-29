//! Update checker and self-updater.
//!
//! The latest version is whatever the CDN release manifest says it is
//! ([`LATEST_MANIFEST_URL`]) — never GitHub. A `releases/latest` lookup or a
//! `git ls-remote` tag sort is polluted by candidate and test tags, so it can
//! name a build that was never published for download.
//!
//! Applying an update downloads the host's tarball, verifies its SHA-256
//! against the manifest, extracts exactly `hcom-<target>/hcom` from it, and
//! swaps the running executable in place, keeping the previous bytes next to it
//! as `<exe>.bak`. No downloaded script is ever executed, and a host with no
//! prebuilt artifact is told how to build from the release tag instead.
//!
//! Builds carrying the non-default `update-test-manifest` feature may read a
//! release rehearsal manifest instead, named by `HCOM_UPDATE_MANIFEST_URL`. The
//! override accepts that one manifest shape and refuses everything else, and a
//! default build does not read the variable at all.

use crate::paths::{FLAGS_DIR, atomic_write, hcom_path};
use anyhow::{Context, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const CHECK_INTERVAL: Duration = Duration::from_secs(86400); // 24 hours

/// Public CDN prefix serving the release manifest and every release archive.
pub(crate) const CDN_BASE_URL: &str = "https://cdn.ffc-w.com/hcom/releases/";

/// Release manifest naming the current stable version and its artifacts.
pub(crate) const LATEST_MANIFEST_URL: &str = "https://cdn.ffc-w.com/hcom/releases/latest.json";

/// Environment variable naming a release rehearsal manifest for hcom to read
/// instead of the production one. It is a test seam, not a configuration knob,
/// and it only exists in builds carrying the non-default
/// `update-test-manifest` feature — a release binary does not read it at all.
#[cfg(feature = "update-test-manifest")]
pub(crate) const TEST_MANIFEST_URL_ENV: &str = "HCOM_UPDATE_MANIFEST_URL";

/// The one manifest shape [`TEST_MANIFEST_URL_ENV`] may point at: the
/// rehearsal tag, which is published versioned and deliberately never lands in
/// `latest.json`. A release rehearsal therefore exercises the real update path
/// without moving the advertised latest version.
#[cfg(feature = "update-test-manifest")]
const TEST_MANIFEST_URL_PREFIX: &str = "https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test.";
#[cfg(feature = "update-test-manifest")]
const TEST_MANIFEST_URL_SUFFIX: &str = "/manifest.json";

/// Decide which manifest to read, from an optional environment override.
///
/// Takes the value as a parameter rather than reading the environment itself,
/// so the policy is testable in isolation from whatever the test process
/// happens to inherit.
///
/// Only the rehearsal manifest is honoured. Every other value — another host,
/// `latest.json`, a stable tag, a lookalike host — is refused outright rather
/// than quietly falling back to production, so a mistyped override can never
/// silently repoint the updater somewhere else.
#[cfg(feature = "update-test-manifest")]
pub(crate) fn manifest_url_from(override_value: Option<&str>) -> anyhow::Result<Cow<'static, str>> {
    let Some(candidate) = override_value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(Cow::Borrowed(LATEST_MANIFEST_URL));
    };

    let refused = || {
        anyhow::anyhow!(
            "{TEST_MANIFEST_URL_ENV} is set to {candidate:?}, which is not the release \
             rehearsal manifest this build accepts (expected \
             {TEST_MANIFEST_URL_PREFIX}<digits>{TEST_MANIFEST_URL_SUFFIX})"
        )
    };

    let Some(digits) = candidate
        .strip_prefix(TEST_MANIFEST_URL_PREFIX)
        .and_then(|rest| rest.strip_suffix(TEST_MANIFEST_URL_SUFFIX))
    else {
        return Err(refused());
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refused());
    }

    Ok(Cow::Owned(candidate.to_string()))
}

/// The default build has no override: [`LATEST_MANIFEST_URL`], always, and the
/// environment variable is not consulted even if it is set.
#[cfg(not(feature = "update-test-manifest"))]
pub(crate) fn manifest_url_from(
    _override_value: Option<&str>,
) -> anyhow::Result<Cow<'static, str>> {
    Ok(Cow::Borrowed(LATEST_MANIFEST_URL))
}

/// The manifest this process should read.
#[cfg(feature = "update-test-manifest")]
fn manifest_url() -> anyhow::Result<Cow<'static, str>> {
    manifest_url_from(std::env::var(TEST_MANIFEST_URL_ENV).ok().as_deref())
}

#[cfg(not(feature = "update-test-manifest"))]
fn manifest_url() -> anyhow::Result<Cow<'static, str>> {
    manifest_url_from(None)
}

/// Source repository, used only to tell someone how to build a release hcom
/// cannot install for them. Never queried to decide which version is latest.
pub(crate) const RELEASE_REPO: &str = "Michaelzag/hcom";

/// One release archive: where the publisher says it lives, and what its bytes
/// must hash to.
///
/// `url` is never fetched. It is read only to check that it names the one place
/// a release archive for this version can live — see [`release_archive_url`].
/// The publisher holds PutObject on the mutable channel pointers, so a manifest
/// is a document someone with that key can rewrite; obeying a URL in it would
/// make every host that reads it fetch wherever the rewriter chose.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Artifact {
    pub url: String,
    pub sha256: String,
}

/// A published release manifest.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Manifest {
    pub version: String,
    pub artifacts: BTreeMap<String, Artifact>,
}

/// What `hcom update` did.
#[derive(Debug)]
pub(crate) enum ApplyOutcome {
    /// The running executable was replaced; its previous bytes are at `backup`.
    Updated { version: String, backup: PathBuf },
    /// No prebuilt archive exists for this host. The caller prints
    /// [`source_guidance`] and exits nonzero without touching the binary.
    NoArtifact { platform: String, version: String },
}

/// Where release bytes come from. Injected so the update path is testable
/// without reaching the network.
pub(crate) trait Fetcher {
    fn get(&self, url: &str) -> anyhow::Result<Vec<u8>>;
}

/// The real fetcher: `curl`, with no redirects followed into failure and a
/// timeout so a hung CDN cannot wedge a command.
pub(crate) struct CurlFetcher;

impl Fetcher for CurlFetcher {
    fn get(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        let output = std::process::Command::new("curl")
            .args(["-fsSL", "--max-time", "60", url])
            .output()
            .with_context(|| format!("could not run curl to download {url}"))?;

        if !output.status.success() {
            bail!(
                "download of {url} failed (curl exit {})",
                output.status.code().unwrap_or(-1)
            );
        }
        Ok(output.stdout)
    }
}

pub(crate) fn flag_path() -> PathBuf {
    hcom_path(&[FLAGS_DIR, "update_check"])
}

/// Parse `X.Y.Z` or `vX.Y.Z` into a comparable tuple.
///
/// Strict: exactly three all-digit components. A pre-release suffix such as
/// `1.2.3-rc.1` or the release rehearsal tag `0.0.0-w3test.1` is rejected, so
/// those can never be mistaken for a published release.
fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let trimmed = v.trim();
    let rest = trimmed.strip_prefix('v').unwrap_or(trimmed);
    let mut parts = rest.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    for part in [major, minor, patch] {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    Some((
        major.parse().ok()?,
        minor.parse().ok()?,
        patch.parse().ok()?,
    ))
}

/// Whether `v` is a stable release tag, matching `^v[0-9]+\.[0-9]+\.[0-9]+$`.
///
/// The manifest carries stable releases only, so anything else in it means the
/// manifest is not what this client understands.
fn is_stable_tag(v: &str) -> bool {
    v.starts_with('v') && parse_version(v).is_some()
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The one URL a release archive for `version` and `target` can live at, built
/// from the fixed CDN base rather than read out of the manifest.
pub(crate) fn release_archive_url(version: &str, target: &str) -> String {
    format!("{CDN_BASE_URL}{version}/hcom-{target}.tar.gz")
}

/// Parse and validate a manifest body.
///
/// Every field this client acts on is checked, including the `url` each artifact
/// declares. A manifest is a published but *mutable* document — the publisher's
/// key can overwrite the channel pointers without any immutability refusal — so
/// the checks are about refusing a re-pointed manifest, not about parsing
/// trust. The digest is taken from the manifest because the manifest is the only
/// place the digest is published; the destination is derived here.
pub(crate) fn parse_manifest(body: &[u8]) -> anyhow::Result<Manifest> {
    let manifest: Manifest =
        serde_json::from_slice(body).context("release manifest is not valid JSON")?;

    if !is_stable_tag(&manifest.version) {
        bail!(
            "release manifest names version {:?}, which is not a stable vX.Y.Z release",
            manifest.version
        );
    }
    // Artifact names are the ones this client can act on. Anything carrying a
    // character outside printable ASCII, or a path separator, is refused rather
    // than normalized: a target triple is a fixed identifier, so a manifest
    // needing a lenient parse of one is not a manifest this client understands.
    for (target, artifact) in &manifest.artifacts {
        if !is_plain_ascii_identifier(target) {
            bail!(
                "release manifest names an artifact for {target:?}, which is not a plain target name"
            );
        }
        let expected = release_archive_url(&manifest.version, target);
        if artifact.url != expected {
            bail!(
                "release manifest points {target} at {:?}, but a release archive for {} must be at {expected:?}",
                artifact.url,
                manifest.version
            );
        }
        if !is_sha256_hex(&artifact.sha256) {
            bail!("release manifest has a malformed sha256 for {target}");
        }
    }

    Ok(manifest)
}

/// A target triple: printable ASCII, no separators, nothing that could name a
/// different path when it is formatted into a URL.
fn is_plain_ascii_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !s.starts_with('.')
        && s != ".."
}

pub(crate) fn fetch_manifest(fetcher: &dyn Fetcher) -> anyhow::Result<Manifest> {
    let url = manifest_url()?;
    let body = fetcher
        .get(&url)
        .with_context(|| format!("could not read the release manifest at {url}"))?;
    parse_manifest(&body)
}

/// Structured update information: the running version, the published one, and
/// how the two compare.
///
/// The comparison is a three-way relation rather than an "is there an update"
/// flag because the caller must act differently in all three cases: install a
/// newer release, do nothing for an equal one, and refuse an older one unless
/// the operator asked for it. A boolean cannot express the third, and
/// collapsing "equal" into "not available" is what made an `--allow-downgrade`
/// reinstall the version already running.
#[derive(Clone, Debug)]
pub(crate) struct UpdateInfo {
    pub current: String,
    pub latest: String,
    pub relation: VersionRelation,
}

/// The command that applies an available update. Reported verbatim by
/// `status --json` as `version.update_cmd`, so it must stay something a user
/// can actually run — never a sentence of prose.
pub(crate) const UPDATE_COMMAND: &str = "hcom update";

/// How to get a version hcom cannot install for you. Printed when the host has
/// no prebuilt archive, and when the manifest itself cannot be read.
pub(crate) fn source_guidance(version: Option<&str>) -> String {
    let clone = match version {
        Some(v) => format!(
            "git clone --branch v{} https://github.com/{RELEASE_REPO}.git",
            v.trim_start_matches('v')
        ),
        None => format!("git clone https://github.com/{RELEASE_REPO}.git"),
    };

    format!(
        "Install it from source instead:\n  {clone}\n  cd hcom && cargo build --release --locked\n\n\
         Release archives and the release manifest live at {CDN_BASE_URL}"
    )
}

/// Compare this build against an already-fetched manifest.
///
/// Takes the manifest rather than fetching one so a command can decide and
/// then install from a single read: announcing one version and installing
/// another would be worse than useless.
pub(crate) fn update_info(manifest: &Manifest) -> UpdateInfo {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let latest = manifest.version.trim_start_matches('v').to_string();
    let relation = compare_versions(&current, &latest);

    UpdateInfo {
        current,
        latest,
        relation,
    }
}

fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// How the manifest's version compares with the running build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VersionRelation {
    /// The published release is newer and is worth installing.
    Upgrade,
    /// The published release is exactly what is running.
    Same,
    /// The published release is OLDER than the running build. The channel
    /// pointer is mutable by the publisher, so this is the shape a re-pointed or
    /// rolled-back `latest.json` takes, and installing it would silently revert
    /// the host to older code.
    Downgrade,
}

pub(crate) fn compare_versions(current: &str, latest: &str) -> VersionRelation {
    match (parse_version(current), parse_version(latest)) {
        (Some(c), Some(l)) if l > c => VersionRelation::Upgrade,
        (Some(c), Some(l)) if l == c => VersionRelation::Same,
        (Some(_), Some(_)) => VersionRelation::Downgrade,
        // An unparseable version on either side is not evidence of anything, so
        // it is not treated as a downgrade attempt; update_info separately
        // refuses to act on it because is_newer is false.
        _ => VersionRelation::Same,
    }
}

/// Whether this build links the GNU C library, i.e. whether the published
/// `x86_64-unknown-linux-gnu` archive is a working replacement for the running
/// executable.
///
/// A musl-linked hcom launches fine on a musl host and would keep launching fine
/// if it were left alone, but the archive hcom publishes is glibc-linked: it
/// needs the GNU dynamic loader, which a musl-only host does not have. Installing
/// it there replaces a working binary with one that cannot start, so the musl
/// hosts are told how to build the tag from source instead. A musl *glibc*
/// (`x86_64-unknown-linux-musl` with a glibc target) is out of scope: hcom does
/// not ship such a build today, so there is no working binary to protect and
/// nothing to decide.
#[cfg(target_env = "musl")]
fn is_gnu_libc() -> bool {
    false
}

#[cfg(not(target_env = "musl"))]
fn is_gnu_libc() -> bool {
    true
}

/// Target triples hcom publishes release archives for.
///
/// Linux x86_64 only: every other host — aarch64 Linux included, and x86_64
/// musl — is told how to build the release tag instead of being pointed at an
/// archive that does not run there.
fn supported_target(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") if is_gnu_libc() => Some("x86_64-unknown-linux-gnu"),
        _ => None,
    }
}

/// Download, verify, extract and install the release named by `manifest`,
/// replacing `exe`.
///
/// The manifest is passed in rather than fetched here so the version the
/// caller announced and the version installed come from one read of one
/// document. Split out from [`apply_manifest`] so tests can point it at a
/// scratch file instead of a live installation.
pub(crate) fn apply_manifest_to(
    manifest: &Manifest,
    exe: &Path,
    os: &str,
    arch: &str,
    fetcher: &dyn Fetcher,
) -> anyhow::Result<ApplyOutcome> {
    let version = manifest.version.trim_start_matches('v').to_string();

    let Some(target) = supported_target(os, arch) else {
        return Ok(ApplyOutcome::NoArtifact {
            platform: format!("{arch}-{os}"),
            version,
        });
    };

    let Some(artifact) = manifest.artifacts.get(target) else {
        return Ok(ApplyOutcome::NoArtifact {
            platform: target.to_string(),
            version,
        });
    };

    let archive_url = release_archive_url(&manifest.version, target);
    let archive = fetcher
        .get(&archive_url)
        .with_context(|| format!("could not download {archive_url}"))?;
    verify_sha256(&archive, &artifact.sha256, &archive_url)?;

    let scratch = tempfile::tempdir().context("could not create a temporary directory")?;
    let binary = extract_binary(&archive, target, scratch.path())?;
    let backup = install_binary(&binary, exe)?;

    Ok(ApplyOutcome::Updated { version, backup })
}

/// Install the release named by `manifest` into the running executable.
pub(crate) fn apply_manifest(
    manifest: &Manifest,
    fetcher: &dyn Fetcher,
) -> anyhow::Result<ApplyOutcome> {
    let exe = std::env::current_exe().context("could not locate the running hcom executable")?;
    apply_manifest_to(
        manifest,
        &exe,
        std::env::consts::OS,
        std::env::consts::ARCH,
        fetcher,
    )
}

/// Lowercase hex SHA-256 of `bytes`.
fn hex_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Refuse to unpack anything whose bytes do not hash to what the manifest
/// promised. This is the only thing standing between a corrupted or swapped
/// download and a replaced executable.
fn verify_sha256(bytes: &[u8], expected: &str, url: &str) -> anyhow::Result<()> {
    let actual = hex_sha256(bytes);
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("{url} hashed to sha256 {actual}, manifest expects {expected}");
    }
    Ok(())
}

/// Extract exactly `hcom-<target>/hcom` from a release tarball.
///
/// Unpacking goes through the system `tar` (present on every supported host,
/// along with `curl`) and names the single member we want, so nothing else in
/// the archive — in particular no path escaping the temporary directory — is
/// ever written out.
fn extract_binary(archive: &[u8], target: &str, dest: &Path) -> anyhow::Result<PathBuf> {
    let tarball = dest.join("release.tar.gz");
    fs::write(&tarball, archive).context("could not stage the downloaded archive")?;

    let member = format!("hcom-{target}/hcom");
    let output = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(dest)
        .arg(&member)
        .output()
        .context("could not run tar to unpack the downloaded release")?;

    if !output.status.success() {
        bail!(
            "release archive does not contain {member} ({})",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let binary = dest.join(&member);
    // symlink_metadata does not follow links: is_file() is true for a symlink to
    // a regular file, and a member that is a link would have its target's bytes
    // copied over the live executable. The archive's URL is now derived rather
    // than read from the manifest, so this is defence in depth for a
    // second-order path rather than the primary defence.
    match fs::symlink_metadata(&binary) {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => bail!("release archive member {member} is not a regular file"),
        Err(e) => bail!("release archive did not unpack {member}: {e}"),
    }
    Ok(binary)
}

/// Replace `exe` with `new_binary`, keeping the old bytes at `<exe>.bak`.
///
/// The new bytes are staged next to the target first, because `rename` across a
/// filesystem boundary fails and a temporary directory usually is one. The
/// original is moved aside before the new file takes its place, so a failure
/// half way through leaves a restorable executable rather than none.
///
/// The staging and the swap happen under an exclusive lock beside the
/// executable. Two updates that overlap used to interleave here and could delete
/// each other's backup: one moved the live binary aside, the other's
/// `remove_file` on that same backup succeeded, and the first then restored it
/// into place — a single surviving backup, now the *new* binary, for two callers
/// that both reported success. The lock makes the read-swap-write of the pair
/// (`exe`, `<exe>.bak`) a single critical section instead.
fn install_binary(new_binary: &Path, exe: &Path) -> anyhow::Result<PathBuf> {
    let dir = exe
        .parent()
        .context("hcom executable has no parent directory")?;
    let name = exe
        .file_name()
        .context("hcom executable has no file name")?
        .to_string_lossy()
        .into_owned();

    let staged = dir.join(format!(".{name}.new-{}", std::process::id()));
    let backup = dir.join(format!("{name}.bak"));
    let lock_path = dir.join(format!(".{name}.update.lock"));

    // The lock lives beside the executable, not under HCOM_DIR: two hcom
    // instances (a seat's own HCOM_DIR, the system one) can share an install
    // directory while being mutually invisible, and they must still exclude each
    // other here. Released when `_lock` drops, including on the error path.
    let lock = std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("could not open {}", lock_path.display()))?;
    crate::sys::fs::lock_exclusive(&lock)
        .with_context(|| format!("could not lock {}", lock_path.display()))?;

    let result = (|| -> io::Result<()> {
        fs::copy(new_binary, &staged)?;
        set_executable(&staged)?;
        // Clear any previous backup first: rename onto an existing file is not
        // allowed everywhere hcom builds.
        let _ = fs::remove_file(&backup);
        fs::rename(exe, &backup)?;
        if let Err(e) = fs::rename(&staged, exe) {
            // Put the original back before reporting anything.
            let _ = fs::rename(&backup, exe);
            return Err(e);
        }
        Ok(())
    })();

    // A staged file left behind would shadow the real executable on some PATHs.
    let _ = fs::remove_file(&staged);
    drop(lock);
    result.with_context(|| format!("could not replace {}", exe.display()))?;

    Ok(backup)
}

#[cfg(unix)]
fn set_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Spawn a detached `hcom update --refresh-cache` to refresh the notice cache.
/// Returns immediately — the result shows up on a later command.
///
/// The refresh re-parses the release manifest in hcom's own code rather than in
/// a shell one-liner, so the cached version can only ever be a published
/// release.
fn spawn_background_check() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    // Only re-exec an actual hcom. Under a test harness `current_exe` is the
    // test binary, which would reject the flag and re-run the whole suite.
    let is_hcom = exe
        .file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|stem| stem.eq_ignore_ascii_case("hcom"));
    if !is_hcom {
        return;
    }

    let _ = std::process::Command::new(exe)
        .arg("update")
        .arg("--refresh-cache")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Refresh the cached "update available" version from the release manifest.
///
/// Run detached by [`get_update_info`]. Writes the version when the manifest is
/// ahead of this build, an empty file otherwise.
pub(crate) fn refresh_update_cache() -> anyhow::Result<()> {
    let flag = flag_path();

    let latest = match fetch_manifest(&CurlFetcher) {
        Ok(manifest) => manifest.version.trim_start_matches('v').to_string(),
        Err(_) => {
            // An unreadable manifest is not evidence that a known-good notice is
            // stale, so keep what is cached — but rewrite it so the mtime moves
            // and the next retry is a day away, not the next command.
            let cached = fs::read_to_string(&flag).unwrap_or_default();
            let _ = atomic_write(&flag, &cached);
            return Ok(());
        }
    };

    let ahead = is_newer(env!("CARGO_PKG_VERSION"), &latest);
    atomic_write(&flag, if ahead { latest.as_str() } else { "" })
        .then_some(())
        .context("could not write the update-check cache")
}

/// The cached latest version, or None when this build is up to date.
///
/// Never blocks: if the cache is stale it spawns a background refresh and
/// returns the current (possibly stale) cached result.
pub fn get_update_info() -> Option<String> {
    let flag = flag_path();

    let should_check = match flag.metadata().and_then(|m| m.modified()) {
        Ok(mtime) => {
            SystemTime::now()
                .duration_since(mtime)
                .unwrap_or(Duration::ZERO)
                > CHECK_INTERVAL
        }
        Err(_) => true,
    };

    if should_check {
        spawn_background_check();
    }

    let latest = fs::read_to_string(&flag).ok()?.trim().to_string();
    if latest.is_empty() {
        return None;
    }

    // Double-check, so a manual upgrade silences the notice.
    if !is_newer(env!("CARGO_PKG_VERSION"), &latest) {
        atomic_write(&flag, "");
        return None;
    }

    Some(latest)
}

/// Return update notice string for stderr, or None if up to date.
pub fn get_update_notice() -> Option<String> {
    let latest = get_update_info()?;
    Some(format!(
        "→ hcom v{latest} available — run `{UPDATE_COMMAND}`"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "x86_64-unknown-linux-gnu";

    /// Serves canned bytes per URL and records every request, so a test can
    /// assert not just what was fetched but how many times.
    struct MockFetcher {
        responses: BTreeMap<String, Vec<u8>>,
        requested: std::cell::RefCell<Vec<String>>,
    }

    impl MockFetcher {
        fn new() -> Self {
            Self {
                responses: BTreeMap::new(),
                requested: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn with(mut self, url: impl Into<String>, body: Vec<u8>) -> Self {
            self.responses.insert(url.into(), body);
            self
        }

        fn requested(&self) -> Vec<String> {
            self.requested.borrow().clone()
        }
    }

    impl Fetcher for MockFetcher {
        fn get(&self, url: &str) -> anyhow::Result<Vec<u8>> {
            self.requested.borrow_mut().push(url.to_string());
            self.responses
                .get(url)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no canned response for {url}"))
        }
    }

    /// A fetcher that can reach nothing.
    struct DeadFetcher;

    impl Fetcher for DeadFetcher {
        fn get(&self, url: &str) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("network is unreachable: {url}"))
        }
    }

    /// Build a release tarball containing `hcom-<target>/hcom`, the way the
    /// release workflow lays it out.
    fn release_tarball(target: &str, contents: &[u8]) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let member_dir = dir.path().join(format!("hcom-{target}"));
        fs::create_dir_all(&member_dir).unwrap();
        fs::write(member_dir.join("hcom"), contents).unwrap();

        let tarball = dir.path().join("release.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(dir.path())
            .arg(format!("hcom-{target}"))
            .status()
            .expect("tar is required to build and unpack release archives");
        assert!(status.success(), "failed to build test tarball");

        fs::read(&tarball).unwrap()
    }

    /// A manifest in the published shape, pointing at a fetcher-served archive.
    fn manifest_json(version: &str, target: &str, sha256: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": version,
            "artifacts": {
                target: {
                    "url": format!("{CDN_BASE_URL}{version}/hcom-{target}.tar.gz"),
                    "sha256": sha256,
                }
            }
        }))
        .unwrap()
    }

    /// The same manifest, already parsed — what a command holds between
    /// deciding and installing.
    fn manifest(version: &str, target: &str, sha256: &str) -> Manifest {
        parse_manifest(&manifest_json(version, target, sha256)).unwrap()
    }

    fn archive_url(version: &str, target: &str) -> String {
        format!("{CDN_BASE_URL}{version}/hcom-{target}.tar.gz")
    }

    #[test]
    fn hex_sha256_matches_published_vector() {
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn parse_version_accepts_only_stable_triples() {
        assert_eq!(parse_version("0.7.48"), Some((0, 7, 48)));
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("bad"), None);
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("v1.2.3-rc.1"), None);
        assert_eq!(parse_version("v0.0.0-w3test.1"), None);
        assert_eq!(parse_version("v1..3"), None);
    }

    #[test]
    fn manifest_rejects_release_rehearsal_tag() {
        // A test tag is versioned-only and must never reach latest.json; if one
        // does, the client refuses it rather than offering an unpublished build.
        let body = manifest_json("v0.0.0-w3test.1", TARGET, &"a".repeat(64));
        let err = parse_manifest(&body).unwrap_err().to_string();
        assert!(err.contains("stable"), "unexpected error: {err}");
    }

    #[test]
    fn manifest_whose_url_points_elsewhere_is_refused_not_obeyed() {
        // The publish key can overwrite the mutable channel pointers, so a
        // manifest is a document someone can rewrite. The url it names is
        // checked against the one place a release archive for this version can
        // live; a mismatch aborts instead of becoming the fetch target.
        let good = r#"{"version":"v1.2.3","artifacts":{"x86_64-unknown-linux-gnu":{
            "url":"https://cdn.ffc-w.com/hcom/releases/v1.2.3/hcom-x86_64-unknown-linux-gnu.tar.gz",
            "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#;
        parse_manifest(good.as_bytes()).expect("the canonical url is accepted");

        for hostile in [
            // another host entirely
            r#"{"version":"v1.2.3","artifacts":{"x86_64-unknown-linux-gnu":{
                "url":"https://evil.example/hcom.tar.gz",
                "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#,
            // plain http downgrade of the scheme
            r#"{"version":"v1.2.3","artifacts":{"x86_64-unknown-linux-gnu":{
                "url":"http://cdn.ffc-w.com/hcom/releases/v1.2.3/hcom-x86_64-unknown-linux-gnu.tar.gz",
                "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#,
            // a path traversal out of the release prefix
            r#"{"version":"v1.2.3","artifacts":{"x86_64-unknown-linux-gnu":{
                "url":"https://cdn.ffc-w.com/hcom/releases/v1.2.3/../../../etc/passwd",
                "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#,
            // a well-formed url for a DIFFERENT version than the one declared
            r#"{"version":"v1.2.3","artifacts":{"x86_64-unknown-linux-gnu":{
                "url":"https://cdn.ffc-w.com/hcom/releases/v9.9.9/hcom-x86_64-unknown-linux-gnu.tar.gz",
                "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#,
            // a lookalike host
            r#"{"version":"v1.2.3","artifacts":{"x86_64-unknown-linux-gnu":{
                "url":"https://cdn.ffc-w.com.evil.test/hcom/releases/v1.2.3/hcom-x86_64-unknown-linux-gnu.tar.gz",
                "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#,
        ] {
            let err = parse_manifest(hostile.as_bytes()).unwrap_err().to_string();
            assert!(
                err.contains("must be at"),
                "a re-pointed url must be refused by name, got: {err}"
            );
        }
    }

    #[test]
    fn manifest_with_an_odd_artifact_name_is_refused() {
        // A target triple is a fixed identifier. One carrying a separator or a
        // non-ASCII character is not parsed leniently, because formatting it
        // into a URL would name a different path.
        for target in [
            "a/b",
            "..",
            ".hidden",
            "x86_64 unknown-linux-gnu",
            "ünïcode",
        ] {
            let body = serde_json::to_vec(&serde_json::json!({
                "version": "v1.2.3",
                "artifacts": {
                    target: {
                        "url": format!("{CDN_BASE_URL}v1.2.3/hcom-x86_64-unknown-linux-gnu.tar.gz"),
                        "sha256": "a".repeat(64),
                    }
                }
            }))
            .unwrap();
            let err = parse_manifest(&body).unwrap_err().to_string();
            assert!(
                err.contains("not a plain target name"),
                "artifact name {target:?} must be refused, got: {err}"
            );
        }
    }

    #[test]
    fn version_relation_separates_upgrade_same_and_downgrade() {
        assert_eq!(
            compare_versions("0.7.49", "0.7.50"),
            VersionRelation::Upgrade
        );
        assert_eq!(compare_versions("0.7.50", "0.7.50"), VersionRelation::Same);
        assert_eq!(
            compare_versions("0.7.50", "0.7.49"),
            VersionRelation::Downgrade
        );
        // A big jump back is still a downgrade, not an upgrade.
        assert_eq!(
            compare_versions("1.0.0", "0.1.0"),
            VersionRelation::Downgrade
        );
        // Unparseable on either side is not a downgrade verdict; update_info
        // separately refuses to act on it.
        assert_eq!(compare_versions("0.7.50", "garbage"), VersionRelation::Same);
    }

    /// A tarball whose single member is a symlink, not a regular file.
    #[cfg(unix)]
    fn symlinked_release_tarball(target: &str, link_to: &str) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let member_dir = dir.path().join(format!("hcom-{target}"));
        fs::create_dir_all(&member_dir).unwrap();
        std::os::unix::fs::symlink(link_to, member_dir.join("hcom")).unwrap();

        let tarball = dir.path().join("release.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(dir.path())
            .arg(format!("hcom-{target}"))
            .status()
            .expect("tar is required to build and unpack release archives");
        assert!(status.success(), "failed to build test tarball");
        fs::read(&tarball).unwrap()
    }

    #[test]
    #[cfg(unix)]
    // A musl build refuses the glibc archive by design, so this test's
    // premise - that the request reaches the download on linux/x86_64 - does
    // not hold there. The refusal itself is covered by
    // a_musl_build_will_not_replace_itself_with_a_glibc_archive.
    #[cfg_attr(
        target_env = "musl",
        ignore = "glibc-only: refused before the download"
    )]
    fn a_symlinked_release_member_is_refused_not_installed() {
        // -f / is_file() is true for a symlink to a regular file, so the target's
        // bytes would be copied over the live executable. The archive's URL is
        // derived rather than read from the manifest, which makes this
        // defence in depth, but the extraction step is the last place to catch
        // it and it costs one metadata call.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hcom");
        fs::write(&exe, b"old executable bytes").unwrap();
        let secret = dir.path().join("secret");
        fs::write(&secret, b"not the release binary").unwrap();

        let archive = symlinked_release_tarball(TARGET, secret.to_str().unwrap());
        let manifest = manifest("v1.2.3", TARGET, &hex_sha256(&archive));
        let fetcher = MockFetcher::new().with(archive_url("v1.2.3", TARGET), archive);

        let err = apply_manifest_to(&manifest, &exe, "linux", "x86_64", &fetcher)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not a regular file"),
            "a symlinked member must be refused by name, got: {err}"
        );
        assert_eq!(
            fs::read(&exe).unwrap(),
            b"old executable bytes",
            "the live executable must be untouched"
        );
    }

    #[test]
    // A musl build refuses the glibc archive by design, so this test's
    // premise - that a real install happens on linux/x86_64 - does not
    // hold there. The refusal itself is covered by
    // a_musl_build_will_not_replace_itself_with_a_glibc_archive.
    #[cfg_attr(target_env = "musl", ignore = "glibc-only install test")]
    fn the_download_goes_to_the_derived_url_not_the_manifests() {
        // The manifest's url is checked, then ignored. This pins the property
        // that matters: the only URL requested is the one this client derived.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hcom");
        fs::write(&exe, b"old executable bytes").unwrap();

        let archive = release_tarball(TARGET, b"new executable bytes");
        let sha = hex_sha256(&archive);
        // A manifest whose url is the canonical one, so it is accepted.
        let manifest = manifest("v1.2.3", TARGET, &sha);
        let expected = release_archive_url("v1.2.3", TARGET);
        let fetcher = MockFetcher::new().with(expected.clone(), archive);
        // Anything else is absent from the mock, so a request for it errors.

        apply_manifest_to(&manifest, &exe, "linux", "x86_64", &fetcher).unwrap();
        assert_eq!(fetcher.requested(), vec![expected]);
    }

    #[test]
    fn an_equal_version_is_never_an_install() {
        // `--allow-downgrade` permits stepping BACK. It is not a reinstall
        // switch: reinstalling the running version would overwrite hcom.bak -
        // the only copy of the previous release - with the version already
        // running, destroying the rollback path for nothing.
        let current = env!("CARGO_PKG_VERSION");
        let same = manifest(&format!("v{current}"), TARGET, &"a".repeat(64));
        assert_eq!(
            compare_versions(current, current),
            VersionRelation::Same,
            "the running version against itself is Same, never Downgrade"
        );
        // And the same manifest is not something update_info calls available,
        // so the up-to-date path is the one that runs.
        let info = update_info(&same);
        assert_eq!(info.relation, VersionRelation::Same);
        assert_eq!(info.latest, info.current);
    }

    #[test]
    fn manifest_rejects_malformed_sha256() {
        let body = manifest_json("v1.2.3", TARGET, "not-a-hash");
        let err = parse_manifest(&body).unwrap_err().to_string();
        assert!(err.contains("sha256"), "unexpected error: {err}");
    }

    /// A manifest generated verbatim by the release builder that publishes it
    /// (CT170 `hcom-release.py`: `build_manifest_document` + `canonical_json`)
    /// and checked in, so this client is exercised against the bytes the
    /// publisher really writes rather than a hand-written approximation of
    /// them. `test_hcom_release.py::test_the_golden_manifest_format_hcom_parses`
    /// guards the other half of the same agreement.
    const BUILDER_MANIFEST: &str = include_str!("../tests/fixtures/release-manifest.json");

    #[test]
    fn the_checked_in_builder_manifest_is_canonical_and_parses() {
        // A Windows checkout can rewrite this LF file as CRLF, and the bytes the
        // publisher emits are the LF ones. Normalize the checkout, not the
        // expectation.
        let checked_in = BUILDER_MANIFEST.replace("\r\n", "\n");
        // serde_json's Map is sorted by default and its pretty printer uses two
        // spaces, so this is the builder's canonical_json byte for byte. Drift
        // in the publisher's serialization fails here instead of leaving a
        // fixture that describes a format nothing publishes any more.
        let value: serde_json::Value = serde_json::from_str(&checked_in).unwrap();
        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
            checked_in,
            "the checked-in fixture is not canonical JSON"
        );

        let parsed = parse_manifest(checked_in.as_bytes())
            .expect("the published manifest shape must be one this client accepts");
        assert_eq!(parsed.version, "v99.0.0");

        let artifact = parsed.artifacts.get(TARGET).expect("the linux artifact");
        assert_eq!(
            artifact.url,
            "https://cdn.ffc-w.com/hcom/releases/v99.0.0/hcom-x86_64-unknown-linux-gnu.tar.gz"
        );
        // The digest in the fixture is sha256 of the tarball NAME, which is how
        // the fixture is reproducible from a file instead of a build.
        assert_eq!(
            hex_sha256(b"hcom-x86_64-unknown-linux-gnu.tar.gz"),
            artifact.sha256
        );

        let info = update_info(&parsed);
        assert_eq!(
            info.relation,
            VersionRelation::Upgrade,
            "the golden fixture must name a release newer than this build"
        );
    }

    #[test]
    fn manifest_exposes_artifact_for_target() {
        let sha = "b".repeat(64);
        let body = manifest_json("v1.2.3", TARGET, &sha);
        let manifest = parse_manifest(&body).unwrap();
        assert_eq!(manifest.version, "v1.2.3");
        let artifact = manifest.artifacts.get(TARGET).unwrap();
        assert_eq!(artifact.sha256, sha);
        assert_eq!(artifact.url, archive_url("v1.2.3", TARGET));
    }

    #[test]
    fn source_guidance_names_tag_and_cdn() {
        let guidance = source_guidance(Some("1.2.3"));
        assert!(guidance.contains("--branch v1.2.3"), "{guidance}");
        assert!(
            guidance.contains("cargo build --release --locked"),
            "{guidance}"
        );
        assert!(guidance.contains(CDN_BASE_URL), "{guidance}");

        let unversioned = source_guidance(None);
        assert!(unversioned.contains(CDN_BASE_URL), "{unversioned}");
    }

    #[test]
    fn supported_targets_are_linux_x86_64_only() {
        // aarch64 Linux is deliberately not a release target: it gets source
        // instructions rather than a binary that was never published.
        assert_eq!(supported_target("linux", "aarch64"), None);
        assert_eq!(supported_target("macos", "aarch64"), None);
        assert_eq!(supported_target("macos", "x86_64"), None);
        assert_eq!(supported_target("windows", "x86_64"), None);
        assert_eq!(supported_target("linux", "riscv64"), None);

        // The one host that shares the release target's arch and os but may
        // still not be able to run its archive. Written to hold whichever libc
        // this test binary is linked against, so a musl-targeted run exercises
        // the refusal instead of failing on an unconditional Some.
        assert_eq!(
            supported_target("linux", "x86_64"),
            if cfg!(target_env = "musl") {
                None
            } else {
                Some(TARGET)
            },
            "x86_64 support must follow the libc this build actually links"
        );
    }

    #[test]
    fn a_musl_build_will_not_replace_itself_with_a_glibc_archive() {
        // The archive is glibc-linked. On a musl host that lacks the GNU loader
        // installing it leaves a binary that cannot start, so the swap must not
        // happen and nothing may be downloaded.
        if !cfg!(target_env = "musl") {
            return; // nothing to protect on a glibc test binary
        }
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hcom");
        fs::write(&exe, b"old musl executable bytes").unwrap();

        let sha = "f".repeat(64);
        let manifest = manifest("v1.2.3", TARGET, &sha);
        let fetcher = MockFetcher::new();

        let outcome = apply_manifest_to(&manifest, &exe, "linux", "x86_64", &fetcher).unwrap();
        assert!(
            matches!(outcome, ApplyOutcome::NoArtifact { .. }),
            "a musl build must not install a glibc archive"
        );
        assert_eq!(fs::read(&exe).unwrap(), b"old musl executable bytes");
        assert!(
            fetcher.requested().is_empty(),
            "the archive must not even be downloaded"
        );
    }

    #[test]
    // A musl build refuses the glibc archive by design, so this test's
    // premise - that a real install happens on linux/x86_64 - does not
    // hold there. The refusal itself is covered by
    // a_musl_build_will_not_replace_itself_with_a_glibc_archive.
    #[cfg_attr(target_env = "musl", ignore = "glibc-only install test")]
    fn apply_installs_verified_binary_and_keeps_exact_old_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hcom");
        fs::write(&exe, b"old executable bytes").unwrap();

        let archive = release_tarball(TARGET, b"new executable bytes");
        let manifest = manifest("v1.2.3", TARGET, &hex_sha256(&archive));
        let fetcher = MockFetcher::new().with(archive_url("v1.2.3", TARGET), archive);

        let outcome = apply_manifest_to(&manifest, &exe, "linux", "x86_64", &fetcher).unwrap();
        let ApplyOutcome::Updated { version, backup } = outcome else {
            panic!("expected the binary to be replaced");
        };
        assert_eq!(version, "1.2.3");
        assert_eq!(backup, dir.path().join("hcom.bak"));

        assert_eq!(fs::read(&exe).unwrap(), b"new executable bytes");
        assert_eq!(fs::read(&backup).unwrap(), b"old executable bytes");

        // The staging file must not survive, and nothing else may be left over.
        // The install lock is the one expected resident: it is deliberately
        // never deleted, because removing a path another process may hold locked
        // lets the next install lock a fresh inode and stop excluding anybody.
        let leftovers: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "hcom" && name != "hcom.bak" && name != ".hcom.update.lock")
            .collect();
        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    #[test]
    // A musl build refuses the glibc archive by design, so this test's
    // premise - that a real install happens on linux/x86_64 - does not
    // hold there. The refusal itself is covered by
    // a_musl_build_will_not_replace_itself_with_a_glibc_archive.
    #[cfg_attr(target_env = "musl", ignore = "glibc-only install test")]
    fn apply_downloads_only_the_archive_from_the_manifest_it_was_given() {
        // The version hcom announces and the version it installs must come from
        // one read of one document: applying must not go back to the network
        // for the manifest.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hcom");
        fs::write(&exe, b"old executable bytes").unwrap();

        let archive = release_tarball(TARGET, b"new executable bytes");
        let sha = hex_sha256(&archive);
        let manifest = manifest("v1.2.3", TARGET, &sha);
        let fetcher = MockFetcher::new()
            // The manifest is served too, so a re-read would succeed quietly
            // instead of erroring — only the request log below can catch it.
            .with(LATEST_MANIFEST_URL, manifest_json("v1.2.3", TARGET, &sha))
            .with(archive_url("v1.2.3", TARGET), archive);

        apply_manifest_to(&manifest, &exe, "linux", "x86_64", &fetcher).unwrap();

        assert_eq!(
            fetcher.requested(),
            vec![archive_url("v1.2.3", TARGET)],
            "apply must fetch the archive only, never the manifest"
        );
    }

    #[test]
    // A musl build refuses the glibc archive by design, so this test's
    // premise - that the request reaches the download on linux/x86_64 - does
    // not hold there. The refusal itself is covered by
    // a_musl_build_will_not_replace_itself_with_a_glibc_archive.
    #[cfg_attr(
        target_env = "musl",
        ignore = "glibc-only: refused before the download"
    )]
    fn apply_refuses_archive_that_does_not_match_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hcom");
        fs::write(&exe, b"old executable bytes").unwrap();

        let archive = release_tarball(TARGET, b"tampered bytes");
        let manifest = manifest("v1.2.3", TARGET, &"c".repeat(64));
        let fetcher = MockFetcher::new().with(archive_url("v1.2.3", TARGET), archive);

        let err = apply_manifest_to(&manifest, &exe, "linux", "x86_64", &fetcher)
            .unwrap_err()
            .to_string();

        assert!(err.contains("manifest expects"), "unexpected error: {err}");
        assert_eq!(fs::read(&exe).unwrap(), b"old executable bytes");
        assert!(!dir.path().join("hcom.bak").exists());
    }

    #[test]
    fn two_installs_into_one_directory_never_lose_the_only_backup() {
        // Two updates racing on one install directory used to interleave inside
        // install_binary: A moves the live binary to hcom.bak, B deletes that
        // same file, and A then restores it into place. Both report success, and
        // the surviving "previous binary" is B's new bytes — so hcom.bak is a
        // copy of what is installed and the original is gone. The install holds
        // an exclusive lock, so the pair (exe, hcom.bak) is only ever written by
        // one caller at a time.
        //
        // This is a race, so it is stressed across rounds rather than asserted
        // once: a single round can pass even on the unlocked code. What must hold
        // on every round is the invariant, not the ordering.
        for round in 0..25 {
            let dir = tempfile::tempdir().unwrap();
            let exe = dir.path().join("hcom");
            let incoming_a = dir.path().join("incoming-a");
            let incoming_b = dir.path().join("incoming-b");
            fs::write(&exe, b"original bytes").unwrap();
            fs::write(&incoming_a, b"update A bytes").unwrap();
            fs::write(&incoming_b, b"update B bytes").unwrap();

            let spawn = |source: PathBuf| {
                let exe = exe.clone();
                std::thread::spawn(move || install_binary(&source, &exe))
            };
            let a = spawn(incoming_a);
            let b = spawn(incoming_b);
            a.join().unwrap().unwrap();
            b.join().unwrap().unwrap();

            let live = fs::read(&exe).unwrap();
            let kept = fs::read(dir.path().join("hcom.bak")).unwrap();
            assert_ne!(
                kept, live,
                "round {round}: the backup is a copy of the live binary, so an \
                 interleaved install destroyed the only restorable copy"
            );
            for bytes in [&live, &kept] {
                assert!(
                    matches!(
                        bytes.as_slice(),
                        b"original bytes" | b"update A bytes" | b"update B bytes"
                    ),
                    "round {round}: an install produced bytes nobody handed it: {bytes:?}"
                );
            }
            // No staging file is left behind: a stray one shadows the real
            // executable on some PATHs.
            let strays: Vec<String> = fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains(".new-"))
                .collect();
            assert!(
                strays.is_empty(),
                "round {round}: staging files left: {strays:?}"
            );
        }
    }

    #[test]
    fn fetch_manifest_reports_unreachable_without_falling_back() {
        // Guidance is the command's to print; the update module's job here is
        // to fail rather than quietly check a different document.
        let err = fetch_manifest(&DeadFetcher).unwrap_err().to_string();
        assert!(err.contains(LATEST_MANIFEST_URL), "unexpected error: {err}");

        // And the guidance the command pairs it with must be actionable.
        let guidance = source_guidance(None);
        assert!(guidance.contains(CDN_BASE_URL), "{guidance}");
        assert!(
            guidance.contains("cargo build --release --locked"),
            "{guidance}"
        );
    }

    #[test]
    fn update_info_compares_a_manifest_against_this_build() {
        let ahead = update_info(&manifest("v99.0.0", TARGET, &"a".repeat(64)));
        assert_eq!(ahead.relation, VersionRelation::Upgrade);
        assert_eq!(ahead.latest, "99.0.0");
        assert_eq!(ahead.current, env!("CARGO_PKG_VERSION"));

        let behind = update_info(&manifest("v0.0.1", TARGET, &"a".repeat(64)));
        assert_eq!(
            behind.relation,
            VersionRelation::Downgrade,
            "an older release is a downgrade, not an update"
        );
    }

    #[test]
    fn apply_reports_no_artifact_for_unsupported_platform() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hcom");
        fs::write(&exe, b"old executable bytes").unwrap();

        let sha = "d".repeat(64);
        let manifest = manifest("v1.2.3", TARGET, &sha);
        let fetcher = MockFetcher::new();

        let outcome = apply_manifest_to(&manifest, &exe, "macos", "aarch64", &fetcher).unwrap();
        let ApplyOutcome::NoArtifact { platform, version } = outcome else {
            panic!("expected no-artifact guidance, not a binary swap");
        };
        assert_eq!(platform, "aarch64-macos");
        assert_eq!(version, "1.2.3");
        assert_eq!(fs::read(&exe).unwrap(), b"old executable bytes");
        assert!(
            fetcher.requested().is_empty(),
            "an unsupported host must not download anything"
        );
    }

    #[test]
    // A musl build refuses the glibc archive by design, so this test's
    // premise - that the request reaches the download on linux/x86_64 - does
    // not hold there. The refusal itself is covered by
    // a_musl_build_will_not_replace_itself_with_a_glibc_archive.
    #[cfg_attr(
        target_env = "musl",
        ignore = "glibc-only: refused before the download"
    )]
    fn apply_reports_no_artifact_when_target_is_missing_from_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hcom");
        fs::write(&exe, b"old executable bytes").unwrap();

        let sha = "e".repeat(64);
        let manifest = manifest("v1.2.3", "aarch64-unknown-linux-gnu", &sha);
        let fetcher = MockFetcher::new();

        let outcome = apply_manifest_to(&manifest, &exe, "linux", "x86_64", &fetcher).unwrap();
        let ApplyOutcome::NoArtifact { platform, .. } = outcome else {
            panic!("expected no-artifact guidance, not a binary swap");
        };
        assert_eq!(platform, TARGET);
        assert_eq!(fs::read(&exe).unwrap(), b"old executable bytes");
    }

    #[test]
    fn newer_only_counts_published_higher_versions() {
        assert!(is_newer("0.7.48", "0.7.49"));
        assert!(is_newer("0.7.48", "1.0.0"));
        assert!(!is_newer("0.7.48", "0.7.48"));
        assert!(!is_newer("1.0.0", "0.7.48"));
        assert!(!is_newer("0.7.48", "not-a-version"));
    }

    // The default build has no override at all: the environment variable is
    // never consulted, so a release binary cannot be repointed by it.
    #[cfg(not(feature = "update-test-manifest"))]
    #[test]
    fn default_build_ignores_the_manifest_override() {
        let unset = manifest_url_from(None).unwrap();
        assert_eq!(
            &*unset, LATEST_MANIFEST_URL,
            "an unset override must not change the manifest"
        );
        // Even the legitimate rehearsal URL is ignored without the feature.
        let rehearsal = manifest_url_from(Some(
            "https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test.1/manifest.json",
        ))
        .unwrap();
        assert_eq!(&*rehearsal, LATEST_MANIFEST_URL);
        let other = manifest_url_from(Some("https://example.invalid/manifest.json")).unwrap();
        assert_eq!(&*other, LATEST_MANIFEST_URL);
    }

    #[cfg(feature = "update-test-manifest")]
    #[test]
    fn unset_override_reads_the_production_manifest() {
        for unset in [None, Some(""), Some("   ")] {
            assert_eq!(&*manifest_url_from(unset).unwrap(), LATEST_MANIFEST_URL);
        }
    }

    #[cfg(feature = "update-test-manifest")]
    #[test]
    fn rehearsal_manifest_override_is_honored() {
        // The rehearsal tag is versioned and never lands in latest.json, so
        // pointing at it exercises the real update path without moving the
        // advertised latest version.
        let rehearsal = "https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test.1/manifest.json";
        let chosen = manifest_url_from(Some(rehearsal)).unwrap();
        assert_eq!(&*chosen, rehearsal);

        let padded = " https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test.42/manifest.json ";
        let chosen = manifest_url_from(Some(padded)).unwrap();
        assert_eq!(
            &*chosen, "https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test.42/manifest.json",
            "surrounding whitespace is not a reason to reject a valid URL"
        );
    }

    #[cfg(feature = "update-test-manifest")]
    #[test]
    fn every_other_override_is_refused() {
        for refused in [
            // The production manifest itself: an override is only for rehearsals.
            LATEST_MANIFEST_URL,
            "https://cdn.ffc-w.com/hcom/releases/v0.7.49/manifest.json",
            // Not the rehearsal tag prefix.
            "https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test/manifest.json",
            // Missing or non-numeric rehearsal counter.
            "https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test./manifest.json",
            "https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test.beta/manifest.json",
            // Not the manifest filename.
            "https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test.1/latest.json",
            "https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test.1/manifest.json.sig",
            // Lookalike host, plain http, and a path prefix.
            "https://cdn.ffc-w.com.evil.test/hcom/releases/v0.0.0-w3test.1/manifest.json",
            "http://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test.1/manifest.json",
            "https://evil.test/hcom/releases/v0.0.0-w3test.1/manifest.json",
            "https://cdn.ffc-w.com/other/v0.0.0-w3test.1/manifest.json",
            // A URL with a query or fragment is a different resource.
            "https://cdn.ffc-w.com/hcom/releases/v0.0.0-w3test.1/manifest.json?x=1",
            // Not a URL at all.
            "file:///tmp/manifest.json",
        ] {
            let err = manifest_url_from(Some(refused)).unwrap_err().to_string();
            assert!(
                err.contains(TEST_MANIFEST_URL_ENV),
                "refusal for {refused} must name the variable, got: {err}"
            );
        }
    }
}
