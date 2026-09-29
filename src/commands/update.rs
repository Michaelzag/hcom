//! `hcom update` command — check and apply updates.
//!
//! The latest version comes from the CDN release manifest, and applying an
//! update downloads, hash-checks and unpacks the release archive for this
//! host. No downloaded installer is ever executed. Hosts with no prebuilt
//! archive are told how to build the release tag from source instead.

use crate::db::HcomDb;
use crate::shared::CommandContext;
use crate::update::{ApplyOutcome, CurlFetcher};

#[derive(clap::Parser, Debug)]
#[command(name = "update", about = "Check for and apply updates")]
pub struct UpdateArgs {
    /// Only check — print update status without applying
    #[arg(long)]
    pub check: bool,

    /// Refresh the cached update notice in the background and exit.
    /// Spawned by hcom itself; hidden because it is not a user interface.
    #[arg(long, hide = true)]
    pub refresh_cache: bool,

    /// Install a published release that is OLDER than the running build.
    /// Needed to step back to a known-good version on purpose; without it a
    /// rolled-back or re-pointed channel is refused rather than obeyed.
    #[arg(long)]
    pub allow_downgrade: bool,
}

fn print_dev_root_notice(db: &HcomDb) {
    if let Some((path, source)) = crate::router::resolve_effective_dev_root(db.path()) {
        println!("Using local build: {} [{}]", path.display(), source);
        println!("`hcom update` bypasses dev_root and updates the binary you invoked.");
        println!("The local checkout is not changed.");
        println!();
    }
}

pub fn cmd_update(_db: &HcomDb, args: &UpdateArgs, _ctx: Option<&CommandContext>) -> i32 {
    if args.refresh_cache {
        return if crate::update::refresh_update_cache().is_ok() {
            0
        } else {
            1
        };
    }

    println!("Checking for updates...");
    print_dev_root_notice(_db);

    // One read of one manifest decides and installs. Fetching again to apply
    // could announce one version and install another.
    let manifest = match crate::update::fetch_manifest(&CurlFetcher) {
        Ok(manifest) => manifest,
        Err(e) => {
            eprintln!("Error: {e:#}");
            eprintln!();
            eprintln!("{}", crate::update::source_guidance(None));
            return 1;
        }
    };
    let info = crate::update::update_info(&manifest);
    use crate::update::VersionRelation::{Downgrade, Same, Upgrade};
    let relation = info.relation;

    // An EQUAL version is not an install. `--allow-downgrade` exists to permit
    // stepping back to an older release; it is not a reinstall switch, and
    // treating it as one would overwrite `hcom.bak` — the only copy of the
    // previous release — with the very version already running.
    if relation == Same {
        println!("hcom v{} is up to date", info.current);
        let _ = crate::paths::atomic_write(&crate::update::flag_path(), "");
        return 0;
    }

    // The channel pointer is mutable by whoever holds the publish key, so a
    // manifest naming an OLDER release than the one running is refused by
    // default: obeying it would revert the host on every host at once. Stepping
    // back on purpose is a separate, explicit act.
    if relation == Downgrade && !args.allow_downgrade {
        eprintln!(
            "Refusing to downgrade: the release manifest names v{}, but this hcom is v{}.",
            info.latest, info.current
        );
        eprintln!("Pass --allow-downgrade if that is what you meant.");
        return 1;
    }

    if relation == Downgrade {
        println!(
            "Downgrading: v{} → v{} (--allow-downgrade)",
            info.current, info.latest
        );
    } else {
        debug_assert_eq!(relation, Upgrade);
        println!("Update available: v{} → v{}", info.current, info.latest);
    }

    if args.check {
        // The command to run has to carry the flag too, or it names a command
        // this very invocation just refused.
        if relation == Downgrade {
            println!("Run `hcom update --allow-downgrade` to apply.");
        } else {
            println!("Run `{}` to apply.", crate::update::UPDATE_COMMAND);
        }
        return 0;
    }

    match crate::update::apply_manifest(&manifest, &CurlFetcher) {
        Ok(ApplyOutcome::Updated { version, backup }) => {
            // Clear the cached "update available" notice
            let _ = crate::paths::atomic_write(&crate::update::flag_path(), "");
            println!("Updated to v{version}.");
            println!("Previous executable kept at {}", backup.display());
            println!("Run 'hcom --version' to confirm.");
            0
        }
        Ok(ApplyOutcome::NoArtifact { platform, version }) => {
            eprintln!("hcom v{version} has no prebuilt archive for {platform}.");
            if cfg!(target_env = "musl") && platform == "x86_64-linux" {
                // The published archive is glibc-linked, so this host is
                // excluded by what it can run, not by what was published.
                eprintln!(
                    "This hcom is linked against musl; the published archive needs glibc, \
                     so installing it would leave an executable that cannot start."
                );
            }
            eprintln!();
            eprintln!("{}", crate::update::source_guidance(Some(&version)));
            1
        }
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn update_args_default() {
        let args = UpdateArgs::try_parse_from(["update"]).unwrap();
        assert!(!args.check);
        assert!(!args.refresh_cache);
        assert!(
            !args.allow_downgrade,
            "a downgrade must never be the default"
        );
    }

    #[test]
    fn update_args_check_flag() {
        let args = UpdateArgs::try_parse_from(["update", "--check"]).unwrap();
        assert!(args.check);
        assert!(!args.refresh_cache);
    }

    #[test]
    fn update_args_allow_downgrade_flag() {
        let args = UpdateArgs::try_parse_from(["update", "--allow-downgrade"]).unwrap();
        assert!(args.allow_downgrade);
        assert!(!args.check);
        // It composes with --check, so a caller can see what a downgrade would
        // do before doing it.
        let both = UpdateArgs::try_parse_from(["update", "--check", "--allow-downgrade"]).unwrap();
        assert!(both.allow_downgrade && both.check);
    }

    #[test]
    fn update_args_background_refresh_flag() {
        // The background refresh hcom spawns on itself must parse, and must not
        // be mistaken for an interactive run that swaps the binary.
        let args = UpdateArgs::try_parse_from(["update", "--refresh-cache"]).unwrap();
        assert!(args.refresh_cache);
        assert!(!args.check);
    }

    #[test]
    fn print_dev_root_notice_is_safe_when_unset() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_at(&dir.path().join("hcom.db")).unwrap();
        print_dev_root_notice(&db);
    }
}
