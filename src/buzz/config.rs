//! Connector configuration: `~/.hcom/buzz/config.toml`.
//!
//! One connector per host (mbai). Everything secret is a *path*: the seed and
//! the owner key file are read in-process by `serve` and never appear in this
//! file's contents, in logs, or on a child's argv.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::buzz::nostr::device_label;
use crate::identity::is_valid_base_name;

/// A bridged Buzz channel: relay channel id plus the slug the hcom row uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelConfig {
    /// Buzz channel id (a UUID; the value of the events' `h` tag).
    pub id: String,
    /// Slug used for `ch_<slug>`; defaults to `id` when omitted.
    pub slug: Option<String>,
    /// This channel is a human's private home channel (rule 3 destinations).
    pub home: bool,
}

impl ChannelConfig {
    /// hcom row name for the channel.
    pub fn row_name(&self) -> String {
        format!("ch_{}", self.slug.as_deref().unwrap_or(&self.id))
    }
}

/// A Buzz person the connector knows about before the roster shows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonConfig {
    /// Hex pubkey of the Buzz profile.
    pub pubkey: String,
    /// hcom row name; defaults to the slug of the Buzz profile name.
    pub name: Option<String>,
    /// Home channel slug for rule 3 (`home = true` channel).
    pub home: Option<String>,
}

/// `~/.hcom/buzz/config.toml`, validated on load.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `wss://` relay websocket URL the reader session connects to.
    #[serde(default)]
    pub relay_url: String,
    /// `https://` relay base URL used for `POST /events` and `POST /query`.
    #[serde(default)]
    pub http_url: String,
    /// This device's Buzz label (`mbai`), used for its own hcom identities.
    #[serde(default)]
    pub device_label: String,
    /// Path to the 32-byte seed file.
    #[serde(default)]
    pub seed_path: PathBuf,
    /// Path to the env file carrying `BUZZ_PRIVATE_KEY` (omp's key).
    #[serde(default)]
    pub owner_env_path: PathBuf,
    /// hcom names allowed to sign from the CLI's Q&A subcommands.
    #[serde(default)]
    pub local_signers: Vec<String>,
    /// Bridged channels.
    #[serde(default)]
    pub channels: Vec<ChannelConfig>,
    /// Known people (optional; the roster fills the rest in).
    #[serde(default)]
    pub people: Vec<PersonConfig>,
}

impl Config {
    /// `<HCOM_DIR>/buzz`.
    pub fn dir() -> PathBuf {
        crate::paths::hcom_dir().join("buzz")
    }

    /// `<HCOM_DIR>/buzz/config.toml`.
    pub fn path() -> PathBuf {
        Self::dir().join("config.toml")
    }

    /// `<HCOM_DIR>/buzz/state.db`.
    pub fn state_db_path() -> PathBuf {
        Self::dir().join("state.db")
    }

    /// `<HCOM_DIR>/buzz/serve.lock`.
    pub fn lock_path() -> PathBuf {
        Self::dir().join("serve.lock")
    }

    /// Load and validate, naming the offending field in every error.
    pub fn load() -> Result<Self> {
        let path = Self::path();
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        let config: Self =
            toml::from_str(&raw).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Every failure names the field and its value's *shape*, never key material.
    pub fn validate(&self) -> Result<()> {
        for (field, value) in [("relay_url", &self.relay_url), ("http_url", &self.http_url)] {
            let scheme = value.split("://").next().unwrap_or_default();
            let expected = if field == "relay_url" { "wss" } else { "https" };
            if scheme != expected {
                bail!("{field} must start with {expected}://");
            }
            if value.len() <= expected.len() + 2 {
                bail!("{field} must name a relay host");
            }
        }
        device_label(&self.device_label).map_err(|e| anyhow::anyhow!("device_label: {e}"))?;
        if self.seed_path.as_os_str().is_empty() {
            bail!("seed_path must name a file");
        }
        if self.owner_env_path.as_os_str().is_empty() {
            bail!("owner_env_path must name a file");
        }
        for signer in &self.local_signers {
            if !is_valid_base_name(signer) {
                bail!("local_signers: '{}' is not a valid hcom name", signer);
            }
        }
        let mut rows = std::collections::HashSet::new();
        for channel in &self.channels {
            if channel.id.trim().is_empty() {
                bail!("channels: id must not be empty");
            }
            if let Some(slug) = &channel.slug
                && !is_valid_base_name(&format!("ch_{slug}"))
            {
                bail!("channels: slug '{slug}' is not a valid hcom name");
            }
            if !rows.insert(channel.row_name()) {
                bail!("channels: '{}' is listed twice", channel.row_name());
            }
        }
        let mut people = std::collections::HashSet::new();
        for person in &self.people {
            if !is_hex_pubkey(&person.pubkey) {
                bail!("people: pubkey must be 64 hex characters");
            }
            if let Some(name) = &person.name
                && !is_valid_base_name(name)
            {
                bail!("people: name '{name}' is not a valid hcom name");
            }
            if !people.insert(person.pubkey.clone()) {
                bail!("people: pubkey {} is listed twice", person.pubkey);
            }
            if let Some(home) = &person.home
                && !self
                    .channels
                    .iter()
                    .any(|c| c.slug.as_deref() == Some(home.as_str()) && c.home)
            {
                bail!("people: home channel '{home}' is not a channel with home = true");
            }
        }
        Ok(())
    }

    /// Bridged channels in config order.
    pub fn channels(&self) -> &[ChannelConfig] {
        &self.channels
    }

    /// Resolve a channel row name (`ch_<slug>`) back to its config.
    pub fn channel_by_row(&self, row: &str) -> Option<&ChannelConfig> {
        self.channels.iter().find(|c| c.row_name() == row)
    }

    /// Resolve a channel slug or id to its config.
    pub fn channel_by_slug(&self, slug: &str) -> Option<&ChannelConfig> {
        self.channels
            .iter()
            .find(|c| c.slug.as_deref() == Some(slug) || c.id == slug || c.row_name() == slug)
    }

    /// Config override of a person's hcom name, if any.
    pub fn person_name(&self, pubkey: &str) -> Option<&str> {
        self.people
            .iter()
            .find(|p| p.pubkey == pubkey)
            .and_then(|p| p.name.as_deref())
    }

    /// Home channel slug configured for a person.
    pub fn person_home(&self, pubkey: &str) -> Option<&str> {
        self.people
            .iter()
            .find(|p| p.pubkey == pubkey)
            .and_then(|p| p.home.as_deref())
    }

    /// True when `name` may sign from the mbai-local CLI subcommands.
    pub fn is_local_signer(&self, name: &str) -> bool {
        self.local_signers.iter().any(|s| s == name)
    }
}

fn is_hex_pubkey(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Slug of a Buzz profile name into hcom's `[a-z0-9_]` name space.
pub fn person_slug(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut last_was_sep = false;
    for ch in name.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            slug.push(lower);
            last_was_sep = false;
        } else if !last_was_sep && !slug.is_empty() {
            slug.push('_');
            last_was_sep = true;
        }
    }
    while slug.ends_with('_') {
        slug.pop();
    }
    slug
}

/// hcom name for a person slug, with the `_bz` suffix on collision.
pub fn unique_person_name(base: &str, taken: impl Fn(&str) -> bool) -> String {
    if !taken(base) {
        return base.to_string();
    }
    let mut candidate = format!("{base}_bz");
    let mut counter = 2;
    while taken(&candidate) {
        candidate = format!("{base}_bz{counter}");
        counter += 1;
    }
    candidate
}

/// Reader identity: its own info string, so no hcom agent name can collide.
pub fn reader_canonical(device: &str) -> Result<String> {
    Ok(format!("reader@{}", device_label(device)?))
}

/// Path to the seed file when the config left it relative.
pub fn resolve_relative(base: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_path_buf()
    } else {
        base.join(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        Config {
            relay_url: "wss://buzz.example".into(),
            http_url: "https://buzz.example".into(),
            device_label: "mbai".into(),
            seed_path: "/secrets/seed".into(),
            owner_env_path: "/secrets/owner.env".into(),
            local_signers: vec!["qa".into()],
            channels: vec![ChannelConfig {
                id: "11111111-1111-1111-1111-111111111111".into(),
                slug: Some("infra".into()),
                home: false,
            }],
            people: vec![],
        }
    }

    #[test]
    fn accepts_a_complete_config() {
        sample().validate().unwrap();
    }

    #[test]
    fn rejects_plaintext_relay_urls() {
        for (field, value) in [
            ("relay_url", "ws://buzz.example"),
            ("http_url", "http://buzz.example"),
        ] {
            let mut config = sample();
            if field == "relay_url" {
                config.relay_url = value.into();
            } else {
                config.http_url = value.into();
            }
            let err = config.validate().unwrap_err().to_string();
            assert!(err.starts_with(field), "{err}");
        }
    }

    #[test]
    fn rejects_bad_device_label_and_missing_key_paths() {
        let mut config = sample();
        config.device_label = "Not A Label".into();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("device_label")
        );

        let mut config = sample();
        config.seed_path = PathBuf::new();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("seed_path")
        );

        let mut config = sample();
        config.owner_env_path = PathBuf::new();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("owner_env_path")
        );
    }

    #[test]
    fn rejects_duplicate_rows_and_people() {
        let mut config = sample();
        config.channels.push(ChannelConfig {
            id: "22222222-2222-2222-2222-222222222222".into(),
            slug: Some("infra".into()),
            home: false,
        });
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("ch_infra")
        );

        let mut config = sample();
        config.people.push(PersonConfig {
            pubkey: "aa".repeat(32),
            name: None,
            home: None,
        });
        config.people.push(PersonConfig {
            pubkey: "aa".repeat(32),
            name: None,
            home: None,
        });
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("listed twice")
        );
    }

    #[test]
    fn rejects_a_home_channel_that_is_not_marked_home() {
        let mut config = sample();
        config.people.push(PersonConfig {
            pubkey: "bb".repeat(32),
            name: None,
            home: Some("infra".into()),
        });
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("home = true"), "{err}");

        config.channels[0].home = true;
        config.validate().unwrap();
    }

    #[test]
    fn rejects_a_bad_pubkey_and_a_bad_person_name() {
        let mut config = sample();
        config.people.push(PersonConfig {
            pubkey: "zz".into(),
            name: None,
            home: None,
        });
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("64 hex")
        );

        let mut config = sample();
        config.people.push(PersonConfig {
            pubkey: "cc".repeat(32),
            name: Some("Not Valid".into()),
            home: None,
        });
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("not a valid hcom name")
        );
    }

    #[test]
    fn rejects_a_non_base_signer_name() {
        let mut config = sample();
        config.local_signers = vec!["qa@mbai".into()];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("local_signers")
        );
    }

    #[test]
    fn load_names_the_file_and_reports_toml_errors() {
        let (_env, _dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let err = Config::load().unwrap_err().to_string();
        assert!(err.contains("config.toml"), "{err}");

        std::fs::create_dir_all(Config::dir()).unwrap();
        std::fs::write(Config::path(), "relay_url = \n").unwrap();
        let err = Config::load().unwrap_err().to_string();
        assert!(err.contains("config.toml"), "{err}");
    }

    #[test]
    fn load_round_trips_a_valid_file() {
        let (_env, _dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        std::fs::create_dir_all(Config::dir()).unwrap();
        let config = sample();
        std::fs::write(
            Config::path(),
            toml::to_string(&config).expect("serializes"),
        )
        .unwrap();
        assert_eq!(Config::load().unwrap(), config);
        assert!(config.is_local_signer("qa"));
        assert!(!config.is_local_signer("other"));
    }

    #[test]
    fn person_slug_lowercases_and_joins_on_single_underscore() {
        assert_eq!(person_slug("SeanFitz"), "seanfitz");
        assert_eq!(person_slug("Sean Fitz"), "sean_fitz");
        assert_eq!(person_slug("Sean  Fitz!"), "sean_fitz");
        assert_eq!(person_slug("--"), "");
        assert_eq!(person_slug("Ops_Lead"), "ops_lead");
    }

    #[test]
    fn unique_person_name_suffixes_on_collision() {
        assert_eq!(unique_person_name("michael", |_| false), "michael");
        assert_eq!(
            unique_person_name("michael", |n| n == "michael"),
            "michael_bz"
        );
        assert_eq!(
            unique_person_name("michael", |n| n == "michael" || n == "michael_bz"),
            "michael_bz2"
        );
    }

    #[test]
    fn reader_identity_has_its_own_info_prefix() {
        assert_eq!(reader_canonical("mbai").unwrap(), "reader@mbai");
        assert!(reader_canonical("Bad Label").is_err());
    }

    #[test]
    fn channel_lookup_by_row_slug_and_id() {
        let config = sample();
        assert_eq!(
            config.channel_by_row("ch_infra").map(|c| c.id.as_str()),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert!(config.channel_by_slug("infra").is_some());
        assert!(
            config
                .channel_by_slug("11111111-1111-1111-1111-111111111111")
                .is_some()
        );
        assert!(config.channel_by_slug("warehouse").is_none());
    }

    #[test]
    fn relative_paths_resolve_against_the_config_dir() {
        assert_eq!(
            resolve_relative(Path::new("/hcom/buzz"), Path::new("seed")),
            PathBuf::from("/hcom/buzz/seed")
        );
        assert_eq!(
            resolve_relative(Path::new("/hcom/buzz"), Path::new("/etc/seed")),
            PathBuf::from("/etc/seed")
        );
    }
}
