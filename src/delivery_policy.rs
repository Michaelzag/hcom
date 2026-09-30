//! Operator delivery policy: `[delivery.<instance>]` tables in config.toml.
//!
//! An instance with an entry (the conductor, in practice) takes only the
//! traffic its operator named:
//!
//! ```toml
//! [delivery.kimi]
//! delegate = "mupe"                       # required: receives everything kimi refuses
//! leads = ["poli", "valo"]                # may wake kimi with a decision
//! wake_intents = ["request"]              # default
//! wake_prefixes = ["BLOCKED", "DECISION"] # default
//! ```
//!
//! A targeted message reaches the instance only if (a) its sender is the
//! delegate, (b) its sender is a lead AND its intent is in `wake_intents` AND
//! its text (after leading whitespace) opens with a `wake_prefixes` word as a
//! whole case-sensitive word, or (c) its sender is `SenderKind::External` (the
//! human). System senders (launcher events, hcom notices, reqwatch pings) are
//! not exempt. Broadcasts of any sender kind never reach it. `hcom send`
//! rewrites a refused recipient to the delegate (one hop: the rerouted copy is
//! never re-evaluated, even when the delegate has a policy of its own), and
//! every read path re-applies the rule as a backstop for traffic that never
//! went through `hcom send` (system notices, remote hosts without this
//! config, events written before the entry existed).
//!
//! Fail closed: an entry that is present but invalid (not a table, no or
//! empty `delegate`, wrong types, unknown keys), or a config.toml that no
//! longer parses while it still names `[delivery.<x>]`, leaves that instance
//! receiving only targeted messages from External senders, and logs a warning
//! each time the effective policy changes.
//!
//! Threat model: this stops accidental load (cc floods, non-decision traffic
//! waking the conductor). It is not tamper resistance. A same-uid process can
//! edit config.toml, and `--from <any name>` is an unauthenticated External
//! sender that passes rule (c) by design; every such delivery to a policy
//! instance writes an audit line (`delivery_policy.external_reached`). In
//! practice omp-config's conductor-guard already refuses the conductor any
//! write outside its ledger dir and any hcom subcommand beyond its allowlist.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::Value;

use crate::db::HcomDb;

const DEFAULT_WAKE_INTENTS: &[&str] = &["request"];
const DEFAULT_WAKE_PREFIXES: &[&str] = &["BLOCKED", "DECISION"];
const KNOWN_KEYS: &[&str] = &["delegate", "leads", "wake_intents", "wake_prefixes"];
/// kv key holding the hash of the last policy an audit line was written for.
const KV_LOGGED_HASH: &str = "delivery_policy:logged_hash";
/// Event field recording `{refused recipient: delegate}` for a rerouted send.
pub const REROUTES_FIELD: &str = "delivery_reroutes";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub delegate: String,
    pub leads: Vec<String>,
    pub wake_intents: Vec<String>,
    pub wake_prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Valid(Policy),
    /// Present but unusable; the reason goes in the warning.
    Invalid(String),
}

/// Every `[delivery.*]` entry in effect, keyed by instance name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policies {
    entries: BTreeMap<String, Entry>,
}

/// The facts about one message the rule reads.
#[derive(Debug, Clone, Copy)]
pub struct MessageFacts<'a> {
    pub from: &'a str,
    pub external: bool,
    /// `scope = mentions`; anything else is a broadcast.
    pub targeted: bool,
    pub intent: Option<&'a str>,
    pub text: &'a str,
}

impl<'a> MessageFacts<'a> {
    /// Read the facts from a stored message event. A missing `sender_kind`
    /// (old or foreign event) counts as not External.
    pub fn from_event(data: &'a Value) -> Self {
        let field = |key: &str| data.get(key).and_then(|v| v.as_str());
        Self {
            from: field("from").unwrap_or(""),
            external: field("sender_kind") == Some("external"),
            targeted: field("scope") == Some("mentions"),
            intent: field("intent"),
            text: field("text").unwrap_or(""),
        }
    }
}

/// What `hcom send` does with one resolved recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendVerdict {
    Deliver,
    RerouteTo(String),
    /// Invalid entry: there is no delegate to reroute to.
    Drop,
}

impl Policies {
    #[cfg(test)]
    fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.get(name)
    }

    pub fn has_entry(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Send-side decision for a recipient of a targeted message.
    pub fn send_verdict(&self, recipient: &str, msg: &MessageFacts<'_>) -> SendVerdict {
        match self.entries.get(recipient) {
            None => SendVerdict::Deliver,
            Some(entry) if entry_admits(entry, msg) => SendVerdict::Deliver,
            Some(Entry::Valid(policy)) => SendVerdict::RerouteTo(policy.delegate.clone()),
            Some(Entry::Invalid(_)) => SendVerdict::Drop,
        }
    }

    /// The rule alone, for a receiver that is not a reroute delegate.
    pub fn admits(&self, receiver: &str, msg: &MessageFacts<'_>) -> bool {
        self.entries
            .get(receiver)
            .is_none_or(|entry| entry_admits(entry, msg))
    }

    /// Receive-side backstop: may `receiver` read this stored message event?
    /// A receiver named as a reroute delegate on the event is admitted
    /// without evaluating its own policy (one hop, never re-evaluated).
    pub fn admits_event(&self, receiver: &str, data: &Value) -> bool {
        if !self.has_entry(receiver) {
            return true;
        }
        let rerouted_here = data
            .get(REROUTES_FIELD)
            .and_then(|v| v.as_object())
            .is_some_and(|map| map.values().any(|to| to.as_str() == Some(receiver)));
        rerouted_here || self.admits(receiver, &MessageFacts::from_event(data))
    }

    /// Stable short hash of the effective policy, for the audit line.
    fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        if self.entries.is_empty() {
            return "none".to_string();
        }
        let digest = Sha256::digest(format!("{:?}", self.entries).as_bytes());
        digest[..6].iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn entry_admits(entry: &Entry, msg: &MessageFacts<'_>) -> bool {
    if !msg.targeted {
        return false;
    }
    if msg.external {
        return true;
    }
    let Entry::Valid(policy) = entry else {
        return false;
    };
    if msg.from == policy.delegate {
        return true;
    }
    policy.leads.iter().any(|lead| lead == msg.from)
        && msg
            .intent
            .is_some_and(|intent| policy.wake_intents.iter().any(|w| w == intent))
        && starts_with_wake_word(msg.text, &policy.wake_prefixes)
}

/// `BLOCKED: x` and `DECISION - x` open with a wake word; `BLOCKEDX`,
/// `blocked: x` and `Blocked x` do not.
fn starts_with_wake_word(text: &str, prefixes: &[String]) -> bool {
    let text = text.trim_start();
    prefixes.iter().any(|prefix| {
        text.strip_prefix(prefix.as_str()).is_some_and(|rest| {
            rest.chars()
                .next()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
        })
    })
}

/// Parse the `[delivery.*]` tables out of config.toml text.
pub fn parse(content: &str) -> Policies {
    let table = match content.parse::<toml::Table>() {
        Ok(table) => table,
        Err(_) => return fail_closed_from_headers(content),
    };
    let mut entries = BTreeMap::new();
    if let Some(delivery) = table.get("delivery") {
        match delivery.as_table() {
            Some(delivery) => {
                for (name, value) in delivery {
                    entries.insert(name.clone(), parse_entry(value));
                }
            }
            None => {
                crate::log::log_warn(
                    "delivery_policy",
                    "invalid_config",
                    "`delivery` in config.toml is not a table; no instance names to apply it to",
                );
            }
        }
    }
    Policies { entries }
}

/// config.toml no longer parses: every `[delivery.<name>]` header still in
/// the text fails closed rather than silently dropping its protection.
fn fail_closed_from_headers(content: &str) -> Policies {
    let entries = content
        .lines()
        .filter_map(|line| {
            let inner = line.trim().strip_prefix("[delivery.")?;
            let name = inner.split(']').next()?.trim().trim_matches(['"', '\'']);
            (!name.is_empty()).then(|| {
                (
                    name.to_string(),
                    Entry::Invalid("config.toml does not parse".to_string()),
                )
            })
        })
        .collect();
    Policies { entries }
}

fn parse_entry(value: &toml::Value) -> Entry {
    let Some(table) = value.as_table() else {
        return Entry::Invalid("entry is not a table".to_string());
    };
    if let Some(unknown) = table.keys().find(|k| !KNOWN_KEYS.contains(&k.as_str())) {
        return Entry::Invalid(format!("unknown key `{unknown}`"));
    }
    let delegate = match table.get("delegate").and_then(|v| v.as_str()) {
        Some(d) if !d.trim().is_empty() => d.trim().to_string(),
        _ => return Entry::Invalid("`delegate` must be a non-empty string".to_string()),
    };
    let leads = match string_list(table, "leads", &[]) {
        Ok(v) => v,
        Err(e) => return Entry::Invalid(e),
    };
    let wake_intents = match string_list(table, "wake_intents", DEFAULT_WAKE_INTENTS) {
        Ok(v) => v,
        Err(e) => return Entry::Invalid(e),
    };
    if let Some(bad) = wake_intents
        .iter()
        .find(|i| crate::core::helpers::validate_intent(i).is_err())
    {
        return Entry::Invalid(format!("`wake_intents` has unknown intent `{bad}`"));
    }
    let wake_prefixes = match string_list(table, "wake_prefixes", DEFAULT_WAKE_PREFIXES) {
        Ok(v) => v,
        Err(e) => return Entry::Invalid(e),
    };
    if let Some(bad) = wake_prefixes
        .iter()
        .find(|p| p.is_empty() || p.chars().any(|c| c.is_lowercase() || c.is_whitespace()))
    {
        return Entry::Invalid(format!(
            "`wake_prefixes` entry `{bad}` must be a non-empty uppercase word"
        ));
    }
    Entry::Valid(Policy {
        delegate,
        leads,
        wake_intents,
        wake_prefixes,
    })
}

fn string_list(table: &toml::Table, key: &str, default: &[&str]) -> Result<Vec<String>, String> {
    let Some(value) = table.get(key) else {
        return Ok(default.iter().map(|s| s.to_string()).collect());
    };
    let err = || format!("`{key}` must be an array of strings");
    value
        .as_array()
        .ok_or_else(err)?
        .iter()
        .map(|v| v.as_str().map(|s| s.trim().to_string()).ok_or_else(err))
        .collect()
}

/// Load the policy from config.toml. Read on every call (delivery time), so
/// an operator edit takes effect on the next read without a restart.
pub fn load(db: &HcomDb) -> Policies {
    let policies = match std::fs::read_to_string(crate::paths::config_toml_path()) {
        Ok(content) => parse(&content),
        Err(_) => Policies::default(),
    };
    audit(db, &policies);
    policies
}

/// Log one line when the effective policy differs from the last one logged
/// (the hash is kept in kv, so it is one line per change across processes).
/// A process-local memo keeps repeat loads to a hash compare.
fn audit(db: &HcomDb, policies: &Policies) {
    static SEEN: Mutex<Option<(std::path::PathBuf, String)>> = Mutex::new(None);
    let hash = policies.hash();
    let db_path = db.path().to_path_buf();
    {
        let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
        if seen
            .as_ref()
            .is_some_and(|(p, h)| *p == db_path && *h == hash)
        {
            return;
        }
        *seen = Some((db_path, hash.clone()));
    }
    let previous = db.kv_get(KV_LOGGED_HASH).ok().flatten();
    let previous = previous.as_deref().unwrap_or("none");
    if previous == hash {
        return;
    }
    let _ = db.kv_set(KV_LOGGED_HASH, Some(&hash));
    let names: Vec<&str> = policies.entries.keys().map(String::as_str).collect();
    crate::log::log_with_fields(
        "INFO",
        "delivery_policy",
        "policy_changed",
        &format!("{previous} -> {hash}"),
        &[
            ("pid", &std::process::id().to_string()),
            ("instances", &names.join(",")),
        ],
    );
    for (name, entry) in &policies.entries {
        if let Entry::Invalid(reason) = entry {
            crate::log::log_warn(
                "delivery_policy",
                "invalid_entry",
                &format!(
                    "[delivery.{name}] is invalid ({reason}); failing closed: {name} receives only targeted messages from External senders"
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(from: &'a str, intent: Option<&'a str>, text: &'a str) -> MessageFacts<'a> {
        MessageFacts {
            from,
            external: false,
            targeted: true,
            intent,
            text,
        }
    }

    const KIMI: &str = r#"
[delivery.kimi]
delegate = "mupe"
leads = ["poli", "valo"]
"#;

    #[test]
    fn parse_applies_defaults() {
        let policies = parse(KIMI);
        assert_eq!(
            policies.get("kimi"),
            Some(&Entry::Valid(Policy {
                delegate: "mupe".into(),
                leads: vec!["poli".into(), "valo".into()],
                wake_intents: vec!["request".into()],
                wake_prefixes: vec!["BLOCKED".into(), "DECISION".into()],
            }))
        );
        assert!(
            parse("[terminal]\nactive = \"default\"\n")
                .get("kimi")
                .is_none()
        );
    }

    #[test]
    fn parse_invalid_entries_fail_closed() {
        for bad in [
            "[delivery.kimi]\nleads = [\"poli\"]\n",
            "[delivery.kimi]\ndelegate = \"  \"\n",
            "[delivery.kimi]\ndelegate = 3\n",
            "[delivery.kimi]\ndelegate = \"mupe\"\nleads = \"poli\"\n",
            "[delivery.kimi]\ndelegate = \"mupe\"\nwake_intents = [\"shout\"]\n",
            "[delivery.kimi]\ndelegate = \"mupe\"\nwake_prefixes = [\"blocked\"]\n",
            "[delivery.kimi]\ndelegate = \"mupe\"\nlead = [\"poli\"]\n",
            "[delivery]\nkimi = \"mupe\"\n",
            // Whole file unparseable: the header alone still fails closed.
            "[delivery.kimi]\ndelegate = \"mupe\"\n[terminal\n",
        ] {
            assert!(
                matches!(parse(bad).get("kimi"), Some(Entry::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn rule_admits_delegate_leads_with_wake_word_and_external_only() {
        let policies = parse(KIMI);
        let admit = |msg: MessageFacts<'_>| policies.send_verdict("kimi", &msg);
        let reroute = SendVerdict::RerouteTo("mupe".into());

        assert_eq!(
            admit(facts("mupe", Some("inform"), "fyi")),
            SendVerdict::Deliver
        );
        assert_eq!(admit(facts("mupe", None, "anything")), SendVerdict::Deliver);
        for text in ["BLOCKED: x", "DECISION x", "  DECISION - x", "BLOCKED"] {
            assert_eq!(
                admit(facts("valo", Some("request"), text)),
                SendVerdict::Deliver,
                "{text}"
            );
        }
        for text in [
            "BLOCKEDX",
            "blocked: x",
            "Blocked x",
            "BLOCKED_x",
            "x BLOCKED",
        ] {
            assert_eq!(
                admit(facts("valo", Some("request"), text)),
                reroute,
                "{text}"
            );
        }
        assert_eq!(admit(facts("valo", Some("inform"), "BLOCKED: x")), reroute);
        assert_eq!(admit(facts("valo", None, "BLOCKED: x")), reroute);
        assert_eq!(admit(facts("nova", Some("request"), "BLOCKED: x")), reroute);
        assert_eq!(
            admit(MessageFacts {
                external: true,
                ..facts("bigboss", None, "hi")
            }),
            SendVerdict::Deliver
        );
        // Broadcasts never reach a policy instance, whoever sends them.
        for from in ["mupe", "bigboss"] {
            let broadcast = MessageFacts {
                external: from == "bigboss",
                targeted: false,
                ..facts(from, Some("request"), "BLOCKED: x")
            };
            assert!(!entry_admits(policies.get("kimi").unwrap(), &broadcast));
        }
        // No entry: unchanged.
        assert_eq!(
            policies.send_verdict("nova", &facts("valo", None, "hi")),
            SendVerdict::Deliver
        );
    }

    #[test]
    fn invalid_entry_admits_only_external_targeted() {
        let policies = parse("[delivery.kimi]\nleads = [\"valo\"]\n");
        assert_eq!(
            policies.send_verdict("kimi", &facts("valo", Some("request"), "BLOCKED: x")),
            SendVerdict::Drop
        );
        let external = MessageFacts {
            external: true,
            ..facts("bigboss", None, "hi")
        };
        assert_eq!(
            policies.send_verdict("kimi", &external),
            SendVerdict::Deliver
        );
        let broadcast = MessageFacts {
            targeted: false,
            ..external
        };
        assert!(!entry_admits(policies.get("kimi").unwrap(), &broadcast));
    }
}
