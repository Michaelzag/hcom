//! Operator delivery policy: `[delivery.<role>]` tables in config.toml,
//! applied to whichever live instance holds that role.
//!
//! ```toml
//! [delivery.conductor]
//! delegate = "mupe"                       # required: receives everything refused
//! leads = ["poli", "valo"]                # may wake the conductor with a decision
//! wake_intents = ["request"]              # default
//! wake_prefixes = ["BLOCKED", "DECISION"] # default
//! ```
//!
//! Roles, not names: the conductor seat changes its hcom name every day or
//! two, so a name-keyed entry would silently stop filtering at the next
//! rotation and wrongly filter a later seat reusing the name. An instance
//! holds a role only through [`register_role`], which the omp plugin calls
//! (`hcom omp-role`) once per binding when the omp session carries the
//! `conductor-role` marker entry. Registration is add-only: there is no path
//! to clear or change a role. The registration is tied to one instance row
//! (name + session id + created_at), so it dies with that row: a stop, a
//! reuse of the name by another seat, or `hcom r` (which writes a new row)
//! all end it, and the resumed session's plugin registers again at bind.
//! Non-omp conductors (claude/codex) cannot carry the omp marker and are out
//! of scope; the unheld-role warning below covers them.
//!
//! A targeted message reaches a role holder only if (a) its sender is the
//! delegate, (b) its sender is a lead AND its intent is in `wake_intents` AND
//! its text (after leading whitespace) opens with a `wake_prefixes` word as a
//! whole case-sensitive word, or (c) its sender is `SenderKind::External` (the
//! human). System senders (launcher events, hcom notices, reqwatch pings) are
//! not exempt. Broadcasts of any sender kind never reach it. `hcom send`
//! rewrites a refused recipient to the delegate (one hop: the rerouted copy is
//! never re-evaluated, even when the delegate holds a role of its own), and
//! every read path re-applies the rule as a backstop for traffic that never
//! went through `hcom send` (system notices, remote hosts without this
//! config, events written before the role was registered).
//!
//! Fail closed: an entry that is present but invalid (not a table, no or
//! empty `delegate`, wrong types, unknown keys), or a config.toml that no
//! longer parses while it still names `[delivery.<role>]`, leaves the role's
//! holders receiving only targeted messages from External senders, and logs
//! a warning each time the effective policy changes.
//!
//! Missed registration is the failure that would turn the filter silently
//! off, so a configured role with no live holder is logged as a warning at
//! every omp bind and whenever the effective policy changes, and `hcom
//! status` / `hcom list` print `<role> role: <holders>|NONE`. Two holders of
//! one role are both filtered, with a warning; nothing silently picks one.
//!
//! Threat model: this stops accidental load (cc floods, non-decision traffic
//! waking the conductor). It is not tamper resistance. A same-uid process can
//! edit config.toml, and `--from <any name>` is an unauthenticated External
//! sender that passes rule (c) by design; every such delivery to a role
//! holder writes an audit line (`delivery_policy.external_reached`). In
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
/// kv prefix of one role registration per instance name.
const KV_ROLE_PREFIX: &str = "delivery_role:";
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

/// The `[delivery.*]` entries in effect (keyed by role) and the live
/// instances holding each role.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policies {
    entries: BTreeMap<String, Entry>,
    /// instance name -> role, live registrations only.
    holders: BTreeMap<String, String>,
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
    /// The entry governing `instance`, if it holds a configured role.
    fn entry_for(&self, instance: &str) -> Option<&Entry> {
        self.entries.get(self.holders.get(instance)?)
    }

    /// `instance` holds a role that has a `[delivery.*]` entry.
    pub fn governs(&self, instance: &str) -> bool {
        self.entry_for(instance).is_some()
    }

    /// Send-side decision for a recipient of a targeted message.
    pub fn send_verdict(&self, recipient: &str, msg: &MessageFacts<'_>) -> SendVerdict {
        match self.entry_for(recipient) {
            None => SendVerdict::Deliver,
            Some(entry) if entry_admits(entry, msg) => SendVerdict::Deliver,
            Some(Entry::Valid(policy)) => SendVerdict::RerouteTo(policy.delegate.clone()),
            Some(Entry::Invalid(_)) => SendVerdict::Drop,
        }
    }

    /// The rule alone, for a receiver that is not a reroute delegate.
    pub fn admits(&self, receiver: &str, msg: &MessageFacts<'_>) -> bool {
        self.entry_for(receiver)
            .is_none_or(|entry| entry_admits(entry, msg))
    }

    /// Receive-side backstop: may `receiver` read this stored message event?
    /// A receiver named as a reroute delegate on the event is admitted
    /// without evaluating its own policy (one hop, never re-evaluated).
    pub fn admits_event(&self, receiver: &str, data: &Value) -> bool {
        if !self.governs(receiver) {
            return true;
        }
        let rerouted_here = data
            .get(REROUTES_FIELD)
            .and_then(|v| v.as_object())
            .is_some_and(|map| map.values().any(|to| to.as_str() == Some(receiver)));
        rerouted_here || self.admits(receiver, &MessageFacts::from_event(data))
    }

    /// Every configured role with its live holders (empty = NONE).
    pub fn role_holders(&self) -> Vec<(&str, Vec<&str>)> {
        self.entries
            .keys()
            .map(|role| {
                let holders = self
                    .holders
                    .iter()
                    .filter(|(_, r)| *r == role)
                    .map(|(name, _)| name.as_str())
                    .collect();
                (role.as_str(), holders)
            })
            .collect()
    }

    /// Stable short hash of the effective policy, for the audit line.
    fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        if self.entries.is_empty() {
            return "none".to_string();
        }
        let digest = Sha256::digest(format!("{:?}{:?}", self.entries, self.holders).as_bytes());
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

/// Parse the `[delivery.*]` tables out of config.toml text (no holders).
pub fn parse(content: &str) -> Policies {
    let table = match content.parse::<toml::Table>() {
        Ok(table) => table,
        Err(_) => return fail_closed_from_headers(content),
    };
    let mut entries = BTreeMap::new();
    if let Some(delivery) = table.get("delivery") {
        match delivery.as_table() {
            Some(delivery) => {
                for (role, value) in delivery {
                    entries.insert(role.clone(), parse_entry(value));
                }
            }
            None => {
                crate::log::log_warn(
                    "delivery_policy",
                    "invalid_config",
                    "`delivery` in config.toml is not a table; no role to apply it to",
                );
            }
        }
    }
    Policies {
        entries,
        holders: BTreeMap::new(),
    }
}

/// config.toml no longer parses: every `[delivery.<role>]` header still in
/// the text fails closed rather than silently dropping its protection.
fn fail_closed_from_headers(content: &str) -> Policies {
    let entries = content
        .lines()
        .filter_map(|line| {
            let inner = line.trim().strip_prefix("[delivery.")?;
            let role = inner.split(']').next()?.trim().trim_matches(['"', '\'']);
            (!role.is_empty()).then(|| {
                (
                    role.to_string(),
                    Entry::Invalid("config.toml does not parse".to_string()),
                )
            })
        })
        .collect();
    Policies {
        entries,
        holders: BTreeMap::new(),
    }
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

/// Load the policy from config.toml plus the live role holders. Read on
/// every call (delivery time), so an operator edit or a new registration
/// takes effect on the next read without a restart. No `[delivery.*]` entry
/// means no DB query at all.
pub fn load(db: &HcomDb) -> Policies {
    let mut policies = match std::fs::read_to_string(crate::paths::config_toml_path()) {
        Ok(content) => parse(&content),
        Err(_) => Policies::default(),
    };
    if !policies.entries.is_empty() {
        policies.holders = live_role_holders(db);
    }
    audit(db, &policies);
    policies
}

/// One registration, stored in kv under `delivery_role:<name>`. It counts
/// only while the exact row it was written for (name + session id +
/// created_at) is still there and live.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RoleRecord {
    role: String,
    session_id: String,
    created_at: f64,
}

/// The exact row the record was written for is still there and live.
fn record_is_live(db: &HcomDb, name: &str, record: &RoleRecord) -> Result<bool, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    db.conn()
        .query_row(
            &format!(
                "SELECT 1 FROM instances WHERE name = ? AND session_id = ? AND created_at = ? AND {}",
                crate::fleet_names::LIVE_ROW_PREDICATE
            ),
            rusqlite::params![name, record.session_id, record.created_at],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
}

fn read_record(value: &str) -> Option<RoleRecord> {
    serde_json::from_str(value).ok()
}

fn live_role_holders(db: &HcomDb) -> BTreeMap<String, String> {
    db.kv_prefix(KV_ROLE_PREFIX)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(key, value)| {
            let name = key.strip_prefix(KV_ROLE_PREFIX)?.to_string();
            let record = read_record(&value)?;
            record_is_live(db, &name, &record)
                .unwrap_or(false)
                .then_some((name, record.role))
        })
        .collect()
}

/// Why a registration did not happen. `transient` (a locked or failing
/// database) is worth retrying; anything else is a final answer.
#[derive(Debug)]
pub struct RoleError {
    pub message: String,
    pub transient: bool,
}

impl RoleError {
    fn refused(message: String) -> Self {
        Self {
            message,
            transient: false,
        }
    }

    fn transient(error: impl std::fmt::Display) -> Self {
        Self {
            message: format!("database error: {error}"),
            transient: true,
        }
    }
}

/// Add-only role registration for the instance bound to `session_id`.
///
/// Refuses to change a live registration to a different role; re-registering
/// the same role is a no-op success. A registration left by a dead row (a
/// stopped seat, a resumed seat's previous row) is replaced. Every call
/// writes an audit line.
pub fn register_role(
    db: &HcomDb,
    instance: &str,
    session_id: &str,
    role: &str,
) -> Result<(), RoleError> {
    let audit_fields = [
        ("instance", instance),
        ("session_id", session_id),
        ("role", role),
    ];
    let result = register_role_inner(db, instance, session_id, role);
    match &result {
        Ok(()) => crate::log::log_with_fields(
            "INFO",
            "delivery_policy",
            "role_registered",
            &format!("{instance} holds role {role}"),
            &audit_fields,
        ),
        Err(e) => crate::log::log_with_fields(
            "WARN",
            "delivery_policy",
            if e.transient {
                "role_registration_failed"
            } else {
                "role_registration_refused"
            },
            &e.message,
            &audit_fields,
        ),
    }
    result
}

fn register_role_inner(
    db: &HcomDb,
    instance: &str,
    session_id: &str,
    role: &str,
) -> Result<(), RoleError> {
    use rusqlite::OptionalExtension;
    if role.is_empty()
        || !role
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(RoleError::refused(format!(
            "invalid role `{role}`: use [a-z0-9_-]"
        )));
    }
    let created_at: f64 = db
        .conn()
        .query_row(
            "SELECT created_at FROM instances WHERE name = ? AND session_id = ?",
            rusqlite::params![instance, session_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(RoleError::transient)?
        .ok_or_else(|| {
            RoleError::refused(format!(
                "no instance row {instance} bound to session {session_id}"
            ))
        })?;
    let key = format!("{KV_ROLE_PREFIX}{instance}");
    let existing = db
        .kv_get(&key)
        .map_err(RoleError::transient)?
        .and_then(|v| read_record(&v));
    if let Some(existing) = existing
        && existing.role != role
        && record_is_live(db, instance, &existing).map_err(RoleError::transient)?
    {
        return Err(RoleError::refused(format!(
            "{instance} already holds role {}; roles are add-only",
            existing.role
        )));
    }
    let record = RoleRecord {
        role: role.to_string(),
        session_id: session_id.to_string(),
        created_at,
    };
    let value = serde_json::to_string(&record).map_err(RoleError::transient)?;
    db.kv_set(&key, Some(&value)).map_err(RoleError::transient)
}

/// Warn for every configured role no live instance holds: the filter is off
/// for it. Called at every omp bind.
pub fn warn_unheld_roles(db: &HcomDb) {
    for (role, holders) in load(db).role_holders() {
        if holders.is_empty() {
            crate::log::log_warn(
                "delivery_policy",
                "role_unheld",
                &format!(
                    "[delivery.{role}] is configured but no live instance holds role {role}; its filter is OFF"
                ),
            );
        }
    }
}

/// Every configured role with its live holders (empty = NONE), for
/// `hcom status --json`.
pub fn role_status(db: &HcomDb) -> Vec<(String, Vec<String>)> {
    load(db)
        .role_holders()
        .into_iter()
        .map(|(role, holders)| {
            (
                role.to_string(),
                holders.into_iter().map(str::to_string).collect(),
            )
        })
        .collect()
}

/// `<role> role: <holders>|NONE`, one line per configured role, for
/// `hcom status` / `hcom list`.
pub fn role_status_lines(db: &HcomDb) -> Vec<String> {
    role_status(db)
        .into_iter()
        .map(|(role, holders)| {
            let who = if holders.is_empty() {
                "NONE".to_string()
            } else {
                holders.join(", ")
            };
            format!("{role} role: {who}")
        })
        .collect()
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
    let holders: Vec<String> = policies
        .role_holders()
        .into_iter()
        .map(|(role, names)| format!("{role}={}", names.join("+")))
        .collect();
    crate::log::log_with_fields(
        "INFO",
        "delivery_policy",
        "policy_changed",
        &format!("{previous} -> {hash}"),
        &[
            ("pid", &std::process::id().to_string()),
            ("roles", &holders.join(",")),
        ],
    );
    for (role, entry) in &policies.entries {
        if let Entry::Invalid(reason) = entry {
            crate::log::log_warn(
                "delivery_policy",
                "invalid_entry",
                &format!(
                    "[delivery.{role}] is invalid ({reason}); failing closed: role {role} receives only targeted messages from External senders"
                ),
            );
        }
    }
    for (role, names) in policies.role_holders() {
        match names.len() {
            0 => crate::log::log_warn(
                "delivery_policy",
                "role_unheld",
                &format!("no live instance holds role {role}; its filter is OFF"),
            ),
            1 => {}
            _ => crate::log::log_warn(
                "delivery_policy",
                "role_multiple_holders",
                &format!(
                    "role {role} is held by {}; all are filtered",
                    names.join(", ")
                ),
            ),
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

    const CONDUCTOR: &str = r#"
[delivery.conductor]
delegate = "mupe"
leads = ["poli", "valo"]
"#;

    /// `parse` plus kimi holding `conductor`.
    fn held(content: &str) -> Policies {
        let mut policies = parse(content);
        policies
            .holders
            .insert("kimi".to_string(), "conductor".to_string());
        policies
    }

    #[test]
    fn parse_applies_defaults() {
        let policies = parse(CONDUCTOR);
        assert_eq!(
            policies.entries.get("conductor"),
            Some(&Entry::Valid(Policy {
                delegate: "mupe".into(),
                leads: vec!["poli".into(), "valo".into()],
                wake_intents: vec!["request".into()],
                wake_prefixes: vec!["BLOCKED".into(), "DECISION".into()],
            }))
        );
        assert!(
            parse("[terminal]\nactive = \"default\"\n")
                .entries
                .is_empty()
        );
    }

    #[test]
    fn parse_invalid_entries_fail_closed() {
        for bad in [
            "[delivery.conductor]\nleads = [\"poli\"]\n",
            "[delivery.conductor]\ndelegate = \"  \"\n",
            "[delivery.conductor]\ndelegate = 3\n",
            "[delivery.conductor]\ndelegate = \"mupe\"\nleads = \"poli\"\n",
            "[delivery.conductor]\ndelegate = \"mupe\"\nwake_intents = [\"shout\"]\n",
            "[delivery.conductor]\ndelegate = \"mupe\"\nwake_prefixes = [\"blocked\"]\n",
            "[delivery.conductor]\ndelegate = \"mupe\"\nlead = [\"poli\"]\n",
            "[delivery]\nconductor = \"mupe\"\n",
            // Whole file unparseable: the header alone still fails closed.
            "[delivery.conductor]\ndelegate = \"mupe\"\n[terminal\n",
        ] {
            assert!(
                matches!(parse(bad).entries.get("conductor"), Some(Entry::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn rule_admits_delegate_leads_with_wake_word_and_external_only() {
        let policies = held(CONDUCTOR);
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
        // Broadcasts never reach a role holder, whoever sends them.
        for from in ["mupe", "bigboss"] {
            let broadcast = MessageFacts {
                external: from == "bigboss",
                targeted: false,
                ..facts(from, Some("request"), "BLOCKED: x")
            };
            assert!(!policies.admits("kimi", &broadcast));
        }
        // Not a role holder, or a role with no entry: unchanged.
        assert_eq!(
            policies.send_verdict("nova", &facts("valo", None, "hi")),
            SendVerdict::Deliver
        );
        assert_eq!(
            parse(CONDUCTOR).send_verdict("kimi", &facts("valo", None, "hi")),
            SendVerdict::Deliver
        );
    }

    #[test]
    fn invalid_entry_admits_only_external_targeted() {
        let policies = held("[delivery.conductor]\nleads = [\"valo\"]\n");
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
        assert!(!policies.admits("kimi", &broadcast));
    }
}
