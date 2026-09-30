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
//! not exempt. Broadcasts of any sender kind never reach it. Nothing refused
//! is dropped (zori's ruling): `hcom send` rewrites a refused recipient to
//! the delegate, and the holder's consuming read (`HcomDb::scan_unread`)
//! forwards every refused targeted message that did not go through `hcom
//! send` (system notices, older or unconfigured peers, events written before
//! the role was registered) to the delegate once, with a notice to an
//! instance sender (`HcomDb::forward_refused`). Rerouted and forwarded copies
//! carry `delivery_reroutes`, so they are never re-evaluated, even when the
//! delegate holds a role of its own (one hop).
//!
//! A broken block (not a table, wrong types, unknown keys, or a config.toml
//! that no longer parses while it still names `[delivery.<role>]`) keeps its
//! readable `delegate` and nothing else: no leads, default wake words. With
//! no readable delegate there is nowhere to forward, so the holder receives
//! every targeted message, `hcom status` / `hcom list` say `delivery policy
//! INVALID`, and the holder gets one notice per policy hash. A database
//! error while reading the role holders is never read as "no holders":
//! readers deliver nothing that round and a send fails.
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

use serde_json::Value;

use crate::db::HcomDb;

const DEFAULT_WAKE_INTENTS: &[&str] = &["request"];
const DEFAULT_WAKE_PREFIXES: &[&str] = &["BLOCKED", "DECISION"];
const KNOWN_KEYS: &[&str] = &["delegate", "leads", "wake_intents", "wake_prefixes"];
/// kv key holding the hash of the last policy an audit line was written for.
const KV_LOGGED_HASH: &str = "delivery_policy:logged_hash";
/// kv prefix of one role registration per instance name.
const KV_ROLE_PREFIX: &str = "delivery_role:";
/// Event field recording `{refused recipient: delegate}` for a rerouted send
/// or a forward copy: the delegate named there is never re-evaluated.
pub const REROUTES_FIELD: &str = "delivery_reroutes";
/// Forward copy field naming the local id of the event it forwards.
pub const FORWARD_OF_FIELD: &str = "delivery_forward_of";
/// kv claim: the resolved delegate has its copy of one message
/// (`<delegate>:<origin>`; the primary key is the exactly-once).
pub const KV_FORWARDED_PREFIX: &str = "delivery_forwarded:";
/// kv marker: one holder's refusal of one message is handled, forwarded
/// (`<holder>:<origin>`). Checked first, so a later read never re-decides it.
pub const KV_FORWARD_HANDLED_PREFIX: &str = "delivery_forward_handled:";
/// kv record (JSON `ForwardFailure`) of a forward that failed for good and
/// went to the holder (`<holder>:<origin>`).
pub const KV_FORWARD_FAILED_PREFIX: &str = "delivery_forward_failed:";
/// kv count of failed forward attempts (`<holder>:<origin>`).
pub const KV_FORWARD_ATTEMPTS_PREFIX: &str = "delivery_forward_attempts:";
/// kv marker: a relayed External message to a holder was audited once.
pub const KV_EXTERNAL_AUDITED_PREFIX: &str = "delivery_external_audited:";
/// Locked-database retries before a forward is given up and the holder
/// gets the message instead.
pub const MAX_FORWARD_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub delegate: String,
    pub leads: Vec<String>,
    pub wake_intents: Vec<String>,
    pub wake_prefixes: Vec<String>,
}

/// One `[delivery.<role>]` entry. `policy` is the rule that applies:
/// the whole block, or, for a broken block whose `delegate` is still
/// readable, that delegate alone (no leads, default wake words). A broken
/// block with no readable delegate has no rule: its holder receives every
/// targeted message (nothing is dropped) and status shows it INVALID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub policy: Option<Policy>,
    /// Why the block is broken; `None` for a valid block.
    pub invalid: Option<String>,
}

impl Entry {
    fn valid(policy: Policy) -> Self {
        Self {
            policy: Some(policy),
            invalid: None,
        }
    }

    /// A broken block, degraded to its readable delegate when there is one.
    fn broken(reason: String, delegate: Option<String>) -> Self {
        Self {
            policy: delegate.map(|delegate| Policy {
                delegate,
                leads: Vec::new(),
                wake_intents: DEFAULT_WAKE_INTENTS.iter().map(|s| s.to_string()).collect(),
                wake_prefixes: DEFAULT_WAKE_PREFIXES
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            }),
            invalid: Some(reason),
        }
    }
}

/// The row a role registration was written for. A holder counts only while
/// this exact row is live, and a forward commits only if it still is.
#[derive(Debug, Clone, PartialEq)]
pub struct Registration {
    pub role: String,
    pub session_id: String,
    pub created_at: f64,
}

/// The `[delivery.*]` entries in effect (keyed by role) and the live
/// instances holding each role.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Policies {
    entries: BTreeMap<String, Entry>,
    /// instance name -> its registration, live registrations only.
    holders: BTreeMap<String, Registration>,
    /// config.toml did not parse or could not be read (why): `load` gives
    /// every registered role an entry, so none is silently unfiltered.
    config_broken: Option<&'static str>,
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
}

/// What a reader does with one stored message event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadVerdict {
    Deliver,
    /// Not for this reader (a broadcast to a role holder).
    Skip,
    /// A targeted message the holder refuses: it goes to the delegate as a
    /// forward copy, never dropped.
    ForwardTo(String),
}

impl Policies {
    /// The entry governing `instance`, if it holds a configured role.
    fn entry_for(&self, instance: &str) -> Option<&Entry> {
        self.entries.get(&self.holders.get(instance)?.role)
    }

    /// The registration that makes `instance` a governed holder, if it is one.
    pub fn registration(&self, instance: &str) -> Option<&Registration> {
        self.holders
            .get(instance)
            .filter(|reg| self.entries.contains_key(&reg.role))
    }

    /// `instance` holds a role that has a `[delivery.*]` entry.
    pub fn governs(&self, instance: &str) -> bool {
        self.entry_for(instance).is_some()
    }

    /// Send-side decision for a recipient of a targeted message.
    pub fn send_verdict(&self, recipient: &str, msg: &MessageFacts<'_>) -> SendVerdict {
        match self.entry_for(recipient) {
            Some(entry) if !entry_admits(entry, msg) => match &entry.policy {
                Some(policy) => SendVerdict::RerouteTo(policy.delegate.clone()),
                None => SendVerdict::Deliver,
            },
            _ => SendVerdict::Deliver,
        }
    }

    /// The rule alone, for a receiver that is not a reroute delegate.
    pub fn admits(&self, receiver: &str, msg: &MessageFacts<'_>) -> bool {
        self.entry_for(receiver)
            .is_none_or(|entry| entry_admits(entry, msg))
    }

    /// Receive-side backstop for one stored message event already in the
    /// receiver's scope. A receiver named as a reroute delegate on the event
    /// is admitted without evaluating its own policy (one hop, never
    /// re-evaluated); forward copies carry that mark.
    pub fn read_verdict(&self, receiver: &str, data: &Value) -> ReadVerdict {
        let Some(entry) = self.entry_for(receiver) else {
            return ReadVerdict::Deliver;
        };
        // One hop, keyed on the event's data marks, never on `from` (a relay
        // import namespaces `from`): a forward copy is only ever addressed to
        // its delegate, and a rerouted send names its delegate. Names compare
        // by base name because import strips this host's suffix from the
        // targets but not from the reroute map.
        let base = |name: &str| name.split(':').next().unwrap_or(name).to_string();
        let receiver_base = base(receiver);
        let rerouted_here = data.get(FORWARD_OF_FIELD).is_some()
            || data
                .get(REROUTES_FIELD)
                .and_then(|v| v.as_object())
                .is_some_and(|map| {
                    map.values()
                        .filter_map(|to| to.as_str())
                        .any(|to| to == receiver || base(to) == receiver_base)
                });
        let facts = MessageFacts::from_event(data);
        if rerouted_here || entry_admits(entry, &facts) {
            return ReadVerdict::Deliver;
        }
        match (&entry.policy, facts.targeted) {
            (Some(policy), true) => ReadVerdict::ForwardTo(policy.delegate.clone()),
            _ => ReadVerdict::Skip,
        }
    }

    /// Every configured role with its live holders (empty = NONE).
    pub fn role_holders(&self) -> Vec<(&str, Vec<&str>)> {
        self.entries
            .keys()
            .map(|role| {
                let holders = self
                    .holders
                    .iter()
                    .filter(|(_, reg)| reg.role == *role)
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
        // Name -> role only: a holder re-registering under a new session is
        // not a policy change.
        let holders: BTreeMap<&str, &str> = self
            .holders
            .iter()
            .map(|(name, reg)| (name.as_str(), reg.role.as_str()))
            .collect();
        let digest = Sha256::digest(format!("{:?}{holders:?}", self.entries).as_bytes());
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
    // No readable delegate: nowhere to forward, so the holder keeps it.
    let Some(policy) = &entry.policy else {
        return true;
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
        Err(_) => return fail_closed_from_text(content),
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
        config_broken: None,
    }
}

/// Why every entry recovered from an unparseable config.toml is broken.
const UNPARSEABLE: &str = "config.toml does not parse";
/// Why every registered role is broken when config.toml cannot be read.
const UNREADABLE: &str = "config.toml cannot be read";

/// config.toml no longer parses: every delivery role still named in the
/// text stays in force, degraded to its `delegate` when one is readable,
/// rather than silently dropping its protection. Reads `[delivery.<role>]`
/// headers (spaced or quoted), dotted keys (`delivery.<role>.delegate = ..`,
/// or `<role>.delegate = ..` under `[delivery]`) and inline tables
/// (`<role> = { delegate = .. }`). `load` adds a broken entry for every
/// registered role the text no longer names.
fn fail_closed_from_text(content: &str) -> Policies {
    let mut roles: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut table: Vec<String> = Vec::new();
    for line in content.lines().map(str::trim) {
        if line.starts_with("[[") {
            table.clear();
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            table = key_path(header.split(']').next().unwrap_or(""));
            if let [delivery, role] = table.as_slice()
                && delivery == "delivery"
            {
                roles.entry(role.clone()).or_default();
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let mut path = table.clone();
        path.extend(key_path(key));
        match path.as_slice() {
            [delivery, role] if delivery == "delivery" => {
                // An inline table: `<role> = { delegate = "mupe", ... }`.
                let slot = roles.entry(role.clone()).or_default();
                if let Some(delegate) = inline_delegate(value) {
                    *slot = Some(delegate);
                }
            }
            [delivery, role, field] if delivery == "delivery" => {
                let slot = roles.entry(role.clone()).or_default();
                if field == "delegate"
                    && let Some(delegate) = string_value(value)
                {
                    *slot = Some(delegate);
                }
            }
            _ => {}
        }
    }
    Policies {
        entries: roles
            .into_iter()
            .map(|(role, delegate)| (role, Entry::broken(UNPARSEABLE.to_string(), delegate)))
            .collect(),
        holders: BTreeMap::new(),
        config_broken: Some(UNPARSEABLE),
    }
}

/// `delivery . "conductor"` -> `["delivery", "conductor"]`.
fn key_path(key: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut quote: Option<char> = None;
    for c in key.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => part.push(c),
            (None, '"' | '\'') => quote = Some(c),
            (None, '.') => parts.push(std::mem::take(&mut part)),
            (None, c) if c.is_whitespace() => {}
            (None, c) => part.push(c),
        }
    }
    parts.push(part);
    parts
}

/// The string at the start of a TOML value (`"mupe" # note` -> `mupe`).
fn string_value(value: &str) -> Option<String> {
    let value = value.trim_start();
    let quote = value.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &value[1..];
    let end = rest.find(quote)?;
    let s = rest[..end].trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// `delegate` inside an inline table value `{ delegate = "mupe", ... }`.
fn inline_delegate(value: &str) -> Option<String> {
    let inner = value.trim().strip_prefix('{')?;
    inner.split(',').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key_path(key) == ["delegate"]).then(|| string_value(value))?
    })
}

fn parse_entry(value: &toml::Value) -> Entry {
    let Some(table) = value.as_table() else {
        return Entry::broken("entry is not a table".to_string(), None);
    };
    let delegate = table
        .get("delegate")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(str::to_string);
    match parse_policy(table, delegate.clone()) {
        Ok(policy) => Entry::valid(policy),
        Err(reason) => Entry::broken(reason, delegate),
    }
}

fn parse_policy(table: &toml::Table, delegate: Option<String>) -> Result<Policy, String> {
    if let Some(unknown) = table.keys().find(|k| !KNOWN_KEYS.contains(&k.as_str())) {
        return Err(format!("unknown key `{unknown}`"));
    }
    let delegate = delegate.ok_or("`delegate` must be a non-empty string")?;
    let leads = string_list(table, "leads", &[])?;
    let wake_intents = string_list(table, "wake_intents", DEFAULT_WAKE_INTENTS)?;
    if let Some(bad) = wake_intents
        .iter()
        .find(|i| crate::core::helpers::validate_intent(i).is_err())
    {
        return Err(format!("`wake_intents` has unknown intent `{bad}`"));
    }
    let wake_prefixes = string_list(table, "wake_prefixes", DEFAULT_WAKE_PREFIXES)?;
    if let Some(bad) = wake_prefixes
        .iter()
        .find(|p| p.is_empty() || p.chars().any(|c| c.is_lowercase() || c.is_whitespace()))
    {
        return Err(format!(
            "`wake_prefixes` entry `{bad}` must be a non-empty uppercase word"
        ));
    }
    Ok(Policy {
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
/// means no DB query at all, unless config.toml does not parse.
///
/// A DB error while reading the holders is an error, never "no holders":
/// that would switch the filter off for one read. Readers deliver nothing
/// and leave the cursor where it is; a send fails.
pub fn load(db: &HcomDb) -> Result<Policies, String> {
    // Only a missing file means "no policy". Any other read failure is a
    // broken config: fail closed like an unparseable one.
    let mut policies = match std::fs::read_to_string(crate::paths::config_toml_path()) {
        Ok(content) => parse(&content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Policies::default(),
        Err(_) => Policies {
            config_broken: Some(UNREADABLE),
            ..Policies::default()
        },
    };
    if !policies.entries.is_empty() || policies.config_broken.is_some() {
        policies.holders = live_role_holders(db)
            .map_err(|e| format!("delivery policy: cannot read role holders: {e}"))?;
    }
    if let Some(reason) = policies.config_broken {
        // A registered role the broken text no longer names still gets an
        // entry: INVALID in status, and its holder receives everything
        // targeted (no delegate to send it to), never silently unfiltered.
        for reg in policies.holders.values() {
            policies
                .entries
                .entry(reg.role.clone())
                .or_insert_with(|| Entry::broken(reason.to_string(), None));
        }
    }
    audit(db, &policies);
    Ok(policies)
}

/// Why a configured delegate names no single live row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unresolved {
    NotLive,
    /// Several live rows match (the resolver's refusal).
    Ambiguous(String),
}

impl Unresolved {
    /// `mupe is not live` / `mupe is ambiguous (...)`, for notices and logs.
    pub fn describe(&self, delegate: &str) -> String {
        match self {
            Unresolved::NotLive => format!("{delegate} is not live"),
            Unresolved::Ambiguous(why) => format!("{delegate} is ambiguous ({why})"),
        }
    }
}

/// The live row a configured `delegate` names. A live row with exactly that
/// name wins (so a local `mupe` is never made ambiguous by a relayed
/// namesake); otherwise it resolves like a send target (a bare name live
/// only as a remote mirror maps to that mirror row). The resolver's virtual
/// sender identity has no row and never counts.
pub(crate) fn resolve_delegate(
    delegate: &str,
    rows: &[crate::messages::InstanceInfo],
    fleet: &crate::fleet_names::FleetCtx,
) -> Result<String, Unresolved> {
    if rows.iter().any(|row| row.name == delegate) {
        return Ok(delegate.to_string());
    }
    let (matched, _) = crate::messages::resolve_targets(&[delegate.to_string()], rows, fleet)
        .map_err(Unresolved::Ambiguous)?;
    let real: Vec<&String> = matched
        .iter()
        .filter(|name| rows.iter().any(|row| row.name == **name))
        .collect();
    match real.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(Unresolved::NotLive),
        several => Err(Unresolved::Ambiguous(format!(
            "matches {}",
            several
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// One registration, stored in kv under `delivery_role:<name>`. It counts
/// only while the exact row it was written for (name + session id +
/// created_at) is still there and live. `created_at` is kept as its exact
/// f64 bit pattern: a serde f64 round trip can land one ULP off a real
/// timestamp (see `db::raw_created_at_bits`), and then the row never matches.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RoleRecord {
    role: String,
    session_id: String,
    created_at_bits: u64,
}

impl RoleRecord {
    fn created_at(&self) -> f64 {
        f64::from_bits(self.created_at_bits)
    }
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
            rusqlite::params![name, record.session_id, record.created_at()],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
}

fn read_record(value: &str) -> Option<RoleRecord> {
    serde_json::from_str(value).ok()
}

/// Runs its own query rather than `kv_prefix`, which drops row errors: a
/// failed step here must surface as an error, never as "no holders".
fn live_role_holders(db: &HcomDb) -> Result<BTreeMap<String, Registration>, String> {
    let rows = db
        .conn()
        .prepare_cached("SELECT key, value FROM kv WHERE key >= ?1 AND key < ?2")
        .and_then(|mut stmt| {
            stmt.query_map(rusqlite::params![KV_ROLE_PREFIX, "delivery_role;"], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        })
        .map_err(|e| e.to_string())?;
    let mut holders = BTreeMap::new();
    for (key, value) in rows {
        let (Some(name), Some(record)) = (key.strip_prefix(KV_ROLE_PREFIX), read_record(&value))
        else {
            continue;
        };
        if record_is_live(db, name, &record).map_err(|e| e.to_string())? {
            holders.insert(
                name.to_string(),
                Registration {
                    created_at: record.created_at(),
                    role: record.role,
                    session_id: record.session_id,
                },
            );
        }
    }
    Ok(holders)
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
    // Check and write in one IMMEDIATE transaction: a racing registration of
    // another role waits, then sees this one live and is refused.
    let tx =
        rusqlite::Transaction::new_unchecked(db.conn(), rusqlite::TransactionBehavior::Immediate)
            .map_err(RoleError::transient)?;
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
        created_at_bits: created_at.to_bits(),
    };
    let value = serde_json::to_string(&record).map_err(RoleError::transient)?;
    tx.execute(
        "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, value],
    )
    .map_err(RoleError::transient)?;
    tx.commit().map_err(RoleError::transient)
}

/// Warn for every configured role no live instance holds: the filter is off
/// for it. Called at every omp bind.
pub fn warn_unheld_roles(db: &HcomDb) {
    let policies = match load(db) {
        Ok(policies) => policies,
        Err(e) => {
            crate::log::log_warn("delivery_policy", "load_failed", &e);
            return;
        }
    };
    for (role, holders) in policies.role_holders() {
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

/// One configured role as `hcom status` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleStatus {
    pub role: String,
    /// Live holders; empty means the role's filter is off.
    pub holders: Vec<String>,
    /// Why the block is broken, if it is.
    pub invalid: Option<String>,
    /// Where refused messages go (`None` for a broken block with no
    /// readable delegate: its holders get everything).
    pub delegate: Option<String>,
}

/// Every configured role with its live holders, for `hcom status --json`.
pub fn role_status(db: &HcomDb) -> Result<Vec<RoleStatus>, String> {
    let policies = load(db)?;
    Ok(policies
        .role_holders()
        .into_iter()
        .map(|(role, holders)| {
            let entry = &policies.entries[role];
            RoleStatus {
                role: role.to_string(),
                holders: holders.into_iter().map(str::to_string).collect(),
                invalid: entry.invalid.clone(),
                delegate: entry.policy.as_ref().map(|p| p.delegate.clone()),
            }
        })
        .collect())
}

/// One forward that failed for good: the holder got the message instead.
/// Stored as JSON in the kv value; the key is only a uniqueness token.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ForwardFailure {
    pub holder: String,
    pub delegate: String,
    /// The sender's reference to its message (`#id` or `#id:DEVICE`).
    pub message: String,
    pub reason: String,
}

/// Forwards that failed for good and went to the holder instead. A record
/// whose refusal was also forwarded (a give-up racing another reader's
/// forward) is not a failure: the handled marker is final.
pub fn forward_failures(db: &HcomDb) -> Vec<ForwardFailure> {
    db.kv_prefix(KV_FORWARD_FAILED_PREFIX)
        .unwrap_or_default()
        .into_iter()
        .filter(|(key, _)| {
            let handled = key.replacen(KV_FORWARD_FAILED_PREFIX, KV_FORWARD_HANDLED_PREFIX, 1);
            !matches!(db.kv_get(&handled), Ok(Some(_)))
        })
        .filter_map(|(_, value)| serde_json::from_str(&value).ok())
        .collect()
}

/// `<role> role: <holders>|NONE` per configured role, plus a loud line for a
/// broken block and for every forward that failed, for `hcom status` /
/// `hcom list`.
pub fn role_status_lines(db: &HcomDb) -> Vec<String> {
    let roles = match role_status(db) {
        Ok(roles) => roles,
        Err(e) => return vec![format!("delivery roles: unknown ({e})")],
    };
    let mut lines = Vec::new();
    for status in roles {
        let who = if status.holders.is_empty() {
            "NONE".to_string()
        } else {
            status.holders.join(", ")
        };
        lines.push(format!("{} role: {who}", status.role));
        if let Some(reason) = &status.invalid {
            let effect = match &status.delegate {
                Some(delegate) => format!("delegate {delegate} only, no leads"),
                None => "no delegate: the holder receives everything targeted".to_string(),
            };
            lines.push(format!(
                "delivery policy INVALID: [delivery.{}] {reason} ({effect})",
                status.role
            ));
        }
    }
    for f in forward_failures(db) {
        lines.push(format!(
            "delivery forward failed for message {} to {}: {} ({} keeps it)",
            f.message, f.delegate, f.reason, f.holder
        ));
    }
    lines
}

/// Log one line when the effective policy differs from the last one logged.
/// Compared against the hash persisted in kv (never a per-process memo, which
/// would hide A -> B -> A changes made by other processes) and moved with a
/// compare-and-set, so of several processes loading the same change only the
/// one that moves the stored hash logs it. A broken block with no readable
/// delegate also sends each holder one notice per hash.
fn audit(db: &HcomDb, policies: &Policies) {
    let hash = policies.hash();
    let stored = db.kv_get(KV_LOGGED_HASH).ok().flatten();
    if stored.as_deref().unwrap_or("none") == hash {
        return;
    }
    let moved = match &stored {
        Some(prev) => db.conn().execute(
            "UPDATE kv SET value = ?1 WHERE key = ?2 AND value = ?3",
            rusqlite::params![hash, KV_LOGGED_HASH, prev],
        ),
        None => db.conn().execute(
            "INSERT OR IGNORE INTO kv (key, value) VALUES (?2, ?1)",
            rusqlite::params![hash, KV_LOGGED_HASH],
        ),
    }
    .is_ok_and(|n| n == 1);
    if !moved {
        return;
    }
    let previous = stored.as_deref().unwrap_or("none");
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
    for (role, names) in policies.role_holders() {
        let entry = &policies.entries[role];
        if let Some(reason) = &entry.invalid {
            let effect = match &entry.policy {
                Some(policy) => format!("forwarding to its delegate {} only", policy.delegate),
                None => {
                    "no readable delegate, so every targeted message reaches the holder".to_string()
                }
            };
            crate::log::log_warn(
                "delivery_policy",
                "invalid_entry",
                &format!("[delivery.{role}] is invalid ({reason}); {effect}"),
            );
            if entry.policy.is_none() {
                for holder in &names {
                    // One notice per policy hash and holder, however many
                    // processes see the change: the kv primary key claims it.
                    let claimed = db
                        .conn()
                        .execute(
                            "INSERT OR IGNORE INTO kv (key, value) VALUES (?1, '1')",
                            [format!("delivery_invalid_notice:{hash}:{holder}")],
                        )
                        .is_ok_and(|n| n == 1);
                    if claimed {
                        let _ = crate::db::subscriptions::send_system_message(
                            db,
                            "[hcom-delivery]",
                            &format!(
                                "@{holder} delivery policy INVALID for role {role} ({reason}): no readable delegate, so every targeted message now reaches you. Fix [delivery.{role}] in ~/.hcom/config.toml."
                            ),
                        );
                    }
                }
            }
        }
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
        policies.holders.insert(
            "kimi".to_string(),
            Registration {
                role: "conductor".to_string(),
                session_id: "sess-kimi".to_string(),
                created_at: 1000.0,
            },
        );
        policies
    }

    #[test]
    fn parse_applies_defaults() {
        let policies = parse(CONDUCTOR);
        assert_eq!(
            policies.entries.get("conductor"),
            Some(&Entry::valid(Policy {
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
    fn broken_entries_keep_a_readable_delegate_and_nothing_else() {
        let delegate_only = |delegate: &str| {
            Some(Policy {
                delegate: delegate.into(),
                leads: Vec::new(),
                wake_intents: vec!["request".into()],
                wake_prefixes: vec!["BLOCKED".into(), "DECISION".into()],
            })
        };
        for (bad, policy) in [
            ("[delivery.conductor]\nleads = [\"poli\"]\n", None),
            ("[delivery.conductor]\ndelegate = \"  \"\n", None),
            ("[delivery.conductor]\ndelegate = 3\n", None),
            ("[delivery]\nconductor = \"mupe\"\n", None),
            (
                "[delivery.conductor]\ndelegate = \"mupe\"\nleads = \"poli\"\n",
                delegate_only("mupe"),
            ),
            (
                "[delivery.conductor]\ndelegate = \"mupe\"\nwake_intents = [\"shout\"]\n",
                delegate_only("mupe"),
            ),
            (
                "[delivery.conductor]\ndelegate = \"mupe\"\nwake_prefixes = [\"blocked\"]\n",
                delegate_only("mupe"),
            ),
            (
                "[delivery.conductor]\ndelegate = \"mupe\"\nlead = [\"poli\"]\n",
                delegate_only("mupe"),
            ),
            // Whole file unparseable: the header and its delegate line stand.
            (
                "[delivery.conductor]\ndelegate = \"mupe\"\n[terminal\n",
                delegate_only("mupe"),
            ),
            ("[delivery.conductor]\nleads = [\n[terminal\n", None),
            // Unparseable, in the other shapes TOML allows.
            (
                "[ delivery . \"conductor\" ]\n\"delegate\" = 'mupe'  # note\n[terminal\n",
                delegate_only("mupe"),
            ),
            (
                "delivery.conductor.delegate = \"mupe\"\n[terminal\n",
                delegate_only("mupe"),
            ),
            (
                "[delivery]\nconductor.delegate = \"mupe\"\n[terminal\n",
                delegate_only("mupe"),
            ),
            (
                "[delivery]\nconductor = { leads = [\"poli\"], delegate = \"mupe\" }\n[terminal\n",
                delegate_only("mupe"),
            ),
            (
                "delivery.conductor = { delegate = \"mupe\" }\n[terminal\n",
                delegate_only("mupe"),
            ),
            ("[delivery.conductor]\ndelegate = \"\"\n[terminal\n", None),
        ] {
            let entry = parse(bad).entries.remove("conductor");
            let entry = entry.unwrap_or_else(|| panic!("no entry for {bad}"));
            assert!(entry.invalid.is_some(), "{bad}");
            assert_eq!(entry.policy, policy, "{bad}");
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
    fn broken_entry_without_delegate_delivers_targeted_to_the_holder() {
        let policies = held("[delivery.conductor]\nleads = [\"valo\"]\n");
        for msg in [
            facts("nova", Some("inform"), "cc"),
            MessageFacts {
                external: true,
                ..facts("bigboss", None, "hi")
            },
        ] {
            assert_eq!(policies.send_verdict("kimi", &msg), SendVerdict::Deliver);
        }
        let broadcast = MessageFacts {
            targeted: false,
            ..facts("nova", None, "all")
        };
        assert!(!policies.admits("kimi", &broadcast));
    }
}
