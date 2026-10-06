//! Message operations — routing, scope computation, and delivery formatting.

use crate::fleet_names::{BareCandidate, BareOutcome, FleetCtx, resolve_bare_name};
use crate::relay::control::split_device_suffix;
use crate::shared::{MAX_MESSAGE_SIZE, SENDER, extract_mentions};
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Precompiled regex for @[hcom-*] system notification mentions.
static SYSTEM_BRACKET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"@\[hcom-[a-z]+\]").unwrap());

/// Message scope: broadcast (everyone) or mentions (targeted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageScope {
    Broadcast,
    Mentions,
}

impl MessageScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageScope::Broadcast => "broadcast",
            MessageScope::Mentions => "mentions",
        }
    }
}

impl std::str::FromStr for MessageScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "broadcast" => Ok(MessageScope::Broadcast),
            "mentions" => Ok(MessageScope::Mentions),
            _ => Err(format!("invalid message scope: {s}")),
        }
    }
}

/// Message intent for envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageIntent {
    Request,
    Inform,
    Ack,
}

impl MessageIntent {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageIntent::Request => "request",
            MessageIntent::Inform => "inform",
            MessageIntent::Ack => "ack",
        }
    }
}

impl std::str::FromStr for MessageIntent {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "request" => Ok(MessageIntent::Request),
            "inform" => Ok(MessageIntent::Inform),
            "ack" => Ok(MessageIntent::Ack),
            _ => Err(format!("invalid message intent: {s}")),
        }
    }
}

/// Optional envelope fields for messages.
#[derive(Debug, Clone, Default)]
pub struct MessageEnvelope {
    pub intent: Option<MessageIntent>,
    pub reply_to: Option<String>,
    pub thread: Option<String>,
    pub bundle_id: Option<String>,
}

/// Relay metadata for cross-device messages.
#[derive(Debug, Clone)]
pub struct RelayMetadata {
    pub id: String,
    pub short: String,
}

/// Scope computation result.
#[derive(Debug, Clone)]
pub struct ScopeResult {
    pub scope: MessageScope,
    /// For Mentions scope: resolved exact instance names targeted
    /// (a bare base resolves to its single live candidate, e.g. `x:DEVB`).
    pub mentions: Vec<String>,
}

/// Read receipt for a sent message.
#[derive(Debug, Clone)]
pub struct ReadReceipt {
    pub id: i64,
    pub age: String,
    pub text: String,
    pub read_by: Vec<String>,
    pub total_recipients: usize,
}

/// Instance info for scope computation (name + optional tag + origin device).
#[derive(Debug, Clone)]
pub struct InstanceInfo {
    pub name: String,
    pub tag: Option<String>,
    /// `origin_device_id` of the row: `Some` for a relay mirror row, `None`
    /// for a local one. The fleet resolver's suffix-only flag reads it, so a
    /// listed device is recognized even when the row's `:SHORT` suffix is
    /// not that device's canonical short id (a probed slot, or relay's
    /// 4-char import fallback).
    pub origin: Option<String>,
    /// `tool` of the row, verbatim from the column (relay mirrors carry the
    /// origin's value). Hosted participants are recognized by their tool
    /// string — see [`BUZZ_TOOL`]; `None` when the row was built in memory
    /// by a caller that has no row behind it.
    pub tool: Option<String>,
}

/// `instances.tool` value on rows a Buzz connector hosts: humans in a bridged
/// channel (`michael`) and the channels themselves (`ch_infra`). The column is
/// a free string, so this is a value comparison and not an enum variant.
pub const BUZZ_TOOL: &str = "buzz";

/// Base name of a hosted Buzz channel row (`ch_infra`). A person row never
/// starts with this, so a `base:suffix` target can't pick its own base as
/// the channel to expand into.
pub const BUZZ_CHANNEL_PREFIX: &str = "ch_";

impl InstanceInfo {
    /// Full display name: "{tag}-{name}" if tag, else just "{name}".
    pub fn full_name(&self) -> String {
        match &self.tag {
            Some(tag) if !tag.is_empty() => format!("{}-{}", tag, self.name),
            _ => self.name.clone(),
        }
    }
}

/// Every row a message may be delivered to or a bare name resolved against
/// (the live-row predicate), carrying the `origin_device_id` the fleet
/// suffix-only flag needs and the `tool` the hosted-participant check needs.
/// A row that fails to read is an error, never a missing row: callers decide
/// "not live" from this list.
pub(crate) fn deliverable_instances(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<Vec<InstanceInfo>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT name, tag, origin_device_id, tool FROM instances WHERE {}",
        crate::fleet_names::LIVE_ROW_PREDICATE
    ))?;
    stmt.query_map([], |row| {
        Ok(InstanceInfo {
            name: row.get::<_, String>(0)?,
            tag: row.get::<_, Option<String>>(1)?,
            origin: row.get::<_, Option<String>>(2)?.filter(|s| !s.is_empty()),
            tool: row.get::<_, Option<String>>(3)?.filter(|s| !s.is_empty()),
        })
    })?
    .collect()
}

// validate_scope and validate_intent live in core::helpers — re-export for consumers.
pub use crate::core::helpers::{validate_intent, validate_scope};

/// Validate message content and size.
pub fn validate_message(message: &str) -> Result<(), String> {
    if message.is_empty() || message.trim().is_empty() {
        return Err("Message required".to_string());
    }

    // Reject control characters (except \n, \r, \t)
    for ch in message.chars() {
        if ('\x00'..='\x08').contains(&ch)
            || ('\x0B'..='\x0C').contains(&ch)
            || ('\x0E'..='\x1F').contains(&ch)
            || ('\u{0080}'..='\u{009F}').contains(&ch)
        {
            return Err("Message contains control characters".to_string());
        }
    }

    if message.len() > MAX_MESSAGE_SIZE {
        return Err(format!(
            "Message too large (max {} chars)",
            MAX_MESSAGE_SIZE
        ));
    }

    Ok(())
}

/// Format recipients list for display.
///
/// "luna, nova" or "luna, nova, kira (+2 more)" or "(none)"
pub fn format_recipients(delivered_to: &[String], max_show: usize) -> String {
    if delivered_to.is_empty() {
        return "(none)".to_string();
    }

    if delivered_to.len() > max_show {
        let shown: Vec<&str> = delivered_to[..max_show]
            .iter()
            .map(|s| s.as_str())
            .collect();
        let remaining = delivered_to.len() - max_show;
        format!("{} (+{} more)", shown.join(", "), remaining)
    } else {
        delivered_to.join(", ")
    }
}

/// Build the "unknown @mention" error string with a "Did you mean" hint when
/// an unmatched target (without `:`) has the same base name as a remote agent.
///
/// Without this hint, users hit `@zeli` → "non-existent" even though `zeli:ZOME`
/// is right there in the available list and only takes a colon-suffix to reach.
fn build_unmatched_error(unmatched: &[String], full_names: &[String]) -> String {
    let unmatched_display: Vec<String> = unmatched.iter().map(|t| format!("@{}", t)).collect();

    let mut suggestions: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for target in unmatched {
        if target.contains(':') {
            continue;
        }
        let target_lower = target.to_lowercase();
        for fn_ in full_names {
            if let Some((prefix, _device)) = fn_.split_once(':')
                && prefix.to_lowercase() == target_lower
                && seen.insert(fn_.clone())
            {
                suggestions.push(format!("@{}", fn_));
            }
        }
    }

    let mut msg = format!(
        "@mentions to non-existent or stopped agents (or you used '@' char for stuff that wasn't agent name): {}",
        unmatched_display.join(", "),
    );
    if !suggestions.is_empty() {
        msg.push_str(&format!("\nDid you mean: {}?", suggestions.join(", ")));
    }
    msg.push_str(&format!(
        "\nAvailable: {}",
        format_recipients(full_names, 30)
    ));
    msg
}

/// Fleet bare-name resolution for one input, lifted out of `match_target` so
/// the `base` of a `base:suffix` target resolves by exactly the same rules a
/// bare `@base` does.
///
/// `None` = no live row carries the name (caller falls through); `Some(Ok)` =
/// one exact form; `Some(Err)` = the refusal that names the exact forms.
fn bare_resolution(
    target: &str,
    instances: &[InstanceInfo],
    fleet: &FleetCtx,
) -> Option<Result<String, String>> {
    let mut candidates: Vec<BareCandidate> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for inst in instances {
        if inst.origin.is_none()
            && (inst.name.eq_ignore_ascii_case(target)
                || inst.full_name().eq_ignore_ascii_case(target))
        {
            if seen.insert(inst.name.as_str()) {
                candidates.push(BareCandidate {
                    exact: inst.name.clone(),
                    suffix_only: !fleet.own_uuid.is_empty()
                        && fleet.so.device_is_listed(&fleet.own_uuid),
                    display_match: !inst.name.eq_ignore_ascii_case(target),
                });
            }
        } else if let Some((base, suffix)) = split_device_suffix(&inst.name) {
            // Remote mirror row x:DEV whose base matches the bare input.
            if base.eq_ignore_ascii_case(target) && seen.insert(inst.name.as_str()) {
                candidates.push(BareCandidate {
                    exact: inst.name.clone(),
                    suffix_only: fleet
                        .so
                        .mirror_is_suffix_only(inst.origin.as_deref().unwrap_or_default(), suffix),
                    display_match: false,
                });
            }
        }
    }
    match resolve_bare_name(target, &candidates) {
        BareOutcome::Single(exact) => Some(Ok(exact)),
        BareOutcome::Refuse(msg) => Some(Err(msg)),
        BareOutcome::NoCandidate => None,
    }
}

/// The device-suffix shape `relay::control::split_device_suffix` recognizes:
/// exactly four ASCII uppercase alphanumerics. Restated here (rather than
/// called through a synthetic `x:SUFFIX`) so the connector owns that function;
/// `device_suffix_shape_matches_split_device_suffix` pins the two together.
fn is_device_suffix_shape(suffix: &str) -> bool {
    suffix.len() == 4
        && suffix
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// True when `suffix` names a device in this fleet: the uppercase 4-char shape,
/// or a case-insensitive match against the short id a live remote mirror row
/// carries. A device id always wins over a channel slug — `michael:mbai` is
/// Michael on device MBAI, never Michael in a `#mbai` channel.
fn suffix_is_device_id(suffix: &str, instances: &[InstanceInfo]) -> bool {
    is_device_suffix_shape(suffix)
        || instances.iter().any(|inst| {
            split_device_suffix(&inst.name)
                .is_some_and(|(_, known)| known.eq_ignore_ascii_case(suffix))
        })
}

/// The live row behind an exact resolved name (case-insensitive; the resolver
/// returns canonical row spelling, so this is a lookup by name).
fn row_named<'a>(instances: &'a [InstanceInfo], name: &str) -> Option<&'a InstanceInfo> {
    instances
        .iter()
        .find(|inst| inst.name.eq_ignore_ascii_case(name))
}

/// A hosted Buzz person row: `tool = "buzz"`, and not itself a channel row.
fn is_buzz_person(inst: &InstanceInfo) -> bool {
    inst.tool.as_deref() == Some(BUZZ_TOOL)
        && !inst
            .name
            .to_ascii_lowercase()
            .starts_with(BUZZ_CHANNEL_PREFIX)
}

/// A hosted Buzz channel row: `tool = "buzz"` and a `ch_` base name.
fn is_buzz_channel(inst: &InstanceInfo) -> bool {
    inst.tool.as_deref() == Some(BUZZ_TOOL)
        && inst
            .name
            .to_ascii_lowercase()
            .starts_with(BUZZ_CHANNEL_PREFIX)
}

/// Base name of a row: the part before a `:DEVICE` suffix, or the whole name.
fn row_base(name: &str) -> &str {
    split_device_suffix(name).map_or(name, |(base, _)| base)
}

/// `base:suffix` on a hosted Buzz person: Michael in the `#infra` channel.
///
/// Resolves to BOTH ordinary rows — the person and the channel — so both land
/// in `mentions` / `exact_targets` as plain targets and nothing new travels on
/// the wire. On another device the same input resolves to the mirror pair
/// (`michael:MBAI`, `ch_infra:MBAI`): the person goes through ordinary
/// bare-name resolution, mirrors carry the origin's `tool` string, and the
/// channel is the `ch_<suffix>` row on the person's own device.
///
/// The person may also be named exactly, device suffix included
/// (`michael:MBAI:infra`). That is the form to use when the bare name is
/// ambiguous or lives only on a suffix-only device.
///
/// `None` = not this shape, so the caller keeps today's behaviour. `Some(Err)`
/// = a buzz person is behind the base but the address can't complete, which is
/// worth naming rather than reporting as an unknown agent.
fn buzz_person_in_channel(
    target: &str,
    instances: &[InstanceInfo],
    fleet: &FleetCtx,
) -> Option<Result<Vec<String>, String>> {
    let (base, suffix) = target.rsplit_once(':')?;
    if base.is_empty() || suffix.is_empty() || suffix_is_device_id(suffix, instances) {
        return None;
    }

    let person = if base.contains(':') {
        // Exact person form: a device-qualified name bypasses the fleet
        // resolver, exactly as it does for a plain target.
        row_named(instances, base)?
    } else {
        match bare_resolution(base, instances, fleet) {
            Some(Ok(exact)) => row_named(instances, &exact)?,
            Some(Err(refusal)) => {
                return buzz_person_refusal(target, base, suffix, &refusal, instances);
            }
            None => return None,
        }
    };
    // A non-buzz base keeps today's behaviour exactly.
    if !is_buzz_person(person) {
        return None;
    }

    // The channel is the `ch_<suffix>` row on the person's own device: picked
    // by origin, not by bare-name resolution, because the person already
    // fixed the device (and a suffix-only device would refuse a bare lookup).
    let channel_base = format!("{BUZZ_CHANNEL_PREFIX}{suffix}");
    let named_channel: Vec<&InstanceInfo> = instances
        .iter()
        .filter(|inst| row_base(&inst.name).eq_ignore_ascii_case(&channel_base))
        .collect();
    if named_channel.is_empty() {
        return Some(Err(format!(
            "@{target}: @{} is a buzz person, but no live channel row {channel_base} to address them in",
            person.name
        )));
    }
    match named_channel
        .iter()
        .find(|channel| is_buzz_channel(channel) && channel.origin == person.origin)
    {
        Some(channel) => Some(Ok(vec![person.name.clone(), channel.name.clone()])),
        None => Some(Err(format!(
            "@{target}: {} is not a live buzz channel on @{}'s device",
            named_channel
                .iter()
                .map(|channel| channel.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            person.name
        ))),
    }
}

/// The base's bare resolution refused: it is ambiguous, or live only on a
/// suffix-only device. When a buzz person is behind that refusal the sender
/// meant the channel form, so surface the refusal with the exact
/// `person:DEVICE:channel` forms that work, instead of letting the target fall
/// through to "non-existent agent". No buzz person behind it: `None`, today's
/// behaviour.
fn buzz_person_refusal(
    target: &str,
    base: &str,
    suffix: &str,
    refusal: &str,
    instances: &[InstanceInfo],
) -> Option<Result<Vec<String>, String>> {
    let people: Vec<&InstanceInfo> = instances
        .iter()
        .filter(|inst| is_buzz_person(inst) && row_base(&inst.name).eq_ignore_ascii_case(base))
        .collect();
    if people.is_empty() {
        return None;
    }
    let exact_forms: Vec<String> = people
        .iter()
        .filter(|person| person.name.contains(':'))
        .map(|person| format!("@{}:{suffix}", person.name))
        .collect();
    let mut msg = format!("@{target}: {refusal}");
    if !exact_forms.is_empty() {
        msg.push_str(&format!(
            "\nFor the channel form, name the person exactly: {}",
            exact_forms.join(", ")
        ));
    }
    Some(Err(msg))
}

/// Match a target against instance names.
///
/// Resolution order:
/// 1. A bare input uses the fleet resolver over every live matching seat:
///    local base or full tagged display name, and remote base names. One
///    candidate resolves; multiple candidates refuse and name all exact
///    forms (including a local tagged seat); suffix-only devices count.
/// 2. An explicit device-qualified name bypasses the fleet resolver.
/// 3. Legacy exact, tag-group and unique remote-prefix matching when the
///    fleet has no candidates for the bare input.
/// 4. A colon target nothing above matched — no exact name, no unique
///    device prefix — whose suffix is not a device id and whose base is a
///    hosted Buzz person expands to that person and the `ch_<suffix>`
///    channel row on the same device.
///
/// Special case: bigboss:SUFFIX resolves to bigboss (virtual identity, device-agnostic).
fn match_target(
    target: &str,
    instances: &[InstanceInfo],
    fleet: &FleetCtx,
) -> Result<Vec<String>, String> {
    if !target.contains(':')
        && let Some(outcome) = bare_resolution(target, instances, fleet)
    {
        return outcome.map(|exact| vec![exact]);
    }
    let exact_base: Vec<String> = instances
        .iter()
        .filter(|inst| inst.name.eq_ignore_ascii_case(target))
        .map(|inst| inst.name.clone())
        .collect();
    if !exact_base.is_empty() {
        return Ok(dedup_preserving_order(&exact_base));
    }

    // bigboss is device-agnostic — strip any remote suffix
    if target
        .split_once(':')
        .is_some_and(|(base, _)| base.eq_ignore_ascii_case(SENDER))
    {
        return Ok(vec![SENDER.to_string()]);
    }

    let exact_full: Vec<String> = instances
        .iter()
        .filter(|inst| inst.full_name().eq_ignore_ascii_case(target))
        .map(|inst| inst.name.clone())
        .collect();
    if !exact_full.is_empty() {
        return Ok(dedup_preserving_order(&exact_full));
    }

    if let Some(tag_target) = target.strip_suffix('-') {
        let matches: Vec<String> = instances
            .iter()
            .filter(|inst| !inst.name.contains(':'))
            .filter(|inst| {
                inst.tag
                    .as_deref()
                    .is_some_and(|tag| tag.eq_ignore_ascii_case(tag_target))
            })
            .map(|inst| inst.name.clone())
            .collect();
        return Ok(dedup_preserving_order(&matches));
    }

    if target.contains(':') {
        let target_lower = target.to_ascii_lowercase();
        let mut candidates: Vec<(String, String)> = instances
            .iter()
            .filter_map(|inst| {
                let full = inst.full_name();
                (inst.name.to_ascii_lowercase().starts_with(&target_lower)
                    || full.to_ascii_lowercase().starts_with(&target_lower))
                .then(|| (inst.name.clone(), full))
            })
            .collect();
        candidates.sort();
        candidates.dedup_by(|a, b| a.0 == b.0);

        if candidates.len() == 1 {
            return Ok(vec![candidates[0].0.clone()]);
        }
        if candidates.len() > 1 {
            return Err(format!(
                "Ambiguous remote @mention @{target}; matches: {}",
                candidates
                    .iter()
                    .map(|(_, full)| format!("@{full}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        // `person:channel` on a hosted Buzz row. Last, and only when nothing
        // prefix-matched: a lowercase colon target already prefix-matches
        // device suffixes case-insensitively (`michael:mb` -> `michael:MBAI`),
        // so every target that resolved before keeps resolving and a device
        // always wins over a channel slug.
        if let Some(expansion) = buzz_person_in_channel(target, instances, fleet) {
            return expansion;
        }
    }

    Ok(Vec::new())
}

fn target_instances_with_sender(enabled_instances: &[InstanceInfo]) -> Vec<InstanceInfo> {
    let mut instances = enabled_instances.to_vec();
    if !instances
        .iter()
        .any(|inst| inst.name.eq_ignore_ascii_case(SENDER))
    {
        instances.push(InstanceInfo {
            name: SENDER.to_string(),
            tag: None,
            // The virtual identity has no row: it is never a mirror.
            origin: None,
            tool: None,
        });
    }
    instances
}

pub(crate) fn resolve_targets(
    targets: &[String],
    enabled_instances: &[InstanceInfo],
    fleet: &FleetCtx,
) -> Result<(Vec<String>, Vec<String>), String> {
    let target_instances = target_instances_with_sender(enabled_instances);
    let mut matched = Vec::new();
    let mut unmatched = Vec::new();

    for target in targets {
        let target_matches = match_target(target, &target_instances, fleet)?;
        if target_matches.is_empty() {
            unmatched.push(target.clone());
        } else {
            matched.extend(target_matches);
        }
    }

    Ok((dedup_preserving_order(&matched), unmatched))
}

/// Compute message scope and routing data.
///
/// Returns Ok((scope_result, None)) on success, Ok((None, error)) on validation failure.
///
/// Scope types:
/// - Broadcast: No targets → everyone
/// - Mentions: Has targets → explicit targets only
///
/// STRICT FAILURE: Targets that don't match enabled instances return error.
pub fn compute_scope(
    message: &str,
    enabled_instances: &[InstanceInfo],
    explicit_targets: Option<&[String]>,
    fleet: &FleetCtx,
) -> Result<ScopeResult, String> {
    let target_instances = target_instances_with_sender(enabled_instances);
    let full_names: Vec<String> = target_instances
        .iter()
        .map(InstanceInfo::full_name)
        .collect();

    // If explicit targets specified (via -- separator), use them instead of parsing @mentions
    if let Some(targets) = explicit_targets {
        if !targets.is_empty() {
            let (matched_base_names, unmatched) =
                resolve_targets(targets, enabled_instances, fleet)?;

            if !unmatched.is_empty() {
                return Err(build_unmatched_error(&unmatched, &full_names));
            }

            if !matched_base_names.is_empty() {
                return Ok(ScopeResult {
                    scope: MessageScope::Mentions,
                    mentions: matched_base_names,
                });
            }
        }

        // Empty explicit_targets or no matches = broadcast
        return Ok(ScopeResult {
            scope: MessageScope::Broadcast,
            mentions: vec![],
        });
    }

    // No explicit targets (None) — check for @mentions in message text
    if message.contains('@') {
        // Check for invalid system notification mention attempts like @[hcom-events]
        let system_attempts: Vec<&str> = SYSTEM_BRACKET_RE
            .find_iter(message)
            .map(|m| m.as_str())
            .collect();
        if !system_attempts.is_empty() {
            return Err(format!(
                "System notifications cannot be mentioned: {}\nSystem notifications (names in []) are not agents and cannot receive messages.",
                system_attempts.join(", "),
            ));
        }

        let mentions = extract_mentions(message);
        if !mentions.is_empty() {
            let (matched_base_names, unmatched) =
                resolve_targets(&mentions, enabled_instances, fleet)?;

            // STRICT: fail on unmatched mentions
            if !unmatched.is_empty() {
                // Special cases: literal "@mention", "@name", or "@mentions"
                let special_literals: HashSet<&str> =
                    ["mention", "name", "mentions"].iter().copied().collect();
                let literal_matches: Vec<&String> = unmatched
                    .iter()
                    .filter(|m| special_literals.contains(m.as_str()))
                    .collect();

                if !literal_matches.is_empty() {
                    let literal_text = if literal_matches.len() == 1 {
                        format!("@{}", literal_matches[0])
                    } else {
                        literal_matches
                            .iter()
                            .map(|m| format!("@{}", m))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    return Err(format!(
                        "The literal text {} is not a valid target - use actual instance names",
                        literal_text,
                    ));
                }

                return Err(build_unmatched_error(&unmatched, &full_names));
            }

            return Ok(ScopeResult {
                scope: MessageScope::Mentions,
                mentions: matched_base_names,
            });
        }
    }

    // No @mentions → broadcast to everyone
    Ok(ScopeResult {
        scope: MessageScope::Broadcast,
        mentions: vec![],
    })
}

/// Deduplicate a list preserving insertion order.
fn dedup_preserving_order(items: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            result.push(item.clone());
        }
    }
    result
}

/// The mentions-scope delivery decision for one receiver, shared verbatim
/// with `db::events`'s `should_deliver_to` (the same predicate over a stored
/// row — they must be edited together).
///
/// Device-exact delivery: when the event carries a non-empty `exact_targets`
/// array (mentions resolved to canonical exact instance names at send time),
/// delivery is a pure exact-string match against the receiver name. When the
/// key is absent or empty (old-format event from a peer without exact
/// targets), delivery falls back to the legacy base-name match.
pub fn mentions_delivers_to(event_data: &Value, receiver_name: &str) -> bool {
    if let Some(exacts) = event_data.get("exact_targets").and_then(|v| v.as_array()) {
        let exact_strs: Vec<&str> = exacts.iter().filter_map(|v| v.as_str()).collect();
        if !exact_strs.is_empty() {
            return exact_strs.contains(&receiver_name);
        }
    }
    let mentions: Vec<&str> = event_data
        .get("mentions")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !mentions.is_empty() && event_data.get("exact_targets").is_none() {
        // Only an OLD peer or a sender that forgot to stamp the field lands
        // here; log it so the two stay distinguishable after the fact.
        crate::log::log_debug(
            "messages",
            "mentions_delivery_without_exact_targets",
            &format!(
                "legacy base-name match for mentions [{}]",
                mentions.join(", ")
            ),
        );
    }

    // Strip device suffix for cross-device matching
    let receiver_base = receiver_name.split(':').next().unwrap_or(receiver_name);
    mentions
        .iter()
        .any(|m| receiver_base == m.split(':').next().unwrap_or(m))
}

/// Check if message should be delivered based on scope.
///
/// Returns true if receiver should get the message. The mentions-scope rule
/// itself lives in [`mentions_delivers_to`].
pub fn should_deliver_message(
    event_data: &Value,
    receiver_name: &str,
    sender_name: &str,
) -> Result<bool, String> {
    if receiver_name == sender_name {
        return Ok(false);
    }

    let scope = event_data
        .get("scope")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Message missing 'scope' field (old format)".to_string())?;

    validate_scope(scope)?;

    match scope {
        "broadcast" => Ok(true),
        "mentions" => Ok(mentions_delivers_to(event_data, receiver_name)),
        _ => Ok(false),
    }
}

/// Build message prefix from envelope fields.
///
/// Format: [intent:thread #id] or [intent #id] or [thread:name #id] or [new message #id]
/// Remote messages: #id:DEVICE
fn build_message_prefix(msg: &Value) -> String {
    let intent = msg.get("intent").and_then(|v| v.as_str());
    let thread = msg.get("thread").and_then(|v| v.as_str());
    let event_id = msg.get("event_id").and_then(|v| v.as_i64());
    let relay = msg.get("_relay");

    // Build ID reference (local or remote)
    let id_ref = if let Some(relay) = relay {
        let short = relay.get("short").and_then(|v| v.as_str()).unwrap_or("");
        let rid = relay.get("id");
        if !short.is_empty()
            && let Some(rid_val) = rid
        {
            let rid_str = match rid_val {
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.clone(),
                _ => String::new(),
            };
            if !rid_str.is_empty() {
                format!("#{}:{}", rid_str, short)
            } else {
                String::new()
            }
        } else {
            event_id.map(|id| format!("#{}", id)).unwrap_or_default()
        }
    } else {
        event_id.map(|id| format!("#{}", id)).unwrap_or_default()
    };

    // Build prefix based on envelope fields
    let prefix = match (intent, thread) {
        (Some(i), Some(t)) => format!("{}:{}", i, t),
        (Some(i), None) => i.to_string(),
        (None, Some(t)) => format!("thread:{}", t),
        (None, None) => "new message".to_string(),
    };

    if !id_ref.is_empty() {
        format!("[{} {}]", prefix, id_ref)
    } else {
        format!("[{}]", prefix)
    }
}

/// Format messages for hook feedback.
///
/// Single message uses verbose format: "sender → recipient + N others"
/// Multiple messages use compact format: "sender → recipient (+N)"
///
/// `instance_name`: base name of the receiving instance.
/// `get_instance_data`: callback to get instance data by name (for tag lookup).
/// `get_config_hints`: callback to get config hints.
/// `tip_checker`: optional callback for tip system (has_seen, mark_seen).
#[allow(clippy::type_complexity)]
pub fn format_hook_messages(
    messages: &[Value],
    instance_name: &str,
    get_instance_data: &dyn Fn(&str) -> Option<Value>,
    get_config_hints: &dyn Fn() -> String,
    tip_checker: Option<&dyn Fn(&str, &str) -> (bool, Box<dyn Fn()>)>,
) -> String {
    let recipient_display = get_display_name_from_data(instance_name, get_instance_data);

    let get_sender_display = |sender_base: &str| -> String {
        if let Some(data) = get_instance_data(sender_base) {
            get_full_name_from_value(&data)
        } else {
            sender_base.to_string()
        }
    };

    let reason = if messages.len() == 1 {
        let msg = &messages[0];
        let others = others_count(msg);
        let recipient = if others > 0 {
            let suffix = if others > 1 { "s" } else { "" };
            format!("{} (+{} other{})", recipient_display, others, suffix)
        } else {
            recipient_display.clone()
        };
        let prefix = build_message_prefix(msg);
        let sender_name = msg
            .get("from")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let sender_display = get_sender_display(sender_name);
        let text = msg.get("message").and_then(|v| v.as_str()).unwrap_or("");
        format!("{} {} → {}: {}", prefix, sender_display, recipient, text)
    } else {
        let parts: Vec<String> = messages
            .iter()
            .map(|msg| {
                let others = others_count(msg);
                let recipient = if others > 0 {
                    format!("{} (+{})", recipient_display, others)
                } else {
                    recipient_display.clone()
                };
                let prefix = build_message_prefix(msg);
                let sender_name = msg
                    .get("from")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let sender_display = get_sender_display(sender_name);
                let text = msg.get("message").and_then(|v| v.as_str()).unwrap_or("");
                format!("{} {} → {}: {}", prefix, sender_display, recipient, text)
            })
            .collect();
        format!("[{} new messages] | {}", messages.len(), parts.join(" | "))
    };

    // Append hints
    let mut result = reason;

    // Per-instance hints from data
    let mut hints = String::new();
    if let Some(data) = get_instance_data(instance_name)
        && let Some(h) = data.get("hints").and_then(|v| v.as_str())
        && !h.is_empty()
    {
        hints = h.to_string();
    }
    if hints.is_empty() {
        hints = get_config_hints();
    }
    if !hints.is_empty() {
        result = format!("{} | [{}]", result, hints);
    }

    // Show recv:thread tip on first receipt in each thread
    if let Some(tip_fn) = tip_checker {
        for msg in messages {
            if let Some(thread) = msg.get("thread").and_then(|v| v.as_str()) {
                let tip_key = format!("recv:thread:{thread}");
                let (seen, mark) = tip_fn(instance_name, &tip_key);
                if !seen {
                    mark();
                    result = format!("{}\n{}", result, get_thread_tip_text(instance_name, thread));
                    return result;
                }
            }
        }

        // Show recv:intent tip on first receipt of each intent type
        for msg in messages {
            if let Some(intent) = msg.get("intent").and_then(|v| v.as_str()) {
                let tip_key = format!("recv:intent:{}", intent);
                let (seen, mark) = tip_fn(instance_name, &tip_key);
                if !seen && let Some(tip_text) = get_tip_text(&tip_key) {
                    mark();
                    result = format!("{}\n{}", result, tip_text);
                    break; // Only show one tip per delivery
                }
            }
        }
    }

    result
}

/// Format messages for model injection — wraps in <hcom> tags.
#[allow(clippy::type_complexity)]
pub fn format_messages_json(
    messages: &[Value],
    instance_name: &str,
    get_instance_data: &dyn Fn(&str) -> Option<Value>,
    get_config_hints: &dyn Fn() -> String,
    tip_checker: Option<&dyn Fn(&str, &str) -> (bool, Box<dyn Fn()>)>,
) -> String {
    let formatted = format_hook_messages(
        messages,
        instance_name,
        get_instance_data,
        get_config_hints,
        tip_checker,
    );
    format!("<hcom>{}</hcom>", formatted)
}

/// Get full name from instance data Value.
fn get_full_name_from_value(data: &Value) -> String {
    let name = data.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let tag = data.get("tag").and_then(|v| v.as_str()).unwrap_or("");
    if !tag.is_empty() {
        format!("{}-{}", tag, name)
    } else {
        name.to_string()
    }
}

/// Get display name for an instance by looking up its data.
fn get_display_name_from_data(
    base_name: &str,
    get_instance_data: &dyn Fn(&str) -> Option<Value>,
) -> String {
    if let Some(data) = get_instance_data(base_name) {
        let full = get_full_name_from_value(&data);
        if !full.is_empty() {
            return full;
        }
    }
    base_name.to_string()
}

/// Count other recipients (excluding self) from a message.
fn others_count(msg: &Value) -> usize {
    msg.get("delivered_to")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len().saturating_sub(1))
        .unwrap_or(0)
}

/// Tip text for recv:intent tips. Delegates to core::tips for centralized text.
fn get_tip_text(tip_key: &str) -> Option<&'static str> {
    crate::core::tips::get_tip(tip_key)
}

fn get_thread_tip_text(instance_name: &str, thread: &str) -> String {
    let sub_id = crate::db::subscriptions::thread_membership_sub_id(thread, instance_name);
    format!(
        "[tip] You joined thread {thread}. To leave: hcom events unsub {sub_id} (find your sub-id with: hcom events sub list)"
    )
}

/// Remove bash escape sequences from message content.
///
/// Bash escapes special characters when constructing commands. Since hcom
/// receives messages as command arguments, we unescape common sequences
/// that don't affect the actual message intent.
///
/// NOTE: We do NOT unescape '\\\\' to '\\'. If double backslashes survived
/// bash processing, the user intended them (e.g., Windows paths, regex, JSON).
pub fn unescape_bash(text: &str) -> String {
    text.replace("\\!", "!")
        .replace("\\$", "$")
        .replace("\\`", "`")
        .replace("\\\"", "\"")
        .replace("\\'", "'")
}

/// Check if instance data represents an external sender.
///
/// External senders have empty/null session_id, no parent_session_id,
/// and no origin_device_id.
fn is_external_sender_data(data: &Value) -> bool {
    // Remote instances are not external
    if data
        .get("origin_device_id")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        return false;
    }
    // Subagents have parent_session_id, so are not external
    if data
        .get("parent_session_id")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        return false;
    }
    // External = no session_id
    let session_id = data
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    session_id.is_empty()
}

/// Compute read receipts from pre-fetched data.
///
/// This is a pure function that takes all needed data as parameters
/// (no DB access). The caller is responsible for querying the DB.
///
/// # Arguments
/// * `sent_messages` - Messages sent by this identity: (id, timestamp, data_json)
/// * `active_instances` - All active instances except sender: {name: {tag, origin_device_id, ...}}
/// * `deliver_events` - Set of instance names that have deliver events after each message
/// * `remote_msg_ts` - For remote instances: {name: latest msg_ts}
/// * `max_text_length` - Max text length before truncation
/// * `format_age_fn` - Function to format seconds as age string
#[allow(clippy::too_many_arguments)]
pub fn compute_read_receipts(
    sent_messages: &[(i64, String, Value)],
    active_instances: &HashMap<String, Value>,
    deliver_events_by_msg: &HashMap<i64, HashSet<String>>,
    remote_msg_ts: &HashMap<String, String>,
    max_text_length: usize,
    format_age_fn: &dyn Fn(f64) -> String,
    now_secs: f64,
    parse_timestamp_fn: &dyn Fn(&str) -> Option<f64>,
) -> Vec<ReadReceipt> {
    let mut receipts = Vec::new();

    for (msg_id, msg_timestamp, msg_data) in sent_messages {
        // Validate scope field present
        if msg_data.get("scope").is_none() {
            continue;
        }

        // Use delivered_to for read receipt denominator
        let delivered_to = match msg_data.get("delivered_to").and_then(|v| v.as_array()) {
            Some(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>(),
            None => continue,
        };

        let explicit_mentions: HashSet<&str> = msg_data
            .get("mentions")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
            .collect();
        let msg_text = msg_data.get("text").and_then(|v| v.as_str()).unwrap_or("");

        let delivered_instances = deliver_events_by_msg
            .get(msg_id)
            .cloned()
            .unwrap_or_default();

        let mut read_by = Vec::new();
        for inst_name in &delivered_to {
            let inst_data = active_instances.get(inst_name);

            // Remote instance: compare msg_ts (timestamp-based)
            if let Some(data) = inst_data
                && data
                    .get("origin_device_id")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
            {
                if let Some(ts) = remote_msg_ts.get(inst_name)
                    && ts >= msg_timestamp
                {
                    read_by.push(inst_name.clone());
                }
                continue;
            }

            // Local instance: check for deliver event after message
            if delivered_instances.contains(inst_name) {
                // External senders (no session_id, no parent, not remote) only count
                // as "read" if they were an explicitly resolved recipient.
                // This prevents false-positive read receipts for external watchers.
                if let Some(data) = inst_data
                    && is_external_sender_data(data)
                    && !explicit_mentions.contains(inst_name.as_str())
                {
                    continue;
                }
                read_by.push(inst_name.clone());
            }
        }

        let total_recipients = delivered_to.len();
        if total_recipients > 0 {
            let age_str = parse_timestamp_fn(msg_timestamp)
                .map(|msg_time| format_age_fn(now_secs - msg_time))
                .unwrap_or_else(|| "?".to_string());

            let truncated_text = if msg_text.len() > max_text_length {
                format!(
                    "{}...",
                    crate::delivery::truncate_chars(msg_text, max_text_length.saturating_sub(3))
                )
            } else {
                msg_text.to_string()
            };

            receipts.push(ReadReceipt {
                id: *msg_id,
                age: age_str,
                text: truncated_text,
                read_by,
                total_recipients,
            });
        }
    }

    receipts
}

/// Max length for message preview in PTY trigger.
pub const PREVIEW_MAX_LEN: usize = 60;

/// Build truncated message preview for PTY injection.
///
/// Reuses format_hook_messages but truncates before user message content.
/// User content may contain @ chars that trigger autocomplete in some CLIs.
pub fn build_message_preview(formatted: &str, max_len: usize) -> String {
    let wrapper_open = "<hcom>";
    let wrapper_close = "</hcom>";
    let wrapper_len = wrapper_open.len() + wrapper_close.len();

    if formatted.is_empty() {
        return format!("{}{}", wrapper_open, wrapper_close);
    }

    let content_max = max_len.saturating_sub(wrapper_len);
    if content_max == 0 {
        return format!("{}{}", wrapper_open, wrapper_close);
    }

    // Truncate before user content (after first ": ") to avoid special chars
    if let Some(colon_pos) = formatted.find(": ") {
        let envelope = &formatted[..colon_pos];
        if envelope.len() > content_max {
            if content_max <= 3 {
                return format!("{}{}", wrapper_open, wrapper_close);
            }
            return format!(
                "{}{}...{}",
                wrapper_open,
                crate::delivery::truncate_chars(envelope, content_max - 3),
                wrapper_close
            );
        }
        return format!("{}{}{}", wrapper_open, envelope, wrapper_close);
    }

    // No colon found, just truncate normally
    if formatted.len() > content_max {
        if content_max <= 3 {
            return format!("{}{}", wrapper_open, wrapper_close);
        }
        return format!(
            "{}{}...{}",
            wrapper_open,
            crate::delivery::truncate_chars(formatted, content_max - 3),
            wrapper_close
        );
    }
    format!("{}{}{}", wrapper_open, formatted, wrapper_close)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_names::SuffixOnly;

    // ---- validate_message ----

    #[test]
    fn test_validate_message_empty() {
        assert_eq!(validate_message(""), Err("Message required".to_string()));
        assert_eq!(validate_message("   "), Err("Message required".to_string()));
    }

    #[test]
    fn test_validate_message_valid() {
        assert!(validate_message("hello world").is_ok());
        assert!(validate_message("line1\nline2\ttab").is_ok());
    }

    #[test]
    fn test_validate_message_control_chars() {
        assert!(validate_message("hello\x00world").is_err());
        assert!(validate_message("hello\x07world").is_err());
    }

    #[test]
    fn test_validate_message_too_large() {
        let big = "x".repeat(MAX_MESSAGE_SIZE + 1);
        assert!(validate_message(&big).is_err());
    }

    // ---- format_recipients ----

    #[test]
    fn test_format_recipients_empty() {
        assert_eq!(format_recipients(&[], 30), "(none)");
    }

    #[test]
    fn test_format_recipients_normal() {
        let names = vec!["luna".to_string(), "nova".to_string()];
        assert_eq!(format_recipients(&names, 30), "luna, nova");
    }

    #[test]
    fn test_format_recipients_truncated() {
        let names: Vec<String> = (0..5).map(|i| format!("agent{}", i)).collect();
        let result = format_recipients(&names, 3);
        assert!(result.contains("+2 more"));
    }

    // ---- validate_scope / validate_intent ----

    #[test]
    fn test_validate_scope() {
        assert!(validate_scope("broadcast").is_ok());
        assert!(validate_scope("mentions").is_ok());
        assert!(validate_scope("invalid").is_err());
    }

    #[test]
    fn test_validate_intent() {
        assert!(validate_intent("request").is_ok());
        assert!(validate_intent("inform").is_ok());
        assert!(validate_intent("ack").is_ok());
        assert!(validate_intent("invalid").is_err());
    }

    // ---- match_target ----

    fn make_instances(names: &[(&str, Option<&str>)]) -> Vec<InstanceInfo> {
        names.iter().map(|(name, tag)| info(name, *tag)).collect()
    }

    /// Empty fleet context: no suffix-only devices, fixed test own-uuid.
    /// Bare-name behavior tests build on this; suffix-only cases use
    /// `fleet_with` below.
    fn fleet() -> FleetCtx {
        fleet_with(SuffixOnly::default(), "test-uuid-0000")
    }

    fn fleet_with(so: SuffixOnly, own_uuid: &str) -> FleetCtx {
        FleetCtx {
            so,
            own_uuid: own_uuid.to_string(),
        }
    }

    /// A mirror row of `device_uuid` whose `:SHORT` suffix is NOT that
    /// device's canonical short id (a probed slot, or relay's 4-char import
    /// fallback), so only the ORIGIN leg of the suffix-only flag can
    /// classify it.
    fn probed_mirror(base: &str, device_uuid: &str) -> InstanceInfo {
        InstanceInfo {
            name: format!("{base}:ZZZZ"),
            tag: None,
            origin: Some(device_uuid.to_string()),
            tool: None,
        }
    }

    #[test]
    fn test_match_target_exact() {
        let instances = make_instances(&[("luna", None), ("nova", None)]);
        assert_eq!(
            match_target("luna", &instances, &fleet()).unwrap(),
            vec!["luna"]
        );
    }

    #[test]
    fn test_match_target_tagged() {
        let instances = make_instances(&[("luna", Some("api")), ("nova", None)]);
        assert_eq!(
            match_target("api-luna", &instances, &fleet()).unwrap(),
            vec!["luna"]
        );
    }

    #[test]
    fn test_compute_scope_tagged_local_and_remote_same_display_refuse_both() {
        let mut remote = info("grp-x:DEVB", None);
        remote.origin = Some("device-b".into());
        let instances = vec![info("x", Some("grp")), remote];
        let err = compute_scope("hey @grp-x", &instances, None, &fleet()).unwrap_err();
        assert!(err.contains("@x (local display @grp-x)"), "{err}");
        assert!(err.contains("@grp-x:DEVB"), "{err}");
        let exact = compute_scope("hey @grp-x:DEVB", &instances, None, &fleet()).unwrap();
        assert_eq!(exact.mentions, vec!["grp-x:DEVB"]);
        let local = compute_scope("hey @x", &instances, None, &fleet()).unwrap();
        assert_eq!(local.mentions, vec!["x"]);
    }

    #[test]
    fn test_match_target_tag_prefix() {
        let instances =
            make_instances(&[("luna", Some("api")), ("nova", Some("api")), ("kira", None)]);
        let result = match_target("api-", &instances, &fleet()).unwrap();
        assert!(result.contains(&"luna".to_string()));
        assert!(result.contains(&"nova".to_string()));
        assert!(!result.contains(&"kira".to_string()));
    }

    #[test]
    fn test_match_target_exact_base_name_with_tag() {
        let instances = make_instances(&[("luna", Some("api"))]);
        assert_eq!(
            match_target("luna", &instances, &fleet()).unwrap(),
            vec!["luna"]
        );
    }

    #[test]
    fn test_match_target_exact_name_excludes_prefixes() {
        let instances = make_instances(&[
            ("giru", None),
            ("lasa", Some("giru-test")),
            ("giru2", None),
            ("giru_sub", None),
        ]);
        let result = match_target("giru", &instances, &fleet()).unwrap();
        assert_eq!(result, vec!["giru"]);
    }

    #[test]
    fn test_match_target_rejects_partial_local_name() {
        let instances = make_instances(&[("luna", None), ("lunatic", None)]);
        assert!(
            match_target("lun", &instances, &fleet())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_match_target_group_requires_exact_tag() {
        let instances = make_instances(&[("luna", Some("api")), ("nova", Some("api-extra"))]);
        let result = match_target("api-", &instances, &fleet()).unwrap();
        assert_eq!(result, vec!["luna"]);
    }

    #[test]
    fn test_match_target_bigboss_remote() {
        let instances = make_instances(&[("luna", None), ("bigboss", None)]);
        assert_eq!(
            match_target("bigboss:BOXE", &instances, &fleet()).unwrap(),
            vec!["bigboss"]
        );
    }

    #[test]
    fn test_match_target_remote_prefix() {
        let instances = make_instances(&[("luna:BOXE", None)]);
        assert_eq!(
            match_target("luna:BO", &instances, &fleet()).unwrap(),
            vec!["luna:BOXE"]
        );
    }

    #[test]
    fn test_match_target_ambiguous_remote_prefix_fails() {
        let instances = make_instances(&[("luna:BOXE", None), ("luna:BOLT", None)]);
        let err = match_target("luna:BO", &instances, &fleet()).unwrap_err();
        assert!(err.contains("Ambiguous remote @mention @luna:BO"));
    }

    #[test]
    fn test_match_target_no_match() {
        let instances = make_instances(&[("luna", None)]);
        assert!(
            match_target("nonexistent", &instances, &fleet())
                .unwrap()
                .is_empty()
        );
    }

    // ---- compute_scope ----

    fn info(name: &str, tag: Option<&str>) -> InstanceInfo {
        info_with_tool(name, tag, None)
    }

    /// A row as `deliverable_instances` reads it, including the `tool` string a
    /// hosted participant is recognized by.
    fn info_with_tool(name: &str, tag: Option<&str>, tool: Option<&str>) -> InstanceInfo {
        InstanceInfo {
            name: name.to_string(),
            tag: tag.map(|t| t.to_string()),
            origin: None,
            tool: tool.map(|t| t.to_string()),
        }
    }

    /// A relay mirror of `base:SHORT` on `origin_device_id`, carrying the
    /// origin's `tool` string verbatim the way relay state does.
    fn mirror_with_tool(
        base: &str,
        suffix: &str,
        origin: &str,
        tool: Option<&str>,
    ) -> InstanceInfo {
        InstanceInfo {
            name: format!("{base}:{suffix}"),
            tag: None,
            origin: Some(origin.to_string()),
            tool: tool.map(|t| t.to_string()),
        }
    }

    // ---- person-in-channel (`person:channel` on hosted Buzz rows) ----

    const MBAI: &str = "device-mbai-uuid";

    /// Local hosted rows: buzz person `michael` plus channel `ch_infra`.
    fn local_buzz_rows() -> Vec<InstanceInfo> {
        vec![
            info_with_tool("michael", None, Some(BUZZ_TOOL)),
            info_with_tool("ch_infra", None, Some(BUZZ_TOOL)),
        ]
    }

    /// The same hosted rows as seen from another device: relay mirrors of both,
    /// each carrying the origin's `tool` verbatim.
    fn mirrored_buzz_rows() -> Vec<InstanceInfo> {
        vec![
            mirror_with_tool("michael", "MBAI", MBAI, Some(BUZZ_TOOL)),
            mirror_with_tool("ch_infra", "MBAI", MBAI, Some(BUZZ_TOOL)),
        ]
    }

    #[test]
    fn buzz_person_in_channel_resolves_to_person_and_channel() {
        let instances = local_buzz_rows();
        assert_eq!(
            match_target("michael:infra", &instances, &fleet()).unwrap(),
            vec!["michael".to_string(), "ch_infra".to_string()]
        );
    }

    #[test]
    fn buzz_person_in_channel_resolves_to_both_mirrors_off_device() {
        // Nothing device-specific about the input: on another device the same
        // `michael:infra` resolves through ordinary bare-name resolution to the
        // mirror pair, which is what goes on the wire.
        let instances = mirrored_buzz_rows();
        assert_eq!(
            match_target("michael:infra", &instances, &fleet()).unwrap(),
            vec!["michael:MBAI".to_string(), "ch_infra:MBAI".to_string()]
        );
    }

    #[test]
    fn both_sides_land_as_ordinary_targets_in_mentions() {
        // The expansion is not a new routing kind: both rows land in
        // `mentions` (and so in `exact_targets`) as plain targets.
        let instances = local_buzz_rows();
        let targets = vec!["michael:infra".to_string()];
        let scope = compute_scope("status?", &instances, Some(&targets), &fleet()).unwrap();
        assert_eq!(scope.scope, MessageScope::Mentions);
        assert_eq!(
            scope.mentions,
            vec!["michael".to_string(), "ch_infra".to_string()]
        );
    }

    #[test]
    fn buzz_person_in_channel_without_that_channel_errors_naming_it() {
        let instances = vec![info_with_tool("michael", None, Some(BUZZ_TOOL))];
        let targets = vec!["michael:nochan".to_string()];
        let err = compute_scope("status?", &instances, Some(&targets), &fleet()).unwrap_err();
        assert!(err.contains("ch_nochan"), "{err}");
        assert!(err.contains("michael"), "{err}");
    }

    #[test]
    fn device_id_wins_over_a_matching_channel_slug() {
        // `michael:BOXE` is a device address, not "#boxe": the expansion must
        // not fire and the ordinary device rules must still apply.
        let mut instances = local_buzz_rows();
        instances.push(mirror_with_tool("michael", "BOXE", "device-boxe", None));
        instances.push(info_with_tool("ch_boxe", None, Some(BUZZ_TOOL)));
        assert_eq!(
            match_target("michael:BOXE", &instances, &fleet()).unwrap(),
            vec!["michael:BOXE".to_string()]
        );
    }

    #[test]
    fn non_buzz_base_keeps_todays_behaviour() {
        // `luna:infra` stays an unmatched colon target for a plain agent —
        // exactly what it did before the buzz expansion existed.
        let instances = vec![
            info("luna", None),
            info_with_tool("ch_infra", None, Some(BUZZ_TOOL)),
        ];
        assert!(
            match_target("luna:infra", &instances, &fleet())
                .unwrap()
                .is_empty()
        );
        let targets = vec!["luna:infra".to_string()];
        let err = compute_scope("status?", &instances, Some(&targets), &fleet()).unwrap_err();
        assert!(err.contains("non-existent or stopped"), "{err}");
    }

    #[test]
    fn a_lowercase_suffix_naming_a_live_device_short_id_is_a_device() {
        // The 4-uppercase rule alone would let `michael:boxe` through as a
        // channel slug; the short id a live mirror row carries is a device too.
        let instances = vec![
            mirror_with_tool("michael", "BOXE", "device-boxe", None),
            mirror_with_tool("ch_boxe", "MBAI", MBAI, Some(BUZZ_TOOL)),
        ];
        assert_eq!(
            match_target("michael:boxe", &instances, &fleet()).unwrap(),
            vec!["michael:BOXE".to_string()]
        );
    }

    #[test]
    fn a_channel_row_base_never_expands_into_a_person_in_channel() {
        // `ch_infra:whatever` has a channel base: it keeps today's behaviour
        // (unmatched), so a channel address can't reach into another channel.
        let instances = local_buzz_rows();
        assert!(
            match_target("ch_infra:infra", &instances, &fleet())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_channel_on_another_device_is_not_this_persons_channel() {
        // The channel has to be on the person's own device. Here the person is
        // local and the only `ch_infra` mirror lives on another device.
        let instances = vec![
            info_with_tool("michael", None, Some(BUZZ_TOOL)),
            mirror_with_tool("ch_infra", "MBAI", MBAI, Some(BUZZ_TOOL)),
        ];
        let targets = vec!["michael:infra".to_string()];
        let err = compute_scope("status?", &instances, Some(&targets), &fleet()).unwrap_err();
        assert!(err.contains("ch_infra:MBAI"), "{err}");
    }

    #[test]
    fn a_non_buzz_ch_row_is_not_a_channel_for_a_buzz_person() {
        // The tool string is what makes a row hosted; a plain agent called
        // `ch_infra` does not complete the address.
        let instances = vec![
            info_with_tool("michael", None, Some(BUZZ_TOOL)),
            info_with_tool("ch_infra", None, Some("claude")),
        ];
        let targets = vec!["michael:infra".to_string()];
        let err = compute_scope("status?", &instances, Some(&targets), &fleet()).unwrap_err();
        assert!(err.contains("not a live buzz channel"), "{err}");
    }

    #[test]
    fn device_suffix_shape_matches_split_device_suffix() {
        // `suffix_is_device_id` restates the 4-uppercase-alnum rule instead of
        // calling through a synthetic name; this pins the two together.
        for suffix in ["MBAI", "BOX1", "AB", "ABCDE", "mbai", "mb_1"] {
            let via_helper = is_device_suffix_shape(suffix);
            let via_relay =
                crate::relay::control::split_device_suffix(&format!("x:{suffix}")).is_some();
            assert_eq!(via_helper, via_relay, "suffix {suffix}");
        }
    }

    #[test]
    fn buzz_person_and_channel_addresses_themselves_unchanged() {
        // The two plain addresses keep resolving to exactly one row each.
        let instances = local_buzz_rows();
        assert_eq!(
            match_target("michael", &instances, &fleet()).unwrap(),
            vec!["michael".to_string()]
        );
        assert_eq!(
            match_target("ch_infra", &instances, &fleet()).unwrap(),
            vec!["ch_infra".to_string()]
        );
    }

    #[test]
    fn a_unique_device_prefix_on_a_buzz_person_still_resolves_to_the_device() {
        // Colon targets have always prefix-matched device suffixes,
        // case-insensitively. The channel expansion must not take that away:
        // `michael:mb` is still Michael on MBAI, never "#mb".
        let instances = mirrored_buzz_rows();
        for target in ["michael:MB", "michael:mba", "michael:m"] {
            assert_eq!(
                match_target(target, &instances, &fleet()).unwrap(),
                vec!["michael:MBAI".to_string()],
                "{target}"
            );
        }
    }

    #[test]
    fn a_suffix_only_buzz_person_names_the_exact_channel_form() {
        // The buzz host is suffix-only, so bare `michael` refuses. The channel
        // form must say why and what to type, not "non-existent agent"...
        let fleet = fleet_with(SuffixOnly::parse("MBAI"), "test-uuid-0000");
        let instances = mirrored_buzz_rows();
        let err = match_target("michael:infra", &instances, &fleet).unwrap_err();
        assert!(err.contains("suffix-only"), "{err}");
        assert!(err.contains("@michael:MBAI:infra"), "{err}");
        // ...and the exact form it names resolves to the mirror pair.
        assert_eq!(
            match_target("michael:MBAI:infra", &instances, &fleet).unwrap(),
            vec!["michael:MBAI".to_string(), "ch_infra:MBAI".to_string()]
        );
    }

    #[test]
    fn an_ambiguous_buzz_person_offers_only_the_buzz_exact_form() {
        // A plain agent `michael` on another device makes bare `michael`
        // ambiguous. Only the buzz person can be in a channel, so only its
        // exact form is offered.
        let mut instances = mirrored_buzz_rows();
        instances.push(mirror_with_tool("michael", "BOXE", "device-boxe", None));
        let err = match_target("michael:infra", &instances, &fleet()).unwrap_err();
        assert!(
            err.contains("multiple live agents named 'michael'"),
            "{err}"
        );
        assert!(err.contains("@michael:MBAI:infra"), "{err}");
        assert!(!err.contains("@michael:BOXE:infra"), "{err}");
        assert_eq!(
            match_target("michael:MBAI:infra", &instances, &fleet()).unwrap(),
            vec!["michael:MBAI".to_string(), "ch_infra:MBAI".to_string()]
        );
    }

    #[test]
    fn an_ambiguous_non_buzz_base_keeps_the_unmatched_result() {
        // No buzz person behind the refusal: today's behaviour, unmatched,
        // for both the bare and the exact person form.
        let instances = vec![
            mirror_with_tool("luna", "BOXE", "device-boxe", None),
            mirror_with_tool("luna", "MOXE", "device-moxe", None),
            info_with_tool("ch_infra", None, Some(BUZZ_TOOL)),
        ];
        for target in ["luna:infra", "luna:BOXE:infra"] {
            assert!(
                match_target(target, &instances, &fleet())
                    .unwrap()
                    .is_empty(),
                "{target}"
            );
        }
    }

    #[test]
    fn test_compute_scope_broadcast() {
        let instances = vec![info("luna", None), info("nova", None)];
        let result = compute_scope("hello everyone", &instances, None, &fleet()).unwrap();
        assert_eq!(result.scope, MessageScope::Broadcast);
        assert!(result.mentions.is_empty());
    }

    #[test]
    fn test_compute_scope_mention_in_text() {
        let instances = vec![info("luna", None), info("nova", None)];
        let result = compute_scope("hey @luna fix this", &instances, None, &fleet()).unwrap();
        assert_eq!(result.scope, MessageScope::Mentions);
        assert_eq!(result.mentions, vec!["luna"]);
    }

    #[test]
    fn test_compute_scope_exact_name_beats_tag_prefix_collision() {
        let instances = vec![info("giru", None), info("lasa", Some("giru-test"))];
        let result = compute_scope("hey @giru", &instances, None, &fleet()).unwrap();
        assert_eq!(result.mentions, vec!["giru"]);
    }

    #[test]
    fn test_compute_scope_explicit_targets() {
        let instances = vec![info("luna", None), info("nova", None)];
        let targets = vec!["luna".to_string()];
        let result = compute_scope("fix this", &instances, Some(&targets), &fleet()).unwrap();
        assert_eq!(result.scope, MessageScope::Mentions);
        assert_eq!(result.mentions, vec!["luna"]);
    }

    #[test]
    fn test_compute_scope_explicit_empty_broadcast() {
        let instances = vec![info("luna", None)];
        let targets: Vec<String> = vec![];
        let result = compute_scope("hello", &instances, Some(&targets), &fleet()).unwrap();
        assert_eq!(result.scope, MessageScope::Broadcast);
    }

    #[test]
    fn test_compute_scope_unknown_target_fails() {
        let instances = vec![info("luna", None)];
        let targets = vec!["nonexistent".to_string()];
        let result = compute_scope("hello", &instances, Some(&targets), &fleet());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-existent or stopped"));
    }

    #[test]
    fn test_compute_scope_bare_resolves_single_live_candidate() {
        // Contract change ordered by the ffc-ravoc design: a bare `@zeli` with
        // exactly one live candidate (`zeli:ZOME`, no local `zeli`, no
        // suffix-only collision) resolves to that exact suffixed form instead
        // of erroring. This replaces the old local-only "Did you mean" test.
        let instances = vec![info("zeli:ZOME", None), info("luna", None)];
        let targets = vec!["zeli".to_string()];
        let result = compute_scope("hello", &instances, Some(&targets), &fleet()).unwrap();
        assert_eq!(result.scope, MessageScope::Mentions);
        assert_eq!(result.mentions, vec!["zeli:ZOME"]);
    }

    #[test]
    fn test_compute_scope_bare_resolves_remote_mirror() {
        // Bare `@x` with no local `x` and one live mirror `x:DEVB` resolves
        // to the mirror's exact form.
        let instances = vec![info("x:DEVB", None), info("luna", None)];
        let targets = vec!["x".to_string()];
        let result = compute_scope("hello", &instances, Some(&targets), &fleet()).unwrap();
        assert_eq!(result.mentions, vec!["x:DEVB"]);
    }

    #[test]
    fn test_compute_scope_bare_ambiguous_refuse_lists_both() {
        // Bare `@x` with a live local `x` AND a live mirror `x:DEVB` is
        // refused, naming every exact form (local as the bare name).
        let instances = vec![info("x", None), info("x:DEVB", None)];
        let targets = vec!["x".to_string()];
        let err = compute_scope("hello", &instances, Some(&targets), &fleet()).unwrap_err();
        assert!(err.contains("@x"), "got: {err}");
        assert!(err.contains("@x:DEVB"), "got: {err}");
    }

    #[test]
    fn test_compute_scope_bare_suffix_only_only_points_to_exact() {
        // Bare `@x` live only on a suffix-only device is refused, pointing at
        // the exact `x:GIDU` form.
        let so = SuffixOnly::parse("GIDU");
        let fleet = fleet_with(so, "test-uuid-0000");
        let instances = vec![info("x:GIDU", None), info("luna", None)];
        let targets = vec!["x".to_string()];
        let err = compute_scope("hello", &instances, Some(&targets), &fleet).unwrap_err();
        assert!(err.contains("@x:GIDU"), "got: {err}");
    }

    #[test]
    fn test_compute_scope_bare_suffix_only_plus_other_lists_both() {
        // Bare `@x` live on a suffix-only device plus one other device is
        // refused, listing both exact forms (never silently picked).
        let so = SuffixOnly::parse("GIDU");
        let fleet = fleet_with(so, "test-uuid-0000");
        let instances = vec![info("x", None), info("x:GIDU", None)];
        let targets = vec!["x".to_string()];
        let err = compute_scope("hello", &instances, Some(&targets), &fleet).unwrap_err();
        assert!(err.contains("@x:GIDU"), "got: {err}");
        // The local candidate is listed as the bare name.
        assert!(err.contains("@x"), "got: {err}");
    }

    /// The send path must apply the resolver's own suffix-only policy, which
    /// reads the mirror's ORIGIN device: a listed device whose row carries a
    /// probed `:SHORT` slot (not its canonical short id) is still never a
    /// bare-name target here, exactly as on every command path.
    #[test]
    fn test_compute_scope_bare_suffix_only_recognized_through_the_origin_device() {
        const LISTED: &str = "f3a70268-8ffa-4f0c-9e37-62f78acfcc1e";
        let so = SuffixOnly::parse(LISTED);
        assert!(
            !so.short_is_listed("ZZZZ"),
            "the suffix leg must not be the one that matches"
        );
        let fleet = fleet_with(so, "test-uuid-0000");
        let instances = vec![probed_mirror("x", LISTED), info("luna", None)];
        let targets = vec!["x".to_string()];
        let err = compute_scope("hello", &instances, Some(&targets), &fleet).unwrap_err();
        assert!(err.contains("@x:ZZZZ"), "got: {err}");
    }

    #[test]
    fn test_compute_scope_no_suggestion_when_no_remote_match() {
        let instances = vec![info("luna", None), info("nova", None)];
        let targets = vec!["zeli".to_string()];
        let err = compute_scope("hello", &instances, Some(&targets), &fleet()).unwrap_err();
        assert!(!err.contains("Did you mean"), "got: {err}");
    }

    #[test]
    fn test_compute_scope_unknown_mention_fails() {
        let instances = vec![info("luna", None)];
        let result = compute_scope("hey @nonexistent fix this", &instances, None, &fleet());
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_scope_system_mention_fails() {
        let instances = vec![info("luna", None)];
        let result = compute_scope("hey @[hcom-events]", &instances, None, &fleet());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("System notifications"));
    }

    #[test]
    fn test_compute_scope_literal_mention_fails() {
        let instances = vec![info("luna", None)];
        let result = compute_scope("use @mention to target", &instances, None, &fleet());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("literal text @mention is not a valid target")
        );
    }

    #[test]
    fn test_compute_scope_tagged_instances() {
        let instances = vec![info("luna", Some("api")), info("nova", Some("api"))];
        let targets = vec!["api-".to_string()];
        let result = compute_scope("hello", &instances, Some(&targets), &fleet()).unwrap();
        assert_eq!(result.scope, MessageScope::Mentions);
        assert!(result.mentions.contains(&"luna".to_string()));
        assert!(result.mentions.contains(&"nova".to_string()));
    }

    #[test]
    fn test_compute_scope_deduplicates() {
        let instances = vec![info("luna", Some("api"))];
        // Both api-luna and luna resolve to the same instance
        let targets = vec!["api-luna".to_string(), "luna".to_string()];
        let result = compute_scope("hello", &instances, Some(&targets), &fleet()).unwrap();
        assert_eq!(result.mentions.len(), 1);
        assert_eq!(result.mentions[0], "luna");
    }

    // ---- should_deliver_message ----

    #[test]
    fn test_should_deliver_broadcast() {
        let data = serde_json::json!({"scope": "broadcast", "from": "sender"});
        assert!(should_deliver_message(&data, "receiver", "sender").unwrap());
    }

    #[test]
    fn test_should_deliver_skip_self() {
        let data = serde_json::json!({"scope": "broadcast", "from": "luna"});
        assert!(!should_deliver_message(&data, "luna", "luna").unwrap());
    }

    #[test]
    fn test_should_deliver_mentions_match() {
        let data = serde_json::json!({"scope": "mentions", "mentions": ["luna"]});
        assert!(should_deliver_message(&data, "luna", "nova").unwrap());
    }

    #[test]
    fn test_should_deliver_mentions_no_match() {
        let data = serde_json::json!({"scope": "mentions", "mentions": ["luna"]});
        assert!(!should_deliver_message(&data, "nova", "kira").unwrap());
    }

    #[test]
    fn test_should_deliver_cross_device() {
        let data = serde_json::json!({"scope": "mentions", "mentions": ["luna:BOXE"]});
        // luna matches luna:BOXE after stripping device suffix
        assert!(should_deliver_message(&data, "luna", "nova").unwrap());
    }

    #[test]
    fn test_should_deliver_missing_scope() {
        let data = serde_json::json!({"from": "sender"});
        assert!(should_deliver_message(&data, "receiver", "sender").is_err());
    }

    #[test]
    fn test_should_deliver_exact_targets_pure_match() {
        // Non-empty exact_targets: pure exact-string match. A same-named
        // local `x` must NOT take a message resolved to `x:DEVB`.
        let data = serde_json::json!({
            "scope": "mentions",
            "mentions": ["x:DEVB"],
            "exact_targets": ["x:DEVB"],
        });
        assert!(should_deliver_message(&data, "x:DEVB", "boss").unwrap());
        assert!(!should_deliver_message(&data, "x", "boss").unwrap());
        assert!(!should_deliver_message(&data, "x:OTHE", "boss").unwrap());
    }

    #[test]
    fn test_should_deliver_exact_targets_self_skip_first() {
        // from == receiver still skips even under exact matching.
        let data = serde_json::json!({
            "scope": "mentions",
            "from": "x:DEVB",
            "mentions": ["x:DEVB"],
            "exact_targets": ["x:DEVB"],
        });
        assert!(!should_deliver_message(&data, "x:DEVB", "x:DEVB").unwrap());
    }

    #[test]
    fn test_should_deliver_missing_exact_targets_legacy_base_match() {
        // Absence of the key = old-format event → legacy base-name behavior:
        // `x` takes a message mentioning `x:DEVB`.
        let data = serde_json::json!({"scope": "mentions", "mentions": ["x:DEVB"]});
        assert!(should_deliver_message(&data, "x", "boss").unwrap());
    }

    #[test]
    fn test_should_deliver_empty_exact_targets_legacy_base_match() {
        // An empty array is treated like a missing key (legacy base-name).
        let data = serde_json::json!({
            "scope": "mentions",
            "mentions": ["x:DEVB"],
            "exact_targets": [],
        });
        assert!(should_deliver_message(&data, "x", "boss").unwrap());
    }

    // ---- build_message_prefix ----

    #[test]
    fn test_build_prefix_intent_thread() {
        let msg = serde_json::json!({"intent": "request", "thread": "pr-42", "event_id": 42});
        assert_eq!(build_message_prefix(&msg), "[request:pr-42 #42]");
    }

    #[test]
    fn test_build_prefix_intent_only() {
        let msg = serde_json::json!({"intent": "ack", "event_id": 10});
        assert_eq!(build_message_prefix(&msg), "[ack #10]");
    }

    #[test]
    fn test_build_prefix_thread_only() {
        let msg = serde_json::json!({"thread": "testing", "event_id": 5});
        assert_eq!(build_message_prefix(&msg), "[thread:testing #5]");
    }

    #[test]
    fn test_build_prefix_no_envelope() {
        let msg = serde_json::json!({"event_id": 1});
        assert_eq!(build_message_prefix(&msg), "[new message #1]");
    }

    #[test]
    fn test_build_prefix_remote() {
        let msg = serde_json::json!({"intent": "inform", "_relay": {"short": "BOXE", "id": 42}});
        assert_eq!(build_message_prefix(&msg), "[inform #42:BOXE]");
    }

    // ---- unescape_bash ----

    #[test]
    fn test_unescape_bash() {
        assert_eq!(unescape_bash("hello\\!world"), "hello!world");
        assert_eq!(unescape_bash("\\$HOME"), "$HOME");
        assert_eq!(unescape_bash("\\`cmd\\`"), "`cmd`");
        assert_eq!(unescape_bash("say \\\"hello\\\""), "say \"hello\"");
        assert_eq!(unescape_bash("it\\'s"), "it's");
    }

    #[test]
    fn test_unescape_bash_preserves_backslash() {
        // Double backslashes are NOT unescaped
        assert_eq!(unescape_bash("path\\\\to\\\\file"), "path\\\\to\\\\file");
    }

    // ---- build_message_preview ----

    #[test]
    fn test_build_message_preview_empty() {
        assert_eq!(build_message_preview("", 60), "<hcom></hcom>");
    }

    #[test]
    fn test_build_message_preview_truncates_at_colon() {
        let formatted = "[request #42] luna → nova: here is a long message";
        let result = build_message_preview(formatted, 60);
        // Should include up to the colon but not the message content
        assert!(result.starts_with("<hcom>"));
        assert!(result.ends_with("</hcom>"));
        assert!(result.contains("[request #42] luna → nova"));
        assert!(!result.contains("here is a long message"));
    }

    #[test]
    fn test_build_message_preview_no_colon() {
        let formatted = "short text";
        let result = build_message_preview(formatted, 60);
        assert_eq!(result, "<hcom>short text</hcom>");
    }

    // ---- MessageScope / MessageIntent ----

    #[test]
    fn test_message_scope_roundtrip() {
        assert_eq!(
            MessageScope::Broadcast
                .as_str()
                .parse::<MessageScope>()
                .ok(),
            Some(MessageScope::Broadcast)
        );
        assert_eq!(
            MessageScope::Mentions.as_str().parse::<MessageScope>().ok(),
            Some(MessageScope::Mentions)
        );
        assert!("invalid".parse::<MessageScope>().is_err());
    }

    #[test]
    fn test_message_intent_roundtrip() {
        assert_eq!(
            MessageIntent::Request
                .as_str()
                .parse::<MessageIntent>()
                .ok(),
            Some(MessageIntent::Request)
        );
        assert_eq!(
            MessageIntent::Inform.as_str().parse::<MessageIntent>().ok(),
            Some(MessageIntent::Inform)
        );
        assert_eq!(
            MessageIntent::Ack.as_str().parse::<MessageIntent>().ok(),
            Some(MessageIntent::Ack)
        );
        assert!("invalid".parse::<MessageIntent>().is_err());
    }

    // ---- format_hook_messages / format_messages_json ----

    #[test]
    fn test_format_hook_messages_single() {
        let msgs = vec![serde_json::json!({
            "from": "luna",
            "message": "hello there",
            "event_id": 42,
            "delivered_to": ["nova"],
        })];

        let result = format_hook_messages(&msgs, "nova", &|_name| None, &|| String::new(), None);
        assert!(result.contains("luna"));
        assert!(result.contains("nova"));
        assert!(result.contains("hello there"));
        assert!(result.contains("#42"));
    }

    #[test]
    fn test_format_hook_messages_multiple() {
        let msgs = vec![
            serde_json::json!({
                "from": "luna",
                "message": "first",
                "event_id": 1,
                "delivered_to": ["nova"],
            }),
            serde_json::json!({
                "from": "kira",
                "message": "second",
                "event_id": 2,
                "delivered_to": ["nova"],
            }),
        ];

        let result = format_hook_messages(&msgs, "nova", &|_name| None, &|| String::new(), None);
        assert!(result.contains("[2 new messages]"));
        assert!(result.contains("first"));
        assert!(result.contains("second"));
    }

    #[test]
    fn test_format_hook_messages_with_hints() {
        let msgs = vec![serde_json::json!({
            "from": "luna",
            "message": "hi",
            "event_id": 1,
            "delivered_to": ["nova"],
        })];

        let result = format_hook_messages(
            &msgs,
            "nova",
            &|_name| None,
            &|| "respond with hcom send".to_string(),
            None,
        );
        assert!(result.contains("[respond with hcom send]"));
    }

    #[test]
    fn test_format_messages_json_wraps_in_tags() {
        let msgs = vec![serde_json::json!({
            "from": "luna",
            "message": "hi",
            "event_id": 1,
            "delivered_to": ["nova"],
        })];

        let result = format_messages_json(&msgs, "nova", &|_name| None, &|| String::new(), None);
        assert!(result.starts_with("<hcom>"));
        assert!(result.ends_with("</hcom>"));
    }

    #[test]
    fn test_format_hook_messages_appends_recv_tip_once() {
        use std::cell::Cell;
        use std::rc::Rc;

        let msgs = vec![serde_json::json!({
            "from": "luna",
            "message": "hi",
            "event_id": 1,
            "intent": "request",
            "delivered_to": ["nova"],
        })];
        let marks = Rc::new(Cell::new(0));
        let tip_checker = |_: &str, _: &str| -> (bool, Box<dyn Fn()>) {
            let marks = Rc::clone(&marks);
            let mark = Box::new(move || marks.set(marks.get() + 1)) as Box<dyn Fn()>;
            (false, mark)
        };

        let result = format_hook_messages(
            &msgs,
            "nova",
            &|_name| None,
            &|| String::new(),
            Some(&tip_checker),
        );
        assert!(result.contains("[tip] intent=request: Sender expects a response."));
        assert_eq!(marks.get(), 1);
    }

    #[test]
    fn test_format_messages_json_marks_tip_without_duplicate_text() {
        use std::cell::Cell;
        use std::rc::Rc;

        let msgs = vec![serde_json::json!({
            "from": "luna",
            "message": "hi",
            "event_id": 1,
            "intent": "request",
            "delivered_to": ["nova"],
        })];
        let seen = Rc::new(Cell::new(false));
        let tip_checker = |_: &str, _: &str| -> (bool, Box<dyn Fn()>) {
            let seen = Rc::clone(&seen);
            let already_seen = seen.get();
            let mark = Box::new(move || seen.set(true)) as Box<dyn Fn()>;
            (already_seen, mark)
        };

        let first = format_messages_json(
            &msgs,
            "nova",
            &|_name| None,
            &|| String::new(),
            Some(&tip_checker),
        );
        let second = format_messages_json(
            &msgs,
            "nova",
            &|_name| None,
            &|| String::new(),
            Some(&tip_checker),
        );
        assert!(first.contains("[tip] intent=request: Sender expects a response."));
        assert!(!second.contains("[tip] intent=request: Sender expects a response."));
    }

    #[test]
    fn test_format_hook_messages_with_others() {
        let msgs = vec![serde_json::json!({
            "from": "luna",
            "message": "hi",
            "event_id": 1,
            "delivered_to": ["nova", "kira", "miso"],
        })];

        let result = format_hook_messages(&msgs, "nova", &|_name| None, &|| String::new(), None);
        // Should show "+2 others" for single message
        assert!(result.contains("+2 others"));
    }

    #[test]
    fn test_format_hook_messages_appends_thread_tip_once() {
        use std::cell::Cell;
        use std::rc::Rc;

        let msgs = vec![serde_json::json!({
            "from": "luna",
            "message": "hi",
            "thread": "debate-1",
            "event_id": 1,
            "delivered_to": ["nova"],
        })];
        let marks = Rc::new(Cell::new(0));
        let tip_checker = |_: &str, tip_key: &str| -> (bool, Box<dyn Fn()>) {
            assert_eq!(tip_key, "recv:thread:debate-1");
            let marks = Rc::clone(&marks);
            let mark = Box::new(move || marks.set(marks.get() + 1)) as Box<dyn Fn()>;
            (false, mark)
        };

        let result = format_hook_messages(
            &msgs,
            "nova",
            &|_name| None,
            &|| String::new(),
            Some(&tip_checker),
        );
        assert!(result.contains("[tip] You joined thread debate-1."));
        assert!(result.contains("hcom events unsub sub-"));
        assert_eq!(marks.get(), 1);
    }

    // ---- compute_read_receipts ----

    #[test]
    fn test_compute_read_receipts_basic() {
        let sent = vec![(
            42_i64,
            "2024-01-01T00:00:00Z".to_string(),
            serde_json::json!({
                "scope": "broadcast",
                "text": "hello world",
                "delivered_to": ["nova", "kira"],
            }),
        )];

        let active: HashMap<String, Value> = HashMap::from([
            (
                "nova".to_string(),
                serde_json::json!({"tag": null, "session_id": "sess-1"}),
            ),
            (
                "kira".to_string(),
                serde_json::json!({"tag": null, "session_id": "sess-2"}),
            ),
        ]);

        let mut deliver_events = HashMap::new();
        let mut delivered = HashSet::new();
        delivered.insert("nova".to_string());
        deliver_events.insert(42_i64, delivered);

        let receipts = compute_read_receipts(
            &sent,
            &active,
            &deliver_events,
            &HashMap::new(),
            50,
            &|secs| format!("{}s", secs as i64),
            100.0,
            &|_ts| Some(0.0),
        );

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].id, 42);
        assert_eq!(receipts[0].read_by, vec!["nova"]);
        assert_eq!(receipts[0].total_recipients, 2);
    }

    #[test]
    fn test_compute_read_receipts_remote() {
        let sent = vec![(
            42_i64,
            "2024-01-01T00:00:00Z".to_string(),
            serde_json::json!({
                "scope": "broadcast",
                "text": "hello",
                "delivered_to": ["luna:BOXE"],
            }),
        )];

        let active: HashMap<String, Value> = HashMap::from([(
            "luna:BOXE".to_string(),
            serde_json::json!({"origin_device_id": "device-1"}),
        )]);

        let remote_ts: HashMap<String, String> = HashMap::from([(
            "luna:BOXE".to_string(),
            "2024-01-02T00:00:00Z".to_string(), // After message
        )]);

        let receipts = compute_read_receipts(
            &sent,
            &active,
            &HashMap::new(),
            &remote_ts,
            50,
            &|_| "1h".to_string(),
            100.0,
            &|_| Some(0.0),
        );

        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].read_by, vec!["luna:BOXE"]);
    }

    #[test]
    fn test_compute_read_receipts_external_sender_gating() {
        // External sender (no session_id) should only count as read if @mentioned
        let sent = vec![(
            42_i64,
            "2024-01-01T00:00:00Z".to_string(),
            serde_json::json!({
                "scope": "broadcast",
                "text": "hello everyone",  // No @mention of watcher
                "delivered_to": ["nova", "watcher"],
            }),
        )];

        let active: HashMap<String, Value> = HashMap::from([
            (
                "nova".to_string(),
                serde_json::json!({"tag": null, "session_id": "sess-1"}),
            ),
            // External sender: no session_id → should be gated
            ("watcher".to_string(), serde_json::json!({"tag": null})),
        ]);

        let mut deliver_events = HashMap::new();
        let mut delivered = HashSet::new();
        delivered.insert("nova".to_string());
        delivered.insert("watcher".to_string());
        deliver_events.insert(42_i64, delivered);

        let receipts = compute_read_receipts(
            &sent,
            &active,
            &deliver_events,
            &HashMap::new(),
            50,
            &|secs| format!("{}s", secs as i64),
            100.0,
            &|_ts| Some(0.0),
        );

        assert_eq!(receipts.len(), 1);
        // nova has session_id → counted as read
        // watcher has no session_id (external) and not @mentioned → NOT counted
        assert_eq!(receipts[0].read_by, vec!["nova"]);
        assert_eq!(receipts[0].total_recipients, 2);
    }

    #[test]
    fn test_compute_read_receipts_external_sender_mentioned() {
        // External sender IS @mentioned → should count as read
        let sent = vec![(
            42_i64,
            "2024-01-01T00:00:00Z".to_string(),
            serde_json::json!({
                "scope": "mentions",
                "text": "hey @watcher check this",
                "mentions": ["watcher"],
                "delivered_to": ["watcher"],
            }),
        )];

        let active: HashMap<String, Value> = HashMap::from([
            ("watcher".to_string(), serde_json::json!({"tag": null})), // External
        ]);

        let mut deliver_events = HashMap::new();
        let mut delivered = HashSet::new();
        delivered.insert("watcher".to_string());
        deliver_events.insert(42_i64, delivered);

        let receipts = compute_read_receipts(
            &sent,
            &active,
            &deliver_events,
            &HashMap::new(),
            50,
            &|secs| format!("{}s", secs as i64),
            100.0,
            &|_ts| Some(0.0),
        );

        assert_eq!(receipts.len(), 1);
        // watcher is external but was @mentioned → counted as read
        assert_eq!(receipts[0].read_by, vec!["watcher"]);
    }

    #[test]
    fn test_compute_read_receipts_uses_canonical_mentions_not_text_prefixes() {
        let sent = vec![(
            42_i64,
            "2024-01-01T00:00:00Z".to_string(),
            serde_json::json!({
                "scope": "mentions",
                "text": "hey @giru check this",
                "mentions": ["giru"],
                "delivered_to": ["giru", "lasa"],
            }),
        )];

        let active: HashMap<String, Value> = HashMap::from([
            (
                "giru".to_string(),
                serde_json::json!({"session_id": "sess-1"}),
            ),
            ("lasa".to_string(), serde_json::json!({"tag": "giru-test"})),
        ]);
        let deliver_events = HashMap::from([(
            42_i64,
            HashSet::from(["giru".to_string(), "lasa".to_string()]),
        )]);

        let receipts = compute_read_receipts(
            &sent,
            &active,
            &deliver_events,
            &HashMap::new(),
            50,
            &|_| "1s".to_string(),
            100.0,
            &|_| Some(0.0),
        );

        assert_eq!(receipts[0].read_by, vec!["giru"]);
    }

    #[test]
    fn test_is_external_sender_data() {
        // Normal instance with session_id → not external
        assert!(!is_external_sender_data(
            &serde_json::json!({"session_id": "sess-1"})
        ));

        // External: no session_id
        assert!(is_external_sender_data(&serde_json::json!({"tag": null})));
        assert!(is_external_sender_data(
            &serde_json::json!({"session_id": ""})
        ));

        // Remote: has origin_device_id → not external
        assert!(!is_external_sender_data(
            &serde_json::json!({"origin_device_id": "dev-1"})
        ));

        // Subagent: has parent_session_id → not external
        assert!(!is_external_sender_data(
            &serde_json::json!({"parent_session_id": "parent-sess"})
        ));
    }
}
