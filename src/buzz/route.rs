//! Routing decisions, pure functions over typed inputs.
//!
//! Inbound: a verified Buzz event plus its ancestry becomes (or does not
//! become) one hcom delivery. Outbound: one hcom message plus the hosted rows
//! becomes a list of signed-post destinations, or a notice back to the sender.
//!
//! Nothing here does I/O. The caller owns the databases and the relay.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::json;

use crate::buzz::nostr::{Event, decode_npub, encode_npub};
use crate::buzz::store::AuthorKind;

/// Message kind: stream message (a channel post, top-level or thread reply).
pub const KIND_MESSAGE: u16 = 9;
/// Kind 40003: an edit of a previous message.
pub const KIND_EDIT: u16 = 40003;
/// Kind 5: NIP-09 deletion of a previous event.
pub const KIND_DELETE: u16 = 5;
/// Kind 9005: Buzz channel-scoped deletion.
pub const KIND_CHANNEL_DELETE: u16 = 9005;
/// Kind 39002: relay-signed channel roster.
pub const KIND_ROSTER: u16 = 39002;
/// Kind 0: NIP-01 profile metadata.
pub const KIND_PROFILE: u16 = 0;

/// Profile marker: `about` of a derived agent key's kind 0.
pub const AGENT_MARKER_PREFIX: &str = "zagcom/hcom-identity/v1:";
/// The reader identity's marker, deliberately absent from its `about` so it is
/// never mistaken for an hcom agent.
pub const READER_CANONICAL_PREFIX: &str = "hcom-buzz/connector/v1:";

/// A person row in the connector's roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonRow {
    pub pubkey: String,
    pub name: String,
    /// Home channel slug, for rule 3.
    pub home_slug: Option<String>,
}

/// A bridged channel row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRow {
    /// Buzz channel id (the `h` tag value).
    pub id: String,
    pub slug: String,
}

/// Everything routing needs to know about agents: the pubkey → hcom-name map
/// (as `serve` holds it), and which hcom names currently have a live row.
#[derive(Debug, Clone, Default)]
pub struct AgentRoster {
    /// Buzz pubkey → hcom name (`luna` for mbai, `luna:BOXE` for a mirror).
    pub by_pubkey: HashMap<String, String>,
    /// hcom names with a deliverable row right now.
    pub deliverable: BTreeSet<String>,
}

impl AgentRoster {
    /// True when the hcom name has a deliverable row.
    pub fn is_deliverable(&self, name: &str) -> bool {
        self.deliverable.contains(name)
    }
}

/// One hcom delivery the connector should make for an inbound Buzz event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundDelivery {
    /// Hosted person row the message is sent as.
    pub sender: String,
    /// Canonical hcom target names, explicit so nothing else receives it.
    pub targets: Vec<String>,
    /// `buzz_<channel>_<root12>`.
    pub thread: String,
    /// Content with npub/nprofile mentions rendered as `@name`.
    pub text: String,
    /// Buzz event id of the thread root (for the publisher's `e` tags).
    pub root_id: String,
    /// Buzz channel id.
    pub channel_id: String,
}

/// Why an inbound event produced no delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundSkip {
    /// Our own post, omp, the reader, or another owned key.
    OwnIdentity,
    /// No agent is addressed and no ancestor is one of theirs.
    NoTargets,
    /// The author is not a bridged human yet.
    NotAPerson,
    /// An edit or deletion of something never delivered.
    NeverDelivered,
}

/// Outcome of routing one inbound event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// Deliver this.
    Deliver(InboundDelivery),
    /// Nothing to do, and why.
    Skip(InboundSkip),
}

/// One ancestor of an event, as far as routing cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    pub buzz_id: String,
    pub author: String,
}

/// Everything known about one inbound event before routing.
#[derive(Debug, Clone)]
pub struct InboundEvent {
    pub event: Event,
    /// The bridged channel it arrived on.
    pub channel: ChannelRow,
    /// Thread root id (NIP-10 `root`, or the sole `e` for a direct reply).
    pub root_id: String,
    /// Chain from the event's parent up to (and excluding) the root, nearest
    /// first. Empty for a top-level post.
    pub ancestry: Vec<Ancestor>,
    /// For an edit or deletion: the event it revises. Deployed clients write
    /// only `h` + `e` on 40003/9005, so the people to notify come from the
    /// original's `p` tags, not the revision's.
    pub original: Option<Event>,
}

/// hcom thread name for a Buzz thread.
pub fn thread_name(channel_slug: &str, root_id: &str) -> String {
    format!("buzz_{channel_slug}_{}", short_root(root_id))
}

/// First 12 hex characters of a Buzz event id.
pub fn short_root(root_id: &str) -> String {
    root_id.chars().take(12).collect()
}

/// True when an hcom thread name was minted by this connector.
pub fn is_buzz_thread(thread: &str) -> bool {
    thread.starts_with("buzz_")
}

/// Tag value of the first tag named `name`, if any.
pub fn tag<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.first().is_some_and(|v| v == name))
        .and_then(|t| t.get(1))
        .map(String::as_str)
}

/// Every value of every tag named `name`, in order.
pub fn tags_all<'a>(event: &'a Event, name: &str) -> Vec<&'a str> {
    event
        .tags
        .iter()
        .filter(|t| t.first().is_some_and(|v| v == name))
        .filter_map(|t| t.get(1))
        .map(String::as_str)
        .collect()
}

/// The channel id an event belongs to: its `h` tag, else the channel of the
/// event an h-less kind 5/9005 deletion targets.
pub fn event_channel(
    event: &Event,
    ancestry: &[Ancestor],
    cached: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    if let Some(channel) = tag(event, "h") {
        return Some(channel.to_string());
    }
    if matches!(event.kind, KIND_DELETE | KIND_CHANNEL_DELETE) {
        let target = tag(event, "e")?;
        if ancestry.iter().any(|a| a.buzz_id == target) {
            return cached(target);
        }
    }
    None
}

/// NIP-10 root and reply markers of an event.
pub fn thread_refs(event: &Event) -> (Option<String>, Option<String>) {
    let mut root = None;
    let mut reply = None;
    for tag in &event.tags {
        if tag.first().is_none_or(|name| name != "e") {
            continue;
        }
        let Some(id) = tag.get(1) else { continue };
        match tag.get(3).map(String::as_str) {
            Some("root") => root = Some(id.clone()),
            Some("reply") => reply = Some(id.clone()),
            // A bare `e` (no marker) is the parent, which is also the root when
            // the reply targets it directly.
            None if reply.is_none() => reply = Some(id.clone()),
            _ => {}
        }
    }
    (root, reply)
}

/// Resolve an author pubkey to its hcom name, if it is one of ours.
pub fn agent_name_for(author: &str, roster: &AgentRoster) -> Option<String> {
    roster.by_pubkey.get(author).cloned()
}

/// The hcom name a profile marker claims: `zagcom/hcom-identity/v1:luna@boxe`
/// names `luna`, device `boxe`.
///
/// The marker is the whole point of the kind 0, so the name comes from it
/// rather than from a matching hcom row — an agent whose row is gone is still
/// recognisable, which is exactly the parked-target case.
pub fn identity_from_marker(about: &str) -> Option<(String, String)> {
    let canonical = about
        .strip_prefix(AGENT_MARKER_PREFIX)
        .or_else(|| about.strip_prefix(READER_CANONICAL_PREFIX))?;
    let (name, device) = canonical.rsplit_once('@')?;
    if name.is_empty() || device.is_empty() {
        return None;
    }
    Some((name.to_string(), device.to_string()))
}

/// Classify a Buzz author from its kind 0 profile.
///
/// `derived` is the pubkey → canonical `name@device` map (agents plus the
/// reader); `owner` is omp's pubkey. The marker is re-derived rather than
/// trusted: a profile claiming a name only counts when re-deriving that name
/// from the same seed yields this exact pubkey.
pub fn classify_profile(
    pubkey: &str,
    profile: &Event,
    owner_pubkey: &str,
    derived: &HashMap<String, String>,
    seed: &[u8; 32],
) -> AuthorKind {
    if pubkey == owner_pubkey {
        return AuthorKind::Owner;
    }
    // A kind 0 carries `about` in its content (NIP-01 metadata). The relay also
    // projects it to a tag, so accept either.
    let about = serde_json::from_str::<serde_json::Value>(&profile.content)
        .ok()
        .and_then(|value| {
            value
                .get("about")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| tag(profile, "about").map(str::to_string));
    let Some(about) = about.as_deref() else {
        // An unmarked profile is not an identity we own. This is exactly the
        // reader's own kind 0 case: it never carries the hcom agent marker.
        return AuthorKind::Unknown;
    };
    if let Some(canonical) = about.strip_prefix(READER_CANONICAL_PREFIX) {
        let expected = crate::buzz::nostr::derive_secret(seed, canonical);
        return if crate::buzz::nostr::public_hex(&expected) == pubkey {
            AuthorKind::Reader
        } else {
            AuthorKind::Unknown
        };
    }
    if let Some(canonical) = about.strip_prefix(AGENT_MARKER_PREFIX) {
        let expected = crate::buzz::nostr::derive_secret(seed, canonical);
        return if crate::buzz::nostr::public_hex(&expected) == pubkey {
            AuthorKind::Agent
        } else {
            AuthorKind::Unknown
        };
    }
    // A delegating non-member key that is not one we derived: role `bot` in the
    // roster is the human-facing way to tell an agent from a person.
    if derived.contains_key(pubkey) {
        return AuthorKind::Agent;
    }
    AuthorKind::Unknown
}

/// Render `nostr:npub…` / `nostr:nprofile…` mentions as `@name`.
///
/// A mention we cannot map is left as written rather than dropped: the reader
/// must not silently change what a human said.
pub fn render_mentions(text: &str, names: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let rest = &text[index..];
        if !rest.starts_with("nostr:") {
            let ch = text[index..]
                .chars()
                .next()
                .expect("index is a char boundary");
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        // Take the longest bech32 run after `nostr:`.
        let tail = &rest["nostr:".len()..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '1'))
            .unwrap_or(tail.len());
        let candidate = &tail[..end];
        match decode_npub(candidate) {
            Ok(pubkey) => {
                let name = names.get(&pubkey).map(|n| format!("@{n}")).or_else(|| {
                    // Fall back to the npub so an unmapped mention still renders.
                    encode_npub(&pubkey).ok().map(|npub| format!("@{npub}"))
                });
                out.push_str(&name.unwrap_or_else(|| rest[..end + 6].to_string()));
                index += "nostr:".len() + end;
            }
            Err(_) => {
                out.push('n');
                index += 1;
            }
        }
    }
    out
}

/// Route one inbound Buzz event to an hcom delivery, or explain the skip.
pub fn route_inbound(
    input: &InboundEvent,
    people: &[PersonRow],
    roster: &AgentRoster,
    author_kinds: &HashMap<String, AuthorKind>,
    already_delivered: bool,
) -> Inbound {
    let event = &input.event;

    let Some(sender_person) = people.iter().find(|p| p.pubkey == event.pubkey) else {
        return Inbound::Skip(InboundSkip::NotAPerson);
    };

    // Edits and deletions address the same people the original reached.
    if matches!(event.kind, KIND_EDIT | KIND_DELETE | KIND_CHANNEL_DELETE) && !already_delivered {
        return Inbound::Skip(InboundSkip::NeverDelivered);
    }

    // Our own posts, omp and the reader never come back as a person.
    match author_kinds
        .get(&event.pubkey)
        .copied()
        .unwrap_or(AuthorKind::Unknown)
    {
        AuthorKind::Agent | AuthorKind::Owner | AuthorKind::Reader => {
            return Inbound::Skip(InboundSkip::OwnIdentity);
        }
        AuthorKind::Person | AuthorKind::Unknown => {}
    }

    // Targets: explicit p-tags (the original's, for a revision) plus the author
    // of any ancestor that is an agent, minus the sender (a human never
    // messages themselves here).
    let tagged = input.original.as_ref().unwrap_or(event);
    let mut targets: BTreeSet<String> = tags_all(tagged, "p")
        .into_iter()
        .filter_map(|pubkey| agent_name_for(pubkey, roster))
        .collect();
    for ancestor in &input.ancestry {
        if let Some(name) = agent_name_for(&ancestor.author, roster) {
            targets.insert(name);
        }
    }
    targets.remove(&sender_person.name);
    if targets.is_empty() {
        return Inbound::Skip(InboundSkip::NoTargets);
    }

    let prefix = match event.kind {
        KIND_EDIT => "(edited) ",
        KIND_DELETE | KIND_CHANNEL_DELETE => "(deleted) ",
        _ => "",
    };

    Inbound::Deliver(InboundDelivery {
        sender: sender_person.name.clone(),
        targets: targets.into_iter().collect(),
        thread: thread_name(&input.channel.slug, &input.root_id),
        // A tombstone is empty; say which message went away.
        text: format!(
            "{prefix}{}",
            match (event.kind, &input.original) {
                (KIND_DELETE | KIND_CHANNEL_DELETE, Some(original)) => original.content.trim(),
                _ => event.content.trim(),
            }
        ),
        root_id: input.root_id.clone(),
        channel_id: input.channel.id.clone(),
    })
}

/// Render a name for the sender label of an inbound message.
pub fn sender_label(name: &str, device: Option<&str>) -> String {
    match device {
        Some("mbai") => name.to_string(),
        Some(device) => format!("{name} ({device})"),
        None => name.to_string(),
    }
}

// ── outbound ──────────────────────────────────────────────────────────────

/// One place a message should be posted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// Buzz channel id to post into.
    pub channel_id: String,
    /// NIP-10 `e` tags: reply in a thread, or None for a top-level post.
    pub root_id: Option<String>,
    /// Pubkeys to p-tag: the people being addressed.
    pub mentions: Vec<String>,
}

/// An outbound decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Post to these destinations.
    Post(Vec<Destination>),
    /// Nothing to post; drop the message.
    Drop,
    /// Some addressed people have no home channel: tell the agent why, as an
    /// hcom notice from the first of them, and still post to everyone else.
    Notice {
        sender: String,
        text: String,
        posts: Vec<Destination>,
    },
}

/// One hcom message considered for posting.
#[derive(Debug, Clone)]
pub struct HcomMessage {
    /// Sender's hcom name, possibly `name:SHORTID` for a remote row.
    pub from: String,
    pub text: String,
    pub thread: Option<String>,
    /// Resolved exact targets (may be empty for a broadcast).
    pub exact_targets: Vec<String>,
    /// Rows hcom actually delivered to. A `--reply-to` answer in a Buzz thread
    /// inherits its recipients from the thread, leaving `exact_targets` empty,
    /// so this is where the person being answered shows up.
    pub delivered_to: Vec<String>,
}

/// Everything outbound routing needs.
pub struct OutboundContext<'a> {
    pub people: &'a [PersonRow],
    pub channels: &'a [ChannelRow],
    /// hcom thread name → (channel id, root id) for Buzz-originated threads.
    pub threads: &'a BTreeMap<String, (String, String)>,
    /// Hosted channel rows (`ch_<slug>`) → Buzz channel id.
    pub host_device: &'a str,
}

/// The `name@device` label of an hcom row, per the identity rules.
///
/// `luna` on this device is `luna@mbai`; a remote `luna:BOXE` is `luna@boxe`.
pub fn canonical_identity(from: &str, host_device: &str) -> String {
    match from.rsplit_once(':') {
        Some((base, suffix))
            if suffix.len() == 4
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) =>
        {
            format!("{base}@{}", suffix.to_lowercase())
        }
        _ => format!("{from}@{host_device}"),
    }
}

/// True when a sender is external or system: never posted as a Buzz identity.
pub fn is_unroutable_sender(from: &str) -> bool {
    from.starts_with("ext_") || from.starts_with("sys_")
}

/// Route one hcom message to Buzz destinations.
pub fn route_outbound(message: &HcomMessage, ctx: &OutboundContext<'_>) -> Outbound {
    if is_unroutable_sender(&message.from) {
        return Outbound::Drop;
    }

    // A message a hosted row sent is a person writing to another person or an
    // agent; it is never the agent's post.
    if ctx
        .people
        .iter()
        .any(|p| p.name.eq_ignore_ascii_case(&message.from))
    {
        return Outbound::Drop;
    }

    let addressed: Vec<&PersonRow> = ctx
        .people
        .iter()
        .filter(|p| {
            message
                .exact_targets
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&p.name))
        })
        .collect();
    let channels_addressed: Vec<&ChannelRow> = ctx
        .channels
        .iter()
        .filter(|c| {
            message
                .exact_targets
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&c.row_name()))
        })
        .collect();

    // Rule 1: a Buzz-originated thread is a reply in that thread, p-tagging
    // every person it reached: the addressed ones and the thread's humans hcom
    // fanned it out to (the parent author included).
    if let Some(thread) = &message.thread
        && is_buzz_thread(thread)
        && let Some((channel_id, root_id)) = ctx.threads.get(thread)
    {
        let reached = |p: &&PersonRow| {
            message
                .exact_targets
                .iter()
                .chain(&message.delivered_to)
                .any(|t| t.eq_ignore_ascii_case(&p.name))
        };
        return Outbound::Post(vec![Destination {
            channel_id: channel_id.clone(),
            root_id: Some(root_id.clone()),
            mentions: ctx
                .people
                .iter()
                .filter(reached)
                .map(|p| p.pubkey.clone())
                .collect(),
        }]);
    }

    // Nothing addressed: a broadcast or ordinary hcom fan-out. Never forwarded.
    if addressed.is_empty() && channels_addressed.is_empty() {
        return Outbound::Drop;
    }

    // Rule 2: a channel row means one top-level post per channel.
    if !channels_addressed.is_empty() {
        return Outbound::Post(
            channels_addressed
                .iter()
                .map(|c| Destination {
                    channel_id: c.id.clone(),
                    root_id: None,
                    mentions: addressed.iter().map(|p| p.pubkey.clone()).collect(),
                })
                .collect(),
        );
    }

    // Rule 3: one post per distinct home channel, mentioning its people.
    let mut by_channel: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut homeless: Vec<&PersonRow> = Vec::new();
    for person in &addressed {
        match person.home_slug.as_deref() {
            Some(home) => by_channel
                .entry(home)
                .or_default()
                .push(person.pubkey.clone()),
            None => homeless.push(person),
        }
    }
    let posts: Vec<Destination> = by_channel
        .into_iter()
        .filter_map(|(slug, mentions)| {
            ctx.channels
                .iter()
                .find(|c| c.slug == slug)
                .map(|c| Destination {
                    channel_id: c.id.clone(),
                    root_id: None,
                    mentions,
                })
        })
        .collect();
    // People without a home get nothing posted; the agent hears why. Everyone
    // else addressed still gets their post.
    if !homeless.is_empty() {
        return Outbound::Notice {
            sender: homeless[0].name.clone(),
            text: format!(
                "{} has no home channel; address a channel row such as @ch_warehouse",
                homeless
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            posts,
        };
    }
    if posts.is_empty() {
        return Outbound::Drop;
    }
    Outbound::Post(posts)
}

impl ChannelRow {
    /// `ch_<slug>`.
    pub fn row_name(&self) -> String {
        format!("ch_{}", self.slug)
    }
}

/// Content of a post: text, with mentions left for the caller to p-tag.
pub fn post_content(text: &str) -> String {
    text.trim().to_string()
}

/// Tags for a kind 9 post, in desktop's order: `h`, thread `e` tags, `p` tags.
pub fn message_tags(destination: &Destination) -> Vec<Vec<String>> {
    let mut tags = vec![vec!["h".into(), destination.channel_id.clone()]];
    if let Some(root) = &destination.root_id {
        tags.push(vec![
            "e".into(),
            root.clone(),
            String::new(),
            "reply".into(),
        ]);
    }
    for mention in &destination.mentions {
        tags.push(vec!["p".into(), mention.clone()]);
    }
    tags
}

/// Kind 0 content for a derived agent identity.
pub fn agent_profile_content(name: &str, canonical: &str, remote: bool) -> String {
    json!({
        "display_name": if remote { format!("{name} (DEV)") } else { name.to_string() },
        "name": name,
        "about": format!("{AGENT_MARKER_PREFIX}{canonical}"),
    })
    .to_string()
}

/// Kind 30177 content: the managed-agent policy the mention popup reads.
pub fn managed_agent_content(name: &str) -> String {
    json!({
        "name": name,
        "respond_to": "anyone",
        "parallelism": 1,
    })
    .to_string()
}

/// Kind 9000 tags: add `agent_pubkey` to `channel_id` with role `bot`.
pub fn add_member_tags(channel_id: &str, agent_pubkey: &str) -> Vec<Vec<String>> {
    vec![
        vec!["h".into(), channel_id.into()],
        vec!["p".into(), agent_pubkey.into()],
        vec!["role".into(), "bot".into()],
    ]
}

/// Kind 9001 tags: remove `agent_pubkey` from `channel_id`.
pub fn remove_member_tags(channel_id: &str, agent_pubkey: &str) -> Vec<Vec<String>> {
    vec![
        vec!["h".into(), channel_id.into()],
        vec!["p".into(), agent_pubkey.into()],
    ]
}

/// Parse a roster (kind 39002) event into `(pubkey, role)` pairs.
pub fn roster_members(event: &Event) -> Vec<(String, String)> {
    event
        .tags
        .iter()
        .filter(|t| t.first().is_some_and(|v| v == "p"))
        .filter_map(|t| Some((t.get(1)?.to_string(), t.get(3).cloned().unwrap_or_default())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buzz::nostr::{UnsignedEvent, derive_secret, public_hex, sign};

    const SEED: [u8; 32] = [42; 32];
    /// An owner pubkey that is never one of the test keys.
    const OWNER_KEY: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn key(name: &str) -> crate::buzz::nostr::SecretKey {
        derive_secret(&SEED, name)
    }

    fn post(
        author: &crate::buzz::nostr::SecretKey,
        channel: &str,
        content: &str,
        tags: Vec<Vec<String>>,
    ) -> Event {
        let mut all = vec![vec!["h".into(), channel.into()]];
        all.extend(tags);
        sign(
            UnsignedEvent {
                created_at: 1_700_000_000,
                kind: KIND_MESSAGE,
                tags: all,
                content: content.into(),
            },
            author,
        )
    }

    fn person(pubkey: &str, name: &str, home: Option<&str>) -> PersonRow {
        PersonRow {
            pubkey: pubkey.into(),
            name: name.into(),
            home_slug: home.map(str::to_string),
        }
    }

    fn channel(id: &str, slug: &str) -> ChannelRow {
        ChannelRow {
            id: id.into(),
            slug: slug.into(),
        }
    }

    fn roster_with(names: &[&str]) -> AgentRoster {
        AgentRoster {
            by_pubkey: names
                .iter()
                .map(|n| (public_hex(&key(n)), n.to_string()))
                .collect(),
            deliverable: names.iter().map(|n| n.to_string()).collect(),
        }
    }

    // ── inbound ────────────────────────────────────────────────────────

    fn inbound(event: Event, ancestry: Vec<Ancestor>) -> InboundEvent {
        InboundEvent {
            root_id: ancestry
                .last()
                .map(|a| a.buzz_id.clone())
                .unwrap_or_else(|| event.id.clone()),
            event,
            channel: channel("chan-1", "infra"),
            ancestry,
            original: None,
        }
    }

    #[test]
    fn mention_delivers_from_the_person_to_the_agent() {
        let michael = key("michael@human");
        let luna = key("luna@mbai");
        let event = post(
            &michael,
            "chan-1",
            "can you look at this?",
            vec![vec!["p".into(), public_hex(&luna)]],
        );
        let people = [person(&public_hex(&michael), "michael", None)];
        let mut kinds = HashMap::new();
        kinds.insert(public_hex(&michael), AuthorKind::Person);

        let routed = route_inbound(
            &inbound(event, vec![]),
            &people,
            &roster_with(&["luna@mbai"]),
            &kinds,
            false,
        );

        let Inbound::Deliver(delivery) = routed else {
            panic!("a mention must deliver, got {routed:?}");
        };
        assert_eq!(delivery.sender, "michael");
        assert_eq!(delivery.targets, vec!["luna@mbai"]);
        assert_eq!(delivery.channel_id, "chan-1");
        assert_eq!(delivery.text, "can you look at this?");
        assert!(delivery.thread.starts_with("buzz_infra_"));
    }

    #[test]
    fn plain_thread_reply_routes_through_ancestry() {
        let michael = key("michael@human");
        let luna = key("luna@mbai");
        let root = post(&luna, "chan-1", "deploy status?", vec![]);
        // A plain reply carries no p-tag for the parent author.
        let reply = post(
            &michael,
            "chan-1",
            "shipped",
            vec![vec![
                "e".into(),
                root.id.clone(),
                String::new(),
                "reply".into(),
            ]],
        );

        let people = [person(&public_hex(&michael), "michael", None)];
        let mut kinds = HashMap::new();
        kinds.insert(public_hex(&michael), AuthorKind::Person);

        let routed = route_inbound(
            &inbound(
                reply,
                vec![Ancestor {
                    buzz_id: root.id.clone(),
                    author: public_hex(&luna),
                }],
            ),
            &people,
            &roster_with(&["luna@mbai"]),
            &kinds,
            false,
        );

        let Inbound::Deliver(delivery) = routed else {
            panic!("a plain reply under an agent post must deliver, got {routed:?}");
        };
        assert_eq!(delivery.targets, vec!["luna@mbai"]);
        assert_eq!(delivery.text, "shipped");
        assert!(delivery.thread.contains(&short_root(&root.id)));
    }

    #[test]
    fn deeper_reply_walks_two_ancestors_to_the_agent() {
        let michael = key("michael@human");
        let luna = key("luna@mbai");
        let root = post(&luna, "chan-1", "root", vec![]);
        let mid = post(
            &michael,
            "chan-1",
            "mid",
            vec![vec![
                "e".into(),
                root.id.clone(),
                String::new(),
                "reply".into(),
            ]],
        );
        let leaf = post(
            &michael,
            "chan-1",
            "leaf",
            vec![
                vec!["e".into(), root.id.clone(), String::new(), "root".into()],
                vec!["e".into(), mid.id.clone(), String::new(), "reply".into()],
            ],
        );

        let people = [person(&public_hex(&michael), "michael", None)];
        let mut kinds = HashMap::new();
        kinds.insert(public_hex(&michael), AuthorKind::Person);

        let routed = route_inbound(
            &inbound(
                leaf,
                vec![
                    Ancestor {
                        buzz_id: mid.id.clone(),
                        author: public_hex(&michael),
                    },
                    Ancestor {
                        buzz_id: root.id.clone(),
                        author: public_hex(&luna),
                    },
                ],
            ),
            &people,
            &roster_with(&["luna@mbai"]),
            &kinds,
            false,
        );

        let Inbound::Deliver(delivery) = routed else {
            panic!("ancestry must reach the root agent, got {routed:?}");
        };
        assert_eq!(delivery.targets, vec!["luna@mbai"]);
    }

    #[test]
    fn a_reply_under_a_person_post_has_no_agent_targets() {
        let michael = key("michael@human");
        let sean = key("sean@human");
        let root = post(&michael, "chan-1", "hello", vec![]);
        let reply = post(
            &sean,
            "chan-1",
            "hi",
            vec![vec![
                "e".into(),
                root.id.clone(),
                String::new(),
                "reply".into(),
            ]],
        );
        let people = [
            person(&public_hex(&michael), "michael", None),
            person(&public_hex(&sean), "sean", None),
        ];
        let mut kinds = HashMap::new();
        kinds.insert(public_hex(&sean), AuthorKind::Person);

        let routed = route_inbound(
            &inbound(
                reply,
                vec![Ancestor {
                    buzz_id: root.id,
                    author: public_hex(&michael),
                }],
            ),
            &people,
            &roster_with(&["luna@mbai"]),
            &kinds,
            false,
        );
        assert_eq!(routed, Inbound::Skip(InboundSkip::NoTargets));
    }

    #[test]
    fn an_author_missing_from_the_cache_is_still_delivered_by_p_tag() {
        // The ancestry fetch failed, but the explicit mention is enough: the
        // design caches the event for `read` and does not block on ancestry.
        let michael = key("michael@human");
        let luna = key("luna@mbai");
        let event = post(
            &michael,
            "chan-1",
            "ping",
            vec![vec!["p".into(), public_hex(&luna)]],
        );
        let people = [person(&public_hex(&michael), "michael", None)];
        let mut kinds = HashMap::new();
        kinds.insert(public_hex(&michael), AuthorKind::Person);

        let routed = route_inbound(
            &inbound(event, vec![]),
            &people,
            &roster_with(&["luna@mbai"]),
            &kinds,
            false,
        );
        assert!(matches!(routed, Inbound::Deliver(_)));
    }

    #[test]
    fn a_human_never_addresses_themselves() {
        let michael = key("michael@human");
        let event = post(&michael, "chan-1", "note to self", vec![]);
        let people = [person(&public_hex(&michael), "michael", None)];
        let mut kinds = HashMap::new();
        kinds.insert(public_hex(&michael), AuthorKind::Person);
        let mut roster = AgentRoster::default();
        // Even if the person were somehow an agent target, it is removed.
        roster
            .by_pubkey
            .insert(public_hex(&michael), "michael".into());
        roster.deliverable.insert("michael".into());

        let routed = route_inbound(&inbound(event, vec![]), &people, &roster, &kinds, false);
        assert_eq!(routed, Inbound::Skip(InboundSkip::NoTargets));
    }

    #[test]
    fn our_own_keys_are_skipped() {
        let michael = key("michael@human");
        let luna = key("luna@mbai");
        let event = post(&luna, "chan-1", "my own post", vec![]);
        let people = [person(&public_hex(&michael), "michael", None)];
        let mut kinds = HashMap::new();
        kinds.insert(public_hex(&michael), AuthorKind::Person);
        kinds.insert(public_hex(&luna), AuthorKind::Agent);

        let routed = route_inbound(
            &inbound(
                event,
                vec![Ancestor {
                    buzz_id: "x".into(),
                    author: public_hex(&luna),
                }],
            ),
            &people,
            &roster_with(&["luna@mbai"]),
            &kinds,
            false,
        );
        // Not a person row, so the first gate already refuses it.
        assert_eq!(routed, Inbound::Skip(InboundSkip::NotAPerson));

        // And when the author *is* a person row but the key is classified as an
        // owned identity (a reader replaying an old bridge post), skip anyway.
        let mixed = [person(&public_hex(&luna), "luna", None)];
        let routed = route_inbound(
            &inbound(post(&luna, "chan-1", "mine", vec![]), vec![]),
            &mixed,
            &roster_with(&["luna@mbai"]),
            &kinds,
            false,
        );
        assert_eq!(routed, Inbound::Skip(InboundSkip::OwnIdentity));
    }

    #[test]
    fn an_edit_of_a_delivered_post_becomes_an_edit_notice() {
        let michael = key("michael@human");
        let luna = key("luna@mbai");
        let original = post(
            &michael,
            "chan-1",
            "typo",
            vec![vec!["p".into(), public_hex(&luna)]],
        );
        // The deployed CLI's build_edit: kind 40003 with only `h` and a bare
        // `e`. No `p` tag rides along, so the targets must come from the
        // original the edit revises.
        let edit = sign(
            UnsignedEvent {
                created_at: 1_700_000_100,
                kind: KIND_EDIT,
                tags: vec![
                    vec!["h".into(), "chan-1".into()],
                    vec!["e".into(), original.id.clone()],
                ],
                content: "fixed".into(),
            },
            &michael,
        );

        let people = [person(&public_hex(&michael), "michael", None)];
        let mut kinds = HashMap::new();
        kinds.insert(public_hex(&michael), AuthorKind::Person);

        let mut input = inbound(edit.clone(), vec![]);
        input.root_id = original.id.clone();
        let without_original =
            route_inbound(&input, &people, &roster_with(&["luna@mbai"]), &kinds, true);
        assert_eq!(
            without_original,
            Inbound::Skip(InboundSkip::NoTargets),
            "the revision alone names nobody"
        );
        input.original = Some(original.clone());
        let routed = route_inbound(&input, &people, &roster_with(&["luna@mbai"]), &kinds, true);
        let Inbound::Deliver(delivery) = routed else {
            panic!("an edit of a delivered post must deliver, got {routed:?}");
        };
        assert!(delivery.text.starts_with("(edited) "), "{}", delivery.text);
        assert_eq!(delivery.targets, vec!["luna@mbai"]);

        let routed = route_inbound(
            &inbound(edit, vec![]),
            &people,
            &roster_with(&["luna@mbai"]),
            &kinds,
            false,
        );
        assert_eq!(routed, Inbound::Skip(InboundSkip::NeverDelivered));
    }

    #[test]
    fn deletions_of_both_kinds_are_notices_and_need_no_p_tag() {
        for kind in [KIND_DELETE, KIND_CHANNEL_DELETE] {
            let michael = key("michael@human");
            let luna = key("luna@mbai");
            let original = post(
                &michael,
                "chan-1",
                "oops",
                vec![vec!["p".into(), public_hex(&luna)]],
            );
            let deletion = sign(
                UnsignedEvent {
                    created_at: 1_700_000_200,
                    kind,
                    // build_delete_message / build_delete_compat: `h` + bare `e`.
                    tags: vec![
                        vec!["h".into(), "chan-1".into()],
                        vec!["e".into(), original.id.clone()],
                    ],
                    content: String::new(),
                },
                &michael,
            );
            let people = [person(&public_hex(&michael), "michael", None)];
            let mut kinds = HashMap::new();
            kinds.insert(public_hex(&michael), AuthorKind::Person);

            let mut input = inbound(deletion, vec![]);
            input.root_id = original.id.clone();
            input.original = Some(original);
            let routed = route_inbound(&input, &people, &roster_with(&["luna@mbai"]), &kinds, true);
            let Inbound::Deliver(delivery) = routed else {
                panic!("a kind {kind} deletion must deliver, got {routed:?}");
            };
            assert_eq!(
                delivery.text, "(deleted) oops",
                "an empty tombstone names the message it removed"
            );
            assert_eq!(delivery.targets, vec!["luna@mbai"]);
        }
    }

    #[test]
    fn npub_mentions_render_as_at_names() {
        let luna = key("luna@mbai");
        let npub = encode_npub(&public_hex(&luna)).unwrap();
        let names = HashMap::from([(public_hex(&luna), "luna".to_string())]);
        let text = format!("hey nostr:{npub} can you look?");

        assert_eq!(render_mentions(&text, &names), "hey @luna can you look?");

        let unmapped = HashMap::new();
        assert_eq!(
            render_mentions(&text, &unmapped),
            format!("hey @{npub} can you look?"),
            "an unmapped mention still renders, never dropped"
        );
        assert_eq!(
            render_mentions("no mentions here", &names),
            "no mentions here"
        );
        assert_eq!(
            render_mentions("nostr:garbage text", &names),
            "nostr:garbage text"
        );
    }

    #[test]
    fn a_marker_names_the_agent_and_its_device() {
        assert_eq!(
            identity_from_marker(&format!("{AGENT_MARKER_PREFIX}luna@mbai")),
            Some(("luna".to_string(), "mbai".to_string()))
        );
        assert_eq!(
            identity_from_marker(&format!("{AGENT_MARKER_PREFIX}luna@boxe")),
            Some(("luna".to_string(), "boxe".to_string()))
        );
        assert_eq!(
            identity_from_marker(&format!("{READER_CANONICAL_PREFIX}reader@mbai")),
            Some(("reader".to_string(), "mbai".to_string()))
        );
        assert_eq!(identity_from_marker("just a person"), None);
        assert_eq!(
            identity_from_marker(&format!("{AGENT_MARKER_PREFIX}nope")),
            None
        );
        assert_eq!(
            identity_from_marker(&format!("{AGENT_MARKER_PREFIX}@mbai")),
            None
        );
    }

    #[test]
    fn thread_names_are_stable_and_recognisable() {
        let root = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(thread_name("infra", root), "buzz_infra_0123456789ab");
        assert!(is_buzz_thread(&thread_name("infra", root)));
        assert!(!is_buzz_thread("infra"));
        assert!(is_buzz_thread("buzz_"));
    }

    #[test]
    fn thread_refs_read_nip10_markers_and_bare_e_tags() {
        let event = sign(
            UnsignedEvent {
                created_at: 1,
                kind: 9,
                tags: vec![
                    vec!["e".into(), "root-id".into(), String::new(), "root".into()],
                    vec!["e".into(), "reply-id".into(), String::new(), "reply".into()],
                ],
                content: String::new(),
            },
            &key("x@mbai"),
        );
        assert_eq!(
            thread_refs(&event),
            (Some("root-id".into()), Some("reply-id".into()))
        );

        let direct = sign(
            UnsignedEvent {
                created_at: 1,
                kind: 9,
                tags: vec![vec![
                    "e".into(),
                    "same".into(),
                    String::new(),
                    "reply".into(),
                ]],
                content: String::new(),
            },
            &key("x@mbai"),
        );
        assert_eq!(thread_refs(&direct), (None, Some("same".into())));

        let bare = sign(
            UnsignedEvent {
                created_at: 1,
                kind: 9,
                tags: vec![vec!["e".into(), "bare".into(), String::new()]],
                content: String::new(),
            },
            &key("x@mbai"),
        );
        assert_eq!(thread_refs(&bare), (None, Some("bare".into())));
    }

    #[test]
    fn profile_classification_re_derives_the_marker() {
        let agent = key("luna@mbai");
        let agent_pubkey = public_hex(&agent);
        let profile = sign(
            UnsignedEvent {
                created_at: 1,
                kind: KIND_PROFILE,
                tags: vec![vec!["auth".into(), "aa".into(), String::new(), "bb".into()]],
                content: json!({
                    "name": "luna",
                    "display_name": "luna",
                    "about": format!("{AGENT_MARKER_PREFIX}luna@mbai"),
                })
                .to_string(),
            },
            &agent,
        );
        let mut derived = HashMap::new();
        derived.insert(agent_pubkey.clone(), "luna@mbai".to_string());
        assert_eq!(
            classify_profile(&agent_pubkey, &profile, OWNER_KEY, &derived, &SEED),
            AuthorKind::Agent
        );

        // A profile claiming someone else's name: re-derivation must not match.
        let liar = key("liar@mbai");
        let liar_pubkey = public_hex(&liar);
        let forged = sign(
            UnsignedEvent {
                created_at: 1,
                kind: KIND_PROFILE,
                tags: vec![],
                content: json!({
                    "name": "luna",
                    "about": format!("{AGENT_MARKER_PREFIX}luna@mbai"),
                })
                .to_string(),
            },
            &liar,
        );
        assert_eq!(
            classify_profile(&liar_pubkey, &forged, OWNER_KEY, &derived, &SEED),
            AuthorKind::Unknown,
            "a forged marker must not classify as an agent"
        );

        // omp is the owner, whatever its profile says.
        let owner_pubkey = public_hex(&key(OWNER_KEY));
        let owner_profile = sign(
            UnsignedEvent {
                created_at: 1,
                kind: KIND_PROFILE,
                tags: vec![],
                content: "{}".into(),
            },
            &key(OWNER_KEY),
        );
        assert_eq!(
            classify_profile(
                &owner_pubkey,
                &owner_profile,
                &owner_pubkey,
                &derived,
                &SEED
            ),
            AuthorKind::Owner
        );
    }

    #[test]
    fn the_reader_has_its_own_marker_and_is_not_an_agent() {
        let reader = key("reader@mbai");
        let reader_pubkey = public_hex(&reader);
        let profile = sign(
            UnsignedEvent {
                created_at: 1,
                kind: KIND_PROFILE,
                tags: vec![],
                // No hcom agent marker: a reader must never look like an agent.
                content: json!({"name": "hcom-buzz", "display_name": "hcom-buzz"}).to_string(),
            },
            &reader,
        );
        let derived = HashMap::new();
        assert_eq!(
            classify_profile(&reader_pubkey, &profile, OWNER_KEY, &derived, &SEED),
            AuthorKind::Unknown,
            "an unmarked profile is not an identity we own"
        );

        // With the connector marker it classifies as the reader.
        let marked = sign(
            UnsignedEvent {
                created_at: 1,
                kind: KIND_PROFILE,
                tags: vec![],
                content: json!({
                    "name": "hcom-buzz",
                    "about": format!("{READER_CANONICAL_PREFIX}reader@mbai"),
                })
                .to_string(),
            },
            &reader,
        );
        assert_eq!(
            classify_profile(&reader_pubkey, &marked, OWNER_KEY, &derived, &SEED),
            AuthorKind::Reader
        );
    }

    // ── outbound ───────────────────────────────────────────────────────

    fn outctx<'a>(
        people: &'a [PersonRow],
        channels: &'a [ChannelRow],
        threads: &'a BTreeMap<String, (String, String)>,
    ) -> OutboundContext<'a> {
        OutboundContext {
            people,
            channels,
            threads,
            host_device: "mbai",
        }
    }

    fn message(from: &str, targets: &[&str], thread: Option<&str>) -> HcomMessage {
        HcomMessage {
            from: from.into(),
            text: "hello".into(),
            thread: thread.map(str::to_string),
            exact_targets: targets.iter().map(|t| t.to_string()).collect(),
            delivered_to: Vec::new(),
        }
    }

    #[test]
    fn rule1_buzz_thread_is_a_reply_in_that_thread() {
        let michael = person(&"m".repeat(64), "michael", Some("michael"));
        let channels = [
            channel("chan-michael", "michael"),
            channel("chan-1", "infra"),
        ];
        let threads = BTreeMap::from([(
            "buzz_infra_abc123".to_string(),
            ("chan-1".to_string(), "root-id".to_string()),
        )]);
        let routed = route_outbound(
            &message("luna", &["michael"], Some("buzz_infra_abc123")),
            &outctx(std::slice::from_ref(&michael), &channels, &threads),
        );
        assert_eq!(
            routed,
            Outbound::Post(vec![Destination {
                channel_id: "chan-1".into(),
                root_id: Some("root-id".into()),
                mentions: vec!["m".repeat(64)],
            }]),
            "a buzz thread reply goes to the thread's channel, not the home channel"
        );
    }

    #[test]
    fn a_thread_answer_tags_the_person_it_reached_without_addressing() {
        // `--reply-to` inherits the thread: no exact target, but hcom delivered
        // it to the human who wrote in the thread, and Buzz must notify them.
        let michael = person(&"m".repeat(64), "michael", Some("michael"));
        let sean = person(&"s".repeat(64), "seanfitz", Some("seanfitz"));
        let people = [michael, sean];
        let channels = [channel("chan-1", "infra")];
        let threads = BTreeMap::from([(
            "buzz_infra_abc123".to_string(),
            ("chan-1".to_string(), "root-id".to_string()),
        )]);
        let mut answer = message("luna", &[], Some("buzz_infra_abc123"));
        answer.delivered_to = vec!["michael".into(), "luna".into()];
        assert_eq!(
            route_outbound(&answer, &outctx(&people, &channels, &threads)),
            Outbound::Post(vec![Destination {
                channel_id: "chan-1".into(),
                root_id: Some("root-id".into()),
                mentions: vec!["m".repeat(64)],
            }]),
            "only the person the answer reached is tagged"
        );
    }

    #[test]
    fn rule1_wins_over_a_channel_target() {
        let michael = person(&"m".repeat(64), "michael", Some("michael"));
        let channels = [
            channel("chan-michael", "michael"),
            channel("chan-1", "infra"),
        ];
        let threads = BTreeMap::from([(
            "buzz_infra_abc123".to_string(),
            ("chan-1".to_string(), "root-id".to_string()),
        )]);
        let routed = route_outbound(
            &message("luna", &["michael", "ch_infra"], Some("buzz_infra_abc123")),
            &outctx(&[michael], &channels, &threads),
        );
        let Outbound::Post(dests) = routed else {
            panic!("expected a post, got {routed:?}");
        };
        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].channel_id, "chan-1");
        assert_eq!(dests[0].root_id.as_deref(), Some("root-id"));
    }

    #[test]
    fn rule2_a_channel_row_posts_once_per_channel() {
        let people = [person(&"m".repeat(64), "michael", None)];
        let channels = [channel("chan-1", "infra"), channel("chan-2", "warehouse")];
        let routed = route_outbound(
            &message("luna", &["michael", "ch_infra", "ch_warehouse"], None),
            &outctx(&people, &channels, &BTreeMap::new()),
        );
        let Outbound::Post(dests) = routed else {
            panic!("expected posts, got {routed:?}");
        };
        assert_eq!(dests.len(), 2);
        assert!(dests.iter().all(|d| d.root_id.is_none()), "top-level posts");
        assert!(
            dests.iter().all(|d| d.mentions == vec!["m".repeat(64)]),
            "the addressed person is mentioned in both"
        );
    }

    #[test]
    fn rule3_people_post_into_their_home_channels() {
        let people = [
            person(&"m".repeat(64), "michael", Some("michael")),
            person(&"s".repeat(64), "sean", Some("sean")),
        ];
        let channels = [
            channel("chan-michael", "michael"),
            channel("chan-sean", "sean"),
            channel("chan-1", "infra"),
        ];
        let routed = route_outbound(
            &message("luna", &["michael", "sean"], None),
            &outctx(&people, &channels, &BTreeMap::new()),
        );
        let Outbound::Post(dests) = routed else {
            panic!("expected posts, got {routed:?}");
        };
        assert_eq!(dests.len(), 2, "one post per distinct home channel");
        assert_eq!(dests[0].channel_id, "chan-michael");
        assert_eq!(dests[0].mentions, vec!["m".repeat(64)]);
        assert_eq!(dests[1].channel_id, "chan-sean");
        assert_eq!(dests[1].mentions, vec!["s".repeat(64)]);
    }

    #[test]
    fn two_people_sharing_a_home_get_one_post_tagging_both() {
        let people = [
            person(&"m".repeat(64), "michael", Some("infra")),
            person(&"s".repeat(64), "sean", Some("infra")),
        ];
        let channels = [channel("chan-1", "infra")];
        let routed = route_outbound(
            &message("luna", &["michael", "sean"], None),
            &outctx(&people, &channels, &BTreeMap::new()),
        );
        let Outbound::Post(dests) = routed else {
            panic!("expected a post, got {routed:?}");
        };
        assert_eq!(dests.len(), 1);
        assert_eq!(dests[0].mentions.len(), 2);
    }

    #[test]
    fn a_person_with_no_home_gets_a_notice_not_a_post() {
        let people = [person(&"m".repeat(64), "michael", None)];
        let channels = [channel("chan-1", "infra")];
        let routed = route_outbound(
            &message("luna", &["michael"], None),
            &outctx(&people, &channels, &BTreeMap::new()),
        );
        match routed {
            Outbound::Notice {
                sender,
                text,
                posts,
            } => {
                assert_eq!(sender, "michael");
                assert!(text.contains("no home channel"), "{text}");
                assert!(text.contains("@ch_warehouse"), "names the way out: {text}");
                assert!(posts.is_empty(), "nobody else to post to");
            }
            other => panic!("expected a notice, got {other:?}"),
        }
    }

    #[test]
    fn a_homeless_addressee_does_not_cost_the_others_their_post() {
        let michael = person(&"m".repeat(64), "michael", Some("michael"));
        let sean = person(&"s".repeat(64), "seanfitz", None);
        let people = [michael, sean];
        let channels = [channel("chan-michael", "michael")];
        let routed = route_outbound(
            &message("luna", &["michael", "seanfitz"], None),
            &outctx(&people, &channels, &BTreeMap::new()),
        );
        let Outbound::Notice {
            sender,
            text,
            posts,
        } = routed
        else {
            panic!("expected posts plus a notice, got {routed:?}");
        };
        assert_eq!(
            sender, "seanfitz",
            "from the person who couldn't be reached"
        );
        assert!(
            text.contains("seanfitz") && !text.contains("michael"),
            "{text}"
        );
        assert_eq!(
            posts,
            vec![Destination {
                channel_id: "chan-michael".into(),
                root_id: None,
                mentions: vec!["m".repeat(64)],
            }],
            "Michael still gets his post"
        );
    }

    #[test]
    fn a_broadcast_is_never_forwarded() {
        let people = [person(&"m".repeat(64), "michael", Some("michael"))];
        let channels = [channel("chan-michael", "michael")];
        assert_eq!(
            route_outbound(
                &message("luna", &[], None),
                &outctx(&people, &channels, &BTreeMap::new())
            ),
            Outbound::Drop
        );
    }

    #[test]
    fn thread_fanout_in_an_ordinary_thread_is_not_forwarded() {
        let people = [person(&"m".repeat(64), "michael", Some("michael"))];
        let channels = [channel("chan-michael", "michael")];
        // `mentions` alone is never the test: an inherited thread with no exact
        // targets must not reach Buzz.
        let mut msg = message("luna", &[], Some("infra"));
        msg.exact_targets = vec!["michael".into()];
        assert_eq!(
            route_outbound(&msg, &outctx(&people, &channels, &BTreeMap::new())),
            Outbound::Post(vec![Destination {
                channel_id: "chan-michael".into(),
                root_id: None,
                mentions: vec!["m".repeat(64)],
            }]),
            "an explicit target still forwards without a buzz thread"
        );

        let mut inherited = message("luna", &[], Some("infra"));
        inherited.exact_targets = Vec::new();
        assert_eq!(
            route_outbound(&inherited, &outctx(&people, &channels, &BTreeMap::new())),
            Outbound::Drop,
            "an inherited ordinary thread with no targets reaches nobody"
        );
    }

    #[test]
    fn a_message_from_a_hosted_row_is_dropped() {
        let people = [person(&"m".repeat(64), "michael", Some("michael"))];
        let channels = [channel("chan-michael", "michael")];
        let routed = route_outbound(
            &message("michael", &["ch_infra"], None),
            &outctx(&people, &channels, &BTreeMap::new()),
        );
        assert_eq!(routed, Outbound::Drop, "people do not post as agents");
    }

    #[test]
    fn external_and_system_senders_are_dropped() {
        let people = [person(&"m".repeat(64), "michael", Some("michael"))];
        let channels = [channel("chan-michael", "michael")];
        for from in ["ext_operator", "sys_whatever"] {
            assert_eq!(
                route_outbound(
                    &message(from, &["michael"], None),
                    &outctx(&people, &channels, &BTreeMap::new())
                ),
                Outbound::Drop,
                "{from} is not posted"
            );
        }
        assert!(is_unroutable_sender("ext_x"));
        assert!(!is_unroutable_sender("luna"));
    }

    #[test]
    fn target_matching_is_case_insensitive() {
        let people = [person(&"m".repeat(64), "michael", Some("michael"))];
        let channels = [channel("chan-michael", "michael")];
        let routed = route_outbound(
            &message("luna", &["Michael"], None),
            &outctx(&people, &channels, &BTreeMap::new()),
        );
        assert!(matches!(routed, Outbound::Post(_)));
    }

    #[test]
    fn agent_identity_labels_are_canonical() {
        assert_eq!(canonical_identity("luna", "mbai"), "luna@mbai");
        assert_eq!(canonical_identity("luna:BOXE", "mbai"), "luna@boxe");
        assert_eq!(canonical_identity("luna:BOX1", "mbai"), "luna@box1");
        // A lowercase colon that is not a 4-char uppercase device suffix is a
        // tag-style name, not a device.
        assert_eq!(canonical_identity("team:luna", "mbai"), "team:luna@mbai");
    }

    #[test]
    fn post_tags_match_the_desktop_shape() {
        let dest = Destination {
            channel_id: "chan-1".into(),
            root_id: Some("root".into()),
            mentions: vec!["a".into(), "b".into()],
        };
        assert_eq!(
            message_tags(&dest),
            vec![
                vec!["h".into(), "chan-1".into()],
                vec!["e".into(), "root".into(), String::new(), "reply".into()],
                vec!["p".into(), "a".into()],
                vec!["p".into(), "b".into()],
            ]
        );
        assert_eq!(
            message_tags(&Destination {
                channel_id: "c".into(),
                root_id: None,
                mentions: vec![]
            })
            .len(),
            1
        );
    }

    #[test]
    fn enrollment_content_is_what_the_popup_reads() {
        let profile = agent_profile_content("luna", "luna@mbai", false);
        let value: serde_json::Value = serde_json::from_str(&profile).unwrap();
        assert_eq!(value["display_name"], "luna");
        assert_eq!(value["about"], format!("{AGENT_MARKER_PREFIX}luna@mbai"));

        let remote = agent_profile_content("luna", "luna@boxe", true);
        let value: serde_json::Value = serde_json::from_str(&remote).unwrap();
        assert_eq!(value["display_name"], "luna (DEV)");

        let managed: serde_json::Value =
            serde_json::from_str(&managed_agent_content("luna")).unwrap();
        assert_eq!(managed["respond_to"], "anyone");
        assert_eq!(managed["parallelism"], 1);

        assert_eq!(
            add_member_tags("chan-1", "a"),
            vec![
                vec!["h".to_string(), "chan-1".to_string()],
                vec!["p".to_string(), "a".to_string()],
                vec!["role".to_string(), "bot".to_string()],
            ]
        );
        assert_eq!(remove_member_tags("chan-1", "a").len(), 2);
    }

    #[test]
    fn roster_members_carry_their_role() {
        let event = sign(
            UnsignedEvent {
                created_at: 1,
                kind: KIND_ROSTER,
                tags: vec![
                    vec!["d".into(), "chan-1".into()],
                    vec!["p".into(), "a".into(), String::new(), "bot".into()],
                    vec!["p".into(), "b".into(), String::new(), "member".into()],
                    vec!["p".into(), "c".into()],
                ],
                content: String::new(),
            },
            &key("relay@test"),
        );
        assert_eq!(
            roster_members(&event),
            vec![
                ("a".to_string(), "bot".to_string()),
                ("b".to_string(), "member".to_string()),
                ("c".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn h_less_deletions_inherit_their_target_channel() {
        let michael = key("michael@human");
        let original = post(&michael, "chan-1", "text", vec![]);
        let deletion = sign(
            UnsignedEvent {
                created_at: 1_700_000_300,
                kind: KIND_CHANNEL_DELETE,
                tags: vec![vec![
                    "e".into(),
                    original.id.clone(),
                    String::new(),
                    "reply".into(),
                ]],
                content: String::new(),
            },
            &michael,
        );
        let root_id = original.id.clone();
        let ancestry = [Ancestor {
            buzz_id: root_id.clone(),
            author: public_hex(&michael),
        }];
        let cached = move |id: &str| (id == root_id).then(|| "chan-1".to_string());
        assert_eq!(
            event_channel(&deletion, &ancestry, cached),
            Some("chan-1".to_string())
        );
    }
}
