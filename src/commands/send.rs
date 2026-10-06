//! `hcom send` command — send messages to hcom instances.

use std::io::{IsTerminal, Read as IoRead};

use crate::db::HcomDb;
use crate::db::subscriptions::create_request_watches;
use crate::delivery_policy::{MessageFacts, SendVerdict};
use crate::fleet_names::FleetCtx;
use crate::identity;
use crate::instances;
use crate::messages::{
    MessageEnvelope, MessageScope, compute_scope, should_deliver_message, validate_intent,
    validate_message,
};
use crate::shared::{
    CommandContext, SENDER, SenderIdentity, SenderKind, is_inside_ai_tool, status_icon,
};

const SEND_AFTER_HELP: &str = "\
Target matching:
    luna                           exact base name (the '@' is optional)
    @luna                          same target, '@' form
    @api-luna                      exact full name
    @api-                          all local agents with exact tag 'api'
    @luna:BOXE                     exact or uniquely prefixed remote agent
  Partial local names are rejected to avoid accidental fan-out.

Targets before '--':
  With '--' (or --stdin/--file/--base64) every positional is a target and the
  '@' is optional: 'hcom send luna -- text'. That form is the one to use in
  PowerShell, which swallows a bare '@luna' as splatting.
  Without '--' a bare positional is the message text, so the '@' is needed
  there: 'hcom send @luna hello'.

Inline bundle (attach structured context):
    --title <text>                 Create and attach bundle inline
    --description <text>           Bundle description (required with --title)
    --events <ids>                 Event IDs/ranges: 1,2,5-10
    --files <paths>                Comma-separated file paths
    --transcript <ranges>          Format: 3-14:normal,6:full,22-30:detailed
    --extends <id>                 Parent bundle (optional)
  See 'hcom bundle --help' for bundle details

Examples:
    hcom send luna -- Hello there!
    hcom send luna nova --intent request -- Can you help?
    hcom send -- Broadcast message to everyone
    echo 'Complex message' | hcom send luna
    hcom send luna <<'EOF'
    Multi-line message with special chars
    EOF";

/// Parse positional arg: accept both @targets and bare text.
/// Bare text (no @ prefix) is accepted by clap and separated later in cmd_send.
fn parse_positional(s: &str) -> Result<String, String> {
    if s == "@" {
        Err("Empty target '@' is not allowed".to_string())
    } else {
        Ok(s.to_string())
    }
}

/// Parsed arguments for `hcom send`.
#[derive(clap::Parser, Debug)]
#[command(
    name = "send",
    about = "Send a message to agents",
    after_help = SEND_AFTER_HELP,
)]
pub struct SendArgs {
    /// Positional args: @targets and/or bare message text (backward compat)
    #[arg(value_parser = parse_positional)]
    pub positionals: Vec<String>,

    /// Message text (after --)
    #[arg(last = true)]
    pub message: Vec<String>,

    // ── Message source ──
    /// Read message from stdin
    #[arg(long)]
    pub stdin: bool,

    /// Read message from file
    #[arg(long)]
    pub file: Option<String>,

    /// Read message from base64-encoded string
    #[arg(long)]
    pub base64: Option<String>,

    // ── Envelope ──
    /// Message intent (request|inform|ack)
    #[arg(long)]
    pub intent: Option<String>,

    /// Reply to event ID (42 or 42:BOXE)
    #[arg(long)]
    pub reply_to: Option<String>,

    /// Threaded routing: seed recipients once, then reuse thread members
    #[arg(long)]
    pub thread: Option<String>,

    // ── Sender ──
    /// External sender identity
    #[arg(long)]
    pub from: Option<String>,

    /// Shorthand for --from bigboss
    #[arg(short = 'b')]
    pub bigboss: bool,

    /// Suppress output
    #[arg(long)]
    pub quiet: bool,

    // ── Inline bundle ──
    /// Bundle title (creates inline bundle)
    #[arg(long)]
    pub title: Option<String>,

    /// Bundle description
    #[arg(long)]
    pub description: Option<String>,

    /// Bundle event IDs/ranges
    #[arg(long)]
    pub events: Option<String>,

    /// Bundle file paths (comma-separated)
    #[arg(long, rename_all = "verbatim")]
    pub files: Option<String>,

    /// Bundle transcript ranges
    #[arg(long)]
    pub transcript: Option<String>,

    /// Parent bundle ID
    #[arg(long)]
    pub extends: Option<String>,

    /// Set by router: whether `--` was present in raw argv.
    /// Clap can't distinguish "no --" from "-- with no args", so the router sets this.
    #[arg(skip)]
    pub had_separator: bool,
}

impl SendArgs {
    /// Resolve the effective --from name (--from overrides -b).
    fn sender_name(&self) -> Option<String> {
        if let Some(ref name) = self.from {
            Some(name.clone())
        } else if self.bigboss {
            Some("bigboss".to_string())
        } else {
            None
        }
    }

    /// Whether a `--` separator was present in the raw argv.
    fn has_separator(&self) -> bool {
        self.had_separator
    }

    /// Build inline bundle data from flags, or None if no bundle flags present.
    fn build_bundle_data(&self) -> Result<Option<serde_json::Value>, String> {
        let has_any = self.title.is_some()
            || self.description.is_some()
            || self.events.is_some()
            || self.files.is_some()
            || self.transcript.is_some()
            || self.extends.is_some();

        if !has_any {
            return Ok(None);
        }

        let title = self.title.as_ref().ok_or_else(|| {
            let present: Vec<&str> = [
                self.description.as_ref().map(|_| "--description"),
                self.events.as_ref().map(|_| "--events"),
                self.files.as_ref().map(|_| "--files"),
                self.transcript.as_ref().map(|_| "--transcript"),
                self.extends.as_ref().map(|_| "--extends"),
            ]
            .into_iter()
            .flatten()
            .collect();
            format!(
                "Bundle flags require --title: found {} without --title",
                present.join(", ")
            )
        })?;

        let description = self
            .description
            .as_ref()
            .ok_or("--description is required when --title is present")?;

        use crate::core::bundles::parse_csv_list;
        let events = parse_csv_list(self.events.as_deref());
        let files = parse_csv_list(self.files.as_deref());
        let transcript = parse_csv_list(self.transcript.as_deref());

        let mut bundle = serde_json::json!({
            "title": title,
            "description": description,
            "refs": {
                "events": events,
                "files": files,
                "transcript": transcript,
            }
        });

        if let Some(ref ext) = self.extends {
            bundle
                .as_object_mut()
                .unwrap()
                .insert("extends".into(), serde_json::json!(ext));
        }

        Ok(Some(bundle))
    }
}

/// Get formatted recipient feedback showing who received the message.
fn get_recipient_feedback(db: &HcomDb, delivered_to: &[String]) -> String {
    if delivered_to.is_empty() {
        return format!("Sent to: {SENDER}");
    }
    if delivered_to.len() > 10 {
        return format!("Sent to {} agents", delivered_to.len());
    }

    let mut parts = Vec::new();
    for name in delivered_to {
        if let Ok(Some(data)) = db.get_instance_full(name) {
            let icon = status_icon(&data.status);
            let display = identity::get_display_name(db, name);
            parts.push(format!("{icon} {display}"));
        } else {
            parts.push(format!("◌ {name}"));
        }
    }
    format!("Sent to: {}", parts.join(", "))
}

#[derive(Clone)]
struct ResolvedDelivery {
    original_scope: MessageScope,
    effective_scope: MessageScope,
    effective_mentions: Vec<String>,
    delivered_to: Vec<String>,
    is_thread_resolved: bool,
    /// Recipients the delivery policy refused, as `(recipient, delegate)`.
    reroutes: Vec<(String, String)>,
    /// Refused recipients kept because the delegate names no single live
    /// row, as `(recipient, why)` (`mupe is not live`).
    kept_for_holder: Vec<(String, String)>,
    /// Policy instances an External sender reached (the audited bypass).
    external_reached_policy: Vec<String>,
    /// The sender has a `[delivery.*]` entry: its requests create no watches.
    sender_has_policy: bool,
    /// The targets the sender addressed (mentions or thread members), before
    /// any reroute: a delegate named here is a recipient in its own right.
    addressed: Vec<String>,
}

/// One `hcom send` output line per refused recipient.
fn reroute_notices(delivery: &ResolvedDelivery) -> Vec<String> {
    let rerouted = delivery
        .reroutes
        .iter()
        .map(|(recipient, delegate)| format!("{recipient} takes no cc; delivered to {delegate}"));
    let kept = delivery
        .kept_for_holder
        .iter()
        .map(|(recipient, why)| format!("{why}; delivered to {recipient}"));
    rerouted.chain(kept).collect()
}

fn resolve_delivery(
    db: &HcomDb,
    identity: &SenderIdentity,
    message: &str,
    envelope: Option<&MessageEnvelope>,
    explicit_targets: Option<&[String]>,
) -> Result<ResolvedDelivery, String> {
    // Deliverable agents: exclude session-stopped (exit:*) and launch_failed placeholders.
    // Adhoc instances use inactive:tool:* between commands — still @mentionable.
    let rows =
        crate::messages::deliverable_instances(db.conn()).map_err(|e| format!("DB error: {e}"))?;
    // Fleet bare-name context, loaded once per send (infallible: every
    // failure path degrades to the empty fallback).
    let fleet = FleetCtx::load();

    // Compute scope and routing. Thread-only sends keep their original message
    // semantics; membership only affects the delivery target set.
    let scope_result = compute_scope(message, &rows, explicit_targets, &fleet)?;
    let thread_delivery_members =
        if let Some(thread) = envelope.and_then(|env| env.thread.as_deref()) {
            if scope_result.scope == MessageScope::Broadcast {
                let members = db.get_thread_members(thread);
                if members.is_empty() {
                    return Err(format!(
                        "Thread '{thread}' has no members. Seed it with @mentions first."
                    ));
                }
                members
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
    let is_thread_resolved = !thread_delivery_members.is_empty();
    let effective_scope = if thread_delivery_members.is_empty() {
        scope_result.scope
    } else {
        MessageScope::Mentions
    };
    let mut effective_mentions = if thread_delivery_members.is_empty() {
        scope_result.mentions.clone()
    } else {
        thread_delivery_members.clone()
    };
    let addressed = effective_mentions.clone();

    // Operator delivery policy (crate::delivery_policy): a refused recipient
    // is replaced by its delegate in the stored mentions/exact_targets, which
    // is what receivers deliver from. One hop: a delegate is never evaluated.
    let policies = crate::delivery_policy::load(db)?;
    let facts = MessageFacts {
        from: &identity.name,
        external: matches!(identity.kind, SenderKind::External),
        targeted: effective_scope == MessageScope::Mentions,
        intent: envelope
            .and_then(|env| env.intent.as_ref())
            .map(|i| i.as_str()),
        text: message,
    };
    let mut reroutes = Vec::new();
    let mut kept_for_holder = Vec::new();
    if facts.targeted {
        let mut kept: Vec<String> = Vec::with_capacity(effective_mentions.len());
        for name in effective_mentions {
            let target = match policies.send_verdict(&name, &facts) {
                SendVerdict::Deliver => name,
                // The delegate resolves like any target (an exact live name
                // first; a bare remote name maps to its mirror row). No
                // single live row: the holder keeps it (never dropped, and a
                // delegate row started later begins at the current cursor,
                // so parking it for the delegate would lose it).
                SendVerdict::RerouteTo(delegate) => {
                    match crate::delivery_policy::resolve_delegate(&delegate, &rows, &fleet) {
                        Ok(canonical) => {
                            reroutes.push((name, canonical.clone()));
                            canonical
                        }
                        Err(why) => {
                            let why = why.describe(&delegate);
                            crate::log::log_warn(
                                "delivery_policy",
                                "delegate_unresolved",
                                &format!("delegate {why}; delivered to {name}"),
                            );
                            kept_for_holder.push((name.clone(), why));
                            name
                        }
                    }
                }
            };
            if !kept.contains(&target) {
                kept.push(target);
            }
        }
        effective_mentions = kept;
    }
    let external_reached_policy = if facts.external {
        effective_mentions
            .iter()
            .filter(|name| policies.governs(name))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let is_delegate_copy = |name: &str| {
        reroutes.iter().any(|(_, d)| d == name) || kept_for_holder.iter().any(|(h, _)| h == name)
    };

    let scope_data = build_scope_data(
        identity,
        effective_scope,
        &effective_mentions,
        !is_thread_resolved,
    );
    let delivered_to = rows
        .iter()
        .filter(|inst| {
            should_deliver_message(&scope_data, &inst.name, &identity.name).unwrap_or(false)
                && (is_delegate_copy(&inst.name) || policies.admits(&inst.name, &facts))
        })
        .map(|inst| inst.name.clone())
        .collect();

    Ok(ResolvedDelivery {
        original_scope: scope_result.scope,
        effective_scope,
        effective_mentions,
        delivered_to,
        is_thread_resolved,
        reroutes,
        kept_for_holder,
        external_reached_policy,
        sender_has_policy: policies.governs(&identity.name),
        addressed,
    })
}

/// The event data the local `delivered_to` filter is computed from.
/// `resolved` is false for the thread-override path, whose members come from
/// a stored membership list rather than from this send's resolution: the
/// key is omitted there, so that path keeps the legacy base-name match
/// instead of being silently over-constrained to unresolved names.
fn build_scope_data(
    identity: &SenderIdentity,
    scope: MessageScope,
    mentions: &[String],
    resolved: bool,
) -> serde_json::Value {
    let mut scope_data = serde_json::json!({
        "scope": scope.as_str(),
    });
    if !mentions.is_empty() {
        scope_data["mentions"] = serde_json::json!(mentions);
    }
    // Device-exact delivery: mentions are already resolved to canonical
    // exact instance names, so record them for the local delivered_to filter
    // (same value the event writer stores). Broadcast omits the key.
    if resolved && scope == MessageScope::Mentions && !mentions.is_empty() {
        scope_data["exact_targets"] = serde_json::json!(mentions);
    }
    if let Some(gid) = identity.group_id() {
        scope_data["group_id"] = serde_json::json!(gid);
    }
    scope_data
}

fn print_broadcast_preview(db: &HcomDb, delivered_to: &[String]) {
    let count = delivered_to.len();
    let names: Vec<String> = delivered_to
        .iter()
        .map(|name| {
            if let Ok(Some(data)) = db.get_instance_full(name) {
                let icon = status_icon(&data.status);
                let display = identity::get_display_name(db, name);
                format!("{icon} {display}")
            } else {
                format!("◌ {name}")
            }
        })
        .collect();
    let recipient_list = if count <= 12 {
        names.join(", ")
    } else {
        format!("{} ... (+{} more)", names[..10].join(", "), count - 10)
    };

    println!("\n== BROADCAST SEND PREVIEW ==");
    println!("This message has no @targets, so it would broadcast to {count} agents.");
    println!("Recipients:\n  {recipient_list}\n");
    println!("Did you mean to send this to everyone?");
    println!("Broadcasts can wake many terminals and spend many agents' context/tools.");
    println!("\nAdd --go after send and run again to proceed:");
    println!("  hcom send --go ...\n");
}

///
/// Validates message, computes scope, logs event, notifies all instances.
/// Returns delivered_to list (base names).
pub fn send_message(
    db: &HcomDb,
    identity: &SenderIdentity,
    message: &str,
    envelope: Option<&MessageEnvelope>,
    explicit_targets: Option<&[String]>,
) -> Result<Vec<String>, String> {
    send_message_resolved(db, identity, message, envelope, explicit_targets)
        .map(|delivery| delivery.delivered_to)
}

/// `send_message`, returning the whole resolution (reroutes included) for
/// `hcom send`'s own output.
fn send_message_resolved(
    db: &HcomDb,
    identity: &SenderIdentity,
    message: &str,
    envelope: Option<&MessageEnvelope>,
    explicit_targets: Option<&[String]>,
) -> Result<ResolvedDelivery, String> {
    validate_message(message)?;

    let delivery = resolve_delivery(db, identity, message, envelope, explicit_targets)?;
    persist_resolved(db, identity, message, envelope, delivery)
}

/// Store a resolved message and run its after-commit work. The resolution
/// was read outside any write lock; the persist re-checks it (see
/// `recheck_reroutes`) in the transaction that inserts the row.
fn persist_resolved(
    db: &HcomDb,
    identity: &SenderIdentity,
    message: &str,
    envelope: Option<&MessageEnvelope>,
    delivery: ResolvedDelivery,
) -> Result<ResolvedDelivery, String> {
    let scope_str = delivery.effective_scope.as_str();

    // Build event data. The routing fields (delivered_to, mentions,
    // exact_targets, the reroute marker) are added inside the write
    // transaction, from the delivery re-checked there.
    let mut data = serde_json::json!({
        "from": identity.name,
        "sender_kind": match identity.kind {
            SenderKind::External => "external",
            SenderKind::Instance => "instance",
            SenderKind::System => "system",
        },
        "scope": scope_str,
        "text": message,
    });

    if let Some(env) = envelope {
        if let Some(intent) = &env.intent {
            data["intent"] = serde_json::json!(intent.as_str());
        }
        if let Some(reply_to) = &env.reply_to {
            data["reply_to"] = serde_json::json!(reply_to);
            // Resolve to local event ID
            if let Some(local_id) = resolve_reply_to_local(db, reply_to) {
                data["reply_to_local"] = serde_json::json!(local_id);

                // Ack-on-ack loop prevention
                if env.intent.as_ref().map(|i| i.as_str()) == Some("ack")
                    && let Some(parent_intent) = get_intent_from_event(db, local_id)
                {
                    if parent_intent == "ack" {
                        return Err("Ack-on-ack loop detected. Message blocked.".to_string());
                    }
                    if parent_intent == "inform" {
                        return Err("Cannot ack an inform - informational messages don't need acknowledgment.".to_string());
                    }
                }
            }
        }
        if let Some(thread) = &env.thread {
            data["thread"] = serde_json::json!(thread);
        }
        if let Some(bundle_id) = &env.bundle_id {
            data["bundle_id"] = serde_json::json!(bundle_id);
        }
    }

    // Determine routing instance (namespace isolation)
    let routing_instance = match identity.kind {
        SenderKind::External => format!("ext_{}", identity.name),
        SenderKind::System => format!("sys_{}", identity.name),
        SenderKind::Instance => identity.name.clone(),
    };

    // Log event to DB: ONLY the message-row insert runs in the write
    // transaction (one short statement), retried on lock contention. The
    // subscription fan-out below runs after commit: it wakes TCP listeners
    // and writes more rows, so it must never hold the write lock.
    // True worst case ≈ 35s: the 30s retry budget plus one final 5s
    // busy_timeout — the last attempt may itself sleep the full SQLite
    // busy_timeout inside the engine before surfacing SQLITE_BUSY.
    // Every delegate chosen above is re-checked against the rows this
    // transaction sees: a delegate that stopped between resolution and this
    // insert would get a message its restarted row never reads (it starts at
    // the current cursor), with the holder not a target, so lost. A stop
    // needs this same write lock, so no delegate can leave between the check
    // and the insert. Each retry starts again from the resolution, so nothing
    // decided under an earlier attempt's snapshot survives.
    let fleet = crate::fleet_names::FleetCtx::load();
    let write_started = std::time::Instant::now();
    let (event_id, delivery, data) = crate::db::retry_on_busy(
        || {
            db.with_immediate_transaction(|tx| {
                let mut delivery = delivery.clone();
                if !delivery.reroutes.is_empty() {
                    let rows = crate::messages::deliverable_instances(tx)?;
                    recheck_reroutes(&mut delivery, &rows, &fleet);
                }
                let mut data = data.clone();
                set_routing_fields(&mut data, &delivery);
                let event_id = db.insert_event_row("message", &routing_instance, &data, None)?;
                Ok((event_id, delivery, data))
            })
        },
        crate::db::DEFAULT_SEND_WRITE_BUDGET,
    )
    .map_err(|e| {
        // Say `retried` only for lock contention: any other failure (torn
        // WAL, full disk, logic bug) returns on its first attempt.
        let elapsed = write_started.elapsed().as_secs_f64();
        if crate::db::is_busy_error(&e) {
            format!(
                "Failed to write message to database (retried {elapsed:.1}s, message NOT sent): {e}"
            )
        } else {
            format!("Failed to write message to database ({elapsed:.1}s, message NOT sent): {e}")
        }
    })?;
    db.dispatch_logged_event(event_id, "message", &routing_instance, &data);

    // `--from` is unauthenticated, so an External sender reaching a policy
    // instance is the known bypass; leave a trail every time it happens.
    for recipient in &delivery.external_reached_policy {
        crate::log::log_with_fields(
            "INFO",
            "delivery_policy",
            "external_reached",
            &format!(
                "External sender '{}' reached policy instance {recipient}",
                identity.name
            ),
            &[("event_id", &event_id.to_string())],
        );
    }

    // Auto-create request-watch subscriptions for targeted requests
    if let Some(env) = envelope {
        if let Some(thread) = env.thread.as_deref() {
            db.add_thread_memberships(
                thread,
                matches!(identity.kind, SenderKind::Instance).then_some(identity.name.as_str()),
                &delivery.delivered_to,
            );
        }

        // A policy instance (the conductor) never arms request watches: their
        // idle pings would come straight back to it.
        if env.intent.as_ref().map(|i| i.as_str()) == Some("request")
            && matches!(identity.kind, SenderKind::Instance)
            && delivery.effective_scope == MessageScope::Mentions
            && !delivery.is_thread_resolved
            && !delivery.sender_has_policy
        {
            create_request_watches(db, &identity.name, event_id, &delivery.delivered_to);
        }
    }

    // Notify all instances (wake delivery loops)
    crate::notify::wake_all(db);

    // Trigger relay push so remote devices see the message immediately
    crate::relay::trigger_push();

    Ok(delivery)
}

/// The stored routing of a message: `delivered_to`, the mentions and
/// device-exact targets receivers deliver from, and the one-hop reroute marker.
fn set_routing_fields(data: &mut serde_json::Value, delivery: &ResolvedDelivery) {
    data["delivered_to"] = serde_json::json!(delivery.delivered_to);
    // Mentions scope resolved here carries the canonical names in
    // `exact_targets`, so a receiver on another host with a same-named
    // instance does not take it; broadcast omits the key. The thread-override
    // path omits it too: those members come from a stored membership list (a
    // thread seeded by a pre-fleet peer can hold base names), so they keep
    // legacy base matching.
    if !delivery.effective_mentions.is_empty() {
        data["mentions"] = serde_json::json!(delivery.effective_mentions);
    }
    if !delivery.is_thread_resolved
        && delivery.effective_scope == MessageScope::Mentions
        && !delivery.effective_mentions.is_empty()
    {
        data["exact_targets"] = serde_json::json!(delivery.effective_mentions);
    }
    // The one-hop marker: receivers admit a delegate named here without
    // evaluating the delegate's own policy. A holder kept because its
    // delegate is not live names itself, so its read admits it too.
    let delegate_copies: serde_json::Map<String, serde_json::Value> = delivery
        .reroutes
        .iter()
        .map(|(recipient, delegate)| (recipient.clone(), serde_json::json!(delegate)))
        .chain(
            delivery
                .kept_for_holder
                .iter()
                .map(|(recipient, _)| (recipient.clone(), serde_json::json!(recipient))),
        )
        .collect();
    if !delegate_copies.is_empty() {
        data[crate::delivery_policy::REROUTES_FIELD] = serde_json::Value::Object(delegate_copies);
    }
}

/// Inside the send's write transaction: every delegate a refused recipient
/// was rerouted to must still be a live row in `rows`. One that left is
/// resolved again (an exact live name first; a bare name live only as a
/// remote mirror maps to it); none live, the holder keeps the message and
/// the sender gets the warning.
fn recheck_reroutes(
    delivery: &mut ResolvedDelivery,
    rows: &[crate::messages::InstanceInfo],
    fleet: &crate::fleet_names::FleetCtx,
) {
    let live = |name: &str| rows.iter().any(|row| row.name == name);
    for (holder, delegate) in std::mem::take(&mut delivery.reroutes) {
        if live(&delegate) {
            delivery.reroutes.push((holder, delegate));
            continue;
        }
        let target = match crate::delivery_policy::resolve_delegate(&delegate, rows, fleet) {
            Ok(replacement) => {
                delivery.reroutes.push((holder, replacement.clone()));
                replacement
            }
            Err(why) => {
                let why = why.describe(&delegate);
                crate::log::log_warn(
                    "delivery_policy",
                    "delegate_unresolved",
                    &format!("delegate {why} at insert; delivered to {holder}"),
                );
                delivery.kept_for_holder.push((holder.clone(), why));
                holder
            }
        };
        // A delegate the sender also addressed by name keeps its own copy
        // (as a plain `@mupe` send would); only the reroute's copy moves.
        let addressed = delivery.addressed.contains(&delegate);
        for names in [&mut delivery.effective_mentions, &mut delivery.delivered_to] {
            if !addressed {
                names.retain(|name| name != &delegate);
            }
            if !names.contains(&target) {
                names.push(target.clone());
            }
        }
    }
}

/// Resolve reply_to to local event ID. Returns None if not found.
fn resolve_reply_to_local(db: &HcomDb, reply_to: &str) -> Option<i64> {
    // reply_to can be "42" or "42:BOXE" (remote)
    let local_part = reply_to.split(':').next()?;
    let id: i64 = local_part.parse().ok()?;

    // Verify event exists and is a message
    let exists: bool = db
        .conn()
        .query_row(
            "SELECT 1 FROM events WHERE id = ? AND type = 'message'",
            rusqlite::params![id],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if exists { Some(id) } else { None }
}

/// Get thread from an event (for --reply-to thread inheritance).
fn get_thread_from_event(db: &HcomDb, event_id: i64) -> Option<String> {
    db.conn()
        .query_row(
            "SELECT json_extract(data, '$.thread') FROM events WHERE id = ?",
            rusqlite::params![event_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
}

/// Get intent from an event (for ack-on-ack prevention).
fn get_intent_from_event(db: &HcomDb, event_id: i64) -> Option<String> {
    db.conn()
        .query_row(
            "SELECT json_extract(data, '$.intent') FROM events WHERE id = ?",
            rusqlite::params![event_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
}

/// Resolve message from one of 5 source modes.
/// Returns `(message_text, stripped_name_flag)` where `stripped_name_flag` is true
/// if a trailing `--name <agent>` token was silently stripped from the message.
fn resolve_message(
    args: &SendArgs,
    auto_sender_name: Option<&str>,
) -> Result<(String, bool), String> {
    let has_separator = args.has_separator();

    // Mutual exclusivity
    let source_count = [
        args.stdin,
        args.file.is_some(),
        args.base64.is_some(),
        has_separator,
    ]
    .iter()
    .filter(|&&x| x)
    .count();
    if source_count > 1 {
        return Err("Only one of --, --stdin, --file, --base64 can be used".to_string());
    }

    // 1. -- separator
    if has_separator {
        let stripped = auto_sender_name.is_some_and(|name| {
            args.message.len() >= 2
                && args.message[args.message.len() - 2] == "--name"
                && args.message.last().is_some_and(|value| value == name)
        });
        let message_tokens = if stripped {
            &args.message[..args.message.len() - 2]
        } else {
            &args.message
        };
        let text = message_tokens.join(" ");
        if text.is_empty() {
            return Err("No message after --".to_string());
        }
        return Ok((text, stripped));
    }

    // 2. --stdin
    if args.stdin {
        return read_stdin().map(|s| (s, false));
    }

    // 3. --file
    if let Some(ref path) = args.file {
        let resolved = if std::path::Path::new(path).is_absolute() {
            std::path::PathBuf::from(path)
        } else {
            std::env::current_dir().unwrap_or_default().join(path)
        };
        return match std::fs::read_to_string(&resolved) {
            Ok(content) if !content.is_empty() => Ok((content, false)),
            Ok(_) => Err(format!("File is empty: {path}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(format!("File not found: {path}"))
            }
            Err(e) => Err(format!("Cannot read file: {e}")),
        };
    }

    // 4. --base64
    if let Some(ref b64) = args.base64 {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| "Invalid base64 encoding".to_string())?;
        let s =
            String::from_utf8(bytes).map_err(|_| "Base64 decoded to invalid UTF-8".to_string())?;
        if s.is_empty() {
            return Err("Base64 decoded to empty string".to_string());
        }
        return Ok((s, false));
    }

    // 5. Auto-pipe (stdin is a pipe, no explicit source)
    if !std::io::stdin().is_terminal() {
        return read_stdin().map(|s| (s, false));
    }

    // No message source found
    let targets_str = if args.positionals.is_empty() {
        "target".to_string()
    } else {
        args.positionals
            .iter()
            .take(3)
            .map(|t| t.strip_prefix('@').unwrap_or(t))
            .collect::<Vec<_>>()
            .join(" ")
    };
    Err(format!(
        "No message provided.\nUse: hcom send {targets_str} -- your message\n Or: echo 'msg' | hcom send {targets_str}"
    ))
}

/// Read message from stdin pipe.
fn read_stdin() -> Result<String, String> {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_ok() && !buf.is_empty() {
        Ok(buf)
    } else {
        Err("No input received on stdin".to_string())
    }
}

/// Process positional args without `--` separator.
/// Matches Python messaging.py behavior:
///   - Empty → ([], None)
///   - Single arg with `@` prefix and space → backward compat: entire text is message
///   - Mix of @targets and bare text → separate targets from message
///   - Pure @targets → targets only, no message
fn process_positionals(positionals: &[String]) -> (Vec<String>, Option<String>) {
    if positionals.is_empty() {
        return (vec![], None);
    }

    // Backward compat: single arg starting with @ and containing space
    // e.g. "@luna hi" → whole thing is message (compute_scope extracts @mentions)
    if positionals.len() == 1 && positionals[0].starts_with('@') && positionals[0].contains(' ') {
        return (vec![], Some(positionals[0].clone()));
    }

    // Separate @targets from bare text
    let mut targets = Vec::new();
    let mut remaining = Vec::new();

    for arg in positionals {
        if let Some(name) = arg.strip_prefix('@') {
            targets.push(name.to_string());
        } else {
            remaining.push(arg.clone());
        }
    }

    if remaining.len() > 1 {
        // Multiple non-@ args without -- separator → error
        // Return empty message to trigger "no message" error with helpful hint
        return (targets, None);
    }

    if remaining.len() == 1 {
        return (targets, Some(remaining[0].clone()));
    }

    (targets, None)
}

/// Main entry point for `hcom send` command.
///
/// Returns exit code (0 = success, 1 = error).
pub fn cmd_send(db: &HcomDb, args: &SendArgs, ctx: Option<&CommandContext>) -> i32 {
    // ── Resolve --from name ──
    let from_name = args.sender_name();

    if let Some(ref name) = from_name {
        if name.is_empty() || name.len() > 50 {
            eprintln!("Error: Name too long ({} chars, max 50)", name.len());
            return 1;
        }
        if name.contains([
            '@', '|', '&', ';', '<', '>', '`', '$', '\'', '"', '\\', '\n', '\r',
        ]) {
            eprintln!("Error: Name contains invalid characters");
            return 1;
        }
    }

    // Guard: subagents cannot use --from/-b
    if from_name.is_some() {
        let actor_from_ctx = ctx.and_then(|c| c.identity.clone());
        let actor = actor_from_ctx
            .or_else(|| identity::resolve_identity(db, None, None, None, None, None, None).ok());
        match actor {
            Some(ref actor) if matches!(actor.kind, SenderKind::Instance) => {
                if let Some(ref data) = actor.instance_data
                    && data
                        .get("parent_name")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
                {
                    eprintln!("Error: Subagents cannot use --from/-b (external sender spoofing)");
                    return 1;
                }
            }
            _ => {}
        }
    }

    let explicit_name = ctx.and_then(|c| c.explicit_name.as_deref());

    // ── Validate envelope flags ──
    let mut envelope = MessageEnvelope::default();

    if let Some(ref val) = args.intent {
        let val = val.to_lowercase();
        if let Err(e) = validate_intent(&val) {
            eprintln!("Error: {e}");
            return 1;
        }
        envelope.intent = val.parse().ok();
    }

    envelope.reply_to = args.reply_to.clone();

    if let Some(ref val) = args.thread {
        if val.len() > 64 {
            eprintln!("Error: Thread name too long ({} chars, max 64)", val.len());
            return 1;
        }
        if !val
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            eprintln!("Error: Thread name must be alphanumeric with hyphens/underscores");
            return 1;
        }
        envelope.thread = Some(val.clone());
    }

    // Ack requires reply_to
    if envelope.intent.as_ref().map(|i| i.as_str()) == Some("ack") && envelope.reply_to.is_none() {
        eprintln!("Error: Intent 'ack' requires --reply-to <id>");
        eprintln!("<id> is the number in received messages like [request #id]");
        return 1;
    }

    if let Some(ref reply_to) = envelope.reply_to {
        if let Some(local_id) = resolve_reply_to_local(db, reply_to) {
            if envelope.thread.is_none()
                && let Some(parent_thread) = get_thread_from_event(db, local_id)
            {
                envelope.thread = Some(parent_thread);
            }
        } else {
            eprintln!("Error: Invalid --reply-to: event not found or not a message");
            return 1;
        }
    }

    // ── Inline bundle ──
    let bundle_data = match args.build_bundle_data() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    // ── Process positional args: separate targets from bare message text ──
    // Two grammars, keyed on how the message arrives:
    //   - Separated with `--` (or --stdin/--file/--base64): every positional
    //     is a target and the `@` is optional. Nothing else could be the
    //     message, so there is nothing to disambiguate — and PowerShell
    //     swallows a bare `@name` before hcom ever sees it, which turns
    //     `hcom send @michael -- text` into a broadcast.
    //   - Otherwise the pre-`--` compatibility form is unchanged: `@x` args
    //     are targets, one bare arg is the message text, and a lone
    //     `@name message` arg is the whole text with mentions parsed from it.
    let (effective_targets, compat_message) =
        if !args.has_separator() && !args.stdin && args.file.is_none() && args.base64.is_none() {
            process_positionals(&args.positionals)
        } else {
            let mut validated = Vec::with_capacity(args.positionals.len());
            for arg in &args.positionals {
                let target = arg.strip_prefix('@').unwrap_or(arg);
                if target.is_empty() {
                    eprintln!("Error: Empty target '@' is not allowed");
                    return 1;
                }
                validated.push(target.to_string());
            }
            (validated, None)
        };

    // ── Resolve message ──
    let (mut message, name_was_stripped) = if let Some(msg) = compat_message {
        (msg, false)
    } else {
        let auto_sender_name = if from_name.is_none() && explicit_name.is_none() {
            ctx.and_then(|c| c.identity.as_ref())
                .filter(|id| matches!(id.kind, SenderKind::Instance))
                .map(|id| id.name.as_str())
        } else {
            None
        };
        match resolve_message(args, auto_sender_name) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        }
    };

    if let Err(err) = validate_message(&message) {
        eprintln!("Error: {err}");
        return 1;
    }

    // ── Resolve sender identity ──
    let sender_identity = if let Some(ref name) = from_name {
        SenderIdentity {
            kind: SenderKind::External,
            name: name.clone(),
            instance_data: None,
            session_id: None,
        }
    } else if let Some(id) = ctx.and_then(|c| c.identity.as_ref()) {
        id.clone()
    } else if let Some(name) = explicit_name {
        match identity::resolve_identity(db, Some(name), None, None, None, None, None) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        }
    } else {
        match identity::resolve_identity(db, None, None, None, None, None, None) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        }
    };

    // Guard: Block sends from vanilla Claude before opt-in
    if matches!(sender_identity.kind, SenderKind::Instance)
        && sender_identity.instance_data.is_none()
        && std::env::var("CLAUDE_CODE_ENTRYPOINT").is_ok()
    {
        eprintln!("Error: Cannot send without identity.");
        eprintln!("Run 'hcom start' first, then use 'hcom send'.");
        return 1;
    }

    let targets_to_pass: Option<&[String]> =
        if args.has_separator() || !effective_targets.is_empty() {
            Some(&effective_targets)
        } else {
            None
        };

    let preview_has_envelope =
        envelope.intent.is_some() || envelope.reply_to.is_some() || envelope.thread.is_some();
    let preview_delivery = match resolve_delivery(
        db,
        &sender_identity,
        &message,
        if preview_has_envelope {
            Some(&envelope)
        } else {
            None
        },
        targets_to_pass,
    ) {
        Ok(delivery) => delivery,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    if is_inside_ai_tool()
        && !ctx.map(|c| c.go).unwrap_or(false)
        && preview_delivery.original_scope == MessageScope::Broadcast
        && !preview_delivery.is_thread_resolved
        && preview_delivery.delivered_to.len() > 3
    {
        print_broadcast_preview(db, &preview_delivery.delivered_to);
        return 1;
    }

    // ── Create bundle event if inline flags provided ──
    if let Some(mut bundle) = bundle_data {
        if let Err(e) = crate::core::bundles::validate_bundle(&mut bundle) {
            eprintln!("Error: {e}");
            return 1;
        }

        let bundle_instance = match sender_identity.kind {
            SenderKind::External => format!("ext_{}", sender_identity.name),
            SenderKind::System => format!("sys_{}", sender_identity.name),
            SenderKind::Instance => sender_identity.name.clone(),
        };

        match crate::core::bundles::create_bundle_event(
            &mut bundle,
            &bundle_instance,
            Some(&sender_identity.name),
            db,
        ) {
            Ok(bundle_id) => {
                crate::relay::worker::ensure_worker(true);
                envelope.bundle_id = Some(bundle_id.clone());

                // Append bundle summary text to message
                let refs = bundle.get("refs").cloned().unwrap_or(serde_json::json!({}));
                let events = refs
                    .get("events")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().or(v.as_i64().map(|_| "")).or(Some("")))
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let files = refs
                    .get("files")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let transcript = refs
                    .get("transcript")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| {
                                if let Some(obj) = v.as_object() {
                                    Some(format!(
                                        "{}:{}",
                                        obj.get("range").and_then(|r| r.as_str()).unwrap_or(""),
                                        obj.get("detail").and_then(|d| d.as_str()).unwrap_or("")
                                    ))
                                } else {
                                    v.as_str().map(|s| s.to_string())
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();

                let title = bundle.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let description = bundle
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let extends = bundle.get("extends").and_then(|v| v.as_str());

                let mut bundle_lines = vec![
                    format!("[Bundle {bundle_id}]"),
                    format!("Title: {title}"),
                    format!("Description: {description}"),
                    "Refs:".to_string(),
                    format!("  events: {events}"),
                    format!("  files: {files}"),
                    format!("  transcript: {transcript}"),
                ];
                if let Some(ext) = extends {
                    bundle_lines.push(format!("Extends: {ext}"));
                }
                bundle_lines.push(String::new());
                bundle_lines.push("View bundle:".to_string());
                bundle_lines.push(format!("  hcom bundle cat {bundle_id}"));

                message = format!("{}\n\n{}", message.trim_end(), bundle_lines.join("\n"));
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        }
    }

    // ── Send message ──
    let has_envelope = envelope.intent.is_some()
        || envelope.reply_to.is_some()
        || envelope.thread.is_some()
        || envelope.bundle_id.is_some();

    let delivery = match send_message_resolved(
        db,
        &sender_identity,
        &message,
        if has_envelope { Some(&envelope) } else { None },
        targets_to_pass,
    ) {
        Ok(delivery) => delivery,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    // ── Feedback ──
    if args.quiet {
        crate::relay::worker::ensure_worker(true);
        return 0;
    }

    let feedback = std::iter::once(get_recipient_feedback(db, &delivery.delivered_to))
        .chain(reroute_notices(&delivery))
        .collect::<Vec<_>>()
        .join("\n");

    // Show unread messages if instance context (full delivery with cursor advance)
    if matches!(sender_identity.kind, SenderKind::Instance) {
        let messages = db.get_unread_messages(&sender_identity.name);
        if !messages.is_empty() {
            // Advance cursor
            if let Some(last) = messages.last()
                && let Some(id) = last.event_id
            {
                let mut updates = serde_json::Map::new();
                updates.insert("last_event_id".into(), serde_json::json!(id));
                instances::update_instance_position(db, &sender_identity.name, &updates);
            }

            // Separate subagent messages from main messages
            let subagent_names: std::collections::HashSet<String> = db
                .conn()
                .prepare("SELECT name FROM instances WHERE parent_name = ?")
                .ok()
                .map(|mut stmt| {
                    stmt.query_map(rusqlite::params![&sender_identity.name], |row| row.get(0))
                        .ok()
                        .into_iter()
                        .flatten()
                        .filter_map(|r| r.ok())
                        .collect()
                })
                .unwrap_or_default();

            let mut main_msgs = Vec::new();
            let mut sub_msgs = Vec::new();
            for msg in &messages {
                if subagent_names.contains(&msg.from) {
                    sub_msgs.push(msg);
                } else {
                    main_msgs.push(msg);
                }
            }

            const MAX_MSGS: usize = 50;

            print!("{feedback}");
            if !main_msgs.is_empty() {
                let capped: Vec<&_> = main_msgs.iter().take(MAX_MSGS).copied().collect();
                let formatted = format_messages_for_hook(db, &capped, &sender_identity.name);
                println!("\n{formatted}");
            }
            if !sub_msgs.is_empty() {
                let capped: Vec<&_> = sub_msgs.iter().take(MAX_MSGS).copied().collect();
                let formatted = format_messages_for_hook(db, &capped, &sender_identity.name);
                println!("\n[Subagent messages]\n{formatted}");
            }
            if main_msgs.is_empty() && sub_msgs.is_empty() {
                println!();
            }
        } else {
            println!("{feedback}");
        }
    } else {
        println!("{feedback}");
    }

    // ── Trailing --name hint ──
    if name_was_stripped {
        let sender_name = &sender_identity.name;
        println!();
        println!(
            "[hcom] Note: '--name {sender_name}' was stripped from the end of your message body."
        );
        println!("  Correct syntax (--name goes BEFORE --):");
        println!("    hcom send --name {sender_name} target -- your message");
        println!("  To send '--name {sender_name}' as literal text, don't put it at the very end.");
    }

    // Adhoc unread delivery: for --name instances, show unread preview
    if explicit_name.is_some() && matches!(sender_identity.kind, SenderKind::Instance) {
        let messages = db.get_unread_messages(&sender_identity.name);
        if !messages.is_empty() {
            println!("\n{}", "─".repeat(40));
            println!("[hcom] new message(s)");
            println!("{}", "─".repeat(40));
            println!("\nRun: hcom listen --name {}", sender_identity.name);
        }
    }

    // Show intent tip
    if let Some(ref intent) = envelope.intent
        && matches!(sender_identity.kind, SenderKind::Instance)
    {
        let tip_key = format!("send:intent:{}", intent.as_str());
        crate::core::tips::maybe_show_tip(db, &sender_identity.name, &tip_key, false);
    }

    crate::relay::worker::ensure_worker(true);

    0
}

/// Format messages for hook display (no ANSI).
fn format_messages_for_hook(
    db: &HcomDb,
    messages: &[&crate::db::Message],
    instance_name: &str,
) -> String {
    let recipient_display = identity::get_display_name(db, instance_name);

    if messages.len() == 1 {
        let msg = messages[0];
        let sender_display = identity::get_display_name(db, &msg.from);
        let prefix =
            cli_context_build_prefix(msg.intent.as_deref(), msg.thread.as_deref(), msg.event_id);
        format!(
            "{prefix} {sender_display} → {recipient_display}: {}",
            msg.text
        )
    } else {
        let parts: Vec<String> = messages
            .iter()
            .map(|msg| {
                let sender_display = identity::get_display_name(db, &msg.from);
                let prefix = cli_context_build_prefix(
                    msg.intent.as_deref(),
                    msg.thread.as_deref(),
                    msg.event_id,
                );
                format!(
                    "{prefix} {sender_display} → {recipient_display}: {}",
                    msg.text
                )
            })
            .collect();
        format!("[{} new messages] | {}", parts.len(), parts.join(" | "))
    }
}

fn cli_context_build_prefix(
    intent: Option<&str>,
    thread: Option<&str>,
    event_id: Option<i64>,
) -> String {
    let id_ref = event_id.map(|id| format!("#{id}")).unwrap_or_default();
    let prefix = match (intent, thread) {
        (Some(i), Some(t)) => format!("{i}:{t}"),
        (Some(i), None) => i.to_string(),
        (None, Some(t)) => format!("thread:{t}"),
        (None, None) => "new message".to_string(),
    };
    if id_ref.is_empty() {
        format!("[{prefix}]")
    } else {
        format!("[{prefix} {id_ref}]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serial_test::serial;
    use std::path::PathBuf;

    type TestEnv = (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        crate::hooks::test_helpers::EnvGuard,
    );

    #[test]
    fn parse_basic_send() {
        let args = SendArgs::try_parse_from(["send", "@luna", "--", "hello", "there"]).unwrap();
        assert_eq!(args.positionals, vec!["@luna"]);
        assert_eq!(args.message, vec!["hello", "there"]);
    }

    #[test]
    fn parse_multiple_targets() {
        let args = SendArgs::try_parse_from(["send", "@luna", "@nova", "--", "hello"]).unwrap();
        assert_eq!(args.positionals, vec!["@luna", "@nova"]);
        assert_eq!(args.message, vec!["hello"]);
    }

    #[test]
    fn parse_broadcast() {
        let args = SendArgs::try_parse_from(["send", "--", "broadcast", "msg"]).unwrap();
        assert!(args.positionals.is_empty());
        assert_eq!(args.message, vec!["broadcast", "msg"]);
    }

    #[test]
    fn parse_with_intent_flag() {
        let args =
            SendArgs::try_parse_from(["send", "--intent", "request", "@luna", "--", "hello"])
                .unwrap();
        assert_eq!(args.intent.as_deref(), Some("request"));
        assert_eq!(args.positionals, vec!["@luna"]);
    }

    #[test]
    fn parse_flags_after_targets() {
        let args =
            SendArgs::try_parse_from(["send", "@luna", "--intent", "request", "--", "hello"])
                .unwrap();
        assert_eq!(args.intent.as_deref(), Some("request"));
        assert_eq!(args.positionals, vec!["@luna"]);
    }

    #[test]
    fn parse_bigboss_flag() {
        let args = SendArgs::try_parse_from(["send", "-b", "--", "hello"]).unwrap();
        assert!(args.bigboss);
        assert_eq!(args.sender_name(), Some("bigboss".to_string()));
    }

    #[test]
    fn parse_from_overrides_bigboss() {
        let args =
            SendArgs::try_parse_from(["send", "-b", "--from", "reviewer", "--", "hello"]).unwrap();
        assert_eq!(args.sender_name(), Some("reviewer".to_string()));
    }

    #[test]
    fn parse_stdin_flag() {
        let args = SendArgs::try_parse_from(["send", "--stdin", "@luna"]).unwrap();
        assert!(args.stdin);
        assert_eq!(args.positionals, vec!["@luna"]);
        assert!(args.message.is_empty());
    }

    #[test]
    fn parse_file_flag() {
        let args = SendArgs::try_parse_from(["send", "--file", "/tmp/msg.txt", "@luna"]).unwrap();
        assert_eq!(args.file.as_deref(), Some("/tmp/msg.txt"));
        assert_eq!(args.positionals, vec!["@luna"]);
    }

    #[test]
    fn parse_base64_flag() {
        let args = SendArgs::try_parse_from(["send", "--base64", "aGVsbG8=", "@luna"]).unwrap();
        assert_eq!(args.base64.as_deref(), Some("aGVsbG8="));
    }

    #[test]
    fn parse_reply_to_and_thread() {
        let args = SendArgs::try_parse_from([
            "send",
            "--reply-to",
            "42",
            "--thread",
            "pr-99",
            "@luna",
            "--",
            "hi",
        ])
        .unwrap();
        assert_eq!(args.reply_to.as_deref(), Some("42"));
        assert_eq!(args.thread.as_deref(), Some("pr-99"));
    }

    #[test]
    fn parse_quiet_flag() {
        let args = SendArgs::try_parse_from(["send", "--quiet", "-b", "--", "hi"]).unwrap();
        assert!(args.quiet);
    }

    #[test]
    fn parse_inline_bundle_flags() {
        let args = SendArgs::try_parse_from([
            "send",
            "-b",
            "--title",
            "my-bundle",
            "--description",
            "desc",
            "--events",
            "1-10",
            "--files",
            "a.py",
            "--transcript",
            "1-5:normal",
            "--",
            "msg",
        ])
        .unwrap();
        assert_eq!(args.title.as_deref(), Some("my-bundle"));
        assert_eq!(args.description.as_deref(), Some("desc"));
        assert_eq!(args.events.as_deref(), Some("1-10"));
        assert_eq!(args.files.as_deref(), Some("a.py"));
        assert_eq!(args.transcript.as_deref(), Some("1-5:normal"));
    }

    #[test]
    fn parse_no_separator_targets_only() {
        let args = SendArgs::try_parse_from(["send", "@luna"]).unwrap();
        assert_eq!(args.positionals, vec!["@luna"]);
        assert!(args.message.is_empty());
    }

    #[test]
    fn parse_compat_at_name_with_space() {
        // Backward compat: '@luna hi' as a single quoted arg
        // process_positionals treats as full message text
        let args = SendArgs::try_parse_from(["send", "@luna hi"]).unwrap();
        assert_eq!(args.positionals, vec!["@luna hi"]);
    }

    #[test]
    fn parse_bare_text_accepted() {
        // Bare text without @ is accepted by clap; cmd_send handles as message
        let args = SendArgs::try_parse_from(["send", "hello everyone"]).unwrap();
        assert_eq!(args.positionals, vec!["hello everyone"]);
    }

    #[test]
    fn parse_empty_target_rejected() {
        let result = SendArgs::try_parse_from(["send", "@", "--", "hi"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_bare_text_with_separator_accepted() {
        // Bare text before -- is accepted by clap; validated in cmd_send
        let args = SendArgs::try_parse_from(["send", "luna", "--", "hi"]).unwrap();
        assert_eq!(args.positionals, vec!["luna"]);
        assert_eq!(args.message, vec!["hi"]);
    }

    #[test]
    fn parse_message_with_dashes() {
        let args =
            SendArgs::try_parse_from(["send", "@luna", "--", "--this", "is", "a", "message"])
                .unwrap();
        assert_eq!(args.message, vec!["--this", "is", "a", "message"]);
    }

    #[test]
    fn resolve_message_strips_redundant_trailing_auto_name_tokens() {
        let mut args =
            SendArgs::try_parse_from(["send", "@luna", "--", "message", "--name", "beru"]).unwrap();
        args.had_separator = true;

        assert_eq!(resolve_message(&args, Some("beru")).unwrap().0, "message");
    }

    #[test]
    fn resolve_message_keeps_quoted_name_suffix_inside_one_argument() {
        let mut args = SendArgs::try_parse_from([
            "send",
            "@luna",
            "--",
            "I always end commands with --name beru",
        ])
        .unwrap();
        args.had_separator = true;

        assert_eq!(
            resolve_message(&args, Some("beru")).unwrap().0,
            "I always end commands with --name beru"
        );
    }

    #[test]
    fn resolve_message_keeps_trailing_name_for_different_sender() {
        let mut args =
            SendArgs::try_parse_from(["send", "@luna", "--", "message", "--name", "nova"]).unwrap();
        args.had_separator = true;

        assert_eq!(
            resolve_message(&args, Some("beru")).unwrap().0,
            "message --name nova"
        );
    }

    #[test]
    fn parse_extends_flag() {
        let args = SendArgs::try_parse_from([
            "send",
            "-b",
            "--title",
            "t",
            "--extends",
            "abc123",
            "--",
            "msg",
        ])
        .unwrap();
        assert_eq!(args.extends.as_deref(), Some("abc123"));
    }

    // ── process_positionals tests ──

    #[test]
    fn process_empty() {
        let (targets, msg) = process_positionals(&[]);
        assert!(targets.is_empty());
        assert!(msg.is_none());
    }

    fn setup_test_db() -> (HcomDb, PathBuf, TestEnv) {
        setup_test_db_with_config(None)
    }

    /// `config` becomes config.toml before the env points at it (see
    /// `isolated_test_env_with_config`).
    fn setup_test_db_with_config(config: Option<&str>) -> (HcomDb, PathBuf, TestEnv) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        // send_message() reaches the process-global relay notification path,
        // so its ambient HCOM_DIR must live as long as the test DB.
        let env = crate::hooks::test_helpers::isolated_test_env_with_config(config);
        let temp_dir = std::env::temp_dir();
        let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let db_path = temp_dir.join(format!(
            "test_hcom_send_{}_{}.db",
            std::process::id(),
            test_id
        ));

        let db = HcomDb::open_at(&db_path).unwrap();
        (db, db_path, env)
    }

    fn cleanup_test_db(path: PathBuf) {
        let _ = std::fs::remove_file(&path);
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));
        let _ = std::fs::remove_file(wal);
        let _ = std::fs::remove_file(shm);
    }

    // ── no-`@` targets (`hcom send luna -- hi`) ──

    /// Parse argv the way the router does, including the `had_separator` flag
    /// clap cannot see, and run the real `cmd_send`.
    fn send_argv(argv: &[&str]) -> SendArgs {
        let mut args = SendArgs::try_parse_from(argv).unwrap();
        args.had_separator = argv.contains(&"--");
        args
    }

    /// A live row named `luna` plus the test sender.
    fn luna_db() -> (HcomDb, PathBuf, TestEnv) {
        let (db, path, env) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, session_id, created_at) VALUES ('luna', 'sess-luna', 1000.0)",
                [],
            )
            .unwrap();
        (db, path, env)
    }

    /// The command context the router hands `cmd_send`: this seat as the
    /// sender identity, so a send resolves and persists instead of refusing
    /// for want of an identity.
    fn sender_ctx() -> CommandContext {
        CommandContext {
            explicit_name: None,
            identity: Some(sender(SenderKind::Instance, "sender")),
            go: false,
        }
    }

    fn delivered_to_luna(db: &HcomDb) -> Vec<String> {
        let (_, data) = last_message(db);
        data["delivered_to"]
            .as_array()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| n.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    #[serial]
    fn separator_makes_every_positional_a_target_without_an_at_sign() {
        // The PowerShell-safe form: no `@` to be swallowed, and `luna` lands
        // in exact_targets as an ordinary target.
        let (db, path, _env) = luna_db();
        let rc = cmd_send(
            &db,
            &send_argv(&["send", "luna", "--", "hi"]),
            Some(&sender_ctx()),
        );
        assert_eq!(rc, 0);
        let (_, data) = last_message(&db);
        assert_eq!(data["text"], "hi");
        assert_eq!(delivered_to_luna(&db), vec!["luna".to_string()]);
        assert_eq!(data["exact_targets"], serde_json::json!(["luna"]));
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn explicit_source_flag_makes_positionals_targets_without_an_at_sign() {
        // Same rule for `--stdin`: the message arrives from the pipe, so the
        // positionals can only be targets.
        let (db, path, _env) = luna_db();
        let msg_file = std::env::temp_dir().join(format!(
            "hcom_send_stdin_{}_{}.txt",
            std::process::id(),
            path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&msg_file, "hi from file").unwrap();

        let args = SendArgs::try_parse_from(["send", "--file", msg_file.to_str().unwrap(), "luna"])
            .unwrap();
        assert_eq!(args.positionals, vec!["luna"]);
        assert_eq!(cmd_send(&db, &args, Some(&sender_ctx())), 0);

        let (_, data) = last_message(&db);
        assert_eq!(data["text"], "hi from file");
        assert_eq!(delivered_to_luna(&db), vec!["luna".to_string()]);
        assert_eq!(data["exact_targets"], serde_json::json!(["luna"]));
        let _ = std::fs::remove_file(&msg_file);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn a_leading_at_sign_is_still_accepted_with_the_separator() {
        // Both spellings reach the same target, so existing invocations and
        // new no-`@` ones agree on the wire.
        let (db, path, _env) = luna_db();
        assert_eq!(
            cmd_send(
                &db,
                &send_argv(&["send", "@luna", "--", "hi"]),
                Some(&sender_ctx())
            ),
            0
        );
        let (_, data) = last_message(&db);
        assert_eq!(data["exact_targets"], serde_json::json!(["luna"]));
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn several_no_at_positionals_are_several_targets() {
        let (db, path, _env) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, session_id, created_at) VALUES ('luna', 'sess-luna', 1000.0), ('nova', 'sess-nova', 1000.0)",
                [],
            )
            .unwrap();
        assert_eq!(
            cmd_send(
                &db,
                &send_argv(&["send", "luna", "nova", "--", "hi"]),
                Some(&sender_ctx())
            ),
            0
        );
        let (_, data) = last_message(&db);
        let mut targets = data["exact_targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        targets.sort();
        assert_eq!(targets, vec!["luna".to_string(), "nova".to_string()]);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn without_the_separator_a_bare_positional_is_still_the_message() {
        // Compatibility unchanged: `hcom send luna` sends "luna" to everyone,
        // it does not address the agent named luna.
        let (db, path, _env) = luna_db();
        let args = SendArgs::try_parse_from(["send", "luna"]).unwrap();
        assert!(!args.had_separator);
        assert_eq!(cmd_send(&db, &args, Some(&sender_ctx())), 0);
        let (_, data) = last_message(&db);
        assert_eq!(data["text"], "luna");
        assert_eq!(data["scope"], serde_json::json!("broadcast"));
        assert!(data.get("exact_targets").is_none());
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn without_the_separator_an_at_name_still_addresses_the_agent() {
        // The other half of the compatibility contract: with no `--`, `@luna`
        // is a target and the message still has to come from stdin.
        let (db, path, _env) = luna_db();
        let args = SendArgs::try_parse_from(["send", "@luna"]).unwrap();
        assert!(!args.had_separator);
        // No message source and stdin is a terminal-less test process: the
        // resolution refuses rather than silently broadcasting.
        assert_eq!(cmd_send(&db, &args, Some(&sender_ctx())), 1);
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'message'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "nothing may be persisted for a refused send");
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn a_lone_at_sign_is_still_rejected_as_a_target() {
        // `send @ -- hi` reaches clap's parser and never cmd_send; the empty
        // target is refused there. Same for a stripped-to-nothing positional.
        assert!(SendArgs::try_parse_from(["send", "@", "--", "hi"]).is_err());
        let args = send_argv(&["send", "@luna", "--", "hi"]);
        assert_eq!(args.positionals, vec!["@luna"]);
    }

    #[test]
    fn no_at_form_is_documented_as_the_primary_send_form() {
        // The help is what an agent reads first: it has to show the no-`@`
        // form, not just the `@` form.
        assert!(SEND_AFTER_HELP.contains("hcom send luna -- Hello there!"));
        assert!(
            crate::commands::help::get_command_help("send").contains("send name -- message text")
        );
    }

    #[test]
    #[serial]
    fn send_message_threads_seed_and_reuse_memberships() {
        let (db, path, _env) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, created_at) VALUES ('luna', 1000.0), ('nova', 1000.0), ('miso', 1000.0)",
                [],
            )
            .unwrap();

        let sender = SenderIdentity {
            kind: SenderKind::Instance,
            name: "luna".into(),
            instance_data: None,
            session_id: None,
        };
        let envelope = MessageEnvelope {
            thread: Some("debate-1".into()),
            ..Default::default()
        };

        let delivered = send_message(
            &db,
            &sender,
            "hello",
            Some(&envelope),
            Some(&["nova".to_string(), "miso".to_string()]),
        )
        .unwrap();
        assert_eq!(delivered, vec!["nova".to_string(), "miso".to_string()]);

        let members = db.get_thread_members("debate-1");
        assert_eq!(
            members,
            vec!["nova".to_string(), "miso".to_string(), "luna".to_string()]
        );

        let delivered = send_message(&db, &sender, "round 2", Some(&envelope), None).unwrap();
        assert_eq!(delivered, vec!["nova".to_string(), "miso".to_string()]);

        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn send_message_thread_without_members_errors() {
        let (db, path, _env) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, created_at) VALUES ('luna', 1000.0)",
                [],
            )
            .unwrap();

        let sender = SenderIdentity {
            kind: SenderKind::Instance,
            name: "luna".into(),
            instance_data: None,
            session_id: None,
        };
        let envelope = MessageEnvelope {
            thread: Some("empty-thread".into()),
            ..Default::default()
        };

        let err = send_message(&db, &sender, "hello", Some(&envelope), None).unwrap_err();
        assert!(err.contains("has no members"));

        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn send_message_external_sender_does_not_auto_subscribe_to_thread() {
        let (db, path, _env) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, created_at) VALUES ('nova', 1000.0)",
                [],
            )
            .unwrap();

        let sender = SenderIdentity {
            kind: SenderKind::External,
            name: "bigboss".into(),
            instance_data: None,
            session_id: None,
        };
        let envelope = MessageEnvelope {
            thread: Some("ops".into()),
            ..Default::default()
        };

        let delivered = send_message(
            &db,
            &sender,
            "hello",
            Some(&envelope),
            Some(&["nova".to_string()]),
        )
        .unwrap();
        assert_eq!(delivered, vec!["nova".to_string()]);
        assert_eq!(db.get_thread_members("ops"), vec!["nova".to_string()]);

        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn send_message_thread_request_does_not_create_request_watch_rows() {
        let (db, path, _env) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, created_at) VALUES ('luna', 1000.0), ('nova', 1000.0)",
                [],
            )
            .unwrap();

        let sender = SenderIdentity {
            kind: SenderKind::Instance,
            name: "luna".into(),
            instance_data: None,
            session_id: None,
        };
        let seed_envelope = MessageEnvelope {
            thread: Some("ops".into()),
            ..Default::default()
        };
        send_message(
            &db,
            &sender,
            "seed",
            Some(&seed_envelope),
            Some(&["nova".to_string()]),
        )
        .unwrap();

        let request_envelope = MessageEnvelope {
            intent: Some(crate::messages::MessageIntent::Request),
            thread: Some("ops".into()),
            ..Default::default()
        };
        let delivered =
            send_message(&db, &sender, "status?", Some(&request_envelope), None).unwrap();
        assert_eq!(delivered, vec!["nova".to_string()]);

        let reqwatch_count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM kv WHERE key LIKE 'events_sub:reqwatch-%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reqwatch_count, 0);

        let (scope, mentions_json): (String, String) = db
            .conn()
            .query_row(
                "SELECT json_extract(data, '$.scope'), json_extract(data, '$.mentions')
                 FROM events
                 WHERE type = 'message'
                 ORDER BY id DESC
                 LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(scope, "mentions");
        assert!(mentions_json.contains("nova"));

        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn send_mention_excludes_inactive_instances() {
        let (db, path, _env) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, status_context, created_at)
                 VALUES ('luna', 'listening', '', 1000.0),
                        ('vine', 'inactive', 'exit:unknown', 1000.0)",
                [],
            )
            .unwrap();

        let sender = SenderIdentity {
            kind: SenderKind::Instance,
            name: "luna".into(),
            instance_data: None,
            session_id: None,
        };

        let err =
            send_message(&db, &sender, "ping", None, Some(&["vine".to_string()])).unwrap_err();
        assert!(err.contains("@vine"), "err={err}");
        assert!(err.contains("Available:"), "err={err}");
        assert!(
            err.contains("luna"),
            "listening agent should be listed: {err}"
        );
        let available_line = err.lines().find(|l| l.contains("Available:")).unwrap_or("");
        assert!(
            !available_line.contains("vine"),
            "inactive agent must not appear in Available: {err}"
        );

        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn send_mention_excludes_exit_no_tool_call_inactive() {
        let (db, path, _env) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, status_context, created_at)
                 VALUES ('luna', 'listening', '', 1000.0),
                        ('dove', 'inactive', 'exit:no_tool_call', 1000.0)",
                [],
            )
            .unwrap();

        let sender = SenderIdentity {
            kind: SenderKind::Instance,
            name: "luna".into(),
            instance_data: None,
            session_id: None,
        };

        let err =
            send_message(&db, &sender, "ping", None, Some(&["dove".to_string()])).unwrap_err();
        assert!(err.contains("@dove"), "err={err}");
        let available_line = err.lines().find(|l| l.contains("Available:")).unwrap_or("");
        assert!(
            !available_line.contains("dove"),
            "soft-stopped agent must not appear in Available: {err}"
        );

        cleanup_test_db(path);
    }

    /// Hold a write lock on the test DB from a second connection, mimicking
    /// a concurrent hook/relay writer mid-transaction.
    fn hold_write_lock(db_path: &PathBuf) -> rusqlite::Connection {
        let guard = rusqlite::Connection::open(db_path).unwrap();
        guard
            .execute_batch("PRAGMA busy_timeout=0; BEGIN IMMEDIATE;")
            .unwrap();
        guard
    }

    #[test]
    #[serial]
    fn send_message_under_held_lock_fails_unmistakably() {
        let (db, path, _env) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, created_at) VALUES ('luna', 1000.0), ('nova', 1000.0)",
                [],
            )
            .unwrap();
        let _guard = hold_write_lock(&path);
        // Fail fast at the sqlite layer: the (short) test budget bounds the
        // retry loop, not the 5s production busy_timeout.
        db.conn().execute_batch("PRAGMA busy_timeout=0;").unwrap();

        let sender = SenderIdentity {
            kind: SenderKind::External,
            name: "bigboss".into(),
            instance_data: None,
            session_id: None,
        };
        let err =
            send_message(&db, &sender, "hello", None, Some(&["nova".to_string()])).unwrap_err();
        assert!(
            err.contains("Failed to write message to database"),
            "err={err}"
        );
        assert!(
            err.contains("retried"),
            "busy exhaustion must say retried: {err}"
        );
        assert!(err.contains("NOT sent"), "err={err}");

        // Exhaustion means nothing was written: no partial row.
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'message'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);

        cleanup_test_db(path);
    }

    /// Success-after-contention (F7): a second connection holds BEGIN
    /// IMMEDIATE for ~250ms while `send_message` runs with busy_timeout=0.
    /// The retry loop must ride out the contention and write exactly one row.
    /// Fails on trees without the retry (the send errors on first BUSY).
    #[test]
    #[serial]
    fn send_message_succeeds_after_transient_contention() {
        let (db, path, _env) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, created_at) VALUES ('luna', 1000.0), ('nova', 1000.0)",
                [],
            )
            .unwrap();
        // Fail fast at the sqlite layer so each attempt surfaces SQLITE_BUSY
        // at once; the (short) test budget bounds the retry loop.
        db.conn().execute_batch("PRAGMA busy_timeout=0;").unwrap();

        // A concurrent writer holds the lock briefly, then commits. The
        // channel proves the lock is held before the send starts, so the
        // send cannot slip in first and the holder cannot fail its BEGIN.
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn({
            let path = path.clone();
            move || {
                let guard = rusqlite::Connection::open(&path).unwrap();
                guard
                    .execute_batch("PRAGMA busy_timeout=0; BEGIN IMMEDIATE;")
                    .unwrap();
                held_tx.send(()).ok();
                std::thread::sleep(std::time::Duration::from_millis(250));
                guard.execute_batch("COMMIT;").unwrap();
            }
        });
        held_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("holder took the write lock");

        let sender = SenderIdentity {
            kind: SenderKind::External,
            name: "bigboss".into(),
            instance_data: None,
            session_id: None,
        };
        let delivered =
            send_message(&db, &sender, "hello", None, Some(&["nova".to_string()])).unwrap();
        holder.join().expect("holder committed");
        assert!(
            delivered.contains(&"nova".to_string()),
            "delivered={delivered:?}"
        );

        // Exactly one row: the attempts that hit the lock wrote nothing.
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'message'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        cleanup_test_db(path);
    }

    #[test]
    fn process_compat_at_with_space() {
        // "@luna hi" → full text as message, no targets
        let (targets, msg) = process_positionals(&["@luna hi".to_string()]);
        assert!(targets.is_empty());
        assert_eq!(msg.as_deref(), Some("@luna hi"));
    }

    #[test]
    fn process_bare_text() {
        // "hello everyone" → message text, no targets (broadcast)
        let (targets, msg) = process_positionals(&["hello everyone".to_string()]);
        assert!(targets.is_empty());
        assert_eq!(msg.as_deref(), Some("hello everyone"));
    }

    #[test]
    fn process_pure_targets() {
        // "@luna" → target, no message
        let (targets, msg) = process_positionals(&["@luna".to_string()]);
        assert_eq!(targets, vec!["luna"]);
        assert!(msg.is_none());
    }

    #[test]
    fn process_target_plus_bare_text() {
        // "@luna", "hello" → target + message
        let (targets, msg) = process_positionals(&["@luna".to_string(), "hello".to_string()]);
        assert_eq!(targets, vec!["luna"]);
        assert_eq!(msg.as_deref(), Some("hello"));
    }

    // ── Delivery policy ([delivery.conductor] held by kimi, crate::delivery_policy) ──

    const KIMI_POLICY: &str =
        "[delivery.conductor]\ndelegate = \"mupe\"\nleads = [\"poli\", \"valo\"]\n";

    /// Five live rows (session `sess-<name>`) and `config` as config.toml.
    fn rows_db(config: &str) -> (HcomDb, PathBuf, TestEnv) {
        let (db, path, env) = setup_test_db_with_config(Some(config));
        db.conn()
            .execute(
                "INSERT INTO instances (name, session_id, created_at) VALUES
                 ('kimi', 'sess-kimi', 1000.0), ('mupe', 'sess-mupe', 1000.0),
                 ('valo', 'sess-valo', 1000.0), ('nova', 'sess-nova', 1000.0),
                 ('lola', 'sess-lola', 1000.0)",
                [],
            )
            .unwrap();
        (db, path, env)
    }

    /// `rows_db` with kimi registered as `conductor`, the way the plugin's
    /// `hcom omp-role` does it.
    fn policy_db(config: &str) -> (HcomDb, PathBuf, TestEnv) {
        let (db, path, env) = rows_db(config);
        crate::delivery_policy::register_role(&db, "kimi", "sess-kimi", "conductor").unwrap();
        (db, path, env)
    }

    fn log_text(env: &TestEnv) -> String {
        std::fs::read_to_string(env.1.join(".tmp/logs/hcom.log")).unwrap_or_default()
    }

    #[test]
    #[serial]
    fn unreadable_role_holders_fail_closed_not_open() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        send(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "before",
            None,
            None,
            &[],
        );
        // The registrations live in kv; make every read of it fail at step
        // time (abs() of i64::MIN raises "integer overflow").
        db.conn()
            .execute_batch(
                "ALTER TABLE kv RENAME TO kv_gone;
                 CREATE VIEW kv AS SELECT key, value FROM kv_gone
                 WHERE abs(-9223372036854775807 - 1) > 0;",
            )
            .unwrap();
        assert!(
            db.conn()
                .query_row("SELECT count(*) FROM kv", [], |r| r.get::<_, i64>(0))
                .is_err()
        );

        // Readers deliver nothing (the broadcast stays unread for later)
        // instead of treating kimi as unfiltered; a send refuses.
        assert!(unread_texts(&db, "kimi").is_empty());
        assert!(!db.has_pending("kimi"));
        let err = send_message(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "hi",
            None,
            Some(&["kimi".to_string()]),
        )
        .unwrap_err();
        assert!(err.contains("cannot read role holders"), "{err}");
        assert!(
            crate::delivery_policy::role_status_lines(&db)[0]
                .starts_with("delivery roles: unknown"),
        );
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn unparseable_config_keeps_every_registered_role_filtered_and_invalid() {
        // kimi registered while the policy was readable; then the file breaks
        // in a way that no longer names the role at all.
        let (db, path, env) = policy_db(KIMI_POLICY);
        std::fs::write(
            env.1.join("config.toml"),
            "[terminal\nactive = \"default\"\n",
        )
        .unwrap();
        assert_eq!(
            crate::delivery_policy::role_status_lines(&db),
            vec![
                "conductor role: kimi".to_string(),
                "delivery policy INVALID: [delivery.conductor] config.toml does not parse \
                 (no delegate: the holder receives everything targeted)"
                    .to_string(),
            ]
        );
        // No delegate to send it to: kimi is told once, then gets targeted
        // mail, not broadcasts.
        let nova = sender(SenderKind::Instance, "nova");
        let d = send(&db, &nova, "still reaches kimi", None, None, &["kimi"]);
        assert!(d.reroutes.is_empty());
        send(&db, &nova, "broadcast", None, None, &[]);
        let texts = unread_texts(&db, "kimi");
        assert_eq!(texts.len(), 2, "{texts:?}");
        assert!(
            texts[0].contains(
                "delivery policy INVALID for role conductor (config.toml does not parse)"
            ),
            "{texts:?}"
        );
        assert_eq!(texts[1], "still reaches kimi");
        cleanup_test_db(path);
    }

    // ── Backstop forward (zori #238929: nothing to the conductor is dropped) ──

    /// A targeted inform to kimi as a 0.7.48 peer on LOTS writes it: no
    /// send-side reroute, namespaced sender, relay origin 77.
    fn old_peer_inform(text: &str, relay_id: i64) -> serde_json::Value {
        serde_json::json!({
            "from": "nova:LOTS",
            "sender_kind": "instance",
            "scope": "mentions",
            "mentions": ["kimi"],
            "delivered_to": ["kimi"],
            "intent": "inform",
            "text": text,
            "_relay": {"device": "dev-lots", "short": "LOTS", "id": relay_id},
        })
    }

    /// The sender's own timestamp an imported old-peer row keeps (relay
    /// import stores the remote `ts`), so a re-import is the same message.
    const SENT_AT: &str = "2026-09-30T12:00:00.000000+00:00";

    fn inject(db: &HcomDb, data: &serde_json::Value) -> i64 {
        db.log_event_with_ts("message", "nova:LOTS", data, Some(SENT_AT))
            .unwrap()
    }

    /// A stored event for a direct `forward_refused` call.
    fn refused(id: i64, data: &serde_json::Value) -> crate::db::RefusedEvent<'_> {
        crate::db::RefusedEvent {
            id,
            timestamp: SENT_AT,
            data,
        }
    }

    fn forward_rows(db: &HcomDb) -> Vec<(String, serde_json::Value)> {
        db.conn()
            .prepare(
                "SELECT instance, data FROM events
                 WHERE json_extract(data, '$.delivery_forward_of') IS NOT NULL ORDER BY id",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .map(|r| {
                let (instance, data) = r.unwrap();
                (instance, serde_json::from_str(&data).unwrap())
            })
            .collect()
    }

    fn forward_count(db: &HcomDb) -> usize {
        forward_rows(db).len()
    }

    fn notice_rows(db: &HcomDb) -> Vec<(String, serde_json::Value)> {
        db.conn()
            .prepare(
                "SELECT instance, data FROM events
                 WHERE json_extract(data, '$.delivery_notice_for') IS NOT NULL ORDER BY id",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .map(|r| {
                let (instance, data) = r.unwrap();
                (instance, serde_json::from_str(&data).unwrap())
            })
            .collect()
    }

    fn notice_count(db: &HcomDb) -> usize {
        notice_rows(db).len()
    }

    fn cursor(db: &HcomDb, name: &str) -> i64 {
        db.get_cursor(name)
    }

    #[test]
    #[serial]
    fn backstop_forwards_relayed_old_format_inform_once_with_sender_notice() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let id = inject(&db, &old_peer_inform("old peer hi", 77));

        // The holder's read returns nothing, moves its cursor past the event,
        // and a second read adds nothing.
        assert!(unread_texts(&db, "kimi").is_empty());
        assert_eq!(cursor(&db, "kimi"), id);
        assert!(unread_texts(&db, "kimi").is_empty());

        let forwards = forward_rows(&db);
        assert_eq!(forwards.len(), 1, "{forwards:?}");
        let (instance, copy) = &forwards[0];
        assert!(
            !instance.contains(':'),
            "relayable instance column: {instance}"
        );
        assert_eq!(copy["from"], "[hcom-delivery]");
        assert_eq!(copy["delivery_forward_of"], id);
        assert_eq!(copy["delivery_forward_of_from"], "nova:LOTS");
        assert_eq!(
            copy["delivery_forward_of_origin"],
            format!("dev-lots:77:{SENT_AT}")
        );
        assert_eq!(copy["intent"], "inform");
        assert_eq!(copy["mentions"], serde_json::json!(["mupe"]));
        assert_eq!(
            unread_texts(&db, "mupe"),
            vec!["[nova:LOTS → kimi, forwarded] old peer hi".to_string()]
        );

        // The sender on LOTS learns where it went; the row relays out.
        let notices = notice_rows(&db);
        assert_eq!(notices.len(), 1, "{notices:?}");
        let (instance, notice) = &notices[0];
        assert!(
            !instance.contains(':'),
            "relayable instance column: {instance}"
        );
        assert_eq!(notice["mentions"], serde_json::json!(["nova:LOTS"]));
        assert_eq!(notice["exact_targets"], serde_json::json!(["nova:LOTS"]));
        assert_eq!(
            notice["text"],
            "kimi takes no cc; delivered to mupe (your message #77:LOTS)"
        );
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn backstop_forward_is_once_across_readers_and_relay_reimport() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let data = old_peer_inform("once", 78);
        inject(&db, &data);
        // A second process on the same database reads the holder too.
        let other = HcomDb::open_at(&path).unwrap();
        assert!(other.get_unread_messages("kimi").is_empty());
        assert!(unread_texts(&db, "kimi").is_empty());
        assert_eq!(forward_count(&db), 1);
        assert_eq!(notice_count(&db), 1);

        // A relay id-regression reset re-imports the row under a new rowid.
        db.conn()
            .execute(
                "DELETE FROM events WHERE json_extract(data, '$._relay.id') = 78
                 AND json_extract(data, '$.delivery_forward_of') IS NULL",
                [],
            )
            .unwrap();
        inject(&db, &data);
        assert!(unread_texts(&db, "kimi").is_empty());
        assert!(other.get_unread_messages("kimi").is_empty());
        assert_eq!(forward_count(&db), 1);
        assert_eq!(notice_count(&db), 1);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn idle_holder_gate_forwards_without_reporting_pending() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        inject(&db, &old_peer_inform("while idle", 79));
        // The pty loop's gate: nothing to inject into kimi, and mupe already
        // has it after this one check.
        assert!(!db.has_pending("kimi"));
        assert_eq!(forward_count(&db), 1);
        assert!(
            unread_texts(&db, "mupe")
                .iter()
                .any(|t| t.ends_with("while idle"))
        );
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn broadcast_to_holder_is_never_forwarded() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        inject(
            &db,
            &serde_json::json!({
                "from": "nova:LOTS", "sender_kind": "instance", "scope": "broadcast", "text": "all",
            }),
        );
        assert!(unread_texts(&db, "kimi").is_empty());
        assert!(!db.has_pending("kimi"));
        assert_eq!(forward_count(&db), 0);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn forward_copy_is_not_refiltered_by_a_policy_marked_delegate() {
        let (db, path, _env) = policy_db(&format!(
            "{KIMI_POLICY}\n[delivery.deputy]\ndelegate = \"lola\"\n"
        ));
        crate::delivery_policy::register_role(&db, "mupe", "sess-mupe", "deputy").unwrap();
        inject(&db, &old_peer_inform("hop once", 80));
        assert!(unread_texts(&db, "kimi").is_empty());
        assert_eq!(
            unread_texts(&db, "mupe"),
            vec!["[nova:LOTS → kimi, forwarded] hop once".to_string()]
        );
        assert!(unread_texts(&db, "lola").is_empty());
        assert_eq!(forward_count(&db), 1);
        cleanup_test_db(path);
    }

    /// A second connection holding the write lock, and this one failing fast.
    fn lock_writes_fail_fast(db: &HcomDb, path: &PathBuf) -> rusqlite::Connection {
        db.conn().execute_batch("PRAGMA busy_timeout=0;").unwrap();
        let guard = rusqlite::Connection::open(path).unwrap();
        guard
            .execute_batch("PRAGMA busy_timeout=0; BEGIN IMMEDIATE;")
            .unwrap();
        guard
    }

    #[test]
    #[serial]
    fn locked_forward_exposes_nothing_past_it_then_forwards_once() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let refused = inject(&db, &old_peer_inform("refused", 81));
        send(
            &db,
            &sender(SenderKind::Instance, "mupe"),
            "later",
            None,
            None,
            &["kimi"],
        );
        let before = cursor(&db, "kimi");

        let guard = lock_writes_fail_fast(&db, &path);
        // The forward cannot commit: the delegate's later message is not
        // exposed either, so no ack can move the cursor past the refused one.
        assert!(unread_texts(&db, "kimi").is_empty());
        assert!(!db.has_pending("kimi"));
        assert_eq!(cursor(&db, "kimi"), before);
        assert_eq!(forward_count(&db), 0);
        drop(guard);

        assert_eq!(unread_texts(&db, "kimi"), vec!["later".to_string()]);
        assert_eq!(cursor(&db, "kimi"), refused);
        assert_eq!(forward_count(&db), 1);
        assert!(
            unread_texts(&db, "mupe")
                .iter()
                .any(|t| t.ends_with("refused"))
        );
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn forward_that_stays_locked_gives_up_to_the_holder_after_five_tries() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        inject(&db, &old_peer_inform("stuck", 82));
        send(
            &db,
            &sender(SenderKind::Instance, "mupe"),
            "later",
            None,
            None,
            &["kimi"],
        );

        let guard = lock_writes_fail_fast(&db, &path);
        for _ in 0..4 {
            assert!(unread_texts(&db, "kimi").is_empty());
        }
        // Fifth failure: the holder gets it rather than a wedged inbox.
        let both = vec!["stuck".to_string(), "later".to_string()];
        assert_eq!(unread_texts(&db, "kimi"), both);
        drop(guard);
        // Unlocked, it stays given up (no late forward, no duplicate) and the
        // failure is recorded for `hcom status`.
        assert_eq!(unread_texts(&db, "kimi"), both);
        assert_eq!(forward_count(&db), 0);
        assert_failure_recorded(&db, "#82:LOTS", "(after 5 attempt(s))");
        cleanup_test_db(path);
    }

    /// kimi's one forward failure for `message` to mupe, and its status line.
    fn assert_failure_recorded(db: &HcomDb, message: &str, reason_end: &str) {
        let failures = crate::delivery_policy::forward_failures(db);
        assert_eq!(failures.len(), 1, "{failures:?}");
        let f = &failures[0];
        assert_eq!(
            (f.holder.as_str(), f.delegate.as_str(), f.message.as_str()),
            ("kimi", "mupe", message)
        );
        assert!(f.reason.ends_with(reason_end), "{f:?}");
        let line = format!(
            "delivery forward failed for message {message} to mupe: {} (kimi keeps it)",
            f.reason
        );
        let lines = crate::delivery_policy::role_status_lines(db);
        assert!(lines.contains(&line), "{lines:?}");
    }

    #[test]
    #[serial]
    fn delegate_without_a_live_row_leaves_the_message_with_the_holder() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        db.conn()
            .execute("DELETE FROM instances WHERE name = 'mupe'", [])
            .unwrap();
        // Send side: kept for kimi, and the sender is told why.
        let d = send(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "no mupe",
            None,
            None,
            &["kimi"],
        );
        assert!(d.reroutes.is_empty());
        assert_eq!(
            reroute_notices(&d),
            vec!["mupe is not live; delivered to kimi".to_string()]
        );
        assert_eq!(d.delivered_to, vec!["kimi".to_string()]);
        // Read side: an old peer's message stays with kimi too.
        inject(&db, &old_peer_inform("no mupe either", 84));
        assert_eq!(
            unread_texts(&db, "kimi"),
            vec!["no mupe".to_string(), "no mupe either".to_string()]
        );
        assert_eq!(forward_count(&db), 0);
        cleanup_test_db(path);
    }

    fn last_event_id(db: &HcomDb) -> i64 {
        db.conn()
            .query_row("SELECT max(id) FROM events", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    #[serial]
    fn holder_cursor_moves_past_leading_broadcasts_only() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let nova = sender(SenderKind::Instance, "nova");
        send(&db, &nova, "b1", None, None, &[]);
        send(&db, &nova, "b2", None, None, &[]);
        let last_broadcast = last_event_id(&db);
        let valo_before = cursor(&db, "valo");
        assert!(unread_texts(&db, "kimi").is_empty());
        assert_eq!(cursor(&db, "kimi"), last_broadcast);
        // A non-holder's read is not an ack.
        assert_eq!(
            unread_texts(&db, "valo"),
            vec!["b1".to_string(), "b2".to_string()]
        );
        assert_eq!(cursor(&db, "valo"), valo_before);
        // Something kimi reads stops the run: the broadcast after it stays
        // above the cursor until kimi acks.
        send(
            &db,
            &sender(SenderKind::Instance, "mupe"),
            "for kimi",
            None,
            None,
            &["kimi"],
        );
        let for_kimi = last_event_id(&db);
        send(&db, &nova, "b3", None, None, &[]);
        assert_eq!(unread_texts(&db, "kimi"), vec!["for kimi".to_string()]);
        assert_eq!(cursor(&db, "kimi"), last_broadcast);
        assert!(for_kimi > last_broadcast);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn list_counts_only_what_the_holder_would_read() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        inject(&db, &old_peer_inform("goes to mupe", 92));
        send(
            &db,
            &sender(SenderKind::Instance, "mupe"),
            "for kimi",
            None,
            None,
            &["kimi"],
        );
        let count =
            |name: &str| crate::commands::list::get_unread_count(&db, name, cursor(&db, name));
        assert_eq!(count("kimi"), 1);
        send(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "for valo",
            None,
            None,
            &["valo"],
        );
        assert_eq!(count("valo"), 1);
        assert_eq!(unread_texts(&db, "kimi"), vec!["for kimi".to_string()]);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn a_delegate_also_addressed_by_name_keeps_its_copy_when_it_stops_mid_send() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let nova = sender(SenderKind::Instance, "nova");
        let targets = vec!["kimi".to_string(), "mupe".to_string()];
        // `@kimi @mupe`: kimi is rerouted to mupe, deduped with the explicit @mupe.
        let resolved = resolve_delivery(&db, &nova, "both", None, Some(&targets)).unwrap();
        assert_eq!(resolved.effective_mentions, vec!["mupe".to_string()]);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute("DELETE FROM instances WHERE name = 'mupe'", [])
            .unwrap();
        let d = persist_resolved(&db, &nova, "both", None, resolved).unwrap();
        let sorted = |value: &serde_json::Value| {
            let mut names: Vec<String> = serde_json::from_value(value.clone()).unwrap();
            names.sort();
            names
        };
        let both = vec!["kimi".to_string(), "mupe".to_string()];
        let (_, stored) = last_message(&db);
        // (a) mupe keeps the copy the sender addressed to it by name.
        assert_eq!(sorted(&stored["mentions"]), both);
        assert_eq!(sorted(&stored["delivered_to"]), both);
        // (b) the reroute still falls back to the holder: kimi is a target,
        // reads it, and the sender is told why.
        assert_eq!(sorted(&stored["exact_targets"]), both);
        assert_eq!(
            stored[crate::delivery_policy::REROUTES_FIELD],
            serde_json::json!({"kimi": "kimi"})
        );
        assert_eq!(
            reroute_notices(&d),
            vec!["mupe is not live; delivered to kimi".to_string()]
        );
        assert_eq!(unread_texts(&db, "kimi"), vec!["both".to_string()]);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn delegate_stopping_between_resolution_and_insert_leaves_it_with_the_holder() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let nova = sender(SenderKind::Instance, "nova");
        let targets = vec!["kimi".to_string()];
        // Resolved while mupe is live: rerouted to mupe.
        let resolved = resolve_delivery(&db, &nova, "mid-send", None, Some(&targets)).unwrap();
        assert_eq!(
            resolved.reroutes,
            vec![("kimi".to_string(), "mupe".to_string())]
        );
        // Another connection stops mupe before the send's insert.
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute("DELETE FROM instances WHERE name = 'mupe'", [])
            .unwrap();
        let d = persist_resolved(&db, &nova, "mid-send", None, resolved).unwrap();
        assert!(d.reroutes.is_empty());
        assert_eq!(
            reroute_notices(&d),
            vec!["mupe is not live; delivered to kimi".to_string()]
        );
        assert_eq!(d.delivered_to, vec!["kimi".to_string()]);
        let (_, stored) = last_message(&db);
        assert_eq!(stored["mentions"], serde_json::json!(["kimi"]));
        assert_eq!(stored["exact_targets"], serde_json::json!(["kimi"]));
        assert_eq!(
            stored[crate::delivery_policy::REROUTES_FIELD],
            serde_json::json!({"kimi": "kimi"})
        );
        assert_eq!(unread_texts(&db, "kimi"), vec!["mid-send".to_string()]);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn mistyped_delegate_leaves_the_message_with_the_holder() {
        let (db, path, _env) = policy_db("[delivery.conductor]\ndelegate = \"mpue\"\n");
        let d = send(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "typo",
            None,
            None,
            &["kimi"],
        );
        assert!(d.reroutes.is_empty());
        assert_eq!(d.delivered_to, vec!["kimi".to_string()]);
        assert_eq!(
            reroute_notices(&d),
            vec!["mpue is not live; delivered to kimi".to_string()]
        );
        inject(&db, &old_peer_inform("typo too", 88));
        assert_eq!(
            unread_texts(&db, "kimi"),
            vec!["typo".to_string(), "typo too".to_string()]
        );
        assert_eq!(forward_count(&db), 0);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn delegate_gone_at_forward_time_gets_no_claim_and_the_holder_keeps_it() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let data = old_peer_inform("mupe left", 89);
        let id = inject(&db, &data);
        let reg = crate::delivery_policy::load(&db)
            .unwrap()
            .registration("kimi")
            .unwrap()
            .clone();
        // mupe stops after the read decided to forward.
        db.conn()
            .execute("DELETE FROM instances WHERE name = 'mupe'", [])
            .unwrap();
        let before = cursor(&db, "kimi");
        let outcome = db.forward_refused("kimi", refused(id, &data), "mupe", Some(before), &reg);
        assert_eq!(outcome, crate::db::ForwardOutcome::DeliverToHolder);
        assert!(
            db.kv_prefix(crate::delivery_policy::KV_FORWARDED_PREFIX)
                .unwrap()
                .is_empty()
        );
        assert_eq!(cursor(&db, "kimi"), before);
        // mupe coming back does not pull it away: kimi keeps it.
        db.conn()
            .execute(
                "INSERT INTO instances (name, session_id, created_at) VALUES ('mupe', 'sess-mupe2', 3000.0)",
                [],
            )
            .unwrap();
        assert_eq!(unread_texts(&db, "kimi"), vec!["mupe left".to_string()]);
        assert_eq!(forward_count(&db), 0);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn a_reset_peer_reusing_an_old_id_is_forwarded_but_a_reimport_is_not() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let first = old_peer_inform("before the reset", 90);
        db.log_event_with_ts(
            "message",
            "nova:LOTS",
            &first,
            Some("2026-09-01T10:00:00.000000"),
        )
        .unwrap();
        assert!(unread_texts(&db, "kimi").is_empty());
        assert_eq!(forward_count(&db), 1);
        // Our own re-import of the same message (new rowid, same origin
        // and sender timestamp): not forwarded twice.
        db.log_event_with_ts(
            "message",
            "nova:LOTS",
            &first,
            Some("2026-09-01T10:00:00.000000"),
        )
        .unwrap();
        assert!(unread_texts(&db, "kimi").is_empty());
        assert_eq!(forward_count(&db), 1);
        // The peer's database was reset: a new message reuses relay id 90.
        let second = old_peer_inform("after the reset", 90);
        db.log_event_with_ts(
            "message",
            "nova:LOTS",
            &second,
            Some("2026-09-02T09:00:00.000000"),
        )
        .unwrap();
        assert!(unread_texts(&db, "kimi").is_empty());
        let texts: Vec<String> = forward_rows(&db)
            .into_iter()
            .map(|(_, c)| c["text"].as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(texts.len(), 2);
        assert!(texts[1].ends_with("after the reset"), "{texts:?}");
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn a_bare_delegate_name_live_only_as_a_remote_mirror_resolves_to_it() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        db.conn()
            .execute_batch(
                "DELETE FROM instances WHERE name = 'mupe';
                 INSERT INTO instances (name, session_id, created_at, origin_device_id)
                 VALUES ('mupe:BOXE', 'sess-remote', 1000.0, 'dev-boxe');",
            )
            .unwrap();
        let d = send(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "to the remote mupe",
            None,
            None,
            &["kimi"],
        );
        assert_eq!(
            d.reroutes,
            vec![("kimi".to_string(), "mupe:BOXE".to_string())]
        );
        assert_eq!(d.delivered_to, vec!["mupe:BOXE".to_string()]);
        inject(&db, &old_peer_inform("old peer to kimi", 91));
        assert!(unread_texts(&db, "kimi").is_empty());
        let mentions: Vec<serde_json::Value> = forward_rows(&db)
            .into_iter()
            .map(|(_, c)| c["mentions"].clone())
            .collect();
        assert_eq!(mentions, vec![serde_json::json!(["mupe:BOXE"])]);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn local_delegate_with_a_live_remote_namesake_reroutes_to_the_local_one() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        db.conn()
            .execute(
                "INSERT INTO instances (name, session_id, created_at, origin_device_id)
                 VALUES ('mupe:BOXE', 'sess-remote', 1000.0, 'dev-boxe')",
                [],
            )
            .unwrap();
        let d = send(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "to the local mupe",
            None,
            None,
            &["kimi"],
        );
        assert_eq!(d.reroutes, vec![("kimi".to_string(), "mupe".to_string())]);
        assert!(reroute_notices(&d).iter().all(|n| !n.contains("not live")));
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn a_forwarded_refusal_with_a_racing_failure_record_stays_forwarded() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        send(
            &db,
            &sender(SenderKind::Instance, "mupe"),
            "first",
            None,
            None,
            &["kimi"],
        );
        let first = last_event_id(&db);
        let refused = inject(&db, &old_peer_inform("refused", 97));
        // One reader forwards it (handled, no cursor move: "first" precedes it).
        assert_eq!(unread_texts(&db, "kimi"), vec!["first".to_string()]);
        assert_eq!(forward_count(&db), 1);
        // A second reader's give-up raced it and left a failure record too.
        db.kv_set(
            &format!(
                "{}kimi:dev-lots:97:{SENT_AT}",
                crate::delivery_policy::KV_FORWARD_FAILED_PREFIX
            ),
            Some(
                &serde_json::json!({"holder": "kimi", "delegate": "mupe", "message": "#97:LOTS", "reason": "database is locked (after 5 attempt(s))"})
                    .to_string(),
            ),
        )
        .unwrap();
        let mut updates = serde_json::Map::new();
        updates.insert("last_event_id".into(), serde_json::json!(first));
        crate::instances::update_instance_position(&db, "kimi", &updates);
        // Handled wins: the cursor-advancing read skips it, the count and the
        // status agree, and mupe keeps the only copy.
        assert_eq!(
            crate::commands::list::get_unread_count(&db, "kimi", cursor(&db, "kimi")),
            0
        );
        assert!(unread_texts(&db, "kimi").is_empty());
        assert!(cursor(&db, "kimi") >= refused);
        assert!(crate::delivery_policy::forward_failures(&db).is_empty());
        assert_eq!(forward_count(&db), 1);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn a_reader_locked_out_of_a_handled_forward_never_gives_it_to_the_holder() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        send(
            &db,
            &sender(SenderKind::Instance, "mupe"),
            "first",
            None,
            None,
            &["kimi"],
        );
        let first = last_event_id(&db);
        inject(&db, &old_peer_inform("refused", 96));
        // Reader B forwards it: handled, but no cursor move ("first" precedes it).
        let reader_b = HcomDb::open_at(&path).unwrap();
        assert_eq!(
            reader_b
                .get_unread_messages("kimi")
                .into_iter()
                .map(|m| m.text)
                .collect::<Vec<_>>(),
            vec!["first".to_string()]
        );
        assert_eq!(forward_count(&db), 1);
        let mut updates = serde_json::Map::new();
        updates.insert("last_event_id".into(), serde_json::json!(first));
        crate::instances::update_instance_position(&db, "kimi", &updates);
        // Reader A now meets the handled event with the database write-locked,
        // for more reads than the give-up budget.
        let guard = lock_writes_fail_fast(&db, &path);
        for _ in 0..crate::delivery_policy::MAX_FORWARD_ATTEMPTS + 1 {
            assert!(unread_texts(&db, "kimi").is_empty());
        }
        drop(guard);
        assert!(crate::delivery_policy::forward_failures(&db).is_empty());
        assert!(unread_texts(&db, "kimi").is_empty());
        assert_eq!(forward_count(&db), 1);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn forwarded_then_delegate_stops_is_not_redelivered_to_the_holder() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        send(
            &db,
            &sender(SenderKind::Instance, "mupe"),
            "first",
            None,
            None,
            &["kimi"],
        );
        let first = last_event_id(&db);
        let refused = inject(&db, &old_peer_inform("refused", 94));
        // "first" is deliverable, so this read forwards "refused" without
        // moving the cursor past it.
        assert_eq!(unread_texts(&db, "kimi"), vec!["first".to_string()]);
        assert_eq!(forward_count(&db), 1);
        let mut updates = serde_json::Map::new();
        updates.insert("last_event_id".into(), serde_json::json!(first));
        crate::instances::update_instance_position(&db, "kimi", &updates);
        // mupe stops; the next read meets the already-forwarded event first.
        db.conn()
            .execute("DELETE FROM instances WHERE name = 'mupe'", [])
            .unwrap();
        assert!(unread_texts(&db, "kimi").is_empty());
        assert_eq!(forward_count(&db), 1);
        assert!(crate::delivery_policy::forward_failures(&db).is_empty());
        // Past it, and past the forward copy and notice it skips.
        assert!(refused < last_event_id(&db));
        assert_eq!(cursor(&db, "kimi"), last_event_id(&db));
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn list_counts_a_refused_message_the_holder_keeps() {
        let (db, path, _env) = policy_db("[delivery.conductor]\ndelegate = \"mpue\"\n");
        inject(&db, &old_peer_inform("kept", 95));
        let count = crate::commands::list::get_unread_count(&db, "kimi", cursor(&db, "kimi"));
        assert_eq!(count, 1);
        assert_eq!(unread_texts(&db, "kimi"), vec!["kept".to_string()]);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn racing_registrations_of_two_roles_admit_exactly_one() {
        let (db, path, _env) = policy_db(&format!(
            "{KIMI_POLICY}\n[delivery.deputy]\ndelegate = \"lola\"\n"
        ));
        for round in 0..20 {
            db.conn()
                .execute("DELETE FROM kv WHERE key = 'delivery_role:kimi'", [])
                .unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let racers: Vec<_> = ["conductor", "deputy"]
                .into_iter()
                .map(|role| {
                    let (barrier, path) = (barrier.clone(), path.clone());
                    std::thread::spawn(move || {
                        let conn = HcomDb::open_at(&path).unwrap();
                        barrier.wait();
                        // A transient answer (the lock outlasted busy_timeout)
                        // is retried, as the plugin does (bounded, so a leaked
                        // lock fails the test instead of hanging it); only
                        // final answers count.
                        for _ in 0..10 {
                            match crate::delivery_policy::register_role(
                                &conn,
                                "kimi",
                                "sess-kimi",
                                role,
                            ) {
                                Err(e) if e.transient => continue,
                                other => return other,
                            }
                        }
                        panic!("register_role still transient after 10 tries");
                    })
                })
                .collect();
            let results: Vec<_> = racers.into_iter().map(|t| t.join().unwrap()).collect();
            let refused: Vec<_> = results.iter().filter_map(|r| r.as_ref().err()).collect();
            assert_eq!(refused.len(), 1, "round {round}: {results:?}");
            assert!(!refused[0].transient, "round {round}: {results:?}");
            assert!(
                refused[0].message.contains("already holds role"),
                "round {round}: {results:?}"
            );
        }
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn every_policy_change_is_logged_including_a_flip_back() {
        let (db, path, env) = policy_db(KIMI_POLICY);
        let changes = || {
            log_text(&env)
                .lines()
                .filter(|line| line.contains("\"policy_changed\""))
                .count()
        };
        crate::delivery_policy::load(&db).unwrap();
        let before = changes();
        let config = env.1.join("config.toml");
        std::fs::write(&config, "[delivery.conductor]\ndelegate = \"lola\"\n").unwrap();
        crate::delivery_policy::load(&db).unwrap();
        crate::delivery_policy::load(&db).unwrap();
        std::fs::write(&config, KIMI_POLICY).unwrap();
        crate::delivery_policy::load(&db).unwrap();
        assert_eq!(changes(), before + 2);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn one_message_to_two_holders_reaches_each_delegate_once() {
        // Different delegates: one copy each.
        let (db, path, _env) = policy_db(&format!(
            "{KIMI_POLICY}\n[delivery.deputy]\ndelegate = \"lola\"\n"
        ));
        crate::delivery_policy::register_role(&db, "valo", "sess-valo", "deputy").unwrap();
        let mut both = old_peer_inform("to both", 85);
        both["mentions"] = serde_json::json!(["kimi", "valo"]);
        let id = inject(&db, &both);
        assert!(unread_texts(&db, "kimi").is_empty());
        // valo reads after kimi's forward copy and notice exist: it forwards
        // its own and skips through kimi's, up to what its read saw.
        let seen_by_valo = last_event_id(&db);
        assert!(unread_texts(&db, "valo").is_empty());
        let delegates: Vec<serde_json::Value> = forward_rows(&db)
            .into_iter()
            .map(|(_, c)| c["mentions"].clone())
            .collect();
        assert_eq!(
            delegates,
            vec![serde_json::json!(["mupe"]), serde_json::json!(["lola"])]
        );
        assert_eq!(
            (cursor(&db, "kimi"), cursor(&db, "valo")),
            (id, seen_by_valo)
        );
        cleanup_test_db(path);
        // The env guard holds the process-wide env lock: release it before the next fixture.
        drop((db, _env));

        // Same delegate: one copy, and both holders move past it.
        let (db, path, _env) = policy_db(&format!(
            "{KIMI_POLICY}\n[delivery.deputy]\ndelegate = \"mupe\"\n"
        ));
        crate::delivery_policy::register_role(&db, "valo", "sess-valo", "deputy").unwrap();
        let id = inject(&db, &both);
        assert!(unread_texts(&db, "kimi").is_empty());
        assert!(unread_texts(&db, "valo").is_empty());
        assert_eq!(forward_count(&db), 1);
        assert_eq!(
            (cursor(&db, "kimi"), cursor(&db, "valo")),
            (id, last_event_id(&db))
        );
        cleanup_test_db(path);
        drop((db, _env));

        // One delegate spelled two ways ("mupe", live only as a mirror, and
        // "mupe:BOXE"): resolved to one row, so one copy.
        let (db, path, _env) = policy_db(&format!(
            "{KIMI_POLICY}\n[delivery.deputy]\ndelegate = \"mupe:BOXE\"\n"
        ));
        crate::delivery_policy::register_role(&db, "valo", "sess-valo", "deputy").unwrap();
        db.conn()
            .execute_batch(
                "DELETE FROM instances WHERE name = 'mupe';
                 INSERT INTO instances (name, session_id, created_at, origin_device_id)
                 VALUES ('mupe:BOXE', 'sess-remote', 1000.0, 'dev-boxe');",
            )
            .unwrap();
        inject(&db, &both);
        assert!(unread_texts(&db, "kimi").is_empty());
        assert!(unread_texts(&db, "valo").is_empty());
        let delegates: Vec<serde_json::Value> = forward_rows(&db)
            .into_iter()
            .map(|(_, c)| c["mentions"].clone())
            .collect();
        assert_eq!(delegates, vec![serde_json::json!(["mupe:BOXE"])]);
        assert_eq!(notice_count(&db), 1);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn forward_for_a_row_rebound_since_the_read_writes_nothing() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let data = old_peer_inform("rebind race", 86);
        let id = inject(&db, &data);
        let read_policies = crate::delivery_policy::load(&db).unwrap();
        let read_reg = read_policies.registration("kimi").unwrap().clone();
        let before = cursor(&db, "kimi");
        // A new occupant takes the name between the scan and the forward.
        db.conn()
            .execute(
                "UPDATE instances SET session_id = 'sess-new', created_at = 2000.0 WHERE name = 'kimi'",
                [],
            )
            .unwrap();
        let outcome =
            db.forward_refused("kimi", refused(id, &data), "mupe", Some(before), &read_reg);
        assert_eq!(outcome, crate::db::ForwardOutcome::Retry);
        assert_eq!(forward_count(&db), 0);
        assert_eq!(cursor(&db, "kimi"), before);
        // The next read re-evaluates under the new occupant, who holds no role.
        assert_eq!(unread_texts(&db, "kimi"), vec!["rebind race".to_string()]);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn stale_read_cannot_forward_or_move_a_reregistered_occupants_mail() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let data = old_peer_inform("for the new kimi", 87);
        let id = inject(&db, &data);
        let stale_reg = crate::delivery_policy::load(&db)
            .unwrap()
            .registration("kimi")
            .unwrap()
            .clone();
        let before = cursor(&db, "kimi");
        // A new occupant takes the name and registers the same role.
        db.conn()
            .execute(
                "UPDATE instances SET session_id = 'sess-new', created_at = 2000.0 WHERE name = 'kimi'",
                [],
            )
            .unwrap();
        crate::delivery_policy::register_role(&db, "kimi", "sess-new", "conductor").unwrap();
        let outcome =
            db.forward_refused("kimi", refused(id, &data), "mupe", Some(before), &stale_reg);
        assert_eq!(outcome, crate::db::ForwardOutcome::Retry);
        assert_eq!(forward_count(&db), 0);
        assert_eq!(cursor(&db, "kimi"), before);
        // A fresh read under the new registration forwards it once.
        assert!(unread_texts(&db, "kimi").is_empty());
        assert_eq!(forward_count(&db), 1);
        assert_eq!(cursor(&db, "kimi"), id);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn forward_that_always_fails_reaches_the_holder_once_and_blocks_nothing() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        db.conn()
            .execute_batch(
                "CREATE TRIGGER poison_forward BEFORE INSERT ON events
                 WHEN NEW.data LIKE '%delivery_forward_of%'
                 BEGIN SELECT RAISE(ABORT, 'poisoned'); END;",
            )
            .unwrap();
        inject(&db, &old_peer_inform("poison", 83));
        send(
            &db,
            &sender(SenderKind::Instance, "mupe"),
            "later",
            None,
            None,
            &["kimi"],
        );

        let unread = db.get_unread_messages("kimi");
        let texts: Vec<&str> = unread.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(texts, vec!["poison", "later"]);
        // Acked like any delivery: the holder never sees it again.
        let last = unread.last().and_then(|m| m.event_id).unwrap();
        let mut updates = serde_json::Map::new();
        updates.insert("last_event_id".into(), serde_json::json!(last));
        crate::instances::update_instance_position(&db, "kimi", &updates);
        assert!(unread_texts(&db, "kimi").is_empty());
        assert_eq!(forward_count(&db), 0);
        assert_failure_recorded(&db, "#83:LOTS", "(after 1 attempt(s))");
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn conductor_role_unheld_turns_filter_off_and_warns() {
        let (db, path, env) = rows_db(KIMI_POLICY);
        assert_eq!(
            crate::delivery_policy::role_status_lines(&db),
            vec!["conductor role: NONE".to_string()]
        );
        crate::delivery_policy::warn_unheld_roles(&db);
        assert!(
            log_text(&env).contains("\"role_unheld\""),
            "{}",
            log_text(&env)
        );

        // Nobody holds the role, so nobody is filtered: the visible warning
        // above is the only signal a registration was missed.
        let d = send(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "hi",
            None,
            None,
            &["kimi"],
        );
        assert_delivered_to_kimi(&db, &d, "hi");
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn two_conductor_role_holders_both_filtered_and_warned() {
        let (db, path, env) = policy_db(KIMI_POLICY);
        crate::delivery_policy::register_role(&db, "lola", "sess-lola", "conductor").unwrap();
        assert_eq!(
            crate::delivery_policy::role_status_lines(&db),
            vec!["conductor role: kimi, lola".to_string()]
        );
        let d = send(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "cc",
            None,
            None,
            &["kimi", "lola"],
        );
        assert_eq!(
            d.reroutes,
            vec![
                ("kimi".to_string(), "mupe".to_string()),
                ("lola".to_string(), "mupe".to_string()),
            ]
        );
        assert_eq!(d.effective_mentions, vec!["mupe".to_string()]);
        assert!(unread_texts(&db, "kimi").is_empty());
        assert!(unread_texts(&db, "lola").is_empty());
        assert!(log_text(&env).contains("\"role_multiple_holders\""));
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn conductor_role_registration_is_add_only() {
        let (db, path, env) = policy_db(KIMI_POLICY);
        let err =
            crate::delivery_policy::register_role(&db, "kimi", "sess-kimi", "deputy").unwrap_err();
        assert!(
            err.message.contains("add-only") && !err.transient,
            "{err:?}"
        );
        // Same role again is a no-op success; a session the row is not bound
        // to cannot register it.
        crate::delivery_policy::register_role(&db, "kimi", "sess-kimi", "conductor").unwrap();
        assert!(
            crate::delivery_policy::register_role(&db, "nova", "sess-kimi", "conductor").is_err()
        );
        assert_eq!(
            crate::delivery_policy::role_status_lines(&db),
            vec!["conductor role: kimi".to_string()]
        );
        let log = log_text(&env);
        assert!(
            log.lines()
                .any(|l| l.contains("\"role_registered\"")
                    && l.contains("\"session_id\":\"sess-kimi\"")),
            "{log}"
        );
        assert!(log.contains("\"role_registration_refused\""), "{log}");
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn a_row_whose_created_at_json_cannot_round_trip_still_holds_its_role() {
        // A real fractional timestamp a serde f64 round trip lands one ULP
        // off (the same fixture db::mod's created_at_bits migration guards).
        const CREATED_AT: f64 = 1_790_000_000.000_002_1;
        assert_eq!(CREATED_AT.to_bits(), 4_745_294_612_153_761_801);
        let (db, path, _env) = rows_db(KIMI_POLICY);
        db.conn()
            .execute(
                "UPDATE instances SET created_at = ?1 WHERE name = 'kimi'",
                [CREATED_AT],
            )
            .unwrap();
        crate::delivery_policy::register_role(&db, "kimi", "sess-kimi", "conductor").unwrap();
        assert_eq!(
            crate::delivery_policy::role_status_lines(&db),
            vec!["conductor role: kimi".to_string()]
        );
        let d = send(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "filtered",
            None,
            None,
            &["kimi"],
        );
        assert_eq!(d.reroutes, vec![("kimi".to_string(), "mupe".to_string())]);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn conductor_role_dies_with_its_row_and_resume_must_reregister() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let nova = sender(SenderKind::Instance, "nova");
        let recreate = |session: &str, created_at: f64| {
            db.conn()
                .execute("DELETE FROM instances WHERE name = 'kimi'", [])
                .unwrap();
            db.conn()
                .execute(
                    "INSERT INTO instances (name, session_id, created_at) VALUES ('kimi', ?, ?)",
                    rusqlite::params![session, created_at],
                )
                .unwrap();
        };

        // `hcom r kimi`: same name, same omp session, but a new row.
        recreate("sess-kimi", 2000.0);
        let d = send(&db, &nova, "after resume", None, None, &["kimi"]);
        assert_delivered_to_kimi(&db, &d, "after resume");
        // The resumed session's plugin registers again at bind.
        crate::delivery_policy::register_role(&db, "kimi", "sess-kimi", "conductor").unwrap();
        let d = send(&db, &nova, "after re-register", None, None, &["kimi"]);
        assert_rerouted_to_mupe(&db, &d, "after re-register");

        // A later seat reusing the name (fresh launch, new session) is not
        // the conductor.
        recreate("sess-new-seat", 3000.0);
        let d = send(&db, &nova, "new seat", None, None, &["kimi"]);
        assert_delivered_to_kimi(&db, &d, "new seat");
        cleanup_test_db(path);
    }

    fn sender(kind: SenderKind, name: &str) -> SenderIdentity {
        SenderIdentity {
            kind,
            name: name.into(),
            instance_data: None,
            session_id: None,
        }
    }

    fn send(
        db: &HcomDb,
        from: &SenderIdentity,
        text: &str,
        intent: Option<crate::messages::MessageIntent>,
        reply_to: Option<i64>,
        targets: &[&str],
    ) -> ResolvedDelivery {
        let envelope = MessageEnvelope {
            intent,
            reply_to: reply_to.map(|id| id.to_string()),
            ..Default::default()
        };
        let targets: Vec<String> = targets.iter().map(|t| t.to_string()).collect();
        send_message_resolved(
            db,
            from,
            text,
            Some(&envelope),
            (!targets.is_empty()).then_some(targets.as_slice()),
        )
        .unwrap()
    }

    fn last_message(db: &HcomDb) -> (i64, serde_json::Value) {
        let (id, data): (i64, String) = db
            .conn()
            .query_row(
                "SELECT id, data FROM events WHERE type = 'message' ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        (id, serde_json::from_str(&data).unwrap())
    }

    fn unread_texts(db: &HcomDb, name: &str) -> Vec<String> {
        db.get_unread_messages(name)
            .into_iter()
            .map(|m| m.text)
            .collect()
    }

    fn reqwatch_rows(db: &HcomDb) -> i64 {
        db.conn()
            .query_row(
                "SELECT COUNT(*) FROM kv WHERE key LIKE 'events_sub:reqwatch-%'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn assert_delivered_to_kimi(db: &HcomDb, delivery: &ResolvedDelivery, text: &str) {
        assert!(delivery.reroutes.is_empty(), "{:?}", delivery.reroutes);
        assert!(reroute_notices(delivery).is_empty());
        assert_eq!(delivery.delivered_to, vec!["kimi".to_string()]);
        assert!(
            unread_texts(db, "kimi").contains(&text.to_string()),
            "{text}"
        );
    }

    fn assert_rerouted_to_mupe(db: &HcomDb, delivery: &ResolvedDelivery, text: &str) {
        assert_eq!(
            delivery.reroutes,
            vec![("kimi".to_string(), "mupe".to_string())],
            "{text}"
        );
        assert_eq!(
            reroute_notices(delivery),
            vec!["kimi takes no cc; delivered to mupe".to_string()]
        );
        let (_, data) = last_message(db);
        for field in ["mentions", "exact_targets", "delivered_to"] {
            let names: Vec<&str> = data[field]
                .as_array()
                .unwrap_or_else(|| panic!("{field} missing: {data}"))
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            assert!(names.contains(&"mupe"), "{field}: {data}");
            assert!(!names.contains(&"kimi"), "{field}: {data}");
        }
        assert_eq!(
            data["delivery_reroutes"],
            serde_json::json!({"kimi": "mupe"})
        );
        assert!(
            !unread_texts(db, "kimi").contains(&text.to_string()),
            "{text}"
        );
        assert!(
            unread_texts(db, "mupe").contains(&text.to_string()),
            "{text}"
        );
    }

    #[test]
    #[serial]
    fn nonlead_instance_to_kimi_rerouted_to_mupe_with_notice() {
        use crate::messages::MessageIntent::{Ack, Inform, Request};
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let nova = sender(SenderKind::Instance, "nova");
        let kimi = sender(SenderKind::Instance, "kimi");

        let d = send(
            &db,
            &nova,
            "status looks fine",
            Some(Inform),
            None,
            &["kimi"],
        );
        assert_rerouted_to_mupe(&db, &d, "status looks fine");

        send(&db, &kimi, "take the lane", Some(Request), None, &["nova"]);
        let (request_id, _) = last_message(&db);
        let d = send(&db, &nova, "on it", Some(Ack), Some(request_id), &["kimi"]);
        assert_rerouted_to_mupe(&db, &d, "on it");

        // cc: kimi named alongside others; mupe replaces kimi once (dedupe).
        let d = send(&db, &nova, "cc", None, None, &["lola", "kimi", "mupe"]);
        assert_rerouted_to_mupe(&db, &d, "cc");
        assert_eq!(
            d.effective_mentions,
            vec!["lola".to_string(), "mupe".to_string()]
        );

        assert!(unread_texts(&db, "kimi").is_empty());
        // The pending-check counters the plugins gate on see nothing either,
        // so refused events are skipped like mail for someone else.
        assert!(!db.has_pending("kimi"));
        assert!(db.pending_event_range("kimi").is_none());

        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn delegate_mupe_inform_to_kimi_delivered() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let mupe = sender(SenderKind::Instance, "mupe");
        let d = send(
            &db,
            &mupe,
            "michael says hi",
            Some(crate::messages::MessageIntent::Inform),
            None,
            &["kimi"],
        );
        assert_delivered_to_kimi(&db, &d, "michael says hi");
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn delegate_mupe_request_without_prefix_to_kimi_delivered() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let mupe = sender(SenderKind::Instance, "mupe");
        let d = send(
            &db,
            &mupe,
            "please review the queue",
            Some(crate::messages::MessageIntent::Request),
            None,
            &["kimi"],
        );
        assert_delivered_to_kimi(&db, &d, "please review the queue");
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn delegate_mupe_ack_to_kimi_delivered() {
        use crate::messages::MessageIntent::{Ack, Request};
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let mupe = sender(SenderKind::Instance, "mupe");
        let kimi = sender(SenderKind::Instance, "kimi");
        send(&db, &kimi, "file the list", Some(Request), None, &["mupe"]);
        let (request_id, _) = last_message(&db);
        let d = send(&db, &mupe, "filed", Some(Ack), Some(request_id), &["kimi"]);
        assert_delivered_to_kimi(&db, &d, "filed");
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn lead_request_with_wake_word_to_kimi_delivered() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let valo = sender(SenderKind::Instance, "valo");
        for text in ["BLOCKED: x", "DECISION x"] {
            let d = send(
                &db,
                &valo,
                text,
                Some(crate::messages::MessageIntent::Request),
                None,
                &["kimi"],
            );
            assert_delivered_to_kimi(&db, &d, text);
        }
        cleanup_test_db(path);
    }

    /// The block that ships to the conductor's host (omp-config
    /// delivery-conductor-proposal.md): a third wake word, CONFLICT.
    #[test]
    #[serial]
    fn deployment_config_conflict_prefix_wakes_kimi_only_in_uppercase() {
        use crate::messages::MessageIntent::Request;
        let (db, path, _env) = policy_db(
            "[delivery.conductor]\n\
             delegate = \"mupe\"\n\
             leads = [\"poli\", \"valo\", \"henu\", \"todo\", \"zeno\"]\n\
             wake_intents = [\"request\"]\n\
             wake_prefixes = [\"BLOCKED\", \"DECISION\", \"CONFLICT\"]\n",
        );
        let valo = sender(SenderKind::Instance, "valo");
        let d = send(&db, &valo, "CONFLICT: x", Some(Request), None, &["kimi"]);
        assert_delivered_to_kimi(&db, &d, "CONFLICT: x");
        let d = send(&db, &valo, "Conflict: x", Some(Request), None, &["kimi"]);
        assert_rerouted_to_mupe(&db, &d, "Conflict: x");
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn lead_without_wake_word_or_request_and_nonlead_rerouted() {
        use crate::messages::MessageIntent::{Inform, Request};
        let (db, path, _env) = policy_db(KIMI_POLICY);
        let valo = sender(SenderKind::Instance, "valo");
        let nova = sender(SenderKind::Instance, "nova");
        for (from, intent, text) in [
            (&valo, Request, "BLOCKEDX"),
            (&valo, Request, "blocked: x"),
            (&valo, Inform, "BLOCKED: y"),
            (&nova, Request, "BLOCKED: z"),
        ] {
            let d = send(&db, from, text, Some(intent), None, &["kimi"]);
            assert_rerouted_to_mupe(&db, &d, text);
        }
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn external_from_non_instance_to_kimi_delivered_and_audited() {
        let (db, path, env) = policy_db(KIMI_POLICY);
        // `--from michael`: unauthenticated External sender, the known bypass.
        let michael = sender(SenderKind::External, "michael");
        let d = send(&db, &michael, "status?", None, None, &["kimi"]);
        assert_delivered_to_kimi(&db, &d, "status?");

        let (event_id, _) = last_message(&db);
        let log = std::fs::read_to_string(env.1.join(".tmp/logs/hcom.log")).unwrap();
        assert!(
            log.lines().any(|line| line.contains("\"external_reached\"")
                && line.contains("michael")
                && line.contains(&format!("\"event_id\":\"{event_id}\""))),
            "{log}"
        );
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn relayed_external_to_kimi_is_audited_once_on_the_holders_host() {
        let (db, path, env) = policy_db(KIMI_POLICY);
        // `--from michael` on LOTS: that host cannot know kimi's role.
        let id = inject(
            &db,
            &serde_json::json!({
                "from": "michael",
                "sender_kind": "external",
                "scope": "mentions",
                "mentions": ["kimi"],
                "delivered_to": ["kimi"],
                "text": "status?",
                "_relay": {"device": "dev-lots", "short": "LOTS", "id": 93},
            }),
        );
        assert_eq!(unread_texts(&db, "kimi"), vec!["status?".to_string()]);
        assert_eq!(unread_texts(&db, "kimi"), vec!["status?".to_string()]);
        let audits: Vec<String> = log_text(&env)
            .lines()
            .filter(|line| line.contains("\"external_reached\""))
            .map(str::to_string)
            .collect();
        assert_eq!(audits.len(), 1, "{audits:?}");
        assert!(
            audits[0].contains(&format!("\"event_id\":\"{id}\"")),
            "{audits:?}"
        );
        assert!(audits[0].contains("dev-lots:93:"), "{audits:?}");
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn broadcasts_never_reach_kimi_and_reach_mupe() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        for from in [
            sender(SenderKind::Instance, "valo"),
            sender(SenderKind::External, "bigboss"),
        ] {
            let text = format!("all hands from {}", from.name);
            let d = send(&db, &from, &text, None, None, &[]);
            assert_eq!(d.effective_scope, MessageScope::Broadcast);
            assert!(!d.delivered_to.contains(&"kimi".to_string()));
            assert!(d.delivered_to.contains(&"mupe".to_string()));
            assert!(unread_texts(&db, "mupe").contains(&text));
        }
        assert!(unread_texts(&db, "kimi").is_empty());
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn system_launcher_and_reqwatch_ping_to_kimi_forwarded_to_mupe_once() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        // Written straight to the events table, bypassing `hcom send`.
        db.notify_batch_failure("kimi", "batch-1", "zazu", "pty died")
            .unwrap();
        crate::db::subscriptions::send_system_message(
            &db,
            "[hcom-events]",
            "@kimi reqwatch: nova went idle without replying",
        )
        .unwrap();
        assert!(unread_texts(&db, "kimi").is_empty());
        assert!(
            unread_texts(&db, "kimi").is_empty(),
            "a second read adds nothing"
        );

        // Both reach mupe once, and no sender notice goes to a system sender.
        let mupe = unread_texts(&db, "mupe");
        for needle in ["Launch failed: zazu", "reqwatch: nova went idle"] {
            assert_eq!(
                mupe.iter().filter(|t| t.contains(needle)).count(),
                1,
                "{needle}: {mupe:?}"
            );
        }
        assert_eq!(forward_count(&db), 2);
        assert_eq!(notice_count(&db), 0);

        // Through `hcom send`, a System sender is rerouted like any instance.
        let launcher = sender(SenderKind::System, "hcom-launcher");
        let d = send(&db, &launcher, "launch ready", None, None, &["kimi"]);
        assert_rerouted_to_mupe(&db, &d, "launch ready");
        assert!(unread_texts(&db, "kimi").is_empty());
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn send_from_kimi_request_creates_no_request_watch() {
        use crate::messages::MessageIntent::Request;
        let (db, path, _env) = policy_db(KIMI_POLICY);
        send(
            &db,
            &sender(SenderKind::Instance, "kimi"),
            "go",
            Some(Request),
            None,
            &["nova"],
        );
        assert_eq!(reqwatch_rows(&db), 0);
        // Control: the same request from an instance without a policy arms one.
        send(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "go",
            Some(Request),
            None,
            &["valo"],
        );
        assert_eq!(reqwatch_rows(&db), 1);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn broken_policy_with_readable_delegate_forwards_to_it() {
        use crate::messages::MessageIntent::Request;
        // `lead` is a typo: the block is broken, its delegate still readable.
        let (db, path, _env) = policy_db(
            "[delivery.conductor]\ndelegate = \"mupe\"\nleads = [\"valo\"]\nlead = [\"x\"]\n",
        );
        // The broken block keeps no leads: even a lead's wake word goes to mupe.
        let valo = sender(SenderKind::Instance, "valo");
        let d = send(&db, &valo, "BLOCKED: x", Some(Request), None, &["kimi"]);
        assert_rerouted_to_mupe(&db, &d, "BLOCKED: x");
        let lines = crate::delivery_policy::role_status_lines(&db);
        assert!(
            lines.iter().any(
                |l| l.starts_with("delivery policy INVALID: [delivery.conductor]")
                    && l.contains("delegate mupe only")
            ),
            "{lines:?}"
        );
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn broken_policy_without_delegate_delivers_to_holder_loudly() {
        let (db, path, _env) = policy_db("[delivery.conductor]\nleads = [\"valo\"]\n");
        let nova = sender(SenderKind::Instance, "nova");
        let d = send(&db, &nova, "cc", None, None, &["kimi"]);
        assert_delivered_to_kimi(&db, &d, "cc");
        send(&db, &nova, "everyone", None, None, &[]);
        crate::delivery_policy::role_status_lines(&db);

        let unread = unread_texts(&db, "kimi");
        assert_eq!(
            unread
                .iter()
                .filter(|t| t.contains("delivery policy INVALID for role conductor"))
                .count(),
            1,
            "{unread:?}"
        );
        assert!(!unread.contains(&"everyone".to_string()));
        let lines = crate::delivery_policy::role_status_lines(&db);
        assert!(
            lines.iter().any(
                |l| l.starts_with("delivery policy INVALID: [delivery.conductor]")
                    && l.contains("no delegate")
            ),
            "{lines:?}"
        );
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn no_policy_entry_behaviour_unchanged() {
        let (db, path, _env) = policy_db("[terminal]\nactive = \"default\"\n");
        let nova = sender(SenderKind::Instance, "nova");
        let d = send(&db, &nova, "direct", None, None, &["kimi"]);
        assert_delivered_to_kimi(&db, &d, "direct");
        assert!(last_message(&db).1.get("delivery_reroutes").is_none());
        send(&db, &nova, "everyone", None, None, &[]);
        assert_eq!(
            unread_texts(&db, "kimi"),
            vec!["direct".to_string(), "everyone".to_string()]
        );
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn policy_marked_delegate_reroute_stops_after_one_hop() {
        let (db, path, _env) = policy_db(&format!(
            "{KIMI_POLICY}\n[delivery.deputy]\ndelegate = \"lola\"\n"
        ));
        crate::delivery_policy::register_role(&db, "mupe", "sess-mupe", "deputy").unwrap();
        let nova = sender(SenderKind::Instance, "nova");

        let d = send(&db, &nova, "hop", None, None, &["kimi"]);
        assert_rerouted_to_mupe(&db, &d, "hop");
        assert_eq!(d.effective_mentions, vec!["mupe".to_string()]);
        assert!(unread_texts(&db, "lola").is_empty());

        // mupe's own policy still applies to traffic addressed to mupe.
        let d = send(&db, &nova, "direct to mupe", None, None, &["mupe"]);
        assert_eq!(d.reroutes, vec![("mupe".to_string(), "lola".to_string())]);
        assert_eq!(unread_texts(&db, "mupe"), vec!["hop".to_string()]);
        cleanup_test_db(path);
    }

    #[test]
    #[serial]
    fn thread_members_follow_the_policy() {
        let (db, path, _env) = policy_db(KIMI_POLICY);
        db.add_thread_memberships("ops", None, &["kimi".to_string(), "lola".to_string()]);
        let envelope = MessageEnvelope {
            thread: Some("ops".into()),
            ..Default::default()
        };
        let d = send_message_resolved(
            &db,
            &sender(SenderKind::Instance, "nova"),
            "thread update",
            Some(&envelope),
            None,
        )
        .unwrap();
        assert!(d.is_thread_resolved);
        assert_eq!(d.reroutes, vec![("kimi".to_string(), "mupe".to_string())]);
        assert!(unread_texts(&db, "kimi").is_empty());
        assert!(unread_texts(&db, "mupe").contains(&"thread update".to_string()));
        assert!(unread_texts(&db, "lola").contains(&"thread update".to_string()));
        cleanup_test_db(path);
    }
}
