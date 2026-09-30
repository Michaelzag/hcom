//! Event append/read methods and message delivery queries.

use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use super::{HcomDb, chrono_now_iso, subscriptions};
use crate::delivery_policy::{
    FORWARD_OF_FIELD, ForwardFailure, KV_EXTERNAL_AUDITED_PREFIX, KV_FORWARD_ATTEMPTS_PREFIX,
    KV_FORWARD_FAILED_PREFIX, KV_FORWARD_HANDLED_PREFIX, KV_FORWARDED_PREFIX, MAX_FORWARD_ATTEMPTS,
    REROUTES_FIELD, ReadVerdict, Registration,
};

/// What became of one refused event on this read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardOutcome {
    /// The delegate has it (now, or from an earlier reader): the holder skips
    /// it. `cursor_advanced`: this read also moved the holder's cursor past it.
    Forwarded { cursor_advanced: bool },
    /// Not yet (a locked database): expose nothing at or past it; the next
    /// read retries.
    Retry,
    /// The forward failed for good: the holder gets it (logged, and shown by
    /// `hcom status`) so it is never lost and never wedges the inbox.
    DeliverToHolder,
}

/// One refused stored message event: its local id, its row timestamp (for a
/// relayed row, the sender's own timestamp) and its data.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RefusedEvent<'a> {
    pub id: i64,
    pub timestamp: &'a str,
    pub data: &'a serde_json::Value,
}

impl RefusedEvent<'_> {
    /// `<device>:<relay id>:<sender timestamp>` for a relayed row: stable
    /// across our own re-import (new rowid, same remote id and timestamp),
    /// new when a reset peer reuses an old id. `None` for a local row.
    fn relay_origin(&self) -> Option<String> {
        let relay = self.data.get("_relay")?;
        let device = relay.get("device")?.as_str()?;
        let id = relay.get("id")?;
        Some(format!(
            "{device}:{}:{}",
            id.to_string().trim_matches('"'),
            self.timestamp
        ))
    }
}

/// The per-holder kv keys of one refused message: `<holder>:<origin>`, where
/// origin is the relay origin for a relayed row and the local id otherwise
/// (so a relay id-regression re-import is the same message).
struct ForwardKeys {
    origin: String,
    /// Also the in-process retry map key.
    holder_origin: String,
    handled: String,
    failed: String,
    attempts: String,
}

impl ForwardKeys {
    fn new(holder: &str, event: RefusedEvent<'_>) -> Self {
        let origin = event.relay_origin().unwrap_or_else(|| event.id.to_string());
        let holder_origin = format!("{holder}:{origin}");
        Self {
            handled: format!("{KV_FORWARD_HANDLED_PREFIX}{holder_origin}"),
            failed: format!("{KV_FORWARD_FAILED_PREFIX}{holder_origin}"),
            attempts: format!("{KV_FORWARD_ATTEMPTS_PREFIX}{holder_origin}"),
            origin,
            holder_origin,
        }
    }
}

/// What the forward transaction did.
enum Committed {
    /// The holder's registered row changed under this read: nothing written.
    HolderChanged,
    /// Another reader already gave this refusal to the holder: no claim.
    AlreadyFailed,
    /// No single live row matches the delegate: the failure is recorded, no
    /// claim (the reason).
    DelegateUnresolved(String),
    Done {
        /// The resolved delegate; `None` when an earlier read had handled it.
        target: Option<String>,
        inserted: Vec<(i64, serde_json::Value)>,
        cursor_advanced: bool,
    },
}

/// A `Message` from one stored message event.
fn message_from_event(id: i64, timestamp: String, json: &serde_json::Value) -> Message {
    let text_field = |key: &str| json.get(key).and_then(|v| v.as_str()).map(String::from);
    Message {
        from: text_field("from").unwrap_or_else(|| "unknown".to_string()),
        text: text_field("text").unwrap_or_default(),
        intent: text_field("intent"),
        thread: text_field("thread"),
        event_id: Some(id),
        timestamp: Some(timestamp),
        delivered_to: json
            .get("delivered_to")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            }),
        bundle_id: text_field("bundle_id"),
        relay: json
            .get("_relay")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    }
}

/// Retry state of one refused message's forward to one delegate, per
/// process, keyed like the claim (`<delegate>:<origin>`).
#[derive(Clone)]
struct ForwardRetry {
    attempts: u32,
    next_try: std::time::Instant,
    /// Given up (the reason), remembered here too in case the database was
    /// too locked to record it: the holder keeps getting it, never a late
    /// forward on top.
    gave_up: Option<String>,
}

type ForwardRetries = std::collections::HashMap<(std::path::PathBuf, String), ForwardRetry>;

static FORWARD_RETRIES: std::sync::LazyLock<std::sync::Mutex<ForwardRetries>> =
    std::sync::LazyLock::new(Default::default);

fn forward_retries() -> std::sync::MutexGuard<'static, ForwardRetries> {
    FORWARD_RETRIES.lock().unwrap_or_else(|e| e.into_inner())
}

/// First retry delay after a failed forward; doubles per attempt, capped at
/// a minute, so a pending gate polling the holder never spins on it.
#[cfg(not(test))]
const FORWARD_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
const FORWARD_BACKOFF_BASE: std::time::Duration = std::time::Duration::ZERO;

/// The forward failed again: count it (in kv when the database takes the
/// write, and in process memory when it is too locked to) and schedule the
/// next try. Returns the attempt count.
fn note_failed_attempt(db: &HcomDb, forward_key: &str) -> u32 {
    let key = format!("{KV_FORWARD_ATTEMPTS_PREFIX}{forward_key}");
    let stored: u32 = db
        .kv_get(&key)
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut retries = forward_retries();
    let entry = retries
        .entry((db.path().to_path_buf(), forward_key.to_string()))
        .or_insert(ForwardRetry {
            attempts: 0,
            next_try: std::time::Instant::now(),
            gave_up: None,
        });
    entry.attempts = entry.attempts.max(stored) + 1;
    let delay = FORWARD_BACKOFF_BASE
        .saturating_mul(1 << (entry.attempts - 1).min(6))
        .min(std::time::Duration::from_secs(60));
    entry.next_try = std::time::Instant::now() + delay;
    let attempts = entry.attempts;
    drop(retries);
    let _ = db.kv_set(&key, Some(&attempts.to_string()));
    attempts
}

/// Still inside the backoff window of an earlier failed forward.
fn forward_backing_off(db: &HcomDb, forward_key: &str) -> bool {
    forward_retries()
        .get(&(db.path().to_path_buf(), forward_key.to_string()))
        .is_some_and(|retry| std::time::Instant::now() < retry.next_try)
}

/// This process gave the forward up earlier (reason).
fn forward_given_up(db: &HcomDb, forward_key: &str) -> Option<String> {
    forward_retries()
        .get(&(db.path().to_path_buf(), forward_key.to_string()))
        .and_then(|retry| retry.gave_up.clone())
}

fn mark_forward_given_up(db: &HcomDb, forward_key: &str, reason: &str) {
    if let Some(retry) =
        forward_retries().get_mut(&(db.path().to_path_buf(), forward_key.to_string()))
    {
        retry.gave_up = Some(reason.to_string());
    }
}

/// Message from the events table
#[derive(Debug, Clone)]
pub struct Message {
    pub from: String,
    pub text: String,
    pub intent: Option<String>,
    pub thread: Option<String>,
    pub event_id: Option<i64>,
    pub timestamp: Option<String>,
    pub delivered_to: Option<Vec<String>>,
    pub bundle_id: Option<String>,
    pub relay: bool,
}

impl HcomDb {
    /// Check if a message event should be delivered to the given receiver.
    ///
    /// Skips own messages. Checks scope: "broadcast" delivers to all,
    /// "mentions" checks the mentions array with cross-device base-name matching.
    ///
    /// The mentions rule itself is `messages::mentions_delivers_to`, which
    /// `messages::should_deliver_message` also calls: device-exact delivery
    /// when the event carries a non-empty `exact_targets` array (mentions
    /// resolved at send time), else the legacy base-name match for an
    /// old-format event from a peer without exact targets.
    ///
    /// `receiver` may be local (`luna`) or relay-namespaced (`luna:ABCD`).
    /// Mentions compare on base name so the same event JSON routes correctly
    /// on both local and relayed peers without rewriting stored scope.
    ///
    /// `policies` is the operator delivery policy backstop
    /// (`crate::delivery_policy`); see `delivery_verdict`. This bool form is
    /// for callers that only look (no forwarding): a refused event is not
    /// theirs to deliver.
    pub(super) fn should_deliver_to(
        json: &serde_json::Value,
        receiver: &str,
        policies: &crate::delivery_policy::Policies,
    ) -> bool {
        Self::delivery_verdict(json, receiver, policies) == ReadVerdict::Deliver
    }

    /// The scope rule, then the delivery policy for a role holder: deliver,
    /// skip (not addressed here, or a broadcast to a role holder), or forward
    /// a targeted message the holder refuses to its delegate.
    pub(super) fn delivery_verdict(
        json: &serde_json::Value,
        receiver: &str,
        policies: &crate::delivery_policy::Policies,
    ) -> ReadVerdict {
        let from = json.get("from").and_then(|v| v.as_str()).unwrap_or("");
        if from == receiver {
            return ReadVerdict::Skip;
        }
        let scope = json
            .get("scope")
            .and_then(|s| s.as_str())
            .unwrap_or("broadcast");
        let in_scope = match scope {
            "broadcast" => true,
            "mentions" => crate::messages::mentions_delivers_to(json, receiver),
            _ => false,
        };
        if !in_scope {
            return ReadVerdict::Skip;
        }
        policies.read_verdict(receiver, json)
    }

    /// Returns true iff there is at least one unread message that names this
    /// instance directly (`scope='mentions'` and the recipient is in the
    /// `mentions` array). Broadcasts are ignored.
    ///
    /// Used to gate dormant subagent activation: a SubagentStart-allocated
    /// row is in the broadcast recipient set, but we don't want a passing
    /// broadcast to wake a subagent nobody actually addressed. A cheap check:
    /// it never forwards (role holders are top-level seats, whose reads go
    /// through `scan_unread`).
    pub fn has_direct_unread(&self, name: &str) -> bool {
        let last_event_id = match self.get_instance_status(name) {
            Ok(Some(status)) => status.last_event_id,
            _ => 0,
        };
        let Ok(policies) = crate::delivery_policy::load(self) else {
            return false;
        };
        let mut stmt = match self.conn.prepare_cached(
            "SELECT data FROM events
             WHERE id > ? AND type = 'message'
             ORDER BY id",
        ) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let rows = match stmt.query_map(params![last_event_id], |row| row.get::<_, String>(0)) {
            Ok(r) => r,
            Err(_) => return false,
        };
        for data in rows.flatten() {
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) else {
                continue;
            };
            let scope = json
                .get("scope")
                .and_then(|s| s.as_str())
                .unwrap_or("broadcast");
            if scope != "mentions" {
                continue;
            }
            if Self::should_deliver_to(&json, name, &policies) {
                return true;
            }
        }
        false
    }

    /// The unread message events `name` may read, as `(id, timestamp, data)`,
    /// in id order. This is the consuming read: for a role holder it forwards
    /// every targeted message the holder refuses (`forward_refused`), and it
    /// stops before a refused event whose forward has not committed yet, so no
    /// ack can move the cursor past it (the next read retries). `first_only`
    /// returns at the first deliverable event (the pending gate).
    ///
    /// `None` when the instance row or the policy cannot be read: deliver
    /// nothing this round, keep the cursor.
    pub(super) fn scan_unread(
        &self,
        name: &str,
        first_only: bool,
    ) -> Option<Vec<(i64, String, serde_json::Value)>> {
        // A policy that cannot be read delivers nothing instead of switching
        // the filter off.
        let policies = match crate::delivery_policy::load(self) {
            Ok(policies) => policies,
            Err(e) => {
                crate::log::log_error("db", "scan_unread.delivery_policy", &e);
                return None;
            }
        };
        // A governed holder's cursor is read from the exact row its
        // registration names, so the cursor, the verdicts and the forward's
        // re-check all describe one row. A rebind since `load` finds no row:
        // nothing this round, the next read re-evaluates.
        let registration = policies.registration(name);
        let cursor_row = match registration {
            Some(reg) => self
                .conn
                .query_row(
                    "SELECT last_event_id FROM instances
                     WHERE name = ?1 AND session_id = ?2 AND created_at = ?3",
                    params![name, reg.session_id, reg.created_at],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(anyhow::Error::from),
            // A missing/unreadable row means there is no recipient: no unread
            // rather than cursor 0, which would treat the whole channel
            // backlog (broadcasts match everyone) as unread.
            None => self
                .get_instance_status(name)
                .map(|status| status.map(|s| s.last_event_id)),
        };
        let mut cursor = match cursor_row {
            Ok(Some(cursor)) => cursor,
            Ok(None) => return None,
            Err(e) => {
                crate::log::log_error("db", "scan_unread.cursor", &format!("{e}"));
                return None;
            }
        };
        // Collected before any forward writes, so no read statement is open
        // while the forward transaction runs.
        let rows: Vec<(i64, Option<String>, String)> = {
            let mut stmt = match self.conn.prepare_cached(
                "SELECT id, timestamp, data FROM events
                 WHERE id > ? AND type = 'message'
                 ORDER BY id",
            ) {
                Ok(s) => s,
                Err(e) => {
                    crate::log::log_error("db", "scan_unread.prepare", &format!("{e}"));
                    return None;
                }
            };
            let rows = stmt.query_map(params![cursor], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            });
            match rows.and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>()) {
                Ok(rows) => rows,
                Err(e) => {
                    crate::log::log_error("db", "scan_unread.query", &format!("{e}"));
                    return None;
                }
            }
        };

        let mut deliver = Vec::new();
        // A governed holder's leading run of skipped rows (broadcasts it
        // never reads): the cursor moves past them, so they are not rescanned
        // or counted on every read.
        let mut skip_to: Option<i64> = None;
        let flush_skips = |cursor: &mut i64, skip_to: &mut Option<i64>| {
            if let (Some(to), Some(reg)) = (skip_to.take(), registration)
                && self.advance_holder_cursor(name, reg, *cursor, to)
            {
                *cursor = to;
            }
        };
        for (id, timestamp, data) in rows {
            let timestamp = timestamp.unwrap_or_default();
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) else {
                continue;
            };
            match Self::delivery_verdict(&json, name, &policies) {
                ReadVerdict::Skip => {
                    if registration.is_some() && deliver.is_empty() {
                        skip_to = Some(id);
                    }
                    continue;
                }
                ReadVerdict::Deliver => {
                    if registration.is_some() {
                        self.audit_relayed_external(
                            name,
                            RefusedEvent {
                                id,
                                timestamp: &timestamp,
                                data: &json,
                            },
                        );
                    }
                    deliver.push((id, timestamp, json))
                }
                ReadVerdict::ForwardTo(delegate) => {
                    // With nothing deliverable before it, the forward also
                    // moves the cursor past it in the same transaction.
                    flush_skips(&mut cursor, &mut skip_to);
                    let advance_from = deliver.is_empty().then_some(cursor);
                    let outcome = match registration {
                        Some(reg) => {
                            let event = RefusedEvent {
                                id,
                                timestamp: &timestamp,
                                data: &json,
                            };
                            self.forward_refused(name, event, &delegate, advance_from, reg)
                        }
                        // ForwardTo comes only for a governed holder.
                        None => ForwardOutcome::Retry,
                    };
                    match outcome {
                        ForwardOutcome::Forwarded { cursor_advanced } => {
                            if cursor_advanced {
                                cursor = id;
                            }
                            continue;
                        }
                        ForwardOutcome::Retry => break,
                        ForwardOutcome::DeliverToHolder => deliver.push((id, timestamp, json)),
                    }
                }
            }
            if first_only && !deliver.is_empty() {
                break;
            }
        }
        flush_skips(&mut cursor, &mut skip_to);
        Some(deliver)
    }

    /// Compare-and-set a governed holder's cursor from `from` to `to`, only
    /// while its registered row is still the one that read them.
    fn advance_holder_cursor(&self, name: &str, reg: &Registration, from: i64, to: i64) -> bool {
        self.conn
            .execute(
                "UPDATE instances SET last_event_id = ?1
                 WHERE name = ?2 AND last_event_id = ?3 AND session_id = ?4 AND created_at = ?5",
                params![to, name, from, reg.session_id, reg.created_at],
            )
            .is_ok_and(|n| n == 1)
    }

    /// An External sender on another host reached a governed holder (the
    /// unauthenticated `--from` bypass). That host cannot know the role
    /// (roles never relay), so the holder's host writes the audit line, once
    /// per message (a kv marker, `INSERT OR IGNORE`), however often it is
    /// read. Local External sends are audited when they are sent.
    fn audit_relayed_external(&self, holder: &str, event: RefusedEvent<'_>) {
        if event.data.get("sender_kind").and_then(|v| v.as_str()) != Some("external") {
            return;
        }
        let Some(origin) = event.relay_origin() else {
            return;
        };
        let key = format!("{KV_EXTERNAL_AUDITED_PREFIX}{holder}:{origin}");
        // Read first: this runs on every holder read (the pty gate too), and
        // even an ignored INSERT takes the write lock.
        if !matches!(self.kv_get(&key), Ok(None)) {
            return;
        }
        let first = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO kv (key, value) VALUES (?1, ?2)",
                params![key, event.id.to_string()],
            )
            .is_ok_and(|n| n == 1);
        if first {
            let from = event
                .data
                .get("from")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            crate::log::log_with_fields(
                "INFO",
                "delivery_policy",
                "external_reached",
                &format!("External sender '{from}' reached policy instance {holder}"),
                &[("event_id", &event.id.to_string()), ("origin", &origin)],
            );
        }
    }

    /// Get unread messages for an instance
    ///
    /// Returns messages where:
    /// - event.id > instance.last_event_id
    /// - event.type = 'message'
    /// - instance is in scope (broadcast or direct), through the delivery
    ///   policy (`scan_unread`)
    pub fn get_unread_messages(&self, name: &str) -> Vec<Message> {
        self.scan_unread(name, false)
            .unwrap_or_default()
            .into_iter()
            .map(|(id, timestamp, json)| message_from_event(id, timestamp, &json))
            .collect()
    }

    /// Forward one targeted message the role holder `holder` refuses to its
    /// `delegate` (crate::delivery_policy): zori's ruling is that nothing sent
    /// to the conductor is dropped silently.
    ///
    /// One IMMEDIATE transaction:
    /// - re-checks that the holder's registered row (name, session id,
    ///   created_at) is still there and live; a stop or rebind that landed
    ///   meanwhile writes nothing and the next read re-evaluates;
    /// - checks `delivery_forward_handled:<holder>:<origin>` FIRST: a refusal
    ///   already forwarded is never re-decided (a delegate that has since
    ///   stopped must not turn it into a duplicate for the holder);
    /// - otherwise resolves the delegate against the rows it sees. No single
    ///   live row: no claim, a failure record, and the holder keeps the
    ///   message (a new delegate row starts at the current cursor, so
    ///   parking it for the delegate would lose it);
    /// - claims `delivery_forwarded:<resolved delegate>:<origin>` with
    ///   `INSERT OR IGNORE` (the primary key makes one copy per delegate and
    ///   message, however many holders or readers race, however each holder
    ///   spells the delegate) and only if that inserted writes the forward
    ///   copy and, for an instance sender, a notice to that sender;
    /// - with `advance_from`, moves the holder's cursor from that value to
    ///   this event (compare-and-set).
    ///
    /// Subscription dispatch, wakes and the relay push run after commit.
    ///
    /// Runs only on the host where the holder's role is registered (roles are
    /// never relayed), so one host forwards; the copy relayed onward carries
    /// the forward mark and is never refused or forwarded again.
    ///
    /// The kv rows are never pruned: a few small rows per forwarded message,
    /// and forwards happen only for refused targeted messages that skipped
    /// the send-time reroute (older peers, system notices). Pruning below the
    /// holder's cursor would break the re-import dedupe, since a re-imported
    /// relayed row gets a new id above the cursor.
    pub(crate) fn forward_refused(
        &self,
        holder: &str,
        event: RefusedEvent<'_>,
        delegate: &str,
        advance_from: Option<i64>,
        registration: &Registration,
    ) -> ForwardOutcome {
        let (event_id, data) = (event.id, event.data);
        let keys = ForwardKeys::new(holder, event);
        let origin = keys.origin.as_str();
        let relay = data.get("_relay");
        // The sender's own reference to its message: the relayed id and
        // device for a message from another host, else the local id.
        let message_ref = match (
            relay.and_then(|r| r.get("id")),
            relay.and_then(|r| r.get("short")).and_then(|v| v.as_str()),
        ) {
            (Some(id), Some(short)) => format!("#{}:{short}", id.to_string().trim_matches('"')),
            _ => format!("#{event_id}"),
        };
        let failure = |reason: &str| {
            serde_json::to_string(&ForwardFailure {
                holder: holder.to_string(),
                delegate: delegate.to_string(),
                message: message_ref.clone(),
                reason: reason.to_string(),
            })
            .unwrap_or_default()
        };
        // The handled marker is final: once any reader forwarded this
        // refusal, nothing here may re-decide it (a later give-up or an
        // unresolved delegate would hand the holder a message the delegate
        // already has). Read first, before the failure record.
        let handled = |db: &Self| db.kv_get(&keys.handled).ok().flatten().is_some();
        if advance_from.is_none() && handled(self) {
            return ForwardOutcome::Forwarded {
                cursor_advanced: false,
            };
        }
        if self.kv_get(&keys.failed).ok().flatten().is_some() {
            return ForwardOutcome::DeliverToHolder;
        }
        if let Some(reason) = forward_given_up(self, &keys.holder_origin) {
            if handled(self) {
                return ForwardOutcome::Forwarded {
                    cursor_advanced: false,
                };
            }
            // Given up while the database was too locked to record it.
            let _ = self.kv_set(&keys.failed, Some(&failure(&reason)));
            return ForwardOutcome::DeliverToHolder;
        }
        if forward_backing_off(self, &keys.holder_origin) {
            return ForwardOutcome::Retry;
        }
        // Bare-name context for resolving the delegate (config only, read
        // outside the transaction).
        let fleet = crate::fleet_names::FleetCtx::load();

        let text = |key: &str| data.get(key).and_then(|v| v.as_str());
        let from = text("from").unwrap_or("");
        // The copy's own sender is hcom, never the original sender: a peer's
        // self-skip (`from == receiver`) must not hide it. The original
        // sender travels as data and at the head of the text.
        let make_copy = |target: &str| {
            let mut copy = serde_json::json!({
                "from": "[hcom-delivery]",
                "sender_kind": "system",
                "scope": "mentions",
                "mentions": [target],
                "exact_targets": [target],
                "delivered_to": [target],
                "text": format!("[{from} → {holder}, forwarded] {}", text("text").unwrap_or("")),
                "delivery_forward_of_from": from,
                "delivery_forward_of_sender_kind": data.get("sender_kind").cloned().unwrap_or(serde_json::Value::Null),
                "delivery_forward_of_origin": origin,
            });
            copy[FORWARD_OF_FIELD] = serde_json::json!(event_id);
            let mut reroute = serde_json::Map::new();
            reroute.insert(holder.to_string(), serde_json::json!(target));
            copy[REROUTES_FIELD] = serde_json::Value::Object(reroute);
            for key in [
                "intent",
                "thread",
                "bundle_id",
                "reply_to",
                "reply_to_local",
            ] {
                if let Some(value) = data.get(key) {
                    copy[key] = value.clone();
                }
            }
            copy
        };
        // `from` of a relayed message is already namespaced (`valo:GIDU`),
        // so the notice relays back to that host.
        let wants_notice = text("sender_kind") == Some("instance") && !from.is_empty();
        let make_notice = |target: &str| {
            serde_json::json!({
                "from": "[hcom-delivery]",
                "sender_kind": "system",
                "scope": "mentions",
                "mentions": [from],
                "exact_targets": [from],
                "delivered_to": [from],
                "text": format!("{holder} takes no cc; delivered to {target} (your message {message_ref})"),
                "delivery_notice_for": origin,
            })
        };
        const INSTANCE: &str = "sys_[hcom-delivery]";

        let committed = (|| -> rusqlite::Result<Committed> {
            let tx = rusqlite::Transaction::new_unchecked(
                &self.conn,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let same_row = tx
                .query_row(
                    &format!(
                        "SELECT 1 FROM instances
                         WHERE name = ?1 AND session_id = ?2 AND created_at = ?3 AND {}",
                        crate::fleet_names::LIVE_ROW_PREDICATE
                    ),
                    params![holder, registration.session_id, registration.created_at],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !same_row {
                return Ok(Committed::HolderChanged);
            }
            let handled = tx
                .query_row(
                    "SELECT 1 FROM kv WHERE key = ?1",
                    params![keys.handled],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            let mut inserted = Vec::new();
            let mut target = None;
            if !handled {
                // Another reader already gave this refusal to the holder:
                // that stays the decision (no claim, no copy).
                let failed = tx
                    .query_row(
                        "SELECT 1 FROM kv WHERE key = ?1",
                        params![keys.failed],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if failed {
                    return Ok(Committed::AlreadyFailed);
                }
                // Resolved inside the transaction, against the rows it sees.
                let rows = crate::messages::deliverable_instances(&tx)?;
                let resolved =
                    match crate::delivery_policy::resolve_delegate(delegate, &rows, &fleet) {
                        Ok(resolved) => resolved,
                        Err(why) => {
                            let reason = why.describe(&format!("delegate {delegate}"));
                            tx.execute(
                                "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
                                params![keys.failed, failure(&reason)],
                            )?;
                            tx.commit()?;
                            return Ok(Committed::DelegateUnresolved(reason));
                        }
                    };
                let claimed = tx.execute(
                    "INSERT OR IGNORE INTO kv (key, value) VALUES (?1, ?2)",
                    params![
                        format!("{KV_FORWARDED_PREFIX}{resolved}:{origin}"),
                        event_id.to_string()
                    ],
                )? == 1;
                if claimed {
                    let ts = chrono_now_iso();
                    let copy = make_copy(&resolved);
                    let notice = wants_notice.then(|| make_notice(&resolved));
                    for event in std::iter::once(copy).chain(notice) {
                        tx.execute(
                            "INSERT INTO events (timestamp, type, instance, data) VALUES (?, 'message', ?, ?)",
                            params![ts, INSTANCE, event.to_string()],
                        )?;
                        inserted.push((tx.last_insert_rowid(), event));
                    }
                }
                tx.execute(
                    "INSERT OR IGNORE INTO kv (key, value) VALUES (?1, ?2)",
                    params![keys.handled, resolved],
                )?;
                tx.execute("DELETE FROM kv WHERE key = ?1", params![keys.attempts])?;
                target = Some(resolved);
            }
            let cursor_advanced = match advance_from {
                Some(expected) => {
                    tx.execute(
                        "UPDATE instances SET last_event_id = ?1
                         WHERE name = ?2 AND last_event_id = ?3",
                        params![event_id, holder, expected],
                    )? == 1
                }
                None => false,
            };
            tx.commit()?;
            Ok(Committed::Done {
                target,
                inserted,
                cursor_advanced,
            })
        })();

        match committed {
            Ok(Committed::HolderChanged) => ForwardOutcome::Retry,
            Ok(Committed::AlreadyFailed) => ForwardOutcome::DeliverToHolder,
            Ok(Committed::DelegateUnresolved(reason)) => {
                forward_retries().remove(&(self.path().to_path_buf(), keys.holder_origin));
                crate::log::log_warn(
                    "delivery_policy",
                    "delegate_unresolved",
                    &format!("{reason}; {holder} keeps event {event_id}"),
                );
                ForwardOutcome::DeliverToHolder
            }
            Ok(Committed::Done {
                target,
                inserted,
                cursor_advanced,
            }) => {
                forward_retries().remove(&(self.path().to_path_buf(), keys.holder_origin));
                for (id, event) in &inserted {
                    subscriptions::process_logged_event(self, *id, "message", INSTANCE, event);
                }
                if let Some(target) = target.filter(|_| !inserted.is_empty()) {
                    crate::log::log_with_fields(
                        "INFO",
                        "delivery_policy",
                        "forwarded",
                        &format!("{holder} refused event {event_id}; forwarded to {target}"),
                        &[("event_id", &event_id.to_string()), ("from", from)],
                    );
                    crate::notify::wake(self, &target, &[]);
                    if wants_notice {
                        crate::notify::wake(self, from, &[]);
                    }
                    crate::relay::trigger_push();
                }
                ForwardOutcome::Forwarded { cursor_advanced }
            }
            // Another reader forwarded it meanwhile (a plain read works under
            // a held write lock in WAL): it is handled, never counted as a
            // failed attempt or given up to the holder. Only the cursor move
            // is missed; the next read skips it.
            Err(_) if handled(self) => ForwardOutcome::Forwarded {
                cursor_advanced: false,
            },
            Err(e) => {
                let transient = matches!(
                    &e,
                    rusqlite::Error::SqliteFailure(err, _)
                        if matches!(
                            err.code,
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                        )
                );
                let attempts = note_failed_attempt(self, &keys.holder_origin);
                if transient && attempts < MAX_FORWARD_ATTEMPTS {
                    if attempts == 1 {
                        crate::log::log_warn(
                            "delivery_policy",
                            "forward_retry",
                            &format!(
                                "forward of event {event_id} from {holder} to {delegate} failed ({e}); retrying with backoff"
                            ),
                        );
                    }
                    return ForwardOutcome::Retry;
                }
                let reason = format!("{e} (after {attempts} attempt(s))");
                mark_forward_given_up(self, &keys.holder_origin, &reason);
                let _ = self.kv_set(&keys.failed, Some(&failure(&reason)));
                crate::log::log_warn(
                    "delivery_policy",
                    "forward_failed",
                    &format!(
                        "could not forward event {event_id} from {holder} to {delegate}: {reason}; delivering it to {holder} instead"
                    ),
                );
                ForwardOutcome::DeliverToHolder
            }
        }
    }

    /// Whether the holder will itself receive a message it refuses (a
    /// recorded failure, or a delegate with no single live row), without
    /// writing anything: `hcom list`'s count of what the holder will read.
    pub(crate) fn refused_reaches_holder(
        &self,
        holder: &str,
        event: RefusedEvent<'_>,
        delegate: &str,
        rows: &[crate::messages::InstanceInfo],
        fleet: &crate::fleet_names::FleetCtx,
    ) -> bool {
        let keys = ForwardKeys::new(holder, event);
        if self.kv_get(&keys.failed).ok().flatten().is_some() {
            return true;
        }
        if self.kv_get(&keys.handled).ok().flatten().is_some() {
            return false;
        }
        crate::delivery_policy::resolve_delegate(delegate, rows, fleet).is_err()
    }

    /// Build the shared envelope every launch-lifecycle life event uses
    /// (`{action, by, status, context, [reason], [detail], [batch_id]}`) and
    /// write it to the events table. Returns `(launcher, batch_id)` so the
    /// caller can decide whether to push a follow-up notification.
    pub(crate) fn emit_launch_lifecycle_event(
        &self,
        name: &str,
        action: &str,
        status: &str,
        context: &str,
        reason: Option<&str>,
        detail: Option<&str>,
    ) -> Result<(String, Option<String>)> {
        let launcher = std::env::var("HCOM_LAUNCHED_BY").unwrap_or_else(|_| "unknown".to_string());
        let batch_id = std::env::var("HCOM_LAUNCH_BATCH_ID").ok();

        let mut event_data = serde_json::json!({
            "action": action,
            "by": &launcher,
            "status": status,
            "context": context,
        });
        if let Some(reason) = reason.filter(|s| !s.is_empty()) {
            event_data["reason"] = serde_json::Value::String(reason.to_string());
        }
        if let Some(detail) = detail.filter(|s| !s.is_empty()) {
            event_data["detail"] = serde_json::Value::String(detail.to_string());
        }
        if let Some(ref bid) = batch_id {
            event_data["batch_id"] = serde_json::Value::String(bid.clone());
        }

        self.log_event_with_ts("life", name, &event_data, None)?;
        Ok((launcher, batch_id))
    }

    /// Emit "ready" life event and check for batch completion notification.
    ///
    /// Called on first status update (when status_context was "new").
    pub(crate) fn emit_ready_event(&self, name: &str, status: &str, context: &str) -> Result<()> {
        let (launcher, batch_id) =
            self.emit_launch_lifecycle_event(name, "ready", status, context, None, None)?;
        if launcher != "unknown"
            && let Some(ref bid) = batch_id
        {
            self.check_batch_completion(&launcher, bid)?;
        }
        Ok(())
    }

    pub(crate) fn emit_launch_failed_event(
        &self,
        name: &str,
        status: &str,
        context: &str,
        reason: &str,
        detail: &str,
    ) -> Result<()> {
        let (launcher, batch_id) = self.emit_launch_lifecycle_event(
            name,
            "launch_failed",
            status,
            context,
            Some(reason),
            Some(detail),
        )?;
        if launcher != "unknown"
            && let Some(ref bid) = batch_id
        {
            let notify_detail = if detail.is_empty() { reason } else { detail };
            self.notify_batch_failure(&launcher, bid, name, notify_detail)?;
        }
        Ok(())
    }

    pub(crate) fn emit_launch_blocked_event(
        &self,
        name: &str,
        status: &str,
        context: &str,
        reason: &str,
        detail: &str,
    ) -> Result<()> {
        self.emit_launch_lifecycle_event(
            name,
            "launch_blocked",
            status,
            context,
            Some(reason),
            Some(detail),
        )?;
        Ok(())
    }

    /// Check if all instances in a launch batch are ready; send notification if so.
    pub fn check_batch_completion(&self, launcher: &str, batch_id: &str) -> Result<()> {
        // Find the launch event for this batch
        let launch_data: Option<String> = self
            .conn
            .query_row(
                "SELECT data FROM events
             WHERE type = 'life' AND instance = ?
               AND json_extract(data, '$.action') = 'batch_launched'
               AND json_extract(data, '$.batch_id') = ?
             LIMIT 1",
                params![launcher, batch_id],
                |row| row.get(0),
            )
            .ok();

        let Some(data_str) = launch_data else {
            return Ok(());
        };
        let data: serde_json::Value = serde_json::from_str(&data_str)?;
        let expected = data.get("launched").and_then(|v| v.as_u64()).unwrap_or(0);
        if expected == 0 {
            return Ok(());
        }

        // Count ready events with matching batch_id
        let ready_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events
             WHERE type = 'life'
               AND json_extract(data, '$.action') = 'ready'
               AND json_extract(data, '$.batch_id') = ?",
            params![batch_id],
            |row| row.get(0),
        )?;

        if (ready_count as u64) < expected {
            return Ok(());
        }

        // Check idempotency — don't send duplicate notification
        let already_sent: bool = self.conn.query_row(
            "SELECT COUNT(*) FROM events
             WHERE type = 'message'
               AND instance = 'sys_[hcom-launcher]'
               AND json_extract(data, '$.text') LIKE ?
             LIMIT 1",
            params![format!("%batch: {}%", batch_id)],
            |row| Ok(row.get::<_, i64>(0)? > 0),
        )?;

        if already_sent {
            return Ok(());
        }

        // Get instance names from this batch
        let mut stmt = self.conn.prepare_cached(
            "SELECT DISTINCT instance FROM events
             WHERE type = 'life'
               AND json_extract(data, '$.action') = 'ready'
               AND json_extract(data, '$.batch_id') = ?",
        )?;
        let names: Vec<String> = stmt
            .query_map(params![batch_id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();

        let instances_list = names.join(", ");
        let text = format!(
            "@{} All {} instances ready: {} (batch: {})",
            launcher, expected, instances_list, batch_id
        );

        // Insert system message
        let msg_data = serde_json::json!({
            "from": "[hcom-launcher]",
            "text": text,
            "scope": "mentions",
            "mentions": [launcher],
            "sender_kind": "system",
        });
        self.log_event_with_ts("message", "sys_[hcom-launcher]", &msg_data, None)?;

        Ok(())
    }

    /// Send a launcher-targeted notification for a failed launch instance.
    ///
    /// Used for early PTY startup failures so the launcher gets an active signal
    /// instead of having to poll `events launch`.
    pub fn notify_batch_failure(
        &self,
        launcher: &str,
        batch_id: &str,
        instance_name: &str,
        detail: &str,
    ) -> Result<()> {
        let text = format!(
            "@{} Launch failed: {}: {} (batch: {})",
            launcher, instance_name, detail, batch_id
        );

        let already_sent: bool = self.conn.query_row(
            "SELECT COUNT(*) FROM events
             WHERE type = 'message'
               AND instance = 'sys_[hcom-launcher]'
               AND json_extract(data, '$.text') = ?
             LIMIT 1",
            params![text],
            |row| Ok(row.get::<_, i64>(0)? > 0),
        )?;

        if already_sent {
            return Ok(());
        }

        let msg_data = serde_json::json!({
            "from": "[hcom-launcher]",
            "text": text,
            "scope": "mentions",
            "mentions": [launcher],
            "sender_kind": "system",
        });
        self.log_event_with_ts("message", "sys_[hcom-launcher]", &msg_data, None)?;

        Ok(())
    }

    /// Log a life event (started/stopped) to the events table.
    ///
    /// `process_id` keys the event to one process incarnation of the
    /// instance: a `stopped` only releases the row when it equals the row's
    /// current binding (see `finalize_instance_stop`). `None` records null
    /// (writer outside any harness, e.g. legacy paths).
    pub fn log_life_event(
        &self,
        instance: &str,
        action: &str,
        by: &str,
        reason: &str,
        snapshot: Option<serde_json::Value>,
        process_id: Option<&str>,
    ) -> Result<()> {
        let data = match snapshot {
            Some(s) => serde_json::json!({
                "action": action,
                "by": by,
                "reason": reason,
                "process_id": process_id,
                "snapshot": s
            }),
            None => serde_json::json!({
                "action": action,
                "by": by,
                "reason": reason,
                "process_id": process_id
            }),
        };

        self.log_event_with_ts("life", instance, &data, None)?;

        Ok(())
    }

    /// [`log_life_event`] with the fan-out's TCP wakes collected into `post`
    /// instead of connected: the event row and every follow-up write run
    /// inline (joining the caller's write txn when there is one), so call
    /// this at the insertion point inside a write txn and run
    /// [`PostCommit::fire`](crate::hooks::common::PostCommit::fire) only
    /// after that txn commits.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn log_life_event_collected(
        &self,
        instance: &str,
        action: &str,
        by: &str,
        reason: &str,
        snapshot: Option<serde_json::Value>,
        process_id: Option<&str>,
        post: &mut crate::hooks::common::PostCommit,
    ) -> Result<()> {
        let data = match snapshot {
            Some(s) => serde_json::json!({
                "action": action,
                "by": by,
                "reason": reason,
                "process_id": process_id,
                "snapshot": s
            }),
            None => serde_json::json!({
                "action": action,
                "by": by,
                "reason": reason,
                "process_id": process_id
            }),
        };

        self.log_event_collected("life", instance, &data, post)?;

        Ok(())
    }

    /// Insert event and return its ID. Calls subscription check inline.
    pub fn log_event(
        &self,
        event_type: &str,
        instance: &str,
        data: &serde_json::Value,
    ) -> Result<i64> {
        self.log_event_with_ts(event_type, instance, data, None)
    }

    /// Insert an event row with an optional timestamp. Pure INSERT: no
    /// subscription fan-out, so this is safe to call while the caller holds
    /// a write transaction on the same connection. Returns the event ID.
    pub fn insert_event_row(
        &self,
        event_type: &str,
        instance: &str,
        data: &serde_json::Value,
        timestamp: Option<&str>,
    ) -> Result<i64> {
        let ts = match timestamp {
            Some(t) => t.to_string(),
            None => chrono_now_iso(),
        };
        let data_str = serde_json::to_string(data)?;

        self.conn.execute(
            "INSERT INTO events (timestamp, type, instance, data) VALUES (?, ?, ?, ?)",
            params![ts, event_type, instance, data_str],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Insert event and return its ID, with the fan-out's TCP wakes collected
    /// into `post` instead of connected: the event row and every follow-up
    /// write run inline (joining the caller's write txn when there is one),
    /// so call this at the insertion point inside a write txn and run
    /// [`PostCommit::fire`](crate::hooks::common::PostCommit::fire) only
    /// after that txn commits.
    pub(crate) fn log_event_collected(
        &self,
        event_type: &str,
        instance: &str,
        data: &serde_json::Value,
        post: &mut crate::hooks::common::PostCommit,
    ) -> Result<i64> {
        let event_id = self.insert_event_row(event_type, instance, data, None)?;
        subscriptions::process_logged_event_collected(
            self, event_id, event_type, instance, data, post,
        );
        Ok(event_id)
    }

    /// Subscription fan-out for an already-durable event row: TCP wakes,
    /// follow-up messages, kv cursor writes. Best-effort external effects —
    /// call only AFTER the write transaction commits, never under one. (The
    /// in-txn counterpart is [`Self::log_event_collected`], which defers only
    /// the TCP connects into a PostCommit.)
    pub(crate) fn dispatch_logged_event(
        &self,
        event_id: i64,
        event_type: &str,
        instance: &str,
        data: &serde_json::Value,
    ) {
        subscriptions::process_logged_event(self, event_id, event_type, instance, data);
    }

    /// Insert event with optional timestamp. Returns event ID.
    pub fn log_event_with_ts(
        &self,
        event_type: &str,
        instance: &str,
        data: &serde_json::Value,
        timestamp: Option<&str>,
    ) -> Result<i64> {
        let event_id = self.insert_event_row(event_type, instance, data, timestamp)?;
        self.dispatch_logged_event(event_id, event_type, instance, data);
        Ok(event_id)
    }

    /// Diagnostic-only: `writer` field of the most recent "status" event
    /// logged for an instance (set_status's `#[track_caller]` file:line).
    pub fn last_status_writer(&self, instance: &str) -> Option<String> {
        let data: String = self
            .conn
            .query_row(
                "SELECT data FROM events WHERE instance = ? AND type = 'status' ORDER BY id DESC LIMIT 1",
                params![instance],
                |row| row.get(0),
            )
            .ok()?;
        serde_json::from_str::<serde_json::Value>(&data)
            .ok()?
            .get("writer")
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// Get events since a given ID with optional filters.
    pub fn get_events_since(
        &self,
        last_event_id: i64,
        event_type: Option<&str>,
        instance: Option<&str>,
    ) -> Result<Vec<serde_json::Value>> {
        let mut query =
            "SELECT id, timestamp, type, instance, data FROM events WHERE id > ?".to_string();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(last_event_id)];

        if let Some(et) = event_type {
            query.push_str(" AND type = ?");
            param_values.push(Box::new(et.to_string()));
        }
        if let Some(inst) = instance {
            query.push_str(" AND instance = ?");
            param_values.push(Box::new(inst.to_string()));
        }
        query.push_str(" ORDER BY id");

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let id: i64 = row.get(0)?;
                let timestamp: String = row.get(1)?;
                let etype: String = row.get(2)?;
                let inst: String = row.get(3)?;
                let data_str: String = row.get(4)?;
                Ok((id, timestamp, etype, inst, data_str))
            })?
            .filter_map(|r| r.ok())
            .map(|(id, timestamp, etype, inst, data_str)| {
                let data: serde_json::Value =
                    serde_json::from_str(&data_str).unwrap_or(serde_json::Value::Null);
                serde_json::json!({
                    "id": id,
                    "timestamp": timestamp,
                    "type": etype,
                    "instance": inst,
                    "data": data,
                })
            })
            .collect();
        Ok(rows)
    }

    /// Get current maximum event ID, or 0 if no events.
    pub fn get_last_event_id(&self) -> i64 {
        self.conn
            .query_row("SELECT MAX(id) FROM events", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .unwrap_or(None)
            .unwrap_or(0)
    }

    /// Log a status event to the events table
    ///
    /// Used by TranscriptWatcher to log tool:apply_patch, tool:shell, and prompt events.
    pub fn log_status_event(
        &self,
        instance: &str,
        status: &str,
        context: &str,
        detail: Option<&str>,
        timestamp: Option<&str>,
    ) -> Result<()> {
        // Build data JSON
        let data = match detail {
            Some(d) => serde_json::json!({
                "status": status,
                "context": context,
                "detail": d
            }),
            None => serde_json::json!({
                "status": status,
                "context": context
            }),
        };

        self.log_event_with_ts("status", instance, &data, timestamp)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{cleanup_test_db, setup_full_test_db};

    #[test]
    fn test_log_event_returns_id() {
        let (db, db_path) = setup_full_test_db();

        let data = serde_json::json!({"status": "active", "context": "test"});
        let id1 = db.log_event("status", "luna", &data).unwrap();
        let id2 = db.log_event("status", "luna", &data).unwrap();

        assert!(id1 > 0);
        assert_eq!(id2, id1 + 1);

        cleanup_test_db(db_path);
    }

    // Regression: a missing recipient must yield no unread messages, not the whole
    // backlog (broadcasts match every recipient when the cursor falls back to 0).
    #[test]
    fn test_get_unread_messages_empty_for_missing_instance() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (db, db_path) = setup_full_test_db();

        db.log_event(
            "message",
            "kera",
            &serde_json::json!({"from": "kera", "scope": "broadcast", "text": "ack"}),
        )
        .unwrap();

        assert!(
            db.get_unread_messages("ghost").is_empty(),
            "missing instance must have no unread, not the full backlog"
        );

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_get_events_since() {
        let (db, db_path) = setup_full_test_db();

        let data1 = serde_json::json!({"status": "active"});
        let data2 = serde_json::json!({"action": "ready"});
        let id1 = db.log_event("status", "luna", &data1).unwrap();
        let _id2 = db.log_event("life", "nova", &data2).unwrap();

        // Get all events
        let all = db.get_events_since(0, None, None).unwrap();
        assert_eq!(all.len(), 2);

        // Get events since first
        let since = db.get_events_since(id1, None, None).unwrap();
        assert_eq!(since.len(), 1);

        // Filter by type
        let status_only = db.get_events_since(0, Some("status"), None).unwrap();
        assert_eq!(status_only.len(), 1);

        // Filter by instance
        let nova_only = db.get_events_since(0, None, Some("nova")).unwrap();
        assert_eq!(nova_only.len(), 1);

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_get_last_event_id() {
        let (db, db_path) = setup_full_test_db();

        assert_eq!(db.get_last_event_id(), 0);

        let data = serde_json::json!({"status": "active"});
        let id = db.log_event("status", "luna", &data).unwrap();
        assert_eq!(db.get_last_event_id(), id);

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_notify_batch_failure_is_targeted_and_deduplicated() {
        let (db, db_path) = setup_full_test_db();

        db.conn
            .execute(
                "INSERT INTO instances (name, created_at) VALUES ('leku', 1000.0)",
                [],
            )
            .unwrap();

        db.notify_batch_failure("leku", "batch-1", "para", "boom")
            .unwrap();
        db.notify_batch_failure("leku", "batch-1", "para", "boom")
            .unwrap();

        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE type = 'message'
                   AND instance = 'sys_[hcom-launcher]'
                   AND json_extract(data, '$.text') = '@leku Launch failed: para: boom (batch: batch-1)'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        cleanup_test_db(db_path);
    }

    /// Regression: a broadcast must NOT count as direct unread for a dormant
    /// subagent, otherwise SubagentStop wakes every dormant subagent on every
    /// broadcast and the "no message in → no keep-alive" gate is broken.
    #[test]
    fn test_has_direct_unread_ignores_broadcasts() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (db, db_path) = setup_full_test_db();
        db.conn
            .execute(
                "INSERT INTO instances (name, created_at, last_event_id) \
                 VALUES ('luna_reviewer_1', 1000.0, 0)",
                [],
            )
            .unwrap();

        // Broadcast to everyone — must be ignored.
        db.log_event(
            "message",
            "sender",
            &serde_json::json!({"scope": "broadcast", "from": "sender", "text": "hi all"}),
        )
        .unwrap();
        assert!(!db.has_direct_unread("luna_reviewer_1"));

        // Direct mention of a different subagent — also ignored.
        db.log_event(
            "message",
            "sender",
            &serde_json::json!({
                "scope": "mentions",
                "mentions": ["other"],
                "from": "sender",
                "text": "hey other",
            }),
        )
        .unwrap();
        assert!(!db.has_direct_unread("luna_reviewer_1"));

        // Direct mention of this subagent — must trigger.
        db.log_event(
            "message",
            "sender",
            &serde_json::json!({
                "scope": "mentions",
                "mentions": ["luna_reviewer_1"],
                "from": "sender",
                "text": "hey you",
            }),
        )
        .unwrap();
        assert!(db.has_direct_unread("luna_reviewer_1"));

        cleanup_test_db(db_path);
    }
}
