//! Connector state: `~/.hcom/buzz/state.db`.
//!
//! Everything the connector remembers between runs. Every hcom event id stored
//! here is scoped by the hcom DB epoch (`hcom.db` inode + kv
//! `relay_local_reset_ts`), so a `hcom reset` drops id-keyed lookups instead of
//! replaying unrelated history. Buzz event ids need no epoch: the relay keeps
//! them unique.
//!
//! Inbound work is three tables, each a step of the durability model in
//! `docs/design/buzz.md`:
//!
//! - `inbox`: every fetched Buzz event, keyed by its id, with a handling state
//!   (`pending` → `routed` → `done`). It is also the cache `read` lists and the
//!   ancestry walk consults.
//! - `channels.position_*`: how far a channel has been fetched, as the relay's
//!   own sort key `(created_at, id)`. It only says "fetched", never "handled",
//!   and it only moves in the transaction that stored what it points at.
//! - `obligations`: one row per (inbound event, hcom target), written in the
//!   transaction that marks the event routed, before anything is sent.
//!
//! Outbound work is `outbox`, one row per (epoch, hcom id, destination)
//! holding the signed event every retry sends, and `outbox_ids`, every event
//! id a row has ever prepared, so a refused post is looked up by all of them
//! before it is ever re-signed.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::buzz::nostr::Event;

/// How long an inbound obligation keeps being retried before the connector
/// says so in Buzz and closes it.
pub const OBLIGATION_WINDOW_SECS: i64 = 15 * 60;

/// How far before its read position a channel's catch-up starts: the relay's
/// 900 s backdated admission window plus 60 s of NIP-98 clock skew. The live
/// subscription starts the same distance before now.
pub const BACKFILL_SLACK_SECS: u64 = 960;

/// Columns of an outbox row, in `row_to_outbox` order.
const OUTBOX_COLUMNS: &str = "epoch, hcom_id, destination, signer_name, signed_json, buzz_id, \
     recipients, state, attempts, next_at, last_error";

/// Kinds the reader subscribes to, per bridged channel.
pub const CHANNEL_KINDS: &[u16] = &[9, 40002, 45001, 45003, 40003, 5, 9005, 39002];

/// Kind of a channel roster.
const KIND_ROSTER: u16 = 39002;

/// What the connector knows about a Buzz author.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorKind {
    /// A derived hcom agent key (or another owned bot identity).
    Agent,
    /// A human member of a bridged channel.
    Person,
    /// omp, the channel admin and enrollment owner.
    Owner,
    /// The connector's own reader identity.
    Reader,
    /// Not (yet) classifiable.
    Unknown,
}

impl AuthorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthorKind::Agent => "agent",
            AuthorKind::Person => "person",
            AuthorKind::Owner => "owner",
            AuthorKind::Reader => "reader",
            AuthorKind::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "agent" => AuthorKind::Agent,
            "person" => AuthorKind::Person,
            "owner" => AuthorKind::Owner,
            "reader" => AuthorKind::Reader,
            _ => AuthorKind::Unknown,
        }
    }
}

/// A cached author: kind plus the hcom name it maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    pub pubkey: String,
    pub kind: AuthorKind,
    pub hcom_name: Option<String>,
    pub device_label: Option<String>,
}

/// A fetched Buzz event: enough for `read`, for ancestry walking and for
/// handling it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedEvent {
    pub buzz_id: String,
    pub channel_id: String,
    pub kind: u16,
    pub author: String,
    pub created_at: u64,
    pub root_id: Option<String>,
    pub parent_id: Option<String>,
    pub json: String,
}

/// An inbox item still owed handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxItem {
    pub event: CachedEvent,
    pub attempts: u32,
}

/// A person row in the roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonRow {
    pub pubkey: String,
    pub name: String,
    pub home_slug: Option<String>,
    pub active: bool,
    pub left_at: Option<i64>,
}

/// A channel's read position: the relay's sort key of the newest event a
/// completed fetch stored. Ordered by `created_at`, then id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub created_at: u64,
    pub id: String,
}

/// A bridged channel's connector state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRow {
    pub id: String,
    pub slug: String,
    pub position: Option<Position>,
    pub parked_reason: Option<String>,
}

/// A channel's newest roster, saved so it is applied before any message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedRoster {
    pub buzz_id: String,
    pub created_at: u64,
    pub json: String,
    /// Every listed member resolved to a person row (or is not a person).
    pub applied: bool,
    pub attempts: u32,
    pub next_at: i64,
}

/// One outbound post: a signed event bound to a destination channel.
///
/// States: `pending` and `retry` (owed to the relay, the stored event resent
/// as is), `posted` (acknowledged), `logged` (its hcom delivery status
/// written), `deleted` (a prepared id was deleted) and `failed` (refused).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// The hcom DB epoch the row was prepared under. `prepare_outbox` stamps
    /// the store's own, so a caller cannot prepare against a stale one.
    pub epoch: String,
    pub hcom_id: i64,
    pub destination: String,
    pub signer_name: String,
    pub signed_json: String,
    pub buzz_id: String,
    /// Hosted rows the hcom message was for, whose delivery status is logged
    /// once the relay acknowledges the post.
    pub recipients: Vec<String>,
    pub state: String,
    pub attempts: u32,
    pub next_at: i64,
    pub last_error: Option<String>,
}

/// What one target is owed for an inbound event: the routed delivery, exactly
/// as it is sent, so a retry resends that and nothing re-derived.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OwedDelivery {
    /// The person row the message comes from.
    pub sender: String,
    pub thread: String,
    pub root_id: String,
    pub channel_id: String,
    pub text: String,
}

/// One inbound event's obligation to one hcom target.
///
/// States: `pending` (owed, retried with backoff), `delivered`, `notice` (the
/// window closed; the stored "isn't running" notice is being posted) and
/// `expired` (the notice went out, or could never be posted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obligation {
    pub buzz_id: String,
    pub target: String,
    pub state: String,
    pub attempts: u32,
    pub next_at: i64,
    /// When the obligation was written; the 15 min window runs from here.
    pub first_at: i64,
    pub delivery: OwedDelivery,
    /// The signed notice, once the window closed.
    pub notice_json: Option<String>,
}

/// Enrollment state of one (agent, channel) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRow {
    pub agent_pubkey: String,
    pub channel_id: String,
    pub state: String,
    pub updated_at: i64,
}

/// A Buzz thread mapped to its hcom thread name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadRow {
    pub thread_name: String,
    pub channel_id: String,
    pub root_id: String,
}

/// Connector state database.
pub struct Store {
    conn: Connection,
    epoch: String,
}

/// Read-only view for the `buzz_read` RPC and `hcom buzz read`.
pub struct ReadOnlyStore {
    conn: Connection,
}

impl Store {
    /// Open (creating when missing) the connector state DB. The epoch is the
    /// one this store recorded with `adopt_epoch`, empty for a new store.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // serve, its reader thread and the mbai-local CLI share this file;
        // wait out a writer.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let mut store = Self {
            conn,
            epoch: String::new(),
        };
        store.migrate()?;
        store.epoch = store
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'epoch'", [], |row| {
                row.get(0)
            })
            .optional()?
            .unwrap_or_default();
        Ok(store)
    }

    /// Open the state DB read-only, for callers that must not write
    /// (`buzz_read`). The returned handle owns the connection.
    pub fn open_read_only(path: &Path) -> Result<ReadOnlyStore> {
        if !path.exists() {
            anyhow::bail!(
                "no Buzz connector state at {} (run 'hcom buzz serve' there first)",
                path.display()
            );
        }
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("cannot open {} read-only", path.display()))?;
        Ok(ReadOnlyStore { conn })
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                slug TEXT NOT NULL,
                position_created_at INTEGER,
                position_id TEXT,
                caught_up_since REAL,
                parked_reason TEXT);
             CREATE TABLE IF NOT EXISTS people (
                pubkey TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                home_slug TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                left_at INTEGER);
             CREATE TABLE IF NOT EXISTS memberships (
                pubkey TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                PRIMARY KEY (pubkey, channel_id));
             CREATE TABLE IF NOT EXISTS authors (
                pubkey TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                hcom_name TEXT,
                device_label TEXT);
             CREATE TABLE IF NOT EXISTS inbox (
                buzz_id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                kind INTEGER NOT NULL,
                author TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                stored_at REAL NOT NULL,
                root_id TEXT,
                parent_id TEXT,
                json TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_at INTEGER NOT NULL DEFAULT 0,
                last_error TEXT);
             CREATE INDEX IF NOT EXISTS inbox_channel
                ON inbox (channel_id, created_at, buzz_id);
             CREATE INDEX IF NOT EXISTS inbox_due ON inbox (state, channel_id, next_at);
             CREATE TABLE IF NOT EXISTS rosters (
                channel_id TEXT PRIMARY KEY,
                buzz_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                json TEXT NOT NULL,
                applied INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_at INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS obligations (
                buzz_id TEXT NOT NULL,
                target TEXT NOT NULL,
                state TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_at INTEGER NOT NULL DEFAULT 0,
                first_at INTEGER NOT NULL,
                source_created_at INTEGER NOT NULL,
                revision_of TEXT,
                sender TEXT NOT NULL,
                thread TEXT NOT NULL,
                root_id TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                text TEXT NOT NULL,
                notice_json TEXT,
                PRIMARY KEY (buzz_id, target));
             CREATE INDEX IF NOT EXISTS obligations_due ON obligations (state, next_at);
             CREATE TABLE IF NOT EXISTS threads (
                thread_name TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                root_id TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS enrollment (
                agent_pubkey TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                state TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (agent_pubkey, channel_id));
             CREATE TABLE IF NOT EXISTS outbox (
                epoch TEXT NOT NULL,
                hcom_id INTEGER NOT NULL,
                destination TEXT NOT NULL,
                signer_name TEXT NOT NULL,
                signed_json TEXT NOT NULL,
                buzz_id TEXT NOT NULL,
                recipients TEXT NOT NULL,
                state TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_at INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (epoch, hcom_id, destination));
             CREATE INDEX IF NOT EXISTS outbox_due ON outbox (state, next_at);
             CREATE TABLE IF NOT EXISTS outbox_ids (
                buzz_id TEXT PRIMARY KEY,
                epoch TEXT NOT NULL,
                hcom_id INTEGER NOT NULL,
                destination TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS outbox_ids_row
                ON outbox_ids (epoch, hcom_id, destination);",
        )?;
        Ok(())
    }

    /// A write transaction that takes the write lock up front, so a
    /// read-then-write inside it can never be overtaken by another writer.
    fn write_txn(&self) -> Result<Transaction<'_>> {
        Ok(Transaction::new_unchecked(
            &self.conn,
            TransactionBehavior::Immediate,
        )?)
    }

    /// The hcom DB epoch this store's hcom event ids are scoped by.
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// True when `epoch` differs from the store's: hcom was reset under us.
    pub fn epoch_changed(&self, epoch: &str) -> bool {
        epoch != self.epoch
    }

    /// Record the current epoch.
    ///
    /// hcom event ids restart from 1 after a reset, so an id remembered across
    /// one would point at unrelated history. Nothing else is dropped: unposted
    /// outbox rows carry a complete signed event and need no hcom id to go out,
    /// and every other table is keyed by pubkey or Buzz event id, which the
    /// relay keeps unique across a reset.
    pub fn adopt_epoch(&mut self, epoch: String) -> Result<bool> {
        if epoch == self.epoch {
            return Ok(false);
        }
        self.epoch = epoch.clone();
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('epoch', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![epoch],
        )?;
        Ok(true)
    }

    // ── channels ─────────────────────────────────────────────────────────

    /// Insert or refresh a bridged channel row, preserving its position.
    pub fn upsert_channel(&self, id: &str, slug: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO channels (id, slug) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET slug = excluded.slug",
            params![id, slug],
        )?;
        Ok(())
    }

    /// Every bridged channel with its position and parked reason.
    pub fn channels(&self) -> Result<Vec<ChannelRow>> {
        query_channels(&self.conn)
    }

    /// Look up one channel row.
    pub fn channel(&self, id: &str) -> Result<Option<ChannelRow>> {
        Ok(query_channels(&self.conn)?
            .into_iter()
            .find(|row| row.id == id))
    }

    /// Give a channel bridged for the first time its starting position:
    /// `now`, with an empty id. A channel that already has one keeps it.
    pub fn start_position(&self, channel_id: &str, now: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE channels SET position_created_at = ?2, position_id = ''
             WHERE id = ?1 AND position_created_at IS NULL",
            params![channel_id, now as i64],
        )?;
        Ok(())
    }

    /// Store fetched events in a channel's inbox and, when `advance_until` is
    /// given, move the channel's read position to the newest stored key whose
    /// `created_at` is not after it — all in one transaction.
    ///
    /// Inserting is `INSERT OR IGNORE` by Buzz id, so a repeated fetch only
    /// dedupes. The position moves by compare-and-set: never backwards, never
    /// over a newer value. Capping it at `advance_until` (the fetch's wall
    /// clock) keeps a future-dated event, which the relay admits up to 900 s
    /// ahead, from pulling the position past what the next catch-up's 960 s
    /// overlap can still cover. Returns how many events were new.
    pub fn store_fetched(
        &self,
        channel_id: &str,
        events: &[Event],
        advance_until: Option<u64>,
    ) -> Result<usize> {
        self.store_fetch(channel_id, events, advance_until, None)
    }

    /// Commit a completed catch-up's events, position and start time together.
    /// Only revisions already stored before that walk can be settled when their
    /// originals are absent. Live fetches never move this marker.
    pub fn store_caught_up(
        &self,
        channel_id: &str,
        events: &[Event],
        advance_until: u64,
        started_at: f64,
    ) -> Result<usize> {
        self.store_fetch(channel_id, events, Some(advance_until), Some(started_at))
    }

    fn store_fetch(
        &self,
        channel_id: &str,
        events: &[Event],
        advance_until: Option<u64>,
        caught_up_since: Option<f64>,
    ) -> Result<usize> {
        let tx = self.write_txn()?;
        let mut inserted = 0;
        let stored_at = crate::shared::time::now_epoch_f64();
        {
            let mut insert = tx.prepare_cached(
                "INSERT OR IGNORE INTO inbox
                    (buzz_id, channel_id, kind, author, created_at, root_id, parent_id, json, stored_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for event in events {
                let (root_id, parent_id) = crate::buzz::route::thread_refs(event);
                inserted += insert.execute(params![
                    event.id,
                    channel_id,
                    event.kind,
                    event.pubkey,
                    event.created_at as i64,
                    root_id,
                    parent_id,
                    serde_json::to_string(event).context("event serializes")?,
                    stored_at,
                ])?;
            }
        }
        let newest = advance_until.and_then(|limit| {
            events
                .iter()
                .filter(|event| event.created_at <= limit)
                .map(|event| Position {
                    created_at: event.created_at,
                    id: event.id.clone(),
                })
                .max()
        });
        if let Some(newest) = newest {
            tx.execute(
                "UPDATE channels SET position_created_at = ?2, position_id = ?3
                 WHERE id = ?1
                   AND (position_created_at IS NULL
                        OR position_created_at < ?2
                        OR (position_created_at = ?2 AND COALESCE(position_id, '') < ?3))",
                params![channel_id, newest.created_at as i64, newest.id],
            )?;
        }
        if let Some(started_at) = caught_up_since {
            tx.execute(
                "UPDATE channels SET caught_up_since = ?2
                 WHERE id = ?1 AND (caught_up_since IS NULL OR caught_up_since < ?2)",
                params![channel_id, started_at],
            )?;
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// Has this channel completed a walk begun after this item was stored?
    /// The arrival time, not the signed event's created_at, fences the lookup.
    pub fn caught_up_after(&self, channel_id: &str, buzz_id: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM channels c JOIN inbox i ON i.channel_id = c.id
                WHERE c.id = ?1 AND i.buzz_id = ?2 AND c.caught_up_since > i.stored_at)",
            params![channel_id, buzz_id],
            |row| row.get(0),
        )?)
    }

    /// The operator's `hcom buzz cursor set`: put a channel's position at
    /// `since` (id empty, so the whole second is re-read).
    ///
    /// Without `force` this is one compare-and-set that only moves forward, so
    /// two racing seeds can never leave the older value standing. Returns
    /// false when it refused (the position is already later); seeding the
    /// value it already holds is a no-op that succeeds.
    pub fn seed_position(&self, channel_id: &str, since: u64, force: bool) -> Result<bool> {
        let changed = if force {
            self.conn.execute(
                "UPDATE channels SET position_created_at = ?2, position_id = '' WHERE id = ?1",
                params![channel_id, since as i64],
            )?
        } else {
            self.conn.execute(
                "UPDATE channels SET position_created_at = ?2, position_id = ''
                 WHERE id = ?1 AND (position_created_at IS NULL OR position_created_at < ?2)",
                params![channel_id, since as i64],
            )?
        };
        if changed == 1 {
            return Ok(true);
        }
        Ok(self
            .channel(channel_id)?
            .and_then(|row| row.position)
            .is_some_and(|position| position.created_at == since))
    }

    /// Park (or unpark, with an empty reason) a channel subscription.
    pub fn set_channel_parked(&self, id: &str, reason: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE channels SET parked_reason = ?2 WHERE id = ?1",
            params![id, reason],
        )?;
        Ok(())
    }

    // ── people ───────────────────────────────────────────────────────────

    /// Insert or refresh a person row.
    pub fn upsert_person(&self, pubkey: &str, name: &str, home_slug: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO people (pubkey, name, home_slug, active, left_at)
             VALUES (?1, ?2, ?3, 1, NULL)
             ON CONFLICT(pubkey) DO UPDATE SET
                name = excluded.name,
                home_slug = COALESCE(excluded.home_slug, people.home_slug),
                active = 1,
                left_at = NULL",
            params![pubkey, name, home_slug],
        )?;
        Ok(())
    }

    /// Insert a person row only when the pubkey has none. A configured person
    /// is known from the first pass, but a configured person the rosters
    /// retired stays retired. True when a row was created.
    pub fn insert_person_if_absent(
        &self,
        pubkey: &str,
        name: &str,
        home_slug: Option<&str>,
    ) -> Result<bool> {
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO people (pubkey, name, home_slug, active, left_at)
             VALUES (?1, ?2, ?3, 1, NULL)",
            params![pubkey, name, home_slug],
        )?;
        Ok(inserted == 1)
    }

    /// Retire a person: no longer a participant. The grace period is the
    /// caller's business; see `mark_person_leaving`.
    pub fn retire_person(&self, pubkey: &str, at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE people SET active = 0, left_at = ?2 WHERE pubkey = ?1",
            params![pubkey, at],
        )?;
        Ok(())
    }

    /// Start (or move) a person's grace period. They stay active meanwhile.
    pub fn mark_person_leaving(&self, pubkey: &str, at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE people SET left_at = ?2 WHERE pubkey = ?1",
            params![pubkey, at],
        )?;
        Ok(())
    }

    /// A person seen in a roster again: no grace period running.
    pub fn clear_person_leaving(&self, pubkey: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE people SET left_at = NULL WHERE pubkey = ?1 AND active = 1",
            params![pubkey],
        )?;
        Ok(())
    }

    /// Replace one channel's person members with what its roster lists.
    pub fn set_channel_members(&self, channel_id: &str, pubkeys: &[String]) -> Result<()> {
        let tx = self.write_txn()?;
        tx.execute(
            "DELETE FROM memberships WHERE channel_id = ?1",
            params![channel_id],
        )?;
        for pubkey in pubkeys {
            tx.execute(
                "INSERT OR IGNORE INTO memberships (pubkey, channel_id) VALUES (?1, ?2)",
                params![pubkey, channel_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// True when any bridged channel's last roster listed this person.
    pub fn is_member_anywhere(&self, pubkey: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM memberships WHERE pubkey = ?1 LIMIT 1",
                params![pubkey],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Every person row.
    pub fn people(&self) -> Result<Vec<PersonRow>> {
        query_people(&self.conn)
    }

    /// Active person rows only, in name order.
    pub fn active_people(&self) -> Result<Vec<PersonRow>> {
        Ok(self.people()?.into_iter().filter(|p| p.active).collect())
    }

    /// Look up one person by hcom name.
    pub fn person_by_name(&self, name: &str) -> Result<Option<PersonRow>> {
        Ok(self.people()?.into_iter().find(|p| p.name == name))
    }

    /// Look up one person by pubkey.
    pub fn person_by_pubkey(&self, pubkey: &str) -> Result<Option<PersonRow>> {
        Ok(self.people()?.into_iter().find(|p| p.pubkey == pubkey))
    }

    // ── authors ──────────────────────────────────────────────────────────

    /// Cache an author's classification.
    pub fn put_author(&self, author: &Author) -> Result<()> {
        self.conn.execute(
            "INSERT INTO authors (pubkey, kind, hcom_name, device_label)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(pubkey) DO UPDATE SET
                kind = excluded.kind,
                hcom_name = excluded.hcom_name,
                device_label = excluded.device_label",
            params![
                author.pubkey,
                author.kind.as_str(),
                author.hcom_name,
                author.device_label
            ],
        )?;
        Ok(())
    }

    /// One cached author.
    pub fn author(&self, pubkey: &str) -> Result<Option<Author>> {
        Ok(self
            .conn
            .query_row(
                "SELECT pubkey, kind, hcom_name, device_label FROM authors WHERE pubkey = ?1",
                params![pubkey],
                |row| {
                    Ok(Author {
                        pubkey: row.get(0)?,
                        kind: AuthorKind::parse(&row.get::<_, String>(1)?),
                        hcom_name: row.get(2)?,
                        device_label: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// `(pubkey, hcom_name)` for every cached author of one kind.
    pub fn authors_of_kind(&self, kind: AuthorKind) -> Result<Vec<(String, Option<String>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pubkey, hcom_name FROM authors WHERE kind = ?1 ORDER BY pubkey")?;
        let rows = stmt
            .query_map(params![kind.as_str()], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ── inbox ────────────────────────────────────────────────────────────

    /// One fetched event by Buzz id.
    pub fn cached_event(&self, buzz_id: &str) -> Result<Option<CachedEvent>> {
        Ok(self
            .conn
            .query_row(
                "SELECT buzz_id, channel_id, kind, author, created_at, root_id, parent_id, json
                 FROM inbox WHERE buzz_id = ?1",
                params![buzz_id],
                row_to_cached,
            )
            .optional()?)
    }

    /// Fetched events in a channel, newest first, optionally limited to a
    /// thread and continued after `before` in that order.
    pub fn list_events(
        &self,
        channel_id: Option<&str>,
        thread: Option<&str>,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CachedEvent>> {
        list_events_on(&self.conn, channel_id, thread, before, limit)
    }

    /// An inbox item's handling state, if it was fetched at all.
    pub fn inbox_state(&self, buzz_id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT state FROM inbox WHERE buzz_id = ?1",
                params![buzz_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// A channel's items still owed handling whose retry time has come,
    /// oldest first by the relay's key. Rosters are not among them: they are
    /// adopted separately, before any message (`adopt_roster`).
    pub fn due_inbox(&self, channel_id: &str, now: i64) -> Result<Vec<InboxItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT buzz_id, channel_id, kind, author, created_at, root_id, parent_id, json,
                    attempts
             FROM inbox
             WHERE channel_id = ?1 AND state = 'pending' AND next_at <= ?2 AND kind != ?3
             ORDER BY created_at, buzz_id",
        )?;
        let rows = stmt
            .query_map(params![channel_id, now, KIND_ROSTER], |row| {
                Ok(InboxItem {
                    event: row_to_cached(row)?,
                    attempts: row.get::<_, i64>(8)? as u32,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Leave an item pending, to be handled again at `next_at`. Nothing is
    /// ever dropped for failing too often.
    pub fn defer_item(
        &self,
        buzz_id: &str,
        attempts: u32,
        next_at: i64,
        error: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE inbox SET attempts = ?2, next_at = ?3, last_error = ?4
             WHERE buzz_id = ?1 AND state = 'pending'",
            params![buzz_id, attempts, next_at, error],
        )?;
        Ok(())
    }

    /// An item that needs nothing delivered (our own post, no agent addressed,
    /// a known non-person): handled.
    pub fn finish_item(&self, buzz_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE inbox SET state = 'done', last_error = NULL WHERE buzz_id = ?1",
            params![buzz_id],
        )?;
        Ok(())
    }

    /// Route an item: one obligation per target, the thread mapping, and the
    /// item marked routed, in one transaction. Obligations exist before
    /// anything is sent; a crash before the commit re-routes the item, one
    /// after it replays the obligations.
    pub fn route_item(
        &self,
        source: &Event,
        targets: &[String],
        owed: &OwedDelivery,
        now: i64,
    ) -> Result<()> {
        let tx = self.write_txn()?;
        let revision_of = matches!(
            source.kind,
            crate::buzz::route::KIND_EDIT
                | crate::buzz::route::KIND_DELETE
                | crate::buzz::route::KIND_CHANNEL_DELETE
        )
        .then(|| crate::buzz::route::tag(source, "e"))
        .flatten();
        for target in targets {
            tx.execute(
                "INSERT OR IGNORE INTO obligations
                    (buzz_id, target, state, attempts, next_at, first_at,
                     sender, thread, root_id, channel_id, text, source_created_at, revision_of)
                 VALUES (?1, ?2, 'pending', 0, 0, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    source.id,
                    target,
                    now,
                    owed.sender,
                    owed.thread,
                    owed.root_id,
                    owed.channel_id,
                    owed.text,
                    source.created_at as i64,
                    revision_of,
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO threads (thread_name, channel_id, root_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(thread_name) DO UPDATE SET
                channel_id = excluded.channel_id, root_id = excluded.root_id",
            params![owed.thread, owed.channel_id, owed.root_id],
        )?;
        tx.execute(
            "UPDATE inbox SET state = 'routed', last_error = NULL WHERE buzz_id = ?1",
            params![source.id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Mark routed items done once every obligation they own is terminal.
    pub fn finish_routed(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE inbox SET state = 'done'
             WHERE state = 'routed'
               AND NOT EXISTS (
                   SELECT 1 FROM obligations o
                   WHERE o.buzz_id = inbox.buzz_id AND o.state IN ('pending', 'notice'))",
            [],
        )?)
    }

    /// Inbox counts by state, for `hcom buzz status`.
    pub fn inbox_counts(&self) -> Result<Vec<(String, i64)>> {
        state_counts(&self.conn, "inbox")
    }

    /// Make every pending item due now, so a test need not wait out backoff.
    #[cfg(test)]
    pub fn make_inbox_due(&self) -> Result<()> {
        self.conn
            .execute("UPDATE inbox SET next_at = 0 WHERE state = 'pending'", [])?;
        Ok(())
    }

    // ── rosters ──────────────────────────────────────────────────────────

    /// Rosters fetched for a channel and not yet adopted or discarded.
    pub fn pending_rosters(&self, channel_id: &str) -> Result<Vec<CachedEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT buzz_id, channel_id, kind, author, created_at, root_id, parent_id, json
             FROM inbox
             WHERE channel_id = ?1 AND kind = ?2 AND state = 'pending'
             ORDER BY created_at, buzz_id",
        )?;
        let rows = stmt
            .query_map(params![channel_id, KIND_ROSTER], row_to_cached)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// A channel's saved roster.
    pub fn saved_roster(&self, channel_id: &str) -> Result<Option<SavedRoster>> {
        Ok(self
            .conn
            .query_row(
                "SELECT buzz_id, created_at, json, applied, attempts, next_at
                 FROM rosters WHERE channel_id = ?1",
                params![channel_id],
                |row| {
                    Ok(SavedRoster {
                        buzz_id: row.get(0)?,
                        created_at: row.get::<_, i64>(1)? as u64,
                        json: row.get(2)?,
                        applied: row.get::<_, i64>(3)? != 0,
                        attempts: row.get::<_, i64>(4)? as u32,
                        next_at: row.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// Save `newest` as the channel's roster (to be applied) and settle every
    /// fetched roster item in `settled`, in one transaction.
    pub fn adopt_roster(
        &self,
        channel_id: &str,
        newest: Option<&CachedEvent>,
        settled: &[String],
    ) -> Result<()> {
        let tx = self.write_txn()?;
        if let Some(roster) = newest {
            tx.execute(
                "INSERT INTO rosters (channel_id, buzz_id, created_at, json, applied, attempts, next_at)
                 VALUES (?1, ?2, ?3, ?4, 0, 0, 0)
                 ON CONFLICT(channel_id) DO UPDATE SET
                    buzz_id = excluded.buzz_id, created_at = excluded.created_at,
                    json = excluded.json, applied = 0, attempts = 0, next_at = 0",
                params![
                    channel_id,
                    roster.buzz_id,
                    roster.created_at as i64,
                    roster.json
                ],
            )?;
        }
        for buzz_id in settled {
            tx.execute(
                "UPDATE inbox SET state = 'done' WHERE buzz_id = ?1",
                params![buzz_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The saved roster was applied in full.
    pub fn roster_applied(&self, channel_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE rosters SET applied = 1 WHERE channel_id = ?1",
            params![channel_id],
        )?;
        Ok(())
    }

    /// The saved roster could not be applied in full (a member's profile is
    /// missing or unreadable): try again at `next_at`.
    pub fn defer_roster(&self, channel_id: &str, attempts: u32, next_at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE rosters SET applied = 0, attempts = ?2, next_at = ?3 WHERE channel_id = ?1",
            params![channel_id, attempts, next_at],
        )?;
        Ok(())
    }

    // ── obligations ──────────────────────────────────────────────────────

    /// Obligations whose next step is due, in source (created_at, id) order.
    /// A revision waits for its original's obligation on this target to become
    /// terminal, even when the revision is backdated or shares its second.
    pub fn due_obligations(&self, now: i64) -> Result<Vec<Obligation>> {
        let mut stmt = self.conn.prepare(
            "SELECT buzz_id, target, state, attempts, next_at, first_at,
                    sender, thread, root_id, channel_id, text, notice_json
             FROM obligations
             WHERE state IN ('pending', 'notice') AND next_at <= ?1
               AND NOT EXISTS (
                   SELECT 1 FROM obligations original
                   WHERE original.buzz_id = obligations.revision_of
                     AND original.target = obligations.target
                     AND original.state IN ('pending', 'notice'))
             ORDER BY source_created_at, buzz_id, target",
        )?;
        let rows = stmt
            .query_map(params![now], |row| {
                Ok(Obligation {
                    buzz_id: row.get(0)?,
                    target: row.get(1)?,
                    state: row.get(2)?,
                    attempts: row.get::<_, i64>(3)? as u32,
                    next_at: row.get(4)?,
                    first_at: row.get(5)?,
                    delivery: OwedDelivery {
                        sender: row.get(6)?,
                        thread: row.get(7)?,
                        root_id: row.get(8)?,
                        channel_id: row.get(9)?,
                        text: row.get(10)?,
                    },
                    notice_json: row.get(11)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The target's hcom send went through.
    pub fn obligation_delivered(&self, buzz_id: &str, target: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE obligations SET state = 'delivered', attempts = attempts + 1, next_at = 0
             WHERE buzz_id = ?1 AND target = ?2 AND state = 'pending'",
            params![buzz_id, target],
        )?;
        Ok(())
    }

    /// Not deliverable yet, or the notice could not be posted yet: try again
    /// at `next_at`. The obligation is never dropped for failing.
    pub fn defer_obligation(
        &self,
        buzz_id: &str,
        target: &str,
        attempts: u32,
        next_at: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE obligations SET attempts = ?3, next_at = ?4
             WHERE buzz_id = ?1 AND target = ?2 AND state IN ('pending', 'notice')",
            params![buzz_id, target, attempts, next_at],
        )?;
        Ok(())
    }

    /// The window closed: store the signed notice that says so, once. A
    /// retry posts that same event, so the relay sees one notice however
    /// often it is attempted.
    pub fn obligation_notice(&self, buzz_id: &str, target: &str, notice_json: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE obligations SET state = 'notice', notice_json = ?3, next_at = 0
             WHERE buzz_id = ?1 AND target = ?2 AND state = 'pending'",
            params![buzz_id, target, notice_json],
        )?;
        Ok(())
    }

    /// The notice was posted (or can never be): the obligation is closed.
    pub fn obligation_expired(&self, buzz_id: &str, target: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE obligations SET state = 'expired', next_at = 0
             WHERE buzz_id = ?1 AND target = ?2",
            params![buzz_id, target],
        )?;
        Ok(())
    }

    /// True when an event was routed to at least one target still owed it or
    /// already given it: what an edit or deletion of it follows.
    pub fn was_routed(&self, buzz_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM obligations
                 WHERE buzz_id = ?1 AND state IN ('pending', 'delivered') LIMIT 1",
                params![buzz_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Obligation counts by state, for `hcom buzz status`.
    pub fn obligation_counts(&self) -> Result<Vec<(String, i64)>> {
        state_counts(&self.conn, "obligations")
    }

    /// Move an obligation's window start, so a test can age it without
    /// waiting out the real window.
    #[cfg(test)]
    pub fn age_obligation(&self, buzz_id: &str, first_at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE obligations SET first_at = ?2, next_at = 0 WHERE buzz_id = ?1",
            params![buzz_id, first_at],
        )?;
        Ok(())
    }

    // ── threads ──────────────────────────────────────────────────────────

    /// Map a Buzz thread root to its hcom thread name.
    pub fn put_thread(&self, thread_name: &str, channel_id: &str, root_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO threads (thread_name, channel_id, root_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(thread_name) DO UPDATE SET
                channel_id = excluded.channel_id, root_id = excluded.root_id",
            params![thread_name, channel_id, root_id],
        )?;
        Ok(())
    }

    /// Every recorded Buzz thread, for outbound rule 1.
    pub fn threads(&self) -> Result<Vec<ThreadRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT thread_name, channel_id, root_id FROM threads ORDER BY thread_name")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ThreadRow {
                    thread_name: row.get(0)?,
                    channel_id: row.get(1)?,
                    root_id: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Look up the Buzz thread behind an hcom thread name.
    pub fn thread(&self, thread_name: &str) -> Result<Option<ThreadRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT thread_name, channel_id, root_id FROM threads WHERE thread_name = ?1",
                params![thread_name],
                |row| {
                    Ok(ThreadRow {
                        thread_name: row.get(0)?,
                        channel_id: row.get(1)?,
                        root_id: row.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    // ── enrollment ───────────────────────────────────────────────────────

    /// Record an agent's enrollment state in a channel.
    pub fn put_enrollment(&self, agent_pubkey: &str, channel_id: &str, state: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO enrollment (agent_pubkey, channel_id, state, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(agent_pubkey, channel_id) DO UPDATE SET
                state = excluded.state, updated_at = excluded.updated_at",
            params![
                agent_pubkey,
                channel_id,
                state,
                crate::shared::time::now_epoch_i64()
            ],
        )?;
        Ok(())
    }

    /// One agent's enrollment state in a channel, if recorded.
    pub fn enrollment(&self, agent_pubkey: &str, channel_id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT state FROM enrollment WHERE agent_pubkey = ?1 AND channel_id = ?2",
                params![agent_pubkey, channel_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Count of agent-channel pairs currently enrolled.
    pub fn enrolled_count(&self) -> Result<i64> {
        enrolled_count_on(&self.conn)
    }

    /// Every enrollment, for status output and the removal planner.
    pub fn enrollments(&self) -> Result<Vec<EnrollmentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_pubkey, channel_id, state, updated_at FROM enrollment
             ORDER BY channel_id, agent_pubkey",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(EnrollmentRow {
                    agent_pubkey: row.get(0)?,
                    channel_id: row.get(1)?,
                    state: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Forget an agent's enrollment in one channel, once omp removed it there.
    pub fn drop_enrollment(&self, agent_pubkey: &str, channel_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM enrollment WHERE agent_pubkey = ?1 AND channel_id = ?2",
            params![agent_pubkey, channel_id],
        )?;
        Ok(())
    }

    /// Move an enrollment's `updated_at`, so a test can age a missing agent
    /// past the removal window without waiting an hour.
    #[cfg(test)]
    pub fn age_enrollment(&self, agent_pubkey: &str, updated_at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE enrollment SET updated_at = ?2 WHERE agent_pubkey = ?1",
            params![agent_pubkey, updated_at],
        )?;
        Ok(())
    }

    /// Run raw SQL against the state DB, so a test can inject a failure
    /// (a trigger that aborts writes) the way a full disk would.
    #[cfg(test)]
    pub fn exec_for_test(&self, sql: &str) -> Result<()> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    // ── outbox ───────────────────────────────────────────────────────────

    /// Prepare one post: its signed event and the hosted recipients it is
    /// for, keyed (epoch, hcom id, destination), plus the event's id in the
    /// row's id history, in one transaction. A re-read of the same hcom
    /// message prepares nothing new, so the stored event is the one every
    /// retry sends. The store stamps its own epoch, never the row's.
    pub fn prepare_outbox(&self, row: &OutboxRow) -> Result<bool> {
        let tx = self.write_txn()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO outbox
                (epoch, hcom_id, destination, signer_name, signed_json, buzz_id, recipients,
                 state, attempts, next_at, last_error, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', 0, ?8, NULL, ?9)",
            params![
                self.epoch,
                row.hcom_id,
                row.destination,
                row.signer_name,
                row.signed_json,
                row.buzz_id,
                serde_json::to_string(&row.recipients)?,
                row.next_at,
                crate::shared::time::now_epoch_i64()
            ],
        )?;
        if inserted == 1 {
            tx.execute(
                "INSERT OR IGNORE INTO outbox_ids (buzz_id, epoch, hcom_id, destination)
                 VALUES (?1, ?2, ?3, ?4)",
                params![row.buzz_id, self.epoch, row.hcom_id, row.destination],
            )?;
        }
        tx.commit()?;
        Ok(inserted == 1)
    }

    /// Outbox rows for one destination channel whose retry time has come.
    ///
    /// Not epoch-filtered: an unposted row carries its own signed event, so it
    /// still goes out after a `hcom reset` moved every hcom id under it.
    pub fn due_outbox(&self, destination: &str, now: i64) -> Result<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {OUTBOX_COLUMNS} FROM outbox
             WHERE destination = ?1 AND state IN ('pending', 'retry') AND next_at <= ?2
             ORDER BY hcom_id, buzz_id"
        ))?;
        let rows = stmt
            .query_map(params![destination, now], row_to_outbox)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every event id this row has ever prepared, oldest first: any of them
    /// may be the one the relay stored.
    pub fn prepared_ids(&self, row: &OutboxRow) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT buzz_id FROM outbox_ids
             WHERE epoch = ?1 AND hcom_id = ?2 AND destination = ?3
             ORDER BY rowid",
        )?;
        let ids = stmt
            .query_map(params![row.epoch, row.hcom_id, row.destination], |r| {
                r.get(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// The relay acknowledged the post (or holds a prepared id). A by-id
    /// recovery records the event actually found in the same durable ack.
    pub fn mark_outbox_posted(&self, row: &OutboxRow, found: Option<&Event>) -> Result<()> {
        let signed_json = found.map(serde_json::to_string).transpose()?;
        self.conn.execute(
            "UPDATE outbox SET state = 'posted', attempts = attempts + 1, last_error = NULL,
                buzz_id = COALESCE(?4, buzz_id), signed_json = COALESCE(?5, signed_json)
             WHERE epoch = ?1 AND hcom_id = ?2 AND destination = ?3
               AND state IN ('pending', 'retry')",
            params![
                row.epoch,
                row.hcom_id,
                row.destination,
                found.map(|event| event.id.as_str()),
                signed_json,
            ],
        )?;
        Ok(())
    }

    /// A stored deletion references a prepared id: this row must never publish
    /// again, and it must not log a posted status for the absent event.
    pub fn mark_outbox_deleted(&self, row: &OutboxRow, tombstone_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET state = 'deleted', attempts = attempts + 1, last_error = ?4
             WHERE epoch = ?1 AND hcom_id = ?2 AND destination = ?3
               AND state IN ('pending', 'retry')",
            params![
                row.epoch,
                row.hcom_id,
                row.destination,
                format!("deleted by {tombstone_id}"),
            ],
        )?;
        Ok(())
    }

    /// Posted rows whose hcom delivery status isn't logged yet: right after
    /// the ack, or after a crash between the two.
    pub fn posted_unlogged(&self) -> Result<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {OUTBOX_COLUMNS} FROM outbox WHERE state = 'posted'
             ORDER BY created_at, hcom_id"
        ))?;
        let rows = stmt
            .query_map([], row_to_outbox)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The delivery status is logged: the row is finished.
    pub fn mark_outbox_logged(&self, row: &OutboxRow) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET state = 'logged'
             WHERE epoch = ?1 AND hcom_id = ?2 AND destination = ?3 AND state = 'posted'",
            params![row.epoch, row.hcom_id, row.destination],
        )?;
        Ok(())
    }

    /// Reschedule a post that failed transiently. Its stored event stays.
    pub fn retry_outbox(&self, row: &OutboxRow, next_at: i64, error: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox
             SET state = 'retry', attempts = attempts + 1, next_at = ?4, last_error = ?5
             WHERE epoch = ?1 AND hcom_id = ?2 AND destination = ?3
               AND state IN ('pending', 'retry')",
            params![row.epoch, row.hcom_id, row.destination, next_at, error],
        )?;
        Ok(())
    }

    /// Mark a post the relay will never accept.
    pub fn fail_outbox(&self, row: &OutboxRow, error: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET state = 'failed', attempts = attempts + 1, last_error = ?4
             WHERE epoch = ?1 AND hcom_id = ?2 AND destination = ?3
               AND state IN ('pending', 'retry')",
            params![row.epoch, row.hcom_id, row.destination, error],
        )?;
        Ok(())
    }

    /// Swap a row's signed event for a re-signed one, once a lookup over
    /// every id it ever prepared proved the relay holds none of them, and add
    /// the new id to that history, in one transaction. The row goes straight
    /// back to the publisher.
    pub fn resign_outbox(&self, row: &OutboxRow, buzz_id: &str, signed_json: &str) -> Result<()> {
        let tx = self.write_txn()?;
        tx.execute(
            "UPDATE outbox SET buzz_id = ?4, signed_json = ?5, state = 'retry', next_at = 0
             WHERE epoch = ?1 AND hcom_id = ?2 AND destination = ?3
               AND state IN ('pending', 'retry')",
            params![
                row.epoch,
                row.hcom_id,
                row.destination,
                buzz_id,
                signed_json
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO outbox_ids (buzz_id, epoch, hcom_id, destination)
             VALUES (?1, ?2, ?3, ?4)",
            params![buzz_id, row.epoch, row.hcom_id, row.destination],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Make every unposted row due now, so a test need not wait out backoff.
    #[cfg(test)]
    pub fn make_outbox_due(&self) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET next_at = 0 WHERE state IN ('pending', 'retry')",
            [],
        )?;
        Ok(())
    }

    /// Outbox counts by state, for `hcom buzz status`.
    pub fn outbox_counts(&self) -> Result<Vec<(String, i64)>> {
        state_counts(&self.conn, "outbox")
    }

    /// Every outbox row the relay hasn't acknowledged, for `hcom buzz down`'s
    /// leftovers report.
    pub fn unsent_outbox(&self) -> Result<Vec<OutboxRow>> {
        unsent_outbox_on(&self.conn)
    }

    /// Most recent outbox failures, newest first, for status output.
    pub fn recent_errors(&self, limit: usize) -> Result<Vec<(String, i64, String)>> {
        recent_errors_on(&self.conn, limit)
    }
}

impl ReadOnlyStore {
    /// Bridged channels with positions and parked reasons, for `buzz status`.
    pub fn channels(&self) -> Result<Vec<ChannelRow>> {
        query_channels(&self.conn)
    }

    /// One channel row by id.
    pub fn channel(&self, id: &str) -> Result<Option<ChannelRow>> {
        Ok(self.channels()?.into_iter().find(|row| row.id == id))
    }

    /// Every person row.
    pub fn people(&self) -> Result<Vec<PersonRow>> {
        query_people(&self.conn)
    }

    /// Outbox counts by state.
    pub fn outbox_counts(&self) -> Result<Vec<(String, i64)>> {
        state_counts(&self.conn, "outbox")
    }

    /// Inbound obligation counts by state.
    pub fn obligation_counts(&self) -> Result<Vec<(String, i64)>> {
        state_counts(&self.conn, "obligations")
    }

    /// Inbox counts by state.
    pub fn inbox_counts(&self) -> Result<Vec<(String, i64)>> {
        state_counts(&self.conn, "inbox")
    }

    /// Number of agent-channel pairs currently enrolled.
    pub fn enrolled_count(&self) -> Result<i64> {
        enrolled_count_on(&self.conn)
    }

    /// Every outbox row that has not been acknowledged.
    pub fn unsent_outbox(&self) -> Result<Vec<OutboxRow>> {
        unsent_outbox_on(&self.conn)
    }

    /// The most recent outbox failures, newest first.
    pub fn recent_errors(&self, limit: usize) -> Result<Vec<(String, i64, String)>> {
        recent_errors_on(&self.conn, limit)
    }

    /// Fetched events for `buzz read` and the `buzz_read` RPC.
    pub fn list_events(
        &self,
        channel_id: Option<&str>,
        thread: Option<&str>,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CachedEvent>> {
        list_events_on(&self.conn, channel_id, thread, before, limit)
    }

    /// Number of fetched events, for the RPC's answer summary.
    pub fn event_count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM inbox", [], |row| row.get(0))?)
    }
}

fn query_channels(conn: &Connection) -> Result<Vec<ChannelRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, slug, position_created_at, position_id, parked_reason
         FROM channels ORDER BY slug",
    )?;
    let rows = stmt
        .query_map([], |row| {
            let created_at: Option<i64> = row.get(2)?;
            let id: Option<String> = row.get(3)?;
            Ok(ChannelRow {
                id: row.get(0)?,
                slug: row.get(1)?,
                position: created_at.map(|created_at| Position {
                    created_at: created_at as u64,
                    id: id.unwrap_or_default(),
                }),
                parked_reason: row.get(4)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn query_people(conn: &Connection) -> Result<Vec<PersonRow>> {
    let mut stmt =
        conn.prepare("SELECT pubkey, name, home_slug, active, left_at FROM people ORDER BY name")?;
    let rows = stmt
        .query_map([], |row| {
            Ok(PersonRow {
                pubkey: row.get(0)?,
                name: row.get(1)?,
                home_slug: row.get(2)?,
                active: row.get::<_, i64>(3)? != 0,
                left_at: row.get(4)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Fetched events newest first, in the relay's own order (`created_at DESC,
/// id ASC`). `before` continues after that event in the same order: earlier
/// seconds, plus the rest of its own second, so a same-second neighbour on
/// the next page is never skipped.
fn list_events_on(
    conn: &Connection,
    channel_id: Option<&str>,
    thread: Option<&str>,
    before: Option<&str>,
    limit: usize,
) -> Result<Vec<CachedEvent>> {
    let mut sql = String::from(
        "SELECT buzz_id, channel_id, kind, author, created_at, root_id, parent_id, json
         FROM inbox WHERE 1=1",
    );
    let mut binds: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(channel_id) = channel_id {
        sql.push_str(" AND channel_id = ?");
        binds.push(channel_id.to_string().into());
    }
    if let Some(thread) = thread {
        sql.push_str(" AND (buzz_id = ? OR root_id = ? OR parent_id = ?)");
        for _ in 0..3 {
            binds.push(thread.to_string().into());
        }
    }
    if let Some(before) = before {
        let anchor: Option<i64> = conn
            .query_row(
                "SELECT created_at FROM inbox WHERE buzz_id = ?1",
                params![before],
                |row| row.get(0),
            )
            .optional()?;
        let Some(anchor) = anchor else {
            anyhow::bail!("unknown --before event {before}");
        };
        sql.push_str(" AND (created_at < ? OR (created_at = ? AND buzz_id > ?))");
        binds.push(anchor.into());
        binds.push(anchor.into());
        binds.push(before.to_string().into());
    }
    sql.push_str(" ORDER BY created_at DESC, buzz_id ASC LIMIT ?");
    binds.push((limit as i64).into());

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(binds), row_to_cached)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn state_counts(conn: &Connection, table: &str) -> Result<Vec<(String, i64)>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT state, COUNT(*) FROM {table} GROUP BY state ORDER BY state"
    ))?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn enrolled_count_on(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM enrollment WHERE state = 'enrolled'",
        [],
        |row| row.get(0),
    )?)
}

fn unsent_outbox_on(conn: &Connection) -> Result<Vec<OutboxRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {OUTBOX_COLUMNS} FROM outbox
         WHERE state NOT IN ('posted', 'logged', 'deleted')
         ORDER BY created_at, hcom_id"
    ))?;
    let rows = stmt
        .query_map([], row_to_outbox)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn recent_errors_on(conn: &Connection, limit: usize) -> Result<Vec<(String, i64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT destination, hcom_id, COALESCE(last_error, '')
         FROM outbox
         WHERE last_error IS NOT NULL AND last_error != ''
         ORDER BY created_at DESC, hcom_id DESC
         LIMIT ?1",
    )?;
    let rows = stmt
        .query_map(params![limit as i64], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn row_to_cached(row: &rusqlite::Row<'_>) -> rusqlite::Result<CachedEvent> {
    Ok(CachedEvent {
        buzz_id: row.get(0)?,
        channel_id: row.get(1)?,
        kind: row.get(2)?,
        author: row.get(3)?,
        created_at: row.get::<_, i64>(4)? as u64,
        root_id: row.get(5)?,
        parent_id: row.get(6)?,
        json: row.get(7)?,
    })
}

fn row_to_outbox(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboxRow> {
    let recipients: String = row.get(6)?;
    Ok(OutboxRow {
        epoch: row.get(0)?,
        hcom_id: row.get(1)?,
        destination: row.get(2)?,
        signer_name: row.get(3)?,
        signed_json: row.get(4)?,
        buzz_id: row.get(5)?,
        recipients: serde_json::from_str(&recipients).unwrap_or_default(),
        state: row.get(7)?,
        attempts: row.get::<_, i64>(8)? as u32,
        next_at: row.get(9)?,
        last_error: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buzz::nostr::{Event, UnsignedEvent, derive_secret, sign};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("state.db")).unwrap();
        store.adopt_epoch("epoch-1".into()).unwrap();
        (dir, store)
    }

    fn event_with(
        key: &crate::buzz::nostr::SecretKey,
        kind: u16,
        created_at: u64,
        tags: Vec<Vec<String>>,
        content: &str,
    ) -> Event {
        let mut all = vec![vec!["h".into(), "chan-1".into()]];
        all.extend(tags);
        sign(
            UnsignedEvent {
                created_at,
                kind,
                tags: all,
                content: content.into(),
            },
            key,
        )
    }

    fn event(key: &crate::buzz::nostr::SecretKey, kind: u16, created_at: u64) -> Event {
        event_with(key, kind, created_at, vec![], &format!("body {kind}"))
    }

    fn key() -> crate::buzz::nostr::SecretKey {
        derive_secret(&[9; 32], "TEST@mbai")
    }

    fn owed() -> OwedDelivery {
        OwedDelivery {
            sender: "michael".into(),
            thread: "buzz_infra_e1".into(),
            root_id: "e1".into(),
            channel_id: "chan-1".into(),
            text: "ping".into(),
        }
    }

    #[test]
    fn open_creates_schema_and_is_repeatable() {
        let (dir, store) = store();
        assert_eq!(store.epoch(), "epoch-1");
        assert!(store.channels().unwrap().is_empty());
        drop(store);
        let reopened = Store::open(&dir.path().join("state.db")).unwrap();
        assert_eq!(reopened.epoch(), "epoch-1");
    }

    #[test]
    fn channel_position_survives_an_upsert() {
        let (_dir, store) = store();
        store.upsert_channel("chan-1", "infra").unwrap();
        let fetched = event(&key(), 9, 1000);
        store
            .store_fetched("chan-1", std::slice::from_ref(&fetched), Some(5000))
            .unwrap();
        store
            .set_channel_parked("chan-1", Some("closed: rate-limited"))
            .unwrap();
        store.upsert_channel("chan-1", "infra-renamed").unwrap();

        let row = store.channel("chan-1").unwrap().unwrap();
        assert_eq!(row.slug, "infra-renamed");
        assert_eq!(
            row.position,
            Some(Position {
                created_at: 1000,
                id: fetched.id.clone()
            })
        );
        assert_eq!(row.parked_reason.as_deref(), Some("closed: rate-limited"));

        store.set_channel_parked("chan-1", None).unwrap();
        assert!(
            store
                .channel("chan-1")
                .unwrap()
                .unwrap()
                .parked_reason
                .is_none()
        );
    }

    #[test]
    fn the_position_moves_only_forward_and_only_to_what_was_stored() {
        let (_dir, store) = store();
        store.upsert_channel("chan-1", "infra").unwrap();
        let newer = event(&key(), 9, 2000);
        let older = event(&key(), 9, 1500);
        store
            .store_fetched("chan-1", std::slice::from_ref(&newer), Some(9000))
            .unwrap();
        // A repeated or older fetch stores what it has but never moves back.
        store
            .store_fetched("chan-1", std::slice::from_ref(&older), Some(9000))
            .unwrap();
        assert_eq!(
            store.channel("chan-1").unwrap().unwrap().position,
            Some(Position {
                created_at: 2000,
                id: newer.id.clone()
            })
        );
        assert!(store.cached_event(&older.id).unwrap().is_some());

        // A live event before the channel caught up is stored, position still.
        let early = event(&key(), 9, 3000);
        store
            .store_fetched("chan-1", std::slice::from_ref(&early), None)
            .unwrap();
        assert_eq!(
            store
                .channel("chan-1")
                .unwrap()
                .unwrap()
                .position
                .unwrap()
                .created_at,
            2000
        );
    }

    #[test]
    fn a_future_dated_event_never_pulls_the_position_past_the_fetch_clock() {
        // The relay admits created_at up to 900 s ahead. A position there would
        // start the next catch-up after events published in the meantime.
        let (_dir, store) = store();
        store.upsert_channel("chan-1", "infra").unwrap();
        let now_ish = event(&key(), 9, 10_000);
        let ahead = event(&key(), 9, 10_850);
        store
            .store_fetched("chan-1", &[now_ish.clone(), ahead.clone()], Some(10_010))
            .unwrap();
        assert_eq!(
            store.channel("chan-1").unwrap().unwrap().position,
            Some(Position {
                created_at: 10_000,
                id: now_ish.id
            })
        );
        assert!(
            store.cached_event(&ahead.id).unwrap().is_some(),
            "stored all the same"
        );
    }

    #[test]
    fn a_seeded_position_is_compare_and_set() {
        let (_dir, store) = store();
        store.upsert_channel("chan-1", "infra").unwrap();
        assert!(store.seed_position("chan-1", 5000, false).unwrap());
        assert!(
            store.seed_position("chan-1", 6000, false).unwrap(),
            "forward"
        );
        assert!(
            store.seed_position("chan-1", 6000, false).unwrap(),
            "the same value again is a no-op"
        );
        assert!(
            !store.seed_position("chan-1", 4000, false).unwrap(),
            "never backwards without force"
        );
        assert_eq!(
            store
                .channel("chan-1")
                .unwrap()
                .unwrap()
                .position
                .unwrap()
                .created_at,
            6000
        );
        assert!(store.seed_position("chan-1", 4000, true).unwrap());
        assert_eq!(
            store
                .channel("chan-1")
                .unwrap()
                .unwrap()
                .position
                .unwrap()
                .created_at,
            4000
        );
    }

    #[test]
    fn people_upsert_keeps_the_configured_home() {
        let (_dir, store) = store();
        store
            .upsert_person(&"aa".repeat(32), "michael", Some("michael"))
            .unwrap();
        store
            .upsert_person(&"aa".repeat(32), "michael", None)
            .unwrap();
        let person = store.person_by_name("michael").unwrap().unwrap();
        assert_eq!(person.home_slug.as_deref(), Some("michael"));
        assert!(person.active);

        store.retire_person(&"aa".repeat(32), 12345).unwrap();
        let person = store.person_by_pubkey(&"aa".repeat(32)).unwrap().unwrap();
        assert!(!person.active);
        assert_eq!(person.left_at, Some(12345));
        assert!(store.active_people().unwrap().is_empty());
        assert!(
            !store
                .insert_person_if_absent(&"aa".repeat(32), "michael", None)
                .unwrap(),
            "a configured person the rosters retired stays retired"
        );
        assert!(store.active_people().unwrap().is_empty());

        store
            .upsert_person(&"aa".repeat(32), "michael", None)
            .unwrap();
        assert!(store.active_people().unwrap().len() == 1);
    }

    #[test]
    fn author_classification_round_trips() {
        let (_dir, store) = store();
        let pubkey = "bb".repeat(32);
        store
            .put_author(&Author {
                pubkey: pubkey.clone(),
                kind: AuthorKind::Agent,
                hcom_name: Some("luna".into()),
                device_label: Some("boxe".into()),
            })
            .unwrap();
        let author = store.author(&pubkey).unwrap().unwrap();
        assert_eq!(author.kind, AuthorKind::Agent);
        assert_eq!(author.hcom_name.as_deref(), Some("luna"));
        assert_eq!(author.device_label.as_deref(), Some("boxe"));

        store
            .put_author(&Author {
                pubkey: pubkey.clone(),
                kind: AuthorKind::Person,
                hcom_name: None,
                device_label: None,
            })
            .unwrap();
        assert_eq!(
            store.author(&pubkey).unwrap().unwrap().kind,
            AuthorKind::Person
        );
        assert!(store.author(&"cc".repeat(32)).unwrap().is_none());
    }

    #[test]
    fn fetched_events_filter_by_channel_and_thread() {
        let (_dir, store) = store();
        let root = event(&key(), 9, 100);
        let reply = event_with(
            &key(),
            9,
            200,
            vec![vec![
                "e".into(),
                root.id.clone(),
                String::new(),
                "reply".into(),
            ]],
            "reply",
        );
        let other = event(&key(), 9, 300);
        store
            .store_fetched("chan-1", &[root.clone(), reply.clone()], None)
            .unwrap();
        store.store_fetched("chan-2", &[other], None).unwrap();

        assert_eq!(
            store
                .list_events(Some("chan-1"), None, None, 10)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            store
                .list_events(Some("chan-2"), None, None, 10)
                .unwrap()
                .len(),
            1
        );
        let thread = store
            .list_events(Some("chan-1"), Some(&root.id), None, 10)
            .unwrap();
        assert_eq!(thread.len(), 2, "root plus its reply");

        let before = store
            .list_events(Some("chan-1"), None, Some(&reply.id), 10)
            .unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].buzz_id, root.id);
        assert!(store.cached_event(&reply.id).unwrap().is_some());
    }

    #[test]
    fn continuing_a_read_keeps_same_second_events() {
        // Two events in one second, read one at a time: continuing after the
        // first must return the second, in both read paths.
        let (dir, store) = store();
        let first = event_with(&key(), 9, 700, vec![], "one");
        let second = event_with(&key(), 9, 700, vec![], "two");
        store
            .store_fetched("chan-1", &[first, second], None)
            .unwrap();
        let reader = Store::open_read_only(&dir.path().join("state.db")).unwrap();

        for (label, page) in [
            (
                "store",
                Box::new(|before: Option<&str>| {
                    store.list_events(Some("chan-1"), None, before, 1).unwrap()
                }) as Box<dyn Fn(Option<&str>) -> Vec<CachedEvent>>,
            ),
            (
                "read-only",
                Box::new(|before: Option<&str>| {
                    reader.list_events(Some("chan-1"), None, before, 1).unwrap()
                }),
            ),
        ] {
            let head = page(None);
            assert_eq!(head.len(), 1, "{label}");
            let next = page(Some(&head[0].buzz_id));
            assert_eq!(next.len(), 1, "{label}: the same-second neighbour follows");
            assert_ne!(next[0].buzz_id, head[0].buzz_id, "{label}");
            assert!(
                page(Some(&next[0].buzz_id)).is_empty(),
                "{label}: then nothing"
            );
        }
    }

    #[test]
    fn obligations_retry_then_close_through_a_stored_notice() {
        let (_dir, store) = store();
        let item = event(&key(), 9, 100);
        store
            .store_fetched("chan-1", std::slice::from_ref(&item), None)
            .unwrap();
        store
            .route_item(&item, &["luna".into(), "nina".into()], &owed(), 50)
            .unwrap();
        assert_eq!(
            store.inbox_state(&item.id).unwrap().as_deref(),
            Some("routed")
        );
        assert_eq!(
            store.thread("buzz_infra_e1").unwrap().unwrap().root_id,
            "e1",
            "the thread is recorded with the obligations"
        );

        let due = store.due_obligations(60).unwrap();
        assert_eq!(due.len(), 2);
        assert_eq!(
            due[0].delivery,
            owed(),
            "the routed delivery comes back intact"
        );

        store.defer_obligation(&item.id, "nina", 1, 500).unwrap();
        store.obligation_delivered(&item.id, "luna").unwrap();
        assert!(store.due_obligations(100).unwrap().is_empty());
        assert_eq!(store.finish_routed().unwrap(), 0, "nina is still owed");

        store
            .obligation_notice(&item.id, "nina", "{\"notice\":1}")
            .unwrap();
        let notice = store.due_obligations(600).unwrap();
        assert_eq!(notice.len(), 1);
        assert_eq!(notice[0].state, "notice");
        assert_eq!(notice[0].notice_json.as_deref(), Some("{\"notice\":1}"));
        assert_eq!(store.finish_routed().unwrap(), 0, "a notice is still owed");

        store.obligation_expired(&item.id, "nina").unwrap();
        assert_eq!(store.finish_routed().unwrap(), 1);
        assert_eq!(
            store.inbox_state(&item.id).unwrap().as_deref(),
            Some("done")
        );
        let counts = store.obligation_counts().unwrap();
        assert!(counts.contains(&("delivered".to_string(), 1)));
        assert!(counts.contains(&("expired".to_string(), 1)));
        assert!(store.was_routed(&item.id).unwrap(), "luna got it");
    }

    #[test]
    fn a_failed_routing_write_leaves_no_obligation_and_the_item_pending() {
        let (_dir, store) = store();
        let item = event(&key(), 9, 100);
        store
            .store_fetched("chan-1", std::slice::from_ref(&item), None)
            .unwrap();
        store
            .exec_for_test(
                "CREATE TRIGGER no_nina BEFORE INSERT ON obligations
                 WHEN NEW.target = 'nina'
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
        assert!(
            store
                .route_item(&item, &["luna".into(), "nina".into()], &owed(), 50)
                .is_err()
        );
        assert!(
            store.due_obligations(100).unwrap().is_empty(),
            "all or nothing"
        );
        assert_eq!(
            store.inbox_state(&item.id).unwrap().as_deref(),
            Some("pending")
        );
    }

    #[test]
    fn an_epoch_change_keeps_state_keyed_by_buzz_or_pubkey() {
        let (_dir, mut store) = store();
        let item = event(&key(), 9, 100);
        store
            .store_fetched("chan-1", std::slice::from_ref(&item), None)
            .unwrap();
        store
            .route_item(&item, &["luna".into()], &owed(), 0)
            .unwrap();
        assert_eq!(store.due_obligations(100).unwrap().len(), 1);

        assert!(store.adopt_epoch("epoch-2".into()).unwrap());
        assert!(!store.adopt_epoch("epoch-2".into()).unwrap(), "idempotent");
        assert_eq!(
            store.due_obligations(100).unwrap().len(),
            1,
            "an obligation is keyed by Buzz event id, not an hcom id"
        );
    }

    #[test]
    fn threads_map_both_ways() {
        let (_dir, store) = store();
        store
            .put_thread("buzz_infra_abc123", "chan-1", "root-id")
            .unwrap();
        let row = store.thread("buzz_infra_abc123").unwrap().unwrap();
        assert_eq!(row.channel_id, "chan-1");
        assert_eq!(row.root_id, "root-id");
        assert!(store.thread("other").unwrap().is_none());

        store
            .put_thread("buzz_infra_abc123", "chan-2", "root-2")
            .unwrap();
        assert_eq!(
            store
                .thread("buzz_infra_abc123")
                .unwrap()
                .unwrap()
                .channel_id,
            "chan-2"
        );
    }

    #[test]
    fn enrollment_state_is_per_agent_and_channel() {
        let (_dir, store) = store();
        let agent = derive_secret(&[7; 32], "luna@mbai");
        let agent_pubkey = crate::buzz::nostr::public_hex(&agent);
        assert!(store.enrollment(&agent_pubkey, "chan-1").unwrap().is_none());

        store
            .put_enrollment(&agent_pubkey, "chan-1", "enrolled")
            .unwrap();
        assert_eq!(
            store
                .enrollment(&agent_pubkey, "chan-1")
                .unwrap()
                .as_deref(),
            Some("enrolled")
        );
        assert!(store.enrollment(&agent_pubkey, "chan-2").unwrap().is_none());
        assert_eq!(store.enrolled_count().unwrap(), 1);

        let rows = store.enrollments().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].channel_id, "chan-1");
        assert_eq!(rows[0].state, "enrolled");

        store.drop_enrollment(&agent_pubkey, "chan-1").unwrap();
        assert_eq!(store.enrolled_count().unwrap(), 0);
    }

    #[test]
    fn read_only_view_reads_the_same_inbox() {
        let (dir, store) = store();
        let event = event(&key(), 9, 500);
        store
            .store_fetched("chan-1", std::slice::from_ref(&event), None)
            .unwrap();

        let path = dir.path().join("state.db");
        let reader = Store::open_read_only(&path).unwrap();
        let rows = reader.list_events(Some("chan-1"), None, None, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].buzz_id, event.id);
        assert_eq!(rows[0].kind, 9);
        assert_eq!(reader.event_count().unwrap(), 1);
    }

    #[test]
    fn read_only_open_of_a_missing_db_names_the_absence() {
        let dir = tempfile::tempdir().unwrap();
        let Err(err) = Store::open_read_only(&dir.path().join("state.db")) else {
            panic!("a missing state DB must be an error, not an empty answer");
        };
        assert!(err.to_string().contains("hcom buzz serve"), "{err}");
    }

    fn outbox_row(hcom_id: i64, destination: &str, buzz_id: &str) -> OutboxRow {
        OutboxRow {
            epoch: String::new(),
            hcom_id,
            destination: destination.into(),
            signer_name: "luna".into(),
            signed_json: "{}".into(),
            buzz_id: buzz_id.into(),
            recipients: vec!["michael".into()],
            state: "pending".into(),
            attempts: 0,
            next_at: 0,
            last_error: None,
        }
    }

    /// The row as the store holds it, epoch stamped.
    fn stored_row(store: &Store, hcom_id: i64, destination: &str) -> OutboxRow {
        store
            .unsent_outbox()
            .unwrap()
            .into_iter()
            .chain(store.posted_unlogged().unwrap())
            .find(|row| row.hcom_id == hcom_id && row.destination == destination)
            .expect("a stored row")
    }

    #[test]
    fn outbox_is_keyed_by_epoch_hcom_id_and_destination() {
        let (_dir, store) = store();
        assert!(store.prepare_outbox(&outbox_row(1, "chan-1", "a")).unwrap());
        assert!(
            !store.prepare_outbox(&outbox_row(1, "chan-1", "b")).unwrap(),
            "a re-read keeps the event first prepared"
        );
        assert_eq!(stored_row(&store, 1, "chan-1").buzz_id, "a");
        assert!(
            store.prepare_outbox(&outbox_row(1, "chan-2", "c")).unwrap(),
            "other destination"
        );
        assert!(
            store.prepare_outbox(&outbox_row(2, "chan-1", "d")).unwrap(),
            "other message"
        );
        let first = stored_row(&store, 1, "chan-1");
        assert_eq!(first.epoch, "epoch-1", "stamped by the store");
        assert_eq!(first.recipients, vec!["michael".to_string()]);

        assert_eq!(store.due_outbox("chan-1", 100).unwrap().len(), 2);
        store.retry_outbox(&first, 900, "503").unwrap();
        assert_eq!(store.due_outbox("chan-1", 100).unwrap().len(), 1);
        assert_eq!(store.due_outbox("chan-1", 1000).unwrap().len(), 2);

        store.mark_outbox_posted(&first, None).unwrap();
        store
            .fail_outbox(&stored_row(&store, 2, "chan-1"), "rejected: nope")
            .unwrap();
        assert_eq!(store.unsent_outbox().unwrap().len(), 2);
        assert_eq!(store.posted_unlogged().unwrap().len(), 1);
        store.mark_outbox_logged(&first).unwrap();
        assert!(store.posted_unlogged().unwrap().is_empty());

        let counts = store.outbox_counts().unwrap();
        assert!(counts.contains(&("logged".to_string(), 1)));
        assert!(counts.contains(&("failed".to_string(), 1)));
        assert!(counts.contains(&("pending".to_string(), 1)));
    }

    #[test]
    fn a_row_remembers_every_id_it_prepared() {
        let (_dir, store) = store();
        store.prepare_outbox(&outbox_row(1, "chan-1", "a")).unwrap();
        let row = stored_row(&store, 1, "chan-1");
        store.resign_outbox(&row, "b", "{\"b\":1}").unwrap();
        let row = stored_row(&store, 1, "chan-1");
        assert_eq!(row.buzz_id, "b");
        assert_eq!(row.state, "retry");
        store.resign_outbox(&row, "c", "{\"c\":1}").unwrap();
        assert_eq!(
            store
                .prepared_ids(&stored_row(&store, 1, "chan-1"))
                .unwrap(),
            vec!["a", "b", "c"]
        );
        // Another row's ids are its own.
        store.prepare_outbox(&outbox_row(1, "chan-2", "x")).unwrap();
        assert_eq!(
            store
                .prepared_ids(&stored_row(&store, 1, "chan-2"))
                .unwrap(),
            vec!["x"]
        );
    }

    #[test]
    fn an_epoch_change_keeps_unposted_outbox_sendable() {
        let (_dir, mut store) = store();
        store
            .prepare_outbox(&outbox_row(7, "chan-1", "buzz-7"))
            .unwrap();

        store.adopt_epoch("epoch-2".into()).unwrap();
        let due = store.due_outbox("chan-1", 100).unwrap();
        assert_eq!(
            due.len(),
            1,
            "an unposted post still goes out after hcom reset"
        );
        assert_eq!(due[0].hcom_id, 7);
        assert_eq!(
            due[0].epoch, "epoch-1",
            "keyed under the epoch it was prepared in"
        );

        store.mark_outbox_posted(&due[0], None).unwrap();
        assert!(store.unsent_outbox().unwrap().is_empty());
        assert_eq!(store.epoch(), "epoch-2");
    }

    #[test]
    fn outbox_rows_under_one_epoch_do_not_collide_after_a_change() {
        let (_dir, mut store) = store();
        store
            .prepare_outbox(&outbox_row(1, "chan-1", "buzz-1"))
            .unwrap();

        // After a reset, hcom ids restart from 1 and a new message is
        // prepared under the same id: the unposted row must not swallow it.
        store.adopt_epoch("epoch-2".into()).unwrap();
        store
            .prepare_outbox(&outbox_row(1, "chan-1", "buzz-1-fresh"))
            .unwrap();
        let due = store.due_outbox("chan-1", 100).unwrap();
        assert_eq!(due.len(), 2);
        let old = due.iter().find(|row| row.buzz_id == "buzz-1").unwrap();
        store.mark_outbox_posted(old, None).unwrap();
        let due = store.due_outbox("chan-1", 100).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].buzz_id, "buzz-1-fresh");
    }

    #[test]
    fn recent_errors_are_newest_first() {
        let (_dir, store) = store();
        for (id, error) in [(1_i64, "first"), (2, "second")] {
            store
                .prepare_outbox(&outbox_row(id, "chan-1", &format!("b{id}")))
                .unwrap();
            store
                .fail_outbox(&stored_row(&store, id, "chan-1"), error)
                .unwrap();
        }
        let errors = store.recent_errors(10).unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].2, "second");
    }
}
