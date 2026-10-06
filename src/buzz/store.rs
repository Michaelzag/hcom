//! Connector state: `~/.hcom/buzz/state.db`.
//!
//! Everything the connector remembers between runs. Every hcom event id stored
//! here is scoped by the hcom DB epoch (`hcom.db` inode + kv
//! `relay_local_reset_ts`), so a `hcom reset` drops id-keyed lookups instead of
//! replaying unrelated history. Buzz event ids need no epoch: the relay keeps
//! them unique.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::buzz::nostr::Event;

/// How long a parked inbound target keeps being retried before the connector
/// says so in Buzz.
pub const PARK_RETRY_WINDOW_SECS: u64 = 15 * 60;

/// Backfill window subtracted from a channel cursor, matching the relay's
/// 900 s admission window for backdated events.
pub const BACKFILL_SLACK_SECS: u64 = 960;

/// An entry older than this and still unacked is looked up by id before it is
/// re-signed with a fresh `created_at`.
pub const STALE_OUTBOX_SECS: u64 = 840;

/// Kinds the reader subscribes to, per bridged channel.
pub const CHANNEL_KINDS: &[u16] = &[9, 40002, 45001, 45003, 40003, 5, 9005, 39002];

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

/// A cached Buzz event: enough for `read` and for ancestry walking.
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

/// A person row in the roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonRow {
    pub pubkey: String,
    pub name: String,
    pub home_slug: Option<String>,
    pub active: bool,
    pub left_at: Option<i64>,
}

/// A bridged channel's connector state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRow {
    pub id: String,
    pub slug: String,
    pub cursor_created_at: Option<u64>,
    pub parked_reason: Option<String>,
}

/// One outbound post: a signed event bound to a destination channel.
///
/// The epoch is not a field: the store stamps the epoch it was queued under, so
/// a caller cannot queue a post against a stale one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    pub hcom_id: i64,
    pub destination: String,
    pub signer_name: String,
    pub signed_json: String,
    pub buzz_id: String,
    pub state: String,
    pub attempts: u32,
    pub next_at: i64,
    pub last_error: Option<String>,
}

/// A parked inbound target awaiting a live hcom row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkedTarget {
    pub buzz_id: String,
    pub target: String,
    pub state: String,
    pub attempts: u32,
    pub next_at: i64,
    /// When the target was first parked; the retry window runs from here.
    pub first_parked_at: i64,
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
    /// Open (creating when missing) the connector state DB.
    pub fn open(path: &Path, epoch: String) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("cannot open {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self { conn, epoch };
        store.migrate()?;
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
                cursor_created_at INTEGER,
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
             CREATE TABLE IF NOT EXISTS events_cache (
                buzz_id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                kind INTEGER NOT NULL,
                author TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                root_id TEXT,
                parent_id TEXT,
                json TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS events_cache_channel
                ON events_cache (channel_id, created_at);
             CREATE INDEX IF NOT EXISTS events_cache_author
                ON events_cache (author, kind);
             CREATE TABLE IF NOT EXISTS seen (buzz_id TEXT PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS delivered (buzz_id TEXT PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS inbound_targets (
                buzz_id TEXT NOT NULL,
                target TEXT NOT NULL,
                state TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_at INTEGER NOT NULL DEFAULT 0,
                first_parked_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (buzz_id, target));
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
                state TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_at INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (epoch, hcom_id, destination));
             CREATE INDEX IF NOT EXISTS outbox_due ON outbox (state, next_at);
             CREATE INDEX IF NOT EXISTS outbox_buzz ON outbox (buzz_id);",
        )?;
        Ok(())
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

    /// Insert or refresh a bridged channel row, preserving its cursor.
    pub fn upsert_channel(&self, id: &str, slug: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO channels (id, slug) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET slug = excluded.slug",
            params![id, slug],
        )?;
        Ok(())
    }

    /// Every bridged channel with its cursor and parked reason.
    pub fn channels(&self) -> Result<Vec<ChannelRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, slug, cursor_created_at, parked_reason FROM channels ORDER BY slug",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ChannelRow {
                    id: row.get(0)?,
                    slug: row.get(1)?,
                    cursor_created_at: row.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                    parked_reason: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Look up one channel row.
    pub fn channel(&self, id: &str) -> Result<Option<ChannelRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, slug, cursor_created_at, parked_reason FROM channels WHERE id = ?1",
                params![id],
                |row| {
                    Ok(ChannelRow {
                        id: row.get(0)?,
                        slug: row.get(1)?,
                        cursor_created_at: row.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                        parked_reason: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// Advance a channel's backfill cursor.
    pub fn set_channel_cursor(&self, id: &str, created_at: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE channels SET cursor_created_at = ?2 WHERE id = ?1",
            params![id, created_at as i64],
        )?;
        Ok(())
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
        let tx = self.conn.unchecked_transaction()?;
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
        let mut stmt = self
            .conn
            .prepare("SELECT pubkey, name, home_slug, active, left_at FROM people ORDER BY name")?;
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

    /// Active person rows only, in name order.
    pub fn active_people(&self) -> Result<Vec<PersonRow>> {
        Ok(self.people()?.into_iter().filter(|p| p.active).collect())
    }

    /// Look up one person by hcom name.
    pub fn person_by_name(&self, name: &str) -> Result<Option<PersonRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT pubkey, name, home_slug, active, left_at FROM people WHERE name = ?1",
                params![name],
                |row| {
                    Ok(PersonRow {
                        pubkey: row.get(0)?,
                        name: row.get(1)?,
                        home_slug: row.get(2)?,
                        active: row.get::<_, i64>(3)? != 0,
                        left_at: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// Look up one person by pubkey.
    pub fn person_by_pubkey(&self, pubkey: &str) -> Result<Option<PersonRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT pubkey, name, home_slug, active, left_at FROM people WHERE pubkey = ?1",
                params![pubkey],
                |row| {
                    Ok(PersonRow {
                        pubkey: row.get(0)?,
                        name: row.get(1)?,
                        home_slug: row.get(2)?,
                        active: row.get::<_, i64>(3)? != 0,
                        left_at: row.get(4)?,
                    })
                },
            )
            .optional()?)
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

    // ── events ───────────────────────────────────────────────────────────

    /// Cache an event for `read` and ancestry.
    pub fn cache_event(&self, event: &CachedEvent) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events_cache
                (buzz_id, channel_id, kind, author, created_at, root_id, parent_id, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(buzz_id) DO UPDATE SET
                channel_id = excluded.channel_id,
                kind = excluded.kind,
                author = excluded.author,
                created_at = excluded.created_at,
                root_id = excluded.root_id,
                parent_id = excluded.parent_id,
                json = excluded.json",
            params![
                event.buzz_id,
                event.channel_id,
                event.kind,
                event.author,
                event.created_at as i64,
                event.root_id,
                event.parent_id,
                event.json
            ],
        )?;
        Ok(())
    }

    /// One cached event by Buzz id.
    pub fn cached_event(&self, buzz_id: &str) -> Result<Option<CachedEvent>> {
        Ok(self
            .conn
            .query_row(
                "SELECT buzz_id, channel_id, kind, author, created_at, root_id, parent_id, json
                 FROM events_cache WHERE buzz_id = ?1",
                params![buzz_id],
                row_to_cached,
            )
            .optional()?)
    }

    /// Cached events in a channel, newest first, optionally limited to a thread
    /// and continued before `before`.
    pub fn list_events(
        &self,
        channel_id: Option<&str>,
        thread: Option<&str>,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CachedEvent>> {
        let mut sql = String::from(
            "SELECT buzz_id, channel_id, kind, author, created_at, root_id, parent_id, json
             FROM events_cache WHERE 1=1",
        );
        let mut binds: Vec<String> = Vec::new();
        if let Some(channel_id) = channel_id {
            sql.push_str(" AND channel_id = ?");
            binds.push(channel_id.to_string());
        }
        if let Some(thread) = thread {
            sql.push_str(" AND (buzz_id = ? OR root_id = ? OR parent_id = ?)");
            binds.extend([thread.to_string(), thread.to_string(), thread.to_string()]);
        }
        if let Some(before) = before {
            sql.push_str(
                " AND created_at < (SELECT created_at FROM events_cache WHERE buzz_id = ?)",
            );
            binds.push(before.to_string());
        }
        sql.push_str(" ORDER BY created_at DESC, buzz_id ASC LIMIT ?");
        binds.push(limit.to_string());

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(binds), row_to_cached)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Mark an inbound event as processed. True when it was new.
    pub fn mark_seen(&self, buzz_id: &str) -> Result<bool> {
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO seen (buzz_id) VALUES (?1)",
            params![buzz_id],
        )?;
        Ok(inserted == 1)
    }

    /// True when the Buzz event was already handed to hcom.
    pub fn was_delivered(&self, buzz_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM delivered WHERE buzz_id = ?1",
                params![buzz_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Record that the Buzz event reached hcom.
    pub fn mark_delivered(&self, buzz_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO delivered (buzz_id) VALUES (?1)",
            params![buzz_id],
        )?;
        Ok(())
    }

    // ── parked inbound targets ───────────────────────────────────────────

    /// Park an unresolvable inbound target for retry.
    pub fn park_target(&self, buzz_id: &str, target: &str, next_at: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO inbound_targets
                (buzz_id, target, state, attempts, next_at, first_parked_at)
             VALUES (?1, ?2, 'parked', 0, ?3, ?3)
             ON CONFLICT(buzz_id, target) DO UPDATE SET
                state = 'parked', next_at = excluded.next_at",
            params![buzz_id, target, next_at],
        )?;
        Ok(())
    }

    /// Parked targets whose retry time has come, oldest first.
    pub fn due_targets(&self, now: i64) -> Result<Vec<ParkedTarget>> {
        let mut stmt = self.conn.prepare(
            "SELECT buzz_id, target, state, attempts, next_at, first_parked_at
             FROM inbound_targets
             WHERE state = 'parked' AND next_at <= ?1
             ORDER BY next_at, buzz_id",
        )?;
        let rows = stmt
            .query_map(params![now], |row| {
                Ok(ParkedTarget {
                    buzz_id: row.get(0)?,
                    target: row.get(1)?,
                    state: row.get(2)?,
                    attempts: row.get(3)?,
                    next_at: row.get(4)?,
                    first_parked_at: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Move a parked target's window start, so a test can age it without
    /// waiting out the real retry window.
    #[cfg(test)]
    pub fn age_parked_target(&self, buzz_id: &str, first_parked_at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE inbound_targets SET first_parked_at = ?2, next_at = ?2 WHERE buzz_id = ?1",
            params![buzz_id, first_parked_at],
        )?;
        Ok(())
    }

    /// Mark a parked target resolved, given, or still parked with a longer wait.
    pub fn update_target(
        &self,
        buzz_id: &str,
        target: &str,
        state: &str,
        next_at: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE inbound_targets SET state = ?3, next_at = ?4 WHERE buzz_id = ?1 AND target = ?2",
            params![buzz_id, target, state, next_at],
        )?;
        Ok(())
    }

    /// Drop parked targets whose retry window has expired.
    pub fn expire_targets(&self, buzz_id: &str, target: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE inbound_targets SET state = 'expired', next_at = 0
             WHERE buzz_id = ?1 AND target = ?2",
            params![buzz_id, target],
        )?;
        Ok(())
    }

    /// Parked-target counts by state, for `hcom buzz status`.
    pub fn target_counts(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT state, COUNT(*) FROM inbound_targets GROUP BY state")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
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
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM enrollment WHERE state = 'enrolled'",
            [],
            |row| row.get(0),
        )?)
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

    /// Forget an agent's enrollment in every channel.
    pub fn drop_enrollment(&self, agent_pubkey: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM enrollment WHERE agent_pubkey = ?1",
            params![agent_pubkey],
        )?;
        Ok(())
    }

    // ── outbox ───────────────────────────────────────────────────────────

    /// Queue one signed post. The (epoch, hcom id, destination) key makes a
    /// re-read of the same hcom message a no-op.
    pub fn enqueue_outbox(&self, row: &OutboxRow) -> Result<bool> {
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO outbox
                (epoch, hcom_id, destination, signer_name, signed_json, buzz_id,
                 state, attempts, next_at, last_error, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', 0, ?7, NULL, ?8)",
            params![
                self.epoch,
                row.hcom_id,
                row.destination,
                row.signer_name,
                row.signed_json,
                row.buzz_id,
                row.next_at,
                crate::shared::time::now_epoch_i64()
            ],
        )?;
        Ok(inserted == 1)
    }

    /// Outbox rows for one destination channel whose retry time has come.
    ///
    /// Not epoch-filtered: an unposted row carries its own signed event, so it
    /// still goes out after a `hcom reset` moved every hcom id under it.
    pub fn due_outbox(&self, destination: &str, now: i64) -> Result<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT epoch, hcom_id, destination, signer_name, signed_json, buzz_id,
                    state, attempts, next_at, last_error
             FROM outbox
             WHERE destination = ?1 AND state IN ('pending', 'retry')
               AND next_at <= ?2
             ORDER BY hcom_id, buzz_id",
        )?;
        let rows = stmt
            .query_map(params![destination, now], row_to_outbox)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Outbox rows unacked for longer than `STALE_OUTBOX_SECS`.
    pub fn stale_outbox(&self, now: i64) -> Result<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT epoch, hcom_id, destination, signer_name, signed_json, buzz_id,
                    state, attempts, next_at, last_error
             FROM outbox
             WHERE state IN ('pending', 'retry') AND created_at <= ?1
             ORDER BY created_at, hcom_id",
        )?;
        let rows = stmt
            .query_map(params![now - STALE_OUTBOX_SECS as i64], row_to_outbox)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Acknowledge a delivered post, identified by its Buzz event id: the id
    /// is globally unique, so it survives an epoch change the hcom id does not.
    pub fn ack_outbox(&self, buzz_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET state = 'sent', attempts = attempts + 1, last_error = NULL
             WHERE buzz_id = ?1",
            params![buzz_id],
        )?;
        Ok(())
    }

    /// Reschedule a post that failed transiently.
    pub fn retry_outbox(&self, buzz_id: &str, next_at: i64, error: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox
             SET state = 'retry', attempts = attempts + 1, next_at = ?2, last_error = ?3
             WHERE buzz_id = ?1",
            params![buzz_id, next_at, error],
        )?;
        Ok(())
    }

    /// Mark a post the relay will never accept.
    pub fn fail_outbox(&self, buzz_id: &str, error: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET state = 'failed', attempts = attempts + 1, last_error = ?2
             WHERE buzz_id = ?1",
            params![buzz_id, error],
        )?;
        Ok(())
    }

    /// Replace an outbox row's signed event after an id lookup proved the relay
    /// never stored the old one. `hcom_id`/`destination` identify the row.
    pub fn replace_outbox_event(
        &self,
        hcom_id: i64,
        destination: &str,
        buzz_id: &str,
        signed_json: &str,
        created_at: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE outbox SET buzz_id = ?3, signed_json = ?4, created_at = ?5
             WHERE epoch = ?1 AND hcom_id = ?2 AND destination = ?6",
            params![
                self.epoch,
                hcom_id,
                destination,
                buzz_id,
                signed_json,
                created_at
            ],
        )?;
        Ok(())
    }

    /// Remove an outbox row once its replacement is queued.
    pub fn drop_outbox(&self, buzz_id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM outbox WHERE buzz_id = ?1", params![buzz_id])?;
        Ok(())
    }

    /// Outbox counts by state, for `hcom buzz status`.
    pub fn outbox_counts(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT state, COUNT(*) FROM outbox GROUP BY state")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every non-sent outbox row, for `hcom buzz down`'s leftovers report.
    pub fn unsent_outbox(&self) -> Result<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT epoch, hcom_id, destination, signer_name, signed_json, buzz_id,
                    state, attempts, next_at, last_error
             FROM outbox
             WHERE state != 'sent'
             ORDER BY created_at, hcom_id",
        )?;
        let rows = stmt
            .query_map([], row_to_outbox)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Most recent outbox failures, newest first, for status output.
    pub fn recent_errors(&self, limit: usize) -> Result<Vec<(String, i64, String)>> {
        let mut stmt = self.conn.prepare(
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
    Ok(OutboxRow {
        hcom_id: row.get(1)?,
        destination: row.get(2)?,
        signer_name: row.get(3)?,
        signed_json: row.get(4)?,
        buzz_id: row.get(5)?,
        state: row.get(6)?,
        attempts: row.get::<_, i64>(7)? as u32,
        next_at: row.get(8)?,
        last_error: row.get(9)?,
    })
}

impl ReadOnlyStore {
    /// Bridged channels with cursors and parked reasons, for `buzz status`.
    pub fn channels(&self) -> Result<Vec<ChannelRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, slug, cursor_created_at, parked_reason FROM channels ORDER BY slug",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ChannelRow {
                    id: row.get(0)?,
                    slug: row.get(1)?,
                    cursor_created_at: row.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                    parked_reason: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// One channel row by id.
    pub fn channel(&self, id: &str) -> Result<Option<ChannelRow>> {
        Ok(self.channels()?.into_iter().find(|row| row.id == id))
    }

    /// Every person row.
    pub fn people(&self) -> Result<Vec<PersonRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT pubkey, name, home_slug, active, left_at FROM people ORDER BY name")?;
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

    /// Outbox counts by state.
    pub fn outbox_counts(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT state, COUNT(*) FROM outbox GROUP BY state")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Parked-target counts by state.
    pub fn target_counts(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT state, COUNT(*) FROM inbound_targets GROUP BY state")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Number of agent-channel pairs currently enrolled.
    pub fn enrolled_count(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM enrollment WHERE state = 'enrolled'",
            [],
            |row| row.get(0),
        )?)
    }

    /// Every outbox row that has not been acknowledged.
    pub fn unsent_outbox(&self) -> Result<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT epoch, hcom_id, destination, signer_name, signed_json, buzz_id,
                    state, attempts, next_at, last_error
             FROM outbox
             WHERE state != 'sent'
             ORDER BY created_at, hcom_id",
        )?;
        let rows = stmt
            .query_map([], row_to_outbox)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The most recent outbox failures, newest first.
    pub fn recent_errors(&self, limit: usize) -> Result<Vec<(String, i64, String)>> {
        let mut stmt = self.conn.prepare(
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

    /// Cached events for `buzz read` and the `buzz_read` RPC.
    pub fn list_events(
        &self,
        channel_id: Option<&str>,
        thread: Option<&str>,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CachedEvent>> {
        let mut sql = String::from(
            "SELECT buzz_id, channel_id, kind, author, created_at, root_id, parent_id, json
             FROM events_cache WHERE 1=1",
        );
        let mut binds: Vec<String> = Vec::new();
        if let Some(channel_id) = channel_id {
            sql.push_str(" AND channel_id = ?");
            binds.push(channel_id.to_string());
        }
        if let Some(thread) = thread {
            sql.push_str(" AND (buzz_id = ? OR root_id = ? OR parent_id = ?)");
            binds.extend([thread.to_string(), thread.to_string(), thread.to_string()]);
        }
        if let Some(before) = before {
            sql.push_str(
                " AND created_at < (SELECT created_at FROM events_cache WHERE buzz_id = ?)",
            );
            binds.push(before.to_string());
        }
        sql.push_str(" ORDER BY created_at DESC, buzz_id ASC LIMIT ?");
        binds.push(limit.to_string());

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(binds), row_to_cached)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Number of cached events, for the RPC's answer summary.
    pub fn event_count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM events_cache", [], |row| row.get(0))?)
    }
}

/// Build the cached row for a verified event.
pub fn cached_from_event(
    event: &Event,
    channel_id: &str,
    root_id: Option<&str>,
    parent_id: Option<&str>,
) -> Result<CachedEvent> {
    Ok(CachedEvent {
        buzz_id: event.id.clone(),
        channel_id: channel_id.to_string(),
        kind: event.kind,
        author: event.pubkey.clone(),
        created_at: event.created_at,
        root_id: root_id.map(str::to_string),
        parent_id: parent_id.map(str::to_string),
        json: serde_json::to_string(event).context("event serializes")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buzz::nostr::{Event, UnsignedEvent, derive_secret, sign};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state.db"), "epoch-1".into()).unwrap();
        (dir, store)
    }

    fn event(key: &crate::buzz::nostr::SecretKey, kind: u16, created_at: u64) -> Event {
        sign(
            UnsignedEvent {
                created_at,
                kind,
                tags: vec![vec!["h".into(), "chan-1".into()]],
                content: format!("body {kind}"),
            },
            key,
        )
    }

    #[test]
    fn open_creates_schema_and_is_repeatable() {
        let (dir, store) = store();
        assert_eq!(store.epoch(), "epoch-1");
        assert!(store.channels().unwrap().is_empty());
        drop(store);
        let reopened = Store::open(&dir.path().join("state.db"), "epoch-1".into()).unwrap();
        assert_eq!(reopened.epoch(), "epoch-1");
    }

    #[test]
    fn channel_cursor_survives_a_upsert() {
        let (_dir, store) = store();
        store.upsert_channel("chan-1", "infra").unwrap();
        store.set_channel_cursor("chan-1", 1000).unwrap();
        store
            .set_channel_parked("chan-1", Some("closed: rate-limited"))
            .unwrap();
        store.upsert_channel("chan-1", "infra-renamed").unwrap();

        let row = store.channel("chan-1").unwrap().unwrap();
        assert_eq!(row.slug, "infra-renamed");
        assert_eq!(row.cursor_created_at, Some(1000));
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
    fn seen_and_delivered_are_dedupe_sets() {
        let (_dir, store) = store();
        assert!(store.mark_seen("e1").unwrap());
        assert!(!store.mark_seen("e1").unwrap());
        assert!(!store.was_delivered("e1").unwrap());
        store.mark_delivered("e1").unwrap();
        assert!(store.was_delivered("e1").unwrap());
    }

    #[test]
    fn events_cache_filters_by_channel_and_thread() {
        let (_dir, store) = store();
        let key = derive_secret(&[9; 32], "TEST@mbai");
        let root = event(&key, 9, 100);
        let reply = event(&key, 9, 200);
        let other = event(&key, 9, 300);

        store
            .cache_event(&cached_from_event(&root, "chan-1", None, None).unwrap())
            .unwrap();
        store
            .cache_event(
                &cached_from_event(&reply, "chan-1", Some(&root.id), Some(&root.id)).unwrap(),
            )
            .unwrap();
        store
            .cache_event(&cached_from_event(&other, "chan-2", None, None).unwrap())
            .unwrap();

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

        assert_eq!(
            store
                .list_events(Some("chan-1"), None, None, 1)
                .unwrap()
                .len(),
            1
        );
        assert!(store.cached_event(&reply.id).unwrap().is_some());
    }

    #[test]
    fn parked_targets_retry_then_expire() {
        let (_dir, store) = store();
        store.park_target("e1", "luna", 500).unwrap();
        store.park_target("e1", "nina", 100).unwrap();

        assert!(
            store.due_targets(50).unwrap().is_empty(),
            "nothing is due before its retry time"
        );
        let first = store.due_targets(200).unwrap();
        assert_eq!(first.len(), 1, "only the target whose retry time has come");
        assert_eq!(first[0].target, "nina");

        let due = store.due_targets(600).unwrap();
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].target, "nina", "oldest retry first");

        store.update_target("e1", "luna", "delivered", 0).unwrap();
        assert!(
            !store
                .due_targets(600)
                .unwrap()
                .iter()
                .any(|t| t.target == "luna")
        );

        store.expire_targets("e1", "nina").unwrap();
        assert!(store.due_targets(i64::MAX / 2).unwrap().is_empty());
        let counts = store.target_counts().unwrap();
        assert!(
            counts
                .iter()
                .any(|(state, n)| state == "delivered" && *n == 1)
        );
        assert!(
            counts
                .iter()
                .any(|(state, n)| state == "expired" && *n == 1)
        );
    }

    #[test]
    fn an_epoch_change_keeps_state_keyed_by_buzz_or_pubkey() {
        let (_dir, mut store) = store();
        store.park_target("e1", "luna", 0).unwrap();
        assert_eq!(store.due_targets(100).unwrap().len(), 1);

        assert!(store.adopt_epoch("epoch-2".into()).unwrap());
        assert!(!store.adopt_epoch("epoch-2".into()).unwrap(), "idempotent");
        assert_eq!(
            store.due_targets(100).unwrap().len(),
            1,
            "a parked target is keyed by Buzz event id, not an hcom id"
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
    fn outbox_is_keyed_by_epoch_hcom_id_and_destination() {
        let (_dir, store) = store();
        let row = |id: i64, destination: &str| OutboxRow {
            hcom_id: id,
            destination: destination.into(),
            signer_name: "luna".into(),
            signed_json: "{}".into(),
            buzz_id: format!("buzz-{id}-{destination}"),
            state: "pending".into(),
            attempts: 0,
            next_at: 0,
            last_error: None,
        };

        assert!(store.enqueue_outbox(&row(1, "chan-1")).unwrap());
        assert!(
            !store.enqueue_outbox(&row(1, "chan-1")).unwrap(),
            "same key twice"
        );
        assert!(
            store.enqueue_outbox(&row(1, "chan-2")).unwrap(),
            "other destination"
        );
        assert!(
            store.enqueue_outbox(&row(2, "chan-1")).unwrap(),
            "other message"
        );

        assert_eq!(store.due_outbox("chan-1", 100).unwrap().len(), 2);
        assert_eq!(store.unsent_outbox().unwrap().len(), 3);

        store.retry_outbox("buzz-1-chan-1", 900, "503").unwrap();
        assert_eq!(store.due_outbox("chan-1", 100).unwrap().len(), 1);
        assert_eq!(store.due_outbox("chan-1", 1000).unwrap().len(), 2);

        store.ack_outbox("buzz-1-chan-1").unwrap();
        store
            .fail_outbox("buzz-2-chan-1", "rejected: nope")
            .unwrap();
        assert_eq!(store.unsent_outbox().unwrap().len(), 2);

        let counts = store.outbox_counts().unwrap();
        assert!(counts.iter().any(|(state, n)| state == "sent" && *n == 1));
        assert!(counts.iter().any(|(state, n)| state == "failed" && *n == 1));
        assert!(
            counts
                .iter()
                .any(|(state, n)| state == "pending" && *n == 1)
        );
    }

    #[test]
    fn an_epoch_change_keeps_unposted_outbox_sendable() {
        let (_dir, mut store) = store();
        store
            .enqueue_outbox(&OutboxRow {
                hcom_id: 7,
                destination: "chan-1".into(),
                signer_name: "luna".into(),
                signed_json: "{}".into(),
                buzz_id: "buzz-7".into(),
                state: "pending".into(),
                attempts: 0,
                next_at: 0,
                last_error: None,
            })
            .unwrap();

        store.adopt_epoch("epoch-2".into()).unwrap();
        let due = store.due_outbox("chan-1", 100).unwrap();
        assert_eq!(
            due.len(),
            1,
            "an unposted post still goes out after hcom reset"
        );
        assert_eq!(due[0].hcom_id, 7);
        assert_eq!(store.unsent_outbox().unwrap().len(), 1);

        store.ack_outbox("buzz-7").unwrap();
        assert!(store.unsent_outbox().unwrap().is_empty());
        assert_eq!(store.epoch(), "epoch-2");
    }

    #[test]
    fn outbox_rows_under_one_epoch_do_not_collide_after_a_change() {
        let (_dir, mut store) = store();
        let row = |id: i64, buzz: &str| OutboxRow {
            hcom_id: id,
            destination: "chan-1".into(),
            signer_name: "luna".into(),
            signed_json: "{}".into(),
            buzz_id: buzz.into(),
            state: "pending".into(),
            attempts: 0,
            next_at: 0,
            last_error: None,
        };
        store.enqueue_outbox(&row(1, "buzz-1")).unwrap();

        // After a reset, hcom ids restart from 1 and a new message queues under
        // the same id: the unposted row must not be swallowed by its key.
        store.adopt_epoch("epoch-2".into()).unwrap();
        store.enqueue_outbox(&row(1, "buzz-1-fresh")).unwrap();
        assert_eq!(store.due_outbox("chan-1", 100).unwrap().len(), 2);
        store.ack_outbox("buzz-1").unwrap();
        let due = store.due_outbox("chan-1", 100).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].buzz_id, "buzz-1-fresh");
    }

    #[test]
    fn stale_outbox_only_returns_old_unacked_rows() {
        let (_dir, store) = store();
        let now = crate::shared::time::now_epoch_i64();
        store
            .enqueue_outbox(&OutboxRow {
                hcom_id: 1,
                destination: "chan-1".into(),
                signer_name: "luna".into(),
                signed_json: "{}".into(),
                buzz_id: "a".into(),
                state: "pending".into(),
                attempts: 0,
                next_at: 0,
                last_error: None,
            })
            .unwrap();
        assert!(store.stale_outbox(now).unwrap().is_empty(), "fresh row");
        assert!(
            store
                .stale_outbox(now + STALE_OUTBOX_SECS as i64 + 5)
                .unwrap()
                .len()
                == 1
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

        store.drop_enrollment(&agent_pubkey).unwrap();
        assert_eq!(store.enrolled_count().unwrap(), 0);
    }

    #[test]
    fn read_only_view_reads_the_same_cache() {
        let (dir, store) = store();
        let key = derive_secret(&[9; 32], "TEST@mbai");
        let event = event(&key, 9, 500);
        store
            .cache_event(&cached_from_event(&event, "chan-1", None, None).unwrap())
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

    #[test]
    fn recent_errors_are_newest_first() {
        let (_dir, store) = store();
        for (id, error) in [(1_i64, "first"), (2, "second")] {
            store
                .enqueue_outbox(&OutboxRow {
                    hcom_id: id,
                    destination: "chan-1".into(),
                    signer_name: "luna".into(),
                    signed_json: "{}".into(),
                    buzz_id: format!("b{id}"),
                    state: "pending".into(),
                    attempts: 0,
                    next_at: 0,
                    last_error: None,
                })
                .unwrap();
            store.fail_outbox(&format!("b{id}"), error).unwrap();
        }
        let errors = store.recent_errors(10).unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].2, "second");
    }
}
