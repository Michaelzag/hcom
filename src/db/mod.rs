//! SQLite database access for hcom
//!
//! Three loosely-coupled state planes live in a single DB:
//! - `instances`: live per-agent state (TUI display, gating, delivery cursors)
//! - `events`: append-only history / message log / relay replication source
//! - `process_bindings`, `session_bindings`, `notify_endpoints`, `kv`: routing
//!   and control-plane state
//!
//! Callers typically write an event, advance per-instance cursors separately,
//! and touch bindings/endpoints/kv for delivery, identity resolution, relay
//! cursors, request-watch bookkeeping, and other control-plane state.
//!
//! Includes:
//! - Reading unread messages from `events`
//! - Updating cursor position (instances.last_event_id)
//! - Reading instance status
//! - Registering notify endpoints

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, Transaction, TransactionBehavior};

use crate::shared::time::now_epoch_f64;

mod claude_actors;
mod events;
mod instances;
mod kv;
mod notify;
pub(crate) mod reqwatch_policy;
mod sessions;
pub(crate) mod subscriptions;

pub use events::Message;
pub use instances::InstanceRow;
#[allow(unused_imports)]
pub use instances::InstanceStatus;

/// Schema version - bump on any schema change.
const SCHEMA_VERSION: i32 = 20;
pub const DEV_ROOT_KV_KEY: &str = "config:dev_root";
const MIGRATIONS: &[(i32, &str)] = &[
    (
        17,
        "ALTER TABLE instances ADD COLUMN terminal_preset_requested TEXT DEFAULT '';
         ALTER TABLE instances ADD COLUMN terminal_preset_effective TEXT DEFAULT '';
         UPDATE instances
         SET terminal_preset_effective = json_extract(launch_context, '$.terminal_preset')
         WHERE launch_context != '' AND json_valid(launch_context) AND json_extract(launch_context, '$.terminal_preset') IS NOT NULL;",
    ),
    (
        18,
        "ALTER TABLE instances ADD COLUMN last_seen INTEGER DEFAULT 0;
         CREATE TABLE IF NOT EXISTS claude_actor_capabilities (
             token TEXT PRIMARY KEY,
             session_id TEXT NOT NULL,
             tool_use_id TEXT NOT NULL,
             agent_id TEXT NOT NULL DEFAULT '',
             instance_name TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             expires_at INTEGER NOT NULL,
             last_seen INTEGER NOT NULL,
             UNIQUE(session_id, tool_use_id, agent_id)
         );
         CREATE INDEX IF NOT EXISTS idx_claude_actor_expiry
             ON claude_actor_capabilities(expires_at);
         CREATE INDEX IF NOT EXISTS idx_claude_actor_session
             ON claude_actor_capabilities(session_id);",
    ),
    (
        19,
        "ALTER TABLE instances ADD COLUMN purpose TEXT DEFAULT '';
         ALTER TABLE instances ADD COLUMN current TEXT DEFAULT '';",
    ),
    (
        20,
        "SELECT 1;",
    ),
];

/// Schema compatibility check result
enum SchemaCompat {
    /// Schema is compatible (or fresh DB) — proceed with init_db
    Ok,
    /// Schema is incompatible — archive, reconnect, reinit
    NeedsArchive(String, Option<i32>),
    /// DB is newer than code — stale process, work with existing schema
    StaleProcess,
}

/// Database handle for hcom operations
pub struct HcomDb {
    conn: Connection,
    db_path: std::path::PathBuf,
    db_inode: u64,
}

fn get_inode(path: &std::path::Path) -> u64 {
    crate::sys::fs::file_id(path)
}

/// Reject filesystem-backed unit-test databases that are not disposable state.
/// This is a last-resort tripwire for code paths that bypass Config entirely.
///
/// A path is disposable if a fixture registered its root, or if it sits under
/// the system temp tree — the backstop for ad-hoc `tempfile` DBs opened by
/// explicit path. Unlike the Config redirect, this stays lenient about temp
/// geography because tests only ever hand `open_raw` their own throwaway paths;
/// the inherited-real-DB threat flows through Config, which is registry-gated.
#[cfg(test)]
fn assert_isolated_db_path(db_path: &std::path::Path) {
    if db_path == std::path::Path::new(":memory:") {
        return;
    }

    if crate::paths::test_roots::is_registered(db_path) {
        return;
    }

    assert!(
        crate::paths::is_test_temp_path(db_path),
        "test refused to open a DB at {} (not a registered or temp-tree path).\n\
         This path is not disposable test state, so open_raw fails closed.\n\
         Tests must install an isolated environment first:\n    \
         let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();",
        db_path.display(),
    );
}

/// A test seam on a release path: a test sets it to run once (`Cell::take`)
/// between the path's one-snapshot read and its gated writes, landing a
/// rebind or replacement in exactly that gap.
#[cfg(test)]
pub(crate) type GapHook = std::cell::Cell<Option<fn(&HcomDb, &str)>>;

impl HcomDb {
    /// Open a hardened connection: secure the directory and database files to
    /// owner-only modes (see `paths::ensure_private_db`), then open with the
    /// standard hcom PRAGMAs. The single write path for opening the DB.
    fn open_connection(db_path: &std::path::Path) -> Result<Connection> {
        crate::paths::ensure_private_db(db_path)
            .with_context(|| format!("Failed to secure database: {}", db_path.display()))?;

        let conn = Connection::open(db_path)
            .with_context(|| format!("Failed to open database: {}", db_path.display()))?;
        // busy_timeout first: converting a fresh db to WAL takes a brief
        // exclusive lock, so with a 0 timeout a concurrent first-open (or heavy
        // load) fails instantly with SQLITE_BUSY. Setting the timeout up front
        // makes the WAL conversion retry instead.
        conn.execute_batch(
            "PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;",
        )?;

        Ok(conn)
    }

    /// Access the underlying SQLite connection (for direct queries).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Run `f` inside a `BEGIN IMMEDIATE` transaction and commit on success.
    ///
    /// The immediate write lock makes read-modify-write sequences atomic
    /// across the separate database connections used by hook processes.
    /// Queries inside `f` must use the provided transaction.
    pub fn with_immediate_transaction<T>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let txn = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let result = f(&txn)?;
        txn.commit()?;
        Ok(result)
    }

    /// Run `f` inside one `BEGIN DEFERRED` read transaction and commit.
    ///
    /// Every read inside `f` sees the same database snapshot, so reads that
    /// must agree (a row and its process bindings) cannot straddle another
    /// connection's commit between them. A deferred transaction takes no
    /// write lock. Queries inside `f` must use the provided transaction.
    pub fn with_read_snapshot<T>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let txn = Transaction::new_unchecked(&self.conn, TransactionBehavior::Deferred)?;
        let result = f(&txn)?;
        txn.commit()?;
        Ok(result)
    }

    /// One-shot v20 backfill: give every `stopped` snapshot that carries
    /// `created_at` the exact f64 bit pattern beside it.
    ///
    /// This is the whole v20 migration. It runs in the caller's migration
    /// transaction and stamps `user_version = 20` there after its rewrites,
    /// so an interrupted run rolls back completely — stamp included — and the
    /// next open re-migrates.
    ///
    /// The rows are selected through `json_extract(data, '$.snapshot')` so
    /// the scan sees the snapshot object alone, and the numeric token is
    /// parsed with `str::parse::<f64>` (correctly rounded) — both SQLite's
    /// scalar decode and a serde round trip lose ULPs. The rewrite is a
    /// `json_set`, so every other field of the row, adversarial braces and
    /// quote bait included, is preserved byte for byte.
    fn migrate_created_at_bits(&self, tx: &Transaction<'_>) -> Result<()> {
        let rows: Vec<(i64, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, json_extract(data, '$.snapshot') FROM events WHERE json_extract(data, '$.snapshot.created_at') IS NOT NULL
                 AND json_extract(data, '$.snapshot.created_at_bits') IS NULL",
            )?;
            stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (id, snapshot) in rows {
            let Some(bits) = raw_created_at_bits(&snapshot) else {
                continue;
            };
            tx.execute(
                "UPDATE events SET data = json_set(data, '$.snapshot.created_at_bits', ?1) WHERE id = ?2",
                rusqlite::params![bits as i64, id],
            )?;
        }
        // Stamp v20 in the same transaction as the rewrites above, after
        // them: that is what makes the backfill interruption-safe. If it dies
        // partway, the rollback takes the stamp with it and leaves
        // user_version below 20, so the next open re-migrates instead of
        // trusting a half-backfilled database.
        tx.execute_batch("PRAGMA user_version = 20")?;
        Ok(())
    }

    /// Access the filesystem path backing this DB handle.
    pub fn path(&self) -> &std::path::Path {
        &self.db_path
    }

    /// Open the hcom database at ~/.hcom/hcom.db with schema migration/compat.
    pub fn open() -> Result<Self> {
        let hcom_dir = crate::paths::hcom_dir();
        crate::paths::ensure_private_directory(&hcom_dir)
            .with_context(|| format!("Failed to secure hcom directory: {}", hcom_dir.display()))?;
        Self::open_at(&hcom_dir.join("hcom.db"))
    }

    /// Open the hcom database at a specific path with schema migration/compat.
    pub fn open_at(db_path: &std::path::Path) -> Result<Self> {
        let mut db = Self::open_raw(db_path)?;
        db.ensure_schema()?;
        Ok(db)
    }

    /// Open DB connection without schema checks (for testing only).
    pub fn open_raw(db_path: &std::path::Path) -> Result<Self> {
        #[cfg(test)]
        assert_isolated_db_path(db_path);
        let conn = Self::open_connection(db_path)?;

        let inode = get_inode(db_path);

        Ok(Self {
            conn,
            db_path: db_path.to_path_buf(),
            db_inode: inode,
        })
    }

    /// Reconnect if the DB file was replaced (e.g., by hcom reset / schema bump).
    /// Long-lived threads (PTY delivery, listeners) hold an open connection to the
    /// old inode; this moves them onto the new DB file.
    /// Returns true if reconnection happened.
    pub fn reconnect_if_stale(&mut self) -> bool {
        let current_inode = get_inode(&self.db_path);
        if current_inode == 0 || current_inode == self.db_inode {
            return false;
        }
        // DB file replaced — reconnect
        use crate::log::{log_error, log_info};
        // Best-effort re-harden: the replacement was written by another hcom
        // process (reset/archive) that already secured it, so failing here must
        // not wedge a live delivery/listener loop — log and continue.
        if let Err(e) = crate::paths::ensure_private_db(&self.db_path) {
            use crate::log::log_warn;
            log_warn(
                "native",
                "db.secure_fail",
                &format!("Failed to re-secure DB after replacement: {}", e),
            );
        }
        match Connection::open(&self.db_path) {
            Ok(new_conn) => {
                if let Err(e) = new_conn.execute_batch(
                    "PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;",
                ) {
                    use crate::log::log_warn;
                    log_warn(
                        "native",
                        "db.pragma_fail",
                        &format!("PRAGMA setup failed after reconnect: {}", e),
                    );
                }
                log_info(
                    "native",
                    "db.reconnect",
                    &format!(
                        "DB file replaced (inode {} -> {}), reconnected",
                        self.db_inode, current_inode
                    ),
                );
                self.conn = new_conn;
                self.db_inode = current_inode;
                true
            }
            Err(e) => {
                log_error(
                    "native",
                    "db.reconnect_fail",
                    &format!("Failed to reconnect: {}", e),
                );
                false
            }
        }
    }

    /// Initialize database schema. Idempotent (IF NOT EXISTS).
    /// Creates all tables, indexes, events_v view, FTS5 virtual table + trigger,
    /// and sets PRAGMA user_version.
    pub fn init_db(&self) -> Result<()> {
        // Skip if already at current version (avoids DROP VIEW race with concurrent readers)
        let current: i32 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if current == SCHEMA_VERSION {
            return Ok(());
        }

        self.conn.execute_batch(
            "
            -- Events table
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                instance TEXT NOT NULL,
                data TEXT NOT NULL
            );

            -- Notify endpoints
            CREATE TABLE IF NOT EXISTS notify_endpoints (
                instance TEXT NOT NULL,
                kind TEXT NOT NULL,
                port INTEGER NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (instance, kind)
            );
            CREATE INDEX IF NOT EXISTS idx_notify_endpoints_instance ON notify_endpoints(instance);
            CREATE INDEX IF NOT EXISTS idx_notify_endpoints_port ON notify_endpoints(port);

            -- Process bindings
            CREATE TABLE IF NOT EXISTS process_bindings (
                process_id TEXT PRIMARY KEY,
                session_id TEXT,
                instance_name TEXT,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_process_bindings_instance ON process_bindings(instance_name);
            CREATE INDEX IF NOT EXISTS idx_process_bindings_session ON process_bindings(session_id);

            -- Session bindings
            CREATE TABLE IF NOT EXISTS session_bindings (
                session_id TEXT PRIMARY KEY,
                instance_name TEXT NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY (instance_name) REFERENCES instances(name) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_session_bindings_instance ON session_bindings(instance_name);

            -- Instances table
            CREATE TABLE IF NOT EXISTS instances (
                name TEXT PRIMARY KEY,
                session_id TEXT UNIQUE,
                parent_session_id TEXT,
                parent_name TEXT,
                tag TEXT,
                last_event_id INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                status_time INTEGER DEFAULT 0,
                last_seen INTEGER DEFAULT 0,
                status_context TEXT DEFAULT '',
                status_detail TEXT DEFAULT '',
                last_stop INTEGER DEFAULT 0,
                directory TEXT,
                created_at REAL NOT NULL,
                transcript_path TEXT DEFAULT '',
                tcp_mode INTEGER DEFAULT 0,
                wait_timeout INTEGER,
                background INTEGER DEFAULT 0,
                background_log_file TEXT DEFAULT '',
                name_announced INTEGER DEFAULT 0,
                agent_id TEXT UNIQUE,
                running_tasks TEXT DEFAULT '',
                origin_device_id TEXT DEFAULT '',
                hints TEXT DEFAULT '',
                subagent_timeout INTEGER,
                tool TEXT DEFAULT 'claude',
                launch_args TEXT DEFAULT '',
                terminal_preset_requested TEXT DEFAULT '',
                terminal_preset_effective TEXT DEFAULT '',
                idle_since TEXT DEFAULT '',
                pid INTEGER DEFAULT NULL,
                launch_context TEXT DEFAULT '',
                purpose TEXT DEFAULT '',
                current TEXT DEFAULT '',
                FOREIGN KEY (parent_session_id) REFERENCES instances(session_id) ON DELETE SET NULL
            );

            -- Claude shell actor capabilities
            CREATE TABLE IF NOT EXISTS claude_actor_capabilities (
                token TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                tool_use_id TEXT NOT NULL,
                agent_id TEXT NOT NULL DEFAULT '',
                instance_name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                UNIQUE(session_id, tool_use_id, agent_id)
            );
            CREATE INDEX IF NOT EXISTS idx_claude_actor_expiry ON claude_actor_capabilities(expires_at);
            CREATE INDEX IF NOT EXISTS idx_claude_actor_session ON claude_actor_capabilities(session_id);

            -- KV table
            CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);

            -- Event indexes
            CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_type ON events(type);
            CREATE INDEX IF NOT EXISTS idx_instance ON events(instance);
            CREATE INDEX IF NOT EXISTS idx_type_instance ON events(type, instance);

            -- Instance indexes
            CREATE INDEX IF NOT EXISTS idx_session_id ON instances(session_id);
            CREATE INDEX IF NOT EXISTS idx_parent_session_id ON instances(parent_session_id);
            CREATE INDEX IF NOT EXISTS idx_parent_name ON instances(parent_name);
            CREATE INDEX IF NOT EXISTS idx_created_at ON instances(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_status ON instances(status);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_id_unique ON instances(agent_id) WHERE agent_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_instances_origin ON instances(origin_device_id);

            -- Flattened events view (DROP first to apply schema changes)
            DROP VIEW IF EXISTS events_v;
            CREATE VIEW IF NOT EXISTS events_v AS
            SELECT
                id, timestamp, type, instance, data,
                json_extract(data, '$.from') as msg_from,
                json_extract(data, '$.text') as msg_text,
                json_extract(data, '$.scope') as msg_scope,
                json_extract(data, '$.sender_kind') as msg_sender_kind,
                json_extract(data, '$.delivered_to') as msg_delivered_to,
                json_extract(data, '$.mentions') as msg_mentions,
                json_extract(data, '$.intent') as msg_intent,
                json_extract(data, '$.thread') as msg_thread,
                json_extract(data, '$.reply_to') as msg_reply_to,
                json_extract(data, '$.reply_to_local') as msg_reply_to_local,
                json_extract(data, '$.bundle_id') as bundle_id,
                json_extract(data, '$.title') as bundle_title,
                json_extract(data, '$.description') as bundle_description,
                json_extract(data, '$.extends') as bundle_extends,
                json_extract(data, '$.refs.events') as bundle_events,
                json_extract(data, '$.refs.files') as bundle_files,
                json_extract(data, '$.refs.transcript') as bundle_transcript,
                json_extract(data, '$.created_by') as bundle_created_by,
                json_extract(data, '$.status') as status_val,
                json_extract(data, '$.context') as status_context,
                json_extract(data, '$.detail') as status_detail,
                json_extract(data, '$.action') as life_action,
                json_extract(data, '$.by') as life_by,
                json_extract(data, '$.batch_id') as life_batch_id,
                json_extract(data, '$.reason') as life_reason
            FROM events;

            -- FTS5 full-text search index
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                searchable,
                tokenize='unicode61'
            );
            CREATE TRIGGER IF NOT EXISTS events_fts_insert
            AFTER INSERT ON events BEGIN
                INSERT INTO events_fts(rowid, searchable) VALUES (
                    new.id,
                    COALESCE(json_extract(new.data, '$.text'), '') || ' ' ||
                    COALESCE(json_extract(new.data, '$.from'), '') || ' ' ||
                    COALESCE(new.instance, '') || ' ' ||
                    COALESCE(json_extract(new.data, '$.context'), '') || ' ' ||
                    COALESCE(json_extract(new.data, '$.detail'), '') || ' ' ||
                    COALESCE(json_extract(new.data, '$.action'), '') || ' ' ||
                    COALESCE(json_extract(new.data, '$.reason'), '')
                );
            END;
            ",
        )?;

        // Set schema version
        self.conn
            .execute_batch(&format!("PRAGMA user_version = {}", SCHEMA_VERSION))?;

        Ok(())
    }

    /// Full schema bootstrap: check version, archive if mismatched, reconnect, init.
    ///
    /// Checks schema version, archives DB if mismatched, reconnects, and reinitializes.
    /// Call after open() for production use.
    ///
    /// A store already at `SCHEMA_VERSION` opens without the write lock. An
    /// open with anything to do takes one `BEGIN IMMEDIATE` first and runs the
    /// version check and every migration step under it, committed once, so
    /// concurrent first openers (hooks, a relay sweep) queue on
    /// `busy_timeout` and each loser finds the winner's stamp.
    pub fn ensure_schema(&mut self) -> Result<()> {
        // Steady state takes no lock, exactly as before: every hook opens the
        // DB, and a lock here would queue those opens behind any writer.
        let is_current = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i32>(0))
            .unwrap_or(0)
            == SCHEMA_VERSION;
        match self.check_schema_compat()? {
            SchemaCompat::Ok if is_current => return Ok(()),
            // DB is newer than our code — work with it, don't archive
            SchemaCompat::StaleProcess => return Ok(()),
            SchemaCompat::Ok | SchemaCompat::NeedsArchive(..) => {}
        }

        // Take the write lock BEFORE re-reading the version. A DEFERRED
        // transaction reads first and then fails its read->write upgrade with
        // SQLITE_BUSY, which busy_timeout never retries; IMMEDIATE makes a
        // concurrent opener wait here instead, then see the winner's stamp.
        // Held by hand, not via `with_immediate_transaction`, because the
        // archive fallback must roll a partial migration back, not commit it.
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        // Read the version this open migrates from ONCE, under the lock: the
        // v20 created_at-bits backfill is run-once, gated on the version found
        // here, not on whatever `init_db`/`try_apply_migrations` stamp
        // afterwards.
        let opened_version: i32 = tx
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);
        match self.check_schema_compat()? {
            SchemaCompat::Ok => {
                self.init_db()?;
                if opened_version < 20 {
                    self.migrate_created_at_bits(&tx)?;
                }
                tx.commit()?;
                Ok(())
            }
            SchemaCompat::NeedsArchive(reason, old_version) => {
                if let Some(version) = old_version {
                    // A DB can be stamped at some version yet be missing columns
                    // an earlier migration should have added ("stamped without
                    // migration"). The stamp alone can't tell us how far back to
                    // start, so key off the columns actually present.
                    let migrate_from = self.repair_migrate_from(version);
                    match self.try_apply_migrations(&tx, migrate_from) {
                        Ok(true) => match self.missing_required_instance_column() {
                            None => {
                                if migrate_from < 20 {
                                    self.migrate_created_at_bits(&tx)?;
                                }
                                tx.commit()?;
                                return Ok(());
                            }
                            // Repair must not report success it cannot
                            // deliver: a store missing a required column no
                            // migration adds (`tool` predates MIGRATIONS
                            // 17-19) would commit "repaired", stay broken,
                            // and re-migrate on every open. Re-run the column
                            // guard and take the archive path below instead.
                            Some(col) => {
                                crate::log::log_warn(
                                    "db",
                                    "schema.repair_incomplete",
                                    &format!(
                                        "v{} -> v{} repair left instances.{} missing",
                                        migrate_from, SCHEMA_VERSION, col
                                    ),
                                );
                            }
                        },
                        Ok(false) => {}
                        Err(e) => {
                            crate::log::log_warn(
                                "db",
                                "schema.migration_failed",
                                &format!("v{} -> v{} failed: {}", migrate_from, SCHEMA_VERSION, e),
                            );
                            // A lock error is contention, not corruption:
                            // SQLITE_BUSY/SQLITE_LOCKED from ordinary hook
                            // contention must roll the partial migration
                            // back, release the write lock, and hand the
                            // healthy store to the next open — archiving here
                            // would delete it. Archive stays reserved for a
                            // migration that cannot run (Ok(false)) or that
                            // failed non-transiently.
                            if matches!(
                                e.downcast_ref::<rusqlite::Error>(),
                                Some(rusqlite::Error::SqliteFailure(err, _))
                                    if matches!(
                                        err.code,
                                        rusqlite::ErrorCode::DatabaseBusy
                                            | rusqlite::ErrorCode::DatabaseLocked
                                    )
                            ) {
                                drop(tx);
                                return Err(e);
                            }
                        }
                    }
                }
                // Roll back any partial migration and release the write lock
                // before the archive replaces this connection and its file.
                drop(tx);
                eprintln!("hcom: {}, archiving...", reason);

                // Snapshot running instances to pidtrack before archive so orphan
                // recovery can re-register them into the fresh DB.
                self.snapshot_running_to_pidtrack();

                // Release our handle to the old DB file before archiving. Windows
                // refuses to delete a file that still has an open handle; Unix
                // unlinks an open file fine, so this is a no-op there.
                //
                // This only releases *our own* connection. If any other hcom
                // process — another agent instance, a relay worker, a hook
                // invocation — has the same DB file open at this moment, the
                // `remove_file` inside `archive_db_at` below can still fail on
                // Windows; see the doc comment there for why closing our own
                // handle isn't sufficient in general.
                self.conn = Connection::open_in_memory()?;

                // Archive the old DB
                let archive_path = Self::archive_db_at(&self.db_path)?;
                if let Some(ref path) = archive_path {
                    eprintln!("hcom: Archived to {}", path);
                    eprintln!("       Query with: hcom archive 1");
                }

                // Reconnect to fresh DB file
                let new_conn = Self::open_connection(&self.db_path).with_context(|| {
                    format!(
                        "Failed to reopen DB after archive: {}",
                        self.db_path.display()
                    )
                })?;
                self.conn = new_conn;
                self.db_inode = get_inode(&self.db_path);

                // Init fresh schema
                self.init_db()?;

                // Log reset event to fresh DB
                self.log_reset_event()?;

                Ok(())
            }
            SchemaCompat::StaleProcess => {
                // A newer binary migrated past us after the unlocked check:
                // work with it, don't archive
                tx.commit()?;
                Ok(())
            }
        }
    }

    /// The column guard: the first required `instances` column that is
    /// absent. Catches a store stamped without its migration — including
    /// columns like `tool` that predate `MIGRATIONS` and that no step in
    /// there can restore.
    fn missing_required_instance_column(&self) -> Option<String> {
        self.conn
            .prepare("PRAGMA table_info(instances)")
            .and_then(|mut s| {
                let cols: Vec<String> = s
                    .query_map([], |row| row.get::<_, String>(1))?
                    .filter_map(|r| r.ok())
                    .collect();
                let required = [
                    "tool",
                    "terminal_preset_requested",
                    "terminal_preset_effective",
                    "last_seen",
                ];
                Ok(required
                    .iter()
                    .find(|c| !cols.contains(&c.to_string()))
                    .map(|s| s.to_string()))
            })
            .unwrap_or(None)
    }

    /// Internal: check schema compatibility without taking action.
    fn check_schema_compat(&self) -> Result<SchemaCompat> {
        let version: i32 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap_or(0);

        // Check what tables exist
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
        let tables: std::collections::HashSet<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();

        let required: std::collections::HashSet<&str> = [
            "events",
            "instances",
            "kv",
            "notify_endpoints",
            "session_bindings",
            "claude_actor_capabilities",
        ]
        .into_iter()
        .collect();

        if version == 0 {
            // Race handling: another process may be initializing
            if !tables.is_empty() && required.iter().any(|t| tables.contains(*t)) {
                let mut resolved_version = 0i32;
                for _ in 0..20 {
                    let v2: i32 = self
                        .conn
                        .query_row("PRAGMA user_version", [], |row| row.get(0))
                        .unwrap_or(0);
                    if v2 != 0 {
                        resolved_version = v2;
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                if resolved_version == SCHEMA_VERSION {
                    return Ok(SchemaCompat::Ok);
                }
                if resolved_version > SCHEMA_VERSION {
                    crate::log::log_warn(
                        "db",
                        "schema.stale_process",
                        &format!(
                            "DB v{} > code v{}, working with newer schema",
                            resolved_version, SCHEMA_VERSION
                        ),
                    );
                    return Ok(SchemaCompat::StaleProcess);
                }
                // Timeout exhausted — another process is still initializing.
                // Return Ok rather than falling through to NeedsArchive which
                // would incorrectly archive a valid in-progress DB.
                if resolved_version == 0 {
                    crate::log::log_warn(
                        "db",
                        "schema.init_timeout",
                        "Concurrent init poll timed out, assuming OK",
                    );
                    return Ok(SchemaCompat::Ok);
                }
            }
            // Fresh DB (no tables) - safe to initialize
            if tables.is_empty() {
                return Ok(SchemaCompat::Ok);
            }
            // Pre-versioned DB with our tables - needs archive
            if required.iter().any(|t| tables.contains(*t)) {
                return Ok(SchemaCompat::NeedsArchive(
                    "Pre-versioned DB found".to_string(),
                    None,
                ));
            }
            // Has tables but not ours - fresh enough
            return Ok(SchemaCompat::Ok);
        }

        if version != SCHEMA_VERSION {
            if version > SCHEMA_VERSION {
                // DB newer than code - stale process, work with it
                crate::log::log_warn(
                    "db",
                    "schema.stale_process",
                    &format!(
                        "DB v{} > code v{}, working with newer schema",
                        version, SCHEMA_VERSION
                    ),
                );
                return Ok(SchemaCompat::StaleProcess);
            }
            // DB older - needs archive
            return Ok(SchemaCompat::NeedsArchive(
                format!(
                    "DB version mismatch (DB v{}, code v{})",
                    version, SCHEMA_VERSION
                ),
                Some(version),
            ));
        }

        // Verify required tables exist
        let have_all = required.iter().all(|t| tables.contains(*t));
        if !have_all {
            let missing: Vec<&&str> = required.iter().filter(|t| !tables.contains(**t)).collect();
            return Ok(SchemaCompat::NeedsArchive(
                format!("DB missing tables {:?}", missing),
                None,
            ));
        }

        // Column guard: verify all expected columns exist (catches partial schema from
        // version bump before migration was written)
        if let Some(col) = self.missing_required_instance_column() {
            return Ok(SchemaCompat::NeedsArchive(
                format!("DB schema missing instances.{}", col),
                Some(version),
            ));
        }

        Ok(SchemaCompat::Ok)
    }

    /// Decide the version to migrate *from* when repairing a DB that may have
    /// been stamped without actually running its migrations.
    ///
    /// Migrations only ADD COLUMN, so an existing column proves its migration
    /// ran. We walk back to the migration that adds the earliest column still
    /// missing; a genuinely up-to-date-but-one-behind DB (all older columns
    /// present) just re-runs the remaining steps.
    fn repair_migrate_from(&self, version: i32) -> i32 {
        let columns: std::collections::HashSet<String> = self
            .conn
            .prepare("PRAGMA table_info(instances)")
            .and_then(|mut s| {
                Ok(s.query_map([], |row| row.get::<_, String>(1))?
                    .filter_map(|r| r.ok())
                    .collect())
            })
            .unwrap_or_default();

        // (migration version, a column that migration introduces)
        const COLUMN_MIGRATIONS: &[(i32, &str)] = &[
            (17, "terminal_preset_requested"),
            (18, "last_seen"),
            (19, "purpose"),
        ];
        for (migration, column) in COLUMN_MIGRATIONS {
            if !columns.contains(*column) {
                return migration - 1;
            }
        }

        // All migration-added columns present: ordinary version-behind DB, or a
        // current stamp flagged for some other reason — re-run just the last step.
        if version >= SCHEMA_VERSION {
            SCHEMA_VERSION - 1
        } else {
            version
        }
    }

    /// Try in-place migration for consecutive schema versions.
    ///
    /// Every step runs in the caller's transaction, which owns the commit.
    /// Returns `Ok(false)` if any step is missing from `MIGRATIONS`, causing
    /// `ensure_schema()` to roll back and fall back to archive+recreate.
    fn try_apply_migrations(&self, tx: &Transaction<'_>, old_version: i32) -> Result<bool> {
        if old_version <= 0 || old_version >= SCHEMA_VERSION {
            return Ok(false);
        }
        for next_version in (old_version + 1)..=SCHEMA_VERSION {
            if next_version == 17 {
                let has_launch_context = tx
                    .prepare("PRAGMA table_info(instances)")?
                    .query_map([], |row| row.get::<_, String>(1))?
                    .filter_map(|r| r.ok())
                    .any(|col| col == "launch_context");
                if !has_launch_context {
                    tx.execute(
                        "ALTER TABLE instances ADD COLUMN launch_context TEXT DEFAULT ''",
                        [],
                    )?;
                }
            }
            if next_version == 19 {
                let columns: std::collections::HashSet<String> = tx
                    .prepare("PRAGMA table_info(instances)")?
                    .query_map([], |row| row.get::<_, String>(1))?
                    .filter_map(|r| r.ok())
                    .collect();
                let mut columns_added = false;
                for column in ["purpose", "current"] {
                    if !columns.contains(column) {
                        tx.execute(
                            &format!(
                                "ALTER TABLE instances ADD COLUMN {} TEXT DEFAULT ''",
                                column
                            ),
                            [],
                        )?;
                        columns_added = true;
                    }
                }
                // Stamp 19 only when the step actually ran. A re-run against
                // already-migrated columns is a no-op success — stamping
                // there would silently downgrade a v20 store's stamp.
                if columns_added {
                    tx.execute_batch(&format!("PRAGMA user_version = {}", next_version))?;
                }
                continue;
            }
            let Some((_, sql)) = MIGRATIONS.iter().find(|(v, _)| *v == next_version) else {
                return Ok(false);
            };
            let has_status_time = if next_version == 18 {
                let mut statement = tx.prepare("PRAGMA table_info(instances)")?;
                let columns: Vec<String> = statement
                    .query_map([], |row| row.get::<_, String>(1))?
                    .filter_map(|row| row.ok())
                    .collect();
                columns.iter().any(|column| column == "status_time")
            } else {
                false
            };
            tx.execute_batch(sql)?;
            if next_version == 18 && has_status_time {
                tx.execute(
                    "UPDATE instances SET last_seen = status_time WHERE last_seen = 0",
                    [],
                )?;
            }
            // v20's stamp is deliberately not set here. It belongs to the
            // created_at_bits backfill, which stamps it after its rewrites in
            // this same transaction (migrate_created_at_bits); a stamp here
            // would mark the DB v20 whether or not the backfill ever ran.
            // Every earlier version stamps as it lands.
            if next_version != 20 {
                tx.execute_batch(&format!("PRAGMA user_version = {}", next_version))?;
            }
        }
        Ok(true)
    }

    /// Archive current database at a given path.
    /// WAL checkpoint, copy to archive dir (sibling archive/ directory), delete original.
    ///
    /// Known, deliberately deferred limitation on Windows: the `remove_file`
    /// below can fail even though the caller already released its own
    /// connection (see `ensure_schema`). Windows only allows deleting a file
    /// while other handles remain open if *every* one of those handles was
    /// opened with `FILE_SHARE_DELETE` — and SQLite's Windows VFS (and thus
    /// rusqlite's default `Connection::open`) does not request that flag.
    /// Unix has no equivalent restriction; `unlink` on an open file always
    /// succeeds there, which is why this asymmetry doesn't show up in the
    /// Unix path at all.
    ///
    /// In practice this only bites when a schema-version mismatch forces an
    /// archive-and-reset (rare) while some other hcom process — another agent
    /// instance, a relay worker, a hook invocation — still has the same DB
    /// file open anywhere on the machine. When that happens, this call
    /// returns a real, un-recoverable-in-place `Err`; there is no retry that
    /// helps within this function. A proper fix would need a different
    /// strategy entirely — e.g. copying the live file's contents into a fresh
    /// DB and resetting schema in place, rather than deleting the original —
    /// so no cross-process handle-closing coordination is required. That is a
    /// larger change than this narrow Windows-support pass and is deferred
    /// given how rare schema mismatches are in practice.
    fn archive_db_at(db_path: &std::path::Path) -> Result<Option<String>> {
        if !db_path.exists() {
            return Ok(None);
        }

        let db_wal = db_path.with_extension("db-wal");
        let db_shm = db_path.with_extension("db-shm");

        // WAL checkpoint before archive
        if let Ok(temp_conn) = Connection::open(db_path) {
            let _ = temp_conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)");
        }

        // Create archive directory next to the DB file
        let parent = db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let timestamp = Utc::now().format("%Y-%m-%d_%H%M%S").to_string();
        let archive_dir = parent
            .join("archive")
            .join(format!("session-{}", timestamp));
        std::fs::create_dir_all(&archive_dir)?;

        // Copy DB files to archive
        let db_name = db_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("hcom.db"));
        std::fs::copy(db_path, archive_dir.join(db_name))?;
        if db_wal.exists() {
            let wal_name = format!("{}-wal", db_name.to_string_lossy());
            let _ = std::fs::copy(&db_wal, archive_dir.join(wal_name));
        }
        if db_shm.exists() {
            let shm_name = format!("{}-shm", db_name.to_string_lossy());
            let _ = std::fs::copy(&db_shm, archive_dir.join(shm_name));
        }

        // Delete original
        std::fs::remove_file(db_path)?;
        let _ = std::fs::remove_file(&db_wal);
        let _ = std::fs::remove_file(&db_shm);

        Ok(Some(archive_dir.to_string_lossy().to_string()))
    }

    /// Snapshot running instances to pidtrack before DB archive.
    ///
    /// Writes live instances (with their PIDs) to ~/.hcom/.tmp/launched_pids.json
    /// so orphan recovery can re-register them into the fresh DB after schema bump.
    fn snapshot_running_to_pidtrack(&self) {
        let Ok(mut stmt) = self.conn.prepare(
            "SELECT i.name, i.pid, i.tool, i.directory, i.session_id, p.process_id, \
                    n_pty.port AS notify_port, n_inj.port AS inject_port \
             FROM instances i \
             LEFT JOIN process_bindings p ON i.name = p.instance_name \
             LEFT JOIN notify_endpoints n_pty ON i.name = n_pty.instance AND n_pty.kind = 'pty' \
             LEFT JOIN notify_endpoints n_inj ON i.name = n_inj.instance AND n_inj.kind = 'inject' \
             WHERE i.pid IS NOT NULL",
        ) else {
            return;
        };

        let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,         // name
                row.get::<_, i64>(1)?,            // pid
                row.get::<_, Option<String>>(2)?, // tool
                row.get::<_, Option<String>>(3)?, // directory
                row.get::<_, Option<String>>(4)?, // session_id
                row.get::<_, Option<String>>(5)?, // process_id
                row.get::<_, Option<i64>>(6)?,    // notify_port
                row.get::<_, Option<i64>>(7)?,    // inject_port
            ))
        }) else {
            return;
        };

        let pidfile_path = self
            .db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(".tmp")
            .join("launched_pids.json");

        // Read existing pidfile
        let mut piddata: serde_json::Map<String, serde_json::Value> =
            std::fs::read_to_string(&pidfile_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

        for row in rows.flatten() {
            let (name, pid, tool, directory, session_id, process_id, notify_port, inject_port) =
                row;
            let alive = crate::pidtrack::is_alive(pid as u32);
            if !alive {
                continue;
            }

            piddata.insert(
                pid.to_string(),
                serde_json::json!({
                    "tool": tool.unwrap_or_else(|| "claude".to_string()),
                    "names": [name],
                    "directory": directory.unwrap_or_default(),
                    "process_id": process_id.unwrap_or_default(),
                    "session_id": session_id.unwrap_or_default(),
                    "notify_port": notify_port.unwrap_or(0),
                    "inject_port": inject_port.unwrap_or(0),
                    "launched_at": now_epoch_f64(),
                }),
            );
        }

        if let Ok(json) = serde_json::to_string(&piddata) {
            let _ = std::fs::write(&pidfile_path, json);
        }
    }

    /// Log _device reset event + set relay timestamp. Call after any DB archive/reset.
    pub fn log_reset_event(&self) -> Result<()> {
        // Derive hcom_dir from db_path (db is at hcom_dir/hcom.db)
        let hcom_dir = self
            .db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let device_id = std::fs::read_to_string(hcom_dir.join(".tmp").join("device_uuid"))
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();

        self.log_event(
            "life",
            "_device",
            &serde_json::json!({"action": "reset", "device": device_id}),
        )?;

        self.kv_set("relay_local_reset_ts", Some(&now_epoch_f64().to_string()))?;

        Ok(())
    }

    /// Remove all event subscriptions owned by an instance.
    ///
    /// Subscriptions are stored as kv entries with key 'events_sub:sub-{hash}'
    /// and a JSON value containing a "caller" field.
    pub fn cleanup_subscriptions(&self, name: &str) -> Result<u32> {
        // Delegates to db::subscriptions; events_sub: kv ownership lives there.
        subscriptions::cleanup_subscriptions(self, name)
    }

    /// Remove delivery-only thread memberships for an instance.
    ///
    /// This is used when a stopped name is being reused by a fresh instance:
    /// normal stop/resume should preserve memberships, but identity replacement
    /// must not inherit old thread state.
    pub fn cleanup_thread_memberships_for_name_reuse(&self, name: &str) -> Result<u32> {
        // Delegates to db::subscriptions; events_sub: kv ownership lives there.
        subscriptions::cleanup_thread_memberships_for_name_reuse(self, name)
    }

    /// Return active members of a thread in join order.
    pub fn get_thread_members(&self, thread: &str) -> Vec<String> {
        // Delegates to db::subscriptions; events_sub: kv ownership lives there.
        subscriptions::get_thread_members(self, thread)
    }

    /// Upsert memberships for recipients of a thread message.
    pub fn add_thread_memberships(
        &self,
        thread: &str,
        sender: Option<&str>,
        recipients: &[String],
    ) {
        // Delegates to db::subscriptions; events_sub: kv ownership lives there.
        subscriptions::add_thread_memberships(self, thread, sender, recipients);
    }

    /// Send a system notification message (simplified inline version).
    /// Parses @mentions, computes scope, inserts message event.
    pub fn send_system_message(&self, sender_name: &str, message: &str) -> Result<Vec<String>> {
        // Delegates to db::subscriptions; events_sub: kv ownership lives there.
        subscriptions::send_system_message(self, sender_name, message)
    }

    /// Like `send_system_message` but lets the caller specify `sender_kind`
    /// ("instance" | "external" | "system"). Used by subscription on-hit to
    /// preserve the sub caller's real identity on the event.
    pub fn send_message_as(
        &self,
        sender_name: &str,
        sender_kind: &str,
        message: &str,
    ) -> Result<Vec<String>> {
        // Delegates to db::subscriptions; events_sub: kv ownership lives there.
        subscriptions::send_message_as(self, sender_name, sender_kind, message)
    }
}

/// Extract the exact `f64` bit pattern of the first `"created_at"` key in a
/// raw JSON document. Scans the raw bytes, skipping over JSON string
/// contents so a `"created_at"` decoy inside a string is never mistaken for
/// the key, and hands the token itself to `str::parse::<f64>` — correctly
/// rounded, where serde_json's own f64 parser drops the last ULP on roughly
/// one epoch value in eight.
///
/// Both token shapes are accepted: a bare number (`"created_at":1.5`) and a
/// quoted one (`"created_at":"1.5"`), which the scan takes to the closing
/// quote and the surrounding delimiter.
pub(crate) fn raw_created_at_bits(data: &str) -> Option<u64> {
    let bytes = data.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if ch == '"' {
            if data[i..].starts_with("\"created_at\"") {
                let mut j = i + 12;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if bytes.get(j) != Some(&b':') {
                    i += 1;
                    continue;
                }
                j += 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                let start = j;
                if bytes.get(j) == Some(&b'"') {
                    // Quoted token: take the string, then run past its
                    // closing quote to the delimiter that ends the value.
                    j += 1;
                    while j < bytes.len() && bytes[j] != b'"' {
                        j += 1;
                    }
                    while j < bytes.len() && !matches!(bytes[j], b',' | b'}') {
                        j += 1;
                    }
                } else {
                    // Bare number: take the JSON number token itself.
                    while j < bytes.len()
                        && matches!(bytes[j], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                    {
                        j += 1;
                    }
                }
                return data[start..j]
                    .trim_matches('"')
                    .parse::<f64>()
                    .ok()
                    .map(f64::to_bits);
            }
            in_string = true;
        }
        i += 1;
    }
    None
}

/// Generate ISO timestamp for current time.
pub(super) fn chrono_now_iso() -> String {
    crate::shared::time::now_iso()
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use rusqlite::{Connection, params};
    use std::path::PathBuf;

    /// Clean up test database
    pub(super) fn cleanup_test_db(path: PathBuf) {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(PathBuf::from(format!("{}-wal", path.display())));
        let _ = std::fs::remove_file(PathBuf::from(format!("{}-shm", path.display())));
    }

    #[cfg(unix)]
    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn open_raw_creates_private_database_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("hcom.db");

        let db = HcomDb::open_raw(&db_path).unwrap();
        db.conn()
            .execute("CREATE TABLE permission_probe (id INTEGER)", [])
            .unwrap();
        db.conn()
            .execute("INSERT INTO permission_probe VALUES (1)", [])
            .unwrap();

        assert_eq!(mode(&db_path), 0o600);
        assert_eq!(mode(&crate::paths::sidecar_path(&db_path, "-wal")), 0o600);
        assert_eq!(mode(&crate::paths::sidecar_path(&db_path, "-shm")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn open_raw_restricts_existing_database_files() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("hcom.db");
        let first = HcomDb::open_raw(&db_path).unwrap();
        first
            .conn()
            .execute("CREATE TABLE permission_probe (id INTEGER)", [])
            .unwrap();
        first
            .conn()
            .execute("INSERT INTO permission_probe VALUES (1)", [])
            .unwrap();

        for path in [
            db_path.clone(),
            crate::paths::sidecar_path(&db_path, "-wal"),
            crate::paths::sidecar_path(&db_path, "-shm"),
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let _second = HcomDb::open_raw(&db_path).unwrap();

        assert_eq!(mode(&db_path), 0o600);
        assert_eq!(mode(&crate::paths::sidecar_path(&db_path, "-wal")), 0o600);
        assert_eq!(mode(&crate::paths::sidecar_path(&db_path, "-shm")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn open_raw_restricts_sidecars_for_non_db_filename() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("state.sqlite");

        let db = HcomDb::open_raw(&db_path).unwrap();
        db.conn()
            .execute("CREATE TABLE permission_probe (id INTEGER)", [])
            .unwrap();
        db.conn()
            .execute("INSERT INTO permission_probe VALUES (1)", [])
            .unwrap();

        let wal_path = tmp.path().join("state.sqlite-wal");
        let shm_path = tmp.path().join("state.sqlite-shm");
        std::fs::set_permissions(&wal_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&shm_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let _second = HcomDb::open_raw(&db_path).unwrap();

        assert_eq!(mode(&wal_path), 0o600);
        assert_eq!(mode(&shm_path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn open_restricts_the_configured_hcom_directory_and_database() {
        use std::os::unix::fs::PermissionsExt;

        let (_tmp, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        std::fs::set_permissions(&hcom_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let db = HcomDb::open().unwrap();

        assert_eq!(mode(&hcom_dir), 0o700);
        assert_eq!(mode(db.path()), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn reconnect_if_stale_resecures_replaced_database() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let db_path = tmp.path().join("hcom.db");
        let mut db = HcomDb::open_raw(&db_path).unwrap();

        // Simulate another process replacing the DB with a broad-mode file
        // (new inode), as reset/schema-archive does.
        std::fs::remove_file(&db_path).unwrap();
        let _ = std::fs::remove_file(crate::paths::sidecar_path(&db_path, "-wal"));
        let _ = std::fs::remove_file(crate::paths::sidecar_path(&db_path, "-shm"));
        drop(HcomDb::open_raw(&db_path).unwrap());
        std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(db.reconnect_if_stale());
        assert_eq!(mode(&db_path), 0o600);
    }

    #[test]
    #[should_panic(expected = "not a registered or temp-tree path")]
    fn test_open_raw_rejects_non_temp_path() {
        let db_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".hcom-unsafe-test")
            .join("hcom.db");
        let _ = HcomDb::open_raw(&db_path);
    }

    #[test]
    fn test_open_raw_allows_temp_path() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("allowed.db");

        let db = HcomDb::open_raw(&db_path).unwrap();

        assert_eq!(db.path(), db_path);
    }

    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "not a registered or temp-tree path")]
    fn test_open_raw_rejects_temp_symlink_to_non_temp_path() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let link = temp.path().join("outside");
        symlink(env!("CARGO_MANIFEST_DIR"), &link).unwrap();
        let db_path = link.join(".hcom").join("hcom.db");

        let _ = HcomDb::open_raw(&db_path);
    }

    #[test]
    fn test_all_methods_return_ok_none_when_not_found() {
        let (db, db_path) = setup_full_test_db();

        // All these should return Ok(None) for non-existent data
        assert!(db.get_instance_status("nonexistent").unwrap().is_none());
        assert!(db.get_status("nonexistent").unwrap().is_none());
        assert!(db.get_process_binding("nonexistent").unwrap().is_none());
        assert!(db.get_transcript_path("nonexistent").unwrap().is_none());
        assert!(db.get_instance_snapshot("nonexistent").unwrap().is_none());

        cleanup_test_db(db_path);
    }

    /// Create a test DB with full init_db() schema
    pub(super) fn setup_full_test_db() -> (HcomDb, PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let temp_dir = std::env::temp_dir();
        let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let db_path = temp_dir.join(format!(
            "test_hcom_full_{}_{}.db",
            std::process::id(),
            test_id
        ));

        let db = HcomDb::open_at(&db_path).unwrap();
        (db, db_path)
    }

    #[test]
    fn test_init_db_creates_all_tables() {
        let (db, db_path) = setup_full_test_db();

        let tables: Vec<String> = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"events".to_string()));
        assert!(tables.contains(&"instances".to_string()));
        assert!(tables.contains(&"kv".to_string()));
        assert!(tables.contains(&"notify_endpoints".to_string()));
        assert!(tables.contains(&"process_bindings".to_string()));
        assert!(tables.contains(&"session_bindings".to_string()));

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_init_db_sets_schema_version() {
        let (db, db_path) = setup_full_test_db();

        let version: i32 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_init_db_idempotent() {
        let (db, db_path) = setup_full_test_db();

        // Call init_db again - should be no-op
        db.init_db().unwrap();

        let version: i32 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_init_db_creates_events_v_view() {
        let (db, db_path) = setup_full_test_db();

        // Check view exists
        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name='events_v'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_init_db_creates_fts5_table() {
        let (db, db_path) = setup_full_test_db();

        // FTS5 tables show up as 'table' in sqlite_master
        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='events_fts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(count > 0, "events_fts should exist");

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_init_db_fts_trigger_indexes_on_insert() {
        let (db, db_path) = setup_full_test_db();

        // Insert an event
        db.conn
            .execute(
                "INSERT INTO events (timestamp, type, instance, data) VALUES ('2026-01-01T00:00:00Z', 'message', 'luna', ?)",
                params![serde_json::json!({"from": "luna", "text": "hello world"}).to_string()],
            )
            .unwrap();

        // Search FTS
        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events_fts WHERE searchable MATCH 'hello'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_check_schema_compat_fresh_db() {
        let (db, db_path) = setup_full_test_db();
        match db.check_schema_compat().unwrap() {
            SchemaCompat::Ok => {} // expected
            other => panic!(
                "Expected SchemaCompat::Ok, got {:?}",
                match other {
                    SchemaCompat::NeedsArchive(r, v) => format!("NeedsArchive({}, {:?})", r, v),
                    SchemaCompat::StaleProcess => "StaleProcess".to_string(),
                    SchemaCompat::Ok => unreachable!(),
                }
            ),
        }
        cleanup_test_db(db_path);
    }

    #[test]
    fn test_ensure_schema_fresh_db() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1000);

        let temp_dir = std::env::temp_dir();
        let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let db_path = temp_dir.join(format!(
            "test_hcom_ensure_{}_{}.db",
            std::process::id(),
            test_id
        ));

        let mut db = HcomDb::open_raw(&db_path).unwrap();
        db.ensure_schema().unwrap();

        // Should have full schema
        let version: i32 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_ensure_schema_archives_old_version() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(2000);

        let temp_dir = std::env::temp_dir();
        let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let db_path = temp_dir.join(format!(
            "test_hcom_archive_{}_{}.db",
            std::process::id(),
            test_id
        ));

        // Create a DB with old schema version
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT, type TEXT, instance TEXT, data TEXT);
                 CREATE TABLE instances (name TEXT PRIMARY KEY, created_at REAL NOT NULL);
                 CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);
                 CREATE TABLE notify_endpoints (instance TEXT, kind TEXT, port INTEGER, updated_at REAL, PRIMARY KEY(instance, kind));
                 CREATE TABLE session_bindings (session_id TEXT PRIMARY KEY, instance_name TEXT NOT NULL, created_at REAL NOT NULL);
                 PRAGMA user_version = 5;",
            )
            .unwrap();
        }

        let mut db = HcomDb::open_raw(&db_path).unwrap();
        db.ensure_schema().unwrap();

        // Should have been archived and recreated at current version
        let version: i32 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // Archive directory should exist
        let archive_dir = temp_dir.join("archive");
        if archive_dir.exists() {
            let _ = std::fs::remove_dir_all(&archive_dir);
        }

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_ensure_schema_migrates_v16_to_v18_in_place_without_status_time() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(2500);

        let temp_dir = std::env::temp_dir();
        let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let db_path = temp_dir.join(format!(
            "test_hcom_migrate_{}_{}.db",
            std::process::id(),
            test_id
        ));

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT, type TEXT, instance TEXT, data TEXT);
                 CREATE TABLE instances (
                     name TEXT PRIMARY KEY,
                     tool TEXT DEFAULT 'claude',
                     created_at REAL NOT NULL,
                     launch_context TEXT DEFAULT ''
                 );
                 CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);
                 CREATE TABLE notify_endpoints (instance TEXT, kind TEXT, port INTEGER, updated_at REAL, PRIMARY KEY(instance, kind));
                 CREATE TABLE session_bindings (session_id TEXT PRIMARY KEY, instance_name TEXT NOT NULL, created_at REAL NOT NULL);
                 PRAGMA user_version = 16;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO instances (name, tool, created_at, launch_context) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    "luna",
                    "claude",
                    1.0f64,
                    r#"{"terminal_preset":"ghostty-tab"}"#
                ],
            )
            .unwrap();
        }

        let mut db = HcomDb::open_raw(&db_path).unwrap();
        db.ensure_schema().unwrap();

        let version: i32 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        let preset: String = db
            .conn
            .query_row(
                "SELECT terminal_preset_effective FROM instances WHERE name = ?",
                params!["luna"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(preset, "ghostty-tab");
        let launch_context: String = db
            .conn
            .query_row(
                "SELECT launch_context FROM instances WHERE name = ?",
                params!["luna"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(launch_context, r#"{"terminal_preset":"ghostty-tab"}"#);
        let last_seen: i64 = db
            .conn
            .query_row(
                "SELECT last_seen FROM instances WHERE name = ?",
                params!["luna"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(last_seen, 0);

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_ensure_schema_migrates_v17_to_v18_using_status_time() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(2750);

        let temp_dir = std::env::temp_dir();
        let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let db_path = temp_dir.join(format!(
            "test_hcom_migrate_status_time_{}_{}.db",
            std::process::id(),
            test_id
        ));

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT, type TEXT, instance TEXT, data TEXT);
                 CREATE TABLE instances (
                     name TEXT PRIMARY KEY,
                     tool TEXT DEFAULT 'claude',
                     status_time INTEGER DEFAULT 0,
                     created_at REAL NOT NULL,
                     launch_context TEXT DEFAULT '',
                     terminal_preset_requested TEXT DEFAULT '',
                     terminal_preset_effective TEXT DEFAULT ''
                 );
                 CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);
                 CREATE TABLE notify_endpoints (instance TEXT, kind TEXT, port INTEGER, updated_at REAL, PRIMARY KEY(instance, kind));
                 CREATE TABLE session_bindings (session_id TEXT PRIMARY KEY, instance_name TEXT NOT NULL, created_at REAL NOT NULL);
                 PRAGMA user_version = 17;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO instances (name, tool, status_time, created_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params!["luna", "claude", 123i64, 1.0f64],
            )
            .unwrap();
        }

        let mut db = HcomDb::open_raw(&db_path).unwrap();
        db.ensure_schema().unwrap();

        let last_seen: i64 = db
            .conn
            .query_row(
                "SELECT last_seen FROM instances WHERE name = ?",
                params!["luna"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(last_seen, 123);

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_ensure_schema_column_guard() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(3000);

        let temp_dir = std::env::temp_dir();
        let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let db_path = temp_dir.join(format!(
            "test_hcom_colguard_{}_{}.db",
            std::process::id(),
            test_id
        ));

        // Create a DB at current version but missing 'tool' column
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(&format!(
                "CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT, type TEXT, instance TEXT, data TEXT);
                 CREATE TABLE instances (name TEXT PRIMARY KEY, created_at REAL NOT NULL);
                 CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);
                 CREATE TABLE notify_endpoints (instance TEXT, kind TEXT, port INTEGER, updated_at REAL, PRIMARY KEY(instance, kind));
                 CREATE TABLE session_bindings (session_id TEXT PRIMARY KEY, instance_name TEXT NOT NULL, created_at REAL NOT NULL);
                 CREATE TABLE claude_actor_capabilities (
                     token TEXT PRIMARY KEY,
                     session_id TEXT NOT NULL,
                     tool_use_id TEXT NOT NULL,
                     agent_id TEXT NOT NULL DEFAULT '',
                     instance_name TEXT NOT NULL,
                     created_at INTEGER NOT NULL,
                     expires_at INTEGER NOT NULL,
                     last_seen INTEGER NOT NULL,
                     UNIQUE(session_id, tool_use_id, agent_id)
                 );
                 PRAGMA user_version = {};",
                SCHEMA_VERSION
            ))
            .unwrap();
        }

        let mut db = HcomDb::open_raw(&db_path).unwrap();

        // check_schema_compat should detect missing column
        match db.check_schema_compat().unwrap() {
            SchemaCompat::NeedsArchive(reason, _) => {
                assert!(reason.contains("instances.tool"), "reason: {}", reason);
            }
            _ => panic!("Expected NeedsArchive for missing tool column"),
        }

        // No migration adds `tool`, so ensure_schema cannot repair this
        // store: it must take the archive path and leave a current schema.
        db.ensure_schema().unwrap();

        let version: i32 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        cleanup_test_db(db_path);
    }

    /// Regression test for issue #16: init_db() stamped user_version=17 without
    /// actually adding the terminal_preset_* columns. ensure_schema must repair
    /// this via migration instead of archiving (which would lose data).
    #[test]
    fn test_ensure_schema_repairs_stamped_but_not_migrated_db() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(4000);

        let temp_dir = std::env::temp_dir();
        let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let db_path = temp_dir.join(format!(
            "test_hcom_repair_{}_{}.db",
            std::process::id(),
            test_id
        ));

        // Simulate the bug: create a v16-style DB but stamp it as v17
        // (this is what init_db() did — CREATE IF NOT EXISTS is a no-op on
        // existing tables, then it unconditionally set user_version = 17)
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, type TEXT NOT NULL, instance TEXT NOT NULL, data TEXT NOT NULL);
                 CREATE TABLE instances (
                     name TEXT PRIMARY KEY,
                     session_id TEXT UNIQUE,
                     parent_session_id TEXT,
                     parent_name TEXT,
                     tag TEXT,
                     last_event_id INTEGER DEFAULT 0,
                     status TEXT DEFAULT 'active',
                     status_time INTEGER DEFAULT 0,
                     status_context TEXT DEFAULT '',
                     status_detail TEXT DEFAULT '',
                     last_stop INTEGER DEFAULT 0,
                     directory TEXT,
                     created_at REAL NOT NULL,
                     transcript_path TEXT DEFAULT '',
                     tcp_mode INTEGER DEFAULT 0,
                     wait_timeout INTEGER DEFAULT 86400,
                     background INTEGER DEFAULT 0,
                     background_log_file TEXT DEFAULT '',
                     name_announced INTEGER DEFAULT 0,
                     agent_id TEXT UNIQUE,
                     running_tasks TEXT DEFAULT '',
                     origin_device_id TEXT DEFAULT '',
                     hints TEXT DEFAULT '',
                     subagent_timeout INTEGER,
                     tool TEXT DEFAULT 'claude',
                     launch_args TEXT DEFAULT '',
                     idle_since TEXT DEFAULT '',
                     pid INTEGER DEFAULT NULL,
                     launch_context TEXT DEFAULT ''
                 );
                 CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);
                 CREATE TABLE notify_endpoints (instance TEXT NOT NULL, kind TEXT NOT NULL, port INTEGER NOT NULL, updated_at REAL NOT NULL, PRIMARY KEY(instance, kind));
                 CREATE TABLE session_bindings (session_id TEXT PRIMARY KEY, instance_name TEXT NOT NULL, created_at REAL NOT NULL);
                 CREATE TABLE process_bindings (process_id TEXT PRIMARY KEY, session_id TEXT, instance_name TEXT, updated_at REAL NOT NULL);
                 PRAGMA user_version = 17;",
            )
            .unwrap();
            // Insert test data that should survive the repair
            conn.execute(
                "INSERT INTO instances (name, tool, created_at) VALUES ('luna', 'claude', 1.0)",
                [],
            )
            .unwrap();
        }

        // Verify columns are missing before repair
        {
            let conn = Connection::open(&db_path).unwrap();
            let cols: Vec<String> = conn
                .prepare("PRAGMA table_info(instances)")
                .unwrap()
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            assert!(
                !cols.contains(&"terminal_preset_requested".to_string()),
                "column should be missing before repair"
            );
        }

        let mut db = HcomDb::open_raw(&db_path).unwrap();
        db.ensure_schema().unwrap();

        // Should be at current version
        let version: i32 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // Columns should now exist
        let cols: Vec<String> = db
            .conn
            .prepare("PRAGMA table_info(instances)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(
            cols.contains(&"terminal_preset_requested".to_string()),
            "terminal_preset_requested column should exist after repair"
        );
        assert!(
            cols.contains(&"terminal_preset_effective".to_string()),
            "terminal_preset_effective column should exist after repair"
        );

        // Test data should have survived (not archived)
        let name: String = db
            .conn
            .query_row(
                "SELECT name FROM instances WHERE name = 'luna'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "luna");

        cleanup_test_db(db_path);
    }

    /// Concurrent-runner guard for migration 19: the loser of a rollout race
    /// sees `purpose`/`current` already present (winner committed first) with
    /// the stamp still at v18. The re-run must be a no-op success, not an
    /// Err that drops into the archive-the-live-db fallback.
    #[test]
    fn test_migration_19_rerun_against_migrated_columns_is_noop() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(4500);

        let test_id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_dir = std::env::temp_dir().join(format!(
            "test_hcom_migrate19_idem_{}_{}",
            std::process::id(),
            test_id
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("hcom.db");

        // v18 fixture where migration 19's columns already landed but the
        // version stamp was read as 18 before the winner committed.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT, type TEXT, instance TEXT, data TEXT);
                 CREATE TABLE instances (
                     name TEXT PRIMARY KEY,
                     tool TEXT DEFAULT 'claude',
                     created_at REAL NOT NULL,
                     launch_context TEXT DEFAULT '',
                     terminal_preset_requested TEXT DEFAULT '',
                     terminal_preset_effective TEXT DEFAULT '',
                     last_seen INTEGER DEFAULT 0,
                     purpose TEXT DEFAULT '',
                     current TEXT DEFAULT ''
                 );
                 CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);
                 CREATE TABLE notify_endpoints (instance TEXT, kind TEXT, port INTEGER, updated_at REAL, PRIMARY KEY(instance, kind));
                 CREATE TABLE session_bindings (session_id TEXT PRIMARY KEY, instance_name TEXT NOT NULL, created_at REAL NOT NULL);
                 CREATE TABLE process_bindings (process_id TEXT PRIMARY KEY, session_id TEXT, instance_name TEXT, updated_at REAL NOT NULL);
                 PRAGMA user_version = 18;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO instances (name, tool, created_at, purpose) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params!["luna", "claude", 1.0f64, "test-purpose"],
            )
            .unwrap();
        }

        let mut db = HcomDb::open_raw(&db_path).unwrap();
        db.ensure_schema().unwrap();

        let version: i32 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // Second runner re-applying migration 19 must also succeed — and must
        // not downgrade the stamp it found: the store opened at v20 and the
        // re-run is a no-op against already-migrated columns.
        assert!(
            db.with_immediate_transaction(|tx| db.try_apply_migrations(tx, 18))
                .unwrap()
        );
        let version: i32 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            version, SCHEMA_VERSION,
            "migration 19 re-run must leave the v20 stamp alone"
        );

        // Data survived: no archive fallback ran.
        let purpose: String = db
            .conn
            .query_row(
                "SELECT purpose FROM instances WHERE name = ?",
                params!["luna"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(purpose, "test-purpose");
        assert!(
            !temp_dir.join("archive").exists(),
            "migration re-run must not archive the live DB"
        );
        cleanup_test_db(db_path);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// The v20 backfill derives `snapshot.created_at_bits` from the raw JSON
    /// token: `json_extract`'s scalar decode and a serde f64 round trip both
    /// lose ULPs, `str::parse::<f64>` does not. The row is rewritten with
    /// `json_set`, so every other field — adversarial braces and a literal
    /// `"created_at"` inside string bait included — survives untouched.
    ///
    /// The backfill is RUN-ONCE: it fires on the first open that upgrades a
    /// database from below v20, and a database already stamped v20 is never
    /// rescanned (pinned here by the second event).
    #[test]
    fn events_migration_derives_created_at_bits_without_float_loss() {
        const NUMBER_TOKEN: &str = "1790000000.0000021";
        const NUMBER_BITS: u64 = 4_745_294_612_153_761_801;
        const STRING_TOKEN: &str = "1762720048.770769";
        const STRING_BITS: u64 = 4_745_180_191_745_201_223;
        // Guard the fixtures themselves: std parse is the exact decoder.
        assert_eq!(NUMBER_TOKEN.parse::<f64>().unwrap().to_bits(), NUMBER_BITS);
        assert_eq!(STRING_TOKEN.parse::<f64>().unwrap().to_bits(), STRING_BITS);

        let number_row = format!(
            r#"{{"action":"stopped","by":"session","reason":"exit","process_id":null,"snapshot":{{"name":"num","created_at":{NUMBER_TOKEN},"tool":"codex"}}}}"#
        );
        let string_row = format!(
            r#"{{"action":"stopped","by":"session","reason":"exit","process_id":null,"snapshot":{{"name":"str","created_at":"{STRING_TOKEN}"}}}}"#
        );
        let adversarial_row = format!(
            r#"{{"action":"stopped","by":"session","reason":"exit","process_id":null,"hints":"use {{}} and \"created_at\": 999.5","text":"{{\"created_at\": 42}}","snapshot":{{"name":"adv","hints":"literal \"created_at\": 1.5 inside a string","created_at":{STRING_TOKEN}}}}}"#
        );
        let post_v20_row = format!(
            r#"{{"action":"stopped","by":"session","reason":"exit","process_id":null,"snapshot":{{"name":"late","created_at":{NUMBER_TOKEN}}}}}"#
        );

        let (mut db, db_path) = setup_full_test_db();
        // Stand the database back at v19 — the shape production opens.
        db.conn.execute_batch("PRAGMA user_version = 19").unwrap();
        for (name, data) in [
            ("num", &number_row),
            ("str", &string_row),
            ("adv", &adversarial_row),
        ] {
            db.conn
                .execute(
                    "INSERT INTO events (timestamp, type, instance, data) VALUES (?, 'life', ?, ?)",
                    params!["2026-01-01T00:00:00Z", name, data],
                )
                .unwrap();
        }

        // Production entry: open() -> ensure_schema().
        db.ensure_schema().unwrap();
        assert_eq!(
            db.conn
                .query_row("PRAGMA user_version", [], |r| r.get::<_, i32>(0))
                .unwrap(),
            20
        );

        for (name, original, expected_bits) in [
            ("num", &number_row, NUMBER_BITS),
            ("str", &string_row, STRING_BITS),
            ("adv", &adversarial_row, STRING_BITS),
        ] {
            let raw: String = db
                .conn
                .query_row(
                    "SELECT data FROM events WHERE type='life' AND instance=?1",
                    params![name],
                    |r| r.get(0),
                )
                .unwrap();
            let mut migrated: serde_json::Value = serde_json::from_str(&raw).unwrap();
            let bits = migrated["snapshot"]
                .as_object_mut()
                .unwrap()
                .remove("created_at_bits")
                .expect("created_at_bits added");
            assert_eq!(
                bits.as_u64(),
                Some(expected_bits),
                "{name}: bits derived from the real snapshot.created_at"
            );
            let original: serde_json::Value = serde_json::from_str(original).unwrap();
            assert_eq!(&migrated, &original, "{name}: only the key was added");
        }
        // The fractional token itself was not reformatted by the rewrite.
        let num_raw: String = db
            .conn
            .query_row(
                "SELECT data FROM events WHERE type='life' AND instance='num'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            num_raw.contains(&format!(r#""created_at":{NUMBER_TOKEN}"#)),
            "raw token preserved: {num_raw}"
        );

        // Run-once gating: a DB already at v20 is NOT backfilled on re-open.
        db.conn
            .execute(
                "INSERT INTO events (timestamp, type, instance, data) VALUES (?, 'life', 'late', ?)",
                params!["2026-01-01T00:00:00Z", &post_v20_row],
            )
            .unwrap();
        db.ensure_schema().unwrap();
        let late: String = db
            .conn
            .query_row(
                "SELECT data FROM events WHERE type='life' AND instance='late'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            late, post_v20_row,
            "a v20 database is never rescanned by the backfill"
        );

        cleanup_test_db(db_path);
    }

    /// The v20 backfill must be interruption-safe: its row rewrites run in a
    /// single transaction, so an abort partway through must roll the whole
    /// backfill back — no half-migrated snapshots — and a re-run with the
    /// interruption cleared must converge on the uninterrupted end state:
    /// user_version 20, exact bits beside every eligible `created_at`, every
    /// other snapshot key untouched, raw numeric tokens unreformatted.
    ///
    /// The interruption is a BEFORE UPDATE trigger that aborts at the moment
    /// `created_at_bits` is about to land on the last eligible row; the
    /// backfill scans in rowid order, so the two earlier rows are already
    /// rewritten inside the still-open transaction when the abort hits.
    #[test]
    fn events_migration_interrupted_partway_converges_on_rerun() {
        const FIRST_TOKEN: &str = "1790000000.0000021";
        const FIRST_BITS: u64 = 4_745_294_612_153_761_801;
        const SECOND_TOKEN: &str = "1762720048.770769";
        const SECOND_BITS: u64 = 4_745_180_191_745_201_223;
        const THIRD_TOKEN: &str = "1762720048.77077";
        const THIRD_BITS: u64 = 4_745_180_191_745_201_228;
        // Guard the fixtures themselves: std parse is the exact decoder.
        assert_eq!(FIRST_TOKEN.parse::<f64>().unwrap().to_bits(), FIRST_BITS);
        assert_eq!(SECOND_TOKEN.parse::<f64>().unwrap().to_bits(), SECOND_BITS);
        assert_eq!(THIRD_TOKEN.parse::<f64>().unwrap().to_bits(), THIRD_BITS);

        let first_row = format!(
            r#"{{"action":"stopped","by":"session","reason":"exit","process_id":null,"snapshot":{{"name":"first","created_at":{FIRST_TOKEN},"tool":"codex"}}}}"#
        );
        let second_row = format!(
            r#"{{"action":"stopped","by":"session","reason":"exit","process_id":null,"snapshot":{{"name":"second","created_at":"{SECOND_TOKEN}"}}}}"#
        );
        let third_row = format!(
            r#"{{"action":"stopped","by":"session","reason":"exit","process_id":null,"snapshot":{{"name":"third","created_at":{THIRD_TOKEN}}}}}"#
        );

        let (mut db, db_path) = setup_full_test_db();
        // Stand the database back at v19 — the shape production opens.
        db.conn.execute_batch("PRAGMA user_version = 19").unwrap();
        for (name, data) in [
            ("first", &first_row),
            ("second", &second_row),
            ("third", &third_row),
        ] {
            db.conn
                .execute(
                    "INSERT INTO events (timestamp, type, instance, data) VALUES (?, 'life', ?, ?)",
                    params!["2026-01-01T00:00:00Z", name, data],
                )
                .unwrap();
        }

        // Arm the interruption on the last eligible row.
        let last_id: i64 = db
            .conn
            .query_row(
                "SELECT id FROM events WHERE type='life' AND instance='third'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        db.conn
            .execute_batch(&format!(
                "CREATE TRIGGER interrupt_backfill BEFORE UPDATE ON events
                 WHEN NEW.id = {last_id}
                      AND json_extract(NEW.data, '$.snapshot.created_at_bits') IS NOT NULL
                 BEGIN SELECT RAISE(ABORT, 'backfill-interrupted'); END;"
            ))
            .unwrap();

        // Production entry: open() -> ensure_schema(), killed partway.
        let err = db.ensure_schema().unwrap_err();
        assert!(
            format!("{err:#}").contains("backfill-interrupted"),
            "the interruption must surface: {err:#}"
        );

        // All-or-nothing: the backfill transaction rolled back as a unit, so
        // no row kept its bits and the originals survive byte-identical.
        let (with_bits, eligible): (i64, i64) = db
            .conn
            .query_row(
                "SELECT COUNT(CASE WHEN json_extract(data, '$.snapshot.created_at_bits') IS NOT NULL THEN 1 END),
                        COUNT(CASE WHEN json_extract(data, '$.snapshot.created_at') IS NOT NULL THEN 1 END)
                 FROM events WHERE type='life'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(eligible, 3);
        assert_eq!(with_bits, 0, "no row may be left half-migrated");
        for (name, original) in [
            ("first", &first_row),
            ("second", &second_row),
            ("third", &third_row),
        ] {
            let raw: String = db
                .conn
                .query_row(
                    "SELECT data FROM events WHERE type='life' AND instance=?1",
                    params![name],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(raw.as_str(), original.as_str(), "{name}: rollback is clean");
        }

        // Clear the interruption and re-run exactly what the runner makes:
        // a fresh open() -> ensure_schema() against the interrupted database.
        db.conn
            .execute_batch("DROP TRIGGER interrupt_backfill")
            .unwrap();
        drop(db);
        let db = HcomDb::open_at(&db_path).unwrap();

        assert_eq!(
            db.conn
                .query_row("PRAGMA user_version", [], |r| r.get::<_, i32>(0))
                .unwrap(),
            20
        );

        // Converged on the uninterrupted end state.
        for (name, original, expected_bits, token) in [
            ("first", &first_row, FIRST_BITS, FIRST_TOKEN),
            ("second", &second_row, SECOND_BITS, SECOND_TOKEN),
            ("third", &third_row, THIRD_BITS, THIRD_TOKEN),
        ] {
            let raw: String = db
                .conn
                .query_row(
                    "SELECT data FROM events WHERE type='life' AND instance=?1",
                    params![name],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(raw.contains(token), "{name}: raw token preserved: {raw}");
            let mut migrated: serde_json::Value = serde_json::from_str(&raw).unwrap();
            let bits = migrated["snapshot"]
                .as_object_mut()
                .unwrap()
                .remove("created_at_bits")
                .unwrap_or_else(|| panic!("{name}: rerun backfilled created_at_bits"));
            assert_eq!(
                bits.as_u64(),
                Some(expected_bits),
                "{name}: bits derived from the real snapshot.created_at"
            );
            let original: serde_json::Value = serde_json::from_str(original).unwrap();
            assert_eq!(&migrated, &original, "{name}: only the key was added");
        }

        cleanup_test_db(db_path);
    }

    /// The v20 backfill under concurrent opens: the first run after install
    /// has hooks and a relay sweep opening the same store at the same time,
    /// so two independent openers race on one old store, released together
    /// by a barrier. The race runs from v16 — the oldest version migrated in
    /// place, so every migration step contends — and from v19, where only
    /// the backfill does. Both openers must return Ok — SQLITE_BUSY must not
    /// surface to the caller; the busy_timeout retry in `open_connection` is
    /// part of the behavior under test — and the store must converge on
    /// exactly the single-run end state: user_version 20, exact bits beside
    /// every eligible `created_at`, nothing else in any snapshot touched, raw
    /// numeric tokens unreformatted, and the backfill applied exactly once
    /// (post-run rows byte-identical to a control store built the same way
    /// and migrated by a single opener). Every opener's handle and a fresh
    /// open of the path are checked, so a loser that archived and recreated
    /// the live store cannot pass on the winner's handle.
    #[test]
    fn events_migration_concurrent_opens_backfill_exactly_once() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(5000);

        const NUMBER_TOKEN: &str = "1790000000.0000021";
        const NUMBER_BITS: u64 = 4_745_294_612_153_761_801;
        const STRING_TOKEN: &str = "1762720048.770769";
        const STRING_BITS: u64 = 4_745_180_191_745_201_223;
        // Guard the fixtures themselves: std parse is the exact decoder.
        assert_eq!(NUMBER_TOKEN.parse::<f64>().unwrap().to_bits(), NUMBER_BITS);
        assert_eq!(STRING_TOKEN.parse::<f64>().unwrap().to_bits(), STRING_BITS);

        let number_row = format!(
            r#"{{"action":"stopped","by":"session","reason":"exit","process_id":null,"snapshot":{{"name":"num","created_at":{NUMBER_TOKEN},"tool":"codex"}}}}"#
        );
        let string_row = format!(
            r#"{{"action":"stopped","by":"session","reason":"exit","process_id":null,"snapshot":{{"name":"str","created_at":"{STRING_TOKEN}"}}}}"#
        );
        let adversarial_row = format!(
            r#"{{"action":"stopped","by":"session","reason":"exit","process_id":null,"hints":"use {{}} and \"created_at\": 999.5","text":"{{\"created_at\": 42}}","snapshot":{{"name":"adv","hints":"literal \"created_at\": 1.5 inside a string","created_at":{STRING_TOKEN}}}}}"#
        );
        let rows: [(&str, &str); 3] = [
            ("num", &number_row),
            ("str", &string_row),
            ("adv", &adversarial_row),
        ];
        let insert_rows = |conn: &Connection| {
            for (name, data) in rows {
                conn.execute(
                    "INSERT INTO events (timestamp, type, instance, data) VALUES (?, 'life', ?, ?)",
                    params!["2026-01-01T00:00:00Z", name, data],
                )
                .unwrap();
            }
        };

        // Stand a store back at its starting version with the fixture rows —
        // the shape production sees before its first v20 open. v19 is the
        // current schema restamped; v16 predates every MIGRATIONS step.
        let build_v19_store = || -> PathBuf {
            let (db, db_path) = setup_full_test_db();
            db.conn.execute_batch("PRAGMA user_version = 19").unwrap();
            insert_rows(&db.conn);
            db_path
        };
        let build_v16_store = || -> PathBuf {
            let db_path = std::env::temp_dir().join(format!(
                "test_hcom_race_v16_{}_{}.db",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let conn = Connection::open(&db_path).unwrap();
            // WAL like every store hcom has opened: `open_connection` sets it
            // and the mode persists in the file header.
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT, type TEXT, instance TEXT, data TEXT);
                 CREATE TABLE instances (
                     name TEXT PRIMARY KEY,
                     tool TEXT DEFAULT 'claude',
                     created_at REAL NOT NULL,
                     launch_context TEXT DEFAULT ''
                 );
                 CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);
                 CREATE TABLE notify_endpoints (instance TEXT, kind TEXT, port INTEGER, updated_at REAL, PRIMARY KEY(instance, kind));
                 CREATE TABLE session_bindings (session_id TEXT PRIMARY KEY, instance_name TEXT NOT NULL, created_at REAL NOT NULL);
                 PRAGMA user_version = 16;",
            )
            .unwrap();
            insert_rows(&conn);
            db_path
        };
        let dump = |db: &HcomDb| -> Vec<(String, String)> {
            let mut stmt = db
                .conn
                .prepare("SELECT instance, data FROM events WHERE type='life' ORDER BY instance")
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };

        // The race is timing, not determinism: one barrier release per
        // version can serialize lucky and leave the torn interleaving
        // unexercised. Loop it, rebuilding fresh stores per iteration.
        const RACE_ITERATIONS: u32 = 12;
        for (version, iteration) in (0..RACE_ITERATIONS).flat_map(|i| [(16, i), (19, i)]) {
            let (control_path, raced_path) = match version {
                16 => (build_v16_store(), build_v16_store()),
                _ => (build_v19_store(), build_v19_store()),
            };
            // Single-run control: one opener migrates its own store.
            let control = HcomDb::open_at(&control_path).unwrap();

            // The race: two independent openers released together against
            // the one store file, contending on the same migration.
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let openers: Vec<_> = (0..2)
                .map(|_| {
                    let path = raced_path.clone();
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        HcomDb::open_at(&path)
                    })
                })
                .collect();
            let dbs: Vec<HcomDb> = openers
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .enumerate()
                .map(|(i, result)| match result {
                    Ok(db) => db,
                    Err(e) => panic!("v{version} iter {iteration}: opener {i} failed under concurrent open: {e:#}"),
                })
                .collect();
            // What the next open of the path sees.
            let reopened = HcomDb::open_at(&raced_path).unwrap();

            for raced in dbs.iter().chain([&reopened]) {
                assert_eq!(
                    raced
                        .conn
                        .query_row("PRAGMA user_version", [], |r| r.get::<_, i32>(0))
                        .unwrap(),
                    20,
                    "v{version} iter {iteration}"
                );

                // Backfill landed exactly once: exact bits beside every
                // eligible created_at, nothing else in the snapshot touched,
                // raw token kept.
                for (name, original, expected_bits, token) in [
                    ("num", &number_row, NUMBER_BITS, NUMBER_TOKEN),
                    ("str", &string_row, STRING_BITS, STRING_TOKEN),
                    ("adv", &adversarial_row, STRING_BITS, STRING_TOKEN),
                ] {
                    let raw: String = raced
                        .conn
                        .query_row(
                            "SELECT data FROM events WHERE type='life' AND instance=?1",
                            params![name],
                            |r| r.get(0),
                        )
                        .unwrap_or_else(|e| {
                            panic!("v{version} iter {iteration} {name}: row survived the race: {e}")
                        });
                    assert!(
                        raw.contains(token),
                        "v{version} iter {iteration} {name}: raw token preserved: {raw}"
                    );
                    let mut migrated: serde_json::Value = serde_json::from_str(&raw).unwrap();
                    let bits = migrated["snapshot"]
                        .as_object_mut()
                        .unwrap()
                        .remove("created_at_bits")
                        .unwrap_or_else(|| {
                            panic!("v{version} iter {iteration} {name}: concurrent open backfilled created_at_bits")
                        });
                    assert_eq!(
                        bits.as_u64(),
                        Some(expected_bits),
                        "v{version} iter {iteration} {name}: bits bit-identical to the single-run expectation"
                    );
                    let original: serde_json::Value = serde_json::from_str(original).unwrap();
                    assert_eq!(
                        &migrated, &original,
                        "v{version} iter {iteration} {name}: only the key was added"
                    );
                }

                // Post-run contents match the single-run control byte for
                // byte — no double-apply, no archive-and-recreate, no lost rows.
                assert_eq!(
                    dump(raced),
                    dump(&control),
                    "v{version} iter {iteration}: raced store matches the single-run control"
                );
            }

            cleanup_test_db(raced_path);
            cleanup_test_db(control_path);
        }
    }

    /// The steady-state open takes no write lock: every hook opens the store,
    /// so a current store must open while another connection holds a write
    /// transaction, instead of queueing on busy_timeout and failing with
    /// SQLITE_BUSY. Only an open with migration work takes the lock.
    #[test]
    fn test_ensure_schema_current_store_opens_while_writer_holds_lock() {
        let (db, db_path) = setup_full_test_db();
        db.with_immediate_transaction(|_tx| HcomDb::open_at(&db_path).map(drop))
            .expect("a current store opens without the write lock");
        cleanup_test_db(db_path);
    }

    /// The already-WAL store under a concurrent-open storm: the rollout hosts
    /// run stores that were converted to WAL long ago, so the fresh-file race
    /// in `open_connection` (converting to WAL upgrades a read transaction to
    /// a write; the loser gets SQLITE_BUSY with no busy-handler retry) must
    /// not exist for them. `OPENERS` openers per entry point are released
    /// together by a barrier against one already-WAL store, covering both
    /// paths that reach `open_connection`: `open_raw` (bare connection layer)
    /// and `open_at` (production open with the schema check). Zero
    /// "database is locked" failures is the pass condition; exact
    /// success/failure counts are reported either way.
    #[test]
    fn already_wal_store_survives_concurrent_opens() {
        use std::sync::Arc;

        let (db, db_path) = setup_full_test_db();
        // Precondition, not enforcement: the store must already be WAL before
        // the race. If it is not, fail with that fact — forcing the mode here
        // would probe a different race than the rollout's.
        let journal_mode: String = db
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            journal_mode,
            "wal",
            "store at {} is not already in WAL mode (journal_mode={journal_mode})",
            db_path.display()
        );

        const OPENERS: usize = 200;
        for (name, open) in [
            (
                "open_raw",
                HcomDb::open_raw as fn(&std::path::Path) -> Result<HcomDb>,
            ),
            (
                "open_at",
                HcomDb::open_at as fn(&std::path::Path) -> Result<HcomDb>,
            ),
        ] {
            let barrier = Arc::new(std::sync::Barrier::new(OPENERS));
            let handles: Vec<_> = (0..OPENERS)
                .map(|_| {
                    let path = db_path.clone();
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        open(&path).map(drop)
                    })
                })
                .collect();
            let mut ok = 0usize;
            let mut failures: Vec<String> = Vec::new();
            for handle in handles {
                match handle.join().unwrap() {
                    Ok(()) => ok += 1,
                    Err(e) => failures.push(format!("{e:#}")),
                }
            }
            let locked = failures
                .iter()
                .filter(|f| f.contains("database is locked"))
                .count();
            eprintln!(
                "{name}: {ok}/{OPENERS} opens ok, {} failed, {locked} 'database is locked'",
                failures.len()
            );
            assert_eq!(
                locked,
                0,
                "{name}: SQLITE_BUSY surfaced on an already-WAL store: \
                 {locked} of {} failures were 'database is locked': {failures:#?}",
                failures.len()
            );
            assert!(
                failures.is_empty(),
                "{name}: {ok}/{OPENERS} opens ok, {} failed for other reasons: {failures:#?}",
                failures.len()
            );
        }

        cleanup_test_db(db_path);
    }
}
