//! Notify endpoint registry helpers.
//!
//! Owns the `notify_endpoints` table — `(instance, kind, port)` rows that map
//! an instance to TCP ports the rest of the system can poke. Two protocol
//! families share this table:
//!
//! - **Wake endpoints** (kinds: `pty`, `hook`, `listen`, `listen_filter`,
//!   `events_wait`, `plugin`) — connect-and-close wakes a poll loop in the
//!   target process. See `crate::notify::WakeKind`.
//! - **Inject endpoint** (kind: `inject`) — bidirectional RPC for PTY input
//!   and screen queries. Lives in the same table for historical reasons; the
//!   protocol is unrelated to wake.

use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use super::HcomDb;
use crate::shared::time::now_epoch_f64;

impl HcomDb {
    /// Register notify endpoint for PTY wake-ups
    ///
    /// Inserts or updates notify_endpoints table with (instance, kind='pty', port)
    pub fn register_notify_port(&self, name: &str, port: u16) -> Result<()> {
        self.upsert_notify_endpoint(name, "pty", port)
    }

    /// Register inject port for screen queries
    pub fn register_inject_port(&self, name: &str, port: u16) -> Result<()> {
        self.upsert_notify_endpoint(name, "inject", port)
    }

    /// Delete notify endpoints for an instance
    pub fn delete_notify_endpoints(&self, name: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM notify_endpoints WHERE instance = ?",
            params![name],
        )?;
        Ok(())
    }

    /// Insert or update a notify endpoint with specific kind.
    /// Used by listen command to register listen/listen_filter endpoints.
    pub fn upsert_notify_endpoint(&self, name: &str, kind: &str, port: u16) -> Result<()> {
        let now = now_epoch_f64();

        self.conn.execute(
            "INSERT INTO notify_endpoints (instance, kind, port, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(instance, kind) DO UPDATE SET
                 port = excluded.port,
                 updated_at = excluded.updated_at",
            params![name, kind, port as i64, now],
        )?;
        Ok(())
    }

    /// Publish both PTY endpoints while the captured row or this process's
    /// current binding still authorizes them. Capture and publication share
    /// one transaction so stop or replacement cannot interleave with either.
    pub fn refresh_pty_endpoints(
        &self,
        name: &str,
        process_id: &str,
        captured_created_at: &mut Option<f64>,
        notify_port: u16,
        inject_port: u16,
    ) -> Result<()> {
        let held_created_at = *captured_created_at;
        let authorized_created_at = self.with_immediate_transaction(|tx| {
            let authorized_created_at: Option<f64> = tx
                .query_row(
                    "SELECT i.created_at
                     FROM instances AS i
                     WHERE i.name = ?1
                       AND (
                         i.created_at = ?2
                         OR (
                           ?3 != ''
                           AND EXISTS (
                             SELECT 1 FROM process_bindings AS b
                             WHERE b.process_id = ?3 AND b.instance_name = i.name
                           )
                         )
                       )",
                    params![name, held_created_at, process_id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(created_at) = authorized_created_at else {
                return Ok(None);
            };

            let now = now_epoch_f64();
            tx.execute(
                "INSERT INTO notify_endpoints (instance, kind, port, updated_at)
                 VALUES (?1, 'pty', ?2, ?4), (?1, 'inject', ?3, ?4)
                 ON CONFLICT(instance, kind) DO UPDATE SET
                     port = excluded.port,
                     updated_at = excluded.updated_at",
                params![name, notify_port as i64, inject_port as i64, now],
            )?;
            Ok(Some(created_at))
        })?;
        if let Some(created_at) = authorized_created_at {
            *captured_created_at = Some(created_at);
        }
        Ok(())
    }

    /// Delete a specific notify endpoint by instance and kind.
    pub fn delete_notify_endpoint(&self, name: &str, kind: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM notify_endpoints WHERE instance = ? AND kind = ?",
            params![name, kind],
        )?;
        Ok(())
    }

    /// Check if any notify endpoint exists for an instance.
    pub fn has_notify_endpoint(&self, name: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM notify_endpoints WHERE instance = ? LIMIT 1",
                params![name],
                |_| Ok(()),
            )
            .is_ok()
    }

    /// Check whether a notify endpoint of a specific `kind` exists for an
    /// instance. `kind='plugin'` is registered only when a plugin-driven tool
    /// (pi/omp) has bound its extension — a rendering-independent proof that the
    /// interactive TUI is up, used as a launch-readiness signal where the
    /// on-screen ready pattern is theme/preset dependent.
    pub fn has_notify_endpoint_kind(&self, name: &str, kind: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM notify_endpoints WHERE instance = ? AND kind = ? LIMIT 1",
                params![name, kind],
                |_| Ok(()),
            )
            .is_ok()
    }

    /// Every notify endpoint registered for an instance as `(kind, port)`,
    /// ordered by kind. Callers that need a single kind keep using
    /// [`HcomDb::has_notify_endpoint_kind`]; this is the port list for
    /// liveness probes that must not guess the kind.
    pub fn notify_endpoint_ports(&self, instance: &str) -> Result<Vec<(String, u16)>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT kind, port FROM notify_endpoints WHERE instance = ? ORDER BY kind",
        )?;
        let rows = stmt
            .query_map(params![instance], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u16))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{cleanup_test_db, setup_full_test_db};

    #[test]
    fn test_register_inject_port_inserts() {
        let (db, db_path) = setup_full_test_db();

        db.register_inject_port("test", 5555).unwrap();

        let port: i64 = db
            .conn
            .query_row(
                "SELECT port FROM notify_endpoints WHERE instance = 'test' AND kind = 'inject'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(port, 5555);

        cleanup_test_db(db_path);
    }

    #[test]
    fn test_register_inject_port_upserts() {
        let (db, db_path) = setup_full_test_db();

        db.register_inject_port("test", 5555).unwrap();
        db.register_inject_port("test", 6666).unwrap();

        let port: i64 = db
            .conn
            .query_row(
                "SELECT port FROM notify_endpoints WHERE instance = 'test' AND kind = 'inject'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(port, 6666);

        // Should be exactly one row
        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM notify_endpoints WHERE instance = 'test'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        cleanup_test_db(db_path);
    }

    #[test]
    fn pty_endpoint_refresh_preserves_current_incarnation_after_pid_session_change() {
        let (db, db_path) = setup_full_test_db();
        db.conn
            .execute(
                "INSERT INTO instances (name, tool, created_at, pid, session_id)
                 VALUES ('alpha', 'omp', 1, 101, 'session-one')",
                [],
            )
            .unwrap();
        db.set_process_binding("process-p", "session-one", "alpha")
            .unwrap();
        db.upsert_notify_endpoint("alpha", "plugin", 41003).unwrap();

        let mut endpoint_created_at = None;
        db.refresh_pty_endpoints("alpha", "process-p", &mut endpoint_created_at, 41001, 41002)
            .unwrap();
        assert_eq!(
            db.notify_endpoint_ports("alpha").unwrap(),
            vec![
                ("inject".to_string(), 41002),
                ("plugin".to_string(), 41003),
                ("pty".to_string(), 41001),
            ]
        );

        db.conn
            .execute(
                "UPDATE instances SET pid = 202, session_id = 'session-two' WHERE name = 'alpha'",
                [],
            )
            .unwrap();
        // A temporarily absent binding cannot revoke the already captured row.
        db.delete_process_binding("process-p").unwrap();
        db.refresh_pty_endpoints("alpha", "process-p", &mut endpoint_created_at, 42001, 42002)
            .unwrap();
        assert_eq!(
            db.notify_endpoint_ports("alpha").unwrap(),
            vec![
                ("inject".to_string(), 42002),
                ("plugin".to_string(), 41003),
                ("pty".to_string(), 42001),
            ]
        );

        drop(db);
        cleanup_test_db(db_path);
    }

    #[test]
    fn pty_endpoint_refresh_cannot_publish_after_finalize_stop() {
        let (db, db_path) = setup_full_test_db();
        db.conn
            .execute(
                "INSERT INTO instances (name, tool, created_at, session_id)
                 VALUES ('alpha', 'omp', 1, 'session-one')",
                [],
            )
            .unwrap();
        db.set_process_binding("process-p", "session-one", "alpha")
            .unwrap();
        db.upsert_notify_endpoint("alpha", "plugin", 41003).unwrap();
        let mut endpoint_created_at = None;
        db.refresh_pty_endpoints("alpha", "process-p", &mut endpoint_created_at, 41001, 41002)
            .unwrap();

        let snapshot = db.get_instance_full("alpha").unwrap().unwrap();
        let bindings = db.process_binding_ids("alpha").unwrap();
        let event = serde_json::json!({
            "action": "stopped",
            "by": "test",
            "reason": "killed",
            "snapshot": db.get_instance("alpha").unwrap().unwrap(),
        });
        let (won, _) = db
            .with_immediate_transaction(|tx| {
                db.finalize_instance_stop_in_txn(
                    tx,
                    &snapshot.name,
                    snapshot.created_at,
                    snapshot.pid,
                    snapshot.session_id.as_deref(),
                    snapshot.agent_id.as_deref(),
                    &event,
                    Some("process-p"),
                    Some(bindings.as_slice()),
                )
            })
            .unwrap();
        assert!(won, "the matching stop must remove this incarnation");
        assert!(db.get_instance_full("alpha").unwrap().is_none());

        let mut fresh_created_at = None;
        for capture in [&mut endpoint_created_at, &mut fresh_created_at] {
            db.refresh_pty_endpoints("alpha", "process-p", capture, 42001, 42002)
                .unwrap();
            assert!(db.notify_endpoint_ports("alpha").unwrap().is_empty());
            let count: i64 = db
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM notify_endpoints WHERE instance = 'alpha'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
        }

        drop(db);
        cleanup_test_db(db_path);
    }

    #[test]
    fn pty_endpoint_refresh_cannot_overwrite_another_process_replacement() {
        let (db, db_path) = setup_full_test_db();
        db.conn
            .execute(
                "INSERT INTO instances (name, tool, created_at, session_id)
                 VALUES ('alpha', 'omp', 1, 'session-one')",
                [],
            )
            .unwrap();
        db.set_process_binding("process-p", "session-one", "alpha")
            .unwrap();
        let mut endpoint_created_at = None;
        db.refresh_pty_endpoints("alpha", "process-p", &mut endpoint_created_at, 41001, 41002)
            .unwrap();

        db.with_immediate_transaction(|tx| {
            tx.execute_batch(
                "DELETE FROM instances WHERE name = 'alpha';
                 DELETE FROM process_bindings WHERE instance_name = 'alpha';
                 DELETE FROM notify_endpoints WHERE instance = 'alpha';
                 INSERT INTO instances (name, tool, created_at, pid, session_id, agent_id)
                   VALUES ('alpha', 'omp', 2, 202, 'session-two', 'agent-q');
                 INSERT INTO process_bindings (process_id, session_id, instance_name, updated_at)
                   VALUES ('process-q', 'session-two', 'alpha', 20);
                 INSERT INTO notify_endpoints (instance, kind, port, updated_at) VALUES
                   ('alpha', 'pty', 43001, 21),
                   ('alpha', 'inject', 43002, 22),
                   ('alpha', 'plugin', 43003, 23);",
            )?;
            Ok(())
        })
        .unwrap();
        let endpoint_rows = || {
            db.conn
                .prepare(
                    "SELECT instance, kind, port, updated_at FROM notify_endpoints
                     WHERE instance = 'alpha' ORDER BY kind",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, f64>(3)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let replacement_endpoints = endpoint_rows();
        let replacement = db.get_instance("alpha").unwrap().unwrap();
        let replacement_binding = db.get_process_binding_full("process-q").unwrap();

        let mut fresh_created_at = None;
        for capture in [&mut endpoint_created_at, &mut fresh_created_at] {
            db.refresh_pty_endpoints("alpha", "process-p", capture, 42001, 42002)
                .unwrap();
            assert_eq!(endpoint_rows(), replacement_endpoints);
            assert_eq!(
                db.get_instance("alpha").unwrap().as_ref(),
                Some(&replacement)
            );
            assert_eq!(
                db.get_process_binding_full("process-q").unwrap(),
                replacement_binding
            );
            assert_eq!(db.process_binding_ids("alpha").unwrap(), vec!["process-q"]);
            assert_eq!(db.get_process_binding("process-p").unwrap(), None);
        }

        drop(db);
        cleanup_test_db(db_path);
    }
}
