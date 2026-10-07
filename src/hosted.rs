//! Connector-hosted participants: rows one long-lived process owns.
//!
//! An ordinary hcom row belongs to a harness process — it carries a
//! `session_id`, an anchor `pid`, and process bindings, and the daemon sweep
//! releases it once that process is provably gone. A hosted participant is the
//! other shape: one connector process (`hcom buzz serve`) owns *many* rows at
//! once (Buzz people and channels), and no single process dies when the
//! connector does. Binding those rows to a connector pid would get them reaped
//! the moment it exited.
//!
//! So a hosted row is deliberately unowned by process truth: no session, no
//! pid, no bindings. What keeps it alive instead is (a) the exemption in
//! [`crate::proctruth::sweep_vanished_instances`], (b) its exclusion from
//! `hcom stop all`, and (c) liveness written by the connector's own heartbeat.
//! Retention deliberately does NOT depend on status: a hosted row goes
//! `inactive` / `buzz:offline` when the connector stops, and that row still
//! queues the messages sent while it was down.
//!
//! Registration never resets an existing row's `last_event_id`. The ordinary
//! initializer (`instance_binding`) jumps a new row's cursor to the current
//! event maximum, which is right for an agent (it must not read the whole
//! backlog of an existing conversation) and wrong here: a connector restart
//! has to resume each participant's cursor, not silently discard what it has
//! not posted yet. Hence [`RegisterOutcome::Refreshed`], which touches liveness
//! only.

use anyhow::{Result, bail};
use serde_json::json;

use crate::db::HcomDb;
use crate::shared::constants::{ST_INACTIVE, ST_LISTENING};

/// The `tool` value a connector-hosted row carries.
pub const HOSTED_TOOL_BUZZ: &str = "buzz";

/// Liveness context of a hosted row whose connector is running.
const CONTEXT_ONLINE: &str = "buzz:online";
/// Liveness context of a hosted row whose connector has gone away. Not an
/// `exit:*` context, so the row stays deliverable and messages queue on it.
const CONTEXT_OFFLINE: &str = "buzz:offline";
/// Context of a hosted row rolled back to stopped — no longer deliverable.
const CONTEXT_DOWN: &str = "buzz:down";

/// Signals that registration has reached the point between its occupancy
/// check and its row write. A test arms it with a two-party channel: the
/// competing connection is released to commit there, and registration then
/// runs its write against whatever that writer left behind.
///
/// This deliberately does NOT block inside the transaction — a barrier here
/// would deadlock, since the competitor's own write needs the same lock we
/// hold. The channel hands over immediately and the competitor proceeds
/// independently.
struct RegisterGap {
    reached: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

impl RegisterGap {
    fn arrive(&self) {
        let _ = self.reached.send(());
        // Bounded: if the competitor never replies (it lost the race to a
        // lock it cannot get), registration must still finish.
        let _ = self
            .release
            .recv_timeout(std::time::Duration::from_secs(10));
    }
}

thread_local! {
    static REGISTER_GAP_HOOK: std::cell::RefCell<Option<RegisterGap>> =
        const { std::cell::RefCell::new(None) };
}

// The same seam for `set_hosted_state`: fires between its candidate select
// and its conditional writes, so a test can land a competing commit in
// exactly the window the conditional `UPDATE ... WHERE` has to survive.
thread_local! {
    static TRANSITION_GAP_HOOK: std::cell::RefCell<Option<RegisterGap>> =
        const { std::cell::RefCell::new(None) };
}

// Fires right after `set_hosted_state` commits, before its deferred wakes:
// the window where a post-commit row write would clobber a concurrent stop.
thread_local! {
    static TRANSITION_COMMITTED_HOOK: std::cell::RefCell<Option<RegisterGap>> =
        const { std::cell::RefCell::new(None) };
}

/// Does `tool` mark a row as connector-hosted?
///
/// This is the one predicate every exemption keys off: the sweep's skip and
/// `stop all`'s exclusion both call it, so a new hosted tool is exempt from
/// reaping by being named here.
pub fn is_hosted_tool(tool: &str) -> bool {
    tool == HOSTED_TOOL_BUZZ
}

/// What a [`register_hosted`] call did to the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// The row did not exist; it was inserted with its cursor at the current
    /// event maximum, so it starts with no backlog.
    Created,
    /// The row existed with the same tool. Its `last_event_id` is untouched —
    /// only liveness was refreshed — so anything queued while the connector
    /// was down is still unread on restart.
    Refreshed,
}

/// Register (or re-register) `name` as a connector-hosted participant of
/// `tool`.
///
/// Refuses, with a message naming the way out:
/// - a name that is not a valid base name (nothing normalizes it later, so a
///   bad name would be a permanently unroutable row);
/// - a name already held by a row of a *different* tool — that row is a real
///   participant's identity and replacing it would silently retarget its
///   traffic;
/// - a bare name that is live as a mirror row on another device, the same
///   cross-host guard `start --as` applies
///   ([`crate::instance_names::remote_name_refusal`]).
///
/// On success the row is `listening` / `buzz:online`, `tcp_mode = 1`,
/// heartbeated, and — when newly created — carries the ordinary
/// `life{action:"created"}` event so subscribers and the TUI see it appear.
pub fn register_hosted(db: &HcomDb, name: &str, tool: &str) -> Result<RegisterOutcome> {
    if !crate::identity::is_valid_base_name(name) {
        bail!("{}", crate::identity::base_name_error(name));
    }
    if !is_hosted_tool(tool) {
        bail!("'{tool}' is not a connector-hosted tool");
    }

    if let Some(refusal) = crate::instance_names::remote_name_refusal(db, name)? {
        bail!("{refusal}");
    }

    // The occupancy check, the row write and the cursor decision share ONE
    // `BEGIN IMMEDIATE` transaction. Two connectors racing to register the
    // same participant (or a connector racing a harness) must serialize
    // here: read-then-write outside a lock lets a stale creator overwrite a
    // row another registration just wrote, and lets the new-row branch
    // compute its cursor from a maximum that has already moved past a message
    // queued for this participant.
    let mut post = crate::hooks::common::PostCommit::default();
    let outcome = db.with_immediate_transaction(|tx| {
        let existing: Option<String> = tx
            .query_row(
                "SELECT tool FROM instances WHERE name = ?1",
                rusqlite::params![name],
                |r| r.get::<_, String>(0),
            )
            .ok();

        let Some(row_tool) = existing else {
            // Test seam: hands the competing writer its turn in the window
            // between the occupancy check and the row write.
            if let Some(gate) = REGISTER_GAP_HOOK.with(|hook| hook.borrow_mut().take()) {
                gate.arrive();
            }

            // New row: no session_id, no pid, no bindings — process truth has
            // nothing to release. The cursor is read INSIDE this transaction,
            // so it cannot come from a stale maximum and skip a message queued
            // since. A person who joins a channel is not handed the whole
            // group backlog.
            let now = crate::shared::time::now_epoch_i64();
            let current_max: i64 =
                tx.query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |r| {
                    r.get(0)
                })?;
            tx.execute(
                "INSERT INTO instances
                 (name, tool, status, status_time, status_context, status_detail,
                  last_stop, last_event_id, tcp_mode, created_at, directory,
                  transcript_path, background, name_announced, origin_device_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, '', ?4, ?6, 1, ?7, '', '', 0, 0, '')",
                rusqlite::params![
                    name,
                    tool,
                    ST_LISTENING,
                    now,
                    CONTEXT_ONLINE,
                    current_max,
                    crate::shared::time::now_epoch_f64(),
                ],
            )?;

            // The same `life.created` record any other row gets, so the TUI,
            // the relay and subscribers see the participant appear. The tool
            // is not a released harness spec, so there is no auto-subscribe.
            let launcher =
                std::env::var("HCOM_LAUNCHED_BY").unwrap_or_else(|_| "connector".to_string());
            let life = json!({
                "action": "created",
                "by": launcher,
                "is_hcom_launched": false,
                "is_subagent": false,
                "parent_name": "",
            });
            db.log_event_collected("life", name, &life, &mut post)?;
            log_transition(
                db,
                name,
                None,
                current_max,
                ST_LISTENING,
                CONTEXT_ONLINE,
                &mut post,
            )?;
            return Ok(RegisterOutcome::Created);
        };

        if row_tool != tool {
            bail!(
                "instance '{name}' already exists with tool '{row_tool}' (hosted participants need '{tool}')"
            );
        }

        // Test seam: hands the competing writer its turn in the window between
        // the occupancy check and the row write. Fires on whichever branch
        // the row takes, since either one can lose a race.
        if let Some(gate) = REGISTER_GAP_HOOK.with(|hook| hook.borrow_mut().take()) {
            gate.arrive();
        }

        // Existing hosted row: one conditional write carrying every guard,
        // inside the same transaction as the occupancy check, so it cannot
        // land on a replacement row of another tool. `last_event_id` is not
        // written, so the queued backlog survives. The prior state is read in
        // this same snapshot and the status event is written here too: there
        // is no second, post-commit write that could clobber a concurrent
        // stop or re-read a row this transaction already moved.
        let (old_status, old_context, position): (String, String, i64) = tx.query_row(
            "SELECT status, status_context, last_event_id FROM instances WHERE name = ?1",
            rusqlite::params![name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let now = crate::shared::time::now_epoch_i64();
        let written = tx.execute(
            "UPDATE instances
             SET status = ?2, status_time = ?3, status_context = ?4,
                 status_detail = '', last_stop = ?3, tcp_mode = 1
             WHERE name = ?1 AND tool = ?5
               AND COALESCE(origin_device_id, '') = ''",
            rusqlite::params![name, ST_LISTENING, now, CONTEXT_ONLINE, tool],
        )?;
        if written > 0 && (old_status != ST_LISTENING || old_context != CONTEXT_ONLINE) {
            log_transition(
                db,
                name,
                Some((&old_status, &old_context)),
                position,
                ST_LISTENING,
                CONTEXT_ONLINE,
                &mut post,
            )?;
        }
        Ok(RegisterOutcome::Refreshed)
    })?;
    // Only the deferred effects run after commit: subscription TCP wakes and
    // the transition wakes collected above. Nothing here writes a row.
    post.fire(db);

    Ok(outcome)
}

/// Write the status event for one hosted transition, from the prior state the
/// caller read inside its own write transaction, and queue the delivery-loop
/// wake into `post` when the status itself changed — the same event shape and
/// wake rule as `instance_lifecycle::set_status`.
///
/// Call it inside the transaction that made the guarded row write. It writes
/// the event row only, never the instance row: `set_status` re-writes the
/// row by name, which after commit would clobber a concurrent stop and read a
/// row this transaction already moved. `prior` is `None` for a row that did
/// not exist before.
fn log_transition(
    db: &HcomDb,
    name: &str,
    prior: Option<(&str, &str)>,
    position: i64,
    status: &str,
    context: &str,
    post: &mut crate::hooks::common::PostCommit,
) -> Result<()> {
    let (old_status, old_context) = prior.unzip();
    // Hosted rows carry no session, so the event has no `session` field.
    let data = json!({
        "status": status,
        "context": context,
        "position": position,
        "old_status": old_status,
        "old_context": old_context,
        "old_detail": prior.map(|_| ""),
        "new_status": status,
        "new_context": context,
        "new_detail": "",
        "writer": "hosted",
    });
    db.log_event_collected("status", name, &data, post)?;
    if old_status != Some(status) {
        post.collect_wake(db, name, crate::notify::WakeKind::DELIVERY_LOOPS);
    }
    Ok(())
}

/// One connector heartbeat: touch `last_stop` on every live local hosted row
/// of `tool`. Rows already `stopped` are left alone — a stopped row is not
/// resurrected by a heartbeat. Returns the number of rows updated.
pub fn heartbeat_hosted(db: &HcomDb, tool: &str) -> Result<usize> {
    let now = crate::shared::time::now_epoch_i64();
    let updated = db.conn().execute(
        "UPDATE instances SET last_stop = ?1, tcp_mode = 1
         WHERE COALESCE(origin_device_id, '') = ''
           AND tool = ?2
           AND status != 'stopped'",
        rusqlite::params![now, tool],
    )?;
    Ok(updated)
}

/// The connector stopped cleanly: every live local hosted row of `tool` goes
/// `inactive` / `buzz:offline`.
///
/// `buzz:offline` is not an `exit:*` context, so the rows stay deliverable and
/// everything sent while the connector is down queues on their cursors. Only
/// rows that are actually online are transitioned: a row a concurrent
/// [`stop_hosted`] already took down stays down rather than becoming
/// deliverable again.
pub fn set_hosted_offline(db: &HcomDb, tool: &str) -> Result<usize> {
    set_hosted_state(
        db,
        tool,
        None,
        ST_INACTIVE,
        CONTEXT_OFFLINE,
        &[CONTEXT_ONLINE],
    )
}

/// The rollback path: hosted rows of `tool` go `stopped` / `buzz:down`, which
/// `fleet_names::LIVE_ROW_PREDICATE` refuses — a send aimed at them now fails
/// instead of queueing. This is the terminal transition, so it applies to
/// every local hosted row of `tool` whatever state it is in.
pub fn stop_hosted(db: &HcomDb, tool: &str) -> Result<usize> {
    set_hosted_state(db, tool, None, "stopped", CONTEXT_DOWN, &[])
}

/// Stop one hosted row, the same terminal transition `stop_hosted` applies to
/// them all: for a participant that left every bridged channel while the
/// connector keeps running.
pub fn stop_hosted_row(db: &HcomDb, tool: &str, name: &str) -> Result<usize> {
    set_hosted_state(db, tool, Some(name), "stopped", CONTEXT_DOWN, &[])
}

/// Apply one hosted transition to every local row of `tool` that is in one of
/// `from_contexts` (empty means "any context, but never already in the target
/// state").
///
/// The candidate list, every row's write and every row's status event share
/// ONE `BEGIN IMMEDIATE`. Each write is a single conditional `UPDATE ...
/// WHERE name = ? AND tool = ? AND <expected prior state>`, and the status
/// event is written in the same transaction from the prior state read just
/// before it. That rules out the races the bulk form was exposed to:
///
/// - a concurrent `stop_hosted` cannot commit between our read and our write
///   (the write lock excludes it), and one committed before us leaves the
///   row outside our prior-state guard, so a stopped row is never made
///   deliverable again by a stale offline write;
/// - an explicit stop plus a relaunch that replaced the row with another
///   tool fails the `tool = ?` guard, so a connector never writes liveness
///   onto somebody else's identity;
/// - nothing writes the row after commit, so a stop committed right after us
///   stands, and the event's `old_status`/`old_context` are what the row
///   really was.
///
/// Returns the number of rows actually moved; only those get a status event
/// and, when the status changed, a delivery-loop wake after commit.
fn set_hosted_state(
    db: &HcomDb,
    tool: &str,
    only: Option<&str>,
    status: &str,
    context: &str,
    from_contexts: &[&str],
) -> Result<usize> {
    let mut post = crate::hooks::common::PostCommit::default();
    let changed = db.with_immediate_transaction(|tx| {
        let mut names: Vec<String> = if from_contexts.is_empty() {
            let mut stmt = tx.prepare(
                "SELECT name FROM instances
                 WHERE COALESCE(origin_device_id, '') = ''
                   AND tool = ?1
                   AND status != ?2",
            )?;
            stmt.query_map(rusqlite::params![tool, status], |row| {
                row.get::<_, String>(0)
            })?
            .filter_map(|r| r.ok())
            .collect::<Vec<String>>()
        } else {
            let placeholders = vec!["?"; from_contexts.len()].join(", ");
            let sql = format!(
                "SELECT name FROM instances
                 WHERE COALESCE(origin_device_id, '') = ''
                   AND tool = ?1
                   AND status_context IN ({placeholders})"
            );
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(tool.to_string())];
            params.extend(
                from_contexts
                    .iter()
                    .map(|c| Box::new(c.to_string()) as Box<dyn rusqlite::types::ToSql>),
            );
            let refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|b| b.as_ref()).collect();
            let mut stmt = tx.prepare(&sql)?;
            stmt.query_map(refs.as_slice(), |row| row.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect::<Vec<String>>()
        };
        if let Some(only) = only {
            names.retain(|name| name == only);
        }

        // Test seam: hands a competing writer its turn between the candidate
        // select and the conditional writes below.
        if let Some(gate) = TRANSITION_GAP_HOOK.with(|hook| hook.borrow_mut().take()) {
            gate.arrive();
        }

        let now = crate::shared::time::now_epoch_i64();
        let mut changed = 0;
        for name in names {
            // The prior state for the event comes from this snapshot, right
            // before the write it describes.
            let (old_status, old_context, position): (String, String, i64) = tx.query_row(
                "SELECT status, status_context, last_event_id FROM instances WHERE name = ?1",
                rusqlite::params![name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            // One conditional statement, carrying every guard. The prior-state
            // guard is the context list when the caller named one, and
            // "not already in the target state" otherwise — so an empty
            // `from_contexts` is a real guard (any row not already stopped),
            // not an empty IN () that matches nothing.
            let n = tx.execute(
                "UPDATE instances
                 SET status = ?2, status_time = ?3, status_context = ?4, status_detail = ''
                 WHERE name = ?1 AND tool = ?5
                   AND COALESCE(origin_device_id, '') = ''
                   AND CASE WHEN json_array_length(?6) = 0
                            THEN status != ?2
                            ELSE status_context IN (SELECT value FROM json_each(?6))
                       END",
                rusqlite::params![
                    name,
                    status,
                    now,
                    context,
                    tool,
                    serde_json::json!(from_contexts).to_string(),
                ],
            )?;
            if n > 0 {
                log_transition(
                    db,
                    &name,
                    Some((&old_status, &old_context)),
                    position,
                    status,
                    context,
                    &mut post,
                )?;
                changed += 1;
            }
        }
        Ok(changed)
    })?;

    // Test seam: the window right after commit, where the old code wrote the
    // row a second time.
    if let Some(gate) = TRANSITION_COMMITTED_HOOK.with(|hook| hook.borrow_mut().take()) {
        gate.arrive();
    }
    // Only deferred effects from here: subscription TCP wakes and the
    // transition wakes collected in the transaction. No row is written.
    post.fire(db);
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::send::send_message;
    use crate::shared::{SenderIdentity, SenderKind};
    use serial_test::serial;
    use std::path::PathBuf;

    /// `send_message` reaches the process-global relay path, so its ambient
    /// `HCOM_DIR` has to be isolated and outlive the DB. The `TempDir` is
    /// returned rather than dropped: dropping it here would delete the
    /// database file the returned handle still points at.
    fn setup_test_db() -> (
        HcomDb,
        PathBuf,
        tempfile::TempDir,
        crate::hooks::test_helpers::EnvGuard,
    ) {
        let (temp_dir, _hcom_dir, _home, guard) = crate::hooks::test_helpers::isolated_test_env();
        let db_path = temp_dir.path().join("hosted.db");
        let db = HcomDb::open_at(&db_path).unwrap();
        (db, db_path, temp_dir, guard)
    }

    fn cursor(db: &HcomDb, name: &str) -> i64 {
        db.get_cursor(name)
    }

    fn row(db: &HcomDb, name: &str) -> crate::db::InstanceRow {
        db.get_instance_full(name)
            .unwrap()
            .unwrap_or_else(|| panic!("{name} has no row"))
    }

    fn life_events(db: &HcomDb, name: &str, action: &str) -> i64 {
        db.conn()
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE instance = ?1 AND type = 'life'
                   AND json_extract(data, '$.action') = ?2",
                rusqlite::params![name, action],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn sender() -> SenderIdentity {
        SenderIdentity {
            kind: SenderKind::Instance,
            name: "luna".into(),
            instance_data: None,
            session_id: None,
        }
    }

    /// Send `text` to `name` and return the id of the row the send inserted,
    /// read back through the hosted row's own unread scan. That is the whole
    /// deliverability claim: a send resolved to this row, and the row's
    /// cursor (where the connector restarts reading) sits below it.
    fn send_to(db: &HcomDb, name: &str, text: &str) -> Result<i64, String> {
        let delivered = send_message(db, &sender(), text, None, Some(&[name.to_string()]))?;
        assert_eq!(delivered, vec![name.to_string()], "resolved to {name}");
        db.get_unread_messages(name)
            .into_iter()
            .find(|m| m.text == text)
            .and_then(|m| m.event_id)
            .ok_or_else(|| format!("{name} never received {text:?}"))
    }

    fn unread_ids(db: &HcomDb, name: &str) -> Vec<i64> {
        db.get_unread_messages(name)
            .into_iter()
            .filter_map(|m| m.event_id)
            .collect()
    }

    #[test]
    #[serial]
    fn register_creates_a_listening_deliverable_row_with_no_backlog() {
        let (db, _path, _dir, _guard) = setup_test_db();

        assert_eq!(
            register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap(),
            RegisterOutcome::Created
        );

        let row = row(&db, "michael");
        assert_eq!(row.tool, "buzz");
        assert_eq!(row.status, ST_LISTENING);
        assert_eq!(row.status_context, "buzz:online");
        assert_eq!(row.tcp_mode, 1);
        assert!(row.last_stop > 0, "registration heartbeats the row");
        assert!(
            row.session_id.is_none(),
            "a hosted row belongs to no session: {:?}",
            row.session_id
        );
        assert!(
            row.pid.is_none(),
            "a hosted row binds no pid: {:?}",
            row.pid
        );
        assert!(
            db.process_binding_ids("michael").unwrap().is_empty(),
            "a hosted row binds no process"
        );
        assert_eq!(life_events(&db, "michael", "created"), 1);
        assert!(
            row.last_event_id >= db.get_last_event_id() - 2,
            "a new hosted row starts at the current cursor, not the backlog"
        );

        // Deliverable: a send addressed at it is what it reads as unread.
        let id = send_to(&db, "michael", "status?").unwrap();
        assert_eq!(unread_ids(&db, "michael"), vec![id]);
        assert_eq!(cursor(&db, "michael"), 0, "the cursor waits for delivery");
    }

    #[test]
    #[serial]
    fn re_register_preserves_the_cursor_and_the_queued_backlog() {
        let (db, _path, _dir, _guard) = setup_test_db();
        register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap();

        let queued = send_to(&db, "michael", "while you were down").unwrap();
        // The connector goes away, and comes back: registration must not
        // rewind the cursor to the current maximum the way the ordinary
        // initializer does, or this message is silently dropped.
        set_hosted_offline(&db, HOSTED_TOOL_BUZZ).unwrap();
        assert_eq!(row(&db, "michael").status_context, "buzz:offline");

        assert_eq!(
            register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap(),
            RegisterOutcome::Refreshed
        );

        assert_eq!(row(&db, "michael").status, ST_LISTENING);
        assert_eq!(row(&db, "michael").status_context, "buzz:online");
        assert_eq!(
            unread_ids(&db, "michael"),
            vec![queued],
            "the queued message survived the restart"
        );
        assert_eq!(cursor(&db, "michael"), 0, "the cursor never moved");
        assert_eq!(life_events(&db, "michael", "created"), 1, "one creation");
    }

    #[test]
    #[serial]
    fn register_refuses_a_name_held_by_another_tool() {
        let (db, _path, _dir, _guard) = setup_test_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, status_context)
                 VALUES ('luna', 'active', 1.0, 'codex', 'ready')",
                [],
            )
            .unwrap();

        let err = register_hosted(&db, "luna", HOSTED_TOOL_BUZZ)
            .expect_err("a codex row's name is not the connector's to take");
        let msg = err.to_string();
        assert!(msg.contains("luna"), "{msg}");
        assert!(msg.contains("codex"), "{msg}");
        assert_eq!(row(&db, "luna").tool, "codex", "the row is untouched");
        assert_eq!(row(&db, "luna").status, "active");
    }

    #[test]
    #[serial]
    fn register_refuses_an_invalid_name() {
        let (db, _path, _dir, _guard) = setup_test_db();
        let err = register_hosted(&db, "Sean Fitz", HOSTED_TOOL_BUZZ)
            .expect_err("a name that is not a base name is unroutable forever");
        assert!(err.to_string().contains("Invalid instance name"), "{err}");
        assert!(db.get_instance_full("Sean Fitz").unwrap().is_none());
    }

    #[test]
    #[serial]
    fn register_refuses_a_bare_name_live_on_another_device() {
        let (db, _path, _dir, _guard) = setup_test_db();
        let device = "11111111-1111-4111-8111-111111111111";
        let short = crate::relay::device_short_id(device);
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, status_context, status_time,
                                        created_at, tool, origin_device_id)
                 VALUES (?1, 'listening', 'ready', 1, 1.0, 'omp', ?2)",
                rusqlite::params![format!("michael:{short}"), device],
            )
            .unwrap();

        let err = register_hosted(&db, "michael", HOSTED_TOOL_BUZZ)
            .expect_err("the cross-host guard applies to hosted rows too");
        let msg = err.to_string();
        assert!(msg.contains("another device"), "{msg}");
        assert!(msg.contains(&format!("michael:{short}")), "{msg}");
    }

    #[test]
    #[serial]
    fn heartbeat_refreshes_live_rows_only() {
        let (db, _path, _dir, _guard) = setup_test_db();
        register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap();
        register_hosted(&db, "ch_infra", HOSTED_TOOL_BUZZ).unwrap();
        db.conn()
            .execute(
                "UPDATE instances SET last_stop = 1, tcp_mode = 0, status = 'stopped',
                                        status_context = 'buzz:down'
                 WHERE name = 'ch_infra'",
                [],
            )
            .unwrap();

        assert_eq!(heartbeat_hosted(&db, HOSTED_TOOL_BUZZ).unwrap(), 1);
        assert!(row(&db, "michael").last_stop > 1, "the live row beat");
        assert_eq!(row(&db, "michael").tcp_mode, 1);
        assert_eq!(
            row(&db, "ch_infra").last_stop,
            1,
            "a stopped row is not resurrected by a heartbeat"
        );
        assert_eq!(row(&db, "ch_infra").tcp_mode, 0);
    }

    #[test]
    #[serial]
    fn offline_keeps_rows_deliverable_and_stop_refuses_sends() {
        let (db, _path, _dir, _guard) = setup_test_db();
        register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap();

        assert_eq!(set_hosted_offline(&db, HOSTED_TOOL_BUZZ).unwrap(), 1);
        assert_eq!(row(&db, "michael").status, ST_INACTIVE);
        assert_eq!(row(&db, "michael").status_context, "buzz:offline");

        // Offline is still deliverable: it queues.
        let queued = send_to(&db, "michael", "you are down").unwrap();
        assert_eq!(unread_ids(&db, "michael"), vec![queued]);

        // Stopped is not.
        assert_eq!(stop_hosted(&db, HOSTED_TOOL_BUZZ).unwrap(), 1);
        assert_eq!(row(&db, "michael").status, "stopped");
        assert_eq!(row(&db, "michael").status_context, "buzz:down");
        let refused = send_message(
            &db,
            &sender(),
            "still there?",
            None,
            Some(&["michael".to_string()]),
        )
        .expect_err("a stopped row is not a send target");
        assert!(!refused.is_empty(), "the refusal names the reason");
    }

    #[test]
    #[serial]
    fn is_hosted_tool_names_only_the_connector_tool() {
        assert!(is_hosted_tool(HOSTED_TOOL_BUZZ));
        assert!(!is_hosted_tool("codex"));
        assert!(!is_hosted_tool(""));
        assert!(!is_hosted_tool("Buzz"));
    }

    // ── regressions from the PR-77 review ─────────────────────────────

    /// Registration must serialize its occupancy check against a competing
    /// writer. This arms the gap seam: a second connection tries to claim
    /// the name exactly between the check and the row write.
    ///
    /// With the check and the write outside one `BEGIN IMMEDIATE`, the
    /// competitor lands in that window and the connector's INSERT OR REPLACE
    /// silently takes the row — and the other seat's cursor — with it. Here
    /// the competitor is a plain INSERT against the committed row, so the
    /// primary key is what protects the identity once the lock is in place.
    #[test]
    #[serial]
    fn registration_refuses_a_name_a_concurrent_writer_took() {
        let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (temp_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let path = temp_dir.path().join("hosted.db");
        let db = HcomDb::open_at(&path).unwrap();

        REGISTER_GAP_HOOK.with(|h| {
            h.replace(Some(RegisterGap {
                reached: reached_tx,
                release: release_rx,
            }))
        });

        // The competitor: waits for our window, then commits. It is a plain
        // INSERT, so it collides with our committed primary key rather than
        // replacing it.
        let rival_path = path.clone();
        let rival = std::thread::spawn(move || {
            let conn = HcomDb::open_raw(&rival_path).unwrap();
            reached_rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("registration never reached the gap");
            let result = conn
                .conn()
                .execute(
                    "INSERT INTO instances (name, tool, status, created_at, last_event_id)
                     VALUES ('michael', 'codex', 'active', 1.0, 17)",
                    [],
                )
                .map(|_| ())
                .map_err(|e| e.to_string());
            release_tx.send(()).ok();
            result
        });

        let outcome = register_hosted(&db, "michael", HOSTED_TOOL_BUZZ);
        let rival_result = rival.join().expect("competitor thread panicked");
        REGISTER_GAP_HOOK.with(|h| h.replace(None));

        // Ours committed first, so the competitor's INSERT hits the primary
        // key and loses — it cannot steal the identity.
        assert!(
            rival_result.is_err(),
            "the competitor overwrote a committed hosted row: {rival_result:?}"
        );
        assert_eq!(outcome.unwrap(), RegisterOutcome::Created);
        assert_eq!(row(&db, "michael").tool, "buzz", "the hosted row survived");
    }

    /// The same race, read from the cursor side: a message for this
    /// participant is committed in the window between the occupancy check and
    /// the INSERT. The transaction's write lock must make that attempt fail
    /// outright, so the cursor can never be computed from a maximum that
    /// already moved past the message.
    #[test]
    #[serial]
    fn a_new_row_cursor_cannot_skip_a_message_queued_during_registration() {
        let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (temp_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let path = temp_dir.path().join("hosted.db");
        let db = HcomDb::open_at(&path).unwrap();

        REGISTER_GAP_HOOK.with(|h| {
            h.replace(Some(RegisterGap {
                reached: reached_tx,
                release: release_rx,
            }))
        });

        let queued_path = path.clone();
        let queue_thread = std::thread::spawn(move || {
            let conn = HcomDb::open_raw(&queued_path).unwrap();
            reached_rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("registration never reached the gap");
            let result = conn
                .log_event(
                    "message",
                    "luna",
                    &json!({
                        "from": "luna", "text": "queued in the window",
                        "scope": "mentions", "mentions": ["michael"],
                        "exact_targets": ["michael"], "delivered_to": ["michael"],
                    }),
                )
                .map_err(|e| e.to_string());
            release_tx.send(()).ok();
            result
        });

        let outcome = register_hosted(&db, "michael", HOSTED_TOOL_BUZZ);
        let queued_result = queue_thread.join().expect("queueing thread panicked");
        REGISTER_GAP_HOOK.with(|h| h.replace(None));

        assert_eq!(outcome.unwrap(), RegisterOutcome::Created);

        // The window is inside our transaction, so the competing write is
        // refused — nothing lands between our check and our INSERT. Without
        // the lock the message would commit here and the cursor (read from
        // whatever maximum was current) could sit above it, skipping it.
        let queued = queued_result.expect_err(
            "a message committed inside the registration window: \
             the cursor can be computed from a maximum that skipped it",
        );
        assert!(
            queued.contains("locked") || queued.contains("busy"),
            "the competing write must be refused by the transaction's lock, \
             not succeed: {queued}"
        );

        // And the invariant the connector depends on: the new row's cursor was
        // taken from the maximum visible inside its own transaction, so it
        // sits at or above every message that existed when the row was
        // created, and no earlier message is skipped.
        let created_max = db
            .conn()
            .query_row(
                "SELECT COALESCE(MAX(id), 0) FROM events
                 WHERE type = 'message' AND instance != 'michael'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
        assert!(
            cursor(&db, "michael") >= created_max,
            "cursor {} is below message maximum {created_max}: \
             a new hosted row would skip messages",
            cursor(&db, "michael")
        );
    }

    /// An explicit-name launch must refuse a hosted row, never delete it.
    /// `resolve_explicit_name_conflict` treats an `inactive` row as a stale
    /// resume handle and deletes it — for an offline hosted participant that
    /// discards a real cursor and hands the identity to a harness.
    #[test]
    #[serial]
    fn an_explicit_name_launch_refuses_an_offline_hosted_row() {
        let (db, _path, _dir, _guard) = setup_test_db();
        register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap();
        set_hosted_offline(&db, HOSTED_TOOL_BUZZ).unwrap();
        send_to(&db, "michael", "queued while offline").unwrap();
        db.conn()
            .execute(
                "UPDATE instances SET last_event_id = 37 WHERE name = 'michael'",
                [],
            )
            .unwrap();

        let err = crate::launcher::resolve_explicit_name_conflict(&db, "michael", None)
            .expect_err("a hosted identity is not a stale resume handle");
        assert!(
            err.to_string().contains("connector-hosted"),
            "the refusal must say who owns it: {err}"
        );

        let row = row(&db, "michael");
        assert_eq!(row.tool, "buzz", "the hosted row survived");
        assert_eq!(row.last_event_id, 37, "and kept its cursor");
    }

    /// A refresh must log the status the row was ACTUALLY in and wake the
    /// delivery loop on offline→online. Writing the status inside the
    /// registration transaction before the status helper read it made the
    /// helper see `listening`/`buzz:online` on an offline row, log that as
    /// the prior status, and skip the transition wake.
    #[test]
    #[serial]
    fn refresh_logs_the_real_prior_status_on_an_offline_to_online_transition() {
        let (db, _path, _dir, _guard) = setup_test_db();
        register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap();
        set_hosted_offline(&db, HOSTED_TOOL_BUZZ).unwrap();
        assert_eq!(row(&db, "michael").status_context, "buzz:offline");

        register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap();

        let data: String = db
            .conn()
            .query_row(
                "SELECT data FROM events WHERE type = 'status' AND instance = 'michael'
                 ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let data: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(data["old_status"], "inactive", "logged event: {data}");
        assert_eq!(data["old_context"], "buzz:offline", "logged event: {data}");
        assert_eq!(data["new_status"], "listening", "logged event: {data}");
        assert_eq!(data["new_context"], "buzz:online", "logged event: {data}");
    }

    // ── regressions from the round-2 fauna review ────────────────────

    /// A concurrent `stop_hosted` must not be undone by an in-flight
    /// `set_hosted_offline`. The old bulk form read the row, decided, and
    /// wrote outside any transaction: a stop landing in that window was
    /// overwritten with `inactive`/`buzz:offline`, and a rolled-back
    /// participant became deliverable again.
    ///
    /// The stop here commits INSIDE the offline sweep's candidate-select →
    /// write window, which is precisely where the conditional
    /// `... WHERE status_context IN (...)` has to refuse it.
    #[test]
    #[serial]
    fn a_stop_committed_inside_the_offline_window_stays_stopped() {
        let (temp_dir, _hcom_dir, _home, guard) = crate::hooks::test_helpers::isolated_test_env();
        let path = temp_dir.path().join("hosted.db");
        let db = HcomDb::open_at(&path).unwrap();
        register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap();

        let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        TRANSITION_GAP_HOOK.with(|h| {
            h.replace(Some(RegisterGap {
                reached: reached_tx,
                release: release_rx,
            }))
        });

        // The rollback lands from its own connection, and commits BEFORE the
        // sweep resumes. The sweep is holding only a read so far (it has
        // selected candidates but not yet written), so this write succeeds —
        // and the sweep's subsequent conditional UPDATE has to refuse the row
        // whose `status_context` changed underneath it. The write lock is
        // not what saves the row here; the `WHERE` guard is.
        let rollback_path = path.clone();
        let rollback = std::thread::spawn(move || {
            let conn = HcomDb::open_raw(&rollback_path).unwrap();
            reached_rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the offline sweep never reached the gap");
            let result = conn
                .conn()
                .execute(
                    "UPDATE instances
                     SET status = 'stopped', status_context = 'buzz:down'
                     WHERE name = 'michael' AND status_context = 'buzz:online'",
                    [],
                )
                .map(|_| ())
                .map_err(|e| e.to_string());
            release_tx.send(()).ok();
            result
        });

        let swept = set_hosted_offline(&db, HOSTED_TOOL_BUZZ);
        let rollback_result = rollback.join().expect("rollback thread panicked");
        TRANSITION_GAP_HOOK.with(|h| h.replace(None));
        let _ = guard;

        // The rollback's write is refused outright: `set_hosted_state` holds the
        // transaction's write lock from BEGIN IMMEDIATE, so a concurrent
        // writer cannot commit between the candidate select and the
        // conditional UPDATE at all. The conditional `WHERE` guards stay as
        // the second line for any writer that committed before the lock was
        // taken.
        let rollback = rollback_result.expect_err(
            "a rollback committed inside the sweep's transaction: \
             the write lock did not exclude it",
        );
        assert!(
            rollback.contains("locked") || rollback.contains("busy"),
            "the competing write must be refused by the transaction's lock: {rollback}"
        );
        assert_eq!(swept.expect("the offline sweep ran"), 1);

        assert_eq!(
            row(&db, "michael").status_context,
            "buzz:offline",
            "the sweep moved the row while the rollback waited"
        );

        // A rollback that lands AFTER the sweep must still not be undone by a
        // later sweep: the offline transition only applies to rows that were
        // online when it ran, so a row already `buzz:down` is not a candidate
        // and stays stopped.
        assert_eq!(stop_hosted(&db, HOSTED_TOOL_BUZZ).unwrap(), 1);
        assert_eq!(
            set_hosted_offline(&db, HOSTED_TOOL_BUZZ).unwrap(),
            0,
            "the offline sweep must not resurrect a stopped row"
        );

        assert_eq!(row(&db, "michael").status, "stopped", "the rollback stands");
        assert_eq!(row(&db, "michael").status_context, "buzz:down");
        // And a send still refuses: the row is not deliverable again.
        let refused = send_message(
            &db,
            &sender(),
            "still there?",
            None,
            Some(&["michael".to_string()]),
        )
        .expect_err("a stopped row must not become deliverable again");
        assert!(!refused.is_empty(), "{refused}");
    }

    /// The bulk transitions are name-based, so they must never write onto a
    /// row that has been replaced by a different tool underneath them (an
    /// explicit stop plus a relaunch). The `tool = ?` guard is what stops
    /// this; without it a connector would stamp `buzz:offline` onto somebody
    /// else's freshly launched identity. The replacement commits inside the
    /// sweep's candidate-select → write window, where the candidate list is
    /// already built and only the `WHERE` guards can still refuse it.
    #[test]
    #[serial]
    fn a_bulk_transition_never_touches_a_replacement_row_of_another_tool() {
        let (temp_dir, _hcom_dir, _home, guard) = crate::hooks::test_helpers::isolated_test_env();
        let path = temp_dir.path().join("hosted.db");
        let db = HcomDb::open_at(&path).unwrap();
        register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap();

        let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        TRANSITION_GAP_HOOK.with(|h| {
            h.replace(Some(RegisterGap {
                reached: reached_tx,
                release: release_rx,
            }))
        });

        // The operator stops the participant and a harness claims the name.
        let replacement_path = path.clone();
        let replacement = std::thread::spawn(move || {
            let conn = HcomDb::open_raw(&replacement_path).unwrap();
            reached_rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the sweep never reached the gap");
            let result = conn
                .conn()
                .execute(
                    "UPDATE instances
                     SET tool = 'codex', status = 'active', status_context = 'ready',
                         status_time = 1
                     WHERE name = 'michael'",
                    [],
                )
                .map(|_| ())
                .map_err(|e| e.to_string());
            release_tx.send(()).ok();
            result
        });

        let swept = set_hosted_offline(&db, HOSTED_TOOL_BUZZ);
        let replacement_result = replacement.join().expect("replacement thread panicked");
        TRANSITION_GAP_HOOK.with(|h| h.replace(None));
        let _ = guard;

        // The replacement is refused by the sweep's write lock, so the row is
        // still the connector's and the sweep legitimately moved it.
        let replacement = replacement_result.expect_err(
            "a replacement committed inside the sweep's transaction: \
             the write lock did not exclude it",
        );
        assert!(
            replacement.contains("locked") || replacement.contains("busy"),
            "the competing write must be refused by the transaction's lock: {replacement}"
        );
        assert_eq!(swept.expect("the sweep ran"), 1);
        assert_eq!(row(&db, "michael").status_context, "buzz:offline");

        // Now the `tool = ?` guard, with the replacement committed for real:
        // once another tool owns the name, no hosted transition may select
        // or write that row.
        db.conn()
            .execute(
                "UPDATE instances SET tool = 'codex', status = 'active',
                                      status_context = 'ready', status_time = 1
                 WHERE name = 'michael'",
                [],
            )
            .unwrap();

        assert_eq!(
            stop_hosted(&db, HOSTED_TOOL_BUZZ).unwrap(),
            0,
            "a stop must not touch a row another tool now owns"
        );
        assert_eq!(
            set_hosted_offline(&db, HOSTED_TOOL_BUZZ).unwrap(),
            0,
            "an offline sweep must not touch a row another tool now owns"
        );
        assert_eq!(row(&db, "michael").tool, "codex");
        assert_eq!(row(&db, "michael").status_context, "ready");
    }

    /// Only rows the transition actually moved may log a status event. A row
    /// already in the target state must produce no event at all — otherwise
    /// every connector loop rewrites the same transition for every idle
    /// participant and the event stream stops meaning "something changed".
    #[test]
    #[serial]
    fn a_transition_logs_nothing_for_rows_it_did_not_change() {
        let (db, _path, _dir, _guard) = setup_test_db();
        register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap();
        set_hosted_offline(&db, HOSTED_TOOL_BUZZ).unwrap();

        let count = |db: &HcomDb| -> i64 {
            db.conn()
                .query_row(
                    "SELECT COUNT(*) FROM events
                     WHERE type = 'status' AND instance = 'michael'
                       AND json_extract(data, '$.new_context') = 'buzz:offline'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let after_first = count(&db);
        assert_eq!(after_first, 1, "the real transition logged once");

        // A second sweep changes nothing, so it must log nothing.
        assert_eq!(set_hosted_offline(&db, HOSTED_TOOL_BUZZ).unwrap(), 0);
        assert_eq!(count(&db), after_first, "an unchanged row logged again");
    }

    /// Nothing may write the row after the transition commits. A stop that
    /// lands right after the offline sweep commits must stand: the old code
    /// called `set_status_collected` post-commit, which re-wrote the row by
    /// name (`inactive`/`buzz:offline` over the stop, so a rolled-back
    /// participant was deliverable again) and logged the stopped row as the
    /// transition's prior state. The event must carry the state the sweep
    /// really moved from, and the delivery-loop wake must still fire.
    #[test]
    #[serial]
    fn a_stop_committed_right_after_the_offline_commit_stays_stopped() {
        let (db, path, _dir, _guard) = setup_test_db();
        register_hosted(&db, "michael", HOSTED_TOOL_BUZZ).unwrap();

        // A delivery loop listening for the row's wake.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        db.register_notify_port("michael", port).unwrap();

        let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        TRANSITION_COMMITTED_HOOK.with(|h| {
            h.replace(Some(RegisterGap {
                reached: reached_tx,
                release: release_rx,
            }))
        });

        // The rollback commits from its own connection once the sweep's
        // transaction is durable and before anything else the sweep does.
        let rollback = std::thread::spawn(move || {
            let conn = HcomDb::open_raw(&path).unwrap();
            reached_rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the offline sweep never committed");
            let result = conn
                .conn()
                .execute(
                    "UPDATE instances SET status = 'stopped', status_context = 'buzz:down'
                     WHERE name = 'michael'",
                    [],
                )
                .map_err(|e| e.to_string());
            release_tx.send(()).ok();
            result
        });

        let swept = set_hosted_offline(&db, HOSTED_TOOL_BUZZ);
        let rollback = rollback.join().expect("rollback thread panicked");
        TRANSITION_COMMITTED_HOOK.with(|h| h.replace(None));

        assert_eq!(rollback.expect("the rollback committed"), 1);
        assert_eq!(swept.expect("the offline sweep ran"), 1);

        // The stop stands.
        let row = row(&db, "michael");
        assert_eq!(row.status, "stopped", "a post-commit write undid the stop");
        assert_eq!(row.status_context, "buzz:down");

        // The event describes the move the sweep made, from what the row was.
        let data: String = db
            .conn()
            .query_row(
                "SELECT data FROM events WHERE type = 'status' AND instance = 'michael'
                   AND json_extract(data, '$.new_context') = 'buzz:offline'
                 ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let data: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(data["old_status"], "listening", "logged event: {data}");
        assert_eq!(data["old_context"], "buzz:online", "logged event: {data}");
        assert_eq!(data["new_status"], "inactive", "logged event: {data}");

        // And the delivery loop was woken.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let woken = loop {
            match listener.accept() {
                Ok(_) => break true,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        break false;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("accept failed: {e}"),
            }
        };
        assert!(woken, "the offline transition never woke the delivery loop");
    }
}
