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

    let now = crate::shared::time::now_epoch_i64();
    let existing = db.get_instance_full(name)?;

    if let Some(row) = existing.as_ref()
        && row.tool != tool
    {
        bail!(
            "instance '{name}' already exists with tool '{}' (hosted participants need '{}')",
            row.tool,
            tool
        );
    }

    let outcome = match existing {
        // Existing hosted row: liveness only. `last_event_id` is deliberately
        // absent from this update — the queued backlog survives the restart.
        Some(_) => {
            let updates = json!({
                "status": ST_LISTENING,
                "status_time": now,
                "status_context": CONTEXT_ONLINE,
                "status_detail": "",
                "last_stop": now,
                "tcp_mode": 1,
            });
            db.update_instance_fields(name, updates.as_object().expect("object literal"))?;
            RegisterOutcome::Refreshed
        }
        // New row: no session_id, no pid, no bindings — process truth has
        // nothing to release. Cursor at the current maximum, so a person who
        // joins a channel is not handed the whole group backlog.
        None => {
            let mut data = json!({
                "name": name,
                "tool": tool,
                "status": ST_LISTENING,
                "status_time": now,
                "status_context": CONTEXT_ONLINE,
                "status_detail": "",
                "last_stop": now,
                "last_event_id": db.get_last_event_id(),
                "tcp_mode": 1,
                "created_at": crate::shared::time::now_epoch_f64(),
                "directory": "",
                "transcript_path": "",
                "background": 0,
                "name_announced": 0,
                "origin_device_id": "",
            });
            let object = data.as_object_mut().expect("object literal");
            db.save_instance_named(name, object)?;
            RegisterOutcome::Created
        }
    };

    // The same `life.created` record (and auto-subscribe) any other row gets,
    // so the TUI, the relay and subscribers see the participant appear. The
    // tool is not a released harness spec, so the auto-subscribe is a no-op
    // for hosted tools today; the event is what matters.
    let mut post = crate::hooks::common::PostCommit::default();
    if outcome == RegisterOutcome::Created {
        let launcher =
            std::env::var("HCOM_LAUNCHED_BY").unwrap_or_else(|_| "connector".to_string());
        let event_data = json!({
            "action": "created",
            "by": launcher,
            "is_hcom_launched": false,
            "is_subagent": false,
            "parent_name": "",
        });
        let _ = db.log_event_collected("life", name, &event_data, &mut post);
    }

    // Status event so `hcom list` and the relay show the online transition,
    // the same way a process-bound row's transitions are logged.
    crate::instance_lifecycle::set_status_collected(
        db,
        name,
        ST_LISTENING,
        CONTEXT_ONLINE,
        crate::instance_lifecycle::StatusUpdate::default(),
        &mut post,
    );
    post.fire(db);

    Ok(outcome)
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
/// everything sent while the connector is down queues on their cursors.
pub fn set_hosted_offline(db: &HcomDb, tool: &str) -> Result<usize> {
    set_hosted_state(db, tool, ST_INACTIVE, CONTEXT_OFFLINE, &["stopped", "dead"])
}

/// The rollback path: hosted rows of `tool` go `stopped` / `buzz:down`, which
/// `fleet_names::LIVE_ROW_PREDICATE` refuses — a send aimed at them now fails
/// instead of queueing.
pub fn stop_hosted(db: &HcomDb, tool: &str) -> Result<usize> {
    set_hosted_state(db, tool, "stopped", CONTEXT_DOWN, &["stopped", "dead"])
}

/// Shared liveness write for the non-create transitions: one UPDATE over the
/// local hosted rows of `tool`, logging each status change the way the rest of
/// the codebase does so the TUI and relay see it.
fn set_hosted_state(
    db: &HcomDb,
    tool: &str,
    status: &str,
    context: &str,
    skip_statuses: &[&str],
) -> Result<usize> {
    let names: Vec<String> = {
        let mut stmt = db.conn().prepare(
            "SELECT name FROM instances
             WHERE COALESCE(origin_device_id, '') = ''
               AND tool = ?1",
        )?;
        stmt.query_map(rusqlite::params![tool], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect::<Vec<String>>()
    };

    let mut post = crate::hooks::common::PostCommit::default();
    let mut changed = 0;
    for name in &names {
        let skip = db.get_instance_full(name)?;
        if skip
            .as_ref()
            .is_some_and(|row| skip_statuses.contains(&row.status.as_str()) || row.status == status)
        {
            continue;
        }
        crate::instance_lifecycle::set_status_collected(
            db,
            name,
            status,
            context,
            crate::instance_lifecycle::StatusUpdate::default(),
            &mut post,
        );
        changed += 1;
    }
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
    /// `HCOM_DIR` has to be isolated and outlive the DB.
    fn setup_test_db() -> (HcomDb, PathBuf, crate::hooks::test_helpers::EnvGuard) {
        let (temp_dir, _hcom_dir, _home, guard) = crate::hooks::test_helpers::isolated_test_env();
        let db_path = temp_dir.path().join("hosted.db");
        let db = HcomDb::open_at(&db_path).unwrap();
        (db, db_path, guard)
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
        let (db, _path, _guard) = setup_test_db();

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
        let (db, _path, _guard) = setup_test_db();
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
        let (db, _path, _guard) = setup_test_db();
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
        let (db, _path, _guard) = setup_test_db();
        let err = register_hosted(&db, "Sean Fitz", HOSTED_TOOL_BUZZ)
            .expect_err("a name that is not a base name is unroutable forever");
        assert!(err.to_string().contains("Invalid instance name"), "{err}");
        assert!(db.get_instance_full("Sean Fitz").unwrap().is_none());
    }

    #[test]
    #[serial]
    fn register_refuses_a_bare_name_live_on_another_device() {
        let (db, _path, _guard) = setup_test_db();
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
        let (db, _path, _guard) = setup_test_db();
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
        let (db, _path, _guard) = setup_test_db();
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
}
