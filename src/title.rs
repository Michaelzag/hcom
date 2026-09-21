//! Session purpose + live subtask (`title`) — what a session is for.
//!
//! Two fields, both stored on the `instances` row:
//! - `purpose`: stable, set once the session knows its task (`hcom title "<text>"`).
//! - `current`: the live subtask, updated often (`hcom title --now "<text>"`,
//!   or automatically from tool-call intent by the hooks).
//!
//! Both render into the terminal title (`{icon} {name} — {purpose} · {current}`,
//! empty segments omitted) and into `hcom list`. Latest write wins; no timers,
//! no expiry.

use crate::db::HcomDb;
use crate::instances::update_instance_position;

/// Max chars for purpose/current after sanitizing (60, per spec).
pub const MAX_TITLE_CHARS: usize = 60;

/// Sanitize raw purpose/current text: trim, collapse whitespace, strip
/// C0/ESC/controls (reuses the pty layer's title sanitizer), bound to
/// [`MAX_TITLE_CHARS`] chars. Empty in → empty out.
pub fn sanitize(text: &str) -> String {
    crate::pty::screen::sanitize_title_capped(text, MAX_TITLE_CHARS)
}

/// Build the title infix for a non-empty purpose/current pair: `" — {purpose} · {current}"`,
/// omitting empty segments. Returns `""` when both are empty so callers can
/// keep the existing title output byte-identical.
pub fn title_infix(purpose: &str, current: &str) -> String {
    match (purpose.is_empty(), current.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!(" — {purpose}"),
        (true, false) => format!(" — {current}"),
        (false, false) => format!(" — {purpose} · {current}"),
    }
}

/// Set the stable purpose for `name`. Returns the sanitized value stored.
pub fn set_purpose(db: &HcomDb, name: &str, raw: &str) -> String {
    let value = sanitize(raw);
    let mut updates = serde_json::Map::new();
    if value.is_empty() {
        updates.insert("purpose".into(), serde_json::Value::Null);
    } else {
        updates.insert("purpose".into(), serde_json::json!(value));
    }
    update_instance_position(db, name, &updates);
    value
}

/// Set the live subtask for `name`. Returns the sanitized value stored.
/// Empty input leaves the existing value untouched (a hook payload without
/// an intent must not clear an explicitly set phase).
pub fn set_current(db: &HcomDb, name: &str, raw: &str) -> String {
    let value = sanitize(raw);
    if value.is_empty() {
        return String::new();
    }
    let mut updates = serde_json::Map::new();
    updates.insert("current".into(), serde_json::json!(value));
    update_instance_position(db, name, &updates);
    value
}

/// Clear both purpose and current for `name`.
pub fn clear(db: &HcomDb, name: &str) {
    let mut updates = serde_json::Map::new();
    updates.insert("purpose".into(), serde_json::Value::Null);
    updates.insert("current".into(), serde_json::Value::Null);
    update_instance_position(db, name, &updates);
}

/// Record a tool-call intent as the live subtask. No-op when the payload
/// carries no usable intent, so hook traffic without `i` never clobbers an
/// explicitly set phase. Latest write wins.
pub fn record_intent(db: &HcomDb, name: &str, tool_input: &serde_json::Value) {
    let intent = tool_input.get("i").and_then(|v| v.as_str()).unwrap_or("");
    if sanitize(intent).is_empty() {
        return;
    }
    set_current(db, name, intent);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_trims_and_collapses_whitespace() {
        assert_eq!(sanitize("  zagdb:   rc.48\n\troll  "), "zagdb: rc.48 roll");
    }

    #[test]
    fn sanitize_strips_escape_sequences() {
        assert_eq!(sanitize("a\x1b]2;evil\x07b"), "a]2;evilb");
        assert_eq!(sanitize("ok\x1b[31mred"), "ok[31mred");
    }

    #[test]
    fn sanitize_truncates_to_sixty_chars() {
        let long = "x".repeat(61);
        assert_eq!(sanitize(&long).chars().count(), 60);
        assert_eq!(sanitize(&"y".repeat(60)).chars().count(), 60);
    }

    #[test]
    fn sanitize_empty_stays_empty() {
        assert_eq!(sanitize(""), "");
        assert_eq!(sanitize("   \t\n  "), "");
    }

    #[test]
    fn infix_omits_empty_segments() {
        assert_eq!(title_infix("", ""), "");
        assert_eq!(title_infix("zagdb: rc.48 roll", ""), " — zagdb: rc.48 roll");
        assert_eq!(title_infix("", "probing WAL"), " — probing WAL");
        assert_eq!(
            title_infix("zagdb: rc.48 roll", "probing WAL"),
            " — zagdb: rc.48 roll · probing WAL"
        );
    }

    #[test]
    fn set_and_clear_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_at(&dir.path().join("hcom.db")).unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, status, status_context, status_time, created_at)
                 VALUES ('luna', 'claude', 'listening', 'start', 0, 0)",
                [],
            )
            .unwrap();

        assert_eq!(
            set_purpose(&db, "luna", "  zagdb: rc.48 roll  "),
            "zagdb: rc.48 roll"
        );
        assert_eq!(set_current(&db, "luna", "probing WAL"), "probing WAL");
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.purpose.as_deref(), Some("zagdb: rc.48 roll"));
        assert_eq!(row.current.as_deref(), Some("probing WAL"));

        // Empty current never clears.
        set_current(&db, "luna", "   ");
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.current.as_deref(), Some("probing WAL"));

        clear(&db, "luna");
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert!(row.purpose.is_none());
        assert!(row.current.is_none());
    }

    #[test]
    fn record_intent_updates_current_only_with_intent() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_at(&dir.path().join("hcom.db")).unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, status, status_context, status_time, created_at)
                 VALUES ('nova', 'omp', 'active', 'tool:read', 0, 0)",
                [],
            )
            .unwrap();

        record_intent(
            &db,
            "nova",
            &serde_json::json!({"i": "Reading model role settings"}),
        );
        let row = db.get_instance_full("nova").unwrap().unwrap();
        assert_eq!(row.current.as_deref(), Some("Reading model role settings"));
        assert!(row.purpose.is_none());

        // Payload without intent leaves current alone.
        record_intent(&db, "nova", &serde_json::json!({"path": "/tmp/x"}));
        let row = db.get_instance_full("nova").unwrap().unwrap();
        assert_eq!(row.current.as_deref(), Some("Reading model role settings"));
    }

    #[test]
    fn snapshot_carries_purpose_and_current() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::HcomDb::open_at(&dir.path().join("hcom.db")).unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, status, status_context, status_time, created_at)
                 VALUES ('mira', 'claude', 'listening', 'start', 0, 0)",
                [],
            )
            .unwrap();
        set_purpose(&db, "mira", "zagdb: rc.48 roll");
        set_current(&db, "mira", "probing WAL");

        let snap = db.get_instance_snapshot("mira").unwrap().unwrap();
        assert_eq!(snap["purpose"].as_str(), Some("zagdb: rc.48 roll"));
        assert_eq!(snap["current"].as_str(), Some("probing WAL"));
    }
}
