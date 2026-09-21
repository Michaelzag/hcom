//! `hcom title` command — show or set what a session is doing.
//!
//! `hcom title "<purpose>"` sets the stable purpose for the CALLING session
//! (resolved the same way `hcom config -i self` resolves it).
//! `hcom title --now "<subtask>"` sets the live subtask.
//! `hcom title` with neither prints both; `hcom title --clear` clears both.
//!
//! Both values render into the terminal title (`{icon} {name} — {purpose} ·
//! {current}`) and `hcom list`. Max 60 chars after trim; whitespace collapsed,
//! C0/ESC stripped (see `crate::title`).

use crate::db::HcomDb;
use crate::identity;
use crate::shared::CommandContext;

/// Parsed arguments for `hcom title`.
#[derive(clap::Parser, Debug)]
#[command(name = "title", about = "Show or set session purpose")]
pub struct TitleArgs {
    /// Stable purpose text (what this session is for)
    pub text: Option<String>,
    /// Live subtask text (what this session is doing right now)
    #[arg(long)]
    pub now: Option<String>,
    /// Clear purpose and current
    #[arg(long)]
    pub clear: bool,
}

/// Render the `hcom title` no-args readout.
pub fn render_title_get(purpose: Option<&str>, current: Option<&str>) -> String {
    let purpose = purpose.filter(|s| !s.is_empty()).unwrap_or("(none)");
    let current = current.filter(|s| !s.is_empty()).unwrap_or("(none)");
    format!("Purpose: {purpose}\nCurrent: {current}")
}

/// Main entry point for `hcom title`. Returns exit code.
pub fn cmd_title(db: &HcomDb, args: &TitleArgs, ctx: Option<&CommandContext>) -> i32 {
    // Resolve the calling session, same as `config -i self`.
    let Some(name) = ctx
        .and_then(|c| c.identity.as_ref())
        .map(|id| id.name.clone())
    else {
        eprintln!("Error: Cannot resolve 'self' — no active identity");
        return 1;
    };
    let name =
        identity::resolve_display_name(db, &name).unwrap_or_else(|| name.clone());

    let instance = match db.get_instance_full(&name) {
        Ok(Some(inst)) => inst,
        Ok(None) => {
            eprintln!("Error: Agent '{name}' not found");
            return 1;
        }
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };
    let inst_name = instance.name.clone();

    if args.clear {
        crate::title::clear(db, &inst_name);
        println!("Cleared title for {inst_name}");
        crate::relay::spawn_background_push();
        return 0;
    }

    match (args.text.as_deref(), args.now.as_deref()) {
        (None, None) => {
            println!(
                "{}",
                render_title_get(
                    instance.purpose.as_deref(),
                    instance.current.as_deref()
                )
            );
            0
        }
        (purpose, now) => {
            if let Some(text) = purpose {
                let stored = crate::title::set_purpose(db, &inst_name, text);
                if stored.is_empty() {
                    println!("Cleared purpose for {inst_name}");
                } else {
                    println!("Set title for {inst_name}: {stored}");
                }
            }
            if let Some(text) = now {
                let stored = crate::title::set_current(db, &inst_name, text);
                if stored.is_empty() {
                    println!("Current unchanged for {inst_name} (empty --now leaves it)");
                } else {
                    println!("Set current for {inst_name}: {stored}");
                }
            }
            crate::relay::spawn_background_push();
            crate::notify::wake_all(db);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::{SenderIdentity, SenderKind};

    fn ctx_for(name: &str) -> CommandContext {
        CommandContext {
            explicit_name: None,
            identity: Some(SenderIdentity {
                kind: SenderKind::Instance,
                name: name.to_string(),
                instance_data: None,
                session_id: None,
            }),
            go: false,
        }
    }

    fn test_db() -> (tempfile::TempDir, HcomDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_at(&dir.path().join("hcom.db")).unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, status, status_context, status_time, created_at)
                 VALUES ('luna', 'claude', 'listening', 'start', 0, 0)",
                [],
            )
            .unwrap();
        (dir, db)
    }

    #[test]
    fn title_without_identity_errors() {
        let (_dir, db) = test_db();
        let args = TitleArgs {
            text: Some("x".into()),
            now: None,
            clear: false,
        };
        assert_eq!(cmd_title(&db, &args, None), 1);
    }

    #[test]
    fn title_sets_purpose_for_calling_session() {
        let (_dir, db) = test_db();
        let ctx = ctx_for("luna");
        let args = TitleArgs {
            text: Some("zagdb: rc.48 roll".into()),
            now: None,
            clear: false,
        };
        assert_eq!(cmd_title(&db, &args, Some(&ctx)), 0);
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.purpose.as_deref(), Some("zagdb: rc.48 roll"));
    }

    #[test]
    fn title_now_sets_current_and_leaves_purpose() {
        let (_dir, db) = test_db();
        let ctx = ctx_for("luna");
        crate::title::set_purpose(&db, "luna", "zagdb: rc.48 roll");
        let args = TitleArgs {
            text: None,
            now: Some("probing WAL".into()),
            clear: false,
        };
        assert_eq!(cmd_title(&db, &args, Some(&ctx)), 0);
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert_eq!(row.current.as_deref(), Some("probing WAL"));
        assert_eq!(row.purpose.as_deref(), Some("zagdb: rc.48 roll"));
    }

    #[test]
    fn title_clear_wipes_both() {
        let (_dir, db) = test_db();
        let ctx = ctx_for("luna");
        crate::title::set_purpose(&db, "luna", "zagdb: rc.48 roll");
        crate::title::set_current(&db, "luna", "probing WAL");
        let args = TitleArgs {
            text: None,
            now: None,
            clear: true,
        };
        assert_eq!(cmd_title(&db, &args, Some(&ctx)), 0);
        let row = db.get_instance_full("luna").unwrap().unwrap();
        assert!(row.purpose.is_none());
        assert!(row.current.is_none());
    }

    #[test]
    fn render_title_get_shows_none_for_empty() {
        assert_eq!(
            render_title_get(Some("zagdb: rc.48 roll"), None),
            "Purpose: zagdb: rc.48 roll\nCurrent: (none)"
        );
        assert_eq!(
            render_title_get(None, None),
            "Purpose: (none)\nCurrent: (none)"
        );
    }
}
