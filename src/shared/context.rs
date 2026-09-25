//! Per-request execution context for hcom.
//!
//! HcomContext is constructed once at request entry and passed by reference
//! to all handlers. No global state or thread-locals.

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use crate::db::HcomDb;
use crate::tool::Tool;

/// Minimum wall-clock seconds between two `identity.foreign_refused` log
/// lines for the same process id. Hooks are separate short-lived processes,
/// so the throttle state lives in the store's kv table.
const FOREIGN_REFUSED_LOG_INTERVAL: f64 = 600.0;

/// Per-request execution context.
///
/// Constructed once at entry (hook invocation or CLI command), then passed
/// by reference. Contains everything a handler needs: env snapshot, derived
/// paths, tool detection, and identity info.
///
/// No thread-local storage — explicit parameter passing everywhere.
#[derive(Debug, Clone)]
pub struct HcomContext {
    // === Identity ===
    /// HCOM_PROCESS_ID — identifies launched instances.
    pub process_id: Option<String>,
    /// HCOM_LAUNCHED=1 — true if launched by hcom.
    pub is_launched: bool,
    /// HCOM_PTY_MODE=1 — running in PTY wrapper.
    pub is_pty_mode: bool,
    /// HCOM_BACKGROUND is set — background/headless mode.
    pub is_background: bool,
    /// Log filename for background mode (from HCOM_BACKGROUND).
    pub background_name: Option<String>,

    // === Paths ===
    /// Path to hcom data directory (~/.hcom or HCOM_DIR).
    pub hcom_dir: PathBuf,
    /// True if HCOM_DIR was explicitly set.
    pub hcom_dir_override: bool,
    /// Current working directory when context was captured.
    pub cwd: PathBuf,

    // === Tool detection ===
    /// Detected tool type.
    pub tool: Tool,
    /// CLAUDE_ENV_FILE path (for session ID extraction).
    pub claude_env_file: Option<String>,
    /// HCOM_IS_FORK=1 (--fork-session launch).
    pub is_fork: bool,
    /// Codex thread ID (session equivalent).
    pub codex_thread_id: Option<String>,

    // === Launch context ===
    /// HCOM_LAUNCHED_BY — name of instance that launched this one.
    pub launched_by: Option<String>,
    /// HCOM_LAUNCH_BATCH_ID — batch identifier for grouped launches.
    pub launch_batch_id: Option<String>,
    /// HCOM_LAUNCH_EVENT_ID — event ID for this launch.
    pub launch_event_id: Option<String>,
    /// HCOM_LAUNCHED_PRESET — terminal preset used to launch.
    pub launched_preset: Option<String>,
    /// HCOM_NOTES — per-instance bootstrap user notes.
    pub notes: String,

    // === I/O ===
    /// Whether client stdin is a TTY.
    pub stdin_is_tty: bool,
    /// Whether client stdout is a TTY.
    pub stdout_is_tty: bool,

    // === Raw env ===
    /// Full forwarded env dict — used by config loading for env overrides.
    pub raw_env: HashMap<String, String>,
}

impl HcomContext {
    /// Build context from an explicit environment map.
    ///
    /// Primary constructor — used by both CLI (from os env) and future
    /// direct-call paths. TTY flags default to true for normal CLI usage;
    /// callers with non-TTY stdin/stdout should use `with_tty()` after construction.
    pub fn from_env(env: &HashMap<String, String>, cwd: PathBuf) -> Self {
        let get = |key: &str| env.get(key).cloned();
        let get_nonempty = |key: &str| get(key).filter(|v| !v.is_empty());
        let is_eq = |key: &str, val: &str| env.get(key).is_some_and(|v| v == val);

        let tool = crate::shared::tool_detection::detect_tool(env);

        // Resolve hcom_dir using the same normalization as Config/paths.
        let (hcom_dir, hcom_dir_override) = crate::paths::resolve_hcom_dir_from_env(env, &cwd);

        Self {
            process_id: get_nonempty("HCOM_PROCESS_ID"),
            is_launched: is_eq("HCOM_LAUNCHED", "1"),
            is_pty_mode: is_eq("HCOM_PTY_MODE", "1"),
            is_background: get_nonempty("HCOM_BACKGROUND").is_some(),
            background_name: get_nonempty("HCOM_BACKGROUND"),
            hcom_dir,
            hcom_dir_override,
            cwd,
            tool,
            claude_env_file: get_nonempty("CLAUDE_ENV_FILE"),
            is_fork: is_eq("HCOM_IS_FORK", "1"),
            codex_thread_id: get_nonempty("CODEX_THREAD_ID"),
            launched_by: get_nonempty("HCOM_LAUNCHED_BY"),
            launch_batch_id: get_nonempty("HCOM_LAUNCH_BATCH_ID"),
            launch_event_id: get_nonempty("HCOM_LAUNCH_EVENT_ID"),
            launched_preset: get_nonempty("HCOM_LAUNCHED_PRESET"),
            notes: get("HCOM_NOTES").unwrap_or_default(),
            stdin_is_tty: true,
            stdout_is_tty: true,
            raw_env: env.clone(),
        }
    }

    /// Build context from the current process environment.
    ///
    /// Convenience for CLI mode — detects actual stdin/stdout TTY state.
    pub fn from_os() -> Self {
        use std::io::IsTerminal;
        let env: HashMap<String, String> = env::vars().collect();
        let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut ctx = Self::from_env(&env, cwd);
        ctx.stdin_is_tty = std::io::stdin().is_terminal();
        ctx.stdout_is_tty = std::io::stdout().is_terminal();
        ctx
    }

    /// Set TTY state (for callers that know the client's TTY status).
    pub fn with_tty(mut self, stdin_is_tty: bool, stdout_is_tty: bool) -> Self {
        self.stdin_is_tty = stdin_is_tty;
        self.stdout_is_tty = stdout_is_tty;
        self
    }

    /// Drop a process id this hook cannot prove, together with the derived
    /// `is_launched` claim. OMP hooks require a proven launcher UUID or an
    /// OMP-minted ancestor id; other tools retain synthetic-id carriage.
    /// Idempotent — a cleared id is never re-refused.
    ///
    /// `HCOM_LAUNCHED=1` alone proves nothing. For OMP, only a trusted
    /// launcher UUID backed by a recorded ancestor pid establishes a launch;
    /// a proven OMP-minted id belongs to a plain or nested session. Other
    /// tools keep their existing synthetic-id carriage and launch claims.
    pub fn trust_process_id(&mut self, db: &HcomDb) {
        let _ = self.trust_process_id_inner(db);
    }

    /// `trust_process_id` reporting whether this call emitted the
    /// `identity.foreign_refused` log line.
    fn trust_process_id_inner(&mut self, db: &HcomDb) -> bool {
        let Some(id) = self.process_id.clone() else {
            self.is_launched = false;
            return false;
        };
        let trusted = if self.tool == Tool::Omp {
            crate::proctruth::trusted_process_id_for_omp(db, &id)
        } else {
            crate::proctruth::trusted_process_id(db, &id)
        };
        let mut logged = false;
        if !trusted {
            self.process_id = None;
            logged = Self::log_foreign_refused(db, &id, self.tool.as_str());
        }
        self.is_launched = self.is_launched
            && trusted
            && if self.tool == Tool::Omp {
                crate::proctruth::is_launcher_process_id(&id)
            } else {
                crate::proctruth::omp_minted_pid(&id).is_none()
            };
        logged
    }

    /// Throttled `identity.foreign_refused` line: one per process id per
    /// [`FOREIGN_REFUSED_LOG_INTERVAL`], safe across concurrent hook
    /// processes. Returns whether the line was written.
    fn log_foreign_refused(db: &HcomDb, id: &str, tool: &str) -> bool {
        if !Self::foreign_refused_claim(db, id) {
            return false;
        }
        let written = crate::log::log_checked(
            "INFO",
            "hooks",
            "identity.foreign_refused",
            &format!("tool={tool} refused process id {id}"),
        );
        if !written {
            // The line never reached the file: release the claim so the
            // next refusal can log instead of burning this interval's only
            // line on a lost write. A failed release leaves the claim in
            // place — the interval then suppresses one line, the cost of
            // a log filesystem that stayed broken.
            let _ = db.conn().execute(
                "DELETE FROM kv WHERE key = ?1",
                rusqlite::params![Self::foreign_refused_key(id)],
            );
        }
        written
    }

    /// Atomically claim the `identity.foreign_refused` line for this id:
    /// true exactly once per interval, with the loser of a concurrent claim
    /// seeing false. The single UPSERT is the linearization point — the
    /// stamp never moves backwards (an older `now` cannot overwrite a newer
    /// stamp) and two hook processes claiming together cannot both win.
    /// Any SQL failure fails OPEN (claims and logs anyway): unreadable or
    /// malformed state cannot justify suppression.
    fn foreign_refused_claim(db: &HcomDb, id: &str) -> bool {
        let key = Self::foreign_refused_key(id);
        let now = crate::shared::time::now_epoch_f64();
        let claimed = db.conn().execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value
             WHERE CAST(kv.value AS REAL) IS NULL
                OR CAST(kv.value AS REAL) <= ?2 - ?3",
            rusqlite::params![key, now, FOREIGN_REFUSED_LOG_INTERVAL],
        );
        match claimed {
            Ok(1) => {
                // Winning claim: prune other ids' expired stamps so a parade
                // of novel ids cannot grow kv without bound. Best-effort —
                // a failed prune only delays cleanup.
                let _ = db.conn().execute(
                    "DELETE FROM kv
                     WHERE key LIKE 'identity_foreign_refused_last:%' ESCAPE '\\'
                        AND CAST(value AS REAL) < ?1 - ?2",
                    rusqlite::params![now, FOREIGN_REFUSED_LOG_INTERVAL],
                );
                true
            }
            Ok(_) => false,
            // Unreadable throttle state must not suppress the line.
            Err(_) => true,
        }
    }

    fn foreign_refused_key(id: &str) -> String {
        format!("identity_foreign_refused_last:{id}")
    }

    // === Derived paths ===

    /// Path to hcom.db.
    pub fn db_path(&self) -> PathBuf {
        self.hcom_dir.join("hcom.db")
    }

    /// Path to logs directory.
    pub fn log_dir(&self) -> PathBuf {
        self.hcom_dir.join(".tmp").join("logs")
    }

    /// Path to hcom.log.
    pub fn log_path(&self) -> PathBuf {
        self.log_dir().join("hcom.log")
    }

    /// Whether running inside any AI tool.
    pub fn is_inside_ai_tool(&self) -> bool {
        self.tool != Tool::Adhoc || self.is_launched
    }

    /// Detect current tool name, or "adhoc".
    pub fn detect_current_tool(&self) -> &'static str {
        self.tool.as_str()
    }

    /// Detect vanilla (non-hcom-launched) tool, or None.
    pub fn detect_vanilla_tool(&self) -> Option<&'static str> {
        if self.is_launched {
            return None;
        }
        match self.tool {
            Tool::Adhoc => None,
            _ => Some(self.tool.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    use serial_test::serial;

    fn make_env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_from_env_claude() {
        let env = make_env(&[("CLAUDECODE", "1"), ("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.tool, Tool::Claude);
        assert_eq!(ctx.cwd, PathBuf::from("/tmp"));
    }

    #[test]
    fn test_from_env_antigravity() {
        let env = make_env(&[("ANTIGRAVITY_AGENT", "1"), ("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.tool, Tool::Antigravity);
    }

    #[test]
    fn test_antigravity_priority_over_gemini() {
        let env = make_env(&[
            ("ANTIGRAVITY_AGENT", "1"),
            ("GEMINI_CLI", "1"),
            ("HOME", "/home/test"),
        ]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.tool, Tool::Antigravity);
    }

    #[test]
    fn test_from_env_gemini() {
        let env = make_env(&[("GEMINI_CLI", "1"), ("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.tool, Tool::Gemini);
    }

    #[test]
    fn test_from_env_codex() {
        let env = make_env(&[("CODEX_SANDBOX", "1"), ("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.tool, Tool::Codex);
    }

    #[test]
    fn test_from_env_codex_thread_id() {
        let env = make_env(&[("CODEX_THREAD_ID", "thread-abc"), ("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.codex_thread_id.as_deref(), Some("thread-abc"));
    }

    #[test]
    fn test_from_env_opencode() {
        let env = make_env(&[("OPENCODE", "1"), ("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.tool, Tool::OpenCode);
    }

    #[test]
    fn test_from_env_kilo() {
        let env = make_env(&[("KILO", "1"), ("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.tool, Tool::Kilo);
        assert_eq!(ctx.detect_vanilla_tool(), Some("kilo"));
    }

    #[test]
    fn test_from_env_adhoc() {
        let env = make_env(&[("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.tool, Tool::Adhoc);
    }

    #[test]
    fn test_from_env_claude_env_file() {
        let env = make_env(&[
            ("CLAUDE_ENV_FILE", "/tmp/.claude_env"),
            ("HOME", "/home/test"),
        ]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.tool, Tool::Claude);
        assert_eq!(ctx.claude_env_file.as_deref(), Some("/tmp/.claude_env"));
    }

    #[test]
    fn test_hcom_dir_default() {
        let env = make_env(&[("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.hcom_dir, PathBuf::from("/home/test/.hcom"));
        assert!(!ctx.hcom_dir_override);
    }

    #[test]
    fn test_hcom_dir_override() {
        let env = make_env(&[("HCOM_DIR", "/custom/hcom"), ("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.hcom_dir, PathBuf::from("/custom/hcom"));
        assert!(ctx.hcom_dir_override);
    }

    #[test]
    fn test_hcom_dir_tilde_expansion() {
        let env = make_env(&[("HCOM_DIR", "~/custom/.hcom"), ("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.hcom_dir, PathBuf::from("/home/test/custom/.hcom"));
    }

    #[test]
    fn test_hcom_dir_relative_resolved_to_absolute() {
        let env = make_env(&[("HCOM_DIR", "relative/.hcom"), ("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp/worktree"));

        assert_eq!(ctx.hcom_dir, PathBuf::from("/tmp/worktree/relative/.hcom"));
    }

    #[test]
    fn test_identity_fields() {
        let env = make_env(&[
            ("HCOM_PROCESS_ID", "pid-123"),
            ("HCOM_LAUNCHED", "1"),
            ("HCOM_PTY_MODE", "1"),
            ("HCOM_BACKGROUND", "agent.log"),
            ("HCOM_LAUNCHED_BY", "luna"),
            ("HCOM_LAUNCH_BATCH_ID", "batch-1"),
            ("HCOM_LAUNCH_EVENT_ID", "42"),
            ("HCOM_LAUNCHED_PRESET", "kitty"),
            ("HCOM_IS_FORK", "1"),
            ("HCOM_NOTES", "test notes"),
            ("HOME", "/home/test"),
        ]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.process_id.as_deref(), Some("pid-123"));
        assert!(ctx.is_launched);
        assert!(ctx.is_pty_mode);
        assert!(ctx.is_background);
        assert_eq!(ctx.background_name.as_deref(), Some("agent.log"));
        assert_eq!(ctx.launched_by.as_deref(), Some("luna"));
        assert_eq!(ctx.launch_batch_id.as_deref(), Some("batch-1"));
        assert_eq!(ctx.launch_event_id.as_deref(), Some("42"));
        assert_eq!(ctx.launched_preset.as_deref(), Some("kitty"));
        assert!(ctx.is_fork);
        assert_eq!(ctx.notes, "test notes");
    }

    #[test]
    fn test_empty_values_become_none() {
        let env = make_env(&[
            ("HCOM_PROCESS_ID", ""),
            ("HCOM_LAUNCHED", "0"),
            ("HCOM_BACKGROUND", ""),
            ("HOME", "/home/test"),
        ]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert!(ctx.process_id.is_none());
        assert!(!ctx.is_launched);
        assert!(!ctx.is_background);
        assert!(ctx.background_name.is_none());
    }

    #[test]
    fn test_derived_paths() {
        let env = make_env(&[("HOME", "/home/test")]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.db_path(), PathBuf::from("/home/test/.hcom/hcom.db"));
        assert_eq!(ctx.log_dir(), PathBuf::from("/home/test/.hcom/.tmp/logs"));
        assert_eq!(
            ctx.log_path(),
            PathBuf::from("/home/test/.hcom/.tmp/logs/hcom.log")
        );
    }

    #[test]
    fn test_is_inside_ai_tool() {
        let adhoc =
            HcomContext::from_env(&make_env(&[("HOME", "/home/test")]), PathBuf::from("/tmp"));
        assert!(!adhoc.is_inside_ai_tool());

        let claude = HcomContext::from_env(
            &make_env(&[("CLAUDECODE", "1"), ("HOME", "/home/test")]),
            PathBuf::from("/tmp"),
        );
        assert!(claude.is_inside_ai_tool());

        let launched = HcomContext::from_env(
            &make_env(&[("HCOM_LAUNCHED", "1"), ("HOME", "/home/test")]),
            PathBuf::from("/tmp"),
        );
        assert!(launched.is_inside_ai_tool());
    }

    #[test]
    fn test_detect_vanilla_tool() {
        // Claude not launched by hcom = vanilla
        let ctx = HcomContext::from_env(
            &make_env(&[("CLAUDECODE", "1"), ("HOME", "/home/test")]),
            PathBuf::from("/tmp"),
        );
        assert_eq!(ctx.detect_vanilla_tool(), Some("claude"));

        // Claude launched by hcom = not vanilla
        let ctx = HcomContext::from_env(
            &make_env(&[
                ("CLAUDECODE", "1"),
                ("HCOM_LAUNCHED", "1"),
                ("HOME", "/home/test"),
            ]),
            PathBuf::from("/tmp"),
        );
        assert_eq!(ctx.detect_vanilla_tool(), None);

        // Adhoc = not vanilla
        let ctx =
            HcomContext::from_env(&make_env(&[("HOME", "/home/test")]), PathBuf::from("/tmp"));
        assert_eq!(ctx.detect_vanilla_tool(), None);
    }

    #[test]
    fn test_tool_type_display() {
        assert_eq!(Tool::Claude.as_str(), "claude");
        assert_eq!(Tool::Gemini.as_str(), "gemini");
        assert_eq!(Tool::Codex.as_str(), "codex");
        assert_eq!(Tool::OpenCode.as_str(), "opencode");
        assert_eq!(Tool::Kilo.as_str(), "kilo");
        assert_eq!(Tool::Adhoc.as_str(), "adhoc");
    }

    #[test]
    fn test_tool_priority_claude_over_codex() {
        // If both CLAUDECODE and CODEX_SANDBOX are set, claude wins
        let env = make_env(&[
            ("CLAUDECODE", "1"),
            ("CODEX_SANDBOX", "1"),
            ("HOME", "/home/test"),
        ]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));
        assert_eq!(ctx.tool, Tool::Claude);
    }

    #[test]
    fn test_raw_env_preserved() {
        let env = make_env(&[
            ("HOME", "/home/test"),
            ("HCOM_TAG", "test-tag"),
            ("CUSTOM_VAR", "custom-val"),
        ]);
        let ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));

        assert_eq!(ctx.raw_env.get("HCOM_TAG").unwrap(), "test-tag");
        assert_eq!(ctx.raw_env.get("CUSTOM_VAR").unwrap(), "custom-val");
    }

    // === trust_process_id (§1.1) ===

    fn make_test_db() -> (HcomDb, tempfile::TempDir) {
        crate::config::Config::init();
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();
        (db, dir)
    }

    /// Context claiming a launch the way a real one arrives: `HCOM_LAUNCHED=1`
    /// together with a process id.
    fn launched_ctx(process_id: &str) -> HcomContext {
        HcomContext::from_env(
            &make_env(&[("HCOM_PROCESS_ID", process_id), ("HCOM_LAUNCHED", "1")]),
            PathBuf::from("/tmp"),
        )
    }

    #[test]
    fn trust_process_id_refuses_unproven_id() {
        let (db, _dir) = make_test_db();
        // Launcher UUID with no binding row: provenance unprovable.
        let mut ctx = launched_ctx("550e8400-e29b-41d4-a716-446655440000");
        assert!(ctx.is_launched);
        ctx.trust_process_id(&db);
        assert_eq!(ctx.process_id, None);
        assert!(!ctx.is_launched);

        // Idempotent: nothing left to refuse.
        ctx.trust_process_id(&db);
        assert_eq!(ctx.process_id, None);
        assert!(!ctx.is_launched);
    }

    #[test]
    fn trust_process_id_clears_launch_claim_without_id() {
        let (db, _dir) = make_test_db();
        // §1.1: a bare inherited HCOM_LAUNCHED=1 never makes a plain session join.
        let env = make_env(&[("HCOM_LAUNCHED", "1"), ("HOME", "/home/test")]);
        let mut ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));
        assert!(ctx.is_launched);
        ctx.trust_process_id(&db);
        assert_eq!(ctx.process_id, None);
        assert!(!ctx.is_launched);
    }

    #[test]
    fn trust_process_id_keeps_trusted_launcher_id() {
        let (db, _dir) = make_test_db();
        let id = "550e8400-e29b-41d4-a716-446655440001";
        // Binding row whose instance records OUR pid — self is always in the
        // self-inclusive ancestor set, so this is a provable launcher id.
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, pid) \
                 VALUES ('luna', 'active', ?1, 'claude', ?2)",
                rusqlite::params![
                    chrono::Utc::now().timestamp() as f64,
                    std::process::id() as i64
                ],
            )
            .unwrap();
        db.set_process_binding(id, "", "luna").unwrap();

        let mut ctx = launched_ctx(id);
        ctx.trust_process_id(&db);
        assert_eq!(ctx.process_id.as_deref(), Some(id));
        assert!(ctx.is_launched);

        // §1.1 keeps the env conjunct: a trusted id alone is not a launch.
        let env = make_env(&[("HCOM_PROCESS_ID", id), ("HOME", "/home/test")]);
        let mut ctx = HcomContext::from_env(&env, PathBuf::from("/tmp"));
        ctx.trust_process_id(&db);
        assert_eq!(ctx.process_id.as_deref(), Some(id));
        assert!(!ctx.is_launched);
    }

    /// RAII guard over `/proc/self/comm`: renames this process for the
    /// duration of a test and restores the original name on drop (panic-safe),
    /// so the `comm == "omp"` ancestry clause can be exercised in-process.
    #[cfg(target_os = "linux")]
    struct CommGuard(String);

    #[cfg(target_os = "linux")]
    impl CommGuard {
        fn set(name: &str) -> Self {
            let path = format!("/proc/{}/comm", std::process::id());
            let original = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, name).unwrap();
            CommGuard(original)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for CommGuard {
        fn drop(&mut self) {
            let path = format!("/proc/{}/comm", std::process::id());
            let _ = std::fs::write(&path, &self.0);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn trust_process_id_omp_shaped_never_proves_launch() {
        let (db, _dir) = make_test_db();
        // D-69 shape: minted from our own pid, so the minting pid IS in the
        // self-inclusive ancestor set — but nothing here runs `omp`.
        let id = format!("omp-{}-11-22", std::process::id());

        {
            let _comm = CommGuard::set("shell");
            let mut ctx = launched_ctx(&id);
            ctx.trust_process_id(&db);
            // Unproven: refused outright (the lotso leak shape).
            assert_eq!(ctx.process_id, None);
            assert!(!ctx.is_launched);
        }

        {
            // A genuine plugin mint: the minting ancestor runs `omp`, so the
            // id IS trusted and is kept as this tree's identity — but an
            // omp-shaped id must never prove a launch (§1.1 shape clause):
            // the leaked HCOM_LAUNCHED=1 would otherwise let a plain session join.
            let _comm = CommGuard::set("omp");
            let mut ctx = launched_ctx(&id);
            ctx.trust_process_id(&db);
            assert_eq!(ctx.process_id.as_deref(), Some(id.as_str()));
            assert!(!ctx.is_launched);
        }
    }

    // === identity.foreign_refused log throttle ===

    /// Count `identity.foreign_refused` log lines naming this id.
    fn foreign_refused_log_lines(id: &str) -> usize {
        std::fs::read_to_string(crate::paths::log_path())
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains("identity.foreign_refused") && line.contains(id))
            .count()
    }

    /// One hook process: a fresh context and a fresh db handle onto the same
    /// store — hooks are separate short-lived hcom processes, so the throttle
    /// state must persist across this boundary.
    fn refuse_as_hook_process(db_path: &std::path::Path, id: &str) {
        let db = HcomDb::open_raw(db_path).unwrap();
        let mut ctx = launched_ctx(id);
        ctx.trust_process_id(&db);
        assert_eq!(ctx.process_id, None, "the refusal verdict is unchanged");
        assert!(!ctx.is_launched);
    }

    #[test]
    #[serial]
    fn foreign_refused_logs_each_id_once_per_interval() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let (db, db_dir) = make_test_db();
        let db_path = db_dir.path().join("test.db");
        drop(db);
        let id = "550e8400-e29b-41d4-a716-4466554400aa";

        refuse_as_hook_process(&db_path, id);
        refuse_as_hook_process(&db_path, id);

        assert_eq!(
            foreign_refused_log_lines(id),
            1,
            "two refusals of the same id within the interval must log one line"
        );
    }

    #[test]
    #[serial]
    fn foreign_refused_throttle_is_per_id() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let (db, db_dir) = make_test_db();
        let db_path = db_dir.path().join("test.db");
        drop(db);
        let id_a = "550e8400-e29b-41d4-a716-4466554400bb";
        let id_b = "550e8400-e29b-41d4-a716-4466554400cc";

        refuse_as_hook_process(&db_path, id_a);
        refuse_as_hook_process(&db_path, id_b);

        assert_eq!(
            foreign_refused_log_lines(id_a),
            1,
            "a refusal of a different id logs its own line"
        );
        assert_eq!(
            foreign_refused_log_lines(id_b),
            1,
            "a refusal of a different id logs its own line"
        );
    }

    #[test]
    #[serial]
    fn foreign_refused_logs_again_after_interval() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let (db, db_dir) = make_test_db();
        drop(db);
        let db_path = db_dir.path().join("test.db");
        let id = "550e8400-e29b-41d4-a716-4466554400dd";

        refuse_as_hook_process(&db_path, id);
        assert_eq!(foreign_refused_log_lines(id), 1);

        // Inject the clock: backdate the persisted last-logged stamp past the
        // interval, as if the earlier refusal had happened 10 minutes ago.
        let db = HcomDb::open_raw(&db_path).unwrap();
        let key = format!("identity_foreign_refused_last:{id}");
        let backdated = crate::shared::time::now_epoch_f64() - (FOREIGN_REFUSED_LOG_INTERVAL + 1.0);
        db.kv_set(&key, Some(&backdated.to_string())).unwrap();
        drop(db);

        refuse_as_hook_process(&db_path, id);
        assert_eq!(
            foreign_refused_log_lines(id),
            2,
            "after the interval the refusal logs again"
        );
    }

    #[test]
    #[serial]
    fn foreign_refused_throttle_fails_open_on_unreadable_state() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let (db, db_dir) = make_test_db();
        let db_path = db_dir.path().join("test.db");
        let id = "550e8400-e29b-41d4-a716-4466554400ee";

        // Corrupt the persisted stamp so the throttle cannot read it; the
        // refusal must still log (fail OPEN, never suppress silently).
        let key = format!("identity_foreign_refused_last:{id}");
        db.kv_set(&key, Some("not-a-timestamp")).unwrap();
        drop(db);

        refuse_as_hook_process(&db_path, id);
        assert_eq!(
            foreign_refused_log_lines(id),
            1,
            "unreadable throttle state must not suppress the refusal line"
        );
    }

    #[test]
    #[serial]
    fn foreign_refused_race_two_hook_processes_one_log_line() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let (db, db_dir) = make_test_db();
        drop(db);
        let db_path = db_dir.path().join("test.db");
        let id = "550e8400-e29b-41d4-a716-4466554400ff";
        let both_gated = std::sync::Arc::new(std::sync::Barrier::new(3));
        let winner_logged = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut joins = Vec::new();
        for _ in 0..2 {
            let db_path = db_path.clone();
            let both_gated = both_gated.clone();
            let winner_logged = winner_logged.clone();
            let id = id.to_string();
            joins.push(std::thread::spawn(move || {
                let db = HcomDb::open_raw(&db_path).unwrap();
                let mut ctx = launched_ctx(&id);
                // Deterministic interleaving: both hook processes hold at
                // this gate, then claim-and-log together.
                both_gated.wait();
                if ctx.trust_process_id_inner(&db) {
                    winner_logged.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        // Main thread joins the gate so both hooks claim together.
        both_gated.wait();
        for j in joins {
            j.join().unwrap();
        }

        assert_eq!(winner_logged.load(Ordering::SeqCst), 1);
        assert_eq!(foreign_refused_log_lines(id), 1);
    }

    #[test]
    #[serial]
    fn foreign_refused_prunes_expired_stamps_on_claim() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let (db, db_dir) = make_test_db();
        let db_path = db_dir.path().join("test.db");
        let id = "550e8400-e29b-41d4-a716-446655440044";
        let expired_key = format!("identity_foreign_refused_last:{id}");
        let expired_ts =
            crate::shared::time::now_epoch_f64() - (FOREIGN_REFUSED_LOG_INTERVAL * 2.0);
        db.kv_set(&expired_key, Some(&expired_ts.to_string()))
            .unwrap();
        drop(db);

        // A winning claim for a fresh id must prune the expired stamp.
        let new_id = "550e8400-e29b-41d4-a716-446655440055";
        refuse_as_hook_process(&db_path, new_id);
        assert_eq!(foreign_refused_log_lines(new_id), 1);

        let db = HcomDb::open_raw(&db_path).unwrap();
        assert_eq!(
            db.kv_get(&expired_key).unwrap(),
            None,
            "an expired stamp for another id must be pruned after a winning claim"
        );
    }

    #[test]
    #[serial]
    fn foreign_refused_stamp_is_monotonic() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let (db, db_dir) = make_test_db();
        drop(db);
        let db_path = db_dir.path().join("test.db");
        let id = "550e8400-e29b-41d4-a716-446655440066";

        // A refusal stamps now. A second claim whose clock reads older
        // (skewed hook process) must not move the stamp backwards.
        refuse_as_hook_process(&db_path, id);
        let key = format!("identity_foreign_refused_last:{id}");
        let db = HcomDb::open_raw(&db_path).unwrap();
        let newer = db.kv_get(&key).unwrap().unwrap();
        let newer: f64 = newer.parse().unwrap();
        drop(db);

        // Inject the skew: backdate so the WHERE clause would let an
        // older claimant overwrite, then prove it cannot win against the
        // newer stamp — the stamp stays at `newer`.
        let skewed_older = newer - (FOREIGN_REFUSED_LOG_INTERVAL + 1.0);
        let db = HcomDb::open_raw(&db_path).unwrap();
        let changed = db.conn().execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value
             WHERE CAST(kv.value AS REAL) IS NULL
                OR CAST(kv.value AS REAL) <= ?2 - ?3",
            rusqlite::params![key, skewed_older, FOREIGN_REFUSED_LOG_INTERVAL],
        );
        drop(db);

        // Either the skewed claim lost outright (0 changes), or it must
        // not have lowered the stamp. The stored stamp never regresses.
        let db = HcomDb::open_raw(&db_path).unwrap();
        let stored: f64 = db.kv_get(&key).unwrap().unwrap().parse().unwrap();
        match changed {
            Ok(n) => assert_eq!(n, 0, "an older claim must not touch a newer stamp"),
            Err(e) => panic!("claim failed: {e}"),
        }
        assert!(
            stored >= newer,
            "the stored stamp ({stored}) must never move backwards from {newer}"
        );
    }

    #[test]
    #[serial]
    fn foreign_refused_failed_log_write_releases_claim() {
        let (_dir, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let (db, db_dir) = make_test_db();
        drop(db);
        let db_path = db_dir.path().join("test.db");
        let id = "550e8400-e29b-41d4-a716-446655440077";

        // Break the log destination so the log write must fail: replace
        // the log file with a directory, so open(append) fails.
        let log_path = hcom_dir.join(".tmp").join("logs").join("hcom.log");
        std::fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&log_path).unwrap();

        refuse_as_hook_process(&db_path, id);

        // The claim must have been released: no stamp survives a failed
        // log write, so the next refusal can log again.
        let key = format!("identity_foreign_refused_last:{id}");
        let db = HcomDb::open_raw(&db_path).unwrap();
        assert_eq!(
            db.kv_get(&key).unwrap(),
            None,
            "a failed log write must release the claim"
        );

        // Repair the log destination; the next refusal logs again.
        std::fs::remove_dir(&log_path).unwrap();
        refuse_as_hook_process(&db_path, id);
        assert_eq!(
            foreign_refused_log_lines(id),
            1,
            "after a released claim the next refusal logs"
        );
    }
}
