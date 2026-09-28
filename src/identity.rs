//! Identity resolution — 3-tier binding (process → session → ad-hoc).

use regex::Regex;
use std::sync::LazyLock;

use crate::db::{HcomDb, InstanceRow};
use crate::shared::{HcomError, SenderIdentity, SenderKind};

/// UUID pattern for agent_id detection.
static UUID_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
});

/// Valid base instance name: lowercase letters, digits, underscore.
static BASE_NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9_]+$").unwrap());

/// Dangerous characters for user-provided names (injection prevention).
static DANGEROUS_CHARS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[|&;$`<>]").unwrap());

/// Dangerous characters including @ (for --from validation).
static DANGEROUS_CHARS_WITH_AT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[|&;$`<>@]").unwrap());

/// Commands that require a resolved identity to operate.
const REQUIRE_IDENTITY: &[&str] = &["send", "listen"];

/// Check if value looks like a UUID (agent_id format).
pub fn looks_like_uuid(value: &str) -> bool {
    UUID_PATTERN.is_match(value)
}

/// Check if name looks like a Claude Task agent_id (7-char hex).
pub fn looks_like_agent_id(name: &str) -> bool {
    name.len() == 7 && name.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check if name is a valid base instance name (lowercase letters, digits, underscore).
pub fn is_valid_base_name(name: &str) -> bool {
    BASE_NAME_RE.is_match(name)
}

/// Build error message for invalid base instance names.
pub fn base_name_error(name: &str) -> String {
    format!(
        "Invalid instance name '{name}'. Use base name only (lowercase letters, numbers, underscore)."
    )
}

/// Whether `name` ever existed as an identity: any `life` event names it.
pub fn has_life_history(db: &HcomDb, name: &str) -> bool {
    db.conn()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE type = 'life' AND instance = ?)",
            [name],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false)
}

/// Actionable error message for an instance that is not found.
///
/// Prescribes `hcom start --as <name>` only for a name that existed (has life
/// history) and was a top-level identity. A subagent slot, raw agent_id or
/// UUID gets "session may have ended": subagents share their parent's
/// session_id, so `--as <subagent_name>` from a subagent bash rebinds the
/// parent's identity. A never-seen name gets the external-sender form: `--as`
/// from a process holding another identity would rename that identity away.
pub fn instance_not_found_error_for(db: &HcomDb, name: &str) -> String {
    if looks_like_agent_id(name) || looks_like_uuid(name) || db.was_subagent_name(name) {
        return format!(
            "Instance '{name}' not found. Your session may have ended. Stop working and end your turn."
        );
    }
    if !has_life_history(db, name) {
        return format!(
            "Instance '{name}' not found; it has never been an hcom identity. If '{name}' is an external sender (cron/script/manual alert), use 'hcom send --from {name} ...'."
        );
    }
    format!("Instance '{name}' not found. Run 'hcom start --as {name}' to reclaim your identity.")
}

/// Validate user-provided name input for length and dangerous characters.
///
/// Used for `--name` and `--from` flag validation in CLI commands.
pub fn validate_name_input(name: &str, max_length: usize, allow_at: bool) -> Result<(), String> {
    if name.len() > max_length {
        return Err(format!(
            "Name too long ({} chars, max {max_length})",
            name.len()
        ));
    }

    let pattern = if allow_at {
        &*DANGEROUS_CHARS
    } else {
        &*DANGEROUS_CHARS_WITH_AT
    };

    let bad_chars: Vec<&str> = pattern.find_iter(name).map(|m| m.as_str()).collect();
    if !bad_chars.is_empty() {
        let unique: std::collections::HashSet<&str> = bad_chars.into_iter().collect();
        let chars_str: Vec<&str> = unique.into_iter().collect();
        return Err(format!(
            "Name contains invalid characters: {}",
            chars_str.join(" ")
        ));
    }

    Ok(())
}

/// Get full display name: "{tag}-{name}" if tag exists, else just "{name}".
pub fn get_full_name(data: &InstanceRow) -> String {
    match &data.tag {
        Some(tag) if !tag.is_empty() => format!("{}-{}", tag, data.name),
        _ => data.name.clone(),
    }
}

/// Get display name for a base name by loading instance data.
pub fn get_display_name(db: &HcomDb, base_name: &str) -> String {
    match db.get_instance_full(base_name) {
        Ok(Some(data)) => get_full_name(&data),
        _ => base_name.to_string(),
    }
}

/// Resolve base name or tag-name (e.g., "team-luna") to base name.
/// Handles multi-hyphen tags like "vc-p0-p1-parallel-vani" -> tag="vc-p0-p1-parallel", name="vani".
pub fn resolve_display_name(db: &HcomDb, input_name: &str) -> Option<String> {
    if let Ok(Some(_)) = db.get_instance_full(input_name) {
        return Some(input_name.to_string());
    }

    for (i, _) in input_name.match_indices('-') {
        let tag = &input_name[..i];
        let name = &input_name[i + 1..];
        if name.is_empty() {
            continue;
        }
        if let Ok(Some(data)) = db.get_instance_full(name)
            && data.tag.as_deref() == Some(tag)
        {
            return Some(name.to_string());
        }
    }
    None
}

/// Resolve base name or tag-name using live instances first, then stopped snapshots.
pub fn resolve_display_name_or_stopped(db: &HcomDb, input_name: &str) -> Option<String> {
    if let Some(name) = resolve_display_name(db, input_name) {
        return Some(name);
    }

    if db
        .conn()
        .query_row(
            "SELECT instance FROM events
             WHERE type = 'life'
               AND instance = ?1
               AND json_extract(data, '$.action') = 'stopped'
             LIMIT 1",
            rusqlite::params![input_name],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .is_some()
    {
        return Some(input_name.to_string());
    }

    for (i, _) in input_name.match_indices('-') {
        let tag = &input_name[..i];
        let name = &input_name[i + 1..];
        if name.is_empty() {
            continue;
        }
        if db
            .conn()
            .query_row(
                "SELECT instance FROM events
                 WHERE type = 'life'
                   AND instance = ?1
                   AND json_extract(data, '$.action') = 'stopped'
                   AND json_extract(data, '$.snapshot.tag') = ?2
                 LIMIT 1",
                rusqlite::params![name, tag],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .is_some()
        {
            return Some(name.to_string());
        }
    }

    None
}

/// Fleet resolution of a bare input for a CLI command.
///
/// * [`CliResolve::Hit`] — the one live matching candidate fleet-wide:
///   a local base or tagged display-name match, or a live mirror `x:DEV`.
/// * [`CliResolve::Refused`] — more than one candidate, or only suffix-only
///   candidates; the message names every addressable form.
/// * [`CliResolve::Miss`] — live nowhere: the caller's local fallback stands.
#[derive(Clone, Debug, PartialEq)]
pub enum CliResolve {
    Hit(String),
    Refused(String),
    Miss,
}

/// The shared resolver every named CLI command uses. A local match by base
/// name or tagged display name and a remote match are equally eligible;
/// neither silently overrides the other.
///
/// An empty or already device-qualified input is `Miss`, preserving every
/// explicit `:DEVICE` flow. Otherwise resolve the live fleet.
pub fn fleet_first(db: &HcomDb, input: &str) -> CliResolve {
    if input.is_empty() || input.contains(':') {
        return CliResolve::Miss;
    }
    let ctx = crate::fleet_names::FleetCtx::load();
    let candidates = crate::fleet_names::live_candidates(db, input, &ctx);
    match crate::fleet_names::resolve_bare_name(input, &candidates) {
        crate::fleet_names::BareOutcome::Single(exact) => CliResolve::Hit(exact),
        crate::fleet_names::BareOutcome::Refuse(msg) => CliResolve::Refused(msg),
        crate::fleet_names::BareOutcome::NoCandidate => CliResolve::Miss,
    }
}

/// The name a command should act on when its local lookup is the plain
/// instance-name (or tag-name) one: fleet-first, and on a `Miss` today's
/// local lookup verbatim. `Err` is the fleet refusal message.
pub fn cli_target(db: &HcomDb, target: &str) -> Result<String, String> {
    match fleet_first(db, target) {
        CliResolve::Hit(name) => Ok(name),
        CliResolve::Refused(msg) => Err(msg),
        CliResolve::Miss => {
            Ok(resolve_display_name(db, target).unwrap_or_else(|| target.to_string()))
        }
    }
}

/// SQL LIKE pattern for a literal prefix + `:`, with the wildcards in the
/// prefix escaped. Base names may contain `_`, which LIKE would read as
/// "any one character".
fn like_device_prefix(name: &str) -> String {
    let mut pattern = String::with_capacity(name.len() + 6);
    for c in name.chars() {
        if matches!(c, '%' | '_' | '\\') {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push_str(":%");
    pattern
}

/// The exact `X:DEV` forms on other devices where a bare name's history lives:
/// live mirror rows with that base name, plus every `X:DEV` name that appears
/// in the life history. Empty when the name has no history off-host.
pub fn remote_history_forms(db: &HcomDb, name: &str) -> Vec<String> {
    if name.is_empty() || name.contains(':') {
        return Vec::new();
    }
    let pattern = like_device_prefix(name);
    let mut forms: Vec<String> = Vec::new();
    let mut rows = db.conn().prepare(
        "SELECT name FROM instances
         WHERE name LIKE ?1 ESCAPE '\\' AND origin_device_id IS NOT NULL AND origin_device_id != ''
         UNION
         SELECT DISTINCT instance FROM events
         WHERE type = 'life' AND instance LIKE ?1 ESCAPE '\\'",
    );
    let Ok(rows) = rows.as_mut() else {
        return Vec::new();
    };
    if let Ok(found) = rows.query_map([&pattern], |row| row.get::<_, String>(0)) {
        for form in found.flatten() {
            if !forms.contains(&form) {
                forms.push(form);
            }
        }
    }
    forms.sort();
    forms
}

/// Hint for a bare name with no local plan whose history lives on other
/// devices: says where it is and how to reach it. `None` when the name has no
/// off-host history (the caller reports its own not-found error instead).
pub fn remote_history_hint(db: &HcomDb, name: &str) -> Option<String> {
    let forms = remote_history_forms(db, name);
    if forms.is_empty() {
        return None;
    }
    let list = forms.join(", ");
    Some(format!(
        "'{name}' is not an identity on this host. {name}'s history is on {list} — 'hcom r {}' resumes it there, or launch fresh here with 'hcom omp --as {name}'.",
        forms[0]
    ))
}

/// Resolve `--name NAME` with strict instance lookup.
///
/// Resolution order:
/// 1. Instance name lookup (exact) -> kind=Instance if found
/// 2. Agent ID (UUID) lookup -> kind=Instance if found
/// 3. Error if not found
pub fn resolve_from_name(db: &HcomDb, name: &str) -> Result<SenderIdentity, HcomError> {
    let mut resolved_name = name.to_string();

    // Reject invalid base names, but allow tag-name format (e.g. "team-luna")
    if !looks_like_uuid(name) && !is_valid_base_name(name) {
        // Try tag-name resolution before rejecting
        match resolve_display_name(db, name) {
            Some(base) => resolved_name = base,
            None => return Err(HcomError::InvalidInput(base_name_error(name))),
        }
    }

    // 1. Instance name lookup (exact match)
    if let Ok(Some(data)) = db.get_instance(&resolved_name) {
        crate::log::log_info(
            "identity",
            "resolve_from_name",
            &format!("name={}, method=instance_name", resolved_name),
        );
        return Ok(SenderIdentity {
            kind: SenderKind::Instance,
            name: resolved_name,
            session_id: data
                .get("session_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
            instance_data: Some(data),
        });
    }

    // 2. Agent ID lookup (Claude Code sends short IDs like 'a6d9caf')
    if let Ok(Some(instance_name)) = db.get_instance_by_agent_id(&resolved_name)
        && let Ok(Some(data)) = db.get_instance(&instance_name)
    {
        crate::log::log_info(
            "identity",
            "resolve_from_name",
            &format!(
                "name={}, method=agent_id, resolved={}",
                resolved_name, instance_name
            ),
        );
        return Ok(SenderIdentity {
            kind: SenderKind::Instance,
            name: instance_name,
            session_id: data
                .get("session_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
            instance_data: Some(data),
        });
    }

    // 3. Not found
    crate::log::log_info(
        "identity",
        "resolve_from_name.not_found",
        &format!("name={}", resolved_name),
    );
    Err(HcomError::NotFound(instance_not_found_error_for(
        db,
        &resolved_name,
    )))
}

/// Resolve sender identity for CLI commands and hook handlers.
///
/// # Arguments
///
/// * `db` - Database handle
/// * `name` - Instance name from `--name` flag (strict lookup)
/// * `system_sender` - System notification sender name (e.g., 'hcom-launcher')
/// * `session_id` - Explicit session_id (for hook context, bypasses env detection)
/// * `process_id` - HCOM_PROCESS_ID (for launched instances)
/// * `codex_thread_id` - Codex thread ID for opportunistic session binding
/// * `transcript_fallback` - Optional closure for transcript marker resolution
///
/// # Priority
///
/// 1. `system_sender` - system notifications
/// 2. `session_id` - explicit session (internal use)
/// 3. `name` (--name) - strict instance lookup
/// 4. Auto-detect from `process_id` (HCOM_PROCESS_ID)
/// 5. `transcript_fallback` - transcript marker scan (hook extension point)
/// 6. Error if no identity
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn resolve_identity_with_expectation(
    db: &HcomDb,
    name: Option<&str>,
    system_sender: Option<&str>,
    session_id: Option<&str>,
    process_id: Option<&str>,
    codex_thread_id: Option<&str>,
    identity_expected: bool,
    transcript_fallback: Option<&dyn Fn(&HcomDb) -> Option<SenderIdentity>>,
) -> Result<SenderIdentity, HcomError> {
    // 1. System sender (internal use)
    if let Some(sender) = system_sender {
        return Ok(SenderIdentity {
            kind: SenderKind::System,
            name: sender.to_string(),
            instance_data: None,
            session_id: None,
        });
    }

    // 2. Explicit session_id (internal use)
    if let Some(sid) = session_id
        && !sid.is_empty()
    {
        let resolved_name = db
            .get_session_binding(sid)
            .map_err(|e| HcomError::DatabaseError(e.to_string()))?;

        match resolved_name {
            Some(inst_name) => {
                let data = db
                    .get_instance(&inst_name)
                    .map_err(|e| HcomError::DatabaseError(e.to_string()))?;

                match data {
                    Some(d) => {
                        crate::log::log_info(
                            "identity",
                            "resolve",
                            &format!("method=session_id, name={}", inst_name),
                        );
                        return Ok(SenderIdentity {
                            kind: SenderKind::Instance,
                            name: inst_name,
                            session_id: Some(sid.to_string()),
                            instance_data: Some(d),
                        });
                    }
                    None => {
                        return Err(HcomError::NotFound(
                            "Instance not found for session_id".to_string(),
                        ));
                    }
                }
            }
            None => {
                crate::log::log_warn(
                    "identity",
                    "resolve.session_id_not_found",
                    &format!("session_id={}", &sid[..sid.len().min(8)]),
                );
                return Err(HcomError::NotFound(
                    "Instance not found for session_id".to_string(),
                ));
            }
        }
    }

    // 3. Strict instance lookup (--name NAME)
    if let Some(n) = name
        && !n.is_empty()
    {
        return resolve_from_name(db, n);
    }

    // 4. Auto-detect from process binding (hcom-launched instances)
    if let Some(pid) = process_id
        && !pid.is_empty()
    {
        let bound_name = db
            .get_process_binding(pid)
            .map_err(|e| HcomError::DatabaseError(e.to_string()))?;

        match bound_name {
            Some(inst_name) => {
                let data = db
                    .get_instance(&inst_name)
                    .map_err(|e| HcomError::DatabaseError(e.to_string()))?;

                match data {
                    Some(d) => {
                        let has_session = d
                            .get("session_id")
                            .and_then(|v| v.as_str())
                            .is_some_and(|s| !s.is_empty());

                        // Opportunistic Codex session binding for command-time recovery.
                        // Native SessionStart is the primary binding path; this keeps
                        // resume/orphan flows tolerant if a command arrives first.
                        // Uses bind_session_to_process for proper resume/placeholder handling;
                        // a failed bind (logged there) keeps the pre-bound name.
                        let mut final_name = inst_name.clone();
                        if !has_session
                            && let Some(thread_id) = codex_thread_id
                            && !thread_id.is_empty()
                            && let Ok(Some(resolved)) =
                                crate::instance_binding::bind_session_to_process(
                                    db, thread_id, process_id,
                                )
                        {
                            final_name = resolved;
                        }

                        // Re-read instance data — session_id may have been set during binding
                        let final_data = db
                            .get_instance(&final_name)
                            .map_err(|e| HcomError::DatabaseError(e.to_string()))?
                            .unwrap_or(d);

                        let sid = final_data
                            .get("session_id")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string());

                        crate::log::log_info(
                            "identity",
                            "resolve",
                            &format!(
                                "method=process_binding, name={}, process_id={}",
                                final_name, pid
                            ),
                        );
                        return Ok(SenderIdentity {
                            kind: SenderKind::Instance,
                            name: final_name,
                            session_id: sid,
                            instance_data: Some(final_data),
                        });
                    }
                    None => {
                        crate::log::log_warn(
                            "identity",
                            "resolve.process_instance_missing",
                            &format!("process_id={}, bound_name={}", pid, inst_name),
                        );
                        return Err(HcomError::NotFound(instance_not_found_error_for(
                            db, &inst_name,
                        )));
                    }
                }
            }
            None => {
                if identity_expected {
                    crate::log::log_warn(
                        "identity",
                        "resolve.process_binding_expired",
                        &format!("process_id={}", pid),
                    );
                }
                return Err(HcomError::IdentityRequired(
                    "Session expired. Run 'hcom start' to reconnect.".to_string(),
                ));
            }
        }
    }

    // 5. Transcript marker fallback (hook extension point)
    if let Some(fallback) = transcript_fallback
        && let Some(identity) = fallback(db)
    {
        return Ok(identity);
    }

    // 6. No identity
    if identity_expected {
        crate::log::log_warn(
            "identity",
            "resolve.no_identity",
            &format!(
                "has_process_id={}, has_name={}",
                process_id.is_some_and(|s| !s.is_empty()),
                name.is_some_and(|s| !s.is_empty()),
            ),
        );
    }
    Err(HcomError::IdentityRequired(
        "No hcom identity. Run 'hcom start' first, then use --name <yourname> on commands."
            .to_string(),
    ))
}

#[allow(clippy::type_complexity)]
pub fn resolve_identity(
    db: &HcomDb,
    name: Option<&str>,
    system_sender: Option<&str>,
    session_id: Option<&str>,
    process_id: Option<&str>,
    codex_thread_id: Option<&str>,
    transcript_fallback: Option<&dyn Fn(&HcomDb) -> Option<SenderIdentity>>,
) -> Result<SenderIdentity, HcomError> {
    resolve_identity_with_expectation(
        db,
        name,
        system_sender,
        session_id,
        process_id,
        codex_thread_id,
        crate::shared::is_inside_ai_tool(),
        transcript_fallback,
    )
}

/// Check if a command requires identity gating.
pub fn requires_identity(cmd: &str) -> bool {
    REQUIRE_IDENTITY.contains(&cmd)
}

/// Identity gate check for CLI commands.
///
/// Returns `Ok(())` if the identity requirement is satisfied, or `Err` with
/// an actionable error message. The `send` command bypasses the gate when
/// external sender flags (`--from`, `-b`) are present.
pub fn require_identity_gate(
    cmd: &str,
    explicit_name: Option<&str>,
    has_from_flag: bool,
) -> Result<(), HcomError> {
    if !requires_identity(cmd) {
        return Ok(());
    }

    // --name provided: identity will be resolved later
    if explicit_name.is_some() {
        return Ok(());
    }

    // send command: --from or -b bypasses identity requirement
    if cmd == "send" && has_from_flag {
        return Ok(());
    }

    Err(HcomError::IdentityRequired(format!(
        "'{cmd}' requires identity. Use --name <yourname> or run inside an hcom-launched session."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_db() -> (HcomDb, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();
        (db, dir)
    }

    fn insert_instance(db: &HcomDb, name: &str, session_id: Option<&str>, tag: Option<&str>) {
        let now = chrono::Utc::now().timestamp() as f64;
        db.conn()
            .execute(
                "INSERT INTO instances (name, session_id, tag, status, created_at, tool)
             VALUES (?1, ?2, ?3, 'active', ?4, 'claude')",
                rusqlite::params![name, session_id, tag, now],
            )
            .unwrap();
    }

    fn insert_process_binding(db: &HcomDb, process_id: &str, instance_name: &str) {
        let now = chrono::Utc::now().timestamp() as f64;
        db.conn()
            .execute(
                "INSERT INTO process_bindings (process_id, instance_name, updated_at)
             VALUES (?1, ?2, ?3)",
                rusqlite::params![process_id, instance_name, now],
            )
            .unwrap();
    }

    fn insert_session_binding(db: &HcomDb, session_id: &str, instance_name: &str) {
        let now = chrono::Utc::now().timestamp() as f64;
        db.conn()
            .execute(
                "INSERT INTO session_bindings (session_id, instance_name, created_at)
             VALUES (?1, ?2, ?3)",
                rusqlite::params![session_id, instance_name, now],
            )
            .unwrap();
    }

    // ── Name validation tests ──────────────────────────────────────────

    #[test]
    fn test_looks_like_uuid() {
        assert!(looks_like_uuid("12345678-1234-1234-1234-123456789abc"));
        assert!(looks_like_uuid("ABCDEF01-2345-6789-ABCD-EF0123456789"));
        assert!(!looks_like_uuid("not-a-uuid"));
        assert!(!looks_like_uuid("12345678-1234-1234-1234-12345678"));
    }

    #[test]
    fn test_looks_like_agent_id() {
        assert!(looks_like_agent_id("a6d9caf"));
        assert!(looks_like_agent_id("1234567"));
        assert!(!looks_like_agent_id("a6d9ca")); // too short
        assert!(!looks_like_agent_id("a6d9cafg")); // too long
        assert!(!looks_like_agent_id("a6d9caz")); // non-hex
    }

    #[test]
    fn test_is_valid_base_name() {
        assert!(is_valid_base_name("luna"));
        assert!(is_valid_base_name("test_name_123"));
        assert!(!is_valid_base_name("Luna")); // uppercase
        assert!(!is_valid_base_name("my-name")); // dash
        assert!(!is_valid_base_name("")); // empty
        assert!(!is_valid_base_name("name with space"));
    }

    #[test]
    fn test_instance_not_found_error_for() {
        let (db, _dir) = make_test_db();

        // Never-seen name: no `start --as` (it would rename the caller's
        // identity away); point an external sender at --from instead.
        let err = instance_not_found_error_for(&db, "fill_alarm");
        assert!(!err.contains("--as"), "{err}");
        assert!(err.contains("send --from fill_alarm"), "{err}");

        // A name that existed: reclaim with --as.
        db.log_life_event("luna", "stopped", "test", "exit", None, None)
            .unwrap();
        let err = instance_not_found_error_for(&db, "luna");
        assert!(err.contains("start --as luna"), "{err}");

        // Agent ID: don't suggest --as
        let err = instance_not_found_error_for(&db, "a6d9caf");
        assert!(err.contains("Stop working"));
        assert!(!err.contains("--as"));
    }

    #[test]
    fn test_validate_name_input() {
        // Valid
        assert!(validate_name_input("luna", 50, true).is_ok());
        assert!(validate_name_input("test_name", 50, true).is_ok());

        // Too long
        let long_name = "a".repeat(51);
        let err = validate_name_input(&long_name, 50, true).unwrap_err();
        assert!(err.contains("too long"));

        // Dangerous chars
        let err = validate_name_input("name;evil", 50, true).unwrap_err();
        assert!(err.contains("invalid characters"));

        // @ allowed by default
        assert!(validate_name_input("@luna", 50, true).is_ok());

        // @ rejected when allow_at=false
        assert!(validate_name_input("@luna", 50, false).is_err());
    }

    // ── resolve_from_name tests ────────────────────────────────────────

    #[test]
    fn test_resolve_from_name_exact() {
        let (db, _dir) = make_test_db();
        insert_instance(&db, "luna", Some("sess-1"), None);

        let identity = resolve_from_name(&db, "luna").unwrap();
        assert_eq!(identity.name, "luna");
        assert!(matches!(identity.kind, SenderKind::Instance));
        assert_eq!(identity.session_id.as_deref(), Some("sess-1"));
    }

    #[test]
    fn test_resolve_from_name_agent_id() {
        let (db, _dir) = make_test_db();
        insert_instance(&db, "luna", None, None);
        // Set agent_id
        db.conn().execute(
            "UPDATE instances SET agent_id = '12345678-1234-1234-1234-123456789abc' WHERE name = 'luna'",
            [],
        ).unwrap();

        let identity = resolve_from_name(&db, "12345678-1234-1234-1234-123456789abc").unwrap();
        assert_eq!(identity.name, "luna");
    }

    #[test]
    fn test_resolve_from_name_tag_name() {
        let (db, _dir) = make_test_db();
        insert_instance(&db, "luna", None, Some("team"));

        let identity = resolve_from_name(&db, "team-luna").unwrap();
        assert_eq!(identity.name, "luna");
    }

    #[test]
    fn test_resolve_from_name_not_found() {
        let (db, _dir) = make_test_db();

        let err = resolve_from_name(&db, "nonexistent").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_resolve_from_name_invalid() {
        let (db, _dir) = make_test_db();

        let err = resolve_from_name(&db, "Invalid-Name!").unwrap_err();
        assert!(err.to_string().contains("Invalid instance name"));
    }

    // ── resolve_identity tests ─────────────────────────────────────────

    #[test]
    fn test_resolve_identity_system_sender() {
        let (db, _dir) = make_test_db();

        let identity =
            resolve_identity(&db, None, Some("hcom-launcher"), None, None, None, None).unwrap();
        assert!(matches!(identity.kind, SenderKind::System));
        assert_eq!(identity.name, "hcom-launcher");
    }

    #[test]
    fn test_resolve_identity_session_id() {
        let (db, _dir) = make_test_db();
        insert_instance(&db, "luna", Some("sess-1"), None);
        insert_session_binding(&db, "sess-1", "luna");

        let identity = resolve_identity(&db, None, None, Some("sess-1"), None, None, None).unwrap();
        assert!(matches!(identity.kind, SenderKind::Instance));
        assert_eq!(identity.name, "luna");
        assert_eq!(identity.session_id.as_deref(), Some("sess-1"));
    }

    #[test]
    fn test_resolve_identity_name() {
        let (db, _dir) = make_test_db();
        insert_instance(&db, "luna", None, None);

        let identity = resolve_identity(&db, Some("luna"), None, None, None, None, None).unwrap();
        assert_eq!(identity.name, "luna");
    }

    #[test]
    fn test_resolve_identity_process_binding() {
        let (db, _dir) = make_test_db();
        insert_instance(&db, "luna", Some("sess-1"), None);
        insert_process_binding(&db, "pid-123", "luna");

        let identity =
            resolve_identity(&db, None, None, None, Some("pid-123"), None, None).unwrap();
        assert_eq!(identity.name, "luna");
        assert_eq!(identity.session_id.as_deref(), Some("sess-1"));
    }

    #[test]
    fn test_resolve_identity_process_binding_codex_session_bind() {
        let (db, _dir) = make_test_db();
        // Instance without session_id
        insert_instance(&db, "luna", None, None);
        insert_process_binding(&db, "pid-123", "luna");

        let identity = resolve_identity(
            &db,
            None,
            None,
            None,
            Some("pid-123"),
            Some("thread-abc"),
            None,
        )
        .unwrap();
        assert_eq!(identity.name, "luna");
        // Session should now be bound
        assert_eq!(identity.session_id.as_deref(), Some("thread-abc"));

        // Verify binding was persisted
        let bound = db.get_session_binding("thread-abc").unwrap();
        assert_eq!(bound, Some("luna".to_string()));
    }

    #[test]
    fn test_resolve_identity_process_binding_expired() {
        let (db, _dir) = make_test_db();
        // No process binding exists

        let err = resolve_identity(&db, None, None, None, Some("pid-123"), None, None).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn test_resolve_identity_transcript_fallback() {
        let (db, _dir) = make_test_db();
        insert_instance(&db, "nova", Some("sess-2"), None);

        let fallback = |_db: &HcomDb| -> Option<SenderIdentity> {
            Some(SenderIdentity {
                kind: SenderKind::Instance,
                name: "nova".to_string(),
                instance_data: None,
                session_id: Some("sess-2".to_string()),
            })
        };

        let identity =
            resolve_identity(&db, None, None, None, None, None, Some(&fallback)).unwrap();
        assert_eq!(identity.name, "nova");
    }

    #[test]
    fn test_resolve_identity_no_identity() {
        let (db, _dir) = make_test_db();

        let err = resolve_identity(&db, None, None, None, None, None, None).unwrap_err();
        assert!(err.to_string().contains("No hcom identity"));
    }

    #[test]
    fn test_resolve_identity_priority_system_over_name() {
        let (db, _dir) = make_test_db();
        insert_instance(&db, "luna", None, None);

        // system_sender takes priority over name
        let identity = resolve_identity(
            &db,
            Some("luna"),
            Some("hcom-launcher"),
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(matches!(identity.kind, SenderKind::System));
        assert_eq!(identity.name, "hcom-launcher");
    }

    #[test]
    fn test_resolve_identity_priority_session_over_name() {
        let (db, _dir) = make_test_db();
        insert_instance(&db, "luna", Some("sess-1"), None);
        insert_instance(&db, "nova", Some("sess-2"), None);
        insert_session_binding(&db, "sess-1", "luna");

        // session_id takes priority over name
        let identity =
            resolve_identity(&db, Some("nova"), None, Some("sess-1"), None, None, None).unwrap();
        assert_eq!(identity.name, "luna");
    }

    // ── Identity gating tests ──────────────────────────────────────────

    #[test]
    fn test_requires_identity() {
        assert!(requires_identity("send"));
        assert!(requires_identity("listen"));
        assert!(!requires_identity("list"));
        assert!(!requires_identity("status"));
        assert!(!requires_identity("events"));
    }

    #[test]
    fn test_identity_gate_non_gated_command() {
        assert!(require_identity_gate("list", None, false).is_ok());
    }

    #[test]
    fn test_identity_gate_with_name() {
        assert!(require_identity_gate("send", Some("luna"), false).is_ok());
    }

    #[test]
    fn test_identity_gate_send_with_from() {
        assert!(require_identity_gate("send", None, true).is_ok());
    }

    #[test]
    fn test_identity_gate_send_no_identity() {
        let err = require_identity_gate("send", None, false).unwrap_err();
        assert!(err.to_string().contains("requires identity"));
    }

    #[test]
    fn test_identity_gate_listen_no_identity() {
        let err = require_identity_gate("listen", None, false).unwrap_err();
        assert!(err.to_string().contains("requires identity"));
    }

    // ── Codex resume regression tests ──────────────────────────────────

    #[test]
    fn test_codex_session_bind_resume_switches_to_canonical() {
        // Regression: Codex thread_id matches an existing session binding (resume scenario).
        // Must switch identity to canonical instance, not stay on placeholder.
        let (db, _dir) = make_test_db();
        insert_instance(&db, "canonical", Some("thread-resume"), None);
        insert_session_binding(&db, "thread-resume", "canonical");
        insert_instance(&db, "placeholder", None, None);
        // Real launch placeholders are pending/new (PLACEHOLDER_STATUS/CONTEXT); set that
        // here so deletion is gated on genuine placeholder-ness, not merely a null session.
        db.conn()
            .execute(
                "UPDATE instances SET status = 'pending', status_context = 'new' WHERE name = 'placeholder'",
                [],
            )
            .unwrap();
        insert_process_binding(&db, "pid-codex", "placeholder");

        let identity = resolve_identity(
            &db,
            None,
            None,
            None,
            Some("pid-codex"),
            Some("thread-resume"),
            None,
        )
        .unwrap();

        // Must resolve to canonical, not placeholder
        assert_eq!(identity.name, "canonical");
        assert_eq!(identity.session_id.as_deref(), Some("thread-resume"));

        // Placeholder should be deleted (was true placeholder)
        assert!(db.get_instance("placeholder").unwrap().is_none());
    }

    #[test]
    fn test_codex_session_bind_already_bound_same_instance() {
        // Session already bound to the same instance we're on → no-op, no crash
        let (db, _dir) = make_test_db();
        insert_instance(&db, "luna", Some("thread-same"), None);
        insert_session_binding(&db, "thread-same", "luna");
        insert_process_binding(&db, "pid-codex", "luna");

        let identity = resolve_identity(
            &db,
            None,
            None,
            None,
            Some("pid-codex"),
            Some("thread-same"),
            None,
        )
        .unwrap();

        assert_eq!(identity.name, "luna");
        assert_eq!(identity.session_id.as_deref(), Some("thread-same"));
    }

    // ── Display-name resolution tests ──────────────────────────────────

    fn default_instance() -> InstanceRow {
        InstanceRow {
            name: String::new(),
            session_id: None,
            parent_session_id: None,
            parent_name: None,
            agent_id: None,
            tag: None,
            last_event_id: 0,
            last_stop: 0,
            status: String::from("inactive"),
            status_time: 0,
            last_seen: 0,
            status_context: String::new(),
            status_detail: String::new(),
            directory: String::new(),
            created_at: 0.0,
            transcript_path: String::new(),
            tool: "claude".into(),
            background: 0,
            background_log_file: String::new(),
            tcp_mode: 0,
            wait_timeout: None,
            subagent_timeout: None,
            hints: None,
            origin_device_id: None,
            pid: None,
            launch_args: None,
            terminal_preset_requested: None,
            terminal_preset_effective: None,
            launch_context: None,
            name_announced: 0,
            idle_since: None,
            purpose: None,
            current: None,
        }
    }

    #[test]
    fn test_get_full_name() {
        let plain = InstanceRow {
            name: "luna".into(),
            tag: None,
            ..default_instance()
        };
        assert_eq!(get_full_name(&plain), "luna");

        let tagged = InstanceRow {
            name: "luna".into(),
            tag: Some("team".into()),
            ..default_instance()
        };
        assert_eq!(get_full_name(&tagged), "team-luna");
    }

    #[test]
    fn test_resolve_display_name_or_stopped_tagged_snapshot() {
        let (db, _dir) = make_test_db();
        db.conn()
            .execute(
                "INSERT INTO events (timestamp, type, instance, data)
                 VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), 'life', 'luna', ?1)",
                rusqlite::params![
                    serde_json::json!({
                        "action": "stopped",
                        "snapshot": {"tag": "team"}
                    })
                    .to_string()
                ],
            )
            .unwrap();

        assert_eq!(
            resolve_display_name_or_stopped(&db, "team-luna").as_deref(),
            Some("luna")
        );
        assert_eq!(
            resolve_display_name_or_stopped(&db, "luna").as_deref(),
            Some("luna")
        );
    }

    // ── fleet-wide bare-name resolution ─────────────────────────────────

    const DEV_A: &str = "11111111-1111-4111-8111-111111111111";
    const DEV_B: &str = "22222222-2222-4222-8222-222222222222";

    /// The `x:DEV` form a device's rows carry, from the canonical short-id
    /// derivation (never a hand-written suffix).
    fn remote_form(base: &str, device_uuid: &str) -> String {
        format!("{base}:{}", crate::relay::device_short_id(device_uuid))
    }

    fn insert_mirror(db: &HcomDb, name: &str, device_uuid: &str, status: &str) {
        let now = chrono::Utc::now().timestamp_millis() as f64;
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, status_context, status_time,
                                        created_at, tool, origin_device_id)
                 VALUES (?1, ?2, 'ready', ?3, ?3, 'omp', ?4)",
                rusqlite::params![name, status, now, device_uuid],
            )
            .unwrap();
    }

    /// A fresh empty DB. Every fleet test holds an isolated env for its whole
    /// body: the resolver reads the device config on each call, so the guard
    /// must outlive the assertion (and `#[serial]` keeps the env single-threaded).
    fn fleet_db() -> (tempfile::TempDir, HcomDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();
        (dir, db)
    }

    #[test]
    #[serial_test::serial]
    fn one_live_remote_resolves_to_its_suffixed_form() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        insert_mirror(&db, &remote_form("luna", DEV_A), DEV_A, "listening");
        assert_eq!(
            fleet_first(&db, "luna"),
            CliResolve::Hit(remote_form("luna", DEV_A))
        );
    }

    #[test]
    #[serial_test::serial]
    fn two_live_remotes_refuse_and_name_both_forms() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        insert_mirror(&db, &remote_form("luna", DEV_A), DEV_A, "listening");
        insert_mirror(&db, &remote_form("luna", DEV_B), DEV_B, "listening");
        let err = refusal(&db, "luna");
        assert!(err.contains(&remote_form("luna", DEV_A)), "{err}");
        assert!(err.contains(&remote_form("luna", DEV_B)), "{err}");
    }

    /// A live local row is a candidate, not a short-circuit: a live mirror of
    /// the same base name is the collision, and the CLI refuses exactly like
    /// `hcom send @x` does in the same database.
    #[test]
    #[serial_test::serial]
    fn a_live_local_row_and_a_live_mirror_refuse_and_name_both_forms() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        insert_instance(&db, "luna", Some("sess-1"), None);
        insert_mirror(&db, &remote_form("luna", DEV_A), DEV_A, "listening");
        let err = refusal(&db, "luna");
        assert!(err.contains("@luna,"), "local shown as bare @luna: {err}");
        assert!(err.contains(&remote_form("luna", DEV_A)), "{err}");
    }

    #[test]
    #[serial_test::serial]
    fn tagged_local_display_and_remote_same_base_refuse_both_forms() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        insert_instance(&db, "x", Some("sess-1"), None);
        db.conn()
            .execute("UPDATE instances SET tag = 'grp' WHERE name = 'x'", [])
            .unwrap();
        let remote = remote_form("grp-x", DEV_A);
        insert_mirror(&db, &remote, DEV_A, "listening");
        let err = refusal(&db, "grp-x");
        assert!(err.contains("@x (local display @grp-x)"), "{err}");
        assert!(err.contains(&format!("@{remote}")), "{err}");
        assert_eq!(cli_target(&db, &remote).unwrap(), remote);
        assert_eq!(cli_target(&db, "x").unwrap(), "x");
    }

    #[test]
    #[serial_test::serial]
    fn a_live_local_row_is_the_only_candidate_and_keeps_the_bare_name() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        insert_instance(&db, "luna", Some("sess-1"), None);
        assert_eq!(fleet_first(&db, "luna"), CliResolve::Hit("luna".into()));
    }

    #[test]
    #[serial_test::serial]
    fn a_stopped_local_name_is_not_a_fleet_candidate() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        db.log_life_event("luna", "stopped", "test", "exit", None, None)
            .unwrap();
        // Unchanged: the caller's local path still owns the stopped name.
        assert_eq!(fleet_first(&db, "luna"), CliResolve::Miss);
    }

    /// A stopped local row is never a candidate, so a name live on another
    /// device resolves to THAT device's exact form — the same answer
    /// `hcom send @x` gives.
    #[test]
    #[serial_test::serial]
    fn a_stopped_local_name_with_a_live_remote_resolves_to_the_remote_form() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        db.log_life_event("luna", "stopped", "test", "exit", None, None)
            .unwrap();
        insert_mirror(&db, &remote_form("luna", DEV_A), DEV_A, "listening");
        assert_eq!(
            fleet_first(&db, "luna"),
            CliResolve::Hit(remote_form("luna", DEV_A))
        );
    }

    #[test]
    #[serial_test::serial]
    fn a_suffixed_name_is_never_fleet_resolved() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        insert_mirror(&db, &remote_form("luna", DEV_A), DEV_A, "listening");
        insert_mirror(&db, &remote_form("luna", DEV_B), DEV_B, "listening");
        assert_eq!(
            fleet_first(&db, &remote_form("luna", DEV_A)),
            CliResolve::Miss
        );
    }

    #[test]
    #[serial_test::serial]
    fn a_stopped_remote_row_is_not_a_candidate() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        insert_mirror(&db, &remote_form("luna", DEV_A), DEV_A, "stopped");
        assert_eq!(fleet_first(&db, "luna"), CliResolve::Miss);
    }

    /// The refusal text a `Refused` verdict carries, for the assertions above.
    fn refusal(db: &HcomDb, name: &str) -> String {
        match fleet_first(db, name) {
            CliResolve::Refused(msg) => msg,
            other => panic!("expected a refusal for {name}, got {other:?}"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn the_history_hint_names_the_device_and_the_fresh_launch() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        let form = remote_form("X", DEV_A);
        db.log_life_event(&form, "stopped", "test", "exit", None, None)
            .unwrap();
        let hint = remote_history_hint(&db, "X").expect("off-host history");
        assert!(hint.contains(&form), "{hint}");
        assert!(hint.contains("--as X"), "{hint}");
        assert!(hint.contains(&format!("hcom r {form}")), "{hint}");
    }

    #[test]
    #[serial_test::serial]
    fn a_name_with_no_off_host_history_has_no_hint() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        db.log_life_event("luna", "stopped", "test", "exit", None, None)
            .unwrap();
        assert!(remote_history_hint(&db, "luna").is_none());
        // A different base name never matches the other's suffixed history.
        assert!(remote_history_hint(&db, "other").is_none());
    }
}
