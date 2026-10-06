//! Fleet-wide bare-name resolution (ffc-ravoc).
//!
//! One resolver shared by send, r, kill, stop, list, term inject and compact:
//! a bare `x` may resolve to a remote mirror row `x:DEV` when it is the only
//! live candidate. Suffix-only devices (config key `relay_suffix_only_devices`)
//! are never bare-resolution targets, but DO count for collisions and the
//! cross-host launch guard: every refusal names the exact suffixed form(s)
//! to use.
//!
//! Message events carry an `exact_targets` JSON array (exact instance names)
//! on mentions-scope messages resolved at send time. An event WITHOUT the
//! key comes from an older peer and keeps today's legacy base-name delivery.

use crate::db::HcomDb;

/// Liveness rule for instance rows: mirrors `deliverable_instances` in
/// `commands/send.rs` — stopped rows, launch failures, and exited rows are
/// never deliverable, so they are never bare-name candidates either.
///
/// `instance_lifecycle` has no extra inactive-stale rule that lives in the
/// stored `status`/`status_context` values: stale demotion
/// (`inactive` + `stale:…` context) is computed on read by
/// `get_instance_status` and only the *computed* status is published/pushed;
/// a stored `inactive` row without `exit:` context is an adhoc instance
/// idling between commands and stays mentionable, exactly as send treats it.
pub const LIVE_ROW_PREDICATE: &str = "status != 'stopped' AND status_context != 'launch_failed' AND NOT (status = 'inactive' AND status_context LIKE 'exit:%')";

/// One live row whose base name matches a bare input.
///
/// `exact` is the full row name: the bare base for a local row, or the
/// suffixed `base:SHORT` form for a remote mirror row.
#[derive(Clone, Debug, PartialEq)]
pub struct BareCandidate {
    pub exact: String,
    pub suffix_only: bool,
    /// True when this local row's full tagged display name matches the input.
    pub display_match: bool,
}

/// Outcome of resolving a bare name against the live candidate set.
#[derive(Clone, Debug, PartialEq)]
pub enum BareOutcome {
    /// No live row carries this base name.
    NoCandidate,
    /// Exactly one non-suffix-only candidate and no suffix-only candidate.
    Single(String),
    /// Ambiguous, or live only on suffix-only devices: names the exact
    /// suffixed form(s) to use.
    Refuse(String),
}

/// Refusal message for the ambiguous / suffix-only cases.
///
/// Lists every non-suffix-only exact form (local rows as the bare name,
/// mirrors as `x:DEV`) and every suffix-only exact form, then asks for the
/// exact suffixed form.
fn refuse_message(base: &str, normal: &[&BareCandidate], solo: &[&BareCandidate]) -> String {
    let mut forms: Vec<String> = Vec::with_capacity(normal.len() + solo.len());
    for c in normal.iter().chain(solo.iter()) {
        if c.display_match {
            forms.push(format!("@{} (local display @{base})", c.exact));
        } else {
            forms.push(format!("@{}", c.exact));
        }
    }
    let list = forms.join(", ");
    if solo.is_empty() {
        format!("multiple live agents named '{base}': use the exact form instead — {list}")
    } else if normal.is_empty() {
        format!(
            "'{base}' is live only on suffix-only devices (never resolved by bare name): use the exact form — {list}"
        )
    } else {
        format!(
            "multiple live agents named '{base}' (including suffix-only devices): use the exact form instead — {list}"
        )
    }
}

/// Resolve a bare `base` against live candidates (case-insensitive base or
/// tagged local display-name match — see `live_candidates`).
///
/// Partition candidates into normal (not suffix-only) and solo (suffix-only):
/// - none at all → [`BareOutcome::NoCandidate`]
/// - exactly one normal and no solo → [`BareOutcome::Single`] with the exact name
/// - two or more normal → [`BareOutcome::Refuse`] listing every normal exact
/// - zero normal and ≥1 solo → [`BareOutcome::Refuse`] pointing at the solo
///   exact form(s) (`x:GIDU`)
/// - one normal and ≥1 solo → [`BareOutcome::Refuse`] listing both
///
/// Every refusal names the exact suffixed form(s) to use.
pub fn resolve_bare_name(base: &str, candidates: &[BareCandidate]) -> BareOutcome {
    let base_lower = base.to_lowercase();
    let matching: Vec<&BareCandidate> = candidates
        .iter()
        .filter(|c| {
            if c.display_match {
                return true;
            }
            match crate::relay::control::split_device_suffix(&c.exact) {
                // Local row: its whole name is the base.
                None => c.exact.to_lowercase() == base_lower,
                // Mirror row: the base before the device suffix must match.
                Some((row_base, _)) => row_base.to_lowercase() == base_lower,
            }
        })
        .collect();

    let normal: Vec<&BareCandidate> = matching
        .iter()
        .copied()
        .filter(|c| !c.suffix_only)
        .collect();
    let solo: Vec<&BareCandidate> = matching.iter().copied().filter(|c| c.suffix_only).collect();

    match (normal.len(), solo.len()) {
        (0, 0) => BareOutcome::NoCandidate,
        (1, 0) => BareOutcome::Single(normal[0].exact.clone()),
        // ≥2 normal, or 1 normal + ≥1 solo, or 0 normal + ≥1 solo.
        _ => BareOutcome::Refuse(refuse_message(base, &normal, &solo)),
    }
}

/// Devices that must be addressed with a `:SHORT` suffix, from config key
/// `relay_suffix_only_devices` (comma-separated UUIDs or 4-char short ids).
///
/// Listed devices are never bare-resolution targets, but count for collisions
/// and the cross-host launch guard.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SuffixOnly {
    shorts: std::collections::HashSet<String>,
    uuids: std::collections::HashSet<String>,
}

/// A token is UUID-shaped when it has the canonical 8-4-4-4-12 hex layout.
pub(crate) fn is_uuid_shaped(token: &str) -> bool {
    token.len() == 36
        && token.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

impl SuffixOnly {
    /// Parse a comma-separated list of device UUIDs or 4-char short ids.
    /// Trims tokens; empty tokens are skipped. A UUID-shaped token joins the
    /// uuid set, every other token is kept as a short id (uppercased) — this
    /// loader stays infallible, so a malformed entry is left listed-as-short
    /// (and matches nothing) while config validation
    /// (`HcomConfig::collect_errors`) is the path that reports it.
    pub fn parse(raw: &str) -> Self {
        let mut so = SuffixOnly::default();
        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if is_uuid_shaped(token) {
                so.uuids.insert(token.to_lowercase());
            } else {
                so.shorts.insert(token.to_uppercase());
            }
        }
        so
    }

    /// True when no device is listed.
    pub fn is_empty(&self) -> bool {
        self.shorts.is_empty() && self.uuids.is_empty()
    }

    /// Case-insensitive match against explicitly listed short ids only.
    /// A UUID's derived short can collide with another device, so a UUID
    /// listing must never imply a short-id listing.
    pub fn short_is_listed(&self, short: &str) -> bool {
        self.shorts.contains(&short.to_uppercase())
    }

    /// True when `uuid` is listed (case-insensitive), or when its canonical
    /// short id is listed.
    pub fn device_is_listed(&self, uuid: &str) -> bool {
        if self.uuids.contains(&uuid.to_lowercase()) {
            return true;
        }
        !self.shorts.is_empty() && self.short_is_listed(&crate::relay::device_short_id(uuid))
    }

    /// Suffix-only flag for a remote mirror row: true when the row's origin
    /// device is listed, or when the `:SHORT` suffix its row carries is
    /// listed. The suffix is a second, independent leg because a row's suffix
    /// is not always its device's canonical short id (a probed slot, or the
    /// 4-char fallback on relay import).
    pub fn mirror_is_suffix_only(&self, origin_uuid: &str, suffix: &str) -> bool {
        self.device_is_listed(origin_uuid) || self.short_is_listed(suffix)
    }
}

/// Own-device + suffix-only context for fleet bare-name resolution.
#[derive(Clone, Debug)]
pub struct FleetCtx {
    pub so: SuffixOnly,
    pub own_uuid: String,
}

impl FleetCtx {
    /// Read config (`relay_suffix_only_devices`) plus the own device id.
    /// Never fails: every failure path degrades to the empty fallback (no
    /// suffix-only devices, empty own identity).
    pub fn load() -> Self {
        let so = SuffixOnly::parse(
            &crate::config::load_config_snapshot()
                .core
                .relay_suffix_only_devices,
        );

        let own_uuid = crate::relay::read_device_uuid().unwrap_or_default();

        FleetCtx { so, own_uuid }
    }
}

/// Live candidate rows for bare `base` (case-insensitive base or local
/// tagged display-name match):
/// - a local live row named `base` or displayed as `tag-name` matching `base`
///   (suffix-only flag from the own device id), and
/// - live mirror rows (origin_device_id set) whose base after
///   `split_device_suffix` equals `base`, with the suffix-only flag from
///   the config list for that mirror's device (origin uuid first, short id
///   as fallback).
pub fn live_candidates(db: &HcomDb, base: &str, ctx: &FleetCtx) -> Vec<BareCandidate> {
    let mut out: Vec<BareCandidate> = Vec::new();

    // Local live row: no origin_device_id (NULL or empty string — the column
    // defaults to '', while the typed read path filters empty to None).
    if let Ok(rows) = db
        .conn()
        .prepare(&format!(
            "SELECT name, tag FROM instances
             WHERE {LIVE_ROW_PREDICATE}
               AND (origin_device_id IS NULL OR origin_device_id = '')
               AND (LOWER(name) = LOWER(?1)
                    OR LOWER(tag || '-' || name) = LOWER(?1))"
        ))
        .and_then(|mut stmt| {
            stmt.query_map([base], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .map(|rows| rows.filter_map(|r| r.ok()).collect::<Vec<_>>())
        })
    {
        for (name, tag) in rows {
            let display_match = tag
                .as_deref()
                .is_some_and(|tag| format!("{tag}-{name}").eq_ignore_ascii_case(base))
                && !name.eq_ignore_ascii_case(base);
            let suffix_only = !ctx.own_uuid.is_empty() && ctx.so.device_is_listed(&ctx.own_uuid);
            out.push(BareCandidate {
                exact: name,
                suffix_only,
                display_match,
            });
        }
    }

    // Remote mirror rows: origin_device_id set, name is base:SHORT.
    if let Ok(rows) = db
        .conn()
        .prepare(&format!(
            "SELECT name, origin_device_id FROM instances
             WHERE {LIVE_ROW_PREDICATE}
               AND origin_device_id IS NOT NULL AND origin_device_id != ''"
        ))
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map(|rows| rows.filter_map(|r| r.ok()).collect::<Vec<_>>())
        })
    {
        for (name, origin) in rows {
            let Some((row_base, suffix)) = crate::relay::control::split_device_suffix(&name) else {
                continue;
            };
            if !row_base.eq_ignore_ascii_case(base) {
                continue;
            }
            let suffix_only = ctx.so.mirror_is_suffix_only(&origin, suffix);
            out.push(BareCandidate {
                exact: name,
                suffix_only,
                display_match: false,
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    // isolated_test_env swaps HCOM_DIR/HOME process-wide; every test that
    // installs it must run serially against all other env-mutating tests
    // across the crate (serial_test shares one global lock).
    use super::*;
    use serial_test::serial;

    fn cand(exact: &str, suffix_only: bool) -> BareCandidate {
        BareCandidate {
            exact: exact.to_string(),
            suffix_only,
            display_match: false,
        }
    }

    // Decision cell 1: a single remote candidate resolves.
    #[test]
    fn single_remote_resolves() {
        let out = resolve_bare_name(
            "x",
            &[
                cand("x:GIDU", false),
                cand("other:ABCD", false),
                cand("y", false),
            ],
        );
        assert_eq!(out, BareOutcome::Single("x:GIDU".to_string()));
    }

    // Decision cell 1b: a single local candidate resolves to the bare name.
    #[test]
    fn single_local_resolves() {
        let out = resolve_bare_name("x", &[cand("x", false)]);
        assert_eq!(out, BareOutcome::Single("x".to_string()));
    }

    // No candidate at all.
    #[test]
    fn no_candidate() {
        assert_eq!(resolve_bare_name("x", &[]), BareOutcome::NoCandidate);
        assert_eq!(
            resolve_bare_name("x", &[cand("y", false)]),
            BareOutcome::NoCandidate
        );
    }

    // Decision cell 2: two non-suffix-only candidates refuse, listing both.
    #[test]
    fn two_live_candidates_refuse_listing_both() {
        let out = resolve_bare_name("x", &[cand("x:ABCD", false), cand("x:HODA", false)]);
        match out {
            BareOutcome::Refuse(msg) => {
                assert!(msg.contains("@x:ABCD"), "message must list @x:ABCD: {msg}");
                assert!(msg.contains("@x:HODA"), "message must list @x:HODA: {msg}");
            }
            other => panic!("expected Refuse, got {other:?}"),
        }
    }

    // Decision cell 2b: local + remote also refuse, local shown as bare name.
    #[test]
    fn local_and_remote_refuse() {
        let out = resolve_bare_name("x", &[cand("x", false), cand("x:ABCD", false)]);
        match out {
            BareOutcome::Refuse(msg) => {
                assert!(msg.contains("@x,"), "local shown as bare @x: {msg}");
                assert!(msg.contains("@x:ABCD"), "mirror shown as @x:ABCD: {msg}");
            }
            other => panic!("expected Refuse, got {other:?}"),
        }
    }

    // Decision cell 3: suffix-only-only refuses pointing at x:GIDU.
    #[test]
    fn suffix_only_only_refuses_pointing_at_exact_form() {
        // lotso's device UUID must be on the list for this cell.
        let _so = SuffixOnly::parse("f3a70268-8ffa-4f0c-9e37-62f78acfcc1e");
        let out = resolve_bare_name("x", &[cand("x:GIDU", true)]);
        match out {
            BareOutcome::Refuse(msg) => {
                assert!(msg.contains("x:GIDU"), "must point at x:GIDU: {msg}");
            }
            other => panic!("expected Refuse, got {other:?}"),
        }
    }

    // Decision cell 4: suffix-only plus one other refuses, listing both.
    #[test]
    fn suffix_only_plus_other_refuses_listing_both() {
        let out = resolve_bare_name("x", &[cand("x", false), cand("x:GIDU", true)]);
        match out {
            BareOutcome::Refuse(msg) => {
                assert!(msg.contains("@x,"), "must list the normal form: {msg}");
                assert!(
                    msg.contains("@x:GIDU"),
                    "must list the suffix-only form: {msg}"
                );
            }
            other => panic!("expected Refuse, got {other:?}"),
        }
    }

    // Decision cell 6: a stopped local row is never a candidate.
    #[test]
    #[serial]
    fn stopped_local_row_never_candidate() {
        let (_dir, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open_at(&hcom_dir.join("hcom.db")).unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, created_at, status, status_context, status_time)
                 VALUES ('x', 'claude', 1.0, 'stopped', 'stop', 1)",
                [],
            )
            .unwrap();

        let ctx = FleetCtx {
            so: SuffixOnly::default(),
            own_uuid: String::new(),
        };
        assert!(live_candidates(&db, "x", &ctx).is_empty());

        // A live local row IS a candidate.
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, created_at, status, status_context, status_time)
                 VALUES ('y', 'claude', 1.0, 'listening', '', 925000000)",
                [],
            )
            .unwrap();
        let got = live_candidates(&db, "y", &ctx);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].exact, "y");
        assert!(!got[0].suffix_only);
    }

    // Decision cell 7: an exact UUID or an explicitly listed short identifies
    // the device; a UUID listing does not implicitly list its derived short.
    #[test]
    fn device_is_listed_true_for_uuid_and_explicit_short() {
        let uuid = "f3a70268-8ffa-4f0c-9e37-62f78acfcc1e";
        let by_uuid = SuffixOnly::parse(uuid);
        assert!(by_uuid.device_is_listed(uuid));
        assert!(by_uuid.device_is_listed(&uuid.to_uppercase()));
        let short = crate::relay::device_short_id(uuid);
        assert!(!by_uuid.short_is_listed(&short));
        let by_short = SuffixOnly::parse(&short);
        assert!(by_short.device_is_listed(uuid));
        assert!(by_short.short_is_listed(&short));
        assert!(!by_uuid.device_is_listed("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn uuid_listing_does_not_mark_colliding_unlisted_device_suffix_only() {
        let listed_uuid = "0000003f-0000-4000-8000-000000000000";
        let colliding_uuid = "0000008f-0000-4000-8000-000000000000";
        let short = crate::relay::device_short_id(listed_uuid);
        assert_eq!(short, crate::relay::device_short_id(colliding_uuid));
        let by_uuid = SuffixOnly::parse(listed_uuid);
        assert!(by_uuid.mirror_is_suffix_only(listed_uuid, &short));
        assert!(!by_uuid.device_is_listed(colliding_uuid));
        assert!(!by_uuid.mirror_is_suffix_only(colliding_uuid, &short));
        let by_short = SuffixOnly::parse(&short);
        assert!(by_short.mirror_is_suffix_only(colliding_uuid, &short));
    }

    /// A mirror row's suffix is a second, independent leg: a row can carry a
    /// probed or imported `:SHORT` that is not the device's canonical one,
    /// and the origin uuid must still classify the device.
    #[test]
    fn mirror_is_suffix_only_covers_origin_and_suffix_legs() {
        let by_uuid = SuffixOnly::parse("f3a70268-8ffa-4f0c-9e37-62f78acfcc1e");
        assert!(by_uuid.mirror_is_suffix_only("f3a70268-8ffa-4f0c-9e37-62f78acfcc1e", "ZZZZ"));
        let by_short = SuffixOnly::parse("HODA");
        assert!(by_short.mirror_is_suffix_only("00000000-0000-0000-0000-000000000000", "HODA"));
        let unlisted = SuffixOnly::default();
        assert!(!unlisted.mirror_is_suffix_only("f3a70268-8ffa-4f0c-9e37-62f78acfcc1e", "HODA"));
    }

    // SuffixOnly::parse — short ids, UUIDs, empties, case handling.
    #[test]
    fn suffix_only_parse_tokens() {
        let empty = SuffixOnly::parse("");
        assert!(empty.is_empty());
        assert!(SuffixOnly::parse("  ").is_empty());
        assert!(SuffixOnly::parse(",, ,").is_empty());

        let so = SuffixOnly::parse(" GIDU , f3a70268-8ffa-4f0c-9e37-62f78acfcc1e ,,");
        assert!(!so.is_empty());
        assert!(so.short_is_listed("GIDU"));
        assert!(
            so.short_is_listed("gidu"),
            "short match is case-insensitive"
        );
        assert!(so.device_is_listed("F3A70268-8FFA-4F0C-9E37-62F78ACFCC1E"));
        assert!(!so.short_is_listed("HODA"));

        // A listed UUID shortens to its canonical short id.
        let short = crate::relay::device_short_id("f3a70268-8ffa-4f0c-9e37-62f78acfcc1e");
        assert_eq!(short, "GIDU", "lotso's device must hash to GIDU");
        assert!(so.short_is_listed(&short));
    }

    // live_candidates picks up remote mirror rows, case-insensitively.
    #[test]
    #[serial]
    fn live_candidates_finds_remote_mirror() {
        let (_dir, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open_at(&hcom_dir.join("hcom.db")).unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, created_at, status, status_context, status_time, origin_device_id)
                 VALUES ('x:GIDU', 'claude', 1.0, 'listening', '', 925000000, 'f3a70268-8ffa-4f0c-9e37-62f78acfcc1e')",
                [],
            )
            .unwrap();
        // A same-suffix row with a different base must not match.
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, created_at, status, status_context, status_time, origin_device_id)
                 VALUES ('xx:GIDU', 'claude', 1.0, 'listening', '', 925000000, 'f3a70268-8ffa-4f0c-9e37-62f78acfcc1e')",
                [],
            )
            .unwrap();

        let so = SuffixOnly::parse("f3a70268-8ffa-4f0c-9e37-62f78acfcc1e");
        let ctx = FleetCtx {
            so,
            own_uuid: String::new(),
        };
        let got = live_candidates(&db, "X", &ctx);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].exact, "x:GIDU");
        assert!(
            got[0].suffix_only,
            "origin device is on the suffix-only list"
        );
    }

    // Local row flagged suffix-only when the own device is listed.
    #[test]
    #[serial]
    fn own_device_listed_marks_local_row_suffix_only() {
        let (_dir, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open_at(&hcom_dir.join("hcom.db")).unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, created_at, status, status_context, status_time)
                 VALUES ('x', 'claude', 1.0, 'listening', '', 925000000)",
                [],
            )
            .unwrap();

        let so = SuffixOnly::parse("GIDU");
        let ctx = FleetCtx {
            so,
            own_uuid: "f3a70268-8ffa-4f0c-9e37-62f78acfcc1e".to_string(),
        };
        let got = live_candidates(&db, "x", &ctx);
        assert_eq!(got.len(), 1);
        assert!(got[0].suffix_only, "own device is on the list");
    }

    // ── Contract the `person:channel` expansion resolves each side through ──
    //
    // `messages::buzz_person_in_channel` looks its person and channel rows up
    // by the name this resolver returns, so that name must be the row's own
    // canonical spelling (not the caller's casing) and must carry a `:SHORT`
    // suffix for a mirror row while the base still matches.

    #[test]
    fn resolve_bare_name_returns_the_canonical_row_spelling() {
        let out = resolve_bare_name("x", &[cand("X:GIDU", false)]);
        assert_eq!(out, BareOutcome::Single("X:GIDU".to_string()));
        // Case-insensitive in, canonical out: the caller looks up the row by
        // the returned name and compares that row's base against the input.
        let out = resolve_bare_name("michael", &[cand("Michael", false)]);
        assert_eq!(out, BareOutcome::Single("Michael".to_string()));
    }

    #[test]
    fn a_mirror_base_matches_the_input_case_insensitively() {
        // The same leg for a remote mirror: the base before `:SHORT` is what
        // the input has to match, so a person address off-device resolves.
        let out = resolve_bare_name("MICHAEL", &[cand("michael:MBAI", false)]);
        assert_eq!(out, BareOutcome::Single("michael:MBAI".to_string()));
        // A different base never matches, whatever the suffix.
        assert_eq!(
            resolve_bare_name("infra", &[cand("michael:MBAI", false)]),
            BareOutcome::NoCandidate
        );
    }
}
