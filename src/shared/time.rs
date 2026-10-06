//! Time helpers — epoch conversions and ISO formatting.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current time as f64 seconds since epoch (for REAL columns like updated_at, created_at).
pub fn now_epoch_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Convert a SystemTime to f64 seconds since epoch (for file mtimes, etc).
pub fn system_time_to_epoch_f64(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Current time as i64 seconds since epoch (for INTEGER columns like last_stop, heartbeat).
pub fn now_epoch_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Current time as i64 milliseconds since epoch (for session-record timestamps).
pub fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Current time as ISO 8601 string with microsecond precision (for TEXT timestamp columns).
pub fn now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6f+00:00")
        .to_string()
}

/// Canonical form for a supplied TEXT event timestamp: UTC with microseconds
/// and an explicit `+00:00` offset (the `now_iso` shape). Tool transcripts and
/// relay peers supply their own strings; unparseable input is stored unchanged.
///
/// Canonical storage is what makes lexicographic timestamp ranges (e.g. the
/// collision-subscription 30s window over `idx_timestamp`) sound: text order
/// equals time order only when every row shares the shape. A nonzero-offset
/// row sorts by its wall clock, not its instant, and would silently fall
/// outside a UTC-computed window.
pub fn normalize_event_timestamp(ts: &str) -> String {
    const CANON: &str = "%Y-%m-%dT%H:%M:%S%.6f+00:00";
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
        return dt.with_timezone(&chrono::Utc).format(CANON).to_string();
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts, fmt) {
            return naive.and_utc().format(CANON).to_string();
        }
    }
    ts.to_string()
}
/// Format a duration in seconds as a short human-readable string (e.g. "30s", "1h", "2d").
pub fn format_age(seconds: i64) -> String {
    if seconds <= 0 {
        return "now".to_string();
    }
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h", seconds / 3600)
    } else {
        format!("{}d", seconds / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_age() {
        assert_eq!(format_age(0), "now");
        assert_eq!(format_age(-5), "now");
        assert_eq!(format_age(30), "30s");
        assert_eq!(format_age(90), "1m");
        assert_eq!(format_age(3700), "1h");
        assert_eq!(format_age(90000), "1d");
    }

    #[test]
    fn test_now_epoch_f64_positive() {
        assert!(now_epoch_f64() > 0.0);
    }

    #[test]
    fn test_now_epoch_i64_positive() {
        assert!(now_epoch_i64() > 0);
    }

    #[test]
    fn test_now_iso_format() {
        let iso = now_iso();
        assert!(iso.contains("T"));
        assert!(iso.ends_with("+00:00"));
    }

    #[test]
    fn test_system_time_to_epoch() {
        let now = SystemTime::now();
        let epoch = system_time_to_epoch_f64(now);
        assert!(epoch > 0.0);
    }

    #[test]
    fn test_normalize_event_timestamp() {
        // Canonical input is untouched.
        assert_eq!(
            normalize_event_timestamp("2026-09-30T02:00:00.100000+00:00"),
            "2026-09-30T02:00:00.100000+00:00"
        );
        // Nonzero offsets convert to the same instant in UTC.
        assert_eq!(
            normalize_event_timestamp("2026-09-30T10:00:00+08:00"),
            "2026-09-30T02:00:00.000000+00:00"
        );
        assert_eq!(
            normalize_event_timestamp("2026-09-30T10:00:01+08:00"),
            "2026-09-30T02:00:01.000000+00:00"
        );
        // Z and naive wall times are UTC already.
        assert_eq!(
            normalize_event_timestamp("2026-09-30T02:00:00Z"),
            "2026-09-30T02:00:00.000000+00:00"
        );
        assert_eq!(
            normalize_event_timestamp("2026-09-01T10:00:00.000000"),
            "2026-09-01T10:00:00.000000+00:00"
        );
        // Unparseable input is preserved, never invented.
        assert_eq!(
            normalize_event_timestamp("not-a-timestamp"),
            "not-a-timestamp"
        );
        assert_eq!(normalize_event_timestamp("1728000000"), "1728000000");
    }
}
