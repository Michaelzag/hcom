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
}
