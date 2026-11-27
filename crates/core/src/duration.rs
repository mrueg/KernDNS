//! Go's `time.ParseDuration` and `Duration.String`, so Corefile durations
//! (`30s`, `1m30s`, `1h`) are accepted and printed the way CoreDNS does.

use std::time::Duration;

/// Parse a Go duration string. Negative durations are rejected.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let err = || format!("time: invalid duration {s:?}");
    let mut rest = s.strip_prefix('+').unwrap_or(s);
    if rest.starts_with('-') {
        return Err(format!("time: negative duration {s:?}"));
    }
    if rest == "0" {
        return Ok(Duration::ZERO);
    }
    if rest.is_empty() {
        return Err(err());
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let num_end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).ok_or_else(err)?;
        if num_end == 0 {
            return Err(err());
        }
        let value: f64 = rest[..num_end].parse().map_err(|_| err())?;
        rest = &rest[num_end..];
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let nanos = match &rest[..unit_end] {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            "" => return Err(format!("time: missing unit in duration {s:?}")),
            u => return Err(format!("time: unknown unit {u:?} in duration {s:?}")),
        };
        total += value * nanos;
        rest = &rest[unit_end..];
    }
    Ok(Duration::from_nanos(total.round() as u64))
}

/// Format like Go's `Duration.String` for whole seconds and above (`1m0s`, `1h30m0s`, `250ms`).
pub fn format_duration(d: Duration) -> String {
    let total = d.as_nanos();
    if total == 0 {
        return "0s".into();
    }
    if total < 1_000_000_000 {
        let ms = d.as_secs_f64() * 1e3;
        return if total.is_multiple_of(1_000_000) {
            format!("{ms}ms")
        } else {
            format!("{}µs", d.as_secs_f64() * 1e6)
        };
    }
    let secs = d.as_secs();
    let frac = d.subsec_nanos();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let s = if frac == 0 {
        format!("{s}s")
    } else {
        format!("{}s", s as f64 + frac as f64 / 1e9)
    };
    match (h, m) {
        (0, 0) => s,
        (0, m) => format!("{m}m{s}"),
        (h, m) => format!("{h}h{m}m{s}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("1.5h").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("100ms").unwrap(), Duration::from_millis(100));
        assert!(parse_duration("10").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("-1s").is_err());
    }

    #[test]
    fn format() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1m0s");
        assert_eq!(format_duration(Duration::from_secs(5400)), "1h30m0s");
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_millis(250)), "250ms");
    }
}
