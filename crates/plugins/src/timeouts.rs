//! `timeouts`: read, write and idle timeouts for TCP, DoT and DoH
//! connections (DoQ uses read and idle, DoH3 idle), and the query limit
//! for TCP and DoT connections. Port of `plugin/timeouts`.
//!
//! ```text
//! timeouts {
//!     read DURATION
//!     write DURATION
//!     idle DURATION
//!     maxtcpqueries N
//! }
//! ```

use kerndns_core::duration::parse_duration;
use kerndns_core::{Controller, PluginFactory, SetupError};

pub struct Setup;

/// `durations.NewDurationFromArg`: a Go duration, or seconds.
fn duration_arg(s: &str) -> Result<std::time::Duration, String> {
    if let Ok(n) = s.parse::<u64>() {
        return Ok(std::time::Duration::from_secs(n));
    }
    parse_duration(s).map_err(|_| format!("failed to parse duration: {s:?}"))
}

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "timeouts"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        while c.next() {
            if !c.remaining_args().is_empty() {
                return Err(c.arg_err());
            }
            let mut n = 0;
            while c.next_block() {
                let block = c.val().to_string();
                let args = c.remaining_args();
                if args.len() != 1 {
                    return Err(c.arg_err());
                }
                if block == "maxtcpqueries" {
                    let v: i64 = args[0]
                        .parse()
                        .map_err(|e| c.errf(format!("invalid value for maxtcpqueries '{}': {e}", args[0])))?;
                    if v == 0 || v < -1 {
                        return Err(c.errf(format!(
                            "maxtcpqueries provided '{v}' needs to be -1 (unlimited) or a positive integer"
                        )));
                    }
                    c.config.conn.max_tcp_queries = Some(v);
                    n += 1;
                    continue;
                }
                let d = duration_arg(&args[0]).map_err(|e| c.errf(e))?;
                if d < std::time::Duration::from_secs(1) || d > std::time::Duration::from_secs(86400) {
                    return Err(c.errf(format!(
                        "timeout provided '{}' needs to be between 1 second and 24 hours",
                        kerndns_core::duration::format_duration(d)
                    )));
                }
                match block.as_str() {
                    "read" => c.config.conn.read = Some(d),
                    "write" => c.config.conn.write = Some(d),
                    "idle" => c.config.conn.idle = Some(d),
                    other => return Err(c.errf(format!("unknown option: '{other}'"))),
                }
                n += 1;
            }
            if n == 0 {
                return Err(c.errf("timeouts block with no timeouts specified"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use std::time::Duration;

    #[test]
    fn setup() {
        let (r, cfg) = run_setup(
            &Setup,
            "timeouts {\n read 30s\n write 30\n idle 1m\n maxtcpqueries 5\n}",
        );
        assert!(r.is_ok());
        assert_eq!(cfg.conn.read, Some(Duration::from_secs(30)));
        assert_eq!(cfg.conn.write, Some(Duration::from_secs(30)));
        assert_eq!(cfg.conn.idle, Some(Duration::from_secs(60)));
        assert_eq!(cfg.conn.max_tcp_queries, Some(5));
        assert!(setup_err(&Setup, "timeouts {\n}").contains("no timeouts specified"));
        assert!(setup_err(&Setup, "timeouts {\n read 0.5s\n}").contains("between 1 second and 24 hours"));
        assert!(setup_err(&Setup, "timeouts {\n read 25h\n}").contains("between 1 second and 24 hours"));
        assert!(setup_err(&Setup, "timeouts {\n foo 5s\n}").contains("unknown option"));
        assert!(setup_err(&Setup, "timeouts {\n maxtcpqueries 0\n}").contains("needs to be -1"));
        assert!(!setup_err(&Setup, "timeouts 5s").is_empty());
    }
}
