//! `reload`: reloads the Corefile when it changes. Port of `plugin/reload`.
//!
//! ```text
//! reload [INTERVAL] [JITTER]
//! ```
//!
//! The check itself runs in the `kerndns` binary, which compares a hash of
//! the parsed Corefile every INTERVAL (± JITTER/2) and swaps in the new
//! configuration without closing listeners that stay the same.

use std::time::Duration;

use kerndns_core::duration::{format_duration, parse_duration};
use kerndns_core::{Controller, PluginFactory, SetupError};

const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_JITTER: Duration = Duration::from_secs(15);
const MIN_INTERVAL: Duration = Duration::from_secs(2);
const MIN_JITTER: Duration = Duration::from_secs(1);

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "reload"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let err = |m: String| SetupError::new("reload", m);
        c.next();
        let args = c.remaining_args();
        if args.len() > 2 {
            return Err(c.arg_err());
        }
        let mut i = match args.first() {
            Some(a) => parse_duration(a).map_err(err)?,
            None => DEFAULT_INTERVAL,
        };
        if i < MIN_INTERVAL {
            return Err(err(format!(
                "interval value must be greater or equal to {}",
                format_duration(MIN_INTERVAL)
            )));
        }
        let mut j = match args.get(1) {
            Some(a) => parse_duration(a).map_err(err)?,
            None => DEFAULT_JITTER,
        };
        if !j.is_zero() && j < MIN_JITTER {
            return Err(err(format!(
                "jitter value must be 0 or greater or equal to {}",
                format_duration(MIN_JITTER)
            )));
        }
        if j > i / 2 {
            j = i / 2;
        }
        if !j.is_zero() {
            let n = j.as_nanos() as i128;
            let r = kerndns_core::random::rand_below(n as usize) as i128 - n / 2;
            i = Duration::from_nanos((i.as_nanos() as i128 + r).max(0) as u64);
        }
        kerndns_core::reload::enable(i);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "reload"));
        assert!(setup_ok(&Setup, "reload 10s 2s"));
        assert!(setup_err(&Setup, "reload 1s").contains("greater or equal to 2s"));
        assert!(setup_err(&Setup, "reload 10s 500ms").contains("jitter value must be 0"));
        assert!(setup_err(&Setup, "reload 1 2 3").contains("Wrong argument count"));
    }
}
