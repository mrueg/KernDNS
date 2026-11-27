//! `multisocket`: the number of `SO_REUSEPORT` servers (a UDP socket and
//! a TCP listener each) per listen address. Port of `plugin/multisocket`.
//!
//! ```text
//! multisocket [NUM_SOCKETS]
//! ```
//!
//! Without an argument it is the number of CPUs (Go's `GOMAXPROCS`). The
//! first server block that binds an address decides its value.

use kerndns_core::{Controller, PluginFactory, SetupError};

const MAX_NUM_SOCKETS: usize = 1024;

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "multisocket"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        c.next(); // "multisocket"
        let args = c.remaining_args();
        if args.len() > 1 || c.next() {
            return Err(c.arg_err());
        }
        let Some(arg) = args.first() else {
            // the default, like GOMAXPROCS
            c.config.num_sockets = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
            return Ok(());
        };
        let n: i64 = arg.parse().map_err(|e: std::num::ParseIntError| {
            let why = match e.kind() {
                std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow => "value out of range",
                _ => "invalid syntax",
            };
            SetupError::new(
                "multisocket",
                format!("invalid num sockets: strconv.Atoi: parsing {arg:?}: {why}"),
            )
        })?;
        if n < 1 {
            return Err(SetupError::new(
                "multisocket",
                format!("num sockets can not be zero or negative: {n}"),
            ));
        }
        if n as usize > MAX_NUM_SOCKETS {
            return Err(SetupError::new(
                "multisocket",
                format!("num sockets exceeds maximum ({MAX_NUM_SOCKETS}): {n}"),
            ));
        }
        c.config.num_sockets = n as usize;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    // multisocket_test.go: TestMultisocket
    #[test]
    fn multisocket() {
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let tests: &[(&str, bool, usize, &str)] = &[
            ("multisocket", false, cpus, ""),
            ("multisocket 2", false, 2, ""),
            ("multisocket 1024", false, 1024, ""),
            (" multisocket 1", false, 1, ""),
            ("multisocket text", true, 0, "invalid num sockets"),
            ("multisocket 0", true, 0, "num sockets can not be zero or negative"),
            ("multisocket -1", true, 0, "num sockets can not be zero or negative"),
            ("multisocket 1025", true, 0, "num sockets exceeds maximum"),
            (
                "multisocket 2 2",
                true,
                0,
                "Wrong argument count or unexpected line ending after '2'",
            ),
            (
                "multisocket 2 {\n block\n}",
                true,
                0,
                "Unexpected token '{', expecting argument",
            ),
        ];
        for (i, (input, should_err, want, err_content)) in tests.iter().enumerate() {
            let (res, cfg) = run_setup(&Setup, input);
            match res {
                Ok(()) => assert!(!should_err, "test {i}: expected an error for {input:?}"),
                Err(e) => {
                    assert!(should_err, "test {i}: unexpected error {e}");
                    assert!(e.contains(err_content), "test {i}: {e:?} lacks {err_content:?}");
                }
            }
            assert_eq!(cfg.num_sockets, *want, "test {i}");
        }
        assert_eq!(
            setup_err(&Setup, "multisocket text"),
            "plugin/multisocket: invalid num sockets: strconv.Atoi: parsing \"text\": invalid syntax"
        );
    }
}
