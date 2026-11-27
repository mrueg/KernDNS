//! `quic`: connection and stream limits of a DNS-over-QUIC (`quic://`)
//! listener. Port of `plugin/quic`.
//!
//! ```text
//! quic {
//!     max_streams N        # streams per connection, default 256
//!     max_connections N    # default 200, 0 = unbounded
//!     worker_pool_size N   # streams served at once, default 1024
//! }
//! ```

use kerndns_core::{Controller, PluginFactory, SetupError};

use crate::listenopts::{Opt, parse};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        parse(
            c,
            &[
                Opt {
                    name: "max_streams",
                    positive: true,
                    max: None,
                    slot: |l| &mut l.quic_max_streams,
                },
                Opt {
                    name: "max_connections",
                    positive: false,
                    max: None,
                    slot: |l| &mut l.quic_max_connections,
                },
                Opt {
                    name: "worker_pool_size",
                    positive: true,
                    max: None,
                    slot: |l| &mut l.quic_worker_pool_size,
                },
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listenopts::tests::{Case, Field, check};
    use crate::testutil::run_setup;

    /// plugin/quic/setup_test.go: (max_streams, max_connections, worker_pool_size).
    #[test]
    fn setup() {
        let fields: &[Field] = &[
            |l| l.quic_max_streams,
            |l| l.quic_max_connections,
            |l| l.quic_worker_pool_size,
        ];
        let cases: &[Case] = &[
            ("quic", Ok(&[None, None, None])),
            ("quic {\n}", Ok(&[None, None, None])),
            ("quic {\nmax_streams 100\n}", Ok(&[Some(100), None, None])),
            ("quic {\nmax_connections 50\n}", Ok(&[None, Some(50), None])),
            ("quic {\nmax_connections 0\n}", Ok(&[None, Some(0), None])),
            ("quic {\nworker_pool_size 1000\n}", Ok(&[None, None, Some(1000)])),
            (
                "quic {\nmax_streams 100\nmax_connections 50\nworker_pool_size 1000\n}",
                Ok(&[Some(100), Some(50), Some(1000)]),
            ),
            ("quic {\n# Comment\n}", Ok(&[None, None, None])),
            ("quic arg", Err("Wrong argument count")),
            ("quic {\nmax_streams\n}", Err("Wrong argument count")),
            ("quic {\nmax_streams abc\n}", Err("invalid max_streams value")),
            ("quic {\nmax_streams 0\n}", Err("positive integer")),
            ("quic {\nmax_streams -10\n}", Err("positive integer")),
            ("quic {\nmax_connections\n}", Err("Wrong argument count")),
            ("quic {\nmax_connections abc\n}", Err("invalid max_connections value")),
            ("quic {\nmax_connections -10\n}", Err("non-negative integer")),
            (
                "quic {\nmax_connections 50\nmax_connections 100\n}",
                Err("already defined"),
            ),
            ("quic {\nmax_connections 100 200\n}", Err("Wrong argument count")),
            ("quic {\nworker_pool_size\n}", Err("Wrong argument count")),
            ("quic {\nworker_pool_size abc\n}", Err("invalid worker_pool_size value")),
            ("quic {\nworker_pool_size 0\n}", Err("positive integer")),
            ("quic {\nworker_pool_size -10\n}", Err("positive integer")),
            ("quic {\nmax_streams 100\nmax_streams 200\n}", Err("already defined")),
            (
                "quic {\nworker_pool_size 1000\nworker_pool_size 2000\n}",
                Err("already defined"),
            ),
            ("quic {\nunknown_directive\n}", Err("unknown property")),
            ("quic {\nmax_streams 100 200\n}", Err("Wrong argument count")),
            ("quic {\nworker_pool_size 1000 2000\n}", Err("Wrong argument count")),
        ];
        check(&Setup, fields, cases);
    }

    /// Upstream also checks that the first value stays set when a second
    /// one is rejected.
    #[test]
    fn already_defined_keeps_first() {
        let (res, cfg) = run_setup(&Setup, "quic {\nmax_streams 100\nmax_streams 200\n}");
        assert!(res.unwrap_err().contains("already defined"));
        assert_eq!(cfg.limits.quic_max_streams, Some(100));
        let (_, cfg) = run_setup(&Setup, "quic {\nmax_connections 50\nmax_connections 100\n}");
        assert_eq!(cfg.limits.quic_max_connections, Some(50));
        let (_, cfg) = run_setup(&Setup, "quic {\nworker_pool_size 1000\nworker_pool_size 2000\n}");
        assert_eq!(cfg.limits.quic_worker_pool_size, Some(1000));
    }
}
