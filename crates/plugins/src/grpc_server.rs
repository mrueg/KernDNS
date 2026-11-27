//! `grpc_server`: connection and stream limits of a DNS-over-gRPC
//! (`grpc://`) listener. Port of `plugin/grpc_server`.
//!
//! ```text
//! grpc_server {
//!     max_streams N       # HTTP/2 streams per connection, default 256, 0 = unbounded
//!     max_connections N   # default 200, 0 = unbounded
//! }
//! ```

use kerndns_core::{Controller, PluginFactory, SetupError};

use crate::listenopts::{Opt, parse};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "grpc_server"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        parse(
            c,
            &[
                Opt {
                    name: "max_streams",
                    positive: false,
                    max: None,
                    slot: |l| &mut l.grpc_max_streams,
                },
                Opt {
                    name: "max_connections",
                    positive: false,
                    max: None,
                    slot: |l| &mut l.grpc_max_connections,
                },
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listenopts::tests::{Case, Field, check};

    /// plugin/grpc_server/setup_test.go: (max_streams, max_connections).
    #[test]
    fn setup() {
        let fields: &[Field] = &[|l| l.grpc_max_streams, |l| l.grpc_max_connections];
        let cases: &[Case] = &[
            ("grpc_server", Ok(&[None, None])),
            ("grpc_server {\n}", Ok(&[None, None])),
            ("grpc_server {\nmax_streams 100\n}", Ok(&[Some(100), None])),
            ("grpc_server {\nmax_connections 200\n}", Ok(&[None, Some(200)])),
            (
                "grpc_server {\nmax_streams 50\nmax_connections 100\n}",
                Ok(&[Some(50), Some(100)]),
            ),
            ("grpc_server {\nmax_streams 0\n}", Ok(&[Some(0), None])),
            ("grpc_server {\nmax_connections 0\n}", Ok(&[None, Some(0)])),
            ("grpc_server {\nmax_streams\n}", Err("Wrong argument count")),
            ("grpc_server {\nmax_streams abc\n}", Err("invalid max_streams value")),
            (
                "grpc_server {\nmax_streams -1\n}",
                Err("must be a non-negative integer"),
            ),
            (
                "grpc_server {\nmax_streams 100\nmax_streams 200\n}",
                Err("already defined"),
            ),
            ("grpc_server {\nunknown_option 123\n}", Err("unknown property")),
            ("grpc_server extra_arg", Err("Wrong argument count")),
        ];
        check(&Setup, fields, cases);
    }
}
