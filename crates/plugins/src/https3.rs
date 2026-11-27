//! `https3`: connection and stream limits of a DoH3 (`https3://`)
//! listener. Port of `plugin/https3`.
//!
//! ```text
//! https3 {
//!     max_connections N   # default 200, 0 = unbounded
//!     max_streams N       # QUIC streams per connection, default 256, 0 = QUIC default
//! }
//! ```

use kerndns_core::{Controller, PluginFactory, SetupError};

use crate::listenopts::{Opt, parse};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "https3"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        parse(
            c,
            &[
                Opt {
                    name: "max_streams",
                    positive: false,
                    max: None,
                    slot: |l| &mut l.https3_max_streams,
                },
                Opt {
                    name: "max_connections",
                    positive: false,
                    max: None,
                    slot: |l| &mut l.https3_max_connections,
                },
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listenopts::tests::{Case, Field, check};

    /// plugin/https3/setup_test.go: (max_streams, max_connections).
    #[test]
    fn setup() {
        let fields: &[Field] = &[|l| l.https3_max_streams, |l| l.https3_max_connections];
        let cases: &[Case] = &[
            ("https3", Ok(&[None, None])),
            ("https3 {\n}", Ok(&[None, None])),
            ("https3 {\nmax_streams 100\n}", Ok(&[Some(100), None])),
            ("https3 {\nmax_streams 0\n}", Ok(&[Some(0), None])),
            ("https3 {\nmax_streams\n}", Err("Wrong argument count")),
            ("https3 {\nmax_streams abc\n}", Err("invalid max_streams value")),
            ("https3 {\nmax_streams -1\n}", Err("must be a non-negative integer")),
            ("https3 {\nmax_streams 100\nmax_streams 200\n}", Err("already defined")),
            ("https3 {\nunknown_option 123\n}", Err("unknown property")),
            ("https3 extra_arg", Err("Wrong argument count")),
            // not in the upstream table, but in its setup code
            ("https3 {\nmax_connections 3\n}", Ok(&[None, Some(3)])),
            ("https3 {\nmax_connections -3\n}", Err("must be a non-negative integer")),
        ];
        check(&Setup, fields, cases);
    }
}
