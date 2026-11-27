//! `https`: connection and stream limits of a DoH (`https://`) listener.
//! Port of `plugin/https`.
//!
//! ```text
//! https {
//!     max_connections N   # default 200, 0 = unbounded
//!     max_streams N       # HTTP/2 streams per connection, default 250
//! }
//! ```

use kerndns_core::{Controller, PluginFactory, SetupError};

use crate::listenopts::{Opt, parse};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "https"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        parse(
            c,
            &[
                Opt {
                    name: "max_connections",
                    positive: false,
                    max: None,
                    slot: |l| &mut l.https_max_connections,
                },
                Opt {
                    name: "max_streams",
                    positive: false,
                    max: Some(u32::MAX as u64),
                    slot: |l| &mut l.https_max_streams,
                },
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listenopts::tests::{Case, Field, check};

    /// plugin/https/setup_test.go: (max_connections, max_streams).
    #[test]
    fn setup() {
        let fields: &[Field] = &[|l| l.https_max_connections, |l| l.https_max_streams];
        let cases: &[Case] = &[
            ("https", Ok(&[None, None])),
            ("https {\n}", Ok(&[None, None])),
            ("https {\nmax_connections 200\n}", Ok(&[Some(200), None])),
            ("https {\nmax_streams 100\n}", Ok(&[None, Some(100)])),
            (
                "https {\nmax_connections 200\nmax_streams 100\n}",
                Ok(&[Some(200), Some(100)]),
            ),
            ("https {\nmax_connections 0\n}", Ok(&[Some(0), None])),
            ("https {\nmax_connections\n}", Err("Wrong argument count")),
            ("https {\nmax_connections abc\n}", Err("invalid max_connections value")),
            ("https {\nmax_connections -1\n}", Err("must be a non-negative integer")),
            (
                "https {\nmax_connections 100\nmax_connections 200\n}",
                Err("already defined"),
            ),
            ("https {\nmax_streams\n}", Err("Wrong argument count")),
            ("https {\nmax_streams abc\n}", Err("invalid max_streams value")),
            ("https {\nmax_streams 0\n}", Ok(&[None, Some(0)])),
            ("https {\nmax_streams -1\n}", Err("must be a non-negative integer")),
            ("https {\nmax_streams 4294967295\n}", Ok(&[None, Some(4294967295)])),
            ("https {\nmax_streams 4294967296\n}", Err("must not exceed")),
            ("https {\nmax_streams 100\nmax_streams 200\n}", Err("already defined")),
            ("https {\nunknown_option 123\n}", Err("unknown property")),
            ("https extra_arg", Err("Wrong argument count")),
        ];
        check(&Setup, fields, cases);
    }

    #[test]
    fn messages() {
        let e = crate::testutil::setup_err(&Setup, "https {\nmax_streams 4294967296\n}");
        assert_eq!(
            e,
            "plugin/https: Corefile:3 - Error during parsing: max_streams must not exceed 4294967295: 4294967296"
        );
        let e = crate::testutil::setup_err(&Setup, "https {\nmax_connections x1\n}");
        assert_eq!(
            e,
            "plugin/https: Corefile:3 - Error during parsing: invalid max_connections value 'x1': \
             strconv.Atoi: parsing \"x1\": invalid syntax"
        );
    }
}
