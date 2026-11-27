//! Replays the table tests of CoreDNS's plugins against KernDNS.
//!
//! `testdata/plugin_cases/<plugin>.json` holds every table literal of the
//! plugin's Go tests, evaluated in the Go package by `cargo xtask
//! plugin-cases` (see `go/plugincases`), and the package's string
//! constants (zone files). The drivers here set up the same plugin through
//! a Corefile, run each row as the Go test does and check it with the
//! same comparison (`test.SortAndCheck` and friends, see `harness`).
//!
//! Every table must be run or listed in `expectations.txt` with a reason,
//! and every row must pass unless it is listed there as `xfail`.

mod harness;

mod file;
mod hosts;

use harness::Run;

macro_rules! plugin_test {
    ($name:ident, $module:ident) => {
        #[tokio::test]
        async fn $name() {
            let mut r = Run::load(stringify!($name));
            $module::drive(&mut r).await;
            r.finish();
        }
    };
}

plugin_test!(file, file);
plugin_test!(hosts, hosts);
