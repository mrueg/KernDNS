//! Replays the table tests of CoreDNS's plugins against KernDNS.
//!
//! `testdata/plugin_cases/<plugin>.json` holds every table literal of the
//! plugin's Go tests, evaluated in the Go package by `cargo xtask
//! plugin-cases` (see `go/plugincases`), and the package's string
//! constants (zone files). The drivers here set up the same plugin through
//! a Corefile, run each row as the Go test does and check it with the
//! same comparison (`test.SortAndCheck` and friends, see `harness`).
//! Setup tables (`{input, shouldErr}`) run for every plugin
//! ([`harness::Run::auto_setup`]).
//!
//! Every table must be run or listed in `expectations.txt` with a reason,
//! and every row must pass unless it is listed there as `xfail`.

mod harness;

mod chains;
mod file;
mod hosts;
mod policy;
mod rewrite;
mod small;
mod synth;
mod template;

use harness::Run;

/// Plugins whose only drivable tables are setup tables.
async fn setup_only(_: &mut Run) {}

macro_rules! plugin_test {
    ($name:ident, $drive:path) => {
        #[tokio::test]
        async fn $name() {
            let mut r = Run::load(stringify!($name));
            $drive(&mut r).await;
            r.auto_setup();
            r.finish();
        }
    };
}

plugin_test!(acl, policy::acl);
plugin_test!(any, small::any);
plugin_test!(auto, setup_only);
plugin_test!(autopath, chains::autopath);
plugin_test!(bufsize, setup_only);
plugin_test!(cache, chains::cache);
plugin_test!(chaos, small::chaos);
plugin_test!(debug, setup_only);
plugin_test!(dns64, synth::dns64);
plugin_test!(dnssec, chains::dnssec);
plugin_test!(dnstap, setup_only);
plugin_test!(dynupdate, setup_only);
plugin_test!(erratic, chains::erratic);
plugin_test!(errors, setup_only);
plugin_test!(file, file::drive);
plugin_test!(forward, policy::forward);
plugin_test!(geoip, setup_only);
plugin_test!(grpc, setup_only);
plugin_test!(grpc_server, setup_only);
plugin_test!(header, small::header);
plugin_test!(health, setup_only);
plugin_test!(hosts, hosts::drive);
plugin_test!(https, setup_only);
plugin_test!(https3, setup_only);
plugin_test!(loadbalance, setup_only);
plugin_test!(local, small::local);
plugin_test!(log, setup_only);
plugin_test!(r#loop, setup_only);
plugin_test!(metadata, setup_only);
plugin_test!(metrics, setup_only);
plugin_test!(minimal, small::minimal);
plugin_test!(multisocket, setup_only);
plugin_test!(nsid, chains::nsid);
plugin_test!(pprof, setup_only);
plugin_test!(proxyproto, setup_only);
plugin_test!(quic, setup_only);
plugin_test!(ready, setup_only);
plugin_test!(rewrite, rewrite::drive);
plugin_test!(root, setup_only);
plugin_test!(secondary, setup_only);
plugin_test!(shed, setup_only);
plugin_test!(sign, setup_only);
plugin_test!(siit, synth::siit);
plugin_test!(template, template::drive);
plugin_test!(timeouts, setup_only);
plugin_test!(tls, policy::tls);
plugin_test!(trace, setup_only);
plugin_test!(transfer, setup_only);
plugin_test!(tsig, setup_only);
plugin_test!(view, setup_only);
plugin_test!(whoami, small::whoami);
