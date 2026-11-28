//! `ready`, `health` and `prometheus` stop their endpoint in a shutdown
//! hook and bind the same address again in the next configuration's
//! startup hook right after: on reload the port must already be free, as
//! it is once CoreDNS has closed its listener.
//!
//! This is its own test binary: cargo runs test binaries one at a time, so
//! no other test of the crate can bind the freed port (with port 0) in the
//! moment between stop and the next bind, which made it flaky as a unit
//! test.

use std::sync::Arc;

use kerndns_plugins::http::{Route, serve, text};

#[test]
fn stop_releases_the_port() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let route: Route = Arc::new(|_, _| text(200, "OK"));
    let mut ep = rt.block_on(async { serve("127.0.0.1:0", route.clone()) }).unwrap();
    for _ in 0..100 {
        let addr = ep.addr;
        ep.stop();
        ep = rt
            .block_on(async { serve(&addr.to_string(), route.clone()) })
            .unwrap_or_else(|e| panic!("bind {addr} after stop: {e}"));
    }
    ep.stop();
}
