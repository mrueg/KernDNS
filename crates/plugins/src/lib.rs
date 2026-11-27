//! Native Rust ports of CoreDNS plugins.
//!
//! Each module is a port of the plugin with the same name in CoreDNS
//! v1.15.0 and keeps its Corefile syntax and output format.

pub mod any;
pub mod backend;
pub mod bind;
pub mod bufsize;
pub mod cache;
pub mod chaos;
pub mod debug;
pub mod dynupdate;
pub mod errors;
pub mod file;
pub mod forward;
pub mod header;
pub mod health;
pub mod hosts;
pub mod http;
pub mod loadbalance;
pub mod log;
pub mod loopdetect;
pub mod metrics;
pub mod minimal;
pub mod nsid;
pub mod pluginmetrics;
pub mod ready;
pub mod reload;
pub mod root;
pub mod secondary;
pub mod tls;
pub mod tlsconfig;
pub mod transfer;
pub mod tsig;
pub mod whoami;

#[cfg(test)]
pub(crate) mod testutil;

use kerndns_core::Registry;

/// A registry with every plugin in this crate.
pub fn registry() -> Registry {
    let mut r = Registry::new();
    r.register(bind::Setup);
    r.register(cache::Setup);
    r.register(chaos::Setup);
    r.register(debug::Setup);
    r.register(errors::Setup);
    r.register(file::Setup);
    r.register(forward::Setup);
    r.register(header::Setup);
    r.register(health::Setup);
    r.register(hosts::Setup);
    r.register(log::Setup);
    r.register(loopdetect::Setup);
    r.register(metrics::Setup);
    r.register(ready::Setup);
    r.register(reload::Setup);
    r.register(root::Setup);
    r.register(secondary::Setup);
    r.register(dynupdate::Setup);
    r.register(tls::Setup);
    r.register(transfer::Setup);
    r.register(tsig::Setup);
    r.register(whoami::Setup);
    r.register(any::Setup);
    r.register(bufsize::Setup);
    r.register(loadbalance::Setup);
    r.register(minimal::Setup);
    r.register(nsid::Setup);
    r
}
