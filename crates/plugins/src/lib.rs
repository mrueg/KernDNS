//! Native Rust ports of CoreDNS plugins.
//!
//! Each module is a port of the plugin with the same name in CoreDNS
//! v1.15.0 and keeps its Corefile syntax and output format.

pub mod acl;
pub mod any;
pub mod auto;
pub mod autopath;
pub mod backend;
pub mod bind;
pub mod bufsize;
pub mod cache;
pub mod cancel;
pub mod chaos;
pub mod debug;
pub mod dns64;
pub mod dnssec;
pub mod dnstap;
pub mod dynupdate;
pub mod erratic;
pub mod errors;
pub mod expr;
pub mod file;
pub mod forward;
pub mod grpc;
pub mod grpc_server;
pub mod header;
pub mod health;
pub mod hosts;
pub mod http;
pub mod https;
pub mod https3;
mod listenopts;
pub mod loadbalance;
pub mod local;
pub mod log;
pub mod loopdetect;
pub mod metadata;
pub mod metrics;
pub mod minimal;
pub mod multisocket;
pub mod nsid;
pub mod pluginmetrics;
pub mod quic;
pub mod ready;
pub mod reload;
pub mod rewrite;
pub mod root;
pub mod secondary;
pub mod template;
pub mod timeouts;
pub mod tls;
pub mod tlsconfig;
pub mod transfer;
pub mod tsig;
pub mod view;
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
    r.register(dnstap::Setup);
    r.register(errors::Setup);
    r.register(file::Setup);
    r.register(forward::Setup);
    r.register(grpc::Setup);
    r.register(header::Setup);
    r.register(health::Setup);
    r.register(hosts::Setup);
    r.register(log::Setup);
    r.register(loopdetect::Setup);
    r.register(metrics::Setup);
    r.register(ready::Setup);
    r.register(reload::Setup);
    r.register(rewrite::Setup);
    r.register(root::Setup);
    r.register(secondary::Setup);
    r.register(template::Setup);
    r.register(dynupdate::Setup);
    r.register(erratic::Setup);
    r.register(tls::Setup);
    r.register(transfer::Setup);
    r.register(tsig::Setup);
    r.register(whoami::Setup);
    r.register(any::Setup);
    r.register(bufsize::Setup);
    r.register(loadbalance::Setup);
    r.register(minimal::Setup);
    r.register(nsid::Setup);
    r.register(acl::Setup);
    r.register(cancel::Setup);
    r.register(local::Setup);
    r.register(metadata::Setup);
    r.register(timeouts::Setup);
    r.register(view::Setup);
    r.register(autopath::Setup);
    r.register(dns64::Setup);
    r.register(auto::Setup);
    r.register(multisocket::Setup);
    r.register(https::Setup);
    r.register(https3::Setup);
    r.register(grpc_server::Setup);
    r.register(quic::Setup);
    r.register(dnssec::Setup);
    r
}
