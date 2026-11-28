//! The KernDNS plugin model.
//!
//! This mirrors CoreDNS closely so that plugins can be ported one to one:
//!
//! | CoreDNS (Go)                  | KernDNS                          |
//! |-------------------------------|----------------------------------|
//! | `plugin.Handler`              | [`Handler`]                      |
//! | `dns.ResponseWriter`          | [`ResponseWriter`]               |
//! | `request.Request`             | [`Request`]                      |
//! | `plugin.Plugin`               | [`PluginFn`]                     |
//! | `caddy.Controller`            | [`Controller`]                   |
//! | `dnsserver.Config`            | [`BlockConfig`]                  |
//! | `plugin.ClientWrite`          | [`client_write`]                 |
//! | `plugin.NextOrFailure`        | [`next_or_failure`]              |
//! | `plugin.cfg`                  | [`order::DIRECTIVES`]            |
//!
//! Messages are hickory-proto [`Message`](proto::op::Message)s.

pub mod address;
pub mod duration;
pub mod handler;
pub mod log;
pub mod metrics;
pub mod order;
pub mod plugin;
pub mod protobuf;
pub mod proxyproto;
pub mod random;
pub mod readiness;
pub mod reload;
pub mod request;
pub mod response;
pub mod trace;
pub mod transfer;
pub mod typify;
pub mod udpwrite;
pub mod upstream;
pub mod wire;
pub mod zones;

pub use hickory_proto as proto;
pub use kerndns_corefile as corefile;

pub use address::{Transport, ZoneAddr};
pub use handler::{
    Context, Handler, HandlerResult, Next, PluginError, ResponseSigner, client_write, next_or_failure, result_rcode,
};
pub use plugin::{
    BlockConfig, Controller, Event, EventHook, Hooks, PluginFactory, PluginFn, Registry, RestartHook, SetupError,
};
pub use request::{ConnInfo, Protocol, Request};
pub use response::{CaptureWriter, Recorder, ResponseWriter};
pub use upstream::Upstream;
pub use zones::Fall;

/// Re-exported so plugins don't need their own dependency.
pub use async_trait::async_trait;

/// The KernDNS version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
