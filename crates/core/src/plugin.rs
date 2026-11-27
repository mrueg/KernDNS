//! Plugin setup: the registry of plugin factories, the per-block
//! configuration they write into, and the controller they get from the
//! Corefile (the counterpart of `caddy.Controller` + `dnsserver.Config`).

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;

use kerndns_corefile::{Dispenser, ParseError};

use crate::address::{Transport, ZoneAddr};
use crate::handler::{Context, Handler, Next};
use crate::request::Request;

/// Builds a plugin's handler around the rest of the chain, like CoreDNS's
/// `plugin.Plugin` (`func(next Handler) Handler`). It is called once per
/// zone key of the server block.
pub type PluginFn = Arc<dyn Fn(Next) -> Arc<dyn Handler> + Send + Sync>;

/// An error from a plugin's setup, shown as `plugin/<name>: <cause>`.
#[derive(Debug, thiserror::Error)]
#[error("plugin/{plugin}: {msg}")]
pub struct SetupError {
    pub plugin: String,
    pub msg: String,
}

impl SetupError {
    pub fn new(plugin: impl Into<String>, msg: impl std::fmt::Display) -> Self {
        Self {
            plugin: plugin.into(),
            msg: msg.to_string(),
        }
    }
}

/// Creates a plugin from its Corefile directive.
pub trait PluginFactory: Send + Sync {
    /// The directive name.
    fn name(&self) -> &'static str;

    /// Parse the directive's tokens (all occurrences in one server block)
    /// and register a handler with [`Controller::add_plugin`] and/or change
    /// the block configuration.
    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError>;

    /// True for plugins that run in Go through the bridge.
    fn bridged(&self) -> bool {
        false
    }
}

/// The plugins compiled into this binary.
#[derive(Default, Clone)]
pub struct Registry {
    plugins: HashMap<&'static str, Arc<dyn PluginFactory>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, f: impl PluginFactory + 'static) {
        self.plugins.insert(f.name(), Arc::new(f));
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn PluginFactory>> {
        self.plugins.get(name)
    }

    /// Registered plugin names in execution order.
    pub fn names(&self) -> Vec<&'static str> {
        let mut v: Vec<_> = self.plugins.keys().copied().collect();
        v.sort_by_key(|n| crate::order::position(n).unwrap_or(usize::MAX));
        v
    }
}

/// Type-keyed storage for configuration that plugins share within one
/// server block (e.g. the `tls` plugin's config read by the listener).
#[derive(Default)]
pub struct Extensions {
    map: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Extensions {
    pub fn insert<T: Any + Send + Sync>(&mut self, v: T) {
        self.map.insert(TypeId::of::<T>(), Box::new(v));
    }

    pub fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.map.get(&TypeId::of::<T>()).and_then(|b| b.downcast_ref())
    }

    pub fn get_mut<T: Any + Send + Sync>(&mut self) -> Option<&mut T> {
        self.map.get_mut(&TypeId::of::<T>()).and_then(|b| b.downcast_mut())
    }
}

/// Configuration of one server block, like `dnsserver.Config`.
pub struct BlockConfig {
    /// The keys of the block, normalized.
    pub keys: Vec<ZoneAddr>,
    pub transport: Transport,
    pub port: String,
    /// Addresses to listen on (`bind`). Empty means all interfaces.
    pub listen_hosts: Vec<String>,
    /// `debug`: log more and don't recover from handler panics.
    pub debug: bool,
    /// `root`: base directory for relative file paths.
    pub root: Option<PathBuf>,
    /// The CHAOS class is allowed (set by `chaos`).
    pub class_chaos: bool,
    /// Server TLS for `tls://` and `https://` keys (set by `tls`).
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// UPDATE requests reach the chain (`AllowOpcode`, set by `dynupdate`);
    /// otherwise the server answers NOTIMP like miekg/dns.
    pub allow_update: bool,
    /// Decide whether this block handles a request (`FilterFuncs`, set by
    /// `view`); blocks with filters may share a zone with other blocks.
    pub filters: Vec<Arc<dyn RequestFilter>>,
    /// `ViewName`, from `view`.
    pub view_name: Option<String>,
    /// Connection timeouts and limits for TCP/DoT (`timeouts`).
    pub conn: ConnLimits,
    /// Handlers registered by setup, with their directive names, in the
    /// order setup ran (which is the execution order).
    pub plugins: Vec<(&'static str, PluginFn)>,
    pub extensions: Extensions,
}

impl BlockConfig {
    pub fn new(keys: Vec<ZoneAddr>) -> Self {
        let transport = keys.first().map(|k| k.transport).unwrap_or(Transport::Dns);
        let port = keys.first().map(|k| k.port.clone()).unwrap_or_default();
        Self {
            keys,
            transport,
            port,
            listen_hosts: Vec::new(),
            debug: false,
            root: None,
            class_chaos: false,
            tls: None,
            allow_update: false,
            filters: Vec::new(),
            view_name: None,
            conn: ConnLimits::default(),
            plugins: Vec::new(),
            extensions: Extensions::default(),
        }
    }

    /// Build the handler chain: the first registered plugin runs first.
    pub fn chain(&self) -> Next {
        let mut next: Next = None;
        for (_, f) in self.plugins.iter().rev() {
            next = Some(f(next));
        }
        next
    }
}

type StartupHook = Box<dyn FnOnce() -> Result<(), String> + Send>;
type ShutdownHook = Box<dyn FnOnce() + Send>;

/// Lifecycle callbacks registered during setup.
#[derive(Default)]
pub struct Hooks {
    pub startup: Vec<(&'static str, StartupHook)>,
    pub shutdown: Vec<(&'static str, ShutdownHook)>,
}

/// What a plugin's setup gets: a [`Dispenser`] over its tokens (available
/// through `Deref`), the block configuration and the lifecycle hooks.
pub struct Controller<'a> {
    dispenser: Dispenser,
    directive: &'static str,
    pub config: &'a mut BlockConfig,
    hooks: &'a mut Hooks,
    /// Directory of the Corefile, for relative paths.
    pub corefile_dir: PathBuf,
}

impl<'a> Controller<'a> {
    pub fn new(
        directive: &'static str,
        dispenser: Dispenser,
        config: &'a mut BlockConfig,
        hooks: &'a mut Hooks,
        corefile_dir: PathBuf,
    ) -> Self {
        Self {
            dispenser,
            directive,
            config,
            hooks,
            corefile_dir,
        }
    }

    pub fn directive(&self) -> &'static str {
        self.directive
    }

    /// Zones of the server block, normalized (`example.org.`).
    pub fn server_block_keys(&self) -> Vec<String> {
        self.config.keys.iter().map(|k| k.zone.clone()).collect()
    }

    /// Add this directive's handler to the chain.
    pub fn add_plugin(&mut self, f: impl Fn(Next) -> Arc<dyn Handler> + Send + Sync + 'static) {
        self.config.plugins.push((self.directive, Arc::new(f)));
    }

    /// Run `f` after all plugins are set up and before serving starts.
    pub fn on_startup(&mut self, f: impl FnOnce() -> Result<(), String> + Send + 'static) {
        self.hooks.startup.push((self.directive, Box::new(f)));
    }

    /// Run `f` when the server shuts down (or reloads).
    pub fn on_shutdown(&mut self, f: impl FnOnce() + Send + 'static) {
        self.hooks.shutdown.push((self.directive, Box::new(f)));
    }

    /// Wrap a parse error as this plugin's setup error, like `plugin.Error`.
    pub fn error(&self, e: ParseError) -> SetupError {
        SetupError::new(self.directive, e)
    }

    /// `Wrong argument count ...` at the current token, as a setup error.
    pub fn arg_err(&self) -> SetupError {
        self.error(self.dispenser.arg_err())
    }

    /// `Syntax error: Unexpected token ...` at the current token, as a setup error.
    pub fn syntax_err(&self, expected: &str) -> SetupError {
        self.error(self.dispenser.syntax_err(expected))
    }

    /// A custom error at the current token, as a setup error.
    pub fn errf(&self, msg: impl Into<String>) -> SetupError {
        self.error(self.dispenser.err(msg))
    }
}

impl Deref for Controller<'_> {
    type Target = Dispenser;
    fn deref(&self) -> &Dispenser {
        &self.dispenser
    }
}

impl DerefMut for Controller<'_> {
    fn deref_mut(&mut self) -> &mut Dispenser {
        &mut self.dispenser
    }
}

/// Zones whose answers `cache` must not serve or store, registered by
/// authoritative plugins with mutable data (`cache.ZoneBypasser`).
#[derive(Clone, Default)]
pub struct CacheBypass(Arc<std::sync::RwLock<Vec<String>>>);

impl CacheBypass {
    /// The list of this block (created on first use).
    pub fn of(cfg: &mut BlockConfig) -> CacheBypass {
        if cfg.extensions.get::<CacheBypass>().is_none() {
            cfg.extensions.insert(CacheBypass::default());
        }
        cfg.extensions.get::<CacheBypass>().cloned().expect("inserted above")
    }

    pub fn add(&self, zone: String) {
        self.0.write().unwrap().push(zone);
    }

    /// Is `name` in (or below) one of the bypassed zones?
    pub fn contains(&self, name: &str) -> bool {
        let z = self.0.read().unwrap();
        !z.is_empty() && crate::zones::matches(&z, name).is_some()
    }
}

/// The directives of a block that added a handler, filled in once every
/// plugin of the block is set up. Plugins that look another plugin up by
/// name at startup (`dnsserver.GetConfig(c).Handler(name)`) check here
/// whether it is loaded at all.
#[derive(Clone, Default)]
pub struct BlockHandlers(Arc<std::sync::OnceLock<Vec<&'static str>>>);

impl BlockHandlers {
    /// The list of this block (created on first use).
    pub fn of(cfg: &mut BlockConfig) -> BlockHandlers {
        if cfg.extensions.get::<BlockHandlers>().is_none() {
            cfg.extensions.insert(BlockHandlers::default());
        }
        cfg.extensions.get::<BlockHandlers>().cloned().expect("inserted above")
    }

    /// Record the block's handlers (the server does this after setup).
    pub fn fill(cfg: &mut BlockConfig) {
        let names = cfg.plugins.iter().map(|(n, _)| *n).collect();
        let _ = BlockHandlers::of(cfg).0.set(names);
    }

    /// Whether the block has a handler for `name`.
    pub fn contains(&self, name: &str) -> bool {
        self.0.get().is_some_and(|v| v.contains(&name))
    }
}

/// `dnsserver.FilterFunc`: whether a server block handles a request.
pub trait RequestFilter: Send + Sync {
    fn filter(&self, ctx: &Context, req: &Request) -> bool;
}

/// `metadata.Provider`: a plugin that adds values to
/// [`Context::metadata`] before the block's filters and plugins run.
pub trait MetadataProvider: Send + Sync {
    fn metadata(&self, ctx: &mut Context, req: &Request);
}

#[derive(Default)]
struct MetadataInner {
    /// Set when the `metadata` plugin is enabled in the block.
    zones: Option<Vec<String>>,
    providers: Vec<Arc<dyn MetadataProvider>>,
}

/// The block's metadata providers, collected by the `metadata` plugin
/// (`metadata.Collect`) for requests in its zones.
#[derive(Clone, Default)]
pub struct Metadata(Arc<std::sync::RwLock<MetadataInner>>);

impl Metadata {
    /// The registry of this block (created on first use).
    pub fn of(cfg: &mut BlockConfig) -> Metadata {
        if cfg.extensions.get::<Metadata>().is_none() {
            cfg.extensions.insert(Metadata::default());
        }
        cfg.extensions.get::<Metadata>().cloned().expect("inserted above")
    }

    /// The block's collector, if the `metadata` plugin is enabled.
    pub fn enabled_in(cfg: &BlockConfig) -> Option<Metadata> {
        cfg.extensions
            .get::<Metadata>()
            .filter(|m| m.0.read().unwrap().zones.is_some())
            .cloned()
    }

    pub fn add_provider(&self, p: Arc<dyn MetadataProvider>) {
        self.0.write().unwrap().providers.push(p);
    }

    /// Collect for requests in `zones` (`metadata` plugin setup).
    pub fn enable(&self, zones: Vec<String>) {
        self.0.write().unwrap().zones = Some(zones);
    }

    pub fn collect(&self, ctx: &mut Context, req: &Request) {
        let inner = self.0.read().unwrap();
        let Some(zones) = &inner.zones else { return };
        if crate::zones::matches(zones, &req.name()).is_none() {
            return;
        }
        for p in &inner.providers {
            p.metadata(ctx, req);
        }
    }
}

/// `ReadTimeout`, `WriteTimeout`, `IdleTimeout` and `MaxTCPQueries` of a
/// server block; `None` keeps the server's default.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ConnLimits {
    pub read: Option<std::time::Duration>,
    pub write: Option<std::time::Duration>,
    pub idle: Option<std::time::Duration>,
    /// `-1` is unlimited.
    pub max_tcp_queries: Option<i64>,
}

impl ConnLimits {
    /// Fill in what `other` sets, like CoreDNS merging site configs.
    pub fn merge(&mut self, other: &ConnLimits) {
        self.read = other.read.or(self.read);
        self.write = other.write.or(self.write);
        self.idle = other.idle.or(self.idle);
        self.max_tcp_queries = other.max_tcp_queries.or(self.max_tcp_queries);
    }
}
