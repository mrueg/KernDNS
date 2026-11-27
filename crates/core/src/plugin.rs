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
use crate::handler::{Handler, Next};

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
