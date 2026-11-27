//! Logging in CoreDNS's format: `[LEVEL] plugin/<name>: message` on stdout.
//!
//! CoreDNS writes logs to stdout with this prefix and people grep for it, so
//! we keep the format instead of using `tracing`'s default output.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

static DEBUG: AtomicBool = AtomicBool::new(false);

/// Enable `[DEBUG]` output (set by the `debug` plugin).
pub fn set_debug(on: bool) {
    DEBUG.store(on, Ordering::Relaxed);
}

pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

#[doc(hidden)]
pub fn emit(level: &str, plugin: Option<&str>, msg: std::fmt::Arguments<'_>) {
    let mut out = std::io::stdout().lock();
    let _ = match plugin {
        Some(p) => writeln!(out, "[{level}] plugin/{p}: {msg}"),
        None => writeln!(out, "[{level}] {msg}"),
    };
}

/// `info!("plugin", "fmt", args)` or `info!(None, ...)`-style helpers.
#[macro_export]
macro_rules! info {
    (plugin = $p:expr, $($arg:tt)*) => { $crate::log::emit("INFO", Some($p), format_args!($($arg)*)) };
    ($($arg:tt)*) => { $crate::log::emit("INFO", None, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! warning {
    (plugin = $p:expr, $($arg:tt)*) => { $crate::log::emit("WARNING", Some($p), format_args!($($arg)*)) };
    ($($arg:tt)*) => { $crate::log::emit("WARNING", None, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! error {
    (plugin = $p:expr, $($arg:tt)*) => { $crate::log::emit("ERROR", Some($p), format_args!($($arg)*)) };
    ($($arg:tt)*) => { $crate::log::emit("ERROR", None, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! debug {
    (plugin = $p:expr, $($arg:tt)*) => {
        if $crate::log::debug_enabled() { $crate::log::emit("DEBUG", Some($p), format_args!($($arg)*)) }
    };
    ($($arg:tt)*) => {
        if $crate::log::debug_enabled() { $crate::log::emit("DEBUG", None, format_args!($($arg)*)) }
    };
}
