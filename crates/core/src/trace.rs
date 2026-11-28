//! Request tracing hooks for the `trace` plugin: the span a request is in,
//! carried in [`Context::span`](crate::Context::span), and a child span
//! per plugin that [`next_or_failure`](crate::next_or_failure) calls, like
//! CoreDNS's `plugin.NextOrFailure` does with OpenTracing.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Receives finished child spans.
pub trait Tracer: Send + Sync {
    /// A span named `name` (the plugin) under `parent`, with its own `id`.
    fn child_finished(&self, parent: &SpanRef, id: u64, name: &str, start: SystemTime, duration: Duration);
}

/// The current span of a request.
#[derive(Clone)]
pub struct SpanRef {
    pub tracer: Arc<dyn Tracer>,
    pub trace_id: u128,
    pub span_id: u64,
}

/// A random 64-bit span id (never 0).
pub fn new_id() -> u64 {
    loop {
        let id = rand::random();
        if id != 0 {
            return id;
        }
    }
}
