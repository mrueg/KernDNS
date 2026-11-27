//! Corefile reloading requested by the `reload` plugin. The binary watches
//! the Corefile when this is enabled (and on SIGUSR1 regardless).

use std::sync::Mutex;
use std::time::Duration;

static INTERVAL: Mutex<Option<Duration>> = Mutex::new(None);

/// Check the Corefile for changes every `interval` (set by `reload`).
pub fn enable(interval: Duration) {
    *INTERVAL.lock().unwrap() = Some(interval);
}

/// Forget the setting (a new configuration is being loaded).
pub fn reset() {
    *INTERVAL.lock().unwrap() = None;
}

/// Put back a setting saved with [`interval`] (loading a new
/// configuration failed).
pub fn restore(interval: Option<Duration>) {
    *INTERVAL.lock().unwrap() = interval;
}

pub fn interval() -> Option<Duration> {
    *INTERVAL.lock().unwrap()
}
