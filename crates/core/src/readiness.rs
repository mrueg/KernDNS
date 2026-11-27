//! Plugin readiness, used by the `ready` plugin, like CoreDNS's
//! `ready.Readiness` interface and its global plugin list.
//!
//! A plugin that can be not-ready (e.g. `kubernetes` before its caches
//! sync) registers a check during setup. Once a check reports ready it is
//! dropped, unless `ready` monitors continuously.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

type Check = Arc<dyn Fn() -> bool + Send + Sync>;

struct List {
    checks: BTreeMap<String, Option<Check>>,
    keep: bool,
}

static LIST: Mutex<List> = Mutex::new(List {
    checks: BTreeMap::new(),
    keep: false,
});

/// Register `name`'s readiness check.
pub fn register(name: &str, check: impl Fn() -> bool + Send + Sync + 'static) {
    LIST.lock()
        .unwrap()
        .checks
        .insert(name.to_string(), Some(Arc::new(check)));
}

/// Forget all checks (a new configuration is being loaded).
pub fn reset() {
    LIST.lock().unwrap().checks.clear();
}

/// Keep checking plugins after they first report ready.
pub fn set_monitor_continuously(keep: bool) {
    LIST.lock().unwrap().keep = keep;
}

/// Whether every plugin is ready, and the sorted names of those that aren't.
pub fn ready() -> (bool, Vec<String>) {
    let mut l = LIST.lock().unwrap();
    let keep = l.keep;
    let mut not_ready = Vec::new();
    for (name, check) in l.checks.iter_mut() {
        let Some(c) = check else { continue };
        if c() {
            if !keep {
                *check = None;
            }
        } else {
            not_ready.push(name.clone());
        }
    }
    (not_ready.is_empty(), not_ready)
}
