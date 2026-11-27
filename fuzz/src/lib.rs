//! Shared setup for the fuzz targets in `fuzz_targets/`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use kerndns_core::Registry;

/// One single-threaded runtime per fuzzing process.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    })
}

/// Every Rust plugin, as `kerndns` registers them (no Go bridge).
pub fn registry() -> &'static Registry {
    static REG: OnceLock<Registry> = OnceLock::new();
    REG.get_or_init(|| {
        let mut r = kerndns_plugins::registry();
        r.register(kerndns_kubernetes::Setup);
        r.register(kerndns_kubernetes::external::Setup);
        r
    })
}

/// `fuzz/fixtures` (zone and hosts files for the targets' Corefiles).
/// The first call also clears the environment, so `{$VAR}` in a fuzzed
/// Corefile can't expand to a real path.
pub fn fixtures() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let vars: Vec<_> = std::env::vars_os().map(|(k, _)| k).collect();
        for k in vars {
            // SAFETY: runs once, before the fuzzed code starts any threads.
            unsafe { std::env::remove_var(k) };
        }
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    })
}

/// Inputs that could make a setup read from devices or walk the whole
/// file system (e.g. `file /dev/zero` or `import /**`): real misuse, not
/// bugs, so they are skipped.
pub fn escapes_sandbox(input: &str) -> bool {
    input.contains("..")
        || input.contains('~')
        || input.contains("**")
        || input
            .split(|c: char| c.is_whitespace() || c == '"' || c == '`' || c == '{' || c == '}')
            .any(|w| w.starts_with('/'))
}
