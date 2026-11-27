//! `root`: sets the base directory for relative file paths. Port of
//! `plugin/root`.

use std::path::PathBuf;

use kerndns_core::{Controller, PluginFactory, SetupError};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "root"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        while c.next() {
            if !c.next_arg() {
                return Err(c.arg_err());
            }
            let path = PathBuf::from(c.val());
            if c.next_arg() {
                return Err(c.arg_err());
            }
            if let Err(e) = std::fs::metadata(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(c.errf(format!("unable to access root path '{}': {e}", path.display())));
                }
                kerndns_core::warning!(plugin = "root", "Root path does not exist: {}", path.display());
            }
            c.config.root = Some(path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        let (res, cfg) = run_setup(&Setup, "root /tmp");
        res.unwrap();
        assert_eq!(cfg.root.unwrap(), PathBuf::from("/tmp"));
        assert!(setup_err(&Setup, "root").contains("Wrong argument count"));
    }
}
