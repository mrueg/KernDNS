//! `debug`: enables debug logging and disables panic recovery. Port of
//! `plugin/debug`.

use kerndns_core::{Controller, PluginFactory, SetupError};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "debug"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        while c.next() {
            if c.next_arg() {
                return Err(c.arg_err());
            }
        }
        c.config.debug = true;
        kerndns_core::log::set_debug(true);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        let (res, cfg) = run_setup(&Setup, "debug");
        res.unwrap();
        assert!(cfg.debug);
        assert!(setup_err(&Setup, "debug x").contains("Wrong argument count"));
    }
}
