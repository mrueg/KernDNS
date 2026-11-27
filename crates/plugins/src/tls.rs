//! `tls`: the certificate for `tls://` (DoT) and `https://` (DoH) server
//! blocks. Port of `plugin/tls` without ACME.
//!
//! ```text
//! tls CERT KEY [CA] {
//!     client_auth nocert|request|require|verify_if_given|require_and_verify
//! }
//! ```
//!
//! Not ported yet: ACME (`tls` without files) and `keylog`.

use std::path::Path;

use kerndns_core::{Controller, PluginFactory, SetupError};

use crate::tlsconfig::{ClientAuth, server_config};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        if c.config.tls.is_some() {
            return Err(c.errf("TLS already configured for this server instance"));
        }
        while c.next() {
            let mut args = c.remaining_args();
            if args.is_empty() {
                return Err(SetupError::new(
                    "tls",
                    "ACME certificates are not supported by KernDNS yet",
                ));
            }
            if args.len() < 2 || args.len() > 3 {
                return Err(c.arg_err());
            }
            let mut auth = ClientAuth::NoCert;
            while c.next_block() {
                match c.val() {
                    "client_auth" => {
                        let a = c.remaining_args();
                        if a.len() != 1 {
                            return Err(c.arg_err());
                        }
                        auth = match a[0].as_str() {
                            "nocert" => ClientAuth::NoCert,
                            "request" => ClientAuth::Request,
                            "require" => ClientAuth::Require,
                            "verify_if_given" => ClientAuth::VerifyIfGiven,
                            "require_and_verify" => ClientAuth::RequireAndVerify,
                            other => {
                                let msg = format!("unknown authentication type '{other}'");
                                return Err(c.errf(msg));
                            }
                        };
                    }
                    "keylog" => return Err(SetupError::new("tls", "'keylog' is not supported by KernDNS yet")),
                    other => {
                        let msg = format!("unknown option '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
            if let Some(root) = &c.config.root {
                for a in &mut args {
                    if Path::new(a).is_relative() {
                        *a = root.join(&a).display().to_string();
                    }
                }
            }
            let cfg = server_config(&args[0], &args[1], args.get(2).map(String::as_str), auth)
                .map_err(|e| SetupError::new("tls", e))?;
            c.config.tls = Some(cfg);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/coredns/plugin/tls");

    #[test]
    fn setup() {
        let ok = format!("tls {DIR}/test_cert.pem {DIR}/test_key.pem");
        let (res, cfg) = run_setup(&Setup, &ok);
        res.unwrap();
        assert!(cfg.tls.is_some());
        assert!(setup_err(&Setup, "tls a").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "tls /nonexistent/cert /nonexistent/key").contains("could not load TLS cert"));
        assert!(setup_err(&Setup, &format!("{ok} {{\n client_auth bogus\n}}")).contains("unknown authentication type"));
    }
}
