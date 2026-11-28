//! `tls`: the certificate for `tls://` (DoT), `https://` (DoH),
//! `https3://`, `quic://` and `grpc://` server blocks. Port of `plugin/tls`.
//!
//! ```text
//! tls CERT KEY [CA] {
//!     client_auth nocert|request|require|verify_if_given|require_and_verify
//! }
//!
//! tls {
//!     acme DOMAIN...
//!     email EMAIL
//!     ca URL
//!     storage DIRECTORY
//!     ca_root FILE
//!     resolver ADDRESS
//! }
//! ```
//!
//! `keylog FILE` appends the TLS secrets of every connection to FILE in the
//! NSS key log format (for Wireshark), like Go's `KeyLogWriter`.

pub mod acme;
mod issuer;

use std::path::Path;

use kerndns_core::{Controller, PluginFactory, SetupError};

use std::sync::Arc;

use crate::tlsconfig::{ClientAuth, KeyLogFile, server_config};

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
                c.config.tls = Some(acme::parse(c)?);
                continue;
            }
            if args.len() < 2 || args.len() > 3 {
                return Err(c.arg_err());
            }
            let mut auth = ClientAuth::NoCert;
            let mut keylog = None;
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
                    "keylog" => {
                        let a = c.remaining_args();
                        if a.len() != 1 {
                            return Err(c.arg_err());
                        }
                        let mut p = std::path::PathBuf::from(&a[0]);
                        if p.is_relative()
                            && let Some(root) = &c.config.root
                        {
                            p = root.join(p);
                        }
                        keylog = Some(p);
                    }
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
            let mut cfg = server_config(&args[0], &args[1], args.get(2).map(String::as_str), auth)
                .map_err(|e| SetupError::new("tls", e))?;
            if let Some(p) = keylog {
                let abs = std::path::absolute(&p).map_err(|e| {
                    c.errf(format!(
                        "unable to write TLS Key Log to {:?}: {e}",
                        p.display().to_string()
                    ))
                })?;
                let shown = abs.display().to_string();
                let file = KeyLogFile::open(&abs)
                    .map_err(|e| c.errf(format!("unable to write TLS Key Log to {shown:?}: open {shown}: {e}")))?;
                Arc::make_mut(&mut cfg).key_log = Arc::new(file);
                kerndns_core::warning!(plugin = "tls", "Writing TLS Key Log to {shown:?}");
            }
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

    /// `TestTLSKeyLog`.
    #[test]
    fn keylog() {
        let ok = format!("tls {DIR}/test_cert.pem {DIR}/test_key.pem {DIR}/test_ca.pem");
        assert!(setup_err(&Setup, &format!("{ok} {{\n keylog\n}}")).contains("Wrong argument count"));
        let dir = TempDir::new("tls-keylog");
        let missing = dir.0.join("missing/tls.log");
        let err = setup_err(&Setup, &format!("{ok} {{\n keylog {}\n}}", missing.display()));
        assert!(err.contains("unable to write TLS Key Log to"), "{err}");

        let path = dir.0.join("tls.log");
        let (res, cfg) = run_setup(&Setup, &format!("{ok} {{\n keylog {}\n}}", path.display()));
        res.unwrap();
        let tls = cfg.tls.unwrap();
        assert!(tls.key_log.will_log("CLIENT_RANDOM"));
        tls.key_log.log("CLIENT_RANDOM", &[0xab, 0x01], &[0xff]);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "CLIENT_RANDOM ab01 ff\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
