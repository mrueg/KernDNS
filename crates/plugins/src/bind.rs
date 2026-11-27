//! `bind`: restricts the addresses a server block listens on. Port of
//! `plugin/bind` (IP addresses only; interface names are not ported yet).

use std::net::IpAddr;

use kerndns_core::{Controller, PluginFactory, SetupError};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "bind"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut hosts: Vec<String> = Vec::new();
        let mut except: Vec<IpAddr> = Vec::new();
        while c.next() {
            let args = c.remaining_args();
            if args.is_empty() {
                return Err(c.arg_err());
            }
            for a in args {
                match a.parse::<IpAddr>() {
                    Ok(ip) => hosts.push(ip.to_string()),
                    Err(_) => {
                        return Err(c.errf(format!(
                            "not a valid IP address: {a} (interface names are not supported yet)"
                        )));
                    }
                }
            }
            while c.next_block() {
                match c.val() {
                    "except" => {
                        let ex = c.remaining_args();
                        if ex.is_empty() {
                            return Err(c.arg_err());
                        }
                        for a in ex {
                            match a.parse::<IpAddr>() {
                                Ok(ip) => except.push(ip),
                                Err(_) => return Err(c.errf(format!("not a valid IP address: {a}"))),
                            }
                        }
                    }
                    _ => return Err(c.syntax_err("except")),
                }
            }
        }
        hosts.retain(|h| !except.iter().any(|e| e.to_string() == *h));
        if hosts.is_empty() {
            return Err(c.errf("No valid addresses left to bind"));
        }
        for h in hosts {
            if !c.config.listen_hosts.contains(&h) {
                c.config.listen_hosts.push(h);
            }
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
        let (res, cfg) = run_setup(&Setup, "bind 127.0.0.1 ::1");
        res.unwrap();
        assert_eq!(cfg.listen_hosts, vec!["127.0.0.1", "::1"]);
        let (res, cfg) = run_setup(&Setup, "bind 127.0.0.1 127.0.0.2 {\n except 127.0.0.2\n}");
        res.unwrap();
        assert_eq!(cfg.listen_hosts, vec!["127.0.0.1"]);
        assert!(setup_err(&Setup, "bind").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "bind eth0").contains("interface names"));
    }
}
