//! `bind`: restricts the addresses a server block listens on. Port of
//! `plugin/bind`: IP addresses and interface names (the interface's
//! addresses at setup time, IPv6 link-local ones with the interface as
//! zone), with `except` per `bind` directive.

use std::net::IpAddr;

use kerndns_core::{Controller, PluginFactory, SetupError};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "bind"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let ifaces = match if_addrs::get_if_addrs() {
            Ok(i) => i,
            Err(e) => {
                kerndns_core::warning!(
                    "plugin/bind: failed to get interfaces list, cannot bind by interface name: {e}"
                );
                Vec::new()
            }
        };
        let err = |m: String| SetupError::new("bind", m);
        // addresses are consolidated over all bind directives of the block
        let mut all: Vec<String> = Vec::new();
        while c.next() {
            let addrs = c.remaining_args();
            if addrs.is_empty() {
                return Err(err("at least one address or interface name is expected".into()));
            }
            let mut except = Vec::new();
            while c.next_block() {
                match c.val() {
                    "except" => {
                        except = c.remaining_args();
                        if except.is_empty() {
                            return Err(err(
                                "at least one address or interface must be given to except subdirective".into(),
                            ));
                        }
                    }
                    v => return Err(err(format!("invalid option {v:?}"))),
                }
            }
            let ips = list_ip(&addrs, &ifaces).map_err(err)?;
            let except = list_ip(&except, &ifaces).map_err(err)?;
            for ip in ips {
                if !except.contains(&ip) && !all.contains(&ip) {
                    all.push(ip);
                }
            }
        }
        if all.is_empty() {
            // CoreDNS starts such a block without any listener.
            return Err(err("No valid addresses left to bind".into()));
        }
        c.config.listen_hosts = all;
        Ok(())
    }
}

/// The addresses of `args`, each an IP address or an interface name
/// (`listIP`). Interface addresses come in the order the system lists them;
/// IPv6 link-local ones get the interface as zone (`fe80::1%eth0`).
fn list_ip(args: &[String], ifaces: &[if_addrs::Interface]) -> Result<Vec<String>, String> {
    let mut all = Vec::new();
    for a in args {
        let mut is_iface = false;
        for iface in ifaces.iter().filter(|i| i.name == *a) {
            is_iface = true;
            let ip = iface.ip();
            match ip {
                IpAddr::V6(v6) if v6.is_unicast_link_local() || is_link_local_multicast(v6) => {
                    all.push(format!("{ip}%{}", iface.name))
                }
                _ => all.push(ip.to_string()),
            }
        }
        if !is_iface {
            let ip: IpAddr = a
                .parse()
                .map_err(|_| format!("not a valid IP address or interface name: {a:?}"))?;
            all.push(ip.to_string());
        }
    }
    Ok(all)
}

fn is_link_local_multicast(ip: std::net::Ipv6Addr) -> bool {
    ip.segments()[0] & 0xff0f == 0xff02
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
        assert!(setup_err(&Setup, "bind").contains("at least one address or interface name is expected"));
        assert!(setup_err(&Setup, "bind nosuchif0").contains("not a valid IP address or interface name"));
        assert!(setup_err(&Setup, "bind 127.0.0.1 {\n except\n}").contains("except subdirective"));
        assert!(setup_err(&Setup, "bind 127.0.0.1 {\n foo\n}").contains("invalid option \"foo\""));
        assert!(setup_err(&Setup, "bind 127.0.0.1 {\n except 127.0.0.1\n}").contains("No valid addresses"));
    }

    /// `except` only applies to its own `bind` directive.
    #[test]
    fn except_per_directive() {
        let (res, cfg) = run_setup(
            &Setup,
            "bind 127.0.0.1\nbind 127.0.0.2 127.0.0.1 {\n except 127.0.0.1\n}",
        );
        res.unwrap();
        assert_eq!(cfg.listen_hosts, vec!["127.0.0.1", "127.0.0.2"]);
    }

    /// The README's `bind lo` examples (`TestReadme`).
    #[test]
    fn interface_names() {
        let lo: Vec<String> = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .filter(|i| i.name == "lo")
            .map(|i| i.ip().to_string())
            .collect();
        if lo.is_empty() {
            return; // no loopback interface named lo (not Linux)
        }
        let (res, cfg) = run_setup(&Setup, "bind lo");
        res.unwrap();
        assert_eq!(cfg.listen_hosts, lo);
        let (res, cfg) = run_setup(&Setup, "bind lo {\n except 127.0.0.1\n}");
        let want: Vec<String> = lo.iter().filter(|a| *a != "127.0.0.1").cloned().collect();
        if want.is_empty() {
            assert!(res.unwrap_err().contains("No valid addresses"));
        } else {
            res.unwrap();
            assert_eq!(cfg.listen_hosts, want);
        }
        if lo.iter().any(|a| a == "127.0.0.1") {
            let (res, _) = run_setup(&Setup, "bind 127.0.0.1 {\n except lo\n}");
            assert!(res.unwrap_err().contains("No valid addresses"));
        }
    }

    #[test]
    fn link_local_zone() {
        let ifaces = vec![if_addrs::Interface {
            name: "eth9".into(),
            addr: if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
                ip: "fe80::1".parse().unwrap(),
                netmask: "ffff:ffff:ffff:ffff::".parse().unwrap(),
                prefixlen: 64,
                broadcast: None,
            }),
            index: Some(9),
            oper_status: if_addrs::IfOperStatus::Up,
            is_p2p: false,
        }];
        assert_eq!(
            list_ip(&["eth9".into(), "::1".into()], &ifaces).unwrap(),
            vec!["fe80::1%eth9", "::1"]
        );
    }
}
