//! Zone name helpers shared by plugins, like CoreDNS's `plugin.Zones`,
//! `plugin.Host(...).NormalizeExact` and `plugin/pkg/fall`.

use crate::address::split_host_port;

/// True if `child` is `parent` or below it. Both must be lowercase FQDNs
/// (`example.org.`), like `dns.IsSubDomain(parent, child)`.
pub fn is_subdomain(parent: &str, child: &str) -> bool {
    if parent == "." {
        return true;
    }
    child == parent
        || (child.len() > parent.len() && child.ends_with(parent) && {
            let i = child.len() - parent.len();
            child.as_bytes()[i - 1] == b'.' && (i < 2 || child.as_bytes()[i - 2] != b'\\')
        })
}

/// The longest zone in `zones` that contains `qname`, like `Zones.Matches`.
pub fn matches<'a>(zones: &'a [String], qname: &str) -> Option<&'a str> {
    zones
        .iter()
        .filter(|z| is_subdomain(z, qname))
        .max_by_key(|z| z.len())
        .map(String::as_str)
}

/// Normalize a zone argument: lowercase FQDN, port stripped, reverse CIDRs
/// expanded. Invalid input gives an empty list, like `NormalizeExact`.
pub fn normalize_exact(s: &str) -> Vec<String> {
    split_host_port(s).map(|(hosts, _)| hosts).unwrap_or_default()
}

/// The zones named in `args`, or the server block's zones if there are
/// none, like `plugin.OriginsFromArgsOrServerBlock`.
pub fn origins_from_args_or_server_block(args: &[String], server_block: &[String]) -> Vec<String> {
    if args.is_empty() {
        return server_block
            .iter()
            .map(|s| normalize_exact(s).into_iter().next().unwrap_or_else(|| s.clone()))
            .collect();
    }
    args.iter().flat_map(|a| normalize_exact(a)).collect()
}

/// `fallthrough [ZONES...]`: which names may be passed to the next plugin
/// instead of answered with NXDOMAIN.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fall {
    pub zones: Vec<String>,
}

impl Fall {
    /// No arguments means all names (the root zone).
    pub fn set_zones_from_args(&mut self, args: &[String]) {
        self.zones = if args.is_empty() {
            vec![".".into()]
        } else {
            args.iter().flat_map(|a| normalize_exact(a)).collect()
        };
    }

    pub fn through(&self, qname: &str) -> bool {
        self.zones.iter().any(|z| is_subdomain(z, qname))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomain() {
        assert!(is_subdomain(".", "a.b."));
        assert!(is_subdomain("example.org.", "example.org."));
        assert!(is_subdomain("example.org.", "a.example.org."));
        assert!(!is_subdomain("example.org.", "aexample.org."));
        assert!(!is_subdomain("a.example.org.", "example.org."));
    }

    #[test]
    fn zone_matching() {
        let z = vec![
            "example.org.".to_string(),
            "sub.example.org.".to_string(),
            ".".to_string(),
        ];
        assert_eq!(matches(&z, "a.sub.example.org."), Some("sub.example.org."));
        assert_eq!(matches(&z, "example.org."), Some("example.org."));
        assert_eq!(matches(&z, "example.net."), Some("."));
        assert_eq!(matches(&z[..2], "example.net."), None);
    }

    #[test]
    fn fall() {
        let mut f = Fall::default();
        assert!(!f.through("a.example.org."));
        f.set_zones_from_args(&[]);
        assert!(f.through("a.example.org."));
        f.set_zones_from_args(&["example.org".into()]);
        assert!(f.through("a.example.org."));
        assert!(!f.through("example.net."));
    }

    #[test]
    fn origins() {
        let sb = vec!["example.org.".to_string()];
        assert_eq!(origins_from_args_or_server_block(&[], &sb), sb);
        assert_eq!(
            origins_from_args_or_server_block(&["Example.NET:53".into(), "10.0.0.0/24".into()], &sb),
            vec!["example.net.", "0.0.10.in-addr.arpa."]
        );
    }
}

/// The address a reverse name stands for (`1.0.0.10.in-addr.arpa.` →
/// `10.0.0.1`), like `dnsutil.ExtractAddressFromReverse`. Only complete
/// names (4 octets, 32 nibbles) give an address.
pub fn extract_address_from_reverse(name: &str) -> Option<std::net::IpAddr> {
    let name = name.to_ascii_lowercase();
    if let Some(rest) = name.strip_suffix(".in-addr.arpa.") {
        let mut parts: Vec<&str> = rest.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        parts.reverse();
        return parts.join(".").parse::<std::net::Ipv4Addr>().ok().map(Into::into);
    }
    if let Some(rest) = name.strip_suffix(".ip6.arpa.") {
        let nibbles: Vec<&str> = rest.split('.').collect();
        if nibbles.len() != 32 || nibbles.iter().any(|n| n.len() != 1) {
            return None;
        }
        let hex: String = nibbles.iter().rev().copied().collect();
        let v = u128::from_str_radix(&hex, 16).ok()?;
        return Some(std::net::Ipv6Addr::from(v).into());
    }
    None
}

#[cfg(test)]
mod reverse_tests {
    use super::*;

    #[test]
    fn reverse_names() {
        assert_eq!(
            extract_address_from_reverse("1.0.0.10.in-addr.arpa.")
                .unwrap()
                .to_string(),
            "10.0.0.1"
        );
        assert!(extract_address_from_reverse("0.0.10.in-addr.arpa.").is_none());
        let v6 = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.";
        assert_eq!(extract_address_from_reverse(v6).unwrap().to_string(), "2001:db8::1");
        assert!(extract_address_from_reverse("example.org.").is_none());
    }
}
