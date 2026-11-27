//! Server block keys: `[transport://]zone[:port]`, like CoreDNS's
//! `dnsserver/address.go` and `plugin.SplitHostPort`.

use std::fmt;
use std::net::IpAddr;

/// The listener type selected by a key's scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transport {
    Dns,
    Tls,
    Quic,
    Grpc,
    Https,
    Https3,
}

impl Transport {
    pub fn scheme(&self) -> &'static str {
        match self {
            Transport::Dns => "dns",
            Transport::Tls => "tls",
            Transport::Quic => "quic",
            Transport::Grpc => "grpc",
            Transport::Https => "https",
            Transport::Https3 => "https3",
        }
    }

    /// Port used when a key doesn't name one. Plain DNS uses the
    /// `-dns.port` flag instead.
    pub fn default_port(&self, dns_port: &str) -> String {
        match self {
            Transport::Dns => dns_port.to_string(),
            Transport::Tls | Transport::Quic => "853".into(),
            Transport::Grpc | Transport::Https | Transport::Https3 => "443".into(),
        }
    }

    /// Split a scheme prefix off `s`.
    pub fn split(s: &str) -> (Transport, &str) {
        const SCHEMES: &[(&str, Transport)] = &[
            ("dns://", Transport::Dns),
            ("tls://", Transport::Tls),
            ("quic://", Transport::Quic),
            ("grpc://", Transport::Grpc),
            ("https3://", Transport::Https3),
            ("https://", Transport::Https),
        ];
        for (prefix, t) in SCHEMES {
            if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
                return (*t, &s[prefix.len()..]);
            }
        }
        (Transport::Dns, s)
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.scheme())
    }
}

/// A normalized server block key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZoneAddr {
    pub transport: Transport,
    /// Lowercase, fully qualified zone, e.g. `example.org.`.
    pub zone: String,
    pub port: String,
}

impl fmt::Display for ZoneAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}", self.transport, self.zone, self.port)
    }
}

impl ZoneAddr {
    /// Parse one key. Reverse CIDR keys (`10.0.0.0/23`) expand to one zone
    /// per label boundary, so this returns a list.
    pub fn parse(key: &str, dns_port: &str) -> Result<Vec<ZoneAddr>, String> {
        let (transport, rest) = Transport::split(key);
        let (hosts, port) = split_host_port(rest)?;
        let port = port.unwrap_or_else(|| transport.default_port(dns_port));
        Ok(hosts
            .into_iter()
            .map(|zone| ZoneAddr {
                transport,
                zone,
                port: port.clone(),
            })
            .collect())
    }
}

/// Lowercase and add a trailing dot.
pub fn normalize_zone(s: &str) -> String {
    let mut z = s.to_ascii_lowercase();
    if !z.ends_with('.') {
        z.push('.');
    }
    z
}

/// `plugin.SplitHostPort`: a trailing `:<number>` is the port; a CIDR host
/// becomes its reverse zones; anything else is a domain name.
pub fn split_host_port(s: &str) -> Result<(Vec<String>, Option<String>), String> {
    let mut host = s;
    let mut port = None;
    if let Some(colon) = s.rfind(':') {
        if colon == s.len() - 1 {
            return Err(format!("expecting data after last colon: {s:?}"));
        }
        if let Ok(p) = s[colon + 1..].parse::<u32>() {
            port = Some(p.to_string());
            host = &s[..colon];
        }
    }
    if host.len() > 255 {
        return Err(format!("specified zone is too long: {} > 255", host.len()));
    }
    if host.is_empty() {
        return Err(format!("zone is not a valid domain name: {s}"));
    }
    if let Some((ip, len)) = host.split_once('/') {
        if host.starts_with(':') {
            return Err(format!("invalid CIDR {host}"));
        }
        if let (Ok(ip), Ok(len)) = (ip.parse::<IpAddr>(), len.parse::<u8>()) {
            return Ok((reverse_zones(ip, len).map_err(|e| format!("{e}: {host}"))?, port));
        }
    }
    if host.contains("..") || (host != "." && host.starts_with('.')) {
        return Err(format!("zone is not a valid domain name: {host}"));
    }
    Ok((vec![normalize_zone(host)], port))
}

/// Reverse zones for a network. A prefix that is not on a label boundary
/// (8 bits for IPv4, 4 for IPv6) expands to every zone at the next boundary.
pub fn reverse_zones(ip: IpAddr, prefix: u8) -> Result<Vec<String>, &'static str> {
    let (bits, digit, suffix): (u32, u32, &str) = match ip {
        IpAddr::V4(_) => (32, 8, "in-addr.arpa."),
        IpAddr::V6(_) => (128, 4, "ip6.arpa."),
    };
    let prefix = prefix as u32;
    if prefix > bits {
        return Err("invalid CIDR");
    }
    let boundary = prefix.div_ceil(digit) * digit;
    let addr: u128 = match ip {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    };
    let mask = |len: u32| {
        if len == 0 {
            0
        } else {
            (!0u128 << (bits - len)) & (u128::MAX >> (128 - bits))
        }
    };
    let network = addr & mask(prefix);
    let count = 1u128 << (boundary - prefix);
    let mut zones = Vec::with_capacity(count as usize);
    for i in 0..count {
        let sub = network | (i << (bits - boundary));
        let mut labels = Vec::new();
        for n in 0..boundary / digit {
            let shift = bits - digit * (n + 1);
            let v = (sub >> shift) & ((1u128 << digit) - 1);
            labels.push(if digit == 8 { v.to_string() } else { format!("{v:x}") });
        }
        labels.reverse();
        let mut z = labels.join(".");
        if !z.is_empty() {
            z.push('.');
        }
        z.push_str(suffix);
        zones.push(z);
    }
    Ok(zones)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(k: &str) -> Vec<String> {
        ZoneAddr::parse(k, "53")
            .unwrap()
            .iter()
            .map(|z| z.to_string())
            .collect()
    }

    #[test]
    fn keys() {
        assert_eq!(p("."), vec!["dns://.:53"]);
        assert_eq!(p(".:1053"), vec!["dns://.:1053"]);
        assert_eq!(p("Example.ORG"), vec!["dns://example.org.:53"]);
        assert_eq!(p("tls://example.org"), vec!["tls://example.org.:853"]);
        assert_eq!(p("https://.:8443"), vec!["https://.:8443"]);
        assert_eq!(p("grpc://."), vec!["grpc://.:443"]);
        assert!(ZoneAddr::parse("example.org:", "53").is_err());
    }

    #[test]
    fn reverse() {
        assert_eq!(p("10.0.0.0/24"), vec!["dns://0.0.10.in-addr.arpa.:53"]);
        assert_eq!(p("10.0.0.0/8:1053"), vec!["dns://10.in-addr.arpa.:1053"]);
        assert_eq!(
            p("10.0.0.0/23"),
            vec!["dns://0.0.10.in-addr.arpa.:53", "dns://1.0.10.in-addr.arpa.:53"]
        );
        assert_eq!(p("0.0.0.0/0"), vec!["dns://in-addr.arpa.:53"]);
        assert_eq!(p("fd00::/16"), vec!["dns://0.0.d.f.ip6.arpa.:53"]);
        assert_eq!(p("fd00::/15").len(), 2);
    }
}
