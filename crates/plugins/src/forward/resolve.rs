//! Upstream addresses (`TO`): IP addresses, resolv.conf files and host
//! names, ported from CoreDNS's `plugin/forward/resolve.go`,
//! `pkg/parse.HostPortOrFile`, `pkg/parse.Transport` and `splitZone`.
//!
//! Addresses are kept as strings in CoreDNS's forms (`1.2.3.4:53`,
//! `tls://1.2.3.4%dns.example:853`, `https://[::1]:443`) until the proxies
//! are built, so deduplication and error messages match CoreDNS.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query};
use kerndns_core::proto::rr::{Name, RData, RecordType};

pub const DNS: &str = "dns";
pub const TLS: &str = "tls";
pub const QUIC: &str = "quic";
pub const GRPC: &str = "grpc";
pub const HTTPS: &str = "https";
pub const HTTPS3: &str = "https3";
pub const UNIX: &str = "unix";

/// `parse.Transport`: the transport prefix of `s` and the rest; no prefix
/// (or an unknown one) is plain DNS.
pub fn transport(s: &str) -> (&'static str, &str) {
    for t in [TLS, DNS, QUIC, GRPC, HTTPS3, HTTPS, UNIX] {
        if let Some(rest) = s.strip_prefix(t).and_then(|r| r.strip_prefix("://")) {
            return (t, rest);
        }
    }
    (DNS, s)
}

/// The default port of a transport.
pub fn default_port(t: &str) -> &'static str {
    match t {
        TLS | QUIC => "853",
        GRPC | HTTPS => "443",
        _ => "53",
    }
}

/// Go's `net.SplitHostPort`.
pub fn split_host_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?;
        if port.contains(':') || port.contains('[') || port.contains(']') {
            return None;
        }
        return Some((host, port));
    }
    let i = s.rfind(':')?;
    let (host, port) = (&s[..i], &s[i + 1..]);
    if host.contains(':') || host.contains('[') || host.contains(']') {
        return None;
    }
    Some((host, port))
}

/// Go's `net.JoinHostPort`.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn strip_zone(host: &str) -> &str {
    host.rfind('%').map_or(host, |i| &host[..i])
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

/// `splitZone`: split the TLS server name (`%name`) off an upstream,
/// keeping a port that follows it: `tls://1.2.3.4%dns.example:853` is
/// `(tls://1.2.3.4:853, dns.example)`.
pub fn split_zone(host: &str) -> (String, String) {
    let (trans, rest) = match host.split_once("://") {
        Some((t, r)) => (Some(t), r),
        None => (None, host),
    };
    let mut new_host = rest.to_string();
    let mut zone = String::new();
    if let Some(i) = rest.rfind('%') {
        new_host = rest[..i].to_string();
        if new_host.starts_with('[') {
            new_host.push(']');
        }
        zone = rest[i + 1..].to_string();
        if let Some(j) = zone.rfind(':') {
            new_host.push_str(&zone[j..]);
            zone.truncate(j);
            zone = zone.trim_end_matches(']').to_string();
        }
    }
    match trans {
        Some(t) => (format!("{t}://{new_host}"), zone),
        None => (new_host, zone),
    }
}

/// Why [`host_port_or_file`] failed.
#[derive(Debug, PartialEq)]
pub enum HostError {
    /// Every address was an empty file (`parse.ErrNoNameservers`).
    NoNameservers,
    /// Not an IP address and not a readable file: maybe a host name.
    NotIpOrFile(String),
    Other(String),
}

/// `parse.HostPortOrFile` for one address: an IP (with a default port by
/// transport), `IP:port` (kept as given), or a resolv.conf-like file.
pub fn host_port_or_file(h: &str) -> Result<Vec<String>, HostError> {
    let (trans, host) = transport(h);
    if host.is_empty() {
        return Err(HostError::Other(format!("invalid address: {h:?}")));
    }
    if trans == UNIX {
        return Ok(vec![format!("{trans}://{host}")]);
    }
    let servers = match split_host_port(host) {
        None => {
            let host = host.trim_matches(|c| c == '[' || c == ']');
            if parse_ip(strip_zone(host)).is_none() {
                try_file(host)
                    .map_err(|e| HostError::NotIpOrFile(format!("not an IP address or file {host:?}: {e}")))?
            } else {
                let hp = join_host_port(host, default_port(trans));
                vec![if trans == DNS { hp } else { format!("{trans}://{hp}") }]
            }
        }
        Some((addr, _)) => {
            if parse_ip(strip_zone(addr)).is_none() {
                try_file(host)
                    .map_err(|e| HostError::NotIpOrFile(format!("not an IP address or file {host:?}: {e}")))?
            } else {
                vec![h.to_string()]
            }
        }
    };
    if servers.is_empty() {
        return Err(HostError::NoNameservers);
    }
    Ok(servers)
}

/// The nameservers of a resolv.conf-like file (`dns.ClientConfigFromFile`).
fn try_file(path: &str) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("failed to open file {path:?}: {e:?}")
        } else {
            e.to_string()
        }
    })?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        if f.next() == Some("nameserver")
            && let Some(ip) = f.next()
        {
            out.push(join_host_port(strip_zone(ip), "53"));
        }
    }
    Ok(out)
}

/// A host name upstream, resolved at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    pub hostname: String,
    pub port: String,
    pub transport: &'static str,
    pub zone: String,
}

/// One `TO` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToEntry {
    /// IP addresses and files.
    Static(Vec<String>),
    /// A host name.
    Dynamic(HostEntry),
}

/// `classifyToAddrs`: the `TO` arguments in order; files without
/// nameservers are left out.
pub fn classify_to_addrs(to: &[String]) -> Result<Vec<ToEntry>, String> {
    let mut out = Vec::new();
    for h in to {
        match host_port_or_file(h) {
            Ok(addrs) => out.push(ToEntry::Static(addrs)),
            Err(HostError::NoNameservers) => {}
            Err(HostError::Other(e)) => return Err(e),
            Err(HostError::NotIpOrFile(_)) => match parse_as_host_entry(h) {
                Some(e) => out.push(ToEntry::Dynamic(e)),
                None => return Err(format!("not an IP address, file, or valid domain: {h:?}")),
            },
        }
    }
    Ok(out)
}

/// `parseAsHostEntry`: `[scheme://]name[%servername][:port]`.
pub fn parse_as_host_entry(h: &str) -> Option<HostEntry> {
    let (clean, zone) = split_zone(h);
    let (trans, host) = transport(&clean);
    if ![DNS, TLS, QUIC, HTTPS].contains(&trans) {
        return None;
    }
    let (hostname, port) = match split_host_port(host) {
        Some((h, p)) => (h, p.to_string()),
        None => (host, default_port(trans).to_string()),
    };
    let hostname = hostname.trim_matches(|c| c == '[' || c == ']');
    if hostname.is_empty() || !is_domain_name(hostname) || parse_ip(hostname).is_some() {
        return None;
    }
    Some(HostEntry {
        hostname: hostname.to_string(),
        port,
        transport: trans,
        zone,
    })
}

/// `dns.IsDomainName`: labels of at most 63 octets, at most 255 in all,
/// no empty labels except the root. Like miekg/dns, any characters are
/// allowed (they're resolved, and fail there).
pub fn is_domain_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s == "." {
        return true;
    }
    let s = s.strip_suffix('.').unwrap_or(s);
    let mut total = 1;
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        total += label.len() + 1;
    }
    total <= 255
}

/// `formatResolvedAddr`: a resolved IP in the form the proxies are built from.
pub fn format_resolved_addr(ip: &str, port: &str, trans: &str, zone: &str) -> String {
    let v6 = ip.contains(':');
    match trans {
        TLS | QUIC | HTTPS => {
            if !zone.is_empty() {
                if v6 {
                    format!("{trans}://[{ip}%{zone}]:{port}")
                } else {
                    format!("{trans}://{ip}%{zone}:{port}")
                }
            } else {
                format!("{trans}://{}", join_host_port(ip, port))
            }
        }
        _ => join_host_port(ip, port),
    }
}

/// `dedupKey`: transport, endpoint and (case-insensitive) server name.
fn dedup_key(addr: &str) -> String {
    let (host, zone) = split_zone(addr);
    let (trans, endpoint) = transport(&host);
    format!("{trans}\0{endpoint}\0{}", zone.to_lowercase())
}

/// `expandAndDedup`: resolve the host names (with `lookup`) and drop
/// duplicates, the first one wins.
pub fn expand_and_dedup(
    entries: &[ToEntry],
    lookup: &dyn Fn(&str) -> Result<Vec<String>, String>,
) -> Result<Vec<String>, String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for e in entries {
        let addrs = match e {
            ToEntry::Static(a) => a.clone(),
            ToEntry::Dynamic(h) => lookup(&h.hostname)
                .map_err(|err| format!("failed to resolve {:?}: {err}", h.hostname))?
                .iter()
                .map(|ip| format_resolved_addr(ip, &h.port, h.transport, &h.zone))
                .collect(),
        };
        for a in addrs {
            if seen.insert(dedup_key(&a)) {
                out.push(a);
            }
        }
    }
    Ok(out)
}

/// `lookupHost`: the system resolver, or the `resolver` addresses.
pub fn lookup_host(hostname: &str, resolvers: &[String]) -> Result<Vec<String>, String> {
    if resolvers.is_empty() {
        system_lookup(hostname)
    } else {
        dns_lookup(hostname, resolvers)
    }
}

fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// The system resolver (getaddrinfo), with the name made absolute so no
/// search domains apply.
fn system_lookup(hostname: &str) -> Result<Vec<String>, String> {
    let addrs = (fqdn(hostname).as_str(), 0)
        .to_socket_addrs()
        .map_err(|e| format!("lookup {hostname}: {e}"))?;
    let mut ips: Vec<String> = Vec::new();
    for a in addrs {
        let ip = a.ip().to_string();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    if ips.is_empty() {
        return Err(format!("no addresses found for {hostname:?}"));
    }
    Ok(ips)
}

/// The address of a `resolver` argument: `IP` (port 53) or `IP:port`.
pub fn resolver_addr(s: &str) -> Option<SocketAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa);
    }
    s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53))
}

/// `dnsLookup`: A, then AAAA, over UDP to each resolver in turn until one
/// returns addresses.
fn dns_lookup(hostname: &str, resolvers: &[String]) -> Result<Vec<String>, String> {
    let mut last_err: Option<String> = None;
    for r in resolvers {
        let Some(addr) = resolver_addr(r) else {
            last_err = Some(format!("bad resolver address {r:?}"));
            continue;
        };
        let mut ips = Vec::new();
        match query(addr, hostname, RecordType::A) {
            Err(e) => {
                last_err = Some(e);
                continue;
            }
            Ok(v) => ips.extend(v),
        }
        match query(addr, hostname, RecordType::AAAA) {
            Err(e) => {
                if !ips.is_empty() {
                    return Ok(ips);
                }
                last_err = Some(e);
                continue;
            }
            Ok(v) => ips.extend(v),
        }
        if !ips.is_empty() {
            return Ok(ips);
        }
    }
    match last_err {
        Some(e) => Err(format!("no addresses found for {hostname:?}: {e}")),
        None => Err(format!("no addresses found for {hostname:?}")),
    }
}

/// One query with a 2s read and write timeout, like `dns.Client`.
fn query(addr: SocketAddr, hostname: &str, qtype: RecordType) -> Result<Vec<String>, String> {
    let name = Name::from_ascii(fqdn(hostname)).map_err(|e| e.to_string())?;
    let id = super::proxy::rand_id();
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(name, qtype));
    let wire = m.to_vec().map_err(|e| e.to_string())?;
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let io = |e: std::io::Error| format!("read udp {addr}: {e}");
    let sock = UdpSocket::bind(bind).map_err(io)?;
    sock.connect(addr).map_err(io)?;
    sock.set_write_timeout(Some(Duration::from_secs(2))).map_err(io)?;
    sock.send(&wire).map_err(io)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buf = vec![0u8; 65535];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("read udp {addr}: i/o timeout"));
        }
        sock.set_read_timeout(Some(left)).map_err(io)?;
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Err(format!("read udp {addr}: i/o timeout"));
            }
            Err(e) => return Err(io(e)),
        };
        let Ok(r) = Message::from_vec(&buf[..n]) else { continue };
        if r.metadata.id != id {
            continue;
        }
        return Ok(r
            .answers
            .iter()
            .filter_map(|rr| match &rr.data {
                RData::A(a) if qtype == RecordType::A => Some(a.0.to_string()),
                RData::AAAA(a) if qtype == RecordType::AAAA => Some(a.0.to_string()),
                _ => None,
            })
            .collect());
    }
}

#[cfg(test)]
mod tests {
    //! `resolve_test.go` and `TestSplitZone`.
    use super::*;

    #[test]
    fn split_zone_table() {
        // TestSplitZone
        for (input, host, zone) in [
            ("tls://127.0.0.1%example.net:854", "tls://127.0.0.1:854", "example.net"),
            ("tls://127.0.0.1%example.net", "tls://127.0.0.1", "example.net"),
            (
                "https://127.0.0.1%example.net:443",
                "https://127.0.0.1:443",
                "example.net",
            ),
            ("https://127.0.0.1%example.net", "https://127.0.0.1", "example.net"),
            (
                "quic://127.0.0.1%example.net:853",
                "quic://127.0.0.1:853",
                "example.net",
            ),
            ("tls://127.0.0.1:854", "tls://127.0.0.1:854", ""),
            ("https://127.0.0.1:443", "https://127.0.0.1:443", ""),
            ("dns://127.0.0.1", "dns://127.0.0.1", ""),
            ("foo%bar:baz", "foo:baz", "bar"),
            ("tls://[::1%example.net]:853", "tls://[::1]:853", "example.net"),
            ("https://[::1%example.net]:443", "https://[::1]:443", "example.net"),
        ] {
            assert_eq!(split_zone(input), (host.to_string(), zone.to_string()), "{input}");
        }
    }

    #[test]
    fn classify() {
        // TestClassifyToAddrs, with the files in a temporary directory
        let dir = std::env::temp_dir().join(format!("kerndns-fwd-classify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let resolv = dir.join("test_resolv.conf");
        std::fs::write(&resolv, "nameserver 10.0.0.1\n").unwrap();
        let commented = dir.join("commented_resolv.conf");
        std::fs::write(&commented, "# nameserver 1.1.1.1\n# nameserver 1.0.0.1\n").unwrap();
        let resolv = resolv.display().to_string();
        let commented = commented.display().to_string();
        let cases: Vec<(Vec<&str>, usize, usize)> = vec![
            (vec!["127.0.0.1"], 1, 0),
            (vec!["127.0.0.1:8053"], 1, 0),
            (vec!["::1"], 1, 0),
            (vec!["tls://127.0.0.1"], 1, 0),
            (vec![&resolv], 1, 0),
            (vec!["dns.example.com"], 0, 1),
            (vec!["dns.example.com:5353"], 0, 1),
            (vec!["tls://dns.example.com"], 0, 1),
            (vec!["https://dns.example.com"], 0, 1),
            (vec!["rbldnsd.rbldnsd.svc.cluster.local"], 0, 1),
            (vec!["127.0.0.1", "dns.example.com", "10.0.0.1"], 2, 1),
            (vec![&commented], 0, 0),
        ];
        for (input, st, dy) in cases {
            let input: Vec<String> = input.iter().map(|s| s.to_string()).collect();
            let e = classify_to_addrs(&input).unwrap();
            let s = e.iter().filter(|e| matches!(e, ToEntry::Static(_))).count();
            assert_eq!((s, e.len() - s), (st, dy), "{input:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();

        // TestClassifyToAddrsPreservesOrder
        let e = classify_to_addrs(&["dns.example.com".into(), "127.0.0.1".into(), "other.example.com".into()]).unwrap();
        assert!(matches!(&e[0], ToEntry::Dynamic(h) if h.hostname == "dns.example.com"));
        assert_eq!(e[1], ToEntry::Static(vec!["127.0.0.1:53".into()]));
        assert!(matches!(&e[2], ToEntry::Dynamic(h) if h.hostname == "other.example.com"));
    }

    #[test]
    fn host_entries() {
        // TestParseAsHostEntry
        let ok = |input: &str, host: &str, port: &str, t: &str, zone: &str| {
            assert_eq!(
                parse_as_host_entry(input),
                Some(HostEntry {
                    hostname: host.into(),
                    port: port.into(),
                    transport: transport(&format!("{t}://")).0,
                    zone: zone.into()
                }),
                "{input}"
            );
        };
        ok("dns.example.com", "dns.example.com", "53", DNS, "");
        ok("dns.example.com:5353", "dns.example.com", "5353", DNS, "");
        ok("tls://dns.example.com", "dns.example.com", "853", TLS, "");
        ok("tls://dns.example.com:8853", "dns.example.com", "8853", TLS, "");
        ok(
            "tls://dns.example.com%servername.example.com",
            "dns.example.com",
            "853",
            TLS,
            "servername.example.com",
        );
        ok("quic://dns.example.com", "dns.example.com", "853", QUIC, "");
        ok("quic://dns.example.com:8853", "dns.example.com", "8853", QUIC, "");
        ok(
            "quic://dns.example.com%servername.example.com",
            "dns.example.com",
            "853",
            QUIC,
            "servername.example.com",
        );
        ok("https://dns.example.com", "dns.example.com", "443", HTTPS, "");
        ok("https://dns.example.com:8443", "dns.example.com", "8443", HTTPS, "");
        ok(
            "https://dns.example.com%servername.example.com",
            "dns.example.com",
            "443",
            HTTPS,
            "servername.example.com",
        );
        ok(
            "rbldnsd.rbldnsd.svc.cluster.local",
            "rbldnsd.rbldnsd.svc.cluster.local",
            "53",
            DNS,
            "",
        );
        for bad in ["127.0.0.1", "::1", "grpc://example.com", ""] {
            assert_eq!(parse_as_host_entry(bad), None, "{bad}");
        }
    }

    #[test]
    fn resolved_addrs() {
        // TestFormatResolvedAddr
        for (ip, port, t, zone, want) in [
            ("10.0.0.1", "53", DNS, "", "10.0.0.1:53"),
            ("10.0.0.1", "853", TLS, "", "tls://10.0.0.1:853"),
            ("10.0.0.1", "853", TLS, "example.com", "tls://10.0.0.1%example.com:853"),
            ("10.0.0.1", "853", QUIC, "", "quic://10.0.0.1:853"),
            (
                "10.0.0.1",
                "853",
                QUIC,
                "example.com",
                "quic://10.0.0.1%example.com:853",
            ),
            ("10.0.0.1", "443", HTTPS, "", "https://10.0.0.1:443"),
            (
                "10.0.0.1",
                "443",
                HTTPS,
                "example.com",
                "https://10.0.0.1%example.com:443",
            ),
            ("::1", "53", DNS, "", "[::1]:53"),
            ("::1", "853", TLS, "", "tls://[::1]:853"),
            ("::1", "853", TLS, "example.com", "tls://[::1%example.com]:853"),
            ("::1", "853", QUIC, "", "quic://[::1]:853"),
            ("::1", "853", QUIC, "example.com", "quic://[::1%example.com]:853"),
            ("::1", "443", HTTPS, "", "https://[::1]:443"),
            ("::1", "443", HTTPS, "example.com", "https://[::1%example.com]:443"),
        ] {
            assert_eq!(format_resolved_addr(ip, port, t, zone), want);
        }
    }

    fn host(name: &str, port: &str, t: &'static str, zone: &str) -> ToEntry {
        ToEntry::Dynamic(HostEntry {
            hostname: name.into(),
            port: port.into(),
            transport: t,
            zone: zone.into(),
        })
    }

    fn normalize(a: &str) -> String {
        transport(&split_zone(a).0).1.to_string()
    }

    #[test]
    fn expand_dedup() {
        // TestExpandAndDedup
        let lookup = |h: &str| -> Result<Vec<String>, String> {
            Ok(match h {
                "host1.example.com" => vec!["10.0.0.1".into(), "10.0.0.2".into()],
                "host2.example.com" => vec!["10.0.0.2".into(), "10.0.0.3".into()],
                _ => vec![],
            })
        };
        let entries = vec![
            host("host1.example.com", "53", DNS, ""),
            host("host2.example.com", "53", DNS, ""),
            ToEntry::Static(vec!["10.0.0.3:53".into()]),
            ToEntry::Static(vec!["10.0.0.2:53".into()]),
        ];
        let got: Vec<String> = expand_and_dedup(&entries, &lookup)
            .unwrap()
            .iter()
            .map(|a| normalize(a))
            .collect();
        assert_eq!(got, ["10.0.0.1:53", "10.0.0.2:53", "10.0.0.3:53"]);

        // TestExpandAndDedupOrderPreserved
        let lookup = |_: &str| -> Result<Vec<String>, String> { Ok(vec!["10.0.0.42".into()]) };
        let entries = vec![
            host("myhost.example.com", "53", DNS, ""),
            ToEntry::Static(vec!["192.168.1.1:53".into()]),
        ];
        assert_eq!(
            expand_and_dedup(&entries, &lookup).unwrap(),
            ["10.0.0.42:53", "192.168.1.1:53"]
        );

        // TestExpandAndDedupTLS
        let lookup = |h: &str| -> Result<Vec<String>, String> {
            Ok(match h {
                "dns1.example.com" => vec!["9.9.9.9".into(), "149.112.112.112".into()],
                "dns2.example.com" => vec!["9.9.9.9".into(), "9.9.9.10".into()],
                _ => vec![],
            })
        };
        let entries = vec![
            host("dns1.example.com", "853", TLS, ""),
            host("dns2.example.com", "853", TLS, ""),
            ToEntry::Static(vec!["tls://149.112.112.112:853".into()]),
            ToEntry::Static(vec!["tls://9.9.9.10:853".into()]),
            host("dns1.example.com", "443", HTTPS, ""),
            host("dns2.example.com", "443", HTTPS, ""),
            ToEntry::Static(vec!["https://149.112.112.112:443".into()]),
            ToEntry::Static(vec!["https://9.9.9.10:443".into()]),
        ];
        let got: Vec<String> = expand_and_dedup(&entries, &lookup)
            .unwrap()
            .iter()
            .map(|a| normalize(a))
            .collect();
        assert_eq!(
            got,
            [
                "9.9.9.9:853",
                "149.112.112.112:853",
                "9.9.9.10:853",
                "9.9.9.9:443",
                "149.112.112.112:443",
                "9.9.9.10:443"
            ]
        );

        // TestExpandAndDedupKeepsDistinctDoTAndDoQEndpoints
        let entries = vec![
            ToEntry::Static(vec!["tls://192.0.2.1:853".into()]),
            ToEntry::Static(vec!["quic://192.0.2.1:853".into()]),
            ToEntry::Static(vec!["quic://192.0.2.1%doq.example:853".into()]),
            ToEntry::Static(vec!["quic://192.0.2.1%DOQ.EXAMPLE:853".into()]),
            ToEntry::Static(vec!["dns://192.0.2.2:53".into(), "192.0.2.2:53".into()]),
        ];
        assert_eq!(
            expand_and_dedup(&entries, &lookup).unwrap(),
            [
                "tls://192.0.2.1:853",
                "quic://192.0.2.1:853",
                "quic://192.0.2.1%doq.example:853",
                "dns://192.0.2.2:53"
            ]
        );
    }

    #[test]
    fn host_port_or_file_forms() {
        assert_eq!(host_port_or_file("127.0.0.1").unwrap(), ["127.0.0.1:53"]);
        assert_eq!(host_port_or_file("::1").unwrap(), ["[::1]:53"]);
        assert_eq!(host_port_or_file("https://1.1.1.1").unwrap(), ["https://1.1.1.1:443"]);
        assert_eq!(host_port_or_file("quic://1.1.1.1").unwrap(), ["quic://1.1.1.1:853"]);
        assert_eq!(
            host_port_or_file("tls://1.1.1.1%cloudflare-dns.com").unwrap(),
            ["tls://1.1.1.1%cloudflare-dns.com:853"]
        );
        assert_eq!(
            host_port_or_file("tls://fe80::1%example.com").unwrap(),
            ["tls://[fe80::1%example.com]:853"]
        );
        assert_eq!(host_port_or_file("dns://8.8.8.8:5353").unwrap(), ["dns://8.8.8.8:5353"]);
        assert!(matches!(host_port_or_file("tls://"), Err(HostError::Other(_))));
        assert!(matches!(host_port_or_file("a27.0.0.1"), Err(HostError::NotIpOrFile(_))));
    }

    #[test]
    fn dns_lookup_over_udp() {
        // TestDnsLookup / TestSetupWithHostnameTO: a resolver that answers A
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let q = Message::from_vec(&buf[..n]).unwrap();
                let mut r = Message::new(q.metadata.id, MessageType::Response, OpCode::Query);
                r.add_query(q.queries[0].clone());
                if q.queries[0].query_type() == RecordType::A {
                    r.add_answer(kerndns_core::proto::rr::Record::from_rdata(
                        q.queries[0].name().clone(),
                        60,
                        RData::A("10.0.0.42".parse().unwrap()),
                    ));
                }
                sock.send_to(&r.to_vec().unwrap(), from).unwrap();
            }
        });
        let ips = lookup_host("myhost.example.com", &[addr.to_string()]).unwrap();
        assert_eq!(ips, ["10.0.0.42"]);
        t.join().unwrap();
        let entries = vec![host("myhost.example.com", "53", DNS, "")];
        let none = |_: &str| -> Result<Vec<String>, String> { Err("lookup failed".into()) };
        assert_eq!(
            expand_and_dedup(&entries, &none).unwrap_err(),
            "failed to resolve \"myhost.example.com\": lookup failed"
        );
    }
}
