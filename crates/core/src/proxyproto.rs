//! PROXY protocol v1 and v2 (HAProxy's spec): the listener configuration
//! set by the `proxyproto` plugin and a header parser that behaves like
//! `github.com/pires/go-proxyproto`, which CoreDNS uses (same accepted
//! input, same error messages).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// What to do with a PROXY header from a source (`proxyproto.Policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Use the address from the header.
    Use,
    /// Accept and strip a header, but keep the connection's address.
    Ignore,
    /// Refuse connections (or datagrams) that carry a header.
    Reject,
    /// No PROXY processing: a header is left in the data.
    Skip,
}

/// The `proxyproto` settings of a listener (`Config.ProxyProto*`).
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyProtoConfig {
    /// `allow`: sources whose headers are used. Empty means all.
    pub allow: Vec<(IpAddr, u8)>,
    /// `default`: the policy for sources outside `allow`.
    pub default: Policy,
    /// Whether `default` was given (without `allow` it then applies to all).
    pub default_set: bool,
    /// `udp_session_tracking`: how long a UDP header-only datagram's source
    /// is remembered for its sender. `None` disables tracking.
    pub udp_session_ttl: Option<Duration>,
    /// `udp_session_tracking ... MAX`: 0 means the default (10240).
    pub udp_max_sessions: usize,
    /// `tlv_metadata`: capture PPv2 TLVs for the `proxyproto/tlv` label.
    pub tlv_metadata: bool,
}

impl Default for ProxyProtoConfig {
    fn default() -> Self {
        ProxyProtoConfig {
            allow: Vec::new(),
            default: Policy::Ignore,
            default_set: false,
            udp_session_ttl: None,
            udp_max_sessions: 0,
            tlv_metadata: false,
        }
    }
}

/// Default size of the UDP session cache (`udpSessionMaxEntries`).
pub const UDP_SESSION_MAX_ENTRIES: usize = 10_240;

/// How long a TCP connection may take to send its header
/// (`DefaultReadHeaderTimeout`).
pub const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

impl ProxyProtoConfig {
    /// The connection policy for a peer (`ProxyProtoConnPolicy`).
    pub fn policy(&self, upstream: IpAddr) -> Policy {
        if self.allow.is_empty() {
            return if self.default_set { self.default } else { Policy::Use };
        }
        let ip = upstream.to_canonical();
        if self.allow.iter().any(|(net, len)| contains(*net, *len, ip)) {
            return Policy::Use;
        }
        self.default
    }

    /// Combine the settings of the blocks sharing a listener, like
    /// `newServer`: the last policy wins, tracking settings are taken
    /// when set, and TLV capture is on if any block wants it.
    pub fn merge(&mut self, other: &ProxyProtoConfig) {
        self.allow = other.allow.clone();
        self.default = other.default;
        self.default_set = other.default_set;
        if other.udp_session_ttl.is_some() {
            self.udp_session_ttl = other.udp_session_ttl;
        }
        if other.udp_max_sessions > 0 {
            self.udp_max_sessions = other.udp_max_sessions;
        }
        self.tlv_metadata |= other.tlv_metadata;
    }
}

fn contains(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    crate::cidr::IpNet::new(net, len).is_ok_and(|n| crate::cidr::contains(&n, ip))
}

const SIG_V1: &[u8] = b"PROXY";
const SIG_V2: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
/// `MaxV2HeaderSize`.
const MAX_V2_LEN: usize = 4096;

/// A parsed PROXY header (`proxyproto.Header`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    /// The LOCAL command (v2), or `UNKNOWN` (v1): no addresses to use.
    pub local: bool,
    /// The address family and protocol byte (v2 encoding; v1 maps to it).
    pub transport: u8,
    /// The client, for IPv4/IPv6 headers.
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
    /// The TLV vector as received (v2).
    pub tlvs: Vec<u8>,
}

const UNSPEC: u8 = 0x00;
const TCP4: u8 = 0x11;
const TCP6: u8 = 0x21;

impl Header {
    /// `UDPAddrs` succeeds: a datagram header with IP addresses.
    pub fn is_udp(&self) -> bool {
        self.transport & 0x0f == 0x02 && self.source.is_some() && self.destination.is_some()
    }

    /// The TLVs re-split and joined (`rawTLVs`): NOOP padding loses its
    /// value, and a malformed or empty vector gives `None`.
    pub fn raw_tlvs(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let raw = &self.tlvs;
        let mut i = 0;
        while i < raw.len() {
            let ty = raw[i];
            if raw.len() - i <= 2 {
                return None;
            }
            let n = usize::from(u16::from_be_bytes([raw[i + 1], raw[i + 2]]));
            i += 3;
            if i + n > raw.len() {
                return None;
            }
            out.push(ty);
            if ty == 0x04 {
                out.extend_from_slice(&[0, 0]);
            } else {
                out.extend_from_slice(&(n as u16).to_be_bytes());
                out.extend_from_slice(&raw[i..i + n]);
            }
            i += n;
        }
        if out.is_empty() { None } else { Some(out) }
    }
}

/// The result of looking for a header at the start of some bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// No PROXY signature (`ErrNoProxyProtocol`).
    NoHeader,
    /// A signature, but the header isn't complete yet; on a stream, read
    /// more. `eof` callers turn this into [`Parsed::NoHeader`] (signature
    /// incomplete) or an error (header incomplete) with [`parse_eof`].
    Incomplete,
    /// A header of `len` bytes.
    Header(Header, usize),
    Error(String),
}

/// Look for a header at the start of `buf`, which may hold only part of
/// the data (a stream): see [`Parsed::Incomplete`].
pub fn parse(buf: &[u8]) -> Parsed {
    parse_inner(buf, false)
}

/// Like [`parse`] for data that is complete (a datagram): a short read is
/// what go-proxyproto reports at EOF.
pub fn parse_eof(buf: &[u8]) -> Parsed {
    parse_inner(buf, true)
}

fn parse_inner(buf: &[u8], eof: bool) -> Parsed {
    let Some(&b0) = buf.first() else {
        return if eof { Parsed::NoHeader } else { Parsed::Incomplete };
    };
    if b0 != SIG_V1[0] && b0 != SIG_V2[0] {
        return Parsed::NoHeader;
    }
    // Peek(5), then Peek(12): a short read is no header at EOF
    if buf.len() < 5 {
        return if eof { Parsed::NoHeader } else { Parsed::Incomplete };
    }
    if &buf[..5] == SIG_V1 {
        return parse_v1(buf, eof);
    }
    if buf.len() < 12 {
        return if eof || !SIG_V2.starts_with(&buf[..buf.len().min(12)]) {
            Parsed::NoHeader
        } else {
            Parsed::Incomplete
        };
    }
    if &buf[..12] == SIG_V2 {
        return parse_v2(buf, eof);
    }
    Parsed::NoHeader
}

fn parse_v1(buf: &[u8], eof: bool) -> Parsed {
    let Some(end) = buf.iter().take(107).position(|&b| b == b'\n') else {
        if buf.len() >= 107 {
            return Parsed::Error("proxyproto: version 1 header must be 107 bytes or less".into());
        }
        return if eof {
            Parsed::Error("proxyproto: can't read version 1 header: EOF".into())
        } else {
            Parsed::Incomplete
        };
    };
    let line = &buf[..=end];
    if line.len() < 2 || line[line.len() - 2] != b'\r' {
        return Parsed::Error("proxyproto: version 1 header is invalid, must end with \\r\\n".into());
    }
    let text = String::from_utf8_lossy(&line[..line.len() - 2]);
    let tokens: Vec<&str> = text.split(' ').collect();
    let cant_proto = || Parsed::Error("proxyproto: can't read address family or protocol".into());
    if tokens[0] != "PROXY" {
        return Parsed::Error("proxyproto: can't read version 1 header".into());
    }
    if tokens.len() < 2 {
        return cant_proto();
    }
    let transport = match tokens[1] {
        "TCP4" => TCP4,
        "TCP6" => TCP6,
        "UNKNOWN" => UNSPEC,
        _ => return cant_proto(),
    };
    let mut h = Header {
        version: 1,
        local: transport == UNSPEC,
        transport,
        source: None,
        destination: None,
        tlvs: Vec::new(),
    };
    if h.local {
        return Parsed::Header(h, line.len());
    }
    if tokens.len() != 6 {
        return cant_proto();
    }
    let ip = |s: &str| -> Result<IpAddr, String> {
        let invalid = "proxyproto: invalid address".to_string();
        let addr: IpAddr = s.parse().map_err(|_| invalid.clone())?;
        match (transport, addr) {
            (TCP4, IpAddr::V4(_)) | (TCP6, IpAddr::V6(_)) => Ok(addr),
            _ => Err(invalid),
        }
    };
    let port = |s: &str| -> Result<u16, String> {
        let invalid = "proxyproto: invalid port number".to_string();
        if s.len() > 1 && s.starts_with('0') {
            return Err(invalid);
        }
        s.parse::<u16>().map_err(|_| invalid)
    };
    let parsed = (|| -> Result<(IpAddr, IpAddr, u16, u16), String> {
        Ok((ip(tokens[2])?, ip(tokens[3])?, port(tokens[4])?, port(tokens[5])?))
    })();
    match parsed {
        Ok((src, dst, sp, dp)) => {
            h.source = Some(SocketAddr::new(src, sp));
            h.destination = Some(SocketAddr::new(dst, dp));
            Parsed::Header(h, line.len())
        }
        Err(e) => Parsed::Error(e),
    }
}

fn parse_v2(buf: &[u8], eof: bool) -> Parsed {
    let short = |what: &str| {
        if eof {
            Parsed::Error(format!("proxyproto: can't read {what}: EOF"))
        } else {
            Parsed::Incomplete
        }
    };
    let Some(&cmd) = buf.get(12) else {
        return short("proxy protocol version and command");
    };
    if cmd != 0x20 && cmd != 0x21 {
        return Parsed::Error("proxyproto: unsupported proxy protocol version and command".into());
    }
    let local = cmd == 0x20;
    let Some(&transport) = buf.get(13) else {
        return short("address family or protocol");
    };
    if !matches!(transport, 0x00 | 0x11 | 0x12 | 0x21 | 0x22 | 0x31 | 0x32) || (transport == UNSPEC && !local) {
        return Parsed::Error("proxyproto: unsupported address family and protocol".into());
    }
    if buf.len() < 16 {
        return short("length");
    }
    let length = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
    let mut h = Header {
        version: 2,
        local,
        transport,
        source: None,
        destination: None,
        tlvs: Vec::new(),
    };
    let need = match transport >> 4 {
        1 => 12,
        2 => 36,
        3 => 216,
        _ => 0,
    };
    let invalid = || Parsed::Error("proxyproto: invalid length".into());
    if length < need {
        if !local || length > MAX_V2_LEN {
            return invalid();
        }
        // a LOCAL header's body is discarded
        if buf.len() < 16 + length {
            return if eof { invalid() } else { Parsed::Incomplete };
        }
        h.transport = UNSPEC;
        return Parsed::Header(h, 16 + length);
    }
    if length == 0 {
        return Parsed::Header(h, 16);
    }
    if length > MAX_V2_LEN {
        return invalid();
    }
    if buf.len() < 16 + length {
        if !eof {
            return Parsed::Incomplete;
        }
        if buf.len() < 16 + need {
            return Parsed::Error("proxyproto: invalid address: unexpected EOF".into());
        }
        return invalid();
    }
    let body = &buf[16..16 + length];
    match transport >> 4 {
        1 => {
            let src = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let dst = Ipv4Addr::new(body[4], body[5], body[6], body[7]);
            h.source = Some(SocketAddr::new(src.into(), u16::from_be_bytes([body[8], body[9]])));
            h.destination = Some(SocketAddr::new(dst.into(), u16::from_be_bytes([body[10], body[11]])));
        }
        2 => {
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&body[..16]).expect("16 bytes"));
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&body[16..32]).expect("16 bytes"));
            h.source = Some(SocketAddr::new(src.into(), u16::from_be_bytes([body[32], body[33]])));
            h.destination = Some(SocketAddr::new(dst.into(), u16::from_be_bytes([body[34], body[35]])));
        }
        // UNIX sockets: no address a DNS server can use
        _ => {}
    }
    h.tlvs = body[need..].to_vec();
    Parsed::Header(h, 16 + length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2(cmd: u8, transport: u8, body: &[u8]) -> Vec<u8> {
        let mut b = SIG_V2.to_vec();
        b.push(cmd);
        b.push(transport);
        b.extend_from_slice(&(body.len() as u16).to_be_bytes());
        b.extend_from_slice(body);
        b
    }

    fn v4_body(tlvs: &[u8]) -> Vec<u8> {
        let mut b = vec![192, 0, 2, 1, 10, 0, 0, 1, 0x30, 0x39, 0, 53];
        b.extend_from_slice(tlvs);
        b
    }

    #[test]
    fn v1() {
        let line = b"PROXY TCP4 192.0.2.1 10.0.0.1 12345 53\r\nrest";
        let Parsed::Header(h, n) = parse(line) else { panic!() };
        assert_eq!(n, line.len() - 4);
        assert_eq!(h.source, Some("192.0.2.1:12345".parse().unwrap()));
        assert_eq!(h.destination, Some("10.0.0.1:53".parse().unwrap()));
        assert!(!h.local && !h.is_udp());
        let Parsed::Header(h, _) = parse(b"PROXY UNKNOWN\r\n") else {
            panic!()
        };
        assert!(h.local);
        let err = |b: &[u8]| match parse(b) {
            Parsed::Error(e) => e,
            p => panic!("{p:?}"),
        };
        assert_eq!(
            err(b"PROXY TCP4 192.0.2.1 10.0.0.1 12345 53\n"),
            "proxyproto: version 1 header is invalid, must end with \\r\\n"
        );
        assert_eq!(
            err(b"PROXY TCP6 192.0.2.1 10.0.0.1 12345 53\r\n"),
            "proxyproto: invalid address"
        );
        assert_eq!(
            err(b"PROXY TCP4 192.0.2.1 10.0.0.1 012345 53\r\n"),
            "proxyproto: invalid port number"
        );
        assert_eq!(
            err(b"PROXY UDP4 192.0.2.1 10.0.0.1 1 53\r\n"),
            "proxyproto: can't read address family or protocol"
        );
        assert_eq!(
            err(&b"PROXY ".repeat(20)),
            "proxyproto: version 1 header must be 107 bytes or less"
        );
        assert_eq!(parse(b"PROXY TCP4 192.0"), Parsed::Incomplete);
        assert_eq!(parse(b"PROX"), Parsed::Incomplete);
        assert_eq!(parse_eof(b"PROX"), Parsed::NoHeader);
        assert_eq!(parse(b"\x12\x34"), Parsed::NoHeader);
    }

    #[test]
    fn v2_headers() {
        let tlvs = [0xe0, 0, 3, b'a', b'b', b'c', 0x04, 0, 2, 9, 9];
        let b = v2(0x21, 0x12, &v4_body(&tlvs));
        let Parsed::Header(h, n) = parse_eof(&b) else { panic!() };
        assert_eq!(n, b.len());
        assert!(h.is_udp() && !h.local);
        assert_eq!(h.source, Some("192.0.2.1:12345".parse().unwrap()));
        // NOOP padding loses its value
        assert_eq!(h.raw_tlvs().unwrap(), [0xe0, 0, 3, b'a', b'b', b'c', 0x04, 0, 0]);
        // LOCAL with UNSPEC
        let Parsed::Header(h, n) = parse_eof(&v2(0x20, 0x00, &[])) else {
            panic!()
        };
        assert!(h.local && !h.is_udp() && n == 16);
        // LOCAL with a short body is discarded
        let Parsed::Header(h, _) = parse_eof(&v2(0x20, 0x11, &[1, 2, 3])) else {
            panic!()
        };
        assert_eq!(h.transport, UNSPEC);
        let err = |b: &[u8]| match parse_eof(b) {
            Parsed::Error(e) => e,
            p => panic!("{p:?}"),
        };
        assert_eq!(
            err(&v2(0x21, 0x00, &[])),
            "proxyproto: unsupported address family and protocol"
        );
        assert_eq!(
            err(&v2(0x22, 0x11, &[])),
            "proxyproto: unsupported proxy protocol version and command"
        );
        assert_eq!(err(&v2(0x21, 0x11, &[1, 2, 3])), "proxyproto: invalid length");
        let mut trunc = v2(0x21, 0x11, &v4_body(&[]));
        trunc.truncate(20);
        assert_eq!(err(&trunc), "proxyproto: invalid address: unexpected EOF");
        assert_eq!(parse(&trunc), Parsed::Incomplete);
        // malformed TLVs are not exposed
        let Parsed::Header(h, _) = parse_eof(&v2(0x21, 0x11, &v4_body(&[0xe0, 0, 9]))) else {
            panic!()
        };
        assert_eq!(h.raw_tlvs(), None);
    }

    #[test]
    fn policy() {
        let mut c = ProxyProtoConfig::default();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(c.policy(ip("192.0.2.1")), Policy::Use);
        c.default_set = true;
        assert_eq!(c.policy(ip("192.0.2.1")), Policy::Ignore);
        c.allow = vec![(ip("192.168.1.0"), 24)];
        c.default = Policy::Reject;
        assert_eq!(c.policy(ip("192.168.1.7")), Policy::Use);
        assert_eq!(c.policy(ip("::ffff:192.168.1.7")), Policy::Use);
        assert_eq!(c.policy(ip("192.168.2.7")), Policy::Reject);
    }
}
