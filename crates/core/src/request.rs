//! The request a plugin sees, with the helpers of CoreDNS's `request.Request`.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};

/// Smallest UDP response size a client must accept (RFC 1035).
pub const MIN_MSG_SIZE: u16 = 512;
/// Largest DNS message.
pub const MAX_MSG_SIZE: u16 = 65535;

/// The protocol a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Https3,
    Quic,
    Grpc,
}

impl Protocol {
    /// "udp" or "tcp", as CoreDNS's `Proto()` reports it: everything that is
    /// not plain UDP is connection-oriented and reported as "tcp".
    pub fn proto(&self) -> &'static str {
        match self {
            Protocol::Udp => "udp",
            _ => "tcp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protocol::Udp => "udp",
            Protocol::Tcp => "tcp",
            Protocol::Tls => "tls",
            Protocol::Https => "https",
            Protocol::Https3 => "https3",
            Protocol::Quic => "quic",
            Protocol::Grpc => "grpc",
        })
    }
}

/// An incoming DNS request plus where it came from.
#[derive(Debug, Clone)]
pub struct Request {
    pub msg: Message,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub protocol: Protocol,
    /// The request exactly as received, when it came off the wire (TSIG
    /// verification needs the original bytes).
    pub wire: Option<std::sync::Arc<[u8]>>,
}

/// `name` lowercased and fully qualified in presentation format. Labels
/// made of plain hostname bytes are copied directly; anything that needs
/// escaping goes through hickory's formatter.
pub fn lower_fqdn(name: &Name) -> String {
    let mut s = String::with_capacity(name.len() + 1);
    for label in name.iter() {
        if label.is_empty()
            || !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'*'))
        {
            let mut s = name.to_lowercase().to_ascii();
            if !s.ends_with('.') {
                s.push('.');
            }
            return s;
        }
        s.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
        s.push('.');
    }
    if s.is_empty() {
        s.push('.');
    }
    s
}

impl Request {
    pub fn new(msg: Message, local: SocketAddr, remote: SocketAddr, protocol: Protocol) -> Self {
        Self {
            msg,
            local,
            remote,
            protocol,
            wire: None,
        }
    }

    /// The first question. The server rejects requests without one before
    /// any plugin runs, so plugins can rely on it.
    pub fn query(&self) -> &Query {
        &self.msg.queries[0]
    }

    /// The query name as sent (case preserved), like `QName()`.
    pub fn qname(&self) -> &Name {
        self.query().name()
    }

    /// The query name lowercased and fully qualified, like `Name()`.
    pub fn name(&self) -> String {
        lower_fqdn(self.qname())
    }

    pub fn qtype(&self) -> RecordType {
        self.query().query_type()
    }

    pub fn qclass(&self) -> DNSClass {
        self.query().query_class()
    }

    pub fn id(&self) -> u16 {
        self.msg.metadata.id
    }

    pub fn ip(&self) -> IpAddr {
        self.remote.ip().to_canonical()
    }

    pub fn port(&self) -> u16 {
        self.remote.port()
    }

    /// 1 for IPv4, 2 for IPv6 (the address family numbers CoreDNS uses).
    pub fn family(&self) -> u8 {
        if self.ip().is_ipv4() { 1 } else { 2 }
    }

    /// "udp" or "tcp".
    pub fn proto(&self) -> &'static str {
        self.protocol.proto()
    }

    /// The request's EDNS record, if any.
    pub fn edns(&self) -> Option<&Edns> {
        self.msg.edns.as_ref()
    }

    /// The DNSSEC OK bit.
    pub fn do_bit(&self) -> bool {
        self.edns().is_some_and(|e| e.flags().dnssec_ok)
    }

    /// The advertised EDNS buffer size, 0 without EDNS.
    pub fn bufsize(&self) -> u16 {
        self.edns().map(|e| e.max_payload()).unwrap_or(0)
    }

    /// Largest response the client accepts: 64K over TCP, otherwise the EDNS
    /// buffer size but at least 512, like `Size()`.
    pub fn size(&self) -> u16 {
        if self.protocol != Protocol::Udp {
            return MAX_MSG_SIZE;
        }
        self.bufsize().max(MIN_MSG_SIZE)
    }

    /// A reply skeleton for this request, like miekg/dns `SetReply`: same id
    /// and opcode, RD and CD copied for queries, the first question copied.
    pub fn reply(&self) -> Message {
        let mut m = Message::new(self.msg.metadata.id, MessageType::Response, self.msg.metadata.op_code);
        if self.msg.metadata.op_code == OpCode::Query {
            m.metadata.recursion_desired = self.msg.metadata.recursion_desired;
            m.metadata.checking_disabled = self.msg.metadata.checking_disabled;
        }
        if let Some(q) = self.msg.queries.first() {
            m.queries.push(q.clone());
        }
        m
    }

    /// A reply with only a response code set, like `SetRcode`.
    pub fn error_reply(&self, rcode: ResponseCode) -> Message {
        let mut m = self.reply();
        m.metadata.response_code = rcode;
        m
    }

    /// Make the reply's EDNS match the request, like `SizeAndDo`: if the
    /// request had an OPT record, the reply gets one with version 0, the
    /// request's buffer size and the request's DO bit. Options already on
    /// the reply are kept; the request's options are not echoed.
    pub fn size_and_do(&self, reply: &mut Message) -> bool {
        let Some(req) = self.edns() else {
            return false;
        };
        let opt = reply.edns.get_or_insert_with(Edns::new);
        opt.set_version(0);
        opt.set_max_payload(req.max_payload());
        opt.set_rcode_high(0);
        *opt.flags_mut() = Default::default();
        opt.set_dnssec_ok(req.flags().dnssec_ok);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(name: &str, proto: Protocol) -> Request {
        let mut m = Message::new(42, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        Request::new(
            m,
            "127.0.0.1:53".parse().unwrap(),
            "[::ffff:10.0.0.1]:4242".parse().unwrap(),
            proto,
        )
    }

    #[test]
    fn lower_fqdn_matches_slow_path() {
        for n in [
            "Example.ORG.",
            "a.b",
            ".",
            "*.x.org.",
            "a\\.b.org.",
            "_srv._tcp.EX.org.",
        ] {
            let name = Name::from_ascii(n).unwrap();
            let mut slow = name.to_lowercase().to_ascii();
            if !slow.ends_with('.') {
                slow.push('.');
            }
            assert_eq!(lower_fqdn(&name), slow, "{n}");
        }
        // a label with a space (only possible from the wire)
        let name = Name::from_labels(vec![b"Sp ace".to_vec(), b"org".to_vec()]).unwrap();
        assert_eq!(lower_fqdn(&name), "sp\\040ace.org.");
    }

    #[test]
    fn helpers() {
        let r = req("Example.ORG.", Protocol::Udp);
        assert_eq!(r.name(), "example.org.");
        assert_eq!(r.qname().to_ascii(), "Example.ORG.");
        assert_eq!(r.ip().to_string(), "10.0.0.1");
        assert_eq!(r.family(), 1);
        assert_eq!(r.size(), 512);
        assert_eq!(req("a.", Protocol::Tls).size(), 65535);
        assert_eq!(req("a.", Protocol::Tls).proto(), "tcp");
        let reply = r.reply();
        assert_eq!(reply.metadata.id, 42);
        assert!(reply.metadata.recursion_desired);
        assert_eq!(reply.metadata.message_type, MessageType::Response);
    }

    #[test]
    fn size_and_do() {
        let mut r = req("a.", Protocol::Udp);
        let mut reply = r.reply();
        assert!(!r.size_and_do(&mut reply));
        let mut e = Edns::new();
        e.set_max_payload(1232);
        e.set_dnssec_ok(true);
        r.msg.edns = Some(e);
        assert_eq!(r.size(), 1232);
        assert!(r.size_and_do(&mut reply));
        let opt = reply.edns.unwrap();
        assert_eq!(opt.max_payload(), 1232);
        assert!(opt.flags().dnssec_ok);
    }
}
