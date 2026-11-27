//! dnstap messages (`dnstap.proto`) and their protobuf encoding, plus the
//! helpers of CoreDNS's `plugin/dnstap/msg`.

use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use kerndns_core::protobuf::{put_bytes_field, put_fixed32_field, put_varint_field};

/// `Message.Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    AuthQuery = 1,
    AuthResponse = 2,
    ResolverQuery = 3,
    ResolverResponse = 4,
    ClientQuery = 5,
    ClientResponse = 6,
    ForwarderQuery = 7,
    ForwarderResponse = 8,
    StubQuery = 9,
    StubResponse = 10,
    ToolQuery = 11,
    ToolResponse = 12,
    UpdateQuery = 13,
    UpdateResponse = 14,
}

/// `SocketFamily`.
pub const FAMILY_INET: u32 = 1;
pub const FAMILY_INET6: u32 = 2;
/// `SocketProtocol`.
pub const PROTO_UDP: u32 = 1;
pub const PROTO_TCP: u32 = 2;

/// A dnstap `Message`. Unset optional fields are left out of the encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub typ: MessageType,
    pub socket_family: Option<u32>,
    pub socket_protocol: Option<u32>,
    pub query_address: Option<Vec<u8>>,
    pub response_address: Option<Vec<u8>>,
    pub query_port: Option<u32>,
    pub response_port: Option<u32>,
    pub query_time: Option<(u64, u32)>,
    pub query_message: Option<Vec<u8>>,
    pub response_time: Option<(u64, u32)>,
    pub response_message: Option<Vec<u8>>,
}

/// The family and address bytes of `ip`: IPv4 (also IPv4-mapped IPv6) as
/// 4 octets with INET, anything else as 16 with INET6.
fn family_and_address(ip: IpAddr) -> (u32, Vec<u8>) {
    match ip.to_canonical() {
        IpAddr::V4(v4) => (FAMILY_INET, v4.octets().to_vec()),
        IpAddr::V6(v6) => (FAMILY_INET6, v6.octets().to_vec()),
    }
}

fn unix_time(t: SystemTime) -> (u64, u32) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs(), d.subsec_nanos())
}

impl Message {
    pub fn new(typ: MessageType) -> Self {
        Self {
            typ,
            socket_family: None,
            socket_protocol: None,
            query_address: None,
            response_address: None,
            query_port: None,
            response_port: None,
            query_time: None,
            query_message: None,
            response_time: None,
            response_message: None,
        }
    }

    /// `SetQueryAddress`: also sets the socket family and protocol (`tcp`
    /// is TCP, anything else UDP).
    pub fn set_query_address(&mut self, addr: SocketAddr, proto: &str) {
        let (family, a) = family_and_address(addr.ip());
        self.socket_protocol = Some(if proto == "tcp" { PROTO_TCP } else { PROTO_UDP });
        self.socket_family = Some(family);
        self.query_address = Some(a);
        self.query_port = Some(u32::from(addr.port()));
    }

    /// `SetResponseAddress`: also sets the socket family and protocol.
    pub fn set_response_address(&mut self, addr: SocketAddr, proto: &str) {
        let (family, a) = family_and_address(addr.ip());
        self.socket_protocol = Some(if proto == "tcp" { PROTO_TCP } else { PROTO_UDP });
        self.socket_family = Some(family);
        self.response_address = Some(a);
        self.response_port = Some(u32::from(addr.port()));
    }

    pub fn set_query_time(&mut self, t: SystemTime) {
        self.query_time = Some(unix_time(t));
    }

    pub fn set_response_time(&mut self, t: SystemTime) {
        self.response_time = Some(unix_time(t));
    }

    fn encode(&self, out: &mut Vec<u8>) {
        put_varint_field(out, 1, self.typ as u64);
        if let Some(v) = self.socket_family {
            put_varint_field(out, 2, u64::from(v));
        }
        if let Some(v) = self.socket_protocol {
            put_varint_field(out, 3, u64::from(v));
        }
        if let Some(v) = &self.query_address {
            put_bytes_field(out, 4, v);
        }
        if let Some(v) = &self.response_address {
            put_bytes_field(out, 5, v);
        }
        if let Some(v) = self.query_port {
            put_varint_field(out, 6, u64::from(v));
        }
        if let Some(v) = self.response_port {
            put_varint_field(out, 7, u64::from(v));
        }
        if let Some((s, ns)) = self.query_time {
            put_varint_field(out, 8, s);
            put_fixed32_field(out, 9, ns);
        }
        if let Some(v) = &self.query_message {
            put_bytes_field(out, 10, v);
        }
        if let Some((s, ns)) = self.response_time {
            put_varint_field(out, 12, s);
            put_fixed32_field(out, 13, ns);
        }
        if let Some(v) = &self.response_message {
            put_bytes_field(out, 14, v);
        }
    }
}

/// `Dnstap.Type`: MESSAGE.
const DNSTAP_MESSAGE: u64 = 1;

/// The `Dnstap` envelope of `m`, in protobuf.
pub fn encode_dnstap(identity: &[u8], version: &[u8], extra: Option<&[u8]>, m: &Message) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128);
    m.encode(&mut msg);
    let mut out = Vec::with_capacity(msg.len() + identity.len() + version.len() + 16);
    put_bytes_field(&mut out, 1, identity);
    put_bytes_field(&mut out, 2, version);
    if let Some(e) = extra {
        put_bytes_field(&mut out, 3, e);
    }
    put_bytes_field(&mut out, 14, &msg);
    put_varint_field(&mut out, 15, DNSTAP_MESSAGE);
    out
}

/// A decoded `Dnstap` (for tests and readers).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub identity: Option<Vec<u8>>,
    pub version: Option<Vec<u8>>,
    pub extra: Option<Vec<u8>>,
    pub typ: Option<u64>,
    /// The `Message` fields by number: varints, fixed32s and bytes.
    pub fields: std::collections::BTreeMap<u32, DecodedField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedField {
    Int(u64),
    Bytes(Vec<u8>),
}

impl Decoded {
    pub fn int(&self, field: u32) -> Option<u64> {
        match self.fields.get(&field)? {
            DecodedField::Int(v) => Some(*v),
            DecodedField::Bytes(_) => None,
        }
    }

    pub fn bytes(&self, field: u32) -> Option<&[u8]> {
        match self.fields.get(&field)? {
            DecodedField::Bytes(v) => Some(v),
            DecodedField::Int(_) => None,
        }
    }
}

/// Decode a `Dnstap` frame.
pub fn decode_dnstap(mut b: &[u8]) -> Option<Decoded> {
    use kerndns_core::protobuf::{Field, next_field};
    let mut d = Decoded::default();
    while !b.is_empty() {
        match next_field(&mut b)? {
            (1, Field::Bytes(v)) => d.identity = Some(v.to_vec()),
            (2, Field::Bytes(v)) => d.version = Some(v.to_vec()),
            (3, Field::Bytes(v)) => d.extra = Some(v.to_vec()),
            (15, Field::Varint(v)) => d.typ = Some(v),
            (14, Field::Bytes(mut m)) => {
                while !m.is_empty() {
                    let (n, f) = next_field(&mut m)?;
                    let v = match f {
                        Field::Varint(v) | Field::Fixed64(v) => DecodedField::Int(v),
                        Field::Fixed32(v) => DecodedField::Int(u64::from(v)),
                        Field::Bytes(v) => DecodedField::Bytes(v.to_vec()),
                    };
                    d.fields.insert(n, v);
                }
            }
            _ => {}
        }
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPPED: &str = "[::ffff:192.0.2.1]:53";

    // msg_test.go: TestSetAddressIPv4MappedReportedAsINET
    #[test]
    fn ipv4_mapped_is_inet() {
        for proto in ["udp", "tcp"] {
            let mut m = Message::new(MessageType::ClientQuery);
            m.set_query_address(MAPPED.parse().unwrap(), proto);
            assert_eq!(m.socket_family, Some(FAMILY_INET));
            assert_eq!(m.query_address.as_deref(), Some(&[192, 0, 2, 1][..]));
            let mut m = Message::new(MessageType::ClientQuery);
            m.set_response_address(MAPPED.parse().unwrap(), proto);
            assert_eq!(m.socket_family, Some(FAMILY_INET));
            assert_eq!(m.response_address.as_deref(), Some(&[192, 0, 2, 1][..]));
        }
    }

    // TestSetAddressNativeIPv4, TestSetAddressNativeIPv6
    #[test]
    fn native_addresses() {
        let mut m = Message::new(MessageType::ClientQuery);
        m.set_query_address("192.0.2.1:53".parse().unwrap(), "udp");
        assert_eq!(m.socket_family, Some(FAMILY_INET));
        assert_eq!(m.query_address.as_ref().unwrap().len(), 4);
        assert_eq!(m.socket_protocol, Some(PROTO_UDP));
        let mut m = Message::new(MessageType::ClientQuery);
        m.set_query_address("[2001:db8::1]:53".parse().unwrap(), "tcp");
        assert_eq!(m.socket_family, Some(FAMILY_INET6));
        assert_eq!(m.query_address.as_ref().unwrap().len(), 16);
        assert_eq!(m.socket_protocol, Some(PROTO_TCP));
    }

    #[test]
    fn encoding() {
        let mut m = Message::new(MessageType::ClientResponse);
        m.set_query_address("10.240.0.1:40212".parse().unwrap(), "udp");
        m.query_time = Some((1, 2));
        m.response_message = Some(vec![9, 9]);
        let wire = encode_dnstap(b"id", b"v", Some(b"x"), &m);
        // Go's proto.Marshal: identity, version, extra, message, type
        assert_eq!(&wire[..4], &[0x0a, 2, b'i', b'd']);
        assert_eq!(&wire[wire.len() - 2..], &[0x78, 1]);
        let d = decode_dnstap(&wire).unwrap();
        assert_eq!(d.identity.as_deref(), Some(&b"id"[..]));
        assert_eq!(d.extra.as_deref(), Some(&b"x"[..]));
        assert_eq!(d.typ, Some(1));
        assert_eq!(d.int(1), Some(6));
        assert_eq!(d.int(2), Some(1));
        assert_eq!(d.int(3), Some(1));
        assert_eq!(d.bytes(4), Some(&[10, 240, 0, 1][..]));
        assert_eq!(d.int(6), Some(40212));
        assert_eq!(d.int(8), Some(1));
        assert_eq!(d.int(9), Some(2));
        assert_eq!(d.bytes(14), Some(&[9, 9][..]));
        assert_eq!(d.int(12), None);
    }
}
