//! `dnsutil.UnpackRequest`: how CoreDNS's DoH, DoH3, DoQ and gRPC
//! listeners read a query. Unlike plain DNS, they apply miekg/dns's
//! default accept policy themselves and treat a rejected message as a bad
//! request (HTTP 400, a DoQ protocol error, a gRPC error) instead of
//! answering it.

use kerndns_core::proto::op::Message;

/// `errRequestRejected`.
pub const REJECTED: &str = "dns request rejected";

/// `dns.DefaultMsgAcceptFunc` on the header, then the full parse.
pub fn unpack_request(raw: &[u8]) -> Result<Message, String> {
    if raw.len() < 12 {
        return Err("dns: buffer size too small".into());
    }
    let word = |i: usize| u16::from_be_bytes([raw[i], raw[i + 1]]);
    let flags = word(2);
    let opcode = (flags >> 11) & 0xF;
    let rejected = flags & 0x8000 != 0 // a response
        || (opcode != 0 && opcode != 4) // not QUERY or NOTIFY
        || word(4) != 1 // questions
        || word(6) > 1 // answers (a NOTIFY may carry the SOA)
        || word(8) > 1 // authority (an IXFR request carries a SOA)
        || word(10) > 2; // additional
    if rejected {
        return Err(REJECTED.into());
    }
    Message::from_vec(raw).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerndns_core::proto::op::{MessageType, OpCode, Query};
    use kerndns_core::proto::rr::{Name, RecordType};

    fn query(op: OpCode, kind: MessageType, questions: usize) -> Vec<u8> {
        let mut m = Message::new(0, kind, op);
        for _ in 0..questions {
            m.add_query(Query::query(Name::from_ascii("example.org.").unwrap(), RecordType::A));
        }
        m.to_vec().unwrap()
    }

    #[test]
    fn accept_policy() {
        assert!(unpack_request(&query(OpCode::Query, MessageType::Query, 1)).is_ok());
        assert!(unpack_request(&query(OpCode::Notify, MessageType::Query, 1)).is_ok());
        let rejected = |b: Vec<u8>| unpack_request(&b).unwrap_err();
        assert_eq!(rejected(query(OpCode::Query, MessageType::Response, 1)), REJECTED);
        assert_eq!(rejected(query(OpCode::Update, MessageType::Query, 1)), REJECTED);
        assert_eq!(rejected(query(OpCode::Query, MessageType::Query, 0)), REJECTED);
        assert_eq!(rejected(query(OpCode::Query, MessageType::Query, 2)), REJECTED);
        assert_eq!(rejected(vec![0; 5]), "dns: buffer size too small");
        // header fine, body truncated
        let mut b = query(OpCode::Query, MessageType::Query, 1);
        b.truncate(15);
        assert!(unpack_request(&b).is_err());
    }
}
