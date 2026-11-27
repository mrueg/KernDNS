//! A fast DNS message encoder for the common case.
//!
//! hickory's encoder writes field by field through a bounds-checked buffer
//! and keeps a heap copy of every compressible name; for small answers that
//! is most of the CPU a cheap plugin chain spends per query. [`to_wire`]
//! writes the message directly, with the same name compression rules as
//! hickory and miekg/dns (owner and question names, and the names inside
//! CNAME, NS, PTR, MX and SOA; SRV targets are not compressed), and falls
//! back to hickory for anything else: other record types, EDNS options,
//! TSIG/SIG(0) or an extended RCODE without EDNS.

use hickory_proto::ProtoError;
use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::{Name, RData, Record};

/// Encode `m` for the wire.
pub fn to_wire(m: &Message) -> Result<Vec<u8>, ProtoError> {
    match fast(m) {
        Some(v) => Ok(v),
        None => m.to_vec(),
    }
}

/// The encoded size of `m` (`usize::MAX` if it can't be encoded).
pub fn wire_len(m: &Message) -> usize {
    to_wire(m).map(|v| v.len()).unwrap_or(usize::MAX)
}

/// Like miekg/dns `Msg.Truncate`: keep as many answer, authority and
/// additional records (in that order) as fit in `size`, and set TC if any
/// record was dropped.
pub fn truncate(m: &mut Message, size: usize) {
    let size = size.max(512);
    if wire_len(m) <= size {
        return;
    }
    truncate_oversized(m, size);
}

/// [`truncate`] for a message already known not to fit.
pub fn truncate_oversized(m: &mut Message, size: usize) {
    let answers = std::mem::take(&mut m.answers);
    let authorities = std::mem::take(&mut m.authorities);
    let additionals = std::mem::take(&mut m.additionals);
    let (na, nn, nx) = (answers.len(), authorities.len(), additionals.len());

    let mut dropped = false;
    for (section, records) in [(0, answers), (1, authorities), (2, additionals)] {
        for r in records {
            if dropped {
                break;
            }
            let target = match section {
                0 => &mut m.answers,
                1 => &mut m.authorities,
                _ => &mut m.additionals,
            };
            target.push(r);
            if wire_len(m) > size {
                match section {
                    0 => m.answers.pop(),
                    1 => m.authorities.pop(),
                    _ => m.additionals.pop(),
                };
                dropped = true;
            }
        }
    }
    let kept = m.answers.len() + m.authorities.len() + m.additionals.len();
    if kept < na + nn + nx {
        m.metadata.truncation = true;
    }
}

/// Names already written, as (hash of the label sequence, offset).
struct Encoder {
    buf: Vec<u8>,
    names: Vec<(u64, u16)>,
}

const MAX_POINTER: usize = 0x3FFF;
/// Deeper names (rare) go through hickory's encoder.
const MAX_LABELS: usize = 32;

fn mix(h: u64, label: &[u8]) -> u64 {
    let mut h = (h ^ label.len() as u64).wrapping_mul(0x100_0000_01b3);
    for b in label {
        h = (h ^ u64::from(b.to_ascii_lowercase())).wrapping_mul(0x100_0000_01b3);
    }
    h
}

impl Encoder {
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Do the labels at `off` (following pointers) spell `labels`, ignoring
    /// ASCII case like hickory's and miekg's compression?
    fn matches_at(&self, mut off: usize, labels: &[&[u8]]) -> bool {
        let b = &self.buf;
        let mut hops = 0;
        let mut i = 0;
        loop {
            let Some(&len) = b.get(off) else { return false };
            if len & 0xC0 == 0xC0 {
                let Some(&lo) = b.get(off + 1) else { return false };
                off = (usize::from(len & 0x3F) << 8) | usize::from(lo);
                hops += 1;
                if hops > 127 {
                    return false;
                }
                continue;
            }
            if len == 0 {
                return i == labels.len();
            }
            let len = usize::from(len);
            if i == labels.len()
                || labels[i].len() != len
                || !b
                    .get(off + 1..off + 1 + len)
                    .is_some_and(|x| x.eq_ignore_ascii_case(labels[i]))
            {
                return false;
            }
            i += 1;
            off += 1 + len;
        }
    }

    /// Write `name`, compressed against earlier names if `compress`; its
    /// suffixes become targets for later names either way.
    /// `None` for names the fast path doesn't handle.
    fn name(&mut self, name: &Name, compress: bool) -> Option<()> {
        let mut labels: [&[u8]; MAX_LABELS] = [&[]; MAX_LABELS];
        let mut n = 0;
        for l in name.iter() {
            if l.len() > 63 || l.is_empty() || n == MAX_LABELS {
                return None;
            }
            labels[n] = l;
            n += 1;
        }
        let labels = &labels[..n];
        // hashes of each suffix labels[i..]
        let mut hashes = [0u64; MAX_LABELS];
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for i in (0..n).rev() {
            h = mix(h, labels[i]);
            hashes[i] = h;
        }
        let mut pointer = None;
        let mut write_upto = n;
        if compress {
            'search: for i in 0..n {
                for &(hh, off) in &self.names {
                    if hh == hashes[i] && self.matches_at(usize::from(off), &labels[i..]) {
                        pointer = Some(off);
                        write_upto = i;
                        break 'search;
                    }
                }
            }
        }
        for (i, l) in labels[..write_upto].iter().enumerate() {
            let off = self.buf.len();
            // uncompressed names (SRV targets) still serve as targets
            if off <= MAX_POINTER {
                self.names.push((hashes[i], off as u16));
            }
            self.buf.push(l.len() as u8);
            self.buf.extend_from_slice(l);
        }
        match pointer {
            Some(p) => self.u16(0xC000 | p),
            None => self.buf.push(0),
        }
        Some(())
    }

    fn record(&mut self, r: &Record) -> Option<()> {
        self.name(&r.name, true)?;
        self.u16(u16::from(r.record_type()));
        self.u16(u16::from(r.dns_class));
        self.u32(r.ttl);
        let len_at = self.buf.len();
        self.u16(0);
        match &r.data {
            RData::A(a) => self.buf.extend_from_slice(&a.0.octets()),
            RData::AAAA(a) => self.buf.extend_from_slice(&a.0.octets()),
            RData::CNAME(n) => self.name(&n.0, true)?,
            RData::NS(n) => self.name(&n.0, true)?,
            RData::PTR(n) => self.name(&n.0, true)?,
            RData::MX(mx) => {
                self.u16(mx.preference);
                self.name(&mx.exchange, true)?;
            }
            RData::SOA(s) => {
                self.name(&s.mname, true)?;
                self.name(&s.rname, true)?;
                self.u32(s.serial);
                self.u32(s.refresh as u32);
                self.u32(s.retry as u32);
                self.u32(s.expire as u32);
                self.u32(s.minimum);
            }
            RData::SRV(s) => {
                self.u16(s.priority);
                self.u16(s.weight);
                self.u16(s.port);
                self.name(&s.target, false)?;
            }
            RData::TXT(t) => {
                for s in &t.txt_data {
                    if s.len() > 255 {
                        return None;
                    }
                    self.buf.push(s.len() as u8);
                    self.buf.extend_from_slice(s);
                }
            }
            RData::Update0(_) => {}
            _ => return None,
        }
        let len = self.buf.len() - len_at - 2;
        let len = u16::try_from(len).ok()?;
        self.buf[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
        Some(())
    }
}

fn fast(m: &Message) -> Option<Vec<u8>> {
    if m.signature.is_some() {
        return None;
    }
    let md = &m.metadata;
    let rcode = md.response_code;
    if rcode.high() > 0 && m.edns.is_none() {
        return None;
    }
    if let Some(e) = &m.edns
        && !e.options().options.is_empty()
    {
        return None;
    }
    let count = |n: usize| u16::try_from(n).ok();
    let ar = m.additionals.len() + usize::from(m.edns.is_some());
    let (qd, an, ns, ar) = (
        count(m.queries.len())?,
        count(m.answers.len())?,
        count(m.authorities.len())?,
        count(ar)?,
    );

    let mut e = Encoder {
        buf: Vec::with_capacity(512),
        names: Vec::with_capacity(16),
    };
    e.u16(md.id);
    let mut b0 = if md.message_type == MessageType::Response {
        0x80
    } else {
        0
    };
    b0 |= (u8::from(md.op_code) & 0x0F) << 3;
    if md.authoritative {
        b0 |= 0x04;
    }
    if md.truncation {
        b0 |= 0x02;
    }
    if md.recursion_desired {
        b0 |= 0x01;
    }
    let mut b1 = rcode.low() & 0x0F;
    if md.recursion_available {
        b1 |= 0x80;
    }
    if md.authentic_data {
        b1 |= 0x20;
    }
    if md.checking_disabled {
        b1 |= 0x10;
    }
    e.buf.push(b0);
    e.buf.push(b1);
    e.u16(qd);
    e.u16(an);
    e.u16(ns);
    e.u16(ar);
    for q in &m.queries {
        e.name(q.name(), true)?;
        e.u16(u16::from(q.query_type()));
        e.u16(u16::from(q.query_class()));
    }
    for r in m.answers.iter().chain(&m.authorities).chain(&m.additionals) {
        e.record(r)?;
    }
    if let Some(edns) = &m.edns {
        e.buf.push(0);
        e.u16(41);
        e.u16(edns.max_payload().max(512));
        let ttl =
            (u32::from(rcode.high()) << 24) | (u32::from(edns.version()) << 16) | u32::from(u16::from(*edns.flags()));
        e.u32(ttl);
        e.u16(0);
    }
    Some(e.buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
    use hickory_proto::rr::{DNSClass, RecordType};
    use std::str::FromStr;

    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    fn rr(name: &str, data: RData) -> Record {
        Record::from_rdata(n(name), 300, data)
    }

    /// Decodes to the same message as hickory's encoding, and is no larger.
    fn check(m: &Message) {
        let ours = fast(m).expect("fast path");
        let theirs = m.to_vec().unwrap();
        let a = Message::from_vec(&ours).unwrap();
        let b = Message::from_vec(&theirs).unwrap();
        assert_eq!(a, b, "decoded messages differ");
        if ours.len() > theirs.len() {
            let hex = |v: &[u8]| {
                v.chunks(16)
                    .map(|c| c.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            eprintln!("ours:\n{}\ntheirs:\n{}", hex(&ours), hex(&theirs));
        }
        assert!(ours.len() <= theirs.len(), "{} > {}", ours.len(), theirs.len());
    }

    fn base() -> Message {
        let mut m = Message::new(4242, MessageType::Response, OpCode::Query);
        m.metadata.authoritative = true;
        m.metadata.recursion_desired = true;
        m.metadata.recursion_available = true;
        m.add_query(Query::query(n("www.Example.org."), RecordType::A));
        m
    }

    #[test]
    #[allow(deprecated)]
    fn matches_hickory() {
        let mut m = base();
        m.add_answer(rr("www.Example.org.", RData::CNAME(CNAME(n("web.example.org.")))));
        m.add_answer(rr("web.example.org.", RData::A(A::new(192, 0, 2, 1))));
        m.add_answer(rr(
            "web.example.org.",
            RData::AAAA(AAAA::from_str("2001:db8::1").unwrap()),
        ));
        m.add_answer(rr("example.org.", RData::MX(MX::new(10, n("mail.example.org.")))));
        m.add_answer(rr("1.2.0.192.in-addr.arpa.", RData::PTR(PTR(n("web.example.org.")))));
        m.add_answer(rr(
            "_dns._udp.example.org.",
            RData::SRV(SRV::new(0, 100, 53, n("ns.example.org."))),
        ));
        m.add_answer(rr(
            "example.org.",
            RData::TXT(TXT::new(vec!["a b".into(), "".into(), "c".into()])),
        ));
        m.add_authority(rr("example.org.", RData::NS(NS(n("ns.example.org.")))));
        m.add_authority(rr(
            "example.org.",
            RData::SOA(SOA::new(n("ns.example.org."), n("h.example.org."), 7, 60, -1, 3600, 5)),
        ));
        m.add_additional(rr("ns.example.org.", RData::A(A::new(192, 0, 2, 53))));
        check(&m);

        let mut e = Edns::new();
        e.set_max_payload(1232);
        e.set_dnssec_ok(true);
        m.edns = Some(e);
        m.metadata.response_code = ResponseCode::BADVERS;
        check(&m);

        let mut root = base();
        root.queries = vec![Query::query(Name::root(), RecordType::NS)];
        root.add_answer(rr(".", RData::NS(NS(n("a.root-servers.net.")))));
        root.metadata.truncation = true;
        root.metadata.op_code = OpCode::Notify;
        check(&root);
    }

    #[test]
    fn update_records_and_classes() {
        let mut m = Message::new(1, MessageType::Query, OpCode::Update);
        m.add_query(Query::query(n("example.org."), RecordType::SOA));
        let mut del = Record::update0(n("x.example.org."), 0, RecordType::TXT);
        del.dns_class = DNSClass::ANY;
        m.add_authority(del);
        check(&m);
    }

    #[test]
    fn falls_back() {
        let mut m = base();
        m.add_answer(rr(
            "example.org.",
            RData::NULL(hickory_proto::rr::rdata::NULL::with(vec![1, 2])),
        ));
        assert!(fast(&m).is_none());
        assert_eq!(to_wire(&m).unwrap(), m.to_vec().unwrap());
        // extended rcode without EDNS
        let mut m = base();
        m.metadata.response_code = ResponseCode::BADVERS;
        assert!(fast(&m).is_none());
    }

    #[test]
    fn many_names_compress() {
        let mut m = base();
        for i in 0..200 {
            m.add_answer(rr(
                &format!("h{i}.svc.cluster.local."),
                RData::A(A::new(10, 0, (i / 250) as u8, (i % 250) as u8)),
            ));
        }
        check(&m);
    }
}
