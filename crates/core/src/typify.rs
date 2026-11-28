//! Response classification and TTL helpers, like CoreDNS's
//! `plugin/pkg/response` (`Typify`, `Classify`) and `plugin/pkg/dnsutil`
//! (`MinimalTTL`).

use std::time::{Duration, SystemTime};

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::{RData, RecordType};

pub const MINIMAL_DEFAULT_TTL: Duration = Duration::from_secs(5);
pub const MAXIMUM_DEFAULT_TTL: Duration = Duration::from_secs(3600);

/// `response.Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    NoError,
    NameError,
    ServerError,
    NoData,
    Delegation,
    Meta,
    Update,
    OtherError,
}

/// `response.Class`: what `log`'s `class` option selects on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseClass {
    All,
    Success,
    Denial,
    Error,
}

impl ResponseClass {
    /// `Class.String()`.
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseClass::All => "all",
            ResponseClass::Success => "success",
            ResponseClass::Denial => "denial",
            ResponseClass::Error => "error",
        }
    }
}

impl ResponseType {
    /// `Type.String()`.
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseType::NoError => "NOERROR",
            ResponseType::NameError => "NXDOMAIN",
            ResponseType::ServerError => "SERVERERROR",
            ResponseType::NoData => "NODATA",
            ResponseType::Delegation => "DELEGATION",
            ResponseType::Meta => "META",
            ResponseType::Update => "UPDATE",
            ResponseType::OtherError => "OTHERERROR",
        }
    }

    pub fn class(self) -> ResponseClass {
        match self {
            ResponseType::NoError | ResponseType::Delegation => ResponseClass::Success,
            ResponseType::NameError | ResponseType::NoData => ResponseClass::Denial,
            _ => ResponseClass::Error,
        }
    }
}

/// True if any RRSIG in the answer or authority has expired (serial
/// number arithmetic, RFC 1982), like `typifyExpired`.
fn expired(m: &Message, now: SystemTime) -> bool {
    let now = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    m.answers.iter().chain(m.authorities.iter()).any(|r| match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => {
            let exp = s.input().sig_expiration.get();
            (now.wrapping_sub(exp) as i32) > 0
        }
        _ => false,
    })
}

/// Classify a response, like `response.Typify`.
pub fn typify(m: &Message, now: SystemTime) -> ResponseType {
    let do_bit = m.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
    match m.metadata.op_code {
        OpCode::Update => return ResponseType::Update,
        OpCode::Notify => return ResponseType::Meta,
        _ => {}
    }
    if m.queries
        .first()
        .is_some_and(|q| matches!(q.query_type(), RecordType::AXFR | RecordType::IXFR))
    {
        return ResponseType::Meta;
    }
    if do_bit && expired(m, now) {
        return ResponseType::OtherError;
    }
    let rcode = m.metadata.response_code;
    if !m.answers.is_empty() && rcode == ResponseCode::NoError {
        return ResponseType::NoError;
    }
    if !m.answers.is_empty() && rcode == ResponseCode::NXDomain {
        return ResponseType::OtherError;
    }
    let soa = m.authorities.iter().any(|r| r.record_type() == RecordType::SOA);
    let ns = m
        .authorities
        .iter()
        .filter(|r| r.record_type() == RecordType::NS)
        .count();
    if soa && rcode == ResponseCode::NoError {
        return ResponseType::NoData;
    }
    match rcode {
        ResponseCode::NXDomain => ResponseType::NameError,
        ResponseCode::ServFail | ResponseCode::NotImp => ResponseType::ServerError,
        ResponseCode::NoError if ns > 0 => ResponseType::Delegation,
        ResponseCode::NoError => ResponseType::NoError,
        _ => ResponseType::OtherError,
    }
}

/// The lowest TTL in the message, capped at `max`, like
/// `dnsutil.MinimalTTLWithMaximum`.
pub fn minimal_ttl(m: &Message, t: ResponseType, max: Duration) -> Duration {
    if !matches!(
        t,
        ResponseType::NoError | ResponseType::NameError | ResponseType::NoData
    ) {
        return MINIMAL_DEFAULT_TTL;
    }
    // (hickory keeps OPT out of the additional section)
    if m.answers.is_empty() && m.authorities.is_empty() && m.additionals.is_empty() {
        return MINIMAL_DEFAULT_TTL;
    }
    let mut min = max.as_secs() as u32;
    for r in m.answers.iter().chain(&m.authorities).chain(&m.additionals) {
        if r.record_type() != RecordType::OPT && r.ttl < min {
            min = r.ttl;
        }
    }
    Duration::from_secs(min as u64)
}
