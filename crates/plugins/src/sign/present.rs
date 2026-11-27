//! Records in master file (presentation) format, the way miekg/dns's
//! `RR.String()` writes them (`name<TAB>ttl<TAB>class<TAB>type<TAB>rdata`),
//! for the signed zone files that `file` reads back.

use kerndns_core::proto::dnssec::rdata::DNSSECRData;
use kerndns_core::proto::rr::{RData, Record, RecordType};

use crate::file::zonefile::{DNAME, dname_target, extra_type_name};

/// A record type's mnemonic, or `TYPEn` (RFC 3597) for unknown types.
pub fn type_string(t: RecordType) -> String {
    match t {
        RecordType::Unknown(n) => match extra_type_name(n) {
            Some(name) => name.to_string(),
            None => format!("TYPE{n}"),
        },
        t => t.to_string(),
    }
}

/// Unix seconds as `YYYYMMDDHHmmSS` in UTC (`dns.TimeToString`).
pub fn sig_time_string(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    // civil_from_days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn rdata_string(r: &Record) -> String {
    match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => {
            let i = s.input();
            format!(
                "{} {} {} {} {} {} {} {} {}",
                type_string(i.type_covered),
                u8::from(i.algorithm),
                i.num_labels,
                i.original_ttl,
                sig_time_string(i64::from(i.sig_expiration.get())),
                sig_time_string(i64::from(i.sig_inception.get())),
                i.key_tag,
                i.signer_name.to_ascii(),
                data_encoding::BASE64.encode(s.sig())
            )
        }
        RData::DNSSEC(DNSSECRData::NSEC(n)) => {
            let mut s = n.next_domain_name().to_ascii();
            for t in n.type_bit_maps() {
                s.push(' ');
                s.push_str(&type_string(t));
            }
            s
        }
        RData::DNSSEC(DNSSECRData::DS(ds)) => format!(
            "{} {} {} {}",
            ds.key_tag(),
            u8::from(ds.algorithm()),
            u8::from(ds.digest_type()),
            data_encoding::HEXUPPER.encode(ds.digest())
        ),
        RData::TXT(t) => t.txt_data.iter().map(|s| quote(s)).collect::<Vec<_>>().join(" "),
        RData::HINFO(h) => format!("{} {}", quote(&h.cpu), quote(&h.os)),
        RData::Unknown { code, rdata } if *code == DNAME => match dname_target(r) {
            Some(t) => t.to_ascii(),
            None => unknown(rdata.anything.as_slice()),
        },
        RData::Unknown { rdata, .. } => unknown(rdata.anything.as_slice()),
        d => d.to_string(),
    }
}

/// A quoted character-string, like miekg/dns's `sprintTxt`.
fn quote(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() + 2);
    s.push('"');
    for &c in b {
        match c {
            b'"' | b'\\' => {
                s.push('\\');
                s.push(c as char);
            }
            32..=126 => s.push(c as char),
            _ => s.push_str(&format!("\\{c:03}")),
        }
    }
    s.push('"');
    s
}

/// RFC 3597 `\# len hex`.
fn unknown(b: &[u8]) -> String {
    format!("\\# {} {}", b.len(), data_encoding::HEXLOWER.encode(b))
}

/// `RR.String()`.
pub fn rr_string(r: &Record) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}",
        r.name.to_ascii(),
        r.ttl,
        r.dns_class,
        type_string(r.record_type()),
        rdata_string(r)
    )
}
