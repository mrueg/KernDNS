//! RFC 1035 master file reader, matching what miekg/dns's `ZoneParser`
//! accepts for CoreDNS: `$ORIGIN`, `$TTL`, `$INCLUDE`, parentheses,
//! comments, relative names, omitted owner/TTL/class, pre-signed DNSSEC
//! records (RRSIG, NSEC, DNSKEY, DS), DNAME and RFC 3597 `\# len hex` data.
//!
//! hickory-proto's own zone parser can't be used: it rejects RRSIG records
//! ("should be dynamically generated"), doesn't know DNAME, and merges
//! records into RRsets with RFC 2136 update semantics. Rdata without domain
//! names is still parsed by hickory (`RData::try_from_str`).

use std::path::{Path, PathBuf};
use std::str::FromStr;

use kerndns_core::proto::dnssec::Algorithm;
use kerndns_core::proto::dnssec::rdata::sig::SigInput;
use kerndns_core::proto::dnssec::rdata::{DNSSECRData, NSEC, RRSIG};
use kerndns_core::proto::rr::rdata::{CNAME, MX, NS, NULL, PTR, SOA, SRV};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType, SerialNumber};
use kerndns_core::proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder, Restrict};
use kerndns_core::proto::serialize::txt::parse_ttl;

/// RFC 6672 DNAME. hickory knows the type but has no typed rdata for it,
/// so DNAME records carry their target as raw wire bytes.
pub const DNAME: RecordType = RecordType::DNAME;
const MAX_INCLUDE_DEPTH: usize = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneFileError(pub String);

impl std::fmt::Display for ZoneFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ZoneFileError {}

/// Read a zone from `text`. `file` is used for errors and relative
/// `$INCLUDE` paths; `origin` must be fully qualified.
pub fn parse_zone(text: &str, origin: &Name, file: &Path) -> Result<Vec<Record>, ZoneFileError> {
    let mut st = State {
        origin: origin.clone(),
        def_ttl: None,
        ttl_by_directive: false,
        last_owner: None,
        records: Vec::new(),
    };
    st.read(text, file, 0)?;
    Ok(st.records)
}

#[derive(Debug, Clone)]
struct Tok {
    text: String,
    quoted: bool,
}

#[derive(Debug)]
struct Line {
    no: usize,
    /// The line started with whitespace: the owner is the previous owner.
    blank_owner: bool,
    toks: Vec<Tok>,
}

/// Split master-file text into logical lines (parentheses join lines).
#[allow(unused_assignments)] // the final push_tok! resets state that is not read again
fn lex(text: &str) -> Result<Vec<Line>, String> {
    let mut lines = Vec::new();
    let mut toks: Vec<Tok> = Vec::new();
    let mut cur = String::new();
    let mut in_tok = false;
    let mut quoted = false;
    let mut in_quote = false;
    let mut escaped = false;
    let mut parens = 0usize;
    let mut comment = false;
    let mut line_no = 1usize;
    let mut start_no = 1usize;
    let mut blank_owner = false;
    let mut at_line_start = true;

    macro_rules! push_tok {
        () => {
            if in_tok {
                toks.push(Tok {
                    text: std::mem::take(&mut cur),
                    quoted,
                });
                in_tok = false;
                quoted = false;
            }
        };
    }

    for ch in text.chars() {
        if comment {
            if ch != '\n' {
                continue;
            }
            comment = false;
        }
        if in_quote {
            if escaped {
                cur.push(ch);
                escaped = false;
            } else if ch == '\\' {
                cur.push(ch);
                escaped = true;
            } else if ch == '"' {
                in_quote = false;
            } else {
                if ch == '\n' {
                    line_no += 1;
                }
                cur.push(ch);
            }
            continue;
        }
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if at_line_start {
            at_line_start = false;
            if toks.is_empty() && parens == 0 {
                blank_owner = ch == ' ' || ch == '\t';
                start_no = line_no;
            }
        }
        match ch {
            '\\' => {
                if !in_tok {
                    in_tok = true;
                }
                cur.push(ch);
                escaped = true;
            }
            ';' => {
                push_tok!();
                comment = true;
                if parens == 0 {
                    // handled at the newline
                }
            }
            '"' => {
                if !in_tok {
                    in_tok = true;
                }
                quoted = true;
                in_quote = true;
            }
            '(' => {
                push_tok!();
                parens += 1;
            }
            ')' => {
                push_tok!();
                if parens == 0 {
                    return Err(format!("line {line_no}: extra closing parenthesis"));
                }
                parens -= 1;
            }
            '\n' => {
                push_tok!();
                line_no += 1;
                if parens == 0 {
                    if !toks.is_empty() {
                        lines.push(Line {
                            no: start_no,
                            blank_owner,
                            toks: std::mem::take(&mut toks),
                        });
                    }
                    blank_owner = false;
                }
                at_line_start = true;
            }
            c if c.is_whitespace() => push_tok!(),
            c => {
                if !in_tok {
                    in_tok = true;
                }
                cur.push(c);
            }
        }
    }
    if in_quote {
        return Err(format!("line {line_no}: unterminated quoted string"));
    }
    if parens > 0 {
        return Err(format!("line {line_no}: unbalanced parenthesis"));
    }
    push_tok!();
    if !toks.is_empty() {
        lines.push(Line {
            no: start_no,
            blank_owner,
            toks,
        });
    }
    Ok(lines)
}

struct State {
    origin: Name,
    /// TTL for records without one: `$TTL`, or the last explicit TTL.
    def_ttl: Option<u32>,
    ttl_by_directive: bool,
    last_owner: Option<Name>,
    records: Vec<Record>,
}

impl State {
    fn read(&mut self, text: &str, file: &Path, depth: usize) -> Result<(), ZoneFileError> {
        let err = |no: usize, msg: String| ZoneFileError(format!("dns: {msg}: {}:{no}", file.display()));
        let lines = lex(text).map_err(|e| ZoneFileError(format!("dns: {e} in {}", file.display())))?;
        for line in lines {
            let t = &line.toks;
            let first = t[0].text.as_str();
            if !t[0].quoted && first.starts_with('$') {
                match first.to_ascii_uppercase().as_str() {
                    "$ORIGIN" => {
                        let o = t.get(1).ok_or_else(|| err(line.no, "$ORIGIN needs a name".into()))?;
                        self.origin = parse_name(&o.text, &self.origin).map_err(|e| err(line.no, e))?;
                    }
                    "$TTL" => {
                        let v = t.get(1).ok_or_else(|| err(line.no, "$TTL needs a value".into()))?;
                        self.def_ttl = Some(parse_ttl(&v.text).map_err(|e| err(line.no, format!("bad $TTL: {e}")))?);
                        self.ttl_by_directive = true;
                    }
                    "$INCLUDE" => {
                        if depth >= MAX_INCLUDE_DEPTH {
                            return Err(err(line.no, "too deeply nested $INCLUDE".into()));
                        }
                        let p = t.get(1).ok_or_else(|| err(line.no, "$INCLUDE needs a file".into()))?;
                        let mut path = PathBuf::from(&p.text);
                        if path.is_relative() {
                            path = file.parent().unwrap_or(Path::new(".")).join(path);
                        }
                        let content = std::fs::read_to_string(&path)
                            .map_err(|e| err(line.no, format!("failed to open `{}': {e}", path.display())))?;
                        let saved = self.origin.clone();
                        if let Some(o) = t.get(2) {
                            self.origin = parse_name(&o.text, &self.origin).map_err(|e| err(line.no, e))?;
                        }
                        self.read(&content, &path, depth + 1)?;
                        self.origin = saved;
                    }
                    other => return Err(err(line.no, format!("unsupported directive {other}"))),
                }
                continue;
            }
            let rec = self.record(&line).map_err(|e| err(line.no, e))?;
            self.records.push(rec);
        }
        Ok(())
    }

    fn record(&mut self, line: &Line) -> Result<Record, String> {
        let mut i = 0;
        let toks = &line.toks;
        let owner = if line.blank_owner {
            self.last_owner.clone().ok_or("no previous owner name")?
        } else {
            i = 1;
            parse_name(&toks[0].text, &self.origin)?
        };
        self.last_owner = Some(owner.clone());

        let mut ttl: Option<u32> = None;
        let mut class = DNSClass::IN;
        let mut class_given = false;
        let mut rtype: Option<RecordType> = None;
        // up to two of [ttl] [class] in any order, then the type
        while i < toks.len() {
            let w = toks[i].text.as_str();
            if ttl.is_none() && w.as_bytes().first().is_some_and(u8::is_ascii_digit) {
                ttl = Some(parse_ttl(w).map_err(|e| format!("bad TTL {w:?}: {e}"))?);
                i += 1;
                continue;
            }
            if let Some(c) = parse_class(w) {
                class = c;
                class_given = true;
                i += 1;
                continue;
            }
            rtype = Some(parse_type(w)?);
            i += 1;
            break;
        }
        let rtype = rtype.ok_or("missing record type")?;
        let rdata_toks = &toks[i..];

        let data = parse_rdata(rtype, rdata_toks, &self.origin)?;
        // miekg/dns: an explicit TTL becomes the default unless $TTL set
        // one; without any, a record that names its class gets TTL 0.
        let ttl = match ttl {
            Some(t) => {
                if !self.ttl_by_directive {
                    self.def_ttl = Some(t);
                }
                t
            }
            None => match self.def_ttl {
                Some(t) => t,
                None if class_given => 0,
                None => return Err("missing TTL with no previous value".into()),
            },
        };
        let mut rec = Record::from_rdata(owner, ttl, data);
        rec.dns_class = class;
        Ok(rec)
    }
}

fn parse_class(w: &str) -> Option<DNSClass> {
    match w.to_ascii_uppercase().as_str() {
        "IN" => Some(DNSClass::IN),
        "CH" | "CHAOS" => Some(DNSClass::CH),
        "HS" => Some(DNSClass::HS),
        "NONE" => Some(DNSClass::NONE),
        "ANY" => Some(DNSClass::ANY),
        u => u
            .strip_prefix("CLASS")
            .and_then(|n| n.parse::<u16>().ok())
            .map(DNSClass::from),
    }
}

fn parse_type(w: &str) -> Result<RecordType, String> {
    let up = w.to_ascii_uppercase();
    if let Some(n) = up.strip_prefix("TYPE") {
        return n
            .parse::<u16>()
            .map(RecordType::from)
            .map_err(|_| format!("bad record type {w:?}"));
    }
    RecordType::from_str(&up).map_err(|_| format!("unknown record type {w:?}"))
}

/// A name relative to `origin` unless it ends in a dot; `@` is the origin.
pub fn parse_name(s: &str, origin: &Name) -> Result<Name, String> {
    if s == "@" {
        return Ok(origin.clone());
    }
    // RFC 1035 escapes (\X and decimal \DDD), like miekg/dns. hickory's
    // own parser reads \DDD as octal, so labels are split here.
    let (labels, fqdn) = split_labels(s)?;
    let n = Name::from_labels(labels.iter().map(Vec::as_slice)).map_err(|e| format!("bad name {s:?}: {e}"))?;
    if fqdn {
        let mut n = n;
        n.set_fqdn(true);
        return Ok(n);
    }
    let mut n = n.append_domain(origin).map_err(|e| format!("bad name {s:?}: {e}"))?;
    n.set_fqdn(true);
    Ok(n)
}

/// Split a presentation-format name into raw labels. Returns whether the
/// name ended with an unescaped dot (fully qualified).
fn split_labels(s: &str) -> Result<(Vec<Vec<u8>>, bool), String> {
    if s == "." {
        return Ok((Vec::new(), true));
    }
    let b = s.as_bytes();
    let mut labels = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0;
    let mut fqdn = false;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                let digits = b.get(i + 1..i + 4).filter(|d| d.iter().all(u8::is_ascii_digit));
                if let Some(d) = digits {
                    let v = (d[0] - b'0') as u32 * 100 + (d[1] - b'0') as u32 * 10 + (d[2] - b'0') as u32;
                    if v > 255 {
                        return Err(format!("bad escape in name {s:?}"));
                    }
                    cur.push(v as u8);
                    i += 4;
                } else if let Some(&c) = b.get(i + 1) {
                    cur.push(c);
                    i += 2;
                } else {
                    return Err(format!("trailing backslash in name {s:?}"));
                }
            }
            b'.' => {
                if cur.is_empty() {
                    return Err(format!("empty label in name {s:?}"));
                }
                labels.push(std::mem::take(&mut cur));
                i += 1;
                if i == b.len() {
                    fqdn = true;
                }
            }
            c => {
                cur.push(c);
                i += 1;
            }
        }
    }
    if !cur.is_empty() {
        labels.push(cur);
    }
    Ok((labels, fqdn))
}

fn arg<'a>(toks: &'a [Tok], i: usize, what: &str) -> Result<&'a str, String> {
    toks.get(i)
        .map(|t| t.text.as_str())
        .ok_or_else(|| format!("missing {what}"))
}

fn num<T: FromStr>(toks: &[Tok], i: usize, what: &str) -> Result<T, String> {
    let s = arg(toks, i, what)?;
    s.parse::<T>().map_err(|_| format!("bad {what} {s:?}"))
}

/// Re-join rdata tokens for hickory's parser, restoring quotes.
fn join(toks: &[Tok]) -> String {
    toks.iter()
        .map(|t| {
            if t.quoted {
                format!("\"{}\"", t.text)
            } else {
                t.text.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_rdata(rtype: RecordType, toks: &[Tok], origin: &Name) -> Result<RData, String> {
    // RFC 3597: \# <length> <hex...>
    if toks.first().is_some_and(|t| t.text == "\\#" && !t.quoted) {
        let len: usize = num(toks, 1, "rdata length")?;
        let hex: String = toks[2..].iter().map(|t| t.text.as_str()).collect();
        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex.to_ascii_lowercase().as_bytes())
            .map_err(|e| format!("bad hex rdata: {e}"))?;
        if bytes.len() != len {
            return Err(format!(
                "rdata length {len} doesn't match {} bytes of data",
                bytes.len()
            ));
        }
        if matches!(rtype, RecordType::Unknown(_) | DNAME) {
            return Ok(RData::Unknown {
                code: rtype,
                rdata: NULL::with(bytes),
            });
        }
        let mut dec = BinDecoder::new(&bytes);
        return RData::read(&mut dec, rtype, Restrict::new(len as u16)).map_err(|e| format!("bad rdata: {e}"));
    }

    let name = |i: usize, what: &str| -> Result<Name, String> { parse_name(arg(toks, i, what)?, origin) };
    Ok(match rtype {
        RecordType::NS => RData::NS(NS(name(0, "name server")?)),
        RecordType::CNAME => RData::CNAME(CNAME(name(0, "target")?)),
        RecordType::PTR => RData::PTR(PTR(name(0, "target")?)),
        DNAME => dname_rdata(&name(0, "target")?)?,
        RecordType::MX => RData::MX(MX::new(num(toks, 0, "preference")?, name(1, "exchange")?)),
        RecordType::SRV => RData::SRV(SRV::new(
            num(toks, 0, "priority")?,
            num(toks, 1, "weight")?,
            num(toks, 2, "port")?,
            name(3, "target")?,
        )),
        RecordType::SOA => {
            let t = |i: usize, what: &str| -> Result<u32, String> {
                let s = arg(toks, i, what)?;
                parse_ttl(s).map_err(|_| format!("bad {what} {s:?}"))
            };
            RData::SOA(SOA::new(
                name(0, "mname")?,
                name(1, "rname")?,
                num(toks, 2, "serial")?,
                t(3, "refresh")? as i32,
                t(4, "retry")? as i32,
                t(5, "expire")? as i32,
                t(6, "minimum")?,
            ))
        }
        RecordType::SVCB | RecordType::HTTPS => {
            // make the target absolute, then let hickory parse the params
            let mut owned: Vec<Tok> = toks.to_vec();
            if owned.len() < 2 {
                return Err("missing SVCB priority/target".into());
            }
            owned[1].text = name(1, "target")?.to_ascii();
            RData::try_from_str(rtype, &join(&owned)).map_err(|e| format!("bad {rtype} rdata: {e}"))?
        }
        RecordType::RRSIG => rrsig_rdata(toks, origin)?,
        RecordType::DNSKEY | RecordType::CDNSKEY => {
            // flags protocol algorithm base64-key, decoded from wire form
            // (hickory refuses DNSKEY text)
            let flags: u16 = num(toks, 0, "flags")?;
            let protocol: u8 = num(toks, 1, "protocol")?;
            let algorithm: u8 = num(toks, 2, "algorithm")?;
            let b64: String = toks
                .get(3..)
                .unwrap_or_default()
                .iter()
                .map(|t| t.text.as_str())
                .collect();
            let key = data_encoding::BASE64
                .decode(b64.as_bytes())
                .map_err(|e| format!("bad key: {e}"))?;
            let mut wire = flags.to_be_bytes().to_vec();
            wire.push(protocol);
            wire.push(algorithm);
            wire.extend(key);
            let mut dec = BinDecoder::new(&wire);
            RData::read(&mut dec, rtype, Restrict::new(wire.len() as u16)).map_err(|e| format!("bad {rtype}: {e}"))?
        }
        RecordType::NSEC => {
            let next = name(0, "next domain")?;
            let types = toks[1..]
                .iter()
                .map(|t| parse_type(&t.text))
                .collect::<Result<Vec<_>, _>>()?;
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, types)))
        }
        RecordType::Unknown(_) => return Err(format!("unknown record type {rtype} needs RFC 3597 \\# rdata")),
        _ => RData::try_from_str(rtype, &join(toks)).map_err(|e| format!("bad {rtype} rdata: {e}"))?,
    })
}

/// DNAME rdata as wire bytes of the (uncompressed) target name.
pub fn dname_rdata(target: &Name) -> Result<RData, String> {
    let mut buf = Vec::new();
    let mut enc = BinEncoder::new(&mut buf);
    enc.set_canonical_form(true);
    target.emit(&mut enc).map_err(|e| e.to_string())?;
    Ok(RData::Unknown {
        code: DNAME,
        rdata: NULL::with(buf),
    })
}

/// The target of a DNAME record.
pub fn dname_target(r: &Record) -> Option<Name> {
    match &r.data {
        RData::Unknown { code, rdata } if *code == DNAME => {
            let bytes = &rdata.anything;
            let mut dec = BinDecoder::new(bytes);
            Name::read(&mut dec).ok()
        }
        _ => None,
    }
}

fn rrsig_rdata(toks: &[Tok], origin: &Name) -> Result<RData, String> {
    let type_covered = parse_type(arg(toks, 0, "type covered")?)?;
    let algorithm = Algorithm::from_u8(num(toks, 1, "algorithm")?);
    let num_labels: u8 = num(toks, 2, "labels")?;
    let original_ttl: u32 = num(toks, 3, "original TTL")?;
    let expiration = sig_time(arg(toks, 4, "expiration")?)?;
    let inception = sig_time(arg(toks, 5, "inception")?)?;
    let key_tag: u16 = num(toks, 6, "key tag")?;
    let signer_name = parse_name(arg(toks, 7, "signer")?, origin)?;
    let b64: String = toks
        .get(8..)
        .unwrap_or_default()
        .iter()
        .map(|t| t.text.as_str())
        .collect();
    let sig = data_encoding::BASE64
        .decode(b64.as_bytes())
        .map_err(|e| format!("bad signature: {e}"))?;
    let input = SigInput {
        type_covered,
        algorithm,
        num_labels,
        original_ttl,
        sig_expiration: SerialNumber::new(expiration),
        sig_inception: SerialNumber::new(inception),
        key_tag,
        signer_name,
    };
    Ok(RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig))))
}

/// RRSIG times: `YYYYMMDDHHmmSS` (UTC) or seconds since the epoch, mod 2^32.
fn sig_time(s: &str) -> Result<u32, String> {
    if s.len() == 14 && s.bytes().all(|b| b.is_ascii_digit()) {
        let p = |a: usize, b: usize| s[a..b].parse::<i64>().unwrap();
        let (y, mo, d, h, mi, se) = (p(0, 4), p(4, 6), p(6, 8), p(8, 10), p(10, 12), p(12, 14));
        let days = days_from_civil(y, mo, d);
        let secs = days * 86400 + h * 3600 + mi * 60 + se;
        return Ok(secs.rem_euclid(1 << 32) as u32);
    }
    s.parse::<u32>().map_err(|_| format!("bad signature time {s:?}"))
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(text: &str) -> Vec<Record> {
        parse_zone(
            text,
            &Name::from_ascii("example.org.").unwrap(),
            Path::new("db.example.org"),
        )
        .unwrap()
    }

    #[test]
    fn basics() {
        let r = zone(
            "$TTL 1h\n\
             @ IN SOA ns1 hostmaster (\n  2024010101 ; serial\n  7200 3600 1209600 300 )\n\
             \tIN NS ns1\n\
             ns1 300 IN A 192.0.2.1\n\
             www CNAME @\n\
             _sip._tcp SRV 0 5 5060 sip.example.net.\n\
             txt TXT \"hello world\" \"a;b\"\n\
             mx 600 MX 10 mail\n",
        );
        let s: Vec<String> = r.iter().map(|r| r.to_string()).collect();
        assert_eq!(
            s[0],
            "example.org. 3600 IN SOA ns1.example.org. hostmaster.example.org. 2024010101 7200 3600 1209600 300"
        );
        assert_eq!(s[1], "example.org. 3600 IN NS ns1.example.org.");
        assert_eq!(s[2], "ns1.example.org. 300 IN A 192.0.2.1");
        assert_eq!(s[3], "www.example.org. 3600 IN CNAME example.org.");
        assert_eq!(s[4], "_sip._tcp.example.org. 3600 IN SRV 0 5 5060 sip.example.net.");
        assert!(s[5].contains("hello world"), "{}", s[5]);
        assert_eq!(s[6], "mx.example.org. 600 IN MX 10 mail.example.org.");
    }

    #[test]
    fn origin_and_dname() {
        let r = zone("$ORIGIN sub.example.org.\na 60 IN A 192.0.2.2\nd DNAME example.net.\n");
        assert_eq!(r[0].name.to_ascii(), "a.sub.example.org.");
        assert_eq!(r[1].record_type(), DNAME);
        assert_eq!(dname_target(&r[1]).unwrap().to_ascii(), "example.net.");
    }

    #[test]
    fn signed_records() {
        let r = zone(
            "a 3600 IN RRSIG A 8 3 3600 20240101000000 20231201000000 12345 example.org. dGVzdA==\n\
             a 3600 IN NSEC b.example.org. A RRSIG NSEC\n\
             x 60 IN TYPE65280 \\# 3 abcdef\n",
        );
        match &r[0].data {
            RData::DNSSEC(DNSSECRData::RRSIG(s)) => {
                assert_eq!(s.input().type_covered, RecordType::A);
                assert_eq!(s.input().sig_expiration.get(), 1704067200);
            }
            d => panic!("not an RRSIG: {d:?}"),
        }
        assert_eq!(r[1].record_type(), RecordType::NSEC);
        assert_eq!(r[2].record_type(), RecordType::Unknown(65280));
    }

    #[test]
    fn escapes_and_default_ttl() {
        let r = zone("$TTL 300\nhas\\046dot IN A 192.0.2.1\n");
        assert_eq!(r[0].name.to_ascii(), "has\\.dot.example.org.");
        assert_eq!(r[0].ttl, 300);
        // no TTL anywhere: 0 with a class, an error without
        let r = parse_zone("a IN A 192.0.2.1\n", &Name::root(), Path::new("db")).unwrap();
        assert_eq!(r[0].ttl, 0);
        assert!(parse_zone("a A 192.0.2.1\n", &Name::root(), Path::new("db")).is_err());
    }

    #[test]
    fn errors_have_positions() {
        let e = parse_zone("a IN A notanip\n", &Name::root(), Path::new("db.x")).unwrap_err();
        assert!(e.0.contains("db.x:1"), "{e}");
    }
}
