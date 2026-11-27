//! `tsig`: verifies TSIG-signed requests and signs responses (RFC 8945).
//! Port of `plugin/tsig`, with the wire-level TSIG handling miekg/dns does
//! for CoreDNS (`tsigBuffer`, `TsigGenerate`, `TsigVerify`).
//!
//! ```text
//! tsig [ZONE...] {
//!     secret NAME SECRET
//!     secrets FILE
//!     require [QTYPE...|all|none]
//!     require_opcode [OPCODE...|all|none]
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use hmac::{Hmac, Mac};
use kerndns_core::proto::op::{OpCode, ResponseCode};
use kerndns_core::proto::rr::RecordType;
use kerndns_core::zones::{self, is_subdomain};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseSigner,
    ResponseWriter, SetupError, async_trait, client_write, next_or_failure,
};

const TYPE_TSIG: u16 = 250;
const CLASS_ANY: u16 = 255;
const BADSIG: u16 = 16;
const BADKEY: u16 = 17;
const BADTIME: u16 = 18;
const DEFAULT_FUDGE: u16 = 300;

/// HMAC over `data` with the algorithm named `alg` (lowercase FQDN).
fn hmac(alg: &str, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    macro_rules! run {
        ($h:ty) => {{
            let mut m = <Hmac<$h> as Mac>::new_from_slice(key).ok()?;
            m.update(data);
            Some(m.finalize().into_bytes().to_vec())
        }};
    }
    match alg {
        "hmac-md5.sig-alg.reg.int." => run!(md5::Md5),
        "hmac-sha1." => run!(sha1::Sha1),
        "hmac-sha224." => run!(sha2::Sha224),
        "hmac-sha256." => run!(sha2::Sha256),
        "hmac-sha384." => run!(sha2::Sha384),
        "hmac-sha512." => run!(sha2::Sha512),
        _ => None,
    }
}

/// Lowercase uncompressed wire form and text of the name at `off`, and
/// the offset after it.
fn read_name(wire: &[u8], mut off: usize) -> Option<(Vec<u8>, String, usize)> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *wire.get(off)? as usize;
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *wire.get(off + 1)? as usize;
            end.get_or_insert(off + 2);
            off = ptr;
            jumps += 1;
            if jumps > 64 {
                return None;
            }
            continue;
        }
        if len == 0 {
            out.push(0);
            let next = end.unwrap_or(off + 1);
            if text.is_empty() {
                text.push('.');
            }
            return Some((out, text, next));
        }
        let label = wire.get(off + 1..off + 1 + len)?.to_ascii_lowercase();
        out.push(len as u8);
        out.extend_from_slice(&label);
        text.push_str(&String::from_utf8_lossy(&label));
        text.push('.');
        off += 1 + len;
    }
}

fn u16_at(w: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*w.get(o)?, *w.get(o + 1)?]))
}

/// A TSIG record found in a message.
#[derive(Debug, Clone)]
struct Tsig {
    /// Offset where the TSIG RR starts.
    start: usize,
    name_wire: Vec<u8>,
    name: String,
    ttl: u32,
    alg_wire: Vec<u8>,
    alg: String,
    time: u64,
    fudge: u16,
    mac: Vec<u8>,
    orig_id: u16,
    error: u16,
    other: Vec<u8>,
}

enum Found {
    None,
    /// A TSIG that isn't the last additional record.
    Misplaced,
    Tsig(Tsig),
}

/// Find the TSIG record; it must be the last one in the additional section.
fn find_tsig(wire: &[u8]) -> Option<Found> {
    let qd = u16_at(wire, 4)? as usize;
    let total = u16_at(wire, 6)? as usize + u16_at(wire, 8)? as usize + u16_at(wire, 10)? as usize;
    let ar = u16_at(wire, 10)? as usize;
    let mut off = 12;
    for _ in 0..qd {
        off = read_name(wire, off)?.2 + 4;
    }
    let mut found = Found::None;
    for i in 0..total {
        let start = off;
        let (name_wire, name, after) = read_name(wire, off)?;
        let rtype = u16_at(wire, after)?;
        let ttl = u32::from_be_bytes(wire.get(after + 4..after + 8)?.try_into().ok()?);
        let rdlen = u16_at(wire, after + 8)? as usize;
        let rdata = after + 10;
        off = rdata + rdlen;
        if rtype != TYPE_TSIG {
            continue;
        }
        if i != total - 1 || ar == 0 {
            return Some(Found::Misplaced);
        }
        let (alg_wire, alg, mut p) = read_name(wire, rdata)?;
        let t = wire.get(p..p + 6)?;
        let time = t.iter().fold(0u64, |a, b| (a << 8) | *b as u64);
        p += 6;
        let fudge = u16_at(wire, p)?;
        let mac_len = u16_at(wire, p + 2)? as usize;
        let mac = wire.get(p + 4..p + 4 + mac_len)?.to_vec();
        p += 4 + mac_len;
        let orig_id = u16_at(wire, p)?;
        let error = u16_at(wire, p + 2)?;
        let olen = u16_at(wire, p + 4)? as usize;
        let other = wire.get(p + 6..p + 6 + olen)?.to_vec();
        found = Found::Tsig(Tsig {
            start,
            name_wire,
            name,
            ttl,
            alg_wire,
            alg,
            time,
            fudge,
            mac,
            orig_id,
            error,
            other,
        });
    }
    Some(found)
}

/// The TSIG variables that are MAC'ed (`tsigWireFmt`, or `timerWireFmt`).
fn variables(t: &Tsig, timers_only: bool) -> Vec<u8> {
    let mut v = Vec::new();
    if !timers_only {
        v.extend_from_slice(&t.name_wire);
        v.extend_from_slice(&CLASS_ANY.to_be_bytes());
        v.extend_from_slice(&t.ttl.to_be_bytes());
        v.extend_from_slice(&t.alg_wire);
    }
    v.extend_from_slice(&t.time.to_be_bytes()[2..]);
    v.extend_from_slice(&t.fudge.to_be_bytes());
    if !timers_only {
        v.extend_from_slice(&t.error.to_be_bytes());
        v.extend_from_slice(&(t.other.len() as u16).to_be_bytes());
        v.extend_from_slice(&t.other);
    }
    v
}

/// `tsigBuffer`: [prior MAC] + message (ID set to original) + variables.
fn mac_input(msg: &[u8], t: &Tsig, prior_mac: Option<&[u8]>, timers_only: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(msg.len() + 128);
    if let Some(m) = prior_mac {
        buf.extend_from_slice(&(m.len() as u16).to_be_bytes());
        buf.extend_from_slice(m);
    }
    let start = buf.len();
    buf.extend_from_slice(msg);
    buf[start..start + 2].copy_from_slice(&t.orig_id.to_be_bytes());
    buf.extend_from_slice(&variables(t, timers_only));
    buf
}

/// The request without its TSIG record (ARCOUNT decremented).
fn stripped(wire: &[u8], t: &Tsig) -> Vec<u8> {
    let mut m = wire[..t.start].to_vec();
    let ar = u16::from_be_bytes([m[10], m[11]]).saturating_sub(1);
    m[10..12].copy_from_slice(&ar.to_be_bytes());
    m
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Check a request's TSIG: `Ok` or the TSIG error code.
fn verify(wire: &[u8], t: &Tsig, secrets: &HashMap<String, Vec<u8>>, now: u64) -> Result<(), u16> {
    let Some(secret) = secrets.get(&t.name) else {
        return Err(BADKEY);
    };
    let input = mac_input(&stripped(wire, t), t, None, false);
    let Some(expected) = hmac(&t.alg, secret, &input) else {
        return Err(BADKEY);
    };
    // constant-time comparison
    if expected.len() != t.mac.len() || expected.iter().zip(&t.mac).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 {
        return Err(BADSIG);
    }
    if now.abs_diff(t.time) > t.fudge as u64 {
        return Err(BADTIME);
    }
    Ok(())
}

/// Signs responses for one TSIG request (`restoreTsigWriter` + the
/// signing miekg/dns does when writing). The first message is signed over
/// the request MAC; later ones (zone transfers) chain the previous MAC with
/// timers only.
struct Signer {
    req: Tsig,
    secret: Option<Vec<u8>>,
    /// The request's TSIG error (0, BADKEY, BADSIG, BADTIME).
    error: u16,
    prev_mac: Mutex<Option<Vec<u8>>>,
}

impl ResponseSigner for Signer {
    fn sign(&self, mut wire: Vec<u8>) -> Vec<u8> {
        if wire.len() < 12 {
            return wire;
        }
        let id = u16::from_be_bytes([wire[0], wire[1]]);
        let mut prev = self.prev_mac.lock().unwrap();
        let first = prev.is_none();
        let mut t = Tsig {
            start: 0,
            name_wire: self.req.name_wire.clone(),
            name: self.req.name.clone(),
            ttl: 0,
            alg_wire: self.req.alg_wire.clone(),
            alg: self.req.alg.clone(),
            time: now(),
            fudge: DEFAULT_FUDGE,
            mac: Vec::new(),
            orig_id: id,
            error: self.error,
            other: Vec::new(),
        };
        if self.error == BADTIME {
            t.time = self.req.time;
            t.other = now().to_be_bytes()[2..].to_vec();
        }
        if self.error != BADKEY
            && self.error != BADSIG
            && let Some(secret) = &self.secret
        {
            let prior = if first {
                Some(self.req.mac.as_slice())
            } else {
                prev.as_deref()
            };
            let input = mac_input(&wire, &t, prior, !first);
            t.mac = hmac(&t.alg, secret, &input).unwrap_or_default();
            *prev = Some(t.mac.clone());
        } else {
            t.time = 0;
        }
        // append the TSIG RR, uncompressed
        let mut rdata = t.alg_wire.clone();
        rdata.extend_from_slice(&t.time.to_be_bytes()[2..]);
        rdata.extend_from_slice(&t.fudge.to_be_bytes());
        rdata.extend_from_slice(&(t.mac.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&t.mac);
        rdata.extend_from_slice(&t.orig_id.to_be_bytes());
        rdata.extend_from_slice(&t.error.to_be_bytes());
        rdata.extend_from_slice(&(t.other.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&t.other);
        wire.extend_from_slice(&t.name_wire);
        wire.extend_from_slice(&TYPE_TSIG.to_be_bytes());
        wire.extend_from_slice(&CLASS_ANY.to_be_bytes());
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        wire.extend_from_slice(&rdata);
        let ar = u16::from_be_bytes([wire[10], wire[11]]) + 1;
        wire[10..12].copy_from_slice(&ar.to_be_bytes());
        wire
    }
}

fn normalize(name: &str) -> String {
    let mut n = name.to_ascii_lowercase();
    if !n.ends_with('.') {
        n.push('.');
    }
    n
}

/// Keys from a BIND-style file: `key "name" { algorithm ...; secret "..."; };`.
pub fn parse_key_file(text: &str) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        if f[0] != "key" {
            return Err(format!("unexpected token {:?}", f[0]));
        }
        let key = f.get(1).map(|k| k.trim_matches(|c| c == '"' || c == '{')).unwrap_or("");
        if key.is_empty() {
            return Err(format!("expected key name {line:?}"));
        }
        let key = normalize(key);
        if out.contains_key(&key) {
            return Err(format!("key {key:?} redefined"));
        }
        for inner in lines.by_ref() {
            let f: Vec<&str> = inner.split_whitespace().collect();
            match f.first().copied() {
                None | Some("algorithm") => continue,
                Some("secret") => {
                    let s = f.get(1).map(|s| s.trim_matches(|c| c == '"' || c == ';')).unwrap_or("");
                    if s.is_empty() {
                        return Err(format!("expected secret key {inner:?}"));
                    }
                    out.insert(key.clone(), s.to_string());
                }
                Some("}") | Some("};") => break,
                Some(other) => return Err(format!("unexpected token {other:?}")),
            }
        }
        if !out.contains_key(&key) {
            return Err(format!("expected secret for key {key:?}"));
        }
    }
    Ok(out)
}

fn parse_opcode(s: &str) -> Option<OpCode> {
    Some(match s {
        "QUERY" => OpCode::Query,
        "STATUS" => OpCode::Status,
        "NOTIFY" => OpCode::Notify,
        "UPDATE" => OpCode::Update,
        _ => return None,
    })
}

pub struct Setup;

struct Config {
    zones: Vec<String>,
    secrets: HashMap<String, Vec<u8>>,
    types: HashSet<RecordType>,
    all_types: bool,
    opcodes: HashSet<u8>,
    all_opcodes: bool,
}

impl Config {
    fn required(&self, qtype: RecordType, op: OpCode) -> bool {
        self.all_types || self.types.contains(&qtype) || self.all_opcodes || self.opcodes.contains(&u8::from(op))
    }
}

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "tsig"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let err = |m: String| SetupError::new("tsig", m);
        let keys = c.server_block_keys();
        let mut raw: HashMap<String, String> = HashMap::new();
        let mut cfg = Config {
            zones: Vec::new(),
            secrets: HashMap::new(),
            types: HashSet::new(),
            all_types: false,
            opcodes: HashSet::new(),
            all_opcodes: false,
        };
        let mut seen = false;
        while c.next() {
            if seen {
                return Err(err("this plugin can only be used once per Server Block".into()));
            }
            seen = true;
            let args = c.remaining_args();
            cfg.zones = zones::origins_from_args_or_server_block(&args, &keys);
            while c.next_block() {
                let opt = c.val().to_string();
                let a = c.remaining_args();
                match opt.as_str() {
                    "secret" => {
                        let [name, secret] = a.as_slice() else {
                            return Err(c.arg_err());
                        };
                        let k = normalize(name);
                        if raw.insert(k.clone(), secret.clone()).is_some() {
                            return Err(err(format!("key {k:?} redefined")));
                        }
                    }
                    "secrets" => {
                        let [file] = a.as_slice() else { return Err(c.arg_err()) };
                        let text = std::fs::read_to_string(file).map_err(|e| err(format!("open {file}: {e}")))?;
                        for (k, s) in parse_key_file(&text).map_err(err)? {
                            if raw.insert(k.clone(), s).is_some() {
                                return Err(err(format!("key {k:?} redefined")));
                            }
                        }
                    }
                    "require" => {
                        cfg.types.clear();
                        match a.first().map(String::as_str) {
                            None => return Err(c.arg_err()),
                            Some("all") => cfg.all_types = true,
                            Some("none") => {}
                            _ => {
                                for t in &a {
                                    // hickory's FromStr doesn't know IXFR
                                    let rt: RecordType = if t == "IXFR" {
                                        RecordType::IXFR
                                    } else {
                                        t.parse().map_err(|_| c.errf(format!("unknown query type '{t}'")))?
                                    };
                                    cfg.types.insert(rt);
                                }
                            }
                        }
                    }
                    "require_opcode" => {
                        cfg.opcodes.clear();
                        match a.first().map(String::as_str) {
                            None => return Err(c.arg_err()),
                            Some("all") => cfg.all_opcodes = true,
                            Some("none") => {}
                            _ => {
                                for o in &a {
                                    let op = parse_opcode(o).ok_or_else(|| c.errf(format!("unknown opcode '{o}'")))?;
                                    cfg.opcodes.insert(u8::from(op));
                                }
                            }
                        }
                    }
                    other => {
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
        }
        for (k, s) in raw {
            let bytes = data_encoding::BASE64
                .decode(s.as_bytes())
                .map_err(|e| err(format!("invalid secret for {k}: {e}")))?;
            cfg.secrets.insert(k, bytes);
        }
        let cfg = Arc::new(cfg);
        c.add_plugin(move |next| Arc::new(TsigServer { cfg: cfg.clone(), next }));
        Ok(())
    }
}

async fn reply(w: &mut dyn ResponseWriter, m: kerndns_core::proto::op::Message) -> Result<(), PluginError> {
    w.write_msg(m)
        .await
        .map_err(|e| PluginError::servfail("tsig", e.to_string()))
}

pub struct TsigServer {
    cfg: Arc<Config>,
    next: Next,
}

#[async_trait]
impl Handler for TsigServer {
    fn name(&self) -> &'static str {
        "tsig"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let found = req.wire.as_deref().and_then(find_tsig).unwrap_or(Found::None);
        let tsig = match found {
            Found::Misplaced => {
                reply(w, req.error_reply(ResponseCode::FormErr)).await?;
                return Ok(ResponseCode::NoError);
            }
            Found::None => None,
            Found::Tsig(t) => Some(t),
        };
        let name = req.name();
        let in_zone = self.cfg.zones.iter().any(|z| is_subdomain(z, &name));
        let required = self.cfg.required(req.qtype(), req.msg.metadata.op_code);
        let Some(t) = tsig.filter(|_| in_zone) else {
            if !in_zone || !required {
                return next_or_failure("tsig", &self.next, ctx, w, req).await;
            }
            kerndns_core::debug!(plugin = "tsig", "rejecting '{}' request without TSIG", req.qtype());
            reply(w, req.error_reply(ResponseCode::Refused)).await?;
            return Ok(ResponseCode::NoError);
        };

        let wire = req.wire.as_deref().expect("found above");
        let result = verify(wire, &t, &self.cfg.secrets, now());
        let key = normalize(&t.name);
        let signer = Arc::new(Signer {
            secret: self.cfg.secrets.get(&t.name).cloned(),
            error: result.err().unwrap_or(0),
            req: t,
            prev_mac: Mutex::new(None),
        });
        ctx.signer = Some(signer);
        if let Err(code) = result {
            kerndns_core::debug!(plugin = "tsig", "TSIG validation failed: {} error {code}", req.qtype());
            reply(w, req.error_reply(ResponseCode::NotAuth)).await?;
            return Ok(ResponseCode::NoError);
        }

        ctx.tsig_key = Some(key);
        let res = next_or_failure("tsig", &self.next, ctx, w, req).await;
        let rcode = match &res {
            Ok(rc) => *rc,
            Err(e) => {
                kerndns_core::error!(plugin = "tsig", "request handler returned an error: {e}");
                e.rcode
            }
        };
        if !client_write(rcode) {
            // the error answer must be signed too, so write it here
            reply(w, req.error_reply(rcode)).await?;
        }
        Ok(ResponseCode::NoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(
            &Setup,
            "tsig {\n secret tsig.key. i9M+00yrECfVZG2qCjr4mPpaGim/Bq+IWMiNrLjUO4Y=\n require AXFR IXFR\n}"
        ));
        assert!(setup_err(&Setup, "tsig {\n secret a. AAAA\n secret a. BBBB\n}").contains("redefined"));
        assert!(setup_err(&Setup, "tsig {\n require FOO\n}").contains("unknown query type"));
        assert!(setup_err(&Setup, "tsig {\n require_opcode FOO\n}").contains("unknown opcode"));
    }

    #[test]
    fn key_file() {
        let k = parse_key_file("key \"a.example.\" {\n  algorithm hmac-sha256;\n  secret \"c2VjcmV0\";\n};\n").unwrap();
        assert_eq!(k.get("a.example.").map(String::as_str), Some("c2VjcmV0"));
        assert!(parse_key_file("nope\n").is_err());
    }

    /// A request signed the way miekg/dns does it verifies; a wrong key,
    /// time or MAC give BADKEY, BADTIME and BADSIG.
    #[test]
    fn sign_and_verify_roundtrip() {
        use kerndns_core::proto::op::{Message, MessageType, Query};
        use kerndns_core::proto::rr::Name;
        let secret = data_encoding::BASE64
            .decode(b"i9M+00yrECfVZG2qCjr4mPpaGim/Bq+IWMiNrLjUO4Y=")
            .unwrap();
        let mut m = Message::new(4711, MessageType::Query, OpCode::Query);
        m.add_query(Query::query(Name::from_ascii("test.").unwrap(), RecordType::A));
        let wire = m.to_vec().unwrap();
        // sign as a client: a fake "request" signer with no prior MAC
        let key = Tsig {
            start: 0,
            name_wire: b"\x04tsig\x03key\x00".to_vec(),
            name: "tsig.key.".into(),
            ttl: 0,
            alg_wire: b"\x0bhmac-sha256\x00".to_vec(),
            alg: "hmac-sha256.".into(),
            time: now(),
            fudge: 300,
            mac: Vec::new(),
            orig_id: 4711,
            error: 0,
            other: Vec::new(),
        };
        let mac = hmac("hmac-sha256.", &secret, &mac_input(&wire, &key, None, false)).unwrap();
        // the signed request: the message plus the TSIG RR with that MAC
        let mut req_wire = wire.clone();
        let mut t = key.clone();
        t.mac = mac;
        let signed = {
            let mut rdata = t.alg_wire.clone();
            rdata.extend_from_slice(&t.time.to_be_bytes()[2..]);
            rdata.extend_from_slice(&t.fudge.to_be_bytes());
            rdata.extend_from_slice(&(t.mac.len() as u16).to_be_bytes());
            rdata.extend_from_slice(&t.mac);
            rdata.extend_from_slice(&t.orig_id.to_be_bytes());
            rdata.extend_from_slice(&0u16.to_be_bytes());
            rdata.extend_from_slice(&0u16.to_be_bytes());
            req_wire.extend_from_slice(&t.name_wire);
            req_wire.extend_from_slice(&TYPE_TSIG.to_be_bytes());
            req_wire.extend_from_slice(&CLASS_ANY.to_be_bytes());
            req_wire.extend_from_slice(&0u32.to_be_bytes());
            req_wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            req_wire.extend_from_slice(&rdata);
            req_wire[11] += 1;
            req_wire
        };
        let Some(Found::Tsig(parsed)) = find_tsig(&signed) else {
            panic!("TSIG not found")
        };
        let secrets: HashMap<String, Vec<u8>> = [("tsig.key.".to_string(), secret.clone())].into();
        assert_eq!(verify(&signed, &parsed, &secrets, now()), Ok(()));
        assert_eq!(verify(&signed, &parsed, &HashMap::new(), now()), Err(BADKEY));
        assert_eq!(verify(&signed, &parsed, &secrets, now() + 1000), Err(BADTIME));
        let mut bad = signed.clone();
        let l = bad.len();
        bad[l - 10] ^= 1; // flip a MAC bit
        let Some(Found::Tsig(p2)) = find_tsig(&bad) else {
            panic!()
        };
        assert_eq!(verify(&bad, &p2, &secrets, now()), Err(BADSIG));
    }
}
