//! `dynupdate`: accepts TSIG-authenticated RFC 2136 DNS UPDATEs for one
//! authoritative zone, serves it like `file` and keeps it in memory or in
//! a local database. Port of `plugin/dynupdate`.
//!
//! ```text
//! dynupdate [ZONE] {
//!     file DBFILE
//!     database PATH
//!     allow KEY NAME TYPE [TYPE...]
//!     max_records COUNT
//!     max_bytes BYTES
//!     max_update_records COUNT
//! }
//! ```
//!
//! CoreDNS stores the zone in a bbolt database; KernDNS uses its own file
//! format (the records in wire format), replaced atomically on every commit
//! (write, fsync, rename, fsync of the directory). Like CoreDNS the
//! database is created on first use after startup, never during setup, and
//! one database is shared by the old and new instances during a reload.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};

use kerndns_core::plugin::CacheBypass;
use kerndns_core::proto::op::{OpCode, ResponseCode};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use kerndns_core::transfer::{TransferError, TransferRegistry, Transferer};
use kerndns_core::zones::{Fall, is_subdomain};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};

use crate::file::zone::{self, Zone, ZoneData};
use crate::file::{File, FileTransfer, Zones};

const NAME: &str = "dynupdate";
const DEFAULT_MAX_RECORDS: usize = 10000;
const DEFAULT_MAX_BYTES: usize = 8 << 20;
const DEFAULT_MAX_UPDATE_RECORDS: usize = 1024;
const MAGIC: &[u8] = b"KERNDNS-DYNUPDATE-1\n";

// ---------------------------------------------------------------- records

/// Lowercase, fully qualified.
fn canon(n: &Name) -> String {
    let mut s = n.to_ascii().to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

fn canon_str(n: &str) -> String {
    let mut s = n.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

fn in_zone(origin: &str, name: &str) -> bool {
    name == origin || is_subdomain(origin, name)
}

fn code(t: RecordType) -> u16 {
    u16::from(t)
}

/// ANY, AXFR, IXFR, MAILA, MAILB, OPT, TKEY, TSIG.
fn is_query_meta(t: RecordType) -> bool {
    matches!(code(t), 255 | 252 | 251 | 253 | 254 | 41 | 249 | 250)
}

/// DNSSEC records and related metadata that can't be regenerated.
fn unsupported(t: RecordType) -> bool {
    matches!(
        code(t),
        24 | 25 | 30 | 43 | 46 | 47 | 48 | 50 | 51 | 58 | 59 | 60 | 63 | 32768 | 32769
    )
}

/// The record without compression, which is what `dns.Len` measures.
fn rr_len(r: &Record) -> usize {
    r.to_bytes().map(|b| b.len()).unwrap_or(0)
}

/// RDATA in canonical form (lowercased names), for comparisons.
fn rdata_key(r: &Record) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut e = BinEncoder::new(&mut buf);
    e.set_canonical_form(true);
    let _ = r.data.emit(&mut e);
    buf
}

/// `sameRR`: owner, type and data equal; class and TTL ignored.
fn same_rr(a: &Record, b: &Record) -> bool {
    a.record_type() == b.record_type() && canon(&a.name) == canon(&b.name) && rdata_key(a) == rdata_key(b)
}

fn rrset<'a>(records: &'a [Record], name: &str, t: RecordType) -> Vec<&'a Record> {
    records
        .iter()
        .filter(|r| r.record_type() == t && canon(&r.name) == name)
        .collect()
}

/// `sameRRset`: the same records, duplicates ignored.
fn same_rrset(have: &[&Record], want: &[&Record]) -> bool {
    fn unique<'a>(v: &[&'a Record]) -> Vec<&'a Record> {
        let mut u: Vec<&Record> = Vec::new();
        for r in v {
            if !u.iter().any(|x| same_rr(x, r)) {
                u.push(r);
            }
        }
        u
    }
    let (have, want) = (unique(have), unique(want));
    have.len() == want.len() && want.iter().all(|w| have.iter().any(|h| same_rr(h, w)))
}

fn find_rr(records: &[Record], want: &Record) -> Option<usize> {
    records.iter().position(|r| same_rr(r, want))
}

fn soa_serial(r: &Record) -> Option<u32> {
    match &r.data {
        RData::SOA(s) => Some(s.serial),
        _ => None,
    }
}

/// RFC 1982: `a` is newer than `b`.
fn serial_greater(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 1 << 31
}

/// `validateRecords`: a well-formed zone with exactly one apex SOA.
fn validate_records(records: &[Record], origin: &str) -> Result<(), String> {
    let mut soas = 0;
    let mut types: HashMap<String, HashSet<RecordType>> = HashMap::new();
    for r in records {
        if r.dns_class != DNSClass::IN {
            return Err("zone contains a non-IN record".into());
        }
        let name = canon(&r.name);
        if !in_zone(origin, &name) {
            return Err("zone contains an out-of-zone record".into());
        }
        let t = r.record_type();
        if unsupported(t) {
            return Err(format!("zone contains unsupported RR type {t}"));
        }
        let at = types.entry(name).or_default();
        if (t == RecordType::CNAME && !at.is_empty()) || (t != RecordType::CNAME && at.contains(&RecordType::CNAME)) {
            return Err(format!("zone contains CNAME data conflict at {}", r.name));
        }
        at.insert(t);
        if t == RecordType::SOA {
            if canon(&r.name) != origin {
                return Err("zone contains a non-apex SOA record".into());
            }
            if soa_serial(r) == Some(0) {
                return Err("zone contains an SOA with serial zero".into());
            }
            soas += 1;
        }
    }
    match soas {
        0 => Err("zone has no SOA".into()),
        1 => Ok(()),
        _ => Err("zone contains more than one SOA record".into()),
    }
}

#[derive(Clone, Copy)]
struct Limits {
    records: usize,
    bytes: usize,
    update_records: usize,
}

impl Limits {
    fn check(&self, records: &[Record]) -> Result<(), String> {
        if records.len() > self.records {
            return Err(format!("zone exceeds max_records ({})", self.records));
        }
        let mut remaining = self.bytes;
        for r in records {
            let n = rr_len(r);
            if n > remaining {
                return Err(format!("zone exceeds max_bytes ({})", self.bytes));
            }
            remaining -= n;
        }
        Ok(())
    }
}

/// `readZoneLimited`: the seed zone file as a record list.
fn read_seed(path: &Path, origin: &str, limits: &Limits) -> Result<Vec<Record>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("opening zone file {:?}: {e}", path.display()))?;
    let o = Name::from_ascii(origin).map_err(|e| e.to_string())?;
    let data = zone::parse(&text, &o, path, 0).map_err(|e| format!("parsing zone file {:?}: {e}", path.display()))?;
    let mut records = data
        .apex
        .records()
        .ok_or_else(|| format!("zone {origin:?} has no SOA"))?;
    for e in data.tree.elems() {
        records.extend(e.all().cloned());
    }
    limits
        .check(&records)
        .map_err(|_| format!("zone file {:?} exceeds configured limits", path.display()))?;
    validate_records(&records, origin).map_err(|e| format!("invalid zone {origin:?}: {e}"))?;
    Ok(records)
}

fn build(origin: &Name, records: &[Record]) -> Result<ZoneData, String> {
    let mut d = ZoneData::default();
    for r in records {
        d.insert(origin, r.clone())?;
    }
    Ok(d)
}

// --------------------------------------------------------------- database

fn encode_db(origin: &str, records: &[Record]) -> Result<Vec<u8>, String> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(origin.as_bytes());
    out.push(b'\n');
    for r in records {
        let b = r.to_bytes().map_err(|e| e.to_string())?;
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(&b);
    }
    Ok(out)
}

fn decode_db(data: &[u8], origin: &str, limits: &Limits) -> Result<Vec<Record>, String> {
    let rest = data.strip_prefix(MAGIC).ok_or("unrecognized database format")?;
    let nl = rest
        .iter()
        .position(|b| *b == b'\n')
        .ok_or("unrecognized database format")?;
    if &rest[..nl] != origin.as_bytes() {
        return Err("database belongs to a different zone".into());
    }
    let mut buf = &rest[nl + 1..];
    if buf.len() > limits.bytes * 2 {
        return Err(format!("invalid stored zone size (max_bytes {})", limits.bytes));
    }
    let mut records = Vec::new();
    while !buf.is_empty() {
        if records.len() == limits.records {
            return Err(format!("stored zone exceeds max_records ({})", limits.records));
        }
        if buf.len() < 2 {
            return Err("invalid stored record length".into());
        }
        let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        let rr = buf.get(2..2 + n).ok_or("invalid stored record length")?;
        records.push(Record::read(&mut BinDecoder::new(rr)).map_err(|e| e.to_string())?);
        buf = &buf[2 + n..];
    }
    limits.check(&records)?;
    validate_records(&records, origin)?;
    Ok(records)
}

/// Replace `path` atomically and durably.
fn write_db(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name().map(|f| f.to_string_lossy()).unwrap_or_default()
    ));
    let res = (|| -> std::io::Result<()> {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res.map_err(|e| format!("writing database {:?}: {e}", path.display()))
}

// ------------------------------------------------------------------ store

/// The zone's records and the view served from them. One per database
/// path in the process (shared across reloads), or one per instance in
/// memory-only mode.
struct Store {
    origin: String,
    path: Option<PathBuf>,
    /// Updates are serialized by this lock.
    records: Mutex<Vec<Record>>,
    zones: crate::file::SharedZones,
    zone: Arc<Zone>,
}

impl Store {
    fn new(origin: &str, path: Option<PathBuf>, records: Vec<Record>) -> Result<Store, String> {
        let o = Name::from_ascii(origin).map_err(|e| e.to_string())?;
        let data = build(&o, &records)?;
        let mut z = Zone::new(o, PathBuf::new(), data);
        z.reload_interval = std::time::Duration::ZERO;
        let z = Arc::new(z);
        let mut zones = Zones::default();
        zones.names.push(origin.to_string());
        zones.z.insert(origin.to_string(), z.clone());
        Ok(Store {
            origin: origin.to_string(),
            path,
            records: Mutex::new(records),
            zones: crate::file::shared(zones),
            zone: z,
        })
    }

    fn zone(&self) -> &Arc<Zone> {
        &self.zone
    }

    /// Persist (if there is a database) and publish `records`.
    fn commit(&self, current: &mut Vec<Record>, records: Vec<Record>) -> Result<(), String> {
        let data = build(&self.zone().origin, &records)?;
        if let Some(p) = &self.path {
            write_db(p, &encode_db(&self.origin, &records)?)?;
        }
        self.zone().set_data(data);
        *current = records;
        Ok(())
    }
}

static STORES: LazyLock<Mutex<HashMap<PathBuf, Weak<Store>>>> = LazyLock::new(Default::default);

// ------------------------------------------------------------- permissions

struct Permission {
    key: String,
    /// `None` for `*`.
    name: Option<String>,
    types: HashSet<RecordType>,
    all_types: bool,
}

fn parse_type(raw: &str) -> Option<RecordType> {
    let up = raw.to_ascii_uppercase();
    if let Some(n) = up.strip_prefix("TYPE") {
        let n: u16 = n.parse().ok()?;
        return (n != 0 && n != 65535).then(|| RecordType::from(n));
    }
    up.parse::<RecordType>()
        .ok()
        .filter(|t| !matches!(t, RecordType::Unknown(_)))
}

fn valid_policy_type(t: RecordType) -> bool {
    code(t) != 0 && !unsupported(t) && (t == RecordType::ANY || !is_query_meta(t))
}

fn parse_permission(args: &[String], origin: &str) -> Result<Permission, String> {
    if args.len() < 3 {
        return Err("allow requires KEY NAME and at least one RR type".into());
    }
    let key = &args[0];
    if key.trim().is_empty() || key == "*" || key == "@" || Name::from_ascii(key).is_err() {
        return Err(format!("invalid TSIG key {key:?}"));
    }
    let mut p = Permission {
        key: canon_str(key),
        name: None,
        types: HashSet::new(),
        all_types: false,
    };
    if args[1] != "*" {
        let name = if args[1] == "@" {
            origin.to_string()
        } else {
            canon_str(&args[1])
        };
        if Name::from_ascii(&name).is_err() || !in_zone(origin, &name) {
            return Err(format!("allow name {:?} is outside zone {origin:?}", args[1]));
        }
        p.name = Some(name);
    }
    for raw in &args[2..] {
        if raw == "*" {
            if args.len() != 3 {
                return Err("wildcard RR type must be the only type in an allow rule".into());
            }
            p.all_types = true;
            continue;
        }
        match parse_type(raw) {
            Some(t) if valid_policy_type(t) => {
                p.types.insert(t);
            }
            _ => return Err(format!("invalid RR type {raw:?} in allow rule")),
        }
    }
    Ok(p)
}

// ----------------------------------------------------------------- plugin

struct Dyn {
    zone: String,
    permissions: Vec<Permission>,
    limits: Limits,
    seed: PathBuf,
    database: Option<PathBuf>,
    /// The store once in use; for a database it is acquired on first use.
    store: Mutex<Option<Arc<Store>>>,
    closed: std::sync::atomic::AtomicBool,
    registry: TransferRegistry,
    /// (pending, running): at most one NOTIFY round in flight.
    notify: Mutex<(bool, bool)>,
    fall: Arc<Fall>,
}

impl Dyn {
    /// Open the database, creating it from the seed if missing.
    fn open_store(&self, path: &Path, create: bool) -> Result<Arc<Store>, String> {
        let mut stores = STORES.lock().unwrap();
        stores.retain(|_, w| w.strong_count() > 0);
        if let Some(s) = stores.get(path).and_then(Weak::upgrade) {
            if s.origin != self.zone {
                return Err(format!("database already serves zone {:?}", s.origin));
            }
            self.limits.check(&s.records.lock().unwrap())?;
            return Ok(s);
        }
        if let (Ok(a), Ok(b)) = (std::fs::canonicalize(path), std::fs::canonicalize(&self.seed))
            && a == b
        {
            return Err("database and seed must be different files".into());
        }
        let records = match std::fs::read(path) {
            Ok(data) => decode_db(&data, &self.zone, &self.limits)
                .map_err(|e| format!("loading database {:?}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let records = read_seed(&self.seed, &self.zone, &self.limits)?;
                if create {
                    write_db(path, &encode_db(&self.zone, &records)?)?;
                }
                records
            }
            Err(e) => return Err(format!("opening database {:?}: {e}", path.display())),
        };
        let s = Arc::new(Store::new(&self.zone, Some(path.to_path_buf()), records)?);
        if create {
            stores.insert(path.to_path_buf(), Arc::downgrade(&s));
        }
        Ok(s)
    }

    /// The store, acquiring the database on first use (`ensureStore`).
    fn store(&self) -> Result<Arc<Store>, String> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err("dynamic zone is closed".into());
        }
        let mut s = self.store.lock().unwrap();
        if let Some(s) = s.as_ref() {
            return Ok(s.clone());
        }
        let path = self.database.as_ref().expect("memory-only stores exist from setup");
        let st = self.open_store(path, true)?;
        *s = Some(st.clone());
        Ok(st)
    }

    fn configured_key(&self, key: &str) -> bool {
        self.permissions.iter().any(|p| p.key == key)
    }

    fn allows(&self, key: &str, name: &str, t: RecordType) -> bool {
        self.permissions.iter().any(|p| {
            p.key == key && p.name.as_deref().is_none_or(|n| n == name) && (p.all_types || p.types.contains(&t))
        })
    }

    fn check_prerequisites(&self, records: &[Record], prereqs: &[Record]) -> ResponseCode {
        let mut value: HashMap<(String, RecordType), Vec<&Record>> = HashMap::new();
        for r in prereqs {
            if r.ttl != 0 {
                return ResponseCode::FormErr;
            }
            let name = canon(&r.name);
            if !in_zone(&self.zone, &name) {
                return ResponseCode::NotZone;
            }
            let t = r.record_type();
            if unsupported(t) {
                return ResponseCode::NotImp;
            }
            let empty = matches!(r.data, RData::Update0(_));
            let valid = |allow_any: bool| {
                code(t) != 0
                    && (if t == RecordType::ANY {
                        allow_any
                    } else {
                        !is_query_meta(t)
                    })
            };
            let in_use = || records.iter().any(|x| canon(&x.name) == name);
            match r.dns_class {
                DNSClass::ANY => {
                    if !empty || !valid(true) {
                        return ResponseCode::FormErr;
                    }
                    if t == RecordType::ANY {
                        if !in_use() {
                            return ResponseCode::NXDomain;
                        }
                    } else if rrset(records, &name, t).is_empty() {
                        return ResponseCode::NXRRSet;
                    }
                }
                DNSClass::NONE => {
                    if !empty || !valid(true) {
                        return ResponseCode::FormErr;
                    }
                    if t == RecordType::ANY {
                        if in_use() {
                            return ResponseCode::YXDomain;
                        }
                    } else if !rrset(records, &name, t).is_empty() {
                        return ResponseCode::YXRRSet;
                    }
                }
                DNSClass::IN => {
                    if !valid(false) {
                        return ResponseCode::FormErr;
                    }
                    value.entry((name, t)).or_default().push(r);
                }
                _ => return ResponseCode::FormErr,
            }
        }
        for ((name, t), want) in value {
            if !same_rrset(&rrset(records, &name, t), &want) {
                return ResponseCode::NXRRSet;
            }
        }
        ResponseCode::NoError
    }

    fn validate_updates(&self, updates: &[Record]) -> ResponseCode {
        for r in updates {
            let name = canon(&r.name);
            if !in_zone(&self.zone, &name) {
                return ResponseCode::NotZone;
            }
            let t = r.record_type();
            if code(t) == 0 {
                return ResponseCode::FormErr;
            }
            let empty = matches!(r.data, RData::Update0(_));
            match r.dns_class {
                DNSClass::IN => {
                    if is_query_meta(t) || empty {
                        return ResponseCode::FormErr;
                    }
                    if t == RecordType::SOA && (name != self.zone || soa_serial(r).unwrap_or(0) == 0) {
                        return ResponseCode::FormErr;
                    }
                }
                DNSClass::ANY => {
                    if r.ttl != 0 || !empty || (is_query_meta(t) && t != RecordType::ANY) {
                        return ResponseCode::FormErr;
                    }
                }
                DNSClass::NONE => {
                    if r.ttl != 0 || t == RecordType::ANY || is_query_meta(t) {
                        return ResponseCode::FormErr;
                    }
                }
                _ => return ResponseCode::FormErr,
            }
            if unsupported(t) {
                return ResponseCode::NotImp;
            }
        }
        ResponseCode::NoError
    }

    /// `apply`: the candidate records, whether anything changed and
    /// whether the update set the SOA itself.
    fn apply(&self, current: &[Record], updates: &[Record]) -> (Vec<Record>, bool, bool) {
        let mut records = current.to_vec();
        let (mut changed, mut explicit_soa) = (false, false);
        for rr in updates {
            let name = canon(&rr.name);
            let apex = name == self.zone;
            let t = rr.record_type();
            let at = |r: &Record, n: &str| canon(&r.name) == n;
            match rr.dns_class {
                DNSClass::IN => {
                    let mut new = rr.clone();
                    new.dns_class = DNSClass::IN;
                    match t {
                        RecordType::SOA => {
                            let cur = records
                                .iter()
                                .find(|r| r.record_type() == RecordType::SOA && at(r, &self.zone));
                            let (Some(cur), Some(inc)) = (cur.and_then(soa_serial), soa_serial(rr)) else {
                                continue;
                            };
                            if !serial_greater(inc, cur) {
                                continue;
                            }
                            records.retain(|r| !(at(r, &name) && r.record_type() == RecordType::SOA));
                            records.push(new);
                            changed = true;
                            explicit_soa = true;
                        }
                        RecordType::CNAME => {
                            if records
                                .iter()
                                .any(|r| at(r, &name) && r.record_type() != RecordType::CNAME)
                            {
                                continue;
                            }
                            let existing = rrset(&records, &name, RecordType::CNAME);
                            if existing.len() == 1 && same_rr(existing[0], rr) && existing[0].ttl == rr.ttl {
                                continue;
                            }
                            records.retain(|r| !(at(r, &name) && r.record_type() == RecordType::CNAME));
                            records.push(new);
                            changed = true;
                        }
                        _ => {
                            if !rrset(&records, &name, RecordType::CNAME).is_empty() {
                                continue;
                            }
                            if let Some(i) = find_rr(&records, rr) {
                                if records[i].ttl != rr.ttl {
                                    records[i] = new;
                                    changed = true;
                                }
                                continue;
                            }
                            records.push(new);
                            changed = true;
                        }
                    }
                }
                DNSClass::ANY => {
                    let before = records.len();
                    if t == RecordType::ANY {
                        records.retain(|r| {
                            !at(r, &name) || (apex && matches!(r.record_type(), RecordType::SOA | RecordType::NS))
                        });
                    } else if !(apex && matches!(t, RecordType::SOA | RecordType::NS)) {
                        records.retain(|r| !(at(r, &name) && r.record_type() == t));
                    }
                    changed |= records.len() != before;
                }
                DNSClass::NONE => {
                    if apex && t == RecordType::SOA {
                        continue;
                    }
                    if apex && t == RecordType::NS && rrset(&records, &name, RecordType::NS).len() <= 1 {
                        continue;
                    }
                    if let Some(i) = find_rr(&records, rr) {
                        records.remove(i);
                        changed = true;
                    }
                }
                _ => {}
            }
        }
        (records, changed, explicit_soa)
    }

    /// `updateLocked`: returns whether the zone changed and the rcode.
    fn update(&self, key: &str, prereqs: &[Record], updates: &[Record]) -> (bool, ResponseCode, Option<String>) {
        if !self.configured_key(key) {
            return (false, ResponseCode::Refused, None);
        }
        let ur = self.limits.update_records;
        if prereqs.len() > ur || updates.len() > ur - prereqs.len() {
            return (false, ResponseCode::Refused, None);
        }
        let store = match self.store() {
            Ok(s) => s,
            Err(e) => return (false, ResponseCode::ServFail, Some(e)),
        };
        let mut current = store.records.lock().unwrap();
        let rcode = self.check_prerequisites(&current, prereqs);
        if rcode != ResponseCode::NoError {
            return (false, rcode, None);
        }
        for r in updates {
            if !self.allows(key, &canon(&r.name), r.record_type()) {
                return (false, ResponseCode::Refused, None);
            }
        }
        let rcode = self.validate_updates(updates);
        if rcode != ResponseCode::NoError {
            return (false, rcode, None);
        }
        let (mut candidate, changed, explicit_soa) = self.apply(&current, updates);
        if !changed {
            return (false, ResponseCode::NoError, None);
        }
        if let Err(e) = self.limits.check(&candidate) {
            return (false, ResponseCode::Refused, Some(e));
        }
        if !explicit_soa
            && let Some(RData::SOA(soa)) = candidate
                .iter_mut()
                .find(|r| r.record_type() == RecordType::SOA)
                .map(|r| &mut r.data)
        {
            soa.serial = soa.serial.wrapping_add(1).max(1);
        }
        if let Err(e) = validate_records(&candidate, &self.zone) {
            return (
                false,
                ResponseCode::ServFail,
                Some(format!("building candidate zone: {e}")),
            );
        }
        if let Err(e) = store.commit(&mut current, candidate) {
            return (false, ResponseCode::ServFail, Some(format!("committing zone: {e}")));
        }
        (true, ResponseCode::NoError, None)
    }

    /// Best-effort NOTIFY after a change; bursts are coalesced into at most
    /// one round in flight plus one pending.
    fn schedule_notify(self: &Arc<Self>) {
        if !self.registry.has_notifier() {
            return;
        }
        {
            let mut n = self.notify.lock().unwrap();
            n.0 = true;
            if n.1 {
                return;
            }
            n.1 = true;
        }
        let d = self.clone();
        tokio::spawn(async move {
            loop {
                {
                    let mut n = d.notify.lock().unwrap();
                    if !n.0 || d.closed.load(std::sync::atomic::Ordering::Acquire) {
                        n.1 = false;
                        return;
                    }
                    n.0 = false;
                }
                d.registry.notify_wait(&d.zone).await;
            }
        });
    }
}

struct DynTransfer(Arc<Dyn>);

impl Transferer for DynTransfer {
    fn transfer(&self, zone: &str, serial: u32) -> Result<Vec<Vec<Record>>, TransferError> {
        if canon_str(zone) != self.0.zone {
            return Err(TransferError::NotAuthoritative);
        }
        let s = self.0.store().map_err(TransferError::Other)?;
        FileTransfer(s.zones.clone()).transfer(zone, serial)
    }
}

pub struct DynUpdate {
    d: Arc<Dyn>,
    next: Next,
}

async fn reply(w: &mut dyn ResponseWriter, req: &Request, rcode: ResponseCode) -> HandlerResult {
    let mut m = req.reply();
    m.metadata.op_code = OpCode::Update;
    m.metadata.response_code = rcode;
    m.metadata.authoritative = true;
    w.write_msg(m)
        .await
        .map_err(|e| PluginError::servfail(NAME, e.to_string()))?;
    Ok(ResponseCode::NoError)
}

#[async_trait]
impl Handler for DynUpdate {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let d = &self.d;
        if req.msg.metadata.op_code == OpCode::Update {
            let q = &req.msg.queries;
            if q.len() != 1 || q[0].query_type() != RecordType::SOA || q[0].query_class() != DNSClass::IN {
                return reply(w, req, ResponseCode::FormErr).await;
            }
            let zone = canon(q[0].name());
            if zone != d.zone {
                return reply(w, req, ResponseCode::NotAuth).await;
            }
            let Some(key) = ctx.tsig_key.clone() else {
                kerndns_core::debug!(
                    plugin = NAME,
                    "refusing UPDATE for {zone} without a validated TSIG identity"
                );
                return reply(w, req, ResponseCode::Refused).await;
            };
            let (d2, prereqs, updates) = (d.clone(), req.msg.answers.clone(), req.msg.authorities.clone());
            // updates are serialized and may write the database: off the async threads
            let (changed, rcode, err) = tokio::task::spawn_blocking(move || d2.update(&key, &prereqs, &updates))
                .await
                .unwrap_or((false, ResponseCode::ServFail, Some("update task failed".into())));
            if let Some(e) = err {
                kerndns_core::error!(plugin = NAME, "UPDATE for {zone} failed: {e}");
            }
            if changed {
                d.schedule_notify();
            }
            return reply(w, req, rcode).await;
        }
        if req.msg.queries.len() == 1 && !in_zone(&d.zone, &req.name()) {
            return next_or_failure(NAME, &self.next, ctx, w, req).await;
        }
        let store = d.store().map_err(|e| PluginError::servfail(NAME, e))?;
        let view = File {
            name: NAME,
            next: self.next.clone(),
            zones: store.zones.clone(),
            fall: d.fall.clone(),
        };
        view.serve_dns(ctx, w, req).await
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let err = |m: String| SetupError::new(NAME, m);
        if !c.next() {
            return Err(c.arg_err());
        }
        let args = c.remaining_args();
        let zone = match args.len() {
            0 => {
                let keys: HashSet<String> = c.server_block_keys().iter().map(|k| canon_str(k)).collect();
                if keys.len() != 1 {
                    return Err(err(
                        "zone is required when the server block does not define exactly one zone".into(),
                    ));
                }
                keys.into_iter().next().unwrap()
            }
            1 => canon_str(&args[0]),
            _ => return Err(err("exactly one zone is allowed".into())),
        };
        if Name::from_ascii(&zone).is_err() {
            return Err(err(format!("invalid zone {zone:?}")));
        }

        let mut seed: Option<String> = None;
        let mut database: Option<String> = None;
        let mut permissions = Vec::new();
        let mut limits = Limits {
            records: DEFAULT_MAX_RECORDS,
            bytes: DEFAULT_MAX_BYTES,
            update_records: DEFAULT_MAX_UPDATE_RECORDS,
        };
        let mut seen = HashSet::new();
        while c.next_block() {
            let prop = c.val().to_string();
            if prop != "allow" && !seen.insert(prop.clone()) {
                return Err(c.errf(format!("{prop} specified more than once")));
            }
            let a = c.remaining_args();
            match prop.as_str() {
                "file" | "database" => {
                    if a.len() != 1 || a[0].is_empty() {
                        return Err(c.arg_err());
                    }
                    if prop == "file" {
                        seed = Some(a[0].clone());
                    } else {
                        database = Some(a[0].clone());
                    }
                }
                "max_records" | "max_bytes" | "max_update_records" => {
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    let n: usize = match a[0].parse() {
                        Ok(n) if n > 0 => n,
                        _ => return Err(c.errf(format!("{prop} requires a positive integer"))),
                    };
                    match prop.as_str() {
                        "max_records" => limits.records = n,
                        "max_bytes" => limits.bytes = n,
                        _ => limits.update_records = n,
                    }
                }
                "allow" => permissions.push(parse_permission(&a, &zone).map_err(err)?),
                other => return Err(c.errf(format!("unknown property {other:?}"))),
            }
        }
        if c.next() {
            return Err(err("this plugin can only be used once per Server Block".into()));
        }
        let Some(seed) = seed else {
            return Err(c.errf("file is required"));
        };
        if permissions.is_empty() {
            return Err(c.errf("at least one allow rule is required"));
        }
        let root = c.config.root.clone().unwrap_or_default();
        let seed = if Path::new(&seed).is_absolute() {
            PathBuf::from(seed)
        } else {
            root.join(seed)
        };
        let database = match database {
            Some(p) => {
                let p = root.join(p);
                Some(std::path::absolute(&p).unwrap_or(p))
            }
            None => None,
        };

        let registry = TransferRegistry::of(c.config);
        let d = Arc::new(Dyn {
            zone: zone.clone(),
            permissions,
            limits,
            seed,
            database,
            store: Mutex::new(None),
            closed: Default::default(),
            registry: registry.clone(),
            notify: Mutex::new((false, false)),
            fall: Arc::new(Fall::default()),
        });
        match &d.database {
            // validate now, but create nothing until first use
            Some(p) => {
                d.open_store(p, false).map_err(err)?;
            }
            None => {
                let records = read_seed(&d.seed, &zone, &limits).map_err(err)?;
                let s = Store::new(&zone, None, records).map_err(|e| err(format!("building zone {zone:?}: {e}")))?;
                *d.store.lock().unwrap() = Some(Arc::new(s));
            }
        }

        c.config.allow_update = true;
        CacheBypass::of(c.config).add(zone);
        registry.add_source(Arc::new(DynTransfer(d.clone())));
        let d2 = d.clone();
        c.on_shutdown(move || {
            d2.closed.store(true, std::sync::atomic::Ordering::Release);
            d2.store.lock().unwrap().take();
        });
        c.add_plugin(move |next| Arc::new(DynUpdate { d: d.clone(), next }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    /// One record from zone-file text.
    fn rr(s: &str) -> Record {
        let owner = s.split_whitespace().next().unwrap();
        let origin = Name::from_ascii(owner).unwrap();
        let is_soa = s.contains(" SOA ");
        let text = if is_soa {
            s.to_string()
        } else {
            format!("{owner} 1 IN SOA a. b. 1 1 1 1 1\n{s}")
        };
        let d = zone::parse(&text, &origin, Path::new("test"), 0).unwrap();
        if is_soa {
            return d.apex.soa.unwrap();
        }
        let apex = d.apex.ns.iter().cloned();
        apex.chain(d.tree.elems().flat_map(|e| e.all().cloned()))
            .next()
            .unwrap()
    }

    fn dyn_for(records: &[Record]) -> Dyn {
        let d = Dyn {
            zone: "example.org.".into(),
            permissions: vec![parse_permission(&["k.".into(), "*".into(), "*".into()], "example.org.").unwrap()],
            limits: Limits {
                records: 100,
                bytes: 1 << 20,
                update_records: 10,
            },
            seed: PathBuf::new(),
            database: None,
            store: Mutex::new(None),
            closed: Default::default(),
            registry: TransferRegistry::default(),
            notify: Mutex::new((false, false)),
            fall: Arc::default(),
        };
        *d.store.lock().unwrap() = Some(Arc::new(Store::new("example.org.", None, records.to_vec()).unwrap()));
        d
    }

    fn zone() -> Vec<Record> {
        vec![
            rr("example.org. 60 IN SOA ns.example.org. h.example.org. 10 60 60 60 60"),
            rr("example.org. 60 IN NS ns.example.org."),
            rr("www.example.org. 60 IN A 192.0.2.1"),
        ]
    }

    fn records(d: &Dyn) -> Vec<Record> {
        d.store().unwrap().records.lock().unwrap().clone()
    }

    #[test]
    fn add_delete_and_serial() {
        let d = dyn_for(&zone());
        let (changed, rc, _) = d.update("k.", &[], &[rr("new.example.org. 60 IN TXT \"x\"")]);
        assert!(changed && rc == ResponseCode::NoError);
        let r = records(&d);
        assert_eq!(r.len(), 4);
        assert_eq!(r.iter().find_map(soa_serial), Some(11));
        // identical add is no change
        let (changed, _, _) = d.update("k.", &[], &[rr("new.example.org. 60 IN TXT \"x\"")]);
        assert!(!changed);
        // delete rrset (class ANY, empty rdata)
        let mut del = Record::update0(Name::from_ascii("new.example.org.").unwrap(), 0, RecordType::TXT);
        del.dns_class = DNSClass::ANY;
        let (changed, _, _) = d.update("k.", &[], &[del]);
        assert!(changed);
        assert_eq!(records(&d).len(), 3);
    }

    #[test]
    fn prerequisites_and_auth() {
        let d = dyn_for(&zone());
        let mut nx = Record::update0(Name::from_ascii("www.example.org.").unwrap(), 0, RecordType::ANY);
        nx.dns_class = DNSClass::NONE;
        let (_, rc, _) = d.update("k.", &[nx], &[]);
        assert_eq!(rc, ResponseCode::YXDomain);
        let (_, rc, _) = d.update("other.", &[], &[rr("a.example.org. 60 IN A 192.0.2.9")]);
        assert_eq!(rc, ResponseCode::Refused);
        let (_, rc, _) = d.update("k.", &[], &[rr("a.example.com. 60 IN A 192.0.2.9")]);
        assert_eq!(rc, ResponseCode::NotZone);
        // CNAME next to other data is ignored
        let (changed, rc, _) = d.update("k.", &[], &[rr("www.example.org. 60 IN CNAME x.example.org.")]);
        assert!(!changed && rc == ResponseCode::NoError);
    }

    #[test]
    fn database_roundtrip() {
        let recs = zone();
        let lim = Limits {
            records: 10,
            bytes: 1 << 16,
            update_records: 1,
        };
        let enc = encode_db("example.org.", &recs).unwrap();
        let dec = decode_db(&enc, "example.org.", &lim).unwrap();
        assert_eq!(dec.len(), 3);
        assert!(
            decode_db(&enc, "example.com.", &lim)
                .unwrap_err()
                .contains("different zone")
        );
    }

    #[test]
    fn setup() {
        assert!(setup_err(&Setup, "dynupdate example.org {\n allow k. * *\n}").contains("file is required"));
        assert!(setup_err(&Setup, "dynupdate example.org {\n file x\n}").contains("allow rule"));
        assert!(setup_err(&Setup, "dynupdate example.org {\n file a\n file b\n}").contains("more than once"));
        assert!(
            setup_err(
                &Setup,
                "dynupdate example.org {\n file x\n allow k. a.example.com. A\n}"
            )
            .contains("outside zone")
        );
        assert!(setup_err(&Setup, "dynupdate example.org {\n file x\n allow k. * A *\n}").contains("wildcard"));
    }
}
