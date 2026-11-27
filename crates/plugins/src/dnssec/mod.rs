//! `dnssec`: signs responses on the fly, with NSEC "black lies" for
//! authenticated denial of existence. Port of `plugin/dnssec`.
//!
//! Requests with the DO bit get their answers from the rest of the chain
//! signed with the configured keys; DNSKEY queries for a zone apex are
//! answered here. Signatures are kept in a fixed-size cache keyed by the
//! RRset (so `cache`, which runs before `dnssec`, stores signed answers and
//! a changed RRset gets a new signature).

pub mod key;

use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kerndns_core::proto::dnssec::rdata::{DNSSECRData, NSEC};
use kerndns_core::proto::op::{Message, ResponseCode};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::request::lower_fqdn;
use kerndns_core::typify::{ResponseType, typify};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure, zones,
};

use crate::cache::store::Store;
use crate::pluginmetrics as pm;
pub use key::{Key, parse_key_file};

/// Signatures are valid for 8 days...
const EIGHT_DAYS: i64 = 8 * 24 * 3600;
/// ...and a cached one is replaced when less than 2 days are left.
const TWO_DAYS: i64 = 2 * 24 * 3600;
/// Default capacity of the signature cache.
pub const DEFAULT_CAP: usize = 10000;
/// The Original TTL of every signature (`origTTL`).
const ORIG_TTL: u32 = 3600;

type SigCache = Store<Vec<Record>>;

/// One zone to sign: its name as a string (for matching) and as a `Name`.
struct SignZone {
    name: String,
    origin: Name,
}

/// `Dnssec`.
pub struct Dnssec {
    next: Next,
    zones: Arc<Vec<String>>,
    origins: Arc<Vec<SignZone>>,
    keys: Arc<Vec<Key>>,
    splitkeys: bool,
    cache: Arc<SigCache>,
}

fn unix(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Inception 3 hours ago, expiration in 8 days (`incepExpir`).
pub fn incep_expir(now: SystemTime) -> (u32, u32) {
    let now = unix(now);
    ((now - 3 * 3600) as u32, (now + EIGHT_DAYS) as u32)
}

/// The signature cache key of an RRset: everything `rr.String()` shows
/// (owner name with its case, TTL, class, type, rdata), so a changed RRset
/// is signed again.
pub fn hash(rrs: &[Record]) -> u64 {
    let mut h = std::hash::DefaultHasher::new();
    for r in rrs {
        for l in r.name.iter() {
            l.hash(&mut h);
        }
        r.ttl.hash(&mut h);
        u16::from(r.dns_class).hash(&mut h);
        u16::from(r.record_type()).hash(&mut h);
        r.data.hash(&mut h);
    }
    h.finish()
}

/// RRsets of `rrs` in order of first appearance, without RRSIG and OPT
/// records (`rrSets`). Owner names compare case-sensitively, like the
/// strings CoreDNS groups by.
fn rr_sets(rrs: &[Record]) -> Vec<Vec<Record>> {
    let mut sets: Vec<Vec<Record>> = Vec::new();
    for r in rrs {
        let t = r.record_type();
        if t == RecordType::RRSIG || t == RecordType::OPT {
            continue;
        }
        match sets
            .iter_mut()
            .find(|s| s[0].record_type() == t && s[0].name.eq_case(&r.name))
        {
            Some(s) => s.push(r.clone()),
            None => sets.push(vec![r.clone()]),
        }
    }
    sets
}

// The NSEC bit maps we return.
const DELEGATION_BITMAP: [u16; 15] = [1, 2, 13, 16, 28, 29, 33, 37, 44, 46, 47, 52, 55, 61, 99];
const ZONE_BITMAP: [u16; 14] = [1, 13, 16, 28, 29, 33, 37, 44, 46, 47, 52, 55, 61, 99];
const APEX_BITMAP: [u16; 18] = [1, 2, 6, 13, 15, 16, 28, 29, 33, 37, 44, 46, 47, 48, 52, 55, 61, 99];

/// `filter14`/`filter18`: the bitmap without `t` for denials, unless `t` is
/// NSEC; otherwise the whole bitmap.
fn filter(t: RecordType, bitmap: &[u16], mt: ResponseType) -> Vec<RecordType> {
    let all = bitmap.iter().map(|&b| RecordType::from(b));
    if (mt != ResponseType::NoData && mt != ResponseType::NameError) || t == RecordType::NSEC {
        return all.collect();
    }
    all.filter(|&b| b != t).collect()
}

/// `name` with a `\000` label in front.
fn zero_label(name: &Name) -> Name {
    let labels = std::iter::once(&[0u8][..]).chain(name.iter());
    Name::from_labels(labels).unwrap_or_else(|_| name.clone())
}

/// `name` with `\000` appended to its first label (`a.b.` -> `a\000.b.`).
fn zero_suffix(name: &Name) -> Name {
    let mut labels: Vec<Vec<u8>> = name.iter().map(<[u8]>::to_vec).collect();
    if let Some(first) = labels.first_mut() {
        first.push(0);
    }
    Name::from_labels(labels).unwrap_or_else(|_| name.clone())
}

impl Dnssec {
    fn new(zones: Vec<String>, keys: Vec<Key>, splitkeys: bool, next: Next, cache: Arc<SigCache>) -> Self {
        let origins = zones
            .iter()
            .map(|z| SignZone {
                name: z.clone(),
                origin: Name::from_ascii(z).unwrap_or_else(|_| Name::root()),
            })
            .collect();
        Self {
            next,
            zones: Arc::new(zones),
            origins: Arc::new(origins),
            keys: Arc::new(keys),
            splitkeys,
            cache,
        }
    }

    fn origin(&self, zone: &str) -> Name {
        self.origins
            .iter()
            .find(|z| z.name == zone)
            .map(|z| z.origin.clone())
            .unwrap_or_else(|| Name::from_ascii(zone).unwrap_or_else(|_| Name::root()))
    }

    /// `Sign`: sign the response `m` for `zone` (the zone its question is
    /// in). Denials get an NSEC black lie and become NODATA; delegations
    /// get their DS (or an NSEC proving there is none) signed.
    pub fn sign_msg(&self, m: &mut Message, zone: &str, now: SystemTime, server: &str) {
        let (incep, expir) = incep_expir(now);
        let zone_name = self.origin(zone);
        let (qname, qtype) = m
            .queries
            .first()
            .map(|q| (q.name().clone(), q.query_type()))
            .unwrap_or((Name::root(), RecordType::NULL));
        let name = lower_fqdn(&qname);

        let mt = typify(m, SystemTime::now());
        if mt == ResponseType::Delegation {
            let Some(first) = m.authorities.first() else { return };
            let ttl = first.ttl;
            let ds: Vec<Record> = m
                .authorities
                .iter()
                .filter(|r| r.record_type() == RecordType::DS)
                .cloned()
                .collect();
            let sigs = if ds.is_empty() {
                self.nsec(&qname, &name, qtype, zone, &zone_name, mt, ttl, incep, expir, server)
            } else {
                self.sign(&ds, &zone_name, ttl, incep, expir, server)
            };
            if let Ok(sigs) = sigs {
                m.authorities.extend(sigs);
            }
            return;
        }

        if mt == ResponseType::NameError || mt == ResponseType::NoData {
            if m.authorities.len() != 1 || m.authorities[0].record_type() != RecordType::SOA {
                return;
            }
            let ttl = m.authorities[0].ttl;
            if let Ok(sigs) = self.sign(&m.authorities.clone(), &zone_name, ttl, incep, expir, server) {
                m.authorities.extend(sigs);
            }
            if let Ok(sigs) = self.nsec(&qname, &name, qtype, zone, &zone_name, mt, ttl, incep, expir, server) {
                m.authorities.extend(sigs);
            }
            if m.authorities.len() > 1 {
                // actually added nsec and sigs, reset the rcode
                m.metadata.response_code = ResponseCode::NoError;
                if qtype == RecordType::NSEC {
                    // the NSEC and its signature are the answer, without the SOA
                    let n = m.authorities.len();
                    m.answers = m.authorities[n - 2..].to_vec();
                    m.authorities.clear();
                }
            }
            return;
        }

        // only sign what is inside our zones (e.g. not a CNAME target elsewhere)
        for section in 0..3 {
            let rrs = match section {
                0 => &m.answers,
                1 => &m.authorities,
                _ => &m.additionals,
            };
            let mut add = Vec::new();
            for set in rr_sets(rrs) {
                let Some(signer) = zones::matches(&self.zones, &lower_fqdn(&set[0].name)) else {
                    continue;
                };
                let signer = self.origin(signer);
                let ttl = set[0].ttl;
                if let Ok(sigs) = self.sign(&set, &signer, ttl, incep, expir, server) {
                    add.extend(sigs);
                }
            }
            match section {
                0 => m.answers.extend(add),
                1 => m.authorities.extend(add),
                _ => m.additionals.extend(add),
            }
        }
    }

    /// `nsec`: the NSEC black lie for the query name and its signatures
    /// (signatures first). See draft-valsorda-dnsop-black-lies.
    #[allow(clippy::too_many_arguments)]
    fn nsec(
        &self,
        qname: &Name,
        name: &str,
        qtype: RecordType,
        zone: &str,
        zone_name: &Name,
        mt: ResponseType,
        ttl: u32,
        incep: u32,
        expir: u32,
        server: &str,
    ) -> Result<Vec<Record>, String> {
        let mut next = zero_label(qname);
        let bitmap = if name == zone {
            filter(qtype, &APEX_BITMAP, mt)
        } else if mt == ResponseType::Delegation || qtype == RecordType::DS {
            if mt == ResponseType::Delegation {
                next = zero_suffix(qname);
            }
            DELEGATION_BITMAP.iter().map(|&b| RecordType::from(b)).collect()
        } else {
            filter(qtype, &ZONE_BITMAP, mt)
        };
        let mut nsec = Record::from_rdata(
            qname.clone(),
            ttl,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, bitmap))),
        );
        nsec.dns_class = DNSClass::IN;
        let nsec = vec![nsec];
        let mut sigs = self.sign(&nsec, zone_name, ttl, incep, expir, server)?;
        sigs.extend(nsec);
        Ok(sigs)
    }

    /// `sign`: the signatures for one RRset, from the cache or made with
    /// every key (with split keys: KSKs for DNSKEY, ZSKs for the rest).
    /// An error from any key returns no signatures at all.
    pub fn sign(
        &self,
        rrs: &[Record],
        signer: &Name,
        ttl: u32,
        incep: u32,
        expir: u32,
        server: &str,
    ) -> Result<Vec<Record>, String> {
        let k = hash(rrs);
        if let Some(sigs) = self.get(k, server) {
            return Ok(sigs);
        }
        let is_dnskey = rrs.first().is_some_and(|r| r.record_type() == RecordType::DNSKEY);
        let mut sigs = Vec::with_capacity(self.keys.len());
        for key in self.keys.iter() {
            if self.splitkeys && (if is_dnskey { !key.is_ksk() } else { !key.is_zsk() }) {
                continue;
            }
            sigs.push(key.sign(rrs, signer, ttl, ORIG_TTL, incep, expir)?);
        }
        if !sigs.is_empty() {
            self.cache.add(k, Arc::new(sigs.clone()));
        }
        Ok(sigs)
    }

    /// A cached signature set, if every signature is still valid two days
    /// from now (3/4 of the 8 days signed for).
    fn get(&self, key: u64, server: &str) -> Option<Vec<Record>> {
        if let Some(s) = self.cache.get(key) {
            let is75 = unix(SystemTime::now()) + TWO_DAYS;
            if s.iter().all(|r| valid_at(r, is75)) {
                pm::DNSSEC_CACHE_HITS.with_label_values(&[server]).inc();
                return Some((*s).clone());
            }
        }
        pm::DNSSEC_CACHE_MISSES.with_label_values(&[server]).inc();
        None
    }

    /// `getDNSKEY`: the zone's keys, signed when `do_bit` is set.
    fn get_dnskey(&self, req: &Request, zone: &str, do_bit: bool, server: &str) -> Message {
        let origin = self.origin(zone);
        let keys: Vec<Record> = self
            .keys
            .iter()
            .map(|k| {
                let mut r = k.record.clone();
                r.name = origin.clone();
                r
            })
            .collect();
        let mut m = req.reply();
        m.answers = keys;
        if !do_bit {
            return m;
        }
        let (incep, expir) = incep_expir(SystemTime::now());
        if let Ok(sigs) = self.sign(&m.answers.clone(), &origin, 3600, incep, expir, server) {
            m.answers.extend(sigs);
        }
        m
    }
}

fn valid_at(r: &Record, t: i64) -> bool {
    match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => key::validity_period(s, t),
        _ => false,
    }
}

/// Signs what the rest of the chain writes.
struct SignWriter<'a> {
    inner: &'a mut dyn ResponseWriter,
    d: &'a Dnssec,
    server: &'a str,
}

#[async_trait]
impl ResponseWriter for SignWriter<'_> {
    async fn write_msg(&mut self, mut res: Message) -> std::io::Result<()> {
        let zone = res
            .queries
            .first()
            .and_then(|q| zones::matches(&self.d.zones, &lower_fqdn(q.name())).map(str::to_string));
        let Some(zone) = zone else {
            return self.inner.write_msg(res).await;
        };
        self.d.sign_msg(&mut res, &zone, SystemTime::now(), self.server);
        pm::DNSSEC_CACHE_ENTRIES
            .with_label_values(&[self.server, "signature"])
            .set(self.d.cache.len() as f64);
        self.inner.write_msg(res).await
    }
}

#[async_trait]
impl Handler for Dnssec {
    fn name(&self) -> &'static str {
        "dnssec"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let do_bit = req.do_bit();
        let qname = req.name();
        let qtype = req.qtype();
        if zones::matches(&self.zones, &qname).is_none() {
            return next_or_failure("dnssec", &self.next, ctx, w, req).await;
        }
        let server = ctx.server.clone();

        // Answer DNSKEY queries for one of our zones' apex.
        if qtype == RecordType::DNSKEY
            && let Some(z) = self.zones.iter().find(|z| **z == qname)
        {
            let mut resp = self.get_dnskey(req, z, do_bit, &server);
            resp.metadata.authoritative = true;
            w.write_msg(resp)
                .await
                .map_err(|e| PluginError::servfail("dnssec", e.to_string()))?;
            return Ok(ResponseCode::NoError);
        }

        if do_bit {
            let mut sw = SignWriter {
                inner: w,
                d: self,
                server: &server,
            };
            return next_or_failure("dnssec", &self.next, ctx, &mut sw, req).await;
        }
        next_or_failure("dnssec", &self.next, ctx, w, req).await
    }
}

/// `periodicClean`: drop cached signatures that are less than 2 days from
/// expiring.
fn clean(cache: &SigCache) {
    let is75 = unix(SystemTime::now()) + TWO_DAYS;
    cache.retain(|sigs| sigs.iter().all(|r| valid_at(r, is75)));
}

pub struct Setup;

/// What `dnssecParse` returns.
pub struct Config {
    pub zones: Vec<String>,
    pub keys: Vec<Key>,
    pub capacity: usize,
    pub splitkeys: bool,
}

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "dnssec"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let cfg = dnssec_parse(c)?;
        let cache = Arc::new(SigCache::new(cfg.capacity));

        let task: Arc<std::sync::Mutex<Option<tokio::task::AbortHandle>>> = Arc::default();
        {
            let task = task.clone();
            let weak = Arc::downgrade(&cache);
            c.on_startup(move || {
                let every = Duration::from_secs(8 * 3600);
                let t = tokio::spawn(async move {
                    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
                    loop {
                        tick.tick().await;
                        let Some(cache) = weak.upgrade() else { return };
                        clean(&cache);
                    }
                });
                *task.lock().unwrap() = Some(t.abort_handle());
                Ok(())
            });
        }
        c.on_shutdown(move || {
            if let Some(t) = task.lock().unwrap().take() {
                t.abort();
            }
        });

        let Config {
            zones, keys, splitkeys, ..
        } = cfg;
        c.add_plugin(move |next| {
            Arc::new(Dnssec::new(zones.clone(), keys.clone(), splitkeys, next, cache.clone())) as Arc<dyn Handler>
        });
        Ok(())
    }
}

/// `dnssecParse`.
pub fn dnssec_parse(c: &mut Controller<'_>) -> Result<Config, SetupError> {
    let err = |m: String| SetupError::new("dnssec", m);
    let mut zones_v = Vec::new();
    let mut keys: Vec<Key> = Vec::new();
    let mut capacity = DEFAULT_CAP;
    let server_keys = c.server_block_keys();

    let mut i = 0;
    while c.next() {
        if i > 0 {
            return Err(err("this plugin can only be used once per Server Block".into()));
        }
        i += 1;
        let args = c.remaining_args();
        zones_v = zones::origins_from_args_or_server_block(&args, &server_keys);

        while c.next_block() {
            match c.val().to_string().as_str() {
                "key" => keys.extend(key_parse(c)?),
                "cache_capacity" => {
                    if !c.next_arg() {
                        return Err(c.arg_err());
                    }
                    let v = c.val().to_string();
                    capacity = v
                        .parse::<i64>()
                        .map_err(|_| err(format!("strconv.Atoi: parsing {v:?}: invalid syntax")))?
                        .max(0) as usize;
                }
                x => return Err(c.errf(format!("unknown property '{x}'"))),
            }
        }
    }
    // Do we have both KSKs and ZSKs?
    let ksk = keys.iter().filter(|k| k.is_ksk()).count();
    let zsk = keys.iter().filter(|k| !k.is_ksk() && k.is_zsk()).count();
    let splitkeys = zsk > 0 && ksk > 0;

    // Can each key's owner name sign one of the zones?
    for k in &keys {
        let kname = lower_fqdn(&k.record.name);
        if !zones_v.iter().any(|z| zones::is_subdomain(&kname, z)) {
            return Err(err(format!(
                "key {} (keyid: {}) can not sign any of the zones",
                k.record.name.to_ascii(),
                k.tag
            )));
        }
    }
    Ok(Config {
        zones: zones_v,
        keys,
        capacity,
        splitkeys,
    })
}

/// The base name of a key file: `Kmiek.nl.+013+26205.key`, `.private` or
/// without extension, under `root` if relative.
pub fn key_base(k: &str, root: Option<&PathBuf>) -> PathBuf {
    let base = k
        .strip_suffix(".key")
        .or_else(|| k.strip_suffix(".private"))
        .unwrap_or(k);
    let base = PathBuf::from(base);
    match root {
        Some(r) if base.is_relative() => r.join(base),
        _ => base,
    }
}

/// Read the keys `base.key` and `base.private`.
pub fn read_key(base: &std::path::Path) -> Result<Key, String> {
    let mut public = base.as_os_str().to_owned();
    public.push(".key");
    let mut private = base.as_os_str().to_owned();
    private.push(".private");
    parse_key_file(std::path::Path::new(&public), std::path::Path::new(&private))
}

/// `keyParse`: `key file KEY...` (`key aws_secretsmanager` is not
/// supported).
fn key_parse(c: &mut Controller<'_>) -> Result<Vec<Key>, SetupError> {
    let mut keys = Vec::new();
    if !c.next_arg() {
        return Err(c.arg_err());
    }
    match c.val() {
        "file" => {
            let ks = c.remaining_args();
            if ks.is_empty() {
                return Err(c.arg_err());
            }
            let root = c.config.root.clone();
            for k in ks {
                let key = read_key(&key_base(&k, root.as_ref())).map_err(|e| SetupError::new("dnssec", e))?;
                keys.push(key);
            }
        }
        "aws_secretsmanager" => {
            if c.remaining_args().is_empty() {
                return Err(c.arg_err());
            }
            return Err(SetupError::new(
                "dnssec",
                "key aws_secretsmanager is not supported by KernDNS; use key file",
            ));
        }
        _ => {}
    }
    Ok(keys)
}

#[cfg(test)]
mod tests;
