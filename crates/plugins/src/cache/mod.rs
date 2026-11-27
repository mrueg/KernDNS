//! `cache`: caches answers from the plugins after it. Port of `plugin/cache`.
//!
//! ```text
//! cache [TTL] [ZONES...] {
//!     success CAPACITY [TTL] [MINTTL]
//!     denial CAPACITY [TTL] [MINTTL]
//!     prefetch AMOUNT [[DURATION] [PERCENTAGE%]]
//!     serve_stale [DURATION] [immediate|verify]
//!     servfail DURATION
//!     disable success|denial [ZONES...]
//!     keepttl
//! }
//! ```
//!
//! Not ported yet (rejected with an error): `serve_stale_policy` and the
//! verify-timeout, stale-TTL and recheck arguments of `serve_stale`.

pub mod store;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use kerndns_core::duration::parse_duration;
use kerndns_core::proto::op::{Message, OpCode, ResponseCode};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::typify::{MAXIMUM_DEFAULT_TTL, MINIMAL_DEFAULT_TTL, ResponseType, minimal_ttl, typify};
use kerndns_core::zones::{self, is_subdomain};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure, result_rcode,
};

use store::Store;

use crate::pluginmetrics as pm;

const DEFAULT_CAP: usize = 10000;

/// One cached response.
pub struct Item {
    name: Name,
    qtype: RecordType,
    qclass: DNSClass,
    rcode: ResponseCode,
    authoritative: bool,
    authentic_data: bool,
    recursion_available: bool,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    orig_ttl: u32,
    stored: Instant,
    freq: Mutex<(Instant, u32)>,
    refreshing: AtomicBool,
}

impl Item {
    fn new(m: &Message, now: Instant, d: Duration) -> Self {
        let q = m.queries.first();
        Self {
            name: q.map(|q| q.name().clone()).unwrap_or_default(),
            qtype: q.map(|q| q.query_type()).unwrap_or(RecordType::NULL),
            qclass: q.map(|q| q.query_class()).unwrap_or(DNSClass::IN),
            rcode: m.metadata.response_code,
            authoritative: m.metadata.authoritative,
            authentic_data: m.metadata.authentic_data,
            recursion_available: m.metadata.recursion_available,
            answers: m.answers.clone(),
            authorities: m.authorities.clone(),
            additionals: m
                .additionals
                .iter()
                .filter(|r| r.record_type() != RecordType::OPT)
                .cloned()
                .collect(),
            orig_ttl: d.as_secs() as u32,
            stored: now,
            freq: Mutex::new((now, 0)),
            refreshing: AtomicBool::new(false),
        }
    }

    /// Remaining TTL in seconds (negative once expired).
    fn ttl(&self, now: Instant) -> i64 {
        let elapsed = if now >= self.stored {
            (now - self.stored).as_secs() as i64
        } else {
            -((self.stored - now).as_secs() as i64)
        };
        self.orig_ttl as i64 - elapsed
    }

    fn matches(&self, req: &Request) -> bool {
        req.qtype() == self.qtype && req.qclass() == self.qclass && *req.qname() == self.name
    }

    fn to_msg(&self, req: &Request, ttl: u32, do_bit: bool, ad: bool) -> Message {
        let mut m = req.reply();
        m.metadata.authoritative = self.authoritative;
        m.metadata.authentic_data = self.authentic_data && (do_bit || ad);
        m.metadata.recursion_available = self.recursion_available;
        m.metadata.response_code = self.rcode;
        m.answers = with_ttl(&self.answers, ttl);
        m.authorities = with_ttl(&self.authorities, ttl);
        m.additionals = with_ttl(&self.additionals, ttl);
        m
    }

    /// `freq.Update`: count hits within `window`.
    fn update_freq(&self, window: Duration, now: Instant) -> u32 {
        let mut f = self.freq.lock().unwrap();
        if now.saturating_duration_since(f.0) > window {
            *f = (now, 1);
        } else {
            *f = (now, f.1 + 1);
        }
        f.1
    }

    fn hits(&self) -> u32 {
        self.freq.lock().unwrap().1
    }
}

/// Copies of `rrs` (without OPT) with every TTL set to `ttl`, like
/// `filterRRSlice`.
fn with_ttl(rrs: &[Record], ttl: u32) -> Vec<Record> {
    rrs.iter()
        .filter(|r| r.record_type() != RecordType::OPT)
        .map(|r| {
            let mut r = r.clone();
            r.ttl = ttl;
            r
        })
        .collect()
}

/// FNV-1 (64 bit) over do, cd, qtype, qclass and the name, like the Go cache key.
fn hash(qname: &str, qtype: RecordType, qclass: DNSClass, do_bit: bool, cd: bool) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mut feed = |b: u8| {
        h = h.wrapping_mul(0x100000001b3);
        h ^= b as u64;
    };
    feed(if do_bit { b'1' } else { b'0' });
    feed(if cd { b'1' } else { b'0' });
    for b in u16::from(qtype).to_be_bytes() {
        feed(b);
    }
    for b in u16::from(qclass).to_be_bytes() {
        feed(b);
    }
    for b in qname.bytes() {
        feed(b);
    }
    h
}

fn has_soa(m: &Message) -> bool {
    m.authorities.iter().any(|r| r.record_type() == RecordType::SOA)
}

/// The CNAME target of `owner` in `answer`; `Some(None)` if there is no
/// CNAME, `None` if there are conflicting ones.
fn unique_cname_target(answer: &[Record], owner: &Name, qclass: DNSClass) -> Option<Option<Name>> {
    let mut target: Option<Name> = None;
    for r in answer {
        let RData::CNAME(c) = &r.data else { continue };
        if !(qclass == DNSClass::ANY || r.dns_class == qclass) || r.name != *owner {
            continue;
        }
        match &target {
            Some(t) if *t != c.0 => return None,
            _ => target = Some(c.0.clone()),
        }
    }
    Some(target)
}

/// `answersQuestion`: the answer section ends in a record of the asked
/// type (following CNAMEs).
fn answers_question(m: &Message) -> bool {
    let Some(q) = m.queries.first() else { return false };
    if m.metadata.response_code != ResponseCode::NoError || m.answers.is_empty() {
        return false;
    }
    let (qtype, qclass) = (q.query_type(), q.query_class());
    let class_ok = |c: DNSClass| qclass == DNSClass::ANY || c == qclass;
    if qtype == RecordType::ANY {
        return m.answers.iter().any(|r| class_ok(r.dns_class) && r.name == *q.name());
    }
    if qtype == RecordType::CNAME {
        return matches!(unique_cname_target(&m.answers, q.name(), qclass), Some(Some(_)));
    }
    let mut name = q.name().clone();
    let mut seen: Vec<Name> = Vec::new();
    loop {
        if seen.contains(&name) {
            return false;
        }
        seen.push(name.clone());
        match unique_cname_target(&m.answers, &name, qclass) {
            None => return false,
            Some(None) => break,
            Some(Some(t)) => name = t,
        }
    }
    m.answers
        .iter()
        .any(|r| r.record_type() == qtype && class_ok(r.dns_class) && r.name == name)
}

/// Answers that don't answer the question (e.g. a dangling CNAME).
fn is_nodata(m: &Message) -> bool {
    !m.answers.is_empty() && !answers_question(m)
}

fn cache_response_type(m: &Message) -> ResponseType {
    let t = typify(m, SystemTime::now());
    if t == ResponseType::NoError && has_soa(m) && is_nodata(m) {
        ResponseType::NoData
    } else {
        t
    }
}

/// Whether and under which key a response may be cached, like `key`.
fn cache_key(qname: &str, m: &Message, t: ResponseType, do_bit: bool, cd: bool) -> Option<u64> {
    if m.metadata.truncation {
        return None;
    }
    let q = m.queries.first()?;
    match t {
        ResponseType::OtherError | ResponseType::Meta | ResponseType::Update => return None,
        ResponseType::NameError if !has_soa(m) => return None,
        ResponseType::NoError if !has_soa(m) && is_nodata(m) => return None,
        _ => {}
    }
    Some(hash(qname, q.query_type(), q.query_class(), do_bit, cd))
}

/// The cache configuration and stores.
pub struct CacheCore {
    zones: Vec<String>,
    /// The `zones` metric label.
    zones_label: String,
    pcache: Store<Item>,
    pttl: Duration,
    minpttl: Duration,
    ncache: Store<Item>,
    nttl: Duration,
    minnttl: Duration,
    failttl: Duration,
    prefetch: u32,
    prefetch_window: Duration,
    percentage: u32,
    stale_up_to: Duration,
    verify_stale: bool,
    pexcept: Vec<String>,
    nexcept: Vec<String>,
    keepttl: bool,
}

impl CacheCore {
    fn usable(&self, i: &Item, req: &Request, now: Instant) -> bool {
        let ttl = i.ttl(now);
        i.matches(req) && (ttl > 0 || (!self.stale_up_to.is_zero() && -ttl < self.stale_up_to.as_secs() as i64))
    }

    /// `getIfNotStale`: a usable item from the denial or success cache.
    fn get(&self, now: Instant, req: &Request, server: &str) -> Option<Arc<Item>> {
        let k = hash(
            &req.name(),
            req.qtype(),
            req.qclass(),
            req.do_bit(),
            req.msg.metadata.checking_disabled,
        );
        let z = self.zones_label.as_str();
        pm::CACHE_REQUESTS.with_label_values(&[server, z, ""]).inc();
        if let Some(i) = self.ncache.get(k)
            && self.usable(&i, req, now)
        {
            // a cached SERVFAIL loses to a usable positive answer
            if i.rcode == ResponseCode::ServFail
                && let Some(p) = self.pcache.get(k)
                && self.usable(&p, req, now)
            {
                pm::CACHE_HITS.with_label_values(&[server, "success", z, ""]).inc();
                return Some(p);
            }
            pm::CACHE_HITS.with_label_values(&[server, "denial", z, ""]).inc();
            return Some(i);
        }
        if let Some(i) = self.pcache.get(k)
            && self.usable(&i, req, now)
        {
            pm::CACHE_HITS.with_label_values(&[server, "success", z, ""]).inc();
            return Some(i);
        }
        pm::CACHE_MISSES.with_label_values(&[server, z, ""]).inc();
        None
    }

    fn lookup_only(&self, now: Instant, req: &Request) -> Option<Arc<Item>> {
        let k = hash(
            &req.name(),
            req.qtype(),
            req.qclass(),
            req.do_bit(),
            req.msg.metadata.checking_disabled,
        );
        self.ncache
            .get(k)
            .or_else(|| self.pcache.get(k))
            .filter(|i| self.usable(i, req, now))
    }

    fn should_prefetch(&self, i: &Item, now: Instant) -> bool {
        if self.prefetch == 0 {
            return false;
        }
        i.update_freq(self.prefetch_window, now);
        let threshold = ((self.percentage as f64 / 100.0) * i.orig_ttl as f64).ceil() as i64;
        i.hits() >= self.prefetch && i.ttl(now) <= threshold
    }

    /// Store `m` for `key`, like `ResponseWriter.set`.
    fn set(&self, m: &Message, key: u64, t: ResponseType, d: Duration, prefetch: bool, server: &str) {
        self.store(m, key, t, d, prefetch, server);
        let z = self.zones_label.as_str();
        pm::CACHE_ENTRIES
            .with_label_values(&[server, "success", z, ""])
            .set(self.pcache.len() as f64);
        pm::CACHE_ENTRIES
            .with_label_values(&[server, "denial", z, ""])
            .set(self.ncache.len() as f64);
    }

    fn store(&self, m: &Message, key: u64, t: ResponseType, d: Duration, prefetch: bool, server: &str) {
        let z = self.zones_label.as_str();
        let Some(q) = m.queries.first() else { return };
        let qname = q.name().to_lowercase().to_ascii();
        let now = Instant::now();
        match t {
            ResponseType::NoError | ResponseType::Delegation => {
                if self.pexcept.iter().any(|z| is_subdomain(z, &qname)) {
                    return;
                }
                if self.pcache.add(key, Arc::new(Item::new(m, now, d))) {
                    pm::CACHE_EVICTIONS.with_label_values(&[server, "success", z, ""]).inc();
                }
                if prefetch {
                    self.ncache.remove(key);
                }
            }
            ResponseType::NameError | ResponseType::NoData | ResponseType::ServerError => {
                if self.nexcept.iter().any(|z| is_subdomain(z, &qname)) {
                    return;
                }
                if self.ncache.add(key, Arc::new(Item::new(m, now, d))) {
                    pm::CACHE_EVICTIONS.with_label_values(&[server, "denial", z, ""]).inc();
                }
            }
            _ => {}
        }
    }
}

/// Caches what passes through it, like the Go `cache.ResponseWriter`.
struct CacheWriter<'a> {
    inner: Option<&'a mut dyn ResponseWriter>,
    server: &'a str,
    core: &'a CacheCore,
    req: &'a Request,
    do_bit: bool,
    cd: bool,
    ad: bool,
    /// Store only; don't write to the client.
    prefetch: bool,
    /// Only take responses that refresh a stale entry (`serve_stale verify`).
    verify: bool,
    /// The last response written (after TTL adjustment).
    last: Option<Message>,
    /// A verify-mode refresh succeeded.
    refreshed: bool,
}

#[async_trait]
impl ResponseWriter for CacheWriter<'_> {
    async fn write_msg(&mut self, mut res: Message) -> std::io::Result<()> {
        if self.verify {
            // only successful answers and NXDOMAIN may replace a stale entry
            self.refreshed = false;
            let t = typify(&res, SystemTime::now());
            let rc = res.metadata.response_code;
            if res.metadata.truncation
                || !matches_question(self.req, &res)
                || matches!(t, ResponseType::OtherError | ResponseType::Meta | ResponseType::Update)
                || (rc != ResponseCode::NoError && rc != ResponseCode::NXDomain)
            {
                return Ok(());
            }
            self.refreshed = true;
        }

        let t = cache_response_type(&res);
        let key = cache_key(&self.req.name(), &res, t, self.do_bit, self.cd);
        let c = self.core;
        let duration = match t {
            ResponseType::NameError | ResponseType::NoData => {
                minimal_ttl(&res, t, c.nttl).clamp(c.minnttl.min(c.nttl), c.nttl)
            }
            ResponseType::ServerError => c.failttl,
            _ => minimal_ttl(&res, t, c.pttl).clamp(c.minpttl.min(c.pttl), c.pttl),
        };
        let ttl = duration.as_secs() as u32;
        res.answers = with_ttl(&res.answers, ttl);
        res.authorities = with_ttl(&res.authorities, ttl);
        res.additionals = with_ttl(&res.additionals, ttl);

        if let Some(k) = key
            && !duration.is_zero()
        {
            if matches_question(self.req, &res) {
                c.set(&res, k, t, duration, self.prefetch, self.server);
            } else {
                pm::CACHE_DROPS
                    .with_label_values(&[self.server, &c.zones_label, ""])
                    .inc();
            }
        }
        if !self.do_bit && !self.ad {
            res.metadata.authentic_data = false;
        }
        self.last = Some(res.clone());
        if self.prefetch {
            return Ok(());
        }
        match self.inner.as_mut() {
            Some(w) => w.write_msg(res).await,
            None => Ok(()),
        }
    }
}

/// `request.Match` for caching: same question, and a response.
fn matches_question(req: &Request, res: &Message) -> bool {
    use kerndns_core::proto::op::MessageType;
    if res.metadata.message_type != MessageType::Response {
        return false;
    }
    let Some(q) = res.queries.first() else { return false };
    let rq = req.query();
    q.name() == rq.name() && q.query_type() == rq.query_type() && q.query_class() == rq.query_class()
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "cache"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let err = |m: String| SetupError::new("cache", m);
        let num = |s: &str| {
            s.parse::<i64>()
                .map_err(|e| err(format!("strconv.Atoi: parsing {s:?}: {e}")))
        };
        let mut pttl = MAXIMUM_DEFAULT_TTL;
        let mut minpttl = MINIMAL_DEFAULT_TTL;
        let mut nttl = MAXIMUM_DEFAULT_TTL / 2;
        let mut minnttl = MINIMAL_DEFAULT_TTL;
        let mut failttl = MINIMAL_DEFAULT_TTL;
        let (mut pcap, mut ncap) = (DEFAULT_CAP, DEFAULT_CAP);
        let mut prefetch = 0u32;
        let mut prefetch_window = Duration::from_secs(60);
        let mut percentage = 10u32;
        let mut stale_up_to = Duration::ZERO;
        let mut verify_stale = false;
        let mut pexcept = Vec::new();
        let mut nexcept = Vec::new();
        let mut keepttl = false;
        let mut origins = vec![".".to_string()];
        let server_keys = c.server_block_keys();
        let mut seen = false;

        while c.next() {
            if seen {
                return Err(err("this plugin can only be used once per Server Block".into()));
            }
            seen = true;
            let mut args = c.remaining_args();
            if let Some(first) = args.first()
                && let Ok(ttl) = first.parse::<i64>()
            {
                if ttl <= 0 {
                    return Err(err(format!("cache TTL can not be zero or negative: {ttl}")));
                }
                pttl = Duration::from_secs(ttl as u64);
                nttl = pttl;
                args.remove(0);
            }
            origins = zones::origins_from_args_or_server_block(&args, &server_keys);

            while c.next_block() {
                let opt = c.val().to_string();
                match opt.as_str() {
                    "success" | "denial" => {
                        let a = c.remaining_args();
                        if a.is_empty() {
                            return Err(c.arg_err());
                        }
                        let cap = num(&a[0])? as usize;
                        let (mut ttl, mut min) = if opt == "success" {
                            (pttl, minpttl)
                        } else {
                            (nttl, minnttl)
                        };
                        if let Some(t) = a.get(1) {
                            let t = num(t)?;
                            if t <= 0 {
                                return Err(err(format!("cache TTL can not be zero or negative: {t}")));
                            }
                            ttl = Duration::from_secs(t as u64);
                        }
                        if let Some(m) = a.get(2) {
                            let m = num(m)?;
                            if m < 0 {
                                return Err(err(format!("cache min TTL can not be negative: {m}")));
                            }
                            min = Duration::from_secs(m as u64);
                        }
                        if opt == "success" {
                            (pcap, pttl, minpttl) = (cap, ttl, min);
                        } else {
                            (ncap, nttl, minnttl) = (cap, ttl, min);
                        }
                    }
                    "prefetch" => {
                        let a = c.remaining_args();
                        if a.is_empty() || a.len() > 3 {
                            return Err(c.arg_err());
                        }
                        let n = num(&a[0])?;
                        if n < 0 {
                            return Err(err(format!("prefetch amount should be positive: {n}")));
                        }
                        prefetch = n as u32;
                        if let Some(d) = a.get(1) {
                            prefetch_window = parse_duration(d).map_err(err)?;
                        }
                        if let Some(p) = a.get(2) {
                            let Some(p) = p.strip_suffix('%') else {
                                return Err(err(format!(
                                    "last character of percentage should be `%`, but is: {:?}",
                                    p.chars().last().unwrap_or(' ')
                                )));
                            };
                            let n = num(p)?;
                            if !(10..=90).contains(&n) {
                                return Err(err(format!("percentage should fall in range [10, 90]: {n}")));
                            }
                            percentage = n as u32;
                        }
                    }
                    "serve_stale" => {
                        let a = c.remaining_args();
                        if a.len() > 2 {
                            return Err(err(
                                "serve_stale: only DURATION and REFRESH_MODE are supported by KernDNS yet".into(),
                            ));
                        }
                        stale_up_to = Duration::from_secs(3600);
                        verify_stale = false;
                        if let Some(d) = a.first() {
                            stale_up_to = parse_duration(d).map_err(|e| {
                                if e.contains("negative") {
                                    err("invalid negative duration for serve_stale".into())
                                } else {
                                    err(e)
                                }
                            })?;
                        }
                        if let Some(mode) = a.get(1) {
                            match mode.to_ascii_lowercase().as_str() {
                                "immediate" => verify_stale = false,
                                "verify" => verify_stale = true,
                                m => return Err(err(format!("invalid value for serve_stale refresh mode: {m}"))),
                            }
                        }
                    }
                    "serve_stale_policy" => {
                        return Err(err("serve_stale_policy is not supported by KernDNS yet".into()));
                    }
                    "servfail" => {
                        let a = c.remaining_args();
                        if a.len() != 1 {
                            return Err(c.arg_err());
                        }
                        let d = parse_duration(&a[0]).map_err(|e| {
                            if e.contains("negative") {
                                err("invalid negative ttl for servfail".into())
                            } else {
                                err(e)
                            }
                        })?;
                        if d > Duration::from_secs(300) {
                            return Err(err("caching SERVFAIL responses over 5 minutes is not permitted".into()));
                        }
                        failttl = d;
                    }
                    "disable" => {
                        let a = c.remaining_args();
                        if a.is_empty() {
                            return Err(c.arg_err());
                        }
                        let zs: Vec<String> = if a.len() > 1 {
                            a[1..]
                                .iter()
                                .map(|z| zones::normalize_exact(z).into_iter().next().unwrap_or_default())
                                .collect()
                        } else {
                            vec![".".into()]
                        };
                        if let Some(bad) = a[1..].iter().zip(&zs).find(|(_, n)| n.is_empty()) {
                            return Err(err(format!("invalid disabled zone: {}", bad.0)));
                        }
                        match a[0].as_str() {
                            "denial" => nexcept = zs,
                            "success" => pexcept = zs,
                            _ => return Err(err("cache type for disable must be \"success\" or \"denial\"".into())),
                        }
                    }
                    "keepttl" => {
                        if !c.remaining_args().is_empty() {
                            return Err(c.arg_err());
                        }
                        keepttl = true;
                    }
                    _ => return Err(c.arg_err()),
                }
            }
        }

        let core = Arc::new(CacheCore {
            zones_label: origins.join(","),
            zones: origins,
            pcache: Store::new(pcap),
            pttl,
            minpttl,
            ncache: Store::new(ncap),
            nttl,
            minnttl,
            failttl,
            prefetch,
            prefetch_window,
            percentage,
            stale_up_to,
            verify_stale,
            pexcept,
            nexcept,
            keepttl,
        });
        let bypass = kerndns_core::plugin::CacheBypass::of(c.config);
        c.add_plugin(move |next| {
            Arc::new(Cache {
                core: core.clone(),
                bypass: bypass.clone(),
                next,
            })
        });
        Ok(())
    }
}

pub struct Cache {
    core: Arc<CacheCore>,
    /// Zones of mutable authoritative plugins (`dynupdate`).
    bypass: kerndns_core::plugin::CacheBypass,
    next: Next,
}

impl Cache {
    /// Refresh `item` in the background, like `tryPrefetch`.
    fn try_prefetch(&self, ctx: &Context, req: &Request, item: &Arc<Item>, stale: bool) {
        if item.refreshing.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(next) = self.next.clone() else {
            item.refreshing.store(false, Ordering::Release);
            return;
        };
        let (core, item, mut ctx, mut req) = (self.core.clone(), item.clone(), ctx.clone(), req.clone());
        req.msg.metadata.authentic_data = true;
        let now = Instant::now();
        tokio::spawn(async move {
            let do_bit = req.do_bit();
            let cd = req.msg.metadata.checking_disabled;
            let server = ctx.server.clone();
            pm::CACHE_PREFETCHES
                .with_label_values(&[&*server, &core.zones_label, ""])
                .inc();
            let mut w = CacheWriter {
                inner: None,
                server: &server,
                core: &core,
                req: &req,
                do_bit,
                cd,
                ad: true,
                prefetch: true,
                verify: stale,
                last: None,
                refreshed: false,
            };
            let _ = next.serve_dns(&mut ctx, &mut w, &req).await;
            let refreshed = !stale || w.refreshed;
            if refreshed && let Some(i1) = core.lookup_only(now, &req) {
                // keep the hit count across the refresh
                *i1.freq.lock().unwrap() = (now, item.hits());
            }
            item.refreshing.store(false, Ordering::Release);
        });
    }
}

#[async_trait]
impl Handler for Cache {
    fn name(&self) -> &'static str {
        "cache"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let core = &self.core;
        if req.msg.metadata.op_code != OpCode::Query {
            return next_or_failure("cache", &self.next, ctx, w, req).await;
        }
        let name = req.name();
        if !core.zones.iter().any(|z| is_subdomain(z, &name)) || self.bypass.contains(&name) {
            return next_or_failure("cache", &self.next, ctx, w, req).await;
        }
        let do_bit = req.do_bit();
        let cd = req.msg.metadata.checking_disabled;
        let ad = req.msg.metadata.authentic_data;
        let now = Instant::now();

        // the request sent downstream asks for the AD bit
        let mut refresh = req.clone();
        refresh.msg.metadata.authentic_data = true;

        let server = ctx.server.clone();
        let Some(item) = core.get(now, req, &server) else {
            let mut cw = CacheWriter {
                inner: Some(w),
                server: &server,
                core,
                req: &refresh,
                do_bit,
                cd,
                ad,
                prefetch: false,
                verify: false,
                last: None,
                refreshed: false,
            };
            let res = next_or_failure("cache", &self.next, ctx, &mut cw, &refresh).await;
            if result_rcode(&res) == ResponseCode::ServFail && cw.last.is_none() && !core.failttl.is_zero() {
                // remember the failure without answering (the server writes SERVFAIL)
                let m = refresh.error_reply(ResponseCode::ServFail);
                cw.prefetch = true;
                let _ = cw.write_msg(m).await;
            }
            return res;
        };

        let ttl = item.ttl(now);
        let stale = ttl <= 0;
        if stale {
            if core.verify_stale {
                let mut cw = CacheWriter {
                    inner: Some(&mut *w),
                    server: &server,
                    core,
                    req: &refresh,
                    do_bit,
                    cd,
                    ad,
                    prefetch: false,
                    verify: true,
                    last: None,
                    refreshed: false,
                };
                let res = next_or_failure("cache", &self.next, ctx, &mut cw, &refresh).await;
                if cw.refreshed {
                    return res;
                }
            } else {
                self.try_prefetch(ctx, req, &item, true);
            }
        } else if core.should_prefetch(&item, now) {
            self.try_prefetch(ctx, req, &item, false);
        }

        if stale {
            pm::CACHE_SERVED_STALE
                .with_label_values(&[&*server, &core.zones_label, ""])
                .inc();
        }
        let out_ttl = if core.keepttl {
            item.orig_ttl
        } else if stale {
            0
        } else {
            ttl as u32
        };
        let resp = item.to_msg(req, out_ttl, do_bit, ad);
        w.write_msg(resp)
            .await
            .map_err(|e| PluginError::servfail("cache", e.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::rr::rdata::{A, SOA};
    use std::sync::atomic::AtomicU32;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "cache"));
        assert!(setup_ok(
            &Setup,
            "cache 300 example.org {\n success 5000 600 10\n denial 1000\n prefetch 10 1m 20%\n serve_stale 1h verify\n servfail 10s\n disable denial sub.example.org\n keepttl\n}"
        ));
        assert!(setup_err(&Setup, "cache 0").contains("can not be zero or negative"));
        assert!(setup_err(&Setup, "cache {\n prefetch 1 1m 5%\n}").contains("range [10, 90]"));
        assert!(setup_err(&Setup, "cache {\n servfail 10m\n}").contains("over 5 minutes"));
        assert!(setup_err(&Setup, "cache {\n disable foo\n}").contains("must be \"success\" or \"denial\""));
        assert!(
            setup_err(&Setup, "cache {\n serve_stale_policy prefer_positive\n}")
                .contains("not supported by KernDNS yet")
        );
    }

    /// Answers A queries with TTL 300 and counts calls.
    struct Upstream(Arc<AtomicU32>, ResponseCode);

    #[async_trait]
    impl Handler for Upstream {
        fn name(&self) -> &'static str {
            "upstream"
        }
        async fn serve_dns(&self, _: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
            self.0.fetch_add(1, Ordering::Relaxed);
            let mut m = req.reply();
            m.metadata.response_code = self.1;
            if self.1 == ResponseCode::NoError {
                m.answers.push(Record::from_rdata(
                    req.qname().clone(),
                    300,
                    RData::A(A::new(192, 0, 2, 1)),
                ));
                m.answers.push(Record::from_rdata(
                    req.qname().clone(),
                    30,
                    RData::A(A::new(192, 0, 2, 2)),
                ));
            } else {
                let soa = SOA::new(Name::root(), Name::root(), 1, 1, 1, 1, 60);
                m.authorities.push(Record::from_rdata(
                    Name::from_ascii("example.org.").unwrap(),
                    120,
                    RData::SOA(soa),
                ));
            }
            w.write_msg(m).await.unwrap();
            Ok(ResponseCode::NoError)
        }
    }

    fn cache_with(rc: ResponseCode) -> (Cache, Arc<AtomicU32>) {
        let calls = Arc::new(AtomicU32::new(0));
        let core = Arc::new(CacheCore {
            zones_label: ".".into(),
            zones: vec![".".into()],
            pcache: Store::new(100),
            pttl: MAXIMUM_DEFAULT_TTL,
            minpttl: MINIMAL_DEFAULT_TTL,
            ncache: Store::new(100),
            nttl: MAXIMUM_DEFAULT_TTL / 2,
            minnttl: MINIMAL_DEFAULT_TTL,
            failttl: MINIMAL_DEFAULT_TTL,
            prefetch: 0,
            prefetch_window: Duration::from_secs(60),
            percentage: 10,
            stale_up_to: Duration::ZERO,
            verify_stale: false,
            pexcept: vec![],
            nexcept: vec![],
            keepttl: false,
        });
        let up: Arc<dyn Handler> = Arc::new(Upstream(calls.clone(), rc));
        (
            Cache {
                core,
                bypass: Default::default(),
                next: Some(up),
            },
            calls,
        )
    }

    #[tokio::test]
    async fn caches_positive_answers_with_min_ttl() {
        let (c, calls) = cache_with(ResponseCode::NoError);
        let req = query("a.example.org.", RecordType::A, "10.0.0.1:1");
        let (_, w) = serve(&c, &req).await;
        let first = w.msg().unwrap();
        // every record gets the minimal TTL of the response
        assert!(first.answers.iter().all(|r| r.ttl == 30));
        let (_, w) = serve(&c, &req).await;
        assert_eq!(w.msg().unwrap().answers.len(), 2);
        assert_eq!(calls.load(Ordering::Relaxed), 1, "second query served from cache");
        // different type: miss
        let _ = serve(&c, &query("a.example.org.", RecordType::AAAA, "10.0.0.1:1")).await;
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn caches_nxdomain_with_soa() {
        let (c, calls) = cache_with(ResponseCode::NXDomain);
        let req = query("nx.example.org.", RecordType::A, "10.0.0.1:1");
        let _ = serve(&c, &req).await;
        let (_, w) = serve(&c, &req).await;
        let m = w.msg().unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(m.authorities[0].ttl, 120);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn nodata_detection() {
        let req = query("a.example.org.", RecordType::A, "10.0.0.1:1");
        let mut m = req.reply();
        m.answers.push(Record::from_rdata(
            req.qname().clone(),
            60,
            RData::CNAME(kerndns_core::proto::rr::rdata::CNAME(
                Name::from_ascii("b.example.org.").unwrap(),
            )),
        ));
        assert!(is_nodata(&m), "dangling CNAME doesn't answer the question");
        m.answers.push(Record::from_rdata(
            Name::from_ascii("b.example.org.").unwrap(),
            60,
            RData::A(A::new(1, 2, 3, 4)),
        ));
        assert!(!is_nodata(&m));
    }
}
