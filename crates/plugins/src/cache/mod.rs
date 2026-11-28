//! `cache`: caches answers from the plugins after it. Port of `plugin/cache`.
//!
//! ```text
//! cache [TTL] [ZONES...] {
//!     success CAPACITY [TTL] [MINTTL]
//!     denial CAPACITY [TTL] [MINTTL]
//!     prefetch AMOUNT [[DURATION] [PERCENTAGE%]]
//!     serve_stale [DURATION] [immediate [RESPONSE_TTL [FAILURE_RECHECK]] | verify [VERIFY_TIMEOUT [RESPONSE_TTL [FAILURE_RECHECK]]]]
//!     serve_stale_policy prefer_positive
//!     servfail DURATION
//!     disable success|denial [ZONES...]
//!     keepttl
//! }
//! ```
//!
//! Not ported: the `zone/wildcard` metadata CoreDNS keeps with a cached
//! wildcard answer (no KernDNS plugin sets it).

pub mod store;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use kerndns_core::duration::parse_duration;
use kerndns_core::proto::op::{Message, OpCode, ResponseCode};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::typify::{MAXIMUM_DEFAULT_TTL, MINIMAL_DEFAULT_TTL, ResponseType, minimal_ttl, typify};
use kerndns_core::zones::{self, is_subdomain};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Protocol, Request, ResponseWriter,
    SetupError, async_trait, next_or_failure, result_rcode,
};

use store::Store;

use crate::pluginmetrics as pm;

const DEFAULT_CAP: usize = 10000;

/// The cache's time source (Go's `Cache.now`). Unit tests move it forward;
/// in every other build it is the system clocks, with no indirection.
#[derive(Default)]
pub(crate) struct Clock {
    /// Added to the system clocks (unit tests only).
    #[cfg(test)]
    offset_nanos: AtomicU64,
}

impl Clock {
    #[inline]
    fn now(&self) -> Instant {
        #[cfg(test)]
        return Instant::now() + self.offset();
        #[cfg(not(test))]
        Instant::now()
    }

    /// Wall clock time, for RRSIG validity (`response.Typify`).
    #[inline]
    fn wall(&self) -> SystemTime {
        #[cfg(test)]
        return SystemTime::now() + self.offset();
        #[cfg(not(test))]
        SystemTime::now()
    }

    #[cfg(test)]
    fn offset(&self) -> Duration {
        Duration::from_nanos(self.offset_nanos.load(Ordering::Relaxed))
    }

    /// Move the clock to `d` after the real time.
    #[cfg(test)]
    pub(crate) fn set(&self, d: Duration) {
        self.offset_nanos.store(d.as_nanos() as u64, Ordering::Relaxed);
    }
}

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
    /// The response answers its question (`answersQuestion`).
    answering: bool,
    /// `serve_stale_policy prefer_positive`: the answer this success-cache
    /// entry replaced when the new response doesn't answer the question.
    last_known_good: Option<Arc<Item>>,
    orig_ttl: u32,
    stored: Instant,
    freq: Mutex<(Instant, u32)>,
    /// A refresh (prefetch, stale refresh or verify) is in flight.
    refreshing: AtomicBool,
    /// After a failed stale refresh with a failure recheck: no new refresh
    /// before `stored` + this many nanoseconds (0: none).
    retry_after: AtomicU64,
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
            answering: answers_question(m),
            last_known_good: None,
            orig_ttl: d.as_secs() as u32,
            stored: now,
            freq: Mutex::new((now, 0)),
            refreshing: AtomicBool::new(false),
            retry_after: AtomicU64::new(0),
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

    /// `answeringItem`: this item or its last known good answer, if one of
    /// them answers the request's question.
    fn answering_item(self: &Arc<Self>, req: &Request) -> Option<Arc<Item>> {
        if self.answering && self.matches(req) {
            return Some(self.clone());
        }
        self.last_known_good
            .as_ref()
            .filter(|l| l.answering && l.matches(req))
            .cloned()
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

    /// `beginRefresh`: claim the one refresh slot of this item, unless a
    /// failure recheck interval is running.
    fn begin_refresh(&self, now: Instant, recheck: Duration) -> bool {
        if !recheck.is_zero() {
            let r = self.retry_after.load(Ordering::Acquire);
            if r != 0 && now < self.stored + Duration::from_nanos(r) {
                return false;
            }
        }
        self.refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// `endRefresh`: release the slot; a failed refresh with a failure
    /// recheck holds off the next one for `recheck`.
    fn end_refresh(&self, now: Instant, recheck: Duration, refreshed: bool) {
        let r = if !recheck.is_zero() && !refreshed {
            ((now + recheck).saturating_duration_since(self.stored).as_nanos() as u64).max(1)
        } else {
            0
        };
        self.retry_after.store(r, Ordering::Release);
        self.refreshing.store(false, Ordering::Release);
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

fn cache_response_type(m: &Message, now: SystemTime) -> ResponseType {
    let t = typify(m, now);
    if t == ResponseType::NoError && has_soa(m) && is_nodata(m) {
        ResponseType::NoData
    } else {
        t
    }
}

/// `usableAnswer`: a complete positive response that answers its question.
fn usable_answer(m: &Message, now: SystemTime) -> bool {
    !m.metadata.truncation && cache_response_type(m, now) == ResponseType::NoError && answers_question(m)
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

fn request_key(req: &Request) -> u64 {
    hash(
        &req.name(),
        req.qtype(),
        req.qclass(),
        req.do_bit(),
        req.msg.metadata.checking_disabled,
    )
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
    /// `serve_stale DURATION` (zero: off).
    stale_up_to: Duration,
    /// `serve_stale ... verify`.
    verify_stale: bool,
    /// `serve_stale ... verify VERIFY_TIMEOUT` (zero: wait for the upstream).
    verify_stale_timeout: Duration,
    /// `serve_stale ... RESPONSE_TTL` (zero: stale answers have TTL 0).
    stale_ttl: u32,
    /// `serve_stale ... FAILURE_RECHECK`.
    stale_recheck: Duration,
    /// `serve_stale_policy prefer_positive`.
    prefer_positive: bool,
    pexcept: Vec<String>,
    nexcept: Vec<String>,
    keepttl: bool,
    clock: Clock,
}

impl CacheCore {
    /// The defaults of Go's `New()`, with stores of `pcap` and `ncap` entries.
    fn new(pcap: usize, ncap: usize) -> Self {
        Self {
            zones: vec![".".into()],
            zones_label: ".".into(),
            pcache: Store::new(pcap),
            pttl: MAXIMUM_DEFAULT_TTL,
            minpttl: MINIMAL_DEFAULT_TTL,
            ncache: Store::new(ncap),
            nttl: MAXIMUM_DEFAULT_TTL / 2,
            minnttl: MINIMAL_DEFAULT_TTL,
            failttl: MINIMAL_DEFAULT_TTL,
            prefetch: 0,
            prefetch_window: Duration::from_secs(60),
            percentage: 10,
            stale_up_to: Duration::ZERO,
            verify_stale: false,
            verify_stale_timeout: Duration::ZERO,
            stale_ttl: 0,
            stale_recheck: Duration::ZERO,
            prefer_positive: false,
            pexcept: Vec::new(),
            nexcept: Vec::new(),
            keepttl: false,
            clock: Clock::default(),
        }
    }

    /// Fresh, or expired for less than the `serve_stale` duration.
    fn within_stale(&self, i: &Item, now: Instant) -> bool {
        let ttl = i.ttl(now);
        ttl > 0 || (!self.stale_up_to.is_zero() && -ttl < self.stale_up_to.as_secs() as i64)
    }

    fn usable(&self, i: &Item, req: &Request, now: Instant) -> bool {
        i.matches(req) && self.within_stale(i, now)
    }

    /// `getIfNotStale`: a usable item from the denial or success cache.
    fn get(&self, now: Instant, req: &Request, server: &str, view: &str) -> Option<Arc<Item>> {
        let k = request_key(req);
        let z = self.zones_label.as_str();
        pm::CACHE_REQUESTS.with_label_values(&[server, z, view]).inc();
        if self.prefer_positive
            && !self.stale_up_to.is_zero()
            && let Some(i) = self.pcache.get(k)
            && let Some(i) = i.answering_item(req)
            && self.within_stale(&i, now)
        {
            pm::CACHE_HITS.with_label_values(&[server, "success", z, view]).inc();
            return Some(i);
        }
        if let Some(i) = self.ncache.get(k)
            && self.usable(&i, req, now)
        {
            // a cached SERVFAIL loses to a usable positive answer
            if i.rcode == ResponseCode::ServFail
                && let Some(p) = self.pcache.get(k)
                && self.usable(&p, req, now)
            {
                pm::CACHE_HITS.with_label_values(&[server, "success", z, view]).inc();
                return Some(p);
            }
            pm::CACHE_HITS.with_label_values(&[server, "denial", z, view]).inc();
            return Some(i);
        }
        if let Some(i) = self.pcache.get(k)
            && self.usable(&i, req, now)
        {
            pm::CACHE_HITS.with_label_values(&[server, "success", z, view]).inc();
            return Some(i);
        }
        pm::CACHE_MISSES.with_label_values(&[server, z, view]).inc();
        None
    }

    /// `exists`: whatever is cached for the request, expired or not.
    fn exists(&self, req: &Request) -> Option<Arc<Item>> {
        let k = request_key(req);
        self.ncache.get(k).or_else(|| self.pcache.get(k))
    }

    fn should_prefetch(&self, i: &Item, now: Instant) -> bool {
        if self.prefetch == 0 {
            return false;
        }
        i.update_freq(self.prefetch_window, now);
        let threshold = ((self.percentage as f64 / 100.0) * i.orig_ttl as f64).ceil() as i64;
        i.hits() >= self.prefetch && i.ttl(now) <= threshold
    }

    /// Store `m` for `key`, like `ResponseWriter.set`; returns the new item.
    fn set(&self, w: &CacheWriter<'_>, m: &Message, key: u64, t: ResponseType, d: Duration) -> Option<Arc<Item>> {
        let item = self.store(w, m, key, t, d);
        let z = self.zones_label.as_str();
        pm::CACHE_ENTRIES
            .with_label_values(&[w.server, "success", z, w.view])
            .set(self.pcache.len() as f64);
        pm::CACHE_ENTRIES
            .with_label_values(&[w.server, "denial", z, w.view])
            .set(self.ncache.len() as f64);
        item
    }

    fn store(&self, w: &CacheWriter<'_>, m: &Message, key: u64, t: ResponseType, d: Duration) -> Option<Arc<Item>> {
        let (server, view) = (w.server, w.view);
        let z = self.zones_label.as_str();
        let q = m.queries.first()?;
        let qname = q.name().to_lowercase().to_ascii();
        let now = self.clock.now();
        match t {
            ResponseType::NoError | ResponseType::Delegation => {
                if self.pexcept.iter().any(|z| is_subdomain(z, &qname)) {
                    return None;
                }
                let mut item = Item::new(m, now, d);
                if self.prefer_positive
                    && !item.answering
                    && let Some(previous) = self.pcache.get(key)
                {
                    // keep the last answer when the refresh doesn't answer
                    item.last_known_good = previous.answering_item(w.req);
                }
                let answering = item.answering;
                let item = Arc::new(item);
                if self.pcache.add(key, item.clone()) {
                    pm::CACHE_EVICTIONS
                        .with_label_values(&[server, "success", z, view])
                        .inc();
                }
                // a positive refresh is the newest state for the key; under
                // prefer_positive only one that answers the question
                if (!self.prefer_positive && w.prefetch) || (self.prefer_positive && answering) {
                    self.ncache.remove(key);
                }
                Some(item)
            }
            ResponseType::NameError | ResponseType::NoData | ResponseType::ServerError => {
                if self.nexcept.iter().any(|z| is_subdomain(z, &qname)) {
                    return None;
                }
                let item = Arc::new(Item::new(m, now, d));
                if self.ncache.add(key, item.clone()) {
                    pm::CACHE_EVICTIONS
                        .with_label_values(&[server, "denial", z, view])
                        .inc();
                }
                Some(item)
            }
            _ => None,
        }
    }
}

/// Caches what passes through it, like the Go `cache.ResponseWriter`.
struct CacheWriter<'a> {
    inner: Option<&'a mut dyn ResponseWriter>,
    server: &'a str,
    view: &'a str,
    core: &'a CacheCore,
    req: &'a Request,
    do_bit: bool,
    cd: bool,
    ad: bool,
    /// Store only; don't write to the client.
    prefetch: bool,
    /// Only take responses that refresh a stale entry
    /// (`verifyStaleResponseWriter`).
    verify: bool,
    /// The last response written (after TTL adjustment).
    last: Option<Message>,
    /// The cache item the last response created, if it was cached.
    last_item: Option<Arc<Item>>,
    /// A verify-mode refresh succeeded.
    refreshed: bool,
}

impl<'a> CacheWriter<'a> {
    fn new(core: &'a CacheCore, req: &'a Request, server: &'a str, view: &'a str) -> Self {
        Self {
            inner: None,
            server,
            view,
            core,
            req,
            do_bit: req.do_bit(),
            cd: req.msg.metadata.checking_disabled,
            ad: req.msg.metadata.authentic_data,
            prefetch: false,
            verify: false,
            last: None,
            last_item: None,
            refreshed: false,
        }
    }

    /// `ResponseWriter.WriteMsg`: cache `res` and pass it on.
    async fn cache_and_write(&mut self, mut res: Message) -> std::io::Result<()> {
        self.last_item = None;
        let c = self.core;
        let t = cache_response_type(&res, c.clock.wall());
        let key = cache_key(&self.req.name(), &res, t, self.do_bit, self.cd);
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
                self.last_item = c.set(self, &res, k, t, duration);
            } else {
                pm::CACHE_DROPS
                    .with_label_values(&[self.server, &c.zones_label, self.view])
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

#[async_trait]
impl ResponseWriter for CacheWriter<'_> {
    async fn write_msg(&mut self, res: Message) -> std::io::Result<()> {
        if !self.verify {
            return self.cache_and_write(res).await;
        }
        // `verifyStaleResponseWriter`: only matching, complete responses
        // that refresh the data (RFC 8767 section 4) replace a stale entry
        self.refreshed = false;
        self.last = None;
        self.last_item = None;
        if res.metadata.truncation || !matches_question(self.req, &res) {
            return Ok(());
        }
        let now = self.core.clock.wall();
        if self.core.prefer_positive {
            if usable_answer(&res, now) {
                self.refreshed = true;
                return self.cache_and_write(res).await;
            }
            // cached, but the stale positive answer is what the client gets
            let prefetch = std::mem::replace(&mut self.prefetch, true);
            let r = self.cache_and_write(res).await;
            self.prefetch = prefetch;
            return r;
        }
        let rc = res.metadata.response_code;
        if matches!(
            typify(&res, now),
            ResponseType::OtherError | ResponseType::Meta | ResponseType::Update
        ) || (rc != ResponseCode::NoError && rc != ResponseCode::NXDomain)
        {
            return Ok(());
        }
        self.refreshed = true;
        self.cache_and_write(res).await
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

/// `serve_stale`'s settings.
#[derive(Debug, Default, PartialEq)]
struct ServeStale {
    up_to: Duration,
    verify: bool,
    verify_timeout: Duration,
    ttl: u32,
    recheck: Duration,
}

/// Parse `serve_stale`'s arguments, like `cacheParse`.
fn parse_serve_stale(c: &Controller<'_>, a: &[String]) -> Result<ServeStale, SetupError> {
    let err = |m: String| SetupError::new("cache", m);
    let negative = |e: String, msg: &str| {
        if e.contains("negative") {
            err(msg.into())
        } else {
            err(e)
        }
    };
    if a.len() > 5 {
        return Err(c.arg_err());
    }
    let mut s = ServeStale {
        up_to: Duration::from_secs(3600),
        ..Default::default()
    };
    if let Some(d) = a.first() {
        s.up_to = parse_duration(d).map_err(|e| negative(e, "invalid negative duration for serve_stale"))?;
    }
    if let Some(mode) = a.get(1) {
        let mode = mode.to_ascii_lowercase();
        if mode != "immediate" && mode != "verify" {
            return Err(err(format!("invalid value for serve_stale refresh mode: {mode}")));
        }
        s.verify = mode == "verify";
    }
    let ttl = |v: &str| -> Result<u32, SetupError> {
        let d = parse_duration(v).map_err(|e| {
            if e.contains("negative") {
                err("invalid negative response TTL for serve_stale".into())
            } else {
                err(format!("invalid serve_stale response TTL: {e}"))
            }
        })?;
        if d.subsec_nanos() != 0 {
            return Err(err("serve_stale response TTL must be a whole number of seconds".into()));
        }
        u32::try_from(d.as_secs()).map_err(|_| err("serve_stale response TTL exceeds the DNS TTL range".into()))
    };
    let recheck = |v: &str| -> Result<Duration, SetupError> {
        let d = parse_duration(v).map_err(|e| {
            if e.contains("negative") {
                err("invalid negative failure recheck for serve_stale".into())
            } else {
                err(format!("invalid serve_stale failure recheck: {e}"))
            }
        })?;
        if d > Duration::from_secs(300) {
            return Err(err("serve_stale failure recheck cannot exceed 5 minutes".into()));
        }
        Ok(d)
    };
    // verify: VERIFY_TIMEOUT RESPONSE_TTL FAILURE_RECHECK
    // immediate: RESPONSE_TTL FAILURE_RECHECK
    let mut rest = a.iter().skip(2);
    if s.verify {
        if let Some(t) = rest.next() {
            s.verify_timeout = parse_duration(t).map_err(|e| {
                if e.contains("negative") {
                    err("invalid negative timeout for serve_stale verify".into())
                } else {
                    err(format!("invalid serve_stale verify timeout: {e}"))
                }
            })?;
        }
    } else if a.len() > 4 {
        return Err(c.arg_err());
    }
    if let Some(t) = rest.next() {
        s.ttl = ttl(t)?;
    }
    if let Some(r) = rest.next() {
        s.recheck = recheck(r)?;
    }
    Ok(s)
}

/// `cacheParse`.
fn parse(c: &mut Controller<'_>) -> Result<CacheCore, SetupError> {
    let err = |m: String| SetupError::new("cache", m);
    let num = |s: &str| {
        s.parse::<i64>()
            .map_err(|e| err(format!("strconv.Atoi: parsing {s:?}: {e}")))
    };
    let mut core = CacheCore::new(DEFAULT_CAP, DEFAULT_CAP);
    let (mut pcap, mut ncap) = (DEFAULT_CAP, DEFAULT_CAP);
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
            core.pttl = Duration::from_secs(ttl as u64);
            core.nttl = core.pttl;
            args.remove(0);
        }
        origins = zones::origins_from_args_or_server_block(&args, &server_keys);
        let mut serve_stale = false;
        let mut policy = false;

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
                        (core.pttl, core.minpttl)
                    } else {
                        (core.nttl, core.minnttl)
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
                        (pcap, core.pttl, core.minpttl) = (cap, ttl, min);
                    } else {
                        (ncap, core.nttl, core.minnttl) = (cap, ttl, min);
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
                    core.prefetch = n as u32;
                    if let Some(d) = a.get(1) {
                        core.prefetch_window = parse_duration(d).map_err(err)?;
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
                        core.percentage = n as u32;
                    }
                }
                "serve_stale" => {
                    serve_stale = true;
                    let a = c.remaining_args();
                    let s = parse_serve_stale(c, &a)?;
                    core.stale_up_to = s.up_to;
                    core.verify_stale = s.verify;
                    core.verify_stale_timeout = s.verify_timeout;
                    core.stale_ttl = s.ttl;
                    core.stale_recheck = s.recheck;
                }
                "serve_stale_policy" => {
                    if policy {
                        return Err(err("serve_stale_policy can only be specified once".into()));
                    }
                    policy = true;
                    let a = c.remaining_args();
                    if a.len() != 1 {
                        return Err(c.arg_err());
                    }
                    if !a[0].eq_ignore_ascii_case("prefer_positive") {
                        return Err(err(format!("invalid serve_stale_policy: {}", a[0])));
                    }
                    core.prefer_positive = true;
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
                    core.failttl = d;
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
                        "denial" => core.nexcept = zs,
                        "success" => core.pexcept = zs,
                        _ => return Err(err("cache type for disable must be \"success\" or \"denial\"".into())),
                    }
                }
                "keepttl" => {
                    if !c.remaining_args().is_empty() {
                        return Err(c.arg_err());
                    }
                    core.keepttl = true;
                }
                _ => return Err(c.arg_err()),
            }
        }
        if policy && !serve_stale {
            return Err(err("serve_stale_policy requires serve_stale".into()));
        }
    }

    core.zones_label = origins.join(",");
    core.zones = origins;
    core.pcache = Store::new(pcap);
    core.ncache = Store::new(ncap);
    Ok(core)
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "cache"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let core = Arc::new(parse(c)?);
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
    /// Refresh `item` in the background, like `tryPrefetch`: at most one
    /// refresh per item, and none during a failure recheck of a stale one.
    fn try_prefetch(&self, ctx: &Context, req: &Request, item: &Arc<Item>, stale: bool) {
        let core = &self.core;
        let recheck = if stale { core.stale_recheck } else { Duration::ZERO };
        if !item.begin_refresh(core.clock.now(), recheck) {
            return;
        }
        let Some(next) = self.next.clone() else {
            item.end_refresh(core.clock.now(), recheck, false);
            return;
        };
        let (core, item, mut ctx, mut req) = (core.clone(), item.clone(), ctx.clone(), req.clone());
        req.msg.metadata.authentic_data = true;
        // no client connection: like Go's prefetch address, TCP, so the
        // upstream's answer isn't truncated
        req.protocol = Protocol::Tcp;
        let now = core.clock.now();
        tokio::spawn(async move {
            let server = ctx.server.clone();
            let view = ctx.view.clone().unwrap_or_default();
            pm::CACHE_PREFETCHES
                .with_label_values(&[&*server, &core.zones_label, &view])
                .inc();
            let mut w = CacheWriter::new(&core, &req, &server, &view);
            w.ad = true;
            w.prefetch = true;
            w.verify = stale;
            let _ = next.serve_dns(&mut ctx, &mut w, &req).await;
            let refreshed = !stale || w.refreshed;
            if refreshed && let Some(i1) = core.exists(&req) {
                // keep the hit count across the refresh
                *i1.freq.lock().unwrap() = (now, item.hits());
            }
            item.end_refresh(core.clock.now(), recheck, refreshed);
        });
    }

    /// `verifyWithTimeout`: verify a stale entry in the background and wait
    /// up to the verify timeout for it. Returns the result if the client
    /// got the refreshed answer; otherwise the caller serves the stale one
    /// and the verify goes on, refreshing the cache when it succeeds.
    async fn verify_with_timeout(
        &self,
        ctx: &Context,
        req: &Request,
        refresh: &Request,
        item: &Arc<Item>,
        w: &mut dyn ResponseWriter,
        ad: bool,
    ) -> Option<HandlerResult> {
        let core = self.core.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let (core, item, next, mut ctx, req) = (
                core.clone(),
                item.clone(),
                self.next.clone(),
                ctx.clone(),
                refresh.clone(),
            );
            tokio::spawn(async move {
                let server = ctx.server.clone();
                let view = ctx.view.clone().unwrap_or_default();
                let mut cw = CacheWriter::new(&core, &req, &server, &view);
                cw.ad = ad;
                cw.prefetch = true;
                cw.verify = true;
                let _ = next_or_failure("cache", &next, &mut ctx, &mut cw, &req).await;
                item.end_refresh(core.clock.now(), core.stale_recheck, cw.refreshed);
                let _ = tx.send(cw.refreshed.then(|| (cw.last_item.take(), cw.last.take())));
            });
        }
        let Ok(Ok(Some((fresh, last)))) = tokio::time::timeout(core.verify_stale_timeout, rx).await else {
            return None;
        };
        let msg = match (fresh, last) {
            (Some(i), _) => {
                let ttl = if core.keepttl {
                    i.orig_ttl
                } else {
                    i.ttl(core.clock.now()).max(0) as u32
                };
                i.to_msg(req, ttl, req.do_bit(), ad)
            }
            (None, Some(mut m)) => {
                m.metadata.id = req.msg.metadata.id;
                m
            }
            (None, None) => return None,
        };
        Some(match w.write_msg(msg).await {
            Ok(()) => Ok(ResponseCode::NoError),
            Err(e) => Err(PluginError::servfail("cache", e.to_string())),
        })
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
        let ad = req.msg.metadata.authentic_data;
        let now = core.clock.now();

        // the request sent downstream asks for the AD bit
        let mut refresh = req.clone();
        refresh.msg.metadata.authentic_data = true;

        let server = ctx.server.clone();
        let view = ctx.view.clone().unwrap_or_default();
        let Some(item) = core.get(now, req, &server, &view) else {
            let mut cw = CacheWriter::new(core, &refresh, &server, &view);
            cw.inner = Some(w);
            cw.ad = ad;
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
                let recheck = core.stale_recheck;
                // with a failure recheck or a verify timeout, concurrent
                // requests share one verify and get the stale answer
                let track = !recheck.is_zero() || !core.verify_stale_timeout.is_zero();
                if !track || item.begin_refresh(now, recheck) {
                    if core.verify_stale_timeout.is_zero() {
                        let mut cw = CacheWriter::new(core, &refresh, &server, &view);
                        cw.inner = Some(&mut *w);
                        cw.ad = ad;
                        cw.verify = true;
                        let res = next_or_failure("cache", &self.next, ctx, &mut cw, &refresh).await;
                        let refreshed = cw.refreshed;
                        if track {
                            item.end_refresh(core.clock.now(), recheck, refreshed);
                        }
                        if refreshed {
                            return res;
                        }
                    } else if let Some(res) = self.verify_with_timeout(ctx, req, &refresh, &item, w, ad).await {
                        return res;
                    }
                }
            } else {
                self.try_prefetch(ctx, req, &item, true);
            }
            pm::CACHE_SERVED_STALE
                .with_label_values(&[&*server, &core.zones_label, &view])
                .inc();
        } else if core.should_prefetch(&item, now) {
            self.try_prefetch(ctx, req, &item, false);
        }

        let out_ttl = if stale && core.stale_ttl > 0 {
            core.stale_ttl
        } else if core.keepttl {
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
