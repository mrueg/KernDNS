//! `loadbalance`: shuffles A, AAAA and MX records in responses. Port of
//! `plugin/loadbalance`.
//!
//! ```text
//! loadbalance [round_robin | weighted WEIGHTFILE] {
//!     reload DURATION      # weighted only, default 30s
//!     prefer CIDR...
//! }
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use kerndns_core::duration::parse_duration;
use kerndns_core::proto::op::{Message, ResponseCode};
use kerndns_core::proto::rr::{RData, Record, RecordType};
use kerndns_core::random::rand_below;
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};

// ------------------------------------------------------------ round robin

/// `roundRobinShuffle`: CoreDNS's (biased) shuffle, kept as is.
fn shuffle(records: &mut [Record]) {
    match records.len() {
        0 | 1 => {}
        2 => {
            if rand_below(2) == 0 {
                records.swap(0, 1);
            }
        }
        l => {
            for j in 0..l {
                let p = j + rand_below(l - j);
                records.swap(j, p);
            }
        }
    }
}

/// Split into (CNAME, A/AAAA, MX, rest), keeping order within each.
fn split(records: Vec<Record>) -> (Vec<Record>, Vec<Record>, Vec<Record>, Vec<Record>) {
    let (mut cname, mut address, mut mx, mut rest) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for r in records {
        match r.record_type() {
            RecordType::CNAME => cname.push(r),
            RecordType::A | RecordType::AAAA => address.push(r),
            RecordType::MX => mx.push(r),
            _ => rest.push(r),
        }
    }
    (cname, address, mx, rest)
}

/// `roundRobin`.
fn round_robin(records: Vec<Record>) -> Vec<Record> {
    if records.len() <= 1 {
        return records;
    }
    let t = records[0].record_type();
    if matches!(t, RecordType::A | RecordType::AAAA) && records[1..].iter().all(|r| r.record_type() == t) {
        let mut out = records;
        shuffle(&mut out);
        return out;
    }
    let (mut out, mut address, mut mx, rest) = split(records);
    shuffle(&mut address);
    shuffle(&mut mx);
    out.extend(rest);
    out.extend(address);
    out.extend(mx);
    out
}

// --------------------------------------------------------------- weighted

#[derive(Debug, Default, PartialEq)]
struct Weights(HashMap<String, Vec<(IpAddr, u8)>>);

/// `parseWeights`.
fn parse_weights(text: &str, file: &str) -> Result<Weights, String> {
    let mut domains: HashMap<String, Vec<(IpAddr, u8)>> = HashMap::new();
    let mut dname = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            [d] => {
                if d.parse::<IpAddr>().is_ok() {
                    return Err(format!(
                        "wrong domain name:\"{d}\" in weight file {file}. (Maybe a missing weight value?)"
                    ));
                }
                dname = d.to_string();
                if !dname.ends_with('.') {
                    dname.push('.');
                }
                domains.entry(dname.clone()).or_default();
            }
            [ip, w] => {
                let ip: IpAddr = ip
                    .parse()
                    .map_err(|_| format!("wrong IP address:\"{ip}\" in weight file {file}"))?;
                let w: u8 = match w.parse() {
                    Ok(v) if v > 0 => v,
                    _ => return Err(format!("wrong weight value:\"{w}\" in weight file {file}")),
                };
                if dname.is_empty() {
                    return Err(format!("missing domain name in weight file {file}"));
                }
                domains.entry(dname.clone()).or_default().push((ip, w));
            }
            _ => return Err(format!("could not parse weight line:\"{line}\" in weight file {file}")),
        }
    }
    Ok(Weights(domains))
}

fn ip_of(r: &Record) -> Option<IpAddr> {
    match &r.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    }
}

struct Weighted {
    file: PathBuf,
    reload: Duration,
    weights: RwLock<Weights>,
    /// The file contents last loaded (CoreDNS compares an MD5 sum).
    last: Mutex<Option<Vec<u8>>>,
}

impl Weighted {
    /// `updateWeights`: `Ok(false)` if the file couldn't be opened.
    fn update(&self) -> Result<bool, String> {
        let Ok(data) = std::fs::read(&self.file) else {
            return Ok(false);
        };
        let mut last = self.last.lock().unwrap();
        if last.as_deref() == Some(&data[..]) {
            return Ok(true);
        }
        let w = parse_weights(&String::from_utf8_lossy(&data), &self.file.display().to_string())?;
        *last = Some(data);
        *self.weights.write().unwrap() = w;
        kerndns_core::info!(
            plugin = "loadbalance",
            "Successfully reloaded weight file {}",
            self.file.display()
        );
        Ok(true)
    }

    /// `topAddressIndex`: pick the first address by weight.
    fn top(&self, address: &[Record]) -> Option<usize> {
        let ws = self.weights.read().unwrap();
        let mut weighted: Vec<(usize, u8)> = address
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let owner = kerndns_core::request::lower_fqdn(&r.name);
                let w = ip_of(r)
                    .and_then(|ip| ws.0.get(&owner).and_then(|l| l.iter().find(|(a, _)| *a == ip)))
                    .map_or(1, |(_, w)| *w);
                (i, w)
            })
            .collect();
        let sum: usize = weighted.iter().map(|(_, w)| usize::from(*w)).sum();
        weighted.sort_by_key(|w| std::cmp::Reverse(w.1));
        let v = rand_below(sum);
        let mut acc = 0;
        for (i, w) in weighted {
            acc += usize::from(w);
            if v < acc {
                return Some(i);
            }
        }
        None
    }

    /// `weightedRoundRobin`.
    fn apply(&self, records: Vec<Record>) -> Vec<Record> {
        if !records
            .iter()
            .any(|r| matches!(r.record_type(), RecordType::A | RecordType::AAAA))
        {
            return records;
        }
        let (mut out, mut address, mx, rest) = split(records);
        if let Some(i) = self.top(&address) {
            address.swap(0, i);
        }
        out.extend(rest);
        out.extend(address);
        out.extend(mx);
        out
    }
}

// --------------------------------------------------------------- preferred

#[derive(Debug, Clone, Copy, PartialEq)]
struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    fn parse(s: &str) -> Option<Cidr> {
        let (ip, bits) = s.split_once('/')?;
        let ip: IpAddr = ip.parse().ok()?;
        let bits: u8 = bits.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        (bits <= max).then(|| Cidr {
            net: mask(ip, bits),
            bits,
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.net.is_ipv4() && mask(ip, self.bits) == self.net
    }
}

fn mask(ip: IpAddr, bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let m = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(bits))
            };
            IpAddr::V4((u32::from(a) & m).into())
        }
        IpAddr::V6(a) => {
            let m = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(bits))
            };
            IpAddr::V6((u128::from(a) & m).into())
        }
    }
}

/// `reorderRecords`: addresses in a preferred subnet first, in subnet order.
fn prefer(records: Vec<Record>, subnets: &[Cidr]) -> Vec<Record> {
    let (mut out, address, mx, rest) = split(records);
    let mut taken = vec![false; address.len()];
    let mut sorted = Vec::with_capacity(address.len());
    for s in subnets {
        for (i, r) in address.iter().enumerate() {
            if !taken[i] && ip_of(r).is_some_and(|ip| s.contains(ip)) {
                taken[i] = true;
                sorted.push(r.clone());
            }
        }
    }
    sorted.extend(address.iter().zip(&taken).filter(|(_, t)| !**t).map(|(r, _)| r.clone()));
    out.extend(sorted);
    out.extend(mx);
    out.extend(rest);
    out
}

// ------------------------------------------------------------------ plugin

enum Policy {
    RoundRobin,
    Weighted(Arc<Weighted>),
}

struct Config {
    policy: Policy,
    prefer: Vec<Cidr>,
}

impl Config {
    fn shuffle(&self, mut m: Message) -> Message {
        match &self.policy {
            Policy::RoundRobin => {
                m.answers = round_robin(std::mem::take(&mut m.answers));
                m.authorities = round_robin(std::mem::take(&mut m.authorities));
                m.additionals = round_robin(std::mem::take(&mut m.additionals));
            }
            Policy::Weighted(w) => {
                if matches!(
                    m.queries[0].query_type(),
                    RecordType::A | RecordType::AAAA | RecordType::SRV
                ) {
                    m.answers = w.apply(std::mem::take(&mut m.answers));
                    m.additionals = w.apply(std::mem::take(&mut m.additionals));
                }
            }
        }
        if !self.prefer.is_empty() {
            m.answers = prefer(std::mem::take(&mut m.answers), &self.prefer);
            m.additionals = prefer(std::mem::take(&mut m.additionals), &self.prefer);
        }
        m
    }
}

pub struct LoadBalance {
    next: Next,
    cfg: Arc<Config>,
}

struct LbWriter<'a> {
    inner: &'a mut dyn ResponseWriter,
    cfg: &'a Config,
}

#[async_trait]
impl ResponseWriter for LbWriter<'_> {
    async fn write_msg(&mut self, m: Message) -> std::io::Result<()> {
        let skip = m.metadata.response_code != ResponseCode::NoError
            || m.queries
                .first()
                .is_none_or(|q| matches!(q.query_type(), RecordType::AXFR | RecordType::IXFR));
        let m = if skip { m } else { self.cfg.shuffle(m) };
        self.inner.write_msg(m).await
    }
}

#[async_trait]
impl Handler for LoadBalance {
    fn name(&self) -> &'static str {
        "loadbalance"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let mut lw = LbWriter {
            inner: w,
            cfg: &self.cfg,
        };
        next_or_failure("loadbalance", &self.next, ctx, &mut lw, req).await
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "loadbalance"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let err = |m: String| SetupError::new("loadbalance", m);
        let mut cfg = Config {
            policy: Policy::RoundRobin,
            prefer: Vec::new(),
        };
        while c.next() {
            let args = c.remaining_args();
            match args.first().map(String::as_str) {
                None | Some("round_robin") => {
                    if args.len() > 1 {
                        return Err(c.errf(format!("unknown property for {}", args[0])));
                    }
                    cfg.policy = Policy::RoundRobin;
                }
                Some("weighted") => {
                    if args.len() < 2 {
                        return Err(c.errf("missing weight file argument"));
                    }
                    if args.len() > 2 {
                        return Err(c.errf("unexpected argument(s)"));
                    }
                    let mut file = PathBuf::from(&args[1]);
                    if file.is_relative()
                        && let Some(root) = &c.config.root
                    {
                        file = root.join(file);
                    }
                    cfg.policy = Policy::Weighted(Arc::new(Weighted {
                        file,
                        reload: Duration::from_secs(30),
                        weights: RwLock::default(),
                        last: Mutex::default(),
                    }));
                }
                Some(p) => return Err(err(format!("unknown policy: {p}"))),
            }
            while c.next_block() {
                match c.val() {
                    "reload" if matches!(cfg.policy, Policy::Weighted(_)) => {
                        let t = c.remaining_args();
                        if t.is_empty() {
                            return Err(c.errf("reload duration value is missing"));
                        }
                        if t.len() > 1 {
                            return Err(c.errf("unexpected argument"));
                        }
                        let d =
                            parse_duration(&t[0]).map_err(|_| c.errf(format!("invalid reload duration '{}'", t[0])))?;
                        if let Policy::Weighted(w) = &mut cfg.policy {
                            Arc::get_mut(w).expect("not shared yet").reload = d;
                        }
                    }
                    "prefer" => {
                        for a in c.remaining_args() {
                            let Some(s) = Cidr::parse(&a) else {
                                return Err(c.errf(format!("invalid CIDR {a:?}: invalid CIDR address: {a}")));
                            };
                            cfg.prefer.push(s);
                        }
                    }
                    other => {
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
        }

        if let Policy::Weighted(w) = &cfg.policy {
            let (w, stop) = (w.clone(), Arc::new(Mutex::new(None::<tokio::task::AbortHandle>)));
            let stop2 = stop.clone();
            c.on_startup(move || {
                match w.update() {
                    Ok(true) => {}
                    Ok(false) if !w.reload.is_zero() => kerndns_core::warning!(
                        plugin = "loadbalance",
                        "Failed to open weight file:weight file open error. Will try again in {}",
                        kerndns_core::duration::format_duration(w.reload)
                    ),
                    Ok(false) => return Err("plugin/loadbalance: weight file open error".to_string()),
                    Err(e) => return Err(format!("plugin/loadbalance: {e}")),
                }
                if !w.reload.is_zero()
                    && let Ok(h) = tokio::runtime::Handle::try_current()
                {
                    let w = w.clone();
                    let task = h.spawn(async move {
                        let mut t = tokio::time::interval(w.reload);
                        t.tick().await;
                        loop {
                            t.tick().await;
                            if let Err(e) = w.update() {
                                kerndns_core::error!(plugin = "loadbalance", "{e}");
                            }
                        }
                    });
                    *stop2.lock().unwrap() = Some(task.abort_handle());
                }
                Ok(())
            });
            c.on_shutdown(move || {
                if let Some(t) = stop.lock().unwrap().take() {
                    t.abort();
                }
            });
        }
        let cfg = Arc::new(cfg);
        c.add_plugin(move |next| Arc::new(LoadBalance { next, cfg: cfg.clone() }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::rr::Name;
    use kerndns_core::proto::rr::rdata::{A, CNAME, MX};

    fn a(ip: [u8; 4]) -> Record {
        Record::from_rdata(
            Name::from_ascii("x.example.").unwrap(),
            60,
            RData::A(A::from(std::net::Ipv4Addr::from(ip))),
        )
    }

    fn cname() -> Record {
        Record::from_rdata(
            Name::from_ascii("w.example.").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("x.example.").unwrap())),
        )
    }

    fn mx(p: u16) -> Record {
        Record::from_rdata(
            Name::from_ascii("x.example.").unwrap(),
            60,
            RData::MX(MX::new(p, Name::from_ascii("m.example.").unwrap())),
        )
    }

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "loadbalance"));
        assert!(setup_ok(
            &Setup,
            "loadbalance round_robin {\n prefer 10.0.0.0/8 2001:db8::/32\n}"
        ));
        assert!(setup_ok(&Setup, "loadbalance weighted w.txt {\n reload 10s\n}"));
        assert!(setup_err(&Setup, "loadbalance round_robin x").contains("unknown property for round_robin"));
        assert!(setup_err(&Setup, "loadbalance weighted").contains("missing weight file"));
        assert!(setup_err(&Setup, "loadbalance foo").contains("unknown policy: foo"));
        assert!(setup_err(&Setup, "loadbalance {\n prefer 10.0.0.0/33\n}").contains("invalid CIDR"));
        assert!(setup_err(&Setup, "loadbalance {\n reload 10s\n}").contains("unknown property 'reload'"));
    }

    #[test]
    fn keeps_cname_first_and_mixes_addresses() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let out = round_robin(vec![a([1, 1, 1, 1]), cname(), mx(10), a([2, 2, 2, 2]), a([3, 3, 3, 3])]);
            assert_eq!(out[0].record_type(), RecordType::CNAME);
            assert_eq!(out[4].record_type(), RecordType::MX);
            seen.insert(format!("{:?}", out[1..4].iter().map(ip_of).collect::<Vec<_>>()));
        }
        assert!(seen.len() > 1, "addresses are shuffled");
    }

    #[test]
    fn weights() {
        let w = parse_weights("# c\nx.example\n1.1.1.1 100\n2.2.2.2 1\n", "w").unwrap();
        assert_eq!(w.0["x.example."].len(), 2);
        assert!(
            parse_weights("1.1.1.1\n", "w")
                .unwrap_err()
                .contains("missing weight value")
        );
        assert!(
            parse_weights("1.1.1.1 3\n", "w")
                .unwrap_err()
                .contains("missing domain name")
        );
        assert!(
            parse_weights("x.\n1.1.1.1 0\n", "w")
                .unwrap_err()
                .contains("wrong weight value")
        );

        let wr = Weighted {
            file: PathBuf::new(),
            reload: Duration::ZERO,
            weights: RwLock::new(w),
            last: Mutex::default(),
        };
        let mut first = 0;
        for _ in 0..500 {
            let out = wr.apply(vec![a([2, 2, 2, 2]), a([1, 1, 1, 1])]);
            if ip_of(&out[0]) == Some(IpAddr::from([1, 1, 1, 1])) {
                first += 1;
            }
        }
        assert!(first > 450, "weight 100 vs 1: {first}/500");
    }

    #[test]
    fn preferred_subnets_first() {
        let s = [Cidr::parse("10.0.0.0/8").unwrap(), Cidr::parse("192.0.2.0/24").unwrap()];
        let out = prefer(vec![a([1, 1, 1, 1]), a([192, 0, 2, 1]), a([10, 1, 2, 3])], &s);
        let ips: Vec<_> = out.iter().map(|r| ip_of(r).unwrap().to_string()).collect();
        assert_eq!(ips, ["10.1.2.3", "192.0.2.1", "1.1.1.1"]);
    }

    #[tokio::test]
    async fn leaves_errors_and_transfers_alone() {
        let h = LoadBalance {
            next: reply(|r| {
                let mut m = r.reply();
                m.metadata.response_code = ResponseCode::NXDomain;
                m.answers = vec![a([1, 1, 1, 1]), a([2, 2, 2, 2]), a([3, 3, 3, 3])];
                m
            }),
            cfg: Arc::new(Config {
                policy: Policy::RoundRobin,
                prefer: Vec::new(),
            }),
        };
        for _ in 0..20 {
            let (_, w) = serve(&h, &query("x.example.", RecordType::A, "10.0.0.1:53")).await;
            assert_eq!(ip_of(&w.msgs[0].answers[0]), Some(IpAddr::from([1, 1, 1, 1])));
        }
    }
}
