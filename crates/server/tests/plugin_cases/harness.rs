//! Fixtures, servers and CoreDNS's comparison helpers for the upstream
//! plugin table tests.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use kerndns_core::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::sync::Arc;

use kerndns_core::{
    Context, Controller, Handler, HandlerResult, PluginFactory, Protocol, Registry, Request, ResponseWriter,
    SetupError, async_trait,
};
use kerndns_plugins::file::zonefile::new_rr;
use kerndns_server::config::{Options, load};
use kerndns_server::dispatch::Dispatcher;
use serde_json::Value;

pub const LOCAL: &str = "127.0.0.1:53";
/// `test.ResponseWriter`'s remote address.
pub const REMOTE: &str = "10.240.0.1:40212";

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/plugin_cases")
}

/// One extracted table.
pub struct Table {
    pub id: String,
    pub value: Value,
    pub error: Option<String>,
    pub dropped: Option<String>,
}

impl Table {
    /// Rows: the elements of a slice, the entries of a map (sorted by
    /// key), or the value itself.
    pub fn rows(&self) -> Vec<(String, Value)> {
        match &self.value {
            Value::Array(a) => a.iter().enumerate().map(|(i, v)| (i.to_string(), v.clone())).collect(),
            Value::Object(m) if !m.contains_key("Qname") => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            Value::Null => Vec::new(),
            v => vec![("0".into(), v.clone())],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Skip,
    Xfail,
}

/// A plugin's fixture, the expectations for it and the results so far.
pub struct Run {
    pub plugin: String,
    strings: BTreeMap<String, String>,
    tables: Vec<Table>,
    used: HashSet<String>,
    expect: BTreeMap<String, (Status, String)>,
    pub pass: usize,
    pub xfail: usize,
    failures: Vec<String>,
    checked: HashSet<String>,
    pub skipped_rows: usize,
}

impl Run {
    pub fn load(plugin: &str) -> Run {
        let path = dir().join(format!("{plugin}.json"));
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let v: Value = serde_json::from_str(&text).unwrap();
        let strings = v["strings"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let mut tables = Vec::new();
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for t in v["tables"].as_array().unwrap() {
            let base = match t["func"].as_str() {
                Some(f) => format!("{f}/{}", t["name"].as_str().unwrap()),
                None => t["name"].as_str().unwrap().to_string(),
            };
            // the same name twice in one function: name, name@2, ...
            let n = seen.entry(base.clone()).or_default();
            *n += 1;
            let id = if *n == 1 { base } else { format!("{base}@{n}") };
            tables.push(Table {
                id,
                value: t["value"].clone(),
                error: t["error"].as_str().map(str::to_string),
                dropped: t["dropped"].as_str().map(str::to_string),
            });
        }
        let mut expect = BTreeMap::new();
        let exp = std::fs::read_to_string(dir().join("expectations.txt")).unwrap();
        for line in exp.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut f = line.splitn(4, ' ');
            let (st, p, id, why) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap(), f.next());
            if p != plugin {
                continue;
            }
            let st = match st {
                "skip" => Status::Skip,
                "xfail" => Status::Xfail,
                s => panic!("expectations.txt: unknown status {s}"),
            };
            let why = why
                .unwrap_or_else(|| panic!("expectations.txt: {line}: no reason"))
                .to_string();
            expect.insert(id.to_string(), (st, why));
        }
        Run {
            plugin: plugin.to_string(),
            strings,
            tables,
            used: HashSet::new(),
            expect,
            pass: 0,
            xfail: 0,
            failures: Vec::new(),
            checked: HashSet::new(),
            skipped_rows: 0,
        }
    }

    /// A package-level string constant or variable of the Go tests.
    pub fn string(&self, name: &str) -> &str {
        self.strings
            .get(name)
            .unwrap_or_else(|| panic!("{}: no string {name} in the fixture", self.plugin))
    }

    /// The table `id` (`Func/var` or a package-level `var`), marked as run.
    pub fn table(&mut self, id: &str) -> &Table {
        let t = self
            .tables
            .iter()
            .find(|t| t.id == id)
            .unwrap_or_else(|| panic!("{}: no table {id} in the fixture (regenerate it?)", self.plugin));
        if let Some(e) = t.dropped.as_ref().or(t.error.as_ref()) {
            panic!("{}: table {id} was not extracted: {e}", self.plugin);
        }
        self.used.insert(id.to_string());
        t
    }

    /// The rows of table `id`.
    pub fn rows(&mut self, id: &str) -> Vec<(String, Value)> {
        self.table(id).rows()
    }

    /// Record the outcome of one row (`table#row`).
    pub fn check(&mut self, table: &str, row: &str, res: Result<(), String>) {
        let id = format!("{table}#{row}");
        self.checked.insert(id.clone());
        match (res, self.expect.get(&id)) {
            (_, Some((Status::Skip, _))) => self.skipped_rows += 1,
            (Ok(()), Some((Status::Xfail, _))) => self.failures.push(format!(
                "{id}: passes but is listed as xfail (remove it from expectations.txt)"
            )),
            (Ok(()), _) => self.pass += 1,
            (Err(_), Some((Status::Xfail, _))) => self.xfail += 1,
            (Err(e), _) => self.failures.push(format!("{id}: {e}")),
        }
    }

    /// Check that every table was run or is listed with a reason, and that
    /// every row passed or is an expected failure.
    /// Check that every table was run or is listed with a reason, and that
    /// every row passed or is an expected failure.
    pub fn finish(mut self) {
        let mut skipped_tables = 0;
        let mut skipped_rows = 0;
        let mut not_extracted = Vec::new();
        for t in &self.tables {
            let used = self.used.contains(&t.id);
            let listed = matches!(self.expect.get(&t.id), Some((Status::Skip, _)));
            if let Some(why) = t.dropped.as_ref().or(t.error.as_ref()) {
                // couldn't be evaluated outside its test: the reason is in
                // the fixture
                not_extracted.push(format!("{} ({why})", t.id));
                continue;
            }
            match (used, listed) {
                (true, true) => self
                    .failures
                    .push(format!("{}: run but listed as skip in expectations.txt", t.id)),
                (true, false) => {}
                (false, true) => {
                    skipped_tables += 1;
                    skipped_rows += t.rows().len();
                }
                (false, false) => self.failures.push(format!(
                    "{}: not run and not listed in expectations.txt ({} rows)",
                    t.id,
                    t.rows().len()
                )),
            }
        }
        for (id, (st, _)) in &self.expect {
            let ok = if id.contains('#') {
                self.checked.contains(id)
            } else {
                self.tables.iter().any(|t| &t.id == id)
            };
            if !ok {
                self.failures.push(format!(
                    "expectations.txt: {id} ({st:?}) is not in the fixture or not run"
                ));
            }
        }
        eprintln!(
            "plugin_cases {}: {} rows run: {} pass, {} xfail, {} skipped; {} tables ({} rows) skipped; {} tables not extractable{}{}",
            self.plugin,
            self.pass + self.xfail + self.skipped_rows,
            self.pass,
            self.xfail,
            self.skipped_rows,
            skipped_tables,
            skipped_rows,
            not_extracted.len(),
            if not_extracted.is_empty() { "" } else { ":\n  " },
            not_extracted.join("\n  ")
        );
        assert!(
            self.failures.is_empty(),
            "{}: {} problems:\n  {}",
            self.plugin,
            self.failures.len(),
            self.failures.join("\n  ")
        );
    }
}

/// A directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("kerndns-plugin-cases-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    /// Write `content` to `name` and return the absolute path.
    pub fn write(&self, name: &str, content: &str) -> String {
        let p = self.0.join(name);
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Calls of the `nomad` stand-in per tag.
static NEXT_CALLS: std::sync::Mutex<BTreeMap<String, usize>> = std::sync::Mutex::new(BTreeMap::new());

/// How often the `nomad TAG ...` stand-in has been called.
pub fn next_calls(tag: &str) -> usize {
    NEXT_CALLS.lock().unwrap().get(tag).copied().unwrap_or(0)
}

/// The next handlers of the Go tests, registered as directive `nomad`
/// (last in plugin.cfg and not ported, so it always runs after the plugin
/// under test):
///
/// - `nomad TAG rcode NAME`: `test.NextHandler(rcode, nil)`, writes nothing;
/// - `nomad TAG error`: `test.ErrorHandler()`, writes SERVFAIL.
///
/// Each call is counted under TAG ([`next_calls`]).
struct TestNext;

struct TestNextHandler {
    tag: String,
    write: bool,
    rcode: ResponseCode,
}

impl PluginFactory for TestNext {
    fn name(&self) -> &'static str {
        "nomad"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        c.next();
        let args = c.remaining_args();
        let (tag, write, rcode) = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            [tag, "error"] => (tag.to_string(), true, ResponseCode::ServFail),
            [tag, "rcode", rc] => (
                tag.to_string(),
                false,
                match rc {
                    "NOERROR" => ResponseCode::NoError,
                    "NXDOMAIN" => ResponseCode::NXDomain,
                    "SERVFAIL" => ResponseCode::ServFail,
                    "REFUSED" => ResponseCode::Refused,
                    "FORMERR" => ResponseCode::FormErr,
                    "NOTIMP" => ResponseCode::NotImp,
                    _ => return Err(c.arg_err()),
                },
            ),
            _ => return Err(c.arg_err()),
        };
        c.add_plugin(move |_| {
            Arc::new(TestNextHandler {
                tag: tag.clone(),
                write,
                rcode,
            })
        });
        Ok(())
    }
}

#[async_trait]
impl Handler for TestNextHandler {
    fn name(&self) -> &'static str {
        "nomad"
    }

    async fn serve_dns(&self, _: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        *NEXT_CALLS.lock().unwrap().entry(self.tag.clone()).or_default() += 1;
        if self.write {
            let _ = w.write_msg(req.error_reply(self.rcode)).await;
        }
        Ok(self.rcode)
    }
}

pub fn registry() -> Registry {
    let mut r = kerndns_plugins::registry();
    r.register(TestNext);
    r
}

/// A Corefile loaded through KernDNS's normal setup, served in-process by
/// the first listener's dispatcher (the server's routing, the plugin
/// chain, error responses and EDNS echo; no sockets).
pub struct Server {
    d: Dispatcher,
    pub proto: Protocol,
    _dir: Option<TempDir>,
}

impl Server {
    pub async fn new(corefile: &str) -> Server {
        Self::try_new(corefile)
            .await
            .unwrap_or_else(|e| panic!("{e}\n{corefile}"))
    }

    pub async fn try_new(corefile: &str) -> Result<Server, String> {
        let plan = load(corefile, "Corefile", &registry(), &Options::default()).map_err(|e| e.to_string())?;
        for (name, hook) in plan.hooks.startup {
            hook().map_err(|e| format!("plugin/{name}: {e}"))?;
        }
        let l = &plan.listeners[0];
        let local: SocketAddr = LOCAL.parse().unwrap();
        let d = Dispatcher::new("dns://:53".into(), &l.zones, l.class_chaos, local, local);
        Ok(Server {
            d,
            proto: Protocol::Tcp,
            _dir: None,
        })
    }

    /// Keep `dir` alive as long as the server.
    pub fn with_dir(mut self, dir: TempDir) -> Server {
        self._dir = Some(dir);
        self
    }

    /// The response the client gets, if any. TCP by default so that large
    /// answers aren't truncated: CoreDNS's unit tests call the plugin
    /// directly and never truncate.
    pub async fn exchange(&self, m: Message) -> Option<Message> {
        self.exchange_from(m, REMOTE).await
    }

    pub async fn exchange_from(&self, m: Message, remote: &str) -> Option<Message> {
        self.serve_from(m, remote).await.msg
    }

    /// What the chain did, like calling `ServeDNS` on the plugin in Go.
    pub async fn serve(&self, m: Message) -> Served {
        self.serve_from(m, REMOTE).await
    }

    pub async fn serve_from(&self, m: Message, remote: &str) -> Served {
        let req = Request::new(m, LOCAL.parse().unwrap(), remote.parse().unwrap(), self.proto);
        let mut a = self.d.answer(&req).await;
        let (rcode, wrote) = a.chain.unwrap_or((None, false));
        Served {
            msg: a.msgs.pop(),
            rcode,
            wrote,
        }
    }
}

/// One request through the server.
pub struct Served {
    /// What the client gets: the chain's response or the server's error
    /// response.
    pub msg: Option<Message>,
    /// The rcode the chain returned (`None`: routed nowhere or panicked).
    pub rcode: Option<ResponseCode>,
    /// The chain wrote `msg` itself (`rec.Msg != nil` in a Go test).
    pub wrote: bool,
}

impl Served {
    /// `rec.Msg`: the response if a plugin wrote one.
    pub fn written(&self) -> Option<&Message> {
        if self.wrote { self.msg.as_ref() } else { None }
    }

    /// The rcode `ServeDNS` returned, as a number.
    pub fn code(&self) -> Option<u16> {
        self.rcode.map(u16::from)
    }
}

/// A query like `new(dns.Msg).SetQuestion(name, t)`: RD set, id 1.
pub fn question(name: &str, t: u16) -> Message {
    let mut m = Message::new(1, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    let name = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    let mut q = Query::query(Name::from_ascii(&name).unwrap(), RecordType::from(t));
    q.set_query_class(DNSClass::IN);
    m.add_query(q);
    m
}

/// `m.SetEdns0(size, do)`.
pub fn set_edns(m: &mut Message, size: u16, do_bit: bool) {
    let mut e = Edns::new();
    e.set_max_payload(size);
    e.set_dnssec_ok(do_bit);
    m.edns = Some(e);
}

/// A `test.Case`.
#[derive(Debug, Clone)]
pub struct Case {
    pub qname: String,
    pub qtype: u16,
    pub rcode: u16,
    pub do_bit: bool,
    pub cd: bool,
    pub ad: bool,
    pub aa: bool,
    pub tc: bool,
    pub ra: bool,
    pub answer: Vec<Value>,
    pub ns: Vec<Value>,
    pub extra: Vec<Value>,
}

fn rr_list(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

impl Case {
    pub fn from(v: &Value) -> Case {
        Case {
            qname: v["Qname"].as_str().unwrap_or("").to_string(),
            qtype: v["Qtype"].as_u64().unwrap_or(0) as u16,
            rcode: v["Rcode"].as_u64().unwrap_or(0) as u16,
            do_bit: v["Do"].as_bool().unwrap_or(false),
            cd: v["CheckingDisabled"].as_bool().unwrap_or(false),
            ad: v["AuthenticatedData"].as_bool().unwrap_or(false),
            aa: v["Authoritative"].as_bool().unwrap_or(false),
            tc: v["Truncated"].as_bool().unwrap_or(false),
            ra: v["RecursionAvailable"].as_bool().unwrap_or(false),
            answer: rr_list(&v["Answer"]),
            ns: rr_list(&v["Ns"]),
            extra: rr_list(&v["Extra"]),
        }
    }

    /// `tc.Msg()`.
    pub fn msg(&self) -> Message {
        let mut m = Message::new(1, MessageType::Query, OpCode::Query);
        // SetQuestion sets RD
        m.metadata.recursion_desired = true;
        let qname = if self.qname.ends_with('.') {
            self.qname.clone()
        } else {
            format!("{}.", self.qname)
        };
        m.add_query(Query::query(
            Name::from_ascii(&qname).unwrap(),
            RecordType::from(self.qtype),
        ));
        if self.do_bit {
            set_edns(&mut m, 4096, true);
        }
        m
    }
}

/// An expected record: a record in presentation format or an OPT.
#[derive(Debug)]
pub enum Want {
    Rr(Box<Record>),
    Opt { udp: u16, do_bit: bool },
}

pub fn want(v: &Value) -> Result<Want, String> {
    if let Some(o) = v.get("OPT") {
        return Ok(Want::Opt {
            udp: o["udp"].as_u64().unwrap_or(0) as u16,
            do_bit: o["do"].as_bool().unwrap_or(false),
        });
    }
    let s = v.as_str().ok_or_else(|| format!("not a record: {v}"))?;
    match new_rr(s) {
        Ok(Some(r)) => Ok(Want::Rr(Box::new(r))),
        Ok(None) => Err(format!("no record in {s:?}")),
        Err(e) => {
            // miekg/dns keeps an RRSIG's signature as text, and the tables
            // abbreviate it to invalid base64; test.Section doesn't compare
            // it, so any valid signature does
            let f: Vec<&str> = s.split_whitespace().collect();
            if f.len() > 4 && f[3] == "RRSIG" {
                let fixed = format!("{} AAAA", f[..f.len() - 1].join(" "));
                if let Ok(Some(r)) = new_rr(&fixed) {
                    return Ok(Want::Rr(Box::new(r)));
                }
            }
            Err(format!("{s:?}: {e}"))
        }
    }
}

/// The parts of a record `test.Section` compares, as text, with the TTL
/// separate (303 in the expectation means "any TTL").
fn section_key(r: &Record) -> (String, u32, u16, String) {
    let name = r.name.to_string();
    let t = u16::from(r.record_type());
    let data = match &r.data {
        RData::SRV(s) => format!("{} {} {} {}", s.priority, s.weight, s.port, s.target),
        RData::A(a) => a.to_string(),
        RData::AAAA(a) => a.to_string(),
        RData::TXT(t) => t
            .txt_data
            .iter()
            .map(|d| String::from_utf8_lossy(d).into_owned())
            .collect::<String>(),
        RData::HINFO(h) => format!("{} {}", String::from_utf8_lossy(&h.cpu), String::from_utf8_lossy(&h.os)),
        RData::SOA(s) => s.mname.to_string(),
        RData::PTR(p) => p.0.to_string(),
        RData::CNAME(c) => c.0.to_string(),
        RData::MX(m) => format!("{} {}", m.preference, m.exchange),
        RData::NS(n) => n.0.to_string(),
        RData::SVCB(s) | RData::HTTPS(kerndns_core::proto::rr::rdata::HTTPS(s)) => s.to_string(),
        RData::DNSSEC(d) => {
            use kerndns_core::proto::dnssec::rdata::DNSSECRData;
            match d {
                DNSSECRData::RRSIG(s) => {
                    let i = s.input();
                    format!("{:?} {} {}", i.type_covered, i.num_labels, i.signer_name)
                }
                DNSSECRData::NSEC(n) => n.next_domain_name().to_string(),
                _ => String::new(),
            }
        }
        _ => String::new(),
    };
    (name, r.ttl, t, data)
}

fn rr_matches(want: &Record, got: &Record) -> bool {
    let (wn, wt, wty, wd) = section_key(want);
    let (gn, gt, gty, gd) = section_key(got);
    wn == gn && (wt == 303 || wt == gt) && wty == gty && wd == gd
}

/// One section: the same number of records, and each expected record
/// matches a different response record with `test.Section`'s field
/// checks. CoreDNS sorts the response by its text form and compares
/// position by position against the table, whose records are written in
/// that order; matching irrespective of order is the same check without
/// depending on Go's text formatting.
pub fn section(name: &str, want: &[Value], got: &[Record], edns: Option<&Edns>) -> Result<(), String> {
    let mut wants = Vec::new();
    for w in want {
        wants.push(self::want(w)?);
    }
    let want_opt = wants.iter().any(|w| matches!(w, Want::Opt { .. }));
    // the server adds an OPT echo that the plugin under test didn't write:
    // it only counts if the table expects one
    let n_got = got.len() + usize::from(want_opt && edns.is_some());
    if wants.len() != n_got {
        return Err(format!(
            "{name}: {} records, {} expected\n      got:  {}\n      want: {}",
            n_got,
            wants.len(),
            show(got),
            want.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(" | ")
        ));
    }
    let mut taken = vec![false; got.len()];
    for w in &wants {
        match w {
            Want::Opt { udp, do_bit } => {
                let e = edns.ok_or_else(|| format!("{name}: no OPT record"))?;
                if e.max_payload() != *udp || e.flags().dnssec_ok != *do_bit {
                    return Err(format!(
                        "{name}: OPT {} {} != {udp} {do_bit}",
                        e.max_payload(),
                        e.flags().dnssec_ok
                    ));
                }
            }
            Want::Rr(w) => {
                let Some(i) = (0..got.len()).find(|&i| !taken[i] && rr_matches(w, &got[i])) else {
                    return Err(format!("{name}: no match for {w}\n      got: {}", show(got)));
                };
                taken[i] = true;
            }
        }
    }
    Ok(())
}

pub fn show(rrs: &[Record]) -> String {
    rrs.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(" | ")
}

/// `test.SortAndCheck`: rcode, then the three sections.
pub fn sort_and_check(resp: &Message, tc: &Case) -> Result<(), String> {
    let rc = u16::from(resp.metadata.response_code);
    if rc != tc.rcode {
        return Err(format!(
            "rcode is {}, expected {}\n      answer: {}\n      ns: {}",
            ResponseCode::from(0, rc as u8),
            ResponseCode::from((tc.rcode >> 4) as u8, (tc.rcode & 0xf) as u8),
            show(&resp.answers),
            show(&resp.authorities)
        ));
    }
    section("answer", &tc.answer, &resp.answers, None)?;
    section("ns", &tc.ns, &resp.authorities, None)?;
    section("extra", &tc.extra, &resp.additionals, resp.edns.as_ref())
}

/// `test.CNAMEOrder`: no CNAME after a record it points to.
pub fn cname_order(resp: &Message) -> Result<(), String> {
    for (i, c) in resp.answers.iter().enumerate() {
        let RData::CNAME(t) = &c.data else { continue };
        if resp.answers[..i].iter().any(|a| a.name == t.0) {
            return Err("CNAME found after target record".into());
        }
    }
    Ok(())
}

/// Run `tc` and compare with SortAndCheck.
pub async fn run_case(s: &Server, tc: &Case) -> Result<(), String> {
    let served = s.serve(tc.msg()).await;
    let resp = served.written().ok_or("the plugin wrote no response")?;
    sort_and_check(resp, tc)
}

/// Run every `test.Case` in table `id` against `s`.
pub async fn run_cases(r: &mut Run, id: &str, s: &Server) {
    for (row, v) in r.rows(id) {
        let tc = Case::from(&v);
        let res = run_case(s, &tc).await;
        r.check(id, &row, res);
    }
}

pub fn u16_of(v: &Value) -> u16 {
    v.as_u64().unwrap_or(0) as u16
}

pub fn str_of(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// Run setup for the directives in `body` inside `.:53 { ... }`, like the
/// Go setup tests' `caddy.NewTestController("dns", input)` + `setup(c)`.
/// Startup hooks don't run.
pub fn setup(body: &str) -> Result<(), String> {
    setup_corefile(&format!(".:53 {{\n{body}\n}}"))
}

pub fn setup_corefile(corefile: &str) -> Result<(), String> {
    load(corefile, "Corefile", &registry(), &Options::default())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// A setup table: `input` is the directive text, `should_err` whether
/// setup fails and `content`, if given and not empty, a substring of the
/// error.
pub fn setup_rows(r: &mut Run, id: &str, input: &str, should_err: &str, content: Option<&str>) {
    for (row, v) in r.rows(id) {
        let res = setup(str_of(&v[input]));
        let want_err = v[should_err].as_bool().unwrap_or(false);
        let out = match (&res, want_err) {
            (Ok(()), true) => Err(format!("expected an error for {:?}", str_of(&v[input]))),
            (Err(e), false) => Err(format!("unexpected error for {:?}: {e}", str_of(&v[input]))),
            (Err(e), true) => match content.map(|c| str_of(&v[c])) {
                Some(c) if !c.is_empty() && !e.contains(c) => Err(format!("error {e:?} does not contain {c:?}")),
                _ => Ok(()),
            },
            (Ok(()), false) => Ok(()),
        };
        r.check(id, &row, out);
    }
}

/// The `fallthrough` line for a `fall.F` value, "" for `fall.Zero`.
pub fn fallthrough(v: &Value) -> String {
    let zones: Vec<&str> = v["Zones"]
        .as_array()
        .map(|a| a.iter().map(str_of).collect())
        .unwrap_or_default();
    match zones[..] {
        [] => String::new(),
        ["."] => "fallthrough".into(),
        _ => format!("fallthrough {}", zones.join(" ")),
    }
}
