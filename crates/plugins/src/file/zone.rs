//! Zone data: a canonical-order tree of owner names plus the apex records,
//! ported from `plugin/file/zone.go` and `plugin/file/tree`.

use std::collections::BTreeMap;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use kerndns_core::proto::dnssec::rdata::DNSSECRData;
use kerndns_core::proto::rr::{Name, RData, Record, RecordType};

use super::zonefile::{ZoneFileError, parse_zone_with};

/// The type an RRSIG covers.
pub fn rrsig_covers(r: &Record) -> Option<RecordType> {
    match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(s)) => Some(s.input().type_covered),
        _ => None,
    }
}

/// RRSIGs among `sigs` that cover `t`, like `rrutil.SubTypeSignature`.
pub fn sub_type_signature(sigs: &[Record], t: RecordType) -> Vec<Record> {
    sigs.iter().filter(|s| rrsig_covers(s) == Some(t)).cloned().collect()
}

/// Number of labels, counting a leading `*` (hickory's `num_labels` skips it).
pub fn label_count(n: &Name) -> usize {
    n.iter().count()
}

/// All records of one owner name, grouped by type (in the order each type
/// first appeared). A name has only a few records, so one exactly sized
/// list is both smaller and faster to search than a map of lists.
#[derive(Debug, Clone)]
pub struct Elem {
    /// Never empty; the first record's name is the element's name.
    rrs: Vec<Record>,
}

impl Elem {
    pub fn name(&self) -> &Name {
        &self.rrs[0].name
    }

    /// Records of type `t` (empty if none).
    pub fn typ(&self, t: RecordType) -> &[Record] {
        let Some(start) = self.rrs.iter().position(|r| r.record_type() == t) else {
            return &[];
        };
        let len = self.rrs[start..].iter().take_while(|r| r.record_type() == t).count();
        &self.rrs[start..start + len]
    }

    pub fn has(&self, t: RecordType) -> bool {
        self.rrs.iter().any(|r| r.record_type() == t)
    }

    /// Add `r` after the records of its type.
    fn push(&mut self, r: Record) {
        let t = r.record_type();
        let at = self
            .rrs
            .iter()
            .rposition(|x| x.record_type() == t)
            .map_or(self.rrs.len(), |i| i + 1);
        if self.rrs.len() == self.rrs.capacity() {
            // grow by half instead of doubling (or starting at four): most
            // names have one or two records
            self.rrs.reserve_exact((self.rrs.len() / 2).max(1));
        }
        self.rrs.insert(at, r);
    }

    /// Records of type `t` renamed to `qname`, for wildcard answers.
    pub fn type_for_wildcard(&self, t: RecordType, qname: &Name) -> Vec<Record> {
        self.typ(t)
            .iter()
            .map(|r| {
                let mut r = r.clone();
                r.name = qname.clone();
                r
            })
            .collect()
    }

    pub fn all(&self) -> impl Iterator<Item = &Record> {
        self.rrs.iter()
    }
}

/// Owner names in canonical DNS order (RFC 4034 6.1), like `tree.Tree`.
/// hickory's `Name` ordering is that canonical, case-insensitive order.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    map: BTreeMap<Name, Elem>,
}

impl Tree {
    pub fn insert(&mut self, r: Record) {
        match self.map.get_mut(&r.name) {
            Some(e) => e.push(r),
            None => {
                let mut rrs = Vec::with_capacity(1);
                let name = r.name.clone();
                rrs.push(r);
                self.map.insert(name, Elem { rrs });
            }
        }
    }

    pub fn search(&self, name: &Name) -> Option<&Elem> {
        self.map.get(name)
    }

    /// The greatest name less than or equal to `name`.
    pub fn prev(&self, name: &Name) -> Option<&Elem> {
        self.map.range(..=name.clone()).next_back().map(|(_, e)| e)
    }

    /// The smallest name greater than or equal to `name`.
    pub fn next(&self, name: &Name) -> Option<&Elem> {
        self.map.range(name.clone()..).next().map(|(_, e)| e)
    }

    /// The smallest name strictly greater than `name`.
    pub fn next_after(&self, name: &Name) -> Option<&Elem> {
        self.map
            .range((Bound::Excluded(name.clone()), Bound::Unbounded))
            .next()
            .map(|(_, e)| e)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn elems(&self) -> impl Iterator<Item = &Elem> {
        self.map.values()
    }

    /// A and AAAA records for in-bailiwick NS targets, like `Tree.Glue`.
    pub fn glue(&self, nsrrs: &[Record], do_bit: bool) -> Vec<Record> {
        let mut glue = Vec::new();
        for rr in nsrrs {
            if let RData::NS(ns) = &rr.data
                && rr.name.zone_of(&ns.0)
                && let Some(e) = self.search(&ns.0)
            {
                for t in [RecordType::A, RecordType::AAAA] {
                    glue.extend(e.typ(t).iter().cloned());
                    if do_bit {
                        glue.extend(sub_type_signature(e.typ(RecordType::RRSIG), t));
                    }
                }
            }
        }
        glue
    }
}

/// Records at the zone apex that are kept outside the tree.
#[derive(Debug, Clone, Default)]
pub struct Apex {
    pub soa: Option<Record>,
    pub ns: Vec<Record>,
    pub sig_soa: Vec<Record>,
    pub sig_ns: Vec<Record>,
}

impl Apex {
    pub fn soa(&self, do_bit: bool) -> Vec<Record> {
        let mut v: Vec<Record> = self.soa.iter().cloned().collect();
        if do_bit {
            v.extend(self.sig_soa.iter().cloned());
        }
        v
    }

    pub fn ns(&self, do_bit: bool) -> Vec<Record> {
        let mut v = self.ns.clone();
        if do_bit {
            v.extend(self.sig_ns.iter().cloned());
        }
        v
    }

    pub fn serial(&self) -> Option<u32> {
        match self.soa.as_ref().map(|r| &r.data) {
            Some(RData::SOA(soa)) => Some(soa.serial),
            _ => None,
        }
    }

    /// SOA, its signatures, NS and their signatures (the AXFR prologue).
    pub fn records(&self) -> Option<Vec<Record>> {
        let soa = self.soa.clone()?;
        let mut v = vec![soa];
        v.extend(self.sig_soa.iter().cloned());
        v.extend(self.ns.iter().cloned());
        v.extend(self.sig_ns.iter().cloned());
        Some(v)
    }
}

/// One immutable version of a zone's contents.
#[derive(Debug, Clone, Default)]
pub struct ZoneData {
    pub apex: Apex,
    pub tree: Tree,
}

impl ZoneData {
    /// Add a record with CoreDNS's normalisation, like `Zone.Insert`.
    pub fn insert(&mut self, origin: &Name, mut r: Record) -> Result<(), String> {
        let t = r.record_type();
        if t != RecordType::SRV {
            r.name = r.name.to_lowercase();
        }
        match (&mut r.data, t) {
            (RData::NS(ns), _) => {
                ns.0 = ns.0.to_lowercase();
                if &r.name == origin {
                    self.apex.ns.push(r);
                    return Ok(());
                }
            }
            (RData::SOA(soa), _) => {
                soa.mname = soa.mname.to_lowercase();
                soa.rname = soa.rname.to_lowercase();
                self.apex.soa = Some(r);
                return Ok(());
            }
            (_, RecordType::NSEC3 | RecordType::NSEC3PARAM) => {
                return Err(format!(
                    "NSEC3 zone is not supported, dropping RR: {} for zone: {}",
                    r.name, origin
                ));
            }
            (RData::CNAME(c), _) => c.0 = c.0.to_lowercase(),
            (RData::MX(mx), _) => mx.exchange = mx.exchange.to_lowercase(),
            (RData::SVCB(s), _) => s.target_name = s.target_name.to_lowercase(),
            (RData::HTTPS(h), _) => h.0.target_name = h.0.target_name.to_lowercase(),
            _ => {}
        }
        if t == RecordType::RRSIG {
            match rrsig_covers(&r) {
                Some(RecordType::SOA) => {
                    self.apex.sig_soa.push(r);
                    return Ok(());
                }
                Some(RecordType::NS) if &r.name == origin => {
                    self.apex.sig_ns.push(r);
                    return Ok(());
                }
                _ => {}
            }
        }
        self.tree.insert(r);
        Ok(())
    }
}

/// Why loading a zone file didn't produce new data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The SOA serial equals the one already loaded (not an error for reloads).
    NoChange {
        origin: String,
        file: String,
        serial: i64,
    },
    Other(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::NoChange { origin, file, serial } => {
                write!(
                    f,
                    "no change in SOA serial for origin {origin} in file {file}, with {serial} SOA serial"
                )
            }
            LoadError::Other(s) => f.write_str(s),
        }
    }
}

/// Parse a zone file for `origin`, like `file.Parse`. If `serial` is not
/// negative and the file's SOA has that serial, return `NoChange`.
pub fn parse(text: &str, origin: &Name, file: &Path, serial: i64) -> Result<ZoneData, LoadError> {
    let mut data = ZoneData::default();
    let mut seen_soa = false;
    // why the sink stopped the parse
    let mut stop: Option<LoadError> = None;
    // like file.Parse: records go into the zone as they are read
    let mut sink = |rr: Record| -> Result<(), ZoneFileError> {
        let mut fail = |e: LoadError| {
            stop = Some(e);
            Err(ZoneFileError(String::new()))
        };
        if let RData::SOA(soa) = &rr.data {
            if &rr.name != origin {
                return fail(LoadError::Other(format!(
                    "file {:?} has SOA owner {} that does not match origin {}",
                    file.display().to_string(),
                    rr.name,
                    origin
                )));
            }
            if !seen_soa {
                seen_soa = true;
                if serial >= 0 && soa.serial as i64 == serial {
                    return fail(LoadError::NoChange {
                        origin: origin.to_string(),
                        file: file.display().to_string(),
                        serial,
                    });
                }
            }
        }
        match data.insert(origin, rr) {
            Ok(()) => Ok(()),
            Err(e) => fail(LoadError::Other(e)),
        }
    };
    let parsed = parse_zone_with(text, origin, file, &mut sink);
    if let Some(e) = stop {
        return Err(e);
    }
    parsed.map_err(|ZoneFileError(e)| {
        LoadError::Other(format!(
            "failed to parse file {:?} for origin {} with error {}",
            file.display().to_string(),
            origin,
            e
        ))
    })?;
    if !seen_soa {
        return Err(LoadError::Other(format!(
            "file {:?} has no SOA record for origin {}",
            file.display().to_string(),
            origin
        )));
    }
    Ok(data)
}

/// A zone served by `file`: its current data and reload settings.
pub struct Zone {
    pub origin: Name,
    pub orig_len: usize,
    file: RwLock<PathBuf>,
    data: RwLock<Arc<ZoneData>>,
    pub expired: AtomicBool,
    pub reload_interval: Duration,
    pub reload_by_mtime: bool,
    mtime: Mutex<Option<SystemTime>>,
    reload_task: Mutex<Option<tokio::task::AbortHandle>>,
    /// Sends NOTIFYs after a reload (if `transfer` is configured).
    pub registry: Option<kerndns_core::transfer::WeakTransferRegistry>,
    /// Primaries (`ip:port`) of a secondary zone.
    pub transfer_from: Vec<String>,
    /// Checks each transferred-in version (catalog zones).
    pub xfr_hook: Option<Arc<dyn super::xfrin::XfrHook>>,
}

impl Zone {
    pub fn new(origin: Name, file: PathBuf, data: ZoneData) -> Self {
        Self {
            orig_len: label_count(&origin),
            origin,
            file: RwLock::new(file),
            data: RwLock::new(Arc::new(data)),
            expired: AtomicBool::new(false),
            reload_interval: Duration::from_secs(60),
            reload_by_mtime: false,
            mtime: Mutex::new(None),
            reload_task: Mutex::new(None),
            registry: None,
            transfer_from: Vec::new(),
            xfr_hook: None,
        }
    }

    /// The zone for a transfer, like `Zone.Transfer`: apex, every name in
    /// canonical order, then the SOA again; only the SOA if `serial` is
    /// the current one (IXFR "up to date").
    pub fn transfer(&self, serial: u32) -> Result<Vec<Vec<Record>>, String> {
        let data = self.snapshot();
        let apex = data.apex.records().ok_or("no SOA")?;
        let soa = data.apex.soa.clone().ok_or("no SOA")?;
        if serial != 0 && data.apex.serial() == Some(serial) {
            return Ok(vec![vec![soa]]);
        }
        let mut out = vec![apex];
        for e in data.tree.elems() {
            out.push(e.all().cloned().collect());
        }
        out.push(vec![soa]);
        Ok(out)
    }

    /// The current data; cheap to take and stable for one lookup.
    pub fn snapshot(&self) -> Arc<ZoneData> {
        self.data.read().unwrap().clone()
    }

    pub fn set_data(&self, d: ZoneData) {
        *self.data.write().unwrap() = Arc::new(d);
        self.expired.store(false, Ordering::Relaxed);
    }

    pub fn file(&self) -> PathBuf {
        self.file.read().unwrap().clone()
    }

    /// Change the file reloads read from, like `Zone.SetFile`.
    pub fn set_file(&self, p: PathBuf) {
        *self.file.write().unwrap() = p;
    }

    pub fn set_mtime(&self, t: Option<SystemTime>) {
        *self.mtime.lock().unwrap() = t;
    }

    pub fn soa_serial(&self) -> i64 {
        self.snapshot().apex.serial().map(i64::from).unwrap_or(-1)
    }

    /// `nameFromRight`: `origin` plus `i` more labels of `qname` from the
    /// right, and whether that asked for more labels than `qname` has.
    pub fn name_from_right(&self, qname: &Name, i: usize) -> (Name, bool) {
        if i == 0 {
            return (self.origin.clone(), false);
        }
        let want = self.orig_len + i;
        let have = label_count(qname);
        if want > have {
            return (qname.clone(), true);
        }
        (
            Name::from_labels(qname.iter().skip(have - want))
                .map(fqdn)
                .unwrap_or_else(|_| qname.clone()),
            false,
        )
    }

    /// Start reloading the file every `reload_interval` when its SOA serial
    /// (or, with `reload_by_mtime`, its mtime) changes, like `Zone.Reload`.
    pub fn start_reload(self: &Arc<Self>) {
        if self.reload_interval.is_zero() {
            return;
        }
        let z = Arc::downgrade(self);
        let interval = self.reload_interval;
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            loop {
                tick.tick().await;
                let Some(z) = z.upgrade() else { return };
                z.reload_once().await;
            }
        });
        *self.reload_task.lock().unwrap() = Some(task.abort_handle());
    }

    pub fn stop_reload(&self) {
        if let Some(t) = self.reload_task.lock().unwrap().take() {
            t.abort();
        }
    }

    async fn reload_once(&self) {
        let path = self.file();
        let mut serial = self.soa_serial();
        let mut new_mtime = None;
        if self.reload_by_mtime {
            let meta = match tokio::fs::metadata(&path).await {
                Ok(m) => m,
                Err(e) => {
                    kerndns_core::error!(
                        plugin = "file",
                        "Failed to stat zone {:?} in {:?}: {e}",
                        self.origin.to_string(),
                        path
                    );
                    return;
                }
            };
            let m = meta.modified().ok();
            let last = *self.mtime.lock().unwrap();
            if !matches!((m, last), (Some(m), Some(l)) if m > l) && last.is_some() {
                return;
            }
            new_mtime = m;
            serial = 0;
        }
        let text = match tokio::fs::read_to_string(&path).await {
            Ok(t) => t,
            Err(e) => {
                kerndns_core::error!(
                    plugin = "file",
                    "Failed to open zone {:?} in {:?}: {e}",
                    self.origin.to_string(),
                    path
                );
                return;
            }
        };
        match parse(&text, &self.origin, &path, serial) {
            Ok(data) => {
                let new_serial = data.apex.serial().unwrap_or(0);
                self.set_data(data);
                if self.reload_by_mtime {
                    self.set_mtime(new_mtime);
                }
                kerndns_core::info!(
                    plugin = "file",
                    "Successfully reloaded zone {:?} in {:?} with {} SOA serial",
                    self.origin.to_string(),
                    path.display().to_string(),
                    new_serial
                );
                if let Some(r) = &self.registry {
                    r.notify(&self.origin.to_string());
                }
            }
            Err(LoadError::NoChange { .. }) => {}
            Err(e) => kerndns_core::error!(plugin = "file", "Parsing zone {:?}: {e}", self.origin.to_string()),
        }
    }
}

fn fqdn(mut n: Name) -> Name {
    n.set_fqdn(true);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    #[test]
    fn name_from_right_matches_go() {
        // values from CoreDNS's nameFromRight (checked against Go)
        let z = Zone::new(n("example.org."), PathBuf::new(), ZoneData::default());
        let cases = [
            ("www.example.org.", 0, "example.org.", false),
            ("www.example.org.", 1, "www.example.org.", false),
            ("www.example.org.", 2, "www.example.org.", true),
            ("a.b.example.org.", 1, "b.example.org.", false),
            ("a.b.example.org.", 2, "a.b.example.org.", false),
            ("a.b.example.org.", 3, "a.b.example.org.", true),
            ("example.org.", 1, "example.org.", true),
        ];
        for (q, i, want, shot) in cases {
            let (got, s) = z.name_from_right(&n(q), i);
            assert_eq!((got.to_ascii(), s), (want.to_string(), shot), "{q} {i}");
        }
    }

    #[test]
    fn canonical_order() {
        let mut t = Tree::default();
        for name in [
            "example.org.",
            "a.example.org.",
            "z.example.org.",
            "*.z.example.org.",
            "b.a.example.org.",
        ] {
            t.insert(Record::from_rdata(n(name), 0, RData::A("192.0.2.1".parse().unwrap())));
        }
        let order: Vec<String> = t.elems().map(|e| e.name().to_ascii()).collect();
        assert_eq!(
            order,
            [
                "example.org.",
                "a.example.org.",
                "b.a.example.org.",
                "z.example.org.",
                "*.z.example.org."
            ]
        );
        assert_eq!(
            t.prev(&n("c.example.org.")).unwrap().name().to_ascii(),
            "b.a.example.org."
        );
        assert_eq!(
            t.next(&n("c.example.org.")).unwrap().name().to_ascii(),
            "z.example.org."
        );
    }
}
