//! `secondary`: serves zones transferred in from primaries, kept current
//! by the SOA refresh/retry/expire timers and NOTIFYs. Port of
//! `plugin/secondary`, including RFC 9432 catalog zones.
//!
//! ```text
//! secondary [ZONES...] {
//!     transfer from ADDRESS...
//!     catalog [MEMBER-ZONES...]
//!     fallthrough [ZONES...]
//! }
//! ```
//!
//! With `catalog`, every successful transfer of the zone is parsed as a
//! catalog; its member zones are added (and transferred from the same
//! primaries), removed, or migrated between catalogs following the `coo`
//! property, like `applyCatalog`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use kerndns_core::proto::rr::{DNSClass, Name, RData, Record};
use kerndns_core::transfer::TransferRegistry;
use kerndns_core::zones::{self, Fall, is_subdomain};
use kerndns_core::{Controller, PluginFactory, SetupError};

use crate::file::xfrin::XfrHook;
use crate::file::zone::{Zone, ZoneData};
use crate::file::{File, FileTransfer, SharedZones, Zones, shared};

fn host_port(s: &str) -> Result<String, String> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa.to_string());
    }
    let ip: IpAddr = s
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .map_err(|_| format!("not an IP address: {s:?}"))?;
    Ok(SocketAddr::new(ip, 53).to_string())
}

// ---------------------------------------------------------------- catalog

/// The catalog schema version KernDNS understands.
const CATALOG_VERSION: &str = "2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub id: String,
    pub zone: String,
    pub groups: Vec<String>,
    /// `coo`: the catalog this member is moving to.
    pub change_of_ownership: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    pub origin: String,
    /// Sorted by member ID.
    pub members: Vec<Member>,
}

fn labels(n: &Name) -> Vec<String> {
    n.iter()
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .collect()
}

fn fqdn(n: &Name) -> String {
    kerndns_core::request::lower_fqdn(n)
}

/// `catalog.Parse`: a catalog zone (RFC 9432) from its records.
pub fn parse_catalog(origin: &str, records: &[Record]) -> Result<Catalog, String> {
    let origin = origin.to_ascii_lowercase();
    let origin_labels: Vec<String> = origin
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    let mut zones_labels = vec!["zones".to_string()];
    zones_labels.extend(origin_labels);
    let version_owner = format!("version.{origin}");
    let suffix_ok =
        |l: &[String], extra: usize| l.len() == zones_labels.len() + extra && l[extra..] == zones_labels[..];

    let (mut has_soa, mut has_ns) = (false, false);
    let mut version = Vec::new();
    let mut ptrs: HashMap<String, Vec<String>> = HashMap::new();
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    let mut coo: HashMap<String, Vec<String>> = HashMap::new();
    for r in records {
        if r.dns_class != DNSClass::IN {
            return Err(format!("catalog zone {origin} contains non-IN record {r}"));
        }
        let owner = fqdn(&r.name);
        let l = labels(&r.name);
        match &r.data {
            RData::SOA(_) if owner == origin => has_soa = true,
            RData::NS(_) if owner == origin => has_ns = true,
            RData::TXT(t) => {
                let text: String = t.txt_data.iter().map(|s| String::from_utf8_lossy(s)).collect();
                if owner == version_owner {
                    version.push(text);
                } else if suffix_ok(&l, 2) && l[0] == "group" {
                    groups.entry(l[1].clone()).or_default().push(text);
                }
            }
            RData::PTR(p) => {
                if suffix_ok(&l, 1) {
                    ptrs.entry(l[0].clone()).or_default().push(fqdn(&p.0));
                } else if suffix_ok(&l, 2) && l[0] == "coo" {
                    coo.entry(l[1].clone()).or_default().push(fqdn(&p.0));
                }
            }
            _ => {}
        }
    }
    if !has_soa {
        return Err(format!("catalog zone {origin} has no SOA record"));
    }
    if !has_ns {
        return Err(format!("catalog zone {origin} has no NS record"));
    }
    if version.len() != 1 {
        return Err(format!(
            "catalog zone {origin} must have exactly one version TXT record"
        ));
    }
    if version[0] != CATALOG_VERSION {
        return Err(format!(
            "catalog zone {origin} has unsupported version {:?}",
            version[0]
        ));
    }
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut members = Vec::new();
    for (id, zones) in ptrs {
        if zones.len() != 1 {
            return Err(format!(
                "catalog member {id}.zones.{origin} must have exactly one PTR record"
            ));
        }
        let zone = zones[0].clone();
        if let Some(prev) = seen.insert(zone.clone(), id.clone()) {
            return Err(format!("catalog member zone {zone} is listed by both {prev} and {id}"));
        }
        let mut g = groups.get(&id).cloned().unwrap_or_default();
        g.sort();
        let c = coo.get(&id).cloned().unwrap_or_default();
        if c.len() > 1 {
            return Err(format!("catalog member {id} has more than one coo PTR record"));
        }
        members.push(Member {
            id,
            zone,
            groups: g,
            change_of_ownership: c.into_iter().next().unwrap_or_default(),
        });
    }
    members.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Catalog { origin, members })
}

// ------------------------------------------------------------- the plugin

/// A member zone a catalog added.
struct Dynamic {
    catalog: String,
    member_id: String,
    task: Option<tokio::task::AbortHandle>,
}

impl Dynamic {
    fn stop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

#[derive(Default)]
struct CatalogState {
    dynamic: HashMap<String, Dynamic>,
    catalogs: HashMap<String, Catalog>,
    members_of: HashMap<String, HashSet<String>>,
}

struct Secondary {
    zones: SharedZones,
    registry: TransferRegistry,
    /// Catalog zones and the member zones they may add (`None`: any).
    catalog_zones: HashMap<String, Option<Vec<String>>>,
    state: Mutex<CatalogState>,
    /// Transfer loops of the configured zones.
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
}

fn spawn(z: Arc<Zone>) -> Option<tokio::task::AbortHandle> {
    let h = tokio::runtime::Handle::try_current().ok()?;
    Some(h.spawn(z.transfer_and_update()).abort_handle())
}

impl Secondary {
    fn member_allowed(&self, origin: &str, member: &str) -> bool {
        match self.catalog_zones.get(origin) {
            Some(None) => true,
            Some(Some(zs)) => zs.iter().any(|z| is_subdomain(z, member)),
            None => false,
        }
    }

    /// A fresh member zone (`replaceDynamicZoneLocked`), optionally keeping
    /// the data of `preserve`. The caller starts its transfer loop.
    fn new_member(
        &self,
        st: &mut CatalogState,
        zones: &mut Zones,
        member: &Member,
        origin: &str,
        catalog_zone: &Zone,
        preserve: Option<&Arc<Zone>>,
    ) -> Option<Arc<Zone>> {
        if let Some(d) = st.dynamic.get_mut(&member.zone) {
            d.stop();
        }
        let name = Name::from_ascii(&member.zone).ok()?;
        let data = preserve.map(|p| (*p.snapshot()).clone()).unwrap_or_default();
        let mut z = Zone::new(name, PathBuf::from("stdin"), data);
        z.reload_interval = std::time::Duration::ZERO;
        z.registry = Some(self.registry.clone());
        z.transfer_from = catalog_zone.transfer_from.clone();
        if let Some(p) = preserve {
            z.expired.store(
                p.expired.load(std::sync::atomic::Ordering::Relaxed),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        let z = Arc::new(z);
        if zones.z.insert(member.zone.clone(), z.clone()).is_none() {
            zones.names.push(member.zone.clone());
        }
        st.dynamic.insert(
            member.zone.clone(),
            Dynamic {
                catalog: origin.to_string(),
                member_id: member.id.clone(),
                task: None,
            },
        );
        Some(z)
    }

    /// `applyCatalog`.
    fn apply_catalog(&self, origin: &str, cat: Catalog, catalog_zone: &Zone) {
        let mut st = self.state.lock().unwrap();
        let mut zones = (**self.zones.load()).clone();
        let mut members = HashSet::new();
        let mut starts: Vec<Arc<Zone>> = Vec::new();
        let mut rejected = 0;
        for m in &cat.members {
            if !self.member_allowed(origin, &m.zone) {
                rejected += 1;
                continue;
            }
            members.insert(m.zone.clone());
            let Some(existing) = zones.z.get(&m.zone).cloned() else {
                starts.extend(self.new_member(&mut st, &mut zones, m, origin, catalog_zone, None));
                kerndns_core::info!(
                    plugin = "secondary",
                    "Added catalog member zone {} from catalog {origin}",
                    m.zone
                );
                continue;
            };
            let Some(dyn_) = st.dynamic.get(&m.zone) else {
                kerndns_core::warning!(
                    plugin = "secondary",
                    "Skipping catalog member zone {} from {origin}: zone already exists",
                    m.zone
                );
                continue;
            };
            if dyn_.catalog == origin {
                if dyn_.member_id == m.id {
                    continue;
                }
                let previous = dyn_.member_id.clone();
                starts.extend(self.new_member(&mut st, &mut zones, m, origin, catalog_zone, None));
                kerndns_core::info!(
                    plugin = "secondary",
                    "Reset catalog member zone {} from {origin} after member ID changed from {previous} to {}",
                    m.zone,
                    m.id
                );
                continue;
            }
            // owned by another catalog: migrate only if that catalog hands it over
            let source_catalog = dyn_.catalog.clone();
            let source = st
                .catalogs
                .get(&source_catalog)
                .and_then(|c| c.members.iter().find(|x| x.zone == m.zone))
                .cloned();
            let Some(source) = source.filter(|s| s.change_of_ownership == origin) else {
                kerndns_core::warning!(
                    plugin = "secondary",
                    "Skipping catalog member zone {} from {origin}: zone already exists",
                    m.zone
                );
                continue;
            };
            let preserved = dyn_.member_id == source.id && source.id == m.id;
            let keep = preserved.then_some(&existing);
            starts.extend(self.new_member(&mut st, &mut zones, m, origin, catalog_zone, keep));
            if preserved {
                kerndns_core::info!(
                    plugin = "secondary",
                    "Migrated catalog member zone {} from catalog {source_catalog} to {origin}, preserving state for member ID {}",
                    m.zone,
                    source.id
                );
            } else {
                kerndns_core::info!(
                    plugin = "secondary",
                    "Migrated catalog member zone {} from catalog {source_catalog} to {origin} with state reset after member identity changed from {} to {}",
                    m.zone,
                    source.id,
                    m.id
                );
            }
        }
        for old in st.members_of.get(origin).cloned().unwrap_or_default() {
            if members.contains(&old) {
                continue;
            }
            if st.dynamic.get(&old).is_some_and(|d| d.catalog == origin) {
                if let Some(mut d) = st.dynamic.remove(&old) {
                    d.stop();
                }
                zones.z.remove(&old);
                zones.names.retain(|n| n != &old);
                kerndns_core::info!(
                    plugin = "secondary",
                    "Removed catalog member zone {old} from catalog {origin}"
                );
            }
        }
        st.members_of.insert(origin.to_string(), members);
        let n = cat.members.len();
        st.catalogs.insert(origin.to_string(), cat);
        self.zones.store(Arc::new(zones));
        for z in starts {
            let key = fqdn(&z.origin);
            let task = spawn(z);
            if let Some(d) = st.dynamic.get_mut(&key) {
                d.task = task;
            }
        }
        drop(st);
        if rejected > 0 {
            kerndns_core::warning!(
                plugin = "secondary",
                "Skipped {rejected} member zones from catalog {origin}: outside configured member zones"
            );
        }
        kerndns_core::info!(
            plugin = "secondary",
            "Parsed catalog zone {origin} with {n} member zones"
        );
    }

    fn shutdown(&self) {
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        for d in self.state.lock().unwrap().dynamic.values_mut() {
            d.stop();
        }
    }
}

/// Parses each transfer of a catalog zone and applies it once live.
struct CatalogHook {
    origin: String,
    secondary: Weak<Secondary>,
}

impl XfrHook for CatalogHook {
    fn check(&self, records: &[Record]) -> Result<Box<dyn FnOnce() + Send>, String> {
        let cat = parse_catalog(&self.origin, records)?;
        let (s, origin) = (self.secondary.clone(), self.origin.clone());
        Ok(Box::new(move || {
            let Some(s) = s.upgrade() else { return };
            let zone = s.zones.load().z.get(&origin).cloned();
            if let Some(z) = zone {
                s.apply_catalog(&origin, cat, &z);
            }
        }))
    }
}

/// `catalogMemberZonesFromArgs` + `mergeCatalogMemberZones`.
fn merge_members(cfg: &mut HashMap<String, Option<Vec<String>>>, origin: &str, args: &[String]) -> Result<(), String> {
    let mut new = Vec::new();
    for a in args {
        let n = zones::normalize_exact(a);
        if n.is_empty() || n.iter().any(|z| z.is_empty() || Name::from_ascii(z).is_err()) {
            return Err(format!("invalid catalog member zone {a:?}"));
        }
        new.extend(n);
    }
    match cfg.get_mut(origin) {
        None => {
            cfg.insert(origin.to_string(), (!new.is_empty()).then_some(new));
        }
        Some(existing) => match existing {
            None => {}
            Some(_) if new.is_empty() => *existing = None,
            Some(v) => {
                for z in new {
                    if !v.contains(&z) {
                        v.push(z);
                    }
                }
            }
        },
    }
    Ok(())
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "secondary"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let err = |m: String| SetupError::new("secondary", m);
        let keys = c.server_block_keys();
        let registry = TransferRegistry::of(c.config);
        let mut zones = Zones::default();
        let mut fall = Fall::default();
        let mut from: HashMap<String, Vec<String>> = HashMap::new();
        let mut catalog_zones: HashMap<String, Option<Vec<String>>> = HashMap::new();
        while c.next() {
            let args = c.remaining_args();
            let origins = zones::origins_from_args_or_server_block(&args, &keys);
            let mut has_transfer = false;
            while c.next_block() {
                match c.val() {
                    "transfer" => {
                        if !c.next_arg() {
                            return Err(c.arg_err());
                        }
                        if c.val() != "from" {
                            let msg = format!("unknown property {}", c.val());
                            return Err(c.errf(msg));
                        }
                        let a = c.remaining_args();
                        if a.is_empty() {
                            return Err(c.arg_err());
                        }
                        for f in a {
                            if f == "*" {
                                return Err(err("can't use '*' in transfer from".into()));
                            }
                            let hp = host_port(&f).map_err(err)?;
                            for o in &origins {
                                from.entry(o.clone()).or_default().push(hp.clone());
                            }
                        }
                        has_transfer = true;
                    }
                    "catalog" => {
                        let a = c.remaining_args();
                        for o in &origins {
                            merge_members(&mut catalog_zones, o, &a).map_err(err)?;
                        }
                    }
                    "fallthrough" => {
                        let a = c.remaining_args();
                        fall.set_zones_from_args(&a);
                    }
                    other => {
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
            if !has_transfer {
                return Err(c.errf("secondary zones require a transfer from property"));
            }
            for o in origins {
                let origin = Name::from_ascii(&o).map_err(|e| err(format!("invalid zone {o}: {e}")))?;
                let mut z = Zone::new(origin, PathBuf::from("stdin"), ZoneData::default());
                z.reload_interval = std::time::Duration::ZERO;
                z.registry = Some(registry.clone());
                z.transfer_from = from.get(&o).cloned().unwrap_or_default();
                if !zones.z.contains_key(&o) {
                    zones.names.push(o.clone());
                }
                zones.z.insert(o, Arc::new(z));
            }
        }

        let s = Arc::new_cyclic(|weak: &Weak<Secondary>| {
            // catalog zones get a hook that applies each transferred version
            for (o, z) in zones.z.iter_mut() {
                if catalog_zones.contains_key(o)
                    && let Some(zm) = Arc::get_mut(z)
                {
                    zm.xfr_hook = Some(Arc::new(CatalogHook {
                        origin: o.clone(),
                        secondary: weak.clone(),
                    }));
                }
            }
            Secondary {
                zones: shared(zones),
                registry: registry.clone(),
                catalog_zones,
                state: Mutex::default(),
                tasks: Mutex::default(),
            }
        });
        registry.add_source(Arc::new(FileTransfer(s.zones.clone())));
        let s2 = s.clone();
        c.on_startup(move || {
            let zs = s2.zones.load();
            for name in &zs.names {
                let z = zs.z[name].clone();
                if !z.transfer_from.is_empty()
                    && let Some(t) = spawn(z)
                {
                    s2.tasks.lock().unwrap().push(t);
                }
            }
            Ok(())
        });
        let s3 = s.clone();
        c.on_shutdown(move || s3.shutdown());
        let (fall, zones) = (Arc::new(fall), s.zones.clone());
        c.add_plugin(move |next| {
            Arc::new(File {
                name: "secondary",
                next,
                zones: zones.clone(),
                fall: fall.clone(),
            })
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use std::path::Path;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "secondary {\n transfer from 10.0.0.1 [::1]:5300\n}"));
        assert!(setup_err(&Setup, "secondary").contains("require a transfer from"));
        assert!(setup_err(&Setup, "secondary {\n transfer from *\n}").contains("can't use '*'"));
        assert!(setup_err(&Setup, "secondary {\n transfer to 10.0.0.1\n}").contains("unknown property to"));
        assert!(setup_ok(
            &Setup,
            "secondary catalog.example {\n transfer from 127.0.0.1\n catalog\n}"
        ));
        assert!(
            setup_err(
                &Setup,
                "secondary catalog.example {\n transfer from 127.0.0.1\n catalog :\n}"
            )
            .contains("invalid catalog member zone")
        );
    }

    #[test]
    fn member_restrictions_merge() {
        let mut m = HashMap::new();
        merge_members(&mut m, "c.", &["EXAMPLE.ORG".into(), "internal.example".into()]).unwrap();
        merge_members(&mut m, "c.", &["example.org".into()]).unwrap();
        assert_eq!(
            m["c."],
            Some(vec!["example.org.".to_string(), "internal.example.".to_string()])
        );
        merge_members(&mut m, "c.", &[]).unwrap();
        assert_eq!(m["c."], None, "a bare `catalog` accepts every member");
    }

    fn records(text: &str, origin: &str) -> Vec<Record> {
        let o = Name::from_ascii(origin).unwrap();
        let d = crate::file::zone::parse(text, &o, Path::new("test"), 0).unwrap();
        let mut v = d.apex.records().unwrap();
        for e in d.tree.elems() {
            v.extend(e.all().cloned());
        }
        v
    }

    fn catalog_text(origin: &str, members: &[(&str, &str)], coo: Option<(&str, &str)>) -> String {
        let mut t = format!(
            "{origin} 0 IN SOA invalid. invalid. 1 3600 600 2147483646 0\n{origin} 0 IN NS invalid.\nversion.{origin} 0 IN TXT \"2\"\n"
        );
        for (id, zone) in members {
            t.push_str(&format!("{id}.zones.{origin} 0 IN PTR {zone}\n"));
        }
        if let Some((id, target)) = coo {
            t.push_str(&format!("coo.{id}.zones.{origin} 0 IN PTR {target}\n"));
        }
        t
    }

    #[test]
    fn parses_catalogs() {
        let mut t = catalog_text(
            "cat.example.",
            &[("b", "b.example."), ("a", "A.example.")],
            Some(("a", "new.example.")),
        );
        t.push_str("group.a.zones.cat.example. 0 IN TXT \"g1\"\n");
        let c = parse_catalog("cat.example.", &records(&t, "cat.example.")).unwrap();
        assert_eq!(c.members.len(), 2);
        assert_eq!(c.members[0].id, "a");
        assert_eq!(c.members[0].zone, "a.example.");
        assert_eq!(c.members[0].change_of_ownership, "new.example.");
        assert_eq!(c.members[0].groups, vec!["g1".to_string()]);

        let bad = catalog_text("cat.example.", &[("a", "x.example."), ("b", "x.example.")], None);
        assert!(
            parse_catalog("cat.example.", &records(&bad, "cat.example."))
                .unwrap_err()
                .contains("listed by both")
        );
        let v1 = catalog_text("cat.example.", &[], None).replace("\"2\"", "\"1\"");
        assert!(
            parse_catalog("cat.example.", &records(&v1, "cat.example."))
                .unwrap_err()
                .contains("unsupported version")
        );
    }

    fn secondary(catalogs: &[(&str, Option<Vec<String>>)]) -> (Arc<Secondary>, HashMap<String, Arc<Zone>>) {
        let mut zones = Zones::default();
        let mut czs = HashMap::new();
        for (o, allowed) in catalogs {
            let mut z = Zone::new(
                Name::from_ascii(o).unwrap(),
                PathBuf::from("stdin"),
                ZoneData::default(),
            );
            z.transfer_from = vec!["192.0.2.53:53".into()];
            zones.names.push(o.to_string());
            zones.z.insert(o.to_string(), Arc::new(z));
            czs.insert(o.to_string(), allowed.clone());
        }
        let cz = zones.z.clone();
        let s = Arc::new(Secondary {
            zones: shared(zones),
            registry: TransferRegistry::default(),
            catalog_zones: czs,
            state: Mutex::default(),
            tasks: Mutex::default(),
        });
        (s, cz)
    }

    fn apply(s: &Secondary, cz: &HashMap<String, Arc<Zone>>, origin: &str, text: &str) {
        let c = parse_catalog(origin, &records(text, origin)).unwrap();
        s.apply_catalog(origin, c, &cz[origin]);
    }

    fn owner(s: &Secondary, zone: &str) -> Option<(String, String)> {
        s.state
            .lock()
            .unwrap()
            .dynamic
            .get(zone)
            .map(|d| (d.catalog.clone(), d.member_id.clone()))
    }

    #[test]
    fn adds_restricts_resets_and_removes_members() {
        let (s, cz) = secondary(&[("cat.example.", Some(vec!["example.org.".into()]))]);
        apply(
            &s,
            &cz,
            "cat.example.",
            &catalog_text("cat.example.", &[("a", "a.example.org."), ("x", "evil.example.")], None),
        );
        let names = s.zones.load().names.clone();
        assert!(names.contains(&"a.example.org.".to_string()));
        assert!(
            !names.contains(&"evil.example.".to_string()),
            "outside the configured member zones"
        );
        let first = s.zones.load().z["a.example.org."].clone();
        assert_eq!(
            first.transfer_from,
            vec!["192.0.2.53:53".to_string()],
            "members use the catalog's primaries"
        );

        // same ID: untouched; new ID: a fresh zone
        apply(
            &s,
            &cz,
            "cat.example.",
            &catalog_text("cat.example.", &[("a", "a.example.org.")], None),
        );
        assert!(Arc::ptr_eq(&first, &s.zones.load().z["a.example.org."]));
        apply(
            &s,
            &cz,
            "cat.example.",
            &catalog_text("cat.example.", &[("b", "a.example.org.")], None),
        );
        assert!(!Arc::ptr_eq(&first, &s.zones.load().z["a.example.org."]));
        assert_eq!(owner(&s, "a.example.org."), Some(("cat.example.".into(), "b".into())));

        apply(&s, &cz, "cat.example.", &catalog_text("cat.example.", &[], None));
        assert!(!s.zones.load().z.contains_key("a.example.org."));
        assert!(
            s.zones.load().z.contains_key("cat.example."),
            "the catalog zone itself stays"
        );
    }

    #[test]
    fn migrates_only_with_coo_handshake() {
        let (s, cz) = secondary(&[("old.example.", None), ("new.example.", None)]);
        let soa = "m.example. 60 IN SOA ns. h. 7 60 60 60 60\nm.example. 60 IN A 192.0.2.1\n";
        apply(
            &s,
            &cz,
            "old.example.",
            &catalog_text("old.example.", &[("a", "m.example.")], None),
        );
        s.zones.load().z["m.example."].set_data(
            crate::file::zone::parse(soa, &Name::from_ascii("m.example.").unwrap(), Path::new("t"), 0).unwrap(),
        );

        // the new catalog lists it without the old one handing it over
        apply(
            &s,
            &cz,
            "new.example.",
            &catalog_text("new.example.", &[("a", "m.example.")], None),
        );
        assert_eq!(owner(&s, "m.example.").unwrap().0, "old.example.");
        // the old catalog adds coo: still waits for the new catalog's next update
        apply(
            &s,
            &cz,
            "old.example.",
            &catalog_text("old.example.", &[("a", "m.example.")], Some(("a", "new.example."))),
        );
        assert_eq!(owner(&s, "m.example.").unwrap().0, "old.example.");
        apply(
            &s,
            &cz,
            "new.example.",
            &catalog_text("new.example.", &[("a", "m.example.")], None),
        );
        assert_eq!(owner(&s, "m.example.").unwrap().0, "new.example.");
        // same member ID: the data is kept across the migration
        assert_eq!(s.zones.load().z["m.example."].snapshot().apex.serial(), Some(7));
        // the old catalog dropping it no longer removes it
        apply(&s, &cz, "old.example.", &catalog_text("old.example.", &[], None));
        assert!(s.zones.load().z.contains_key("m.example."));
    }

    #[test]
    fn migration_with_new_id_resets_state() {
        let (s, cz) = secondary(&[("old.example.", None), ("new.example.", None)]);
        apply(
            &s,
            &cz,
            "old.example.",
            &catalog_text("old.example.", &[("a", "m.example.")], Some(("a", "new.example."))),
        );
        let soa = "m.example. 60 IN SOA ns. h. 7 60 60 60 60\n";
        s.zones.load().z["m.example."].set_data(
            crate::file::zone::parse(soa, &Name::from_ascii("m.example.").unwrap(), Path::new("t"), 0).unwrap(),
        );
        apply(
            &s,
            &cz,
            "new.example.",
            &catalog_text("new.example.", &[("b", "m.example.")], None),
        );
        assert_eq!(owner(&s, "m.example."), Some(("new.example.".into(), "b".into())));
        assert_eq!(s.zones.load().z["m.example."].snapshot().apex.serial(), None);
    }
}
