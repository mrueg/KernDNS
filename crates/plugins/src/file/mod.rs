//! `file`: serves zones from RFC 1035 master files. Port of `plugin/file`.
//!
//! ```text
//! file DBFILE [ZONES...] {
//!     reload DURATION
//!     reload_by_mtime
//!     fallthrough [ZONES...]
//! }
//! ```
//!
//! Zones are transfer sources for `transfer`; AXFR/IXFR queries that reach
//! this handler are REFUSED as in CoreDNS. `secondary` reuses this handler
//! for transferred-in zones, including NOTIFYs from their primaries.

pub mod lookup;
pub mod xfrin;
pub mod zone;
pub mod zonefile;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kerndns_core::duration::{format_duration, parse_duration};
use kerndns_core::proto::op::{OpCode, ResponseCode};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_core::transfer::{TransferError, TransferRegistry, Transferer};
use kerndns_core::zones::{self, Fall};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};

use lookup::LookupResult;
use zone::{LoadError, Zone, ZoneData};

pub struct Setup;

/// The zones of one `file` handler.
#[derive(Default, Clone)]
pub struct Zones {
    pub z: HashMap<String, Arc<Zone>>,
    /// Zone names in Corefile order.
    pub names: Vec<String>,
}

/// Zones that a handler serves; `secondary` replaces the set when a
/// catalog zone adds or removes member zones.
pub type SharedZones = Arc<arc_swap::ArcSwap<Zones>>;

pub fn shared(z: Zones) -> SharedZones {
    Arc::new(arc_swap::ArcSwap::from_pointee(z))
}

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "file"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let registry = TransferRegistry::of(c.config);
        let (zones, fall) = file_parse(c, &registry)?;
        let list: Vec<(String, Arc<Zone>)> = zones.names.iter().map(|n| (n.clone(), zones.z[n].clone())).collect();
        let zones = shared(zones);
        registry.add_source(Arc::new(FileTransfer(zones.clone())));
        for (name, z) in list {
            let z2 = z.clone();
            let (reg, n) = (registry.clone(), name);
            c.on_startup(move || {
                z.start_reload();
                reg.notify(&n);
                Ok(())
            });
            c.on_shutdown(move || z2.stop_reload());
        }
        let fall = Arc::new(fall);
        c.add_plugin(move |next| {
            Arc::new(File {
                name: "file",
                next,
                zones: zones.clone(),
                fall: fall.clone(),
            })
        });
        Ok(())
    }
}

fn open_error(path: &std::path::Path, e: &std::io::Error) -> String {
    let msg = match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        _ => e.to_string(),
    };
    format!("open {}: {msg}", path.display())
}

/// `fileParse`.
fn file_parse(c: &mut Controller<'_>, registry: &TransferRegistry) -> Result<(Zones, Fall), SetupError> {
    let mut zones = Zones::default();
    let mut fall = Fall::default();
    let mut open_err: Option<String> = None;
    let mut reload = Duration::from_secs(60);
    let mut reload_by_mtime = false;
    let server_keys = c.server_block_keys();

    while c.next() {
        if !c.next_arg() {
            return Err(c.arg_err());
        }
        let mut file_name = PathBuf::from(c.val());
        let args = c.remaining_args();
        let origins = zones::origins_from_args_or_server_block(&args, &server_keys);
        if file_name.is_relative()
            && let Some(root) = &c.config.root
        {
            file_name = root.join(file_name);
        }

        let (content, mtime) = match std::fs::read_to_string(&file_name) {
            Ok(t) => (Some(t), std::fs::metadata(&file_name).and_then(|m| m.modified()).ok()),
            Err(e) => {
                open_err = Some(open_error(&file_name, &e));
                (None, None)
            }
        };

        let mut parsed: Vec<(String, ZoneData)> = Vec::new();
        for o in &origins {
            let origin = Name::from_ascii(o).map_err(|e| c.errf(format!("invalid zone {o}: {e}")))?;
            let data = match &content {
                Some(text) => zone::parse(text, &origin, &file_name, 0).map_err(|e| match e {
                    LoadError::NoChange { .. } => SetupError::new("file", e),
                    LoadError::Other(m) => SetupError::new("file", m),
                })?,
                None => ZoneData::default(),
            };
            parsed.push((o.clone(), data));
        }

        while c.next_block() {
            match c.val() {
                "fallthrough" => {
                    let a = c.remaining_args();
                    fall.set_zones_from_args(&a);
                }
                "reload" => {
                    let t = c.remaining_args();
                    let Some(d) = t.first() else {
                        return Err(SetupError::new("file", "reload duration value is expected"));
                    };
                    reload = parse_duration(d).map_err(|e| SetupError::new("file", e))?;
                }
                "reload_by_mtime" => reload_by_mtime = true,
                "upstream" => {
                    c.remaining_args();
                }
                other => {
                    let msg = format!("unknown property '{other}'");
                    return Err(c.errf(msg));
                }
            }
        }

        for (o, data) in parsed {
            let origin = Name::from_ascii(&o).expect("checked above");
            let mut z = Zone::new(origin, file_name.clone(), data);
            z.reload_interval = reload;
            z.reload_by_mtime = reload_by_mtime;
            z.registry = Some(registry.clone());
            if reload_by_mtime {
                z.set_mtime(mtime);
            }
            if !zones.z.contains_key(&o) {
                zones.names.push(o.clone());
            }
            zones.z.insert(o, Arc::new(z));
        }
    }

    if let Some(e) = open_err {
        if reload.is_zero() {
            return Err(SetupError::new("file", e));
        }
        kerndns_core::warning!(
            plugin = "file",
            "Failed to open {e:?}: trying again in {}",
            format_duration(reload)
        );
    }
    Ok((zones, fall))
}

/// `file` as a zone source for `transfer` (`File.Transfer`).
pub(crate) struct FileTransfer(pub(crate) SharedZones);

impl Transferer for FileTransfer {
    fn transfer(&self, zone: &str, serial: u32) -> Result<Vec<Vec<kerndns_core::proto::rr::Record>>, TransferError> {
        let zone = zone.to_ascii_lowercase();
        let zs = self.0.load();
        match zones::matches(&zs.names, &zone) {
            Some(m) if m == zone => {}
            _ => return Err(TransferError::NotAuthoritative),
        }
        let z = zs.z.get(&zone).ok_or(TransferError::NotAuthoritative)?;
        z.transfer(serial).map_err(TransferError::Other)
    }
}

/// The handler.
pub struct File {
    /// "file" or "secondary".
    pub(crate) name: &'static str,
    pub(crate) next: Next,
    pub(crate) zones: SharedZones,
    pub(crate) fall: Arc<Fall>,
}

impl File {
    fn lookup_zone(&self, qname: &str) -> Option<(String, Arc<Zone>)> {
        let zs = self.zones.load();
        let zone = zones::matches(&zs.names, qname)?;
        zs.z.get(zone).map(|z| (zone.to_string(), z.clone()))
    }
}

#[async_trait]
impl Handler for File {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let qname_str = req.name();
        let Some((zone, z)) = self.lookup_zone(&qname_str) else {
            if self.next.is_none() {
                return Ok(ResponseCode::Refused);
            }
            return next_or_failure(self.name, &self.next, ctx, w, req).await;
        };

        if matches!(req.qtype(), RecordType::AXFR | RecordType::IXFR) {
            return Ok(ResponseCode::Refused);
        }

        if req.msg.metadata.op_code == OpCode::Notify {
            if z.is_notify(req) {
                let mut m = req.reply();
                m.metadata.authoritative = true;
                w.write_msg(m)
                    .await
                    .map_err(|e| PluginError::servfail(self.name, e.to_string()))?;
                kerndns_core::info!(
                    plugin = "file",
                    "Notify from {} for {}: checking transfer",
                    req.ip(),
                    zone
                );
                // check and transfer in the background; the ack is sent now
                let (z, ip, zone) = (z.clone(), req.ip(), zone.clone());
                tokio::spawn(async move {
                    match z.should_transfer().await {
                        Ok(true) => {
                            if let Err(e) = z.transfer_in().await {
                                kerndns_core::warning!(
                                    plugin = "file",
                                    "Notify from {ip} for {zone}: transfer failed: {e}"
                                );
                            }
                        }
                        Ok(false) => {
                            kerndns_core::info!(
                                plugin = "file",
                                "Notify from {ip} for {zone}: no SOA serial increase seen"
                            )
                        }
                        Err(e) => {
                            kerndns_core::warning!(
                                plugin = "file",
                                "Notify from {ip} for {zone}: failed primary check: {e}"
                            )
                        }
                    }
                });
                return Ok(ResponseCode::NoError);
            }
            kerndns_core::info!(plugin = "file", "Dropping notify from {} for {}", req.ip(), zone);
            return Ok(ResponseCode::NoError);
        }

        if z.expired.load(std::sync::atomic::Ordering::Relaxed) {
            kerndns_core::error!(plugin = "file", "Zone {zone} is expired");
            return Ok(ResponseCode::ServFail);
        }

        let qname = req.qname().to_lowercase();
        let (answer, ns, extra, result) = z.lookup(ctx, req, &qname).await;

        if answer.is_empty()
            && matches!(result, LookupResult::NameError | LookupResult::Success)
            && self.fall.through(&qname_str)
        {
            return next_or_failure(self.name, &self.next, ctx, w, req).await;
        }

        let mut m = req.reply();
        m.metadata.authoritative = true;
        m.answers = answer;
        m.authorities = ns;
        m.additionals = extra;

        match result {
            LookupResult::Success | LookupResult::NoData => {}
            LookupResult::NameError => m.metadata.response_code = ResponseCode::NXDomain,
            LookupResult::Delegation => {
                if m.answers.is_empty() {
                    m.metadata.authoritative = false;
                }
            }
            LookupResult::ServerFailure => {
                if m.answers.is_empty() {
                    return Ok(ResponseCode::ServFail);
                }
                m.metadata.response_code = ResponseCode::ServFail;
            }
        }

        w.write_msg(m)
            .await
            .map_err(|e| PluginError::servfail("file", e.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}
