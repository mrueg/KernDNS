//! `sign`: signs zone files offline, on a schedule, into `db.<zone>.signed`
//! files for `file` or `auto` to serve. Port of `plugin/sign`.
//!
//! *sign* adds a DNSKEY, CDS and CDNSKEY records for each key, an NSEC
//! chain over the authoritative names and an RRSIG for every
//! authoritative RRset, and sets the SOA serial to the signing time. A
//! zone is (re)signed at startup and every 5 hours when the signed file is
//! missing, its SOA signature's inception is more than 6 days ago, or it
//! expires within 7 days. It adds no handler to the chain.

mod present;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kerndns_core::proto::dnssec::rdata::{CDNSKEY, CDS, DNSSECRData, NSEC};
use kerndns_core::proto::dnssec::{DigestType, PublicKey};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::request::lower_fqdn;
use kerndns_core::{Controller, PluginFactory, SetupError, info, warning, zones};

use crate::dnssec::{Key, key_base, read_key};
use crate::file::zone::{ZoneData, rrsig_covers};
use crate::file::zonefile::parse_zone;
pub use present::{rr_string, sig_time_string};

const NAME: &str = "sign";

/// Max time allowed before expiration.
const DURATION_EXPIRE_DAYS: i64 = 7 * 24 * 3600;
/// If the last signing happened this long ago, sign again.
const DURATION_RESIGN_DAYS: i64 = 6 * 24 * 3600;
/// Sign for 32 days.
const DURATION_SIGNATURE_EXPIRE_DAYS: i64 = 32 * 24 * 3600;
/// Check zones every 5 hours.
const DURATION_REFRESH_HOURS: Duration = Duration::from_secs(5 * 3600);
/// Default max jitter for the inception (negative).
const DURATION_INCEPTION_JITTER: i64 = -18 * 3600;
/// Default max jitter for the expiration.
const DURATION_EXPIRATION_DAY_JITTER: i64 = 5 * 24 * 3600;
/// -(2+1) hours, to catch daylight saving time and such; jitter is subtracted.
const DURATION_SIGNATURE_INCEPTION_HOURS: i64 = -3 * 3600;

/// Signs one zone file for one origin.
#[derive(Debug, Clone)]
pub struct Signer {
    pub keys: Vec<Key>,
    pub origin: String,
    pub dbfile: PathBuf,
    pub directory: PathBuf,
    /// Seconds (0 to -18h).
    pub jitter_incep: i64,
    /// Seconds (0 to 5 days).
    pub jitter_expir: i64,
    pub signedfile: String,
}

fn unix(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// A random number in [0, 1), like `rand.Float32`.
fn random_f32() -> f32 {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 4];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    (u32::from_le_bytes(b) >> 8) as f32 / (1u32 << 24) as f32
}

/// `lifetime`: inception and expiration of signatures made at `now`.
pub fn lifetime(now: SystemTime, jitter_incep: i64, jitter_expir: i64) -> (u32, u32) {
    let now = unix(now);
    let incep = now + DURATION_SIGNATURE_INCEPTION_HOURS + jitter_incep;
    let expir = now + DURATION_SIGNATURE_EXPIRE_DAYS + jitter_expir;
    (incep as u32, expir as u32)
}

/// `Parse`: read a zone like `file` does, but without DNSKEY, RRSIG,
/// CDNSKEY and CDS records (they are made by signing).
pub fn parse(text: &str, origin: &str, file: &Path) -> Result<ZoneData, String> {
    let origin_name = Name::from_ascii(origin).map_err(|e| e.to_string())?;
    let records = parse_zone(text, &origin_name, file).map_err(|e| e.0)?;
    let mut z = ZoneData::default();
    let mut seen_soa = false;
    for rr in records {
        match rr.record_type() {
            RecordType::DNSKEY | RecordType::RRSIG | RecordType::CDNSKEY | RecordType::CDS => continue,
            RecordType::SOA => seen_soa = true,
            _ => {}
        }
        z.insert(&origin_name, rr)?;
    }
    if !seen_soa {
        return Err(format!("file {:?} has no SOA record", file.display().to_string()));
    }
    Ok(z)
}

/// `AuthWalk`: the names of the tree in canonical order, with whether each
/// is authoritative (not below a delegation).
pub fn auth_walk(z: &ZoneData) -> Vec<(Name, bool)> {
    let mut cuts: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for e in z.tree.elems() {
        let name = lower_fqdn(e.name());
        if e.has(RecordType::NS) {
            cuts.insert(name.clone());
        }
        let mut auth = true;
        let mut parent = e.name().base_name();
        loop {
            if cuts.contains(&lower_fqdn(&parent)) {
                auth = false;
                break;
            }
            if parent.is_root() {
                break;
            }
            parent = parent.base_name();
        }
        out.push((e.name().clone(), auth));
    }
    out
}

/// `names`: the authoritative names of the zone, in NSEC order.
pub fn names(z: &ZoneData) -> Vec<Name> {
    auth_walk(z).into_iter().filter(|(_, a)| *a).map(|(n, _)| n).collect()
}

/// `NSEC`: an NSEC record for `name` pointing to `next`.
pub fn nsec(name: &Name, next: &Name, ttl: u32, bitmap: Vec<RecordType>) -> Record {
    let mut r = Record::from_rdata(
        name.clone(),
        ttl,
        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next.clone(), bitmap))),
    );
    r.dns_class = DNSClass::IN;
    r
}

/// The types present at a name, in numeric order.
fn types_of(z: &ZoneData, name: &Name) -> Vec<RecordType> {
    let Some(e) = z.tree.search(name) else {
        return Vec::new();
    };
    let mut t: Vec<RecordType> = e
        .all()
        .map(Record::record_type)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    t.sort_by_key(|t| u16::from(*t));
    t
}

impl Signer {
    /// `Sign`: read and sign the zone file at `now`.
    pub fn sign(&self, now: SystemTime) -> Result<ZoneData, String> {
        let text = std::fs::read_to_string(&self.dbfile).map_err(|e| open_error(&self.dbfile, &e))?;
        let mut z = parse(&text, &self.origin, &self.dbfile)?;
        let origin = Name::from_ascii(&self.origin).map_err(|e| e.to_string())?;

        let soa = z.apex.soa.as_mut().ok_or("no SOA record")?;
        let RData::SOA(soa_data) = &mut soa.data else {
            return Err("no SOA record".into());
        };
        let mttl = soa_data.minimum;
        let ttl = soa.ttl;
        let (inception, expiration) = lifetime(now, self.jitter_incep, self.jitter_expir);
        soa_data.serial = unix(now) as u32;

        for pair in &self.keys {
            let mut public = pair.record.clone();
            public.ttl = ttl; // so the key matches its RRSIG
            public.name = origin.clone();
            let dnskey = pair.dnskey();
            let alg = dnskey.public_key().algorithm();
            z.insert(&origin, public.clone())?;
            for dt in [DigestType::SHA1, DigestType::SHA256] {
                let digest = dnskey.to_digest(&origin, dt).map_err(|e| e.to_string())?;
                let cds = CDS::new(pair.tag, Some(alg), dt, digest.as_ref().to_vec());
                let mut r = Record::from_rdata(origin.clone(), ttl, RData::DNSSEC(DNSSECRData::CDS(cds)));
                r.dns_class = DNSClass::IN;
                z.insert(&origin, r)?;
            }
            let cdnskey = CDNSKEY::with_flags(dnskey.flags(), Some(alg), dnskey.public_key().public_bytes().to_vec());
            let mut r = Record::from_rdata(origin.clone(), ttl, RData::DNSSEC(DNSSECRData::CDNSKEY(cdnskey)));
            r.dns_class = DNSClass::IN;
            z.insert(&origin, r)?;
        }

        let names = names(&z);
        let ln = names.len();

        let soa = z.apex.soa.clone().ok_or("no SOA record")?;
        let ns = z.apex.ns.clone();
        for pair in &self.keys {
            let sig = pair.sign(std::slice::from_ref(&soa), &origin, ttl, ttl, inception, expiration)?;
            z.insert(&origin, sig)?;
            // the apex NS may be missing if its records were dropped because the origin doesn't match
            if !ns.is_empty() {
                let sig = pair.sign(&ns, &origin, ttl, ttl, inception, expiration)?;
                z.insert(&origin, sig)?;
            }
        }

        // The walk below visits names in the same order as names[], so
        // names[i] is the next name.
        let mut i = 1;
        for (name, auth) in auth_walk(&z) {
            if !auth {
                continue;
            }
            let mut bitmap = types_of(&z, &name);
            if name == origin {
                bitmap.extend([RecordType::NS, RecordType::SOA]);
            }
            bitmap.extend([RecordType::RRSIG, RecordType::NSEC]);
            z.insert(&origin, nsec(&name, &names[i % ln], mttl, bitmap))?;

            // RRSIGs are not signed, and neither are NS records: we are never
            // authoritative for them (the apex NS is signed above).
            let sets: Vec<Vec<Record>> = types_of(&z, &name)
                .into_iter()
                .filter(|t| *t != RecordType::RRSIG && *t != RecordType::NS)
                .filter_map(|t| z.tree.search(&name).map(|e| e.typ(t).to_vec()))
                .collect();
            for rrs in sets {
                for pair in &self.keys {
                    let sig = pair.sign(&rrs, &origin, rrs[0].ttl, rrs[0].ttl, inception, expiration)?;
                    z.insert(&origin, sig)?;
                }
            }
            i += 1;
        }
        Ok(z)
    }

    /// `resign`: does the signed zone need (re)signing? `Err` says why.
    pub fn resign(&self) -> Result<(), String> {
        let signedfile = self.directory.join(&self.signedfile);
        let text = std::fs::read_to_string(&signedfile).map_err(|e| open_error(&signedfile, &e))?;
        resign(&text, SystemTime::now())
    }

    /// Write the zone to a temporary file and move it into place.
    pub fn write(&self, z: &ZoneData) -> Result<(), String> {
        let tmp = self.directory.join(format!(
            "signed-{}-{:08x}",
            std::process::id(),
            (random_f32() * u32::MAX as f32) as u32
        ));
        let text = write(z);
        if let Err(e) = std::fs::write(&tmp, text) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
        std::fs::rename(&tmp, self.directory.join(&self.signedfile)).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })
    }
}

/// The zone in master file format: SOA, its signatures, NS, their
/// signatures, then every name in canonical order.
pub fn write(z: &ZoneData) -> String {
    let mut out = String::new();
    let mut line = |r: &Record| {
        out.push_str(&rr_string(r));
        out.push('\n');
    };
    if let Some(soa) = &z.apex.soa {
        line(soa);
    }
    z.apex.sig_soa.iter().for_each(&mut line);
    z.apex.ns.iter().for_each(&mut line);
    z.apex.sig_ns.iter().for_each(&mut line);
    for e in z.tree.elems() {
        let mut types: Vec<RecordType> = e
            .all()
            .map(Record::record_type)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        types.sort_by_key(|t| u16::from(*t));
        for t in types {
            e.typ(t).iter().for_each(&mut line);
        }
    }
    out
}

fn open_error(path: &Path, e: &std::io::Error) -> String {
    let msg = match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        _ => e.to_string(),
    };
    format!("open {}: {msg}", path.display())
}

/// Go's `time.Duration` string for seconds.
fn go_duration(secs: i64) -> String {
    let d = kerndns_core::duration::format_duration(Duration::from_secs(secs.unsigned_abs()));
    if secs < 0 { format!("-{d}") } else { d }
}

/// `timeFmt` (`2006-01-02T15:04:05.000Z07:00`) in UTC.
pub fn time_fmt(t: i64) -> String {
    let s = sig_time_string(t);
    format!(
        "{}-{}-{}T{}:{}:{}.000Z",
        &s[0..4],
        &s[4..6],
        &s[6..8],
        &s[8..10],
        &s[10..12],
        &s[12..14]
    )
}

/// `resign`: scan a signed zone for its SOA signatures. Sign again when
/// the inception is more than 6 days ago or in the future, or when less
/// than 7 days are left before expiration. Only the first 100 records
/// are looked at.
pub fn resign(text: &str, now: SystemTime) -> Result<(), String> {
    let records = parse_zone(text, &Name::root(), Path::new("resign")).map_err(|e| e.0)?;
    let now = unix(now);
    for (i, rr) in records.iter().enumerate() {
        if let RData::DNSSEC(DNSSECRData::RRSIG(x)) = &rr.data
            && rrsig_covers(rr) == Some(RecordType::SOA)
        {
            let incep = serial_time(x.input().sig_inception.get(), now);
            let since = now - incep;
            if since > DURATION_RESIGN_DAYS {
                return Err(format!(
                    "inception {:?} was more than: {} ago from {}: {}",
                    time_fmt(incep),
                    go_duration(DURATION_RESIGN_DAYS),
                    time_fmt(now),
                    go_duration(since)
                ));
            }
            if since < 0 {
                return Err(format!(
                    "inception {:?} date is in the future: {}",
                    time_fmt(incep),
                    go_duration(since)
                ));
            }
            let expire = serial_time(x.input().sig_expiration.get(), now);
            if expire - now < DURATION_EXPIRE_DAYS {
                return Err(format!(
                    "expiration {:?} is less than: {} away from {}: {}",
                    time_fmt(expire),
                    go_duration(DURATION_EXPIRE_DAYS),
                    time_fmt(now),
                    go_duration(expire - now)
                ));
            }
        }
        if i + 1 > 100 {
            // A SOA should come first, but RFC 1035 doesn't mandate it.
            return Err("no SOA RRSIG found in first 100 records".into());
        }
    }
    Ok(())
}

/// A 32-bit signature time as Unix seconds, like `dns.TimeToString`
/// reads it.
fn serial_time(t: u32, now: i64) -> i64 {
    const YEAR68: i64 = 1 << 31;
    let t = i64::from(t);
    let m = ((t - now) / YEAR68 - 1).max(0);
    t - m * YEAR68
}

/// `keyTag`: the key tags as a comma-separated list.
fn key_tags(keys: &[Key]) -> String {
    keys.iter().map(|k| k.tag.to_string()).collect::<Vec<_>>().join(",")
}

/// `signAndLog`.
pub fn sign_and_log(s: &Signer, why: &str) {
    let now = SystemTime::now();
    let start = Instant::now();
    let res = s.sign(now);
    info!(plugin = NAME, "Signing {:?} because {}", s.origin, why);
    let next = time_fmt(unix(now) + DURATION_REFRESH_HOURS.as_secs() as i64);
    let z = match res {
        Ok(z) => z,
        Err(e) => {
            warning!(
                plugin = NAME,
                "Error signing {:?} with key tags {:?} in {}: {}, next: {}",
                s.origin,
                key_tags(&s.keys),
                kerndns_core::duration::format_duration(start.elapsed()),
                e,
                next
            );
            return;
        }
    };
    if let Err(e) = s.write(&z) {
        warning!(
            plugin = NAME,
            "Error signing {:?}: failed to move zone file into place: {}",
            s.origin,
            e
        );
        return;
    }
    info!(
        plugin = NAME,
        "Successfully signed zone {:?} in {:?} with key tags {:?} and {} SOA serial, elapsed {:.6}, next: {}",
        s.origin,
        s.directory.join(&s.signedfile).display().to_string(),
        key_tags(&s.keys),
        z.apex.serial().unwrap_or(0),
        start.elapsed().as_secs_f64(),
        next
    );
}

/// `Sign`: the signers of one `sign` block (or several).
#[derive(Debug, Default)]
pub struct Sign {
    pub signers: Vec<Signer>,
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let sign = parse_sign(c)?;
        let signers: Arc<Vec<Signer>> = Arc::new(sign.signers);
        let tasks: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        {
            let signers = signers.clone();
            let tasks = tasks.clone();
            c.on_startup(move || {
                let mut tasks = tasks.lock().unwrap();
                // OnStartup: sign now what needs it, in the background.
                for s in signers.iter() {
                    match s.resign() {
                        Ok(()) => info!(
                            plugin = NAME,
                            "Skipping signing zone {:?} in {:?}: signatures are valid",
                            s.origin,
                            s.directory.join(&s.signedfile).display().to_string()
                        ),
                        Err(why) => {
                            let s = s.clone();
                            tasks.push(tokio::task::spawn_blocking(move || sign_and_log(&s, &why)).abort_handle());
                        }
                    }
                }
                // refresh: check every 5 hours.
                for s in signers.iter() {
                    let s = s.clone();
                    let t = tokio::spawn(async move {
                        let every = DURATION_REFRESH_HOURS;
                        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
                        loop {
                            tick.tick().await;
                            let s = s.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                if let Err(why) = s.resign() {
                                    sign_and_log(&s, &why);
                                }
                            })
                            .await;
                        }
                    });
                    tasks.push(t.abort_handle());
                }
                Ok(())
            });
        }
        c.on_shutdown(move || {
            for t in tasks.lock().unwrap().drain(..) {
                t.abort();
            }
        });
        // *sign* adds no handler to the chain.
        Ok(())
    }
}

/// `parse`.
pub fn parse_sign(c: &mut Controller<'_>) -> Result<Sign, SetupError> {
    let err = |m: String| SetupError::new(NAME, m);
    let mut sign = Sign::default();
    let server_keys = c.server_block_keys();
    let root = c.config.root.clone();

    while c.next() {
        if !c.next_arg() {
            return Err(c.arg_err());
        }
        let mut dbfile = PathBuf::from(c.val());
        if dbfile.is_relative()
            && let Some(r) = &root
        {
            dbfile = r.join(dbfile);
        }
        // An invalid path could cause an endless signing loop.
        if dbfile.to_string_lossy().contains('\u{FFFD}') {
            return Err(err(format!(
                "dbfile {:?} contains invalid characters",
                dbfile.display().to_string()
            )));
        }

        let args = c.remaining_args();
        let origins = zones::origins_from_args_or_server_block(&args, &server_keys);
        let mut signers: Vec<Signer> = origins
            .iter()
            .map(|o| Signer {
                keys: Vec::new(),
                origin: o.clone(),
                dbfile: dbfile.clone(),
                directory: PathBuf::from("/var/lib/coredns"),
                jitter_incep: (DURATION_INCEPTION_JITTER as f32 * random_f32()) as i64,
                jitter_expir: (DURATION_EXPIRATION_DAY_JITTER as f32 * random_f32()) as i64,
                // the origin ends with a dot, hence "db.<origin>signed"
                signedfile: format!("db.{o}signed"),
            })
            .collect();

        while c.next_block() {
            match c.val().to_string().as_str() {
                "key" => {
                    let pairs = key_parse(c)?;
                    for s in &mut signers {
                        let origin = Name::from_ascii(&s.origin).map_err(|e| err(e.to_string()))?;
                        for p in &pairs {
                            let mut p = p.clone();
                            p.record.name = origin.clone();
                            s.keys.push(p);
                        }
                    }
                }
                "directory" => {
                    let dir = c.remaining_args();
                    if dir.len() != 1 {
                        return Err(err("can only be one argument after \"directory\"".into()));
                    }
                    let mut d = PathBuf::from(&dir[0]);
                    if d.is_relative()
                        && let Some(r) = &root
                    {
                        d = r.join(d);
                    }
                    for s in &mut signers {
                        s.directory = d.clone();
                        s.signedfile = format!("db.{}signed", s.origin);
                    }
                }
                x => return Err(c.errf(format!("unknown property '{x}'"))),
            }
        }
        sign.signers.extend(signers);
    }
    Ok(sign)
}

/// `keyParse`: `key file KEY...`; the keys must be CSKs/KSKs.
fn key_parse(c: &mut Controller<'_>) -> Result<Vec<Key>, SetupError> {
    let err = |m: String| SetupError::new(NAME, m);
    if !c.next_arg() {
        return Err(c.arg_err());
    }
    let mut pairs = Vec::new();
    match c.val() {
        "file" => {
            let ks = c.remaining_args();
            if ks.is_empty() {
                return Err(c.arg_err());
            }
            let root = c.config.root.clone();
            for k in ks {
                let base = key_base(&k, root.as_ref());
                let key = read_key_pair(&base).map_err(err)?;
                pairs.push(key);
            }
        }
        "directory" => return Err(err("directory: not implemented".into())),
        _ => {}
    }
    Ok(pairs)
}

/// `readKeyPair`: like `dnssec`'s key files, but only CSKs/KSKs.
fn read_key_pair(base: &Path) -> Result<Key, String> {
    let key = read_key(base)?;
    if !key.is_ksk() {
        return Err(format!(
            "DNSKEY in {:?} is not a CSK/KSK",
            format!("{}.key", base.display())
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests;
