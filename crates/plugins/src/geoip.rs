//! `geoip`: looks the client's address up in a MaxMind (`.mmdb`) database
//! and adds what it finds to the request's metadata. Port of
//! `plugin/geoip`, reading the database with the `maxminddb` crate.
//!
//! ```text
//! geoip [DBFILE] {
//!     [edns-subnet]
//! }
//! ```
//!
//! City databases set `geoip/city/name`, `geoip/country/code`,
//! `geoip/country/name`, `geoip/country/is_in_european_union`,
//! `geoip/continent/code`, `geoip/continent/name`, `geoip/latitude`,
//! `geoip/longitude`, `geoip/timezone`, `geoip/postalcode` and
//! `geoip/subdivisions/code`; ASN databases `geoip/asn/number` and
//! `geoip/asn/org`. The `metadata` plugin must be enabled.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use kerndns_core::plugin::{Metadata, MetadataProvider};
use kerndns_core::proto::rr::rdata::opt::EdnsOption;
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};
use maxminddb::{MaxMindDbError, Reader};
use serde::Deserialize;

const NAME: &str = "geoip";

const CITY: u8 = 1;
const ASN: u8 = 2;

/// The schemas a database type supports, like geoip2-golang's
/// `getDBType` (City lookups also work on Country databases).
fn db_type(t: &str) -> Result<u8, String> {
    Ok(match t {
        "DBIP-ASN-Lite (compat=GeoLite2-ASN)" | "GeoLite2-ASN" => ASN,
        "DBIP-City-Lite"
        | "DBIP-Country-Lite"
        | "DBIP-Country"
        | "DBIP-Location (compat=City)"
        | "GeoLite2-City"
        | "GeoIP-City-Redacted-US"
        | "GeoIP2-City"
        | "GeoIP2-City-Africa"
        | "GeoIP2-City-Asia-Pacific"
        | "GeoIP2-City-Europe"
        | "GeoIP2-City-North-America"
        | "GeoIP2-City-South-America"
        | "GeoIP2-Precision-City"
        | "GeoLite2-Country"
        | "GeoIP2-Country"
        | "DBIP-ISP (compat=Enterprise)"
        | "DBIP-Location-ISP (compat=Enterprise)"
        | "GeoIP-Enterprise-Redacted-US"
        | "GeoIP2-Enterprise" => CITY,
        "GeoIP2-ISP" | "GeoIP2-Precision-ISP" => ASN,
        // types geoip2-golang reads, but without a schema this plugin uses
        "GeoIP-Anonymous-Plus" | "GeoIP2-Anonymous-IP" | "GeoIP2-Connection-Type" | "GeoIP2-Domain" => 0,
        _ => return Err(format!("geoip2: reader does not support the {t:?} database type")),
    })
}

/// The fields of geoip2's `City` record the plugin uses. Like Go's
/// decoder, numbers of any unsigned width are accepted (the crate's own
/// structs insist on the widths MaxMind uses).
#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct CityRecord<'a> {
    #[serde(borrow)]
    city: Named<'a>,
    #[serde(borrow)]
    continent: Continent<'a>,
    #[serde(borrow)]
    country: Country<'a>,
    #[serde(borrow)]
    location: Location<'a>,
    #[serde(borrow)]
    postal: Postal<'a>,
    #[serde(borrow)]
    subdivisions: Vec<Subdivision<'a>>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Names<'a> {
    #[serde(borrow)]
    en: Option<&'a str>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Named<'a> {
    #[serde(borrow)]
    names: Names<'a>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Continent<'a> {
    #[serde(borrow)]
    code: Option<&'a str>,
    #[serde(borrow)]
    names: Names<'a>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Country<'a> {
    is_in_european_union: Option<bool>,
    #[serde(borrow)]
    iso_code: Option<&'a str>,
    #[serde(borrow)]
    names: Names<'a>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Location<'a> {
    latitude: Option<f64>,
    longitude: Option<f64>,
    #[serde(borrow)]
    time_zone: Option<&'a str>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Postal<'a> {
    #[serde(borrow)]
    code: Option<&'a str>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Subdivision<'a> {
    #[serde(borrow)]
    iso_code: Option<&'a str>,
}

/// geoip2's `ASN` record.
#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct AsnRecord<'a> {
    autonomous_system_number: Option<u64>,
    #[serde(borrow)]
    autonomous_system_organization: Option<&'a str>,
}

/// The database and the schemas it provides.
pub struct GeoIp {
    reader: Reader<Vec<u8>>,
    provides: u8,
    edns0: bool,
}

/// Go's `open` error text for a file that can't be read.
fn open_error(path: &str, e: &std::io::Error) -> String {
    let msg = match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        std::io::ErrorKind::IsADirectory => "is a directory".to_string(),
        _ => e.to_string(),
    };
    format!("open {path}: {msg}")
}

impl GeoIp {
    /// `newGeoIP`.
    pub fn open(path: &str, edns0: bool) -> Result<GeoIp, String> {
        let buf = std::fs::read(path).map_err(|e| format!("failed to open database file: {}", open_error(path, &e)))?;
        let reader = Reader::from_source(buf).map_err(|e| format!("failed to open database file: {e}"))?;
        let types =
            db_type(&reader.metadata().database_type).map_err(|e| format!("failed to open database file: {e}"))?;
        let probe: IpAddr = "127.0.0.1".parse().expect("valid");
        let base = Path::new(path)
            .file_name()
            .map_or(path.into(), |f| f.to_string_lossy().into_owned());
        let mut provides = 0;
        for (schema, bit) in [("city", CITY), ("asn", ASN)] {
            if types & bit == 0 {
                continue;
            }
            let r = match bit {
                CITY => lookup::<CityRecord>(&reader, probe).map(|_| ()),
                _ => lookup::<AsnRecord>(&reader, probe).map(|_| ()),
            };
            if let Err(e) = r {
                return Err(format!(
                    "unexpected failure looking up database {base:?} schema {schema:?}: {e}"
                ));
            }
            provides |= bit;
        }
        if provides == 0 {
            return Err("database does not provide any supported schema (city, asn)".into());
        }
        Ok(GeoIp {
            reader,
            provides,
            edns0,
        })
    }

    /// The address to look up: the client's, or the first EDNS0 client
    /// subnet's with `edns-subnet`.
    fn source(&self, req: &Request) -> IpAddr {
        let mut ip = req.ip();
        if self.edns0
            && let Some(e) = req.edns()
            && let Some(sub) = e.options().options.iter().find_map(|(_, o)| match o {
                EdnsOption::Subnet(s) => Some(s.addr()),
                _ => None,
            })
        {
            // miekg/dns keeps an IPv4 subnet in its 16-byte form, so
            // CoreDNS looks it up as an IPv4-mapped IPv6 address
            ip = match sub {
                IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
                v6 => v6,
            };
        }
        ip
    }

    /// `Metadata`: set the labels for the request's address.
    fn set_metadata(&self, ctx: &mut Context, req: &Request) {
        let ip = self.source(req);
        if self.provides & CITY != 0 {
            match lookup::<CityRecord>(&self.reader, ip) {
                Ok(c) => set_city(ctx, &c.unwrap_or_default()),
                Err(e) => kerndns_core::debug!(
                    plugin = NAME,
                    "Setting up city metadata failed due to database lookup error: {e}"
                ),
            }
        }
        if self.provides & ASN != 0 {
            match lookup::<AsnRecord>(&self.reader, ip) {
                Ok(a) => set_asn(ctx, a.as_ref()),
                Err(e) => kerndns_core::debug!(
                    plugin = NAME,
                    "Setting up asn metadata failed due to database lookup error: {e}"
                ),
            }
        }
    }
}

fn lookup<'a, T: serde::Deserialize<'a>>(reader: &'a Reader<Vec<u8>>, ip: IpAddr) -> Result<Option<T>, MaxMindDbError> {
    reader.lookup(ip)?.decode::<T>()
}

fn set(ctx: &mut Context, label: &str, v: impl Into<String>) {
    ctx.metadata.insert(format!("{NAME}/{label}"), v.into());
}

/// `setCityMetadata`.
fn set_city(ctx: &mut Context, c: &CityRecord<'_>) {
    set(ctx, "city/name", c.city.names.en.unwrap_or(""));
    set(ctx, "country/name", c.country.names.en.unwrap_or(""));
    set(ctx, "continent/name", c.continent.names.en.unwrap_or(""));
    set(ctx, "country/code", c.country.iso_code.unwrap_or(""));
    let subdivisions: Vec<&str> = c.subdivisions.iter().map(|s| s.iso_code.unwrap_or("")).collect();
    set(ctx, "subdivisions/code", subdivisions.join(","));
    set(
        ctx,
        "country/is_in_european_union",
        c.country.is_in_european_union.unwrap_or(false).to_string(),
    );
    set(ctx, "continent/code", c.continent.code.unwrap_or(""));
    set(
        ctx,
        "latitude",
        c.location.latitude.map(format_float).unwrap_or_default(),
    );
    set(
        ctx,
        "longitude",
        c.location.longitude.map(format_float).unwrap_or_default(),
    );
    set(ctx, "timezone", c.location.time_zone.unwrap_or(""));
    set(ctx, "postalcode", c.postal.code.unwrap_or(""));
}

/// `strconv.FormatFloat(f, 'f', -1, 64)`: the shortest decimal that
/// reads back as `f`, without an exponent.
fn format_float(f: f64) -> String {
    format!("{f}")
}

/// `setASNMetadata`.
fn set_asn(ctx: &mut Context, a: Option<&AsnRecord<'_>>) {
    set(
        ctx,
        "asn/number",
        a.and_then(|a| a.autonomous_system_number).unwrap_or(0).to_string(),
    );
    set(
        ctx,
        "asn/org",
        a.and_then(|a| a.autonomous_system_organization).unwrap_or(""),
    );
}

struct Provider(Arc<GeoIp>);

impl MetadataProvider for Provider {
    fn metadata(&self, ctx: &mut Context, req: &Request) {
        self.0.set_metadata(ctx, req);
    }
}

/// The handler: it only passes requests on; the work is in the metadata.
pub struct GeoIpPlugin {
    next: Next,
}

#[async_trait]
impl Handler for GeoIpPlugin {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        next_or_failure(NAME, &self.next, ctx, w, req).await
    }
}

/// `geoipParse`.
fn parse(c: &mut Controller<'_>) -> Result<GeoIp, SetupError> {
    let mut db_path = String::new();
    let mut edns0 = false;
    while c.next() {
        if !c.next_arg() {
            return Err(c.arg_err());
        }
        if !db_path.is_empty() {
            return Err(c.errf("configuring multiple databases is not supported"));
        }
        db_path = c.val().to_string();
        if !c.remaining_args().is_empty() {
            return Err(c.arg_err());
        }
        while c.next_block() {
            if c.val() != "edns-subnet" {
                let msg = format!("unknown property {:?}", c.val());
                return Err(c.errf(msg));
            }
            edns0 = true;
        }
    }
    GeoIp::open(&db_path, edns0).map_err(|e| c.errf(e))
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let g = Arc::new(parse(c)?);
        Metadata::of(c.config).add_provider(Arc::new(Provider(g)));
        c.add_plugin(|next| Arc::new(GeoIpPlugin { next }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::op::Edns;
    use kerndns_core::proto::rr::RecordType;
    use kerndns_core::proto::rr::rdata::opt::ClientSubnet;

    const TESTDATA: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../third_party/coredns/plugin/geoip/testdata"
    );

    fn db(name: &str) -> String {
        format!("{TESTDATA}/{name}")
    }

    fn city_db() -> String {
        db("GeoLite2-City.mmdb")
    }

    fn asn_db() -> String {
        db("GeoLite2-ASN.mmdb")
    }

    fn metadata_for(g: GeoIp, req: &Request) -> std::collections::HashMap<String, String> {
        let mut ctx = Context::new(".", "dns://:53");
        Provider(Arc::new(g)).metadata(&mut ctx, req);
        ctx.metadata
    }

    // geoip_test.go: TestMetadata
    #[test]
    fn metadata() {
        let tests = [
            ("geoip/city/name", "Cambridge", city_db(), "81.2.69.142"),
            ("geoip/country/code", "GB", city_db(), "81.2.69.142"),
            ("geoip/country/name", "United Kingdom", city_db(), "81.2.69.142"),
            ("geoip/country/is_in_european_union", "true", city_db(), "81.2.69.142"),
            ("geoip/continent/code", "EU", city_db(), "81.2.69.142"),
            ("geoip/continent/name", "Europe", city_db(), "81.2.69.142"),
            ("geoip/latitude", "52.2242", city_db(), "81.2.69.142"),
            ("geoip/longitude", "0.1315", city_db(), "81.2.69.142"),
            ("geoip/timezone", "Europe/London", city_db(), "81.2.69.142"),
            ("geoip/postalcode", "CB4", city_db(), "81.2.69.142"),
            ("geoip/subdivisions/code", "ENG,CAM", city_db(), "81.2.69.142"),
            ("geoip/asn/number", "12345", asn_db(), "81.2.69.142"),
            ("geoip/asn/org", "Test ASN Organization", asn_db(), "81.2.69.142"),
            ("geoip/asn/number", "0", asn_db(), "10.0.0.1"),
            ("geoip/asn/org", "Not routed", asn_db(), "10.0.0.1"),
        ];
        for (label, want, path, ip) in tests {
            // direct
            let g = GeoIp::open(&path, false).unwrap();
            let req = query("example.org.", RecordType::A, &format!("{ip}:53"));
            let md = metadata_for(g, &req);
            assert_eq!(md.get(label).map(String::as_str), Some(want), "{label} direct");

            // subnet
            let g = GeoIp::open(&path, true).unwrap();
            let mut req = query("example.org.", RecordType::A, "127.0.0.1:53");
            let mut e = Edns::new();
            e.set_max_payload(4096);
            e.options_mut()
                .insert(EdnsOption::Subnet(ClientSubnet::new(ip.parse().unwrap(), 32, 0)));
            req.msg.edns = Some(e);
            let md = metadata_for(g, &req);
            assert_eq!(md.get(label).map(String::as_str), Some(want), "{label} subnet");
        }
    }

    // geoip_test.go: TestMetadataUnknownIP
    #[test]
    fn unknown_ip() {
        let g = GeoIp::open(&asn_db(), false).unwrap();
        let req = query("example.org.", RecordType::A, "203.0.113.1:53");
        let md = metadata_for(g, &req);
        assert_eq!(md.get("geoip/asn/number").map(String::as_str), Some("0"));
        assert_eq!(md.get("geoip/asn/org").map(String::as_str), Some(""));
    }

    // setup_test.go: TestSetup
    #[test]
    fn setup() {
        let (r, cfg) = run_setup(&Setup, &format!("geoip {}", city_db()));
        r.unwrap();
        assert_eq!(cfg.plugins.len(), 1);
    }

    // setup_test.go: TestGeoIPParse
    #[test]
    fn geoip_parse() {
        let (city, asn) = (city_db(), asn_db());
        let ok = [
            (format!("geoip {city}\n"), CITY),
            (format!("geoip {city} {{ edns-subnet }}"), CITY),
            (format!("geoip {asn}\n"), ASN),
            (format!("geoip {asn} {{ edns-subnet }}"), ASN),
        ];
        for (input, want) in ok {
            let g = with_controller(NAME, &input, |c| parse(c).map_err(|e| e.to_string())).unwrap();
            assert_ne!(g.provides & want, 0, "{input}");
        }
        let bad = [
            ("geoip".to_string(), "Wrong argument count"),
            (
                format!("geoip {city} {{\n\tlanguages en fr es zh-CN\n}}\n"),
                "unknown property \"languages\"",
            ),
            (
                format!("geoip {city}\ngeoip {city}\n"),
                "configuring multiple databases is not supported",
            ),
            ("geoip 1 2 3".to_string(), "Wrong argument count"),
            ("geoip { }".to_string(), "Error during parsing"),
            ("geoip /dbpath { city }".to_string(), "unknown property \"city\""),
            (
                "geoip /invalidPath\n".to_string(),
                "failed to open database file: open /invalidPath: no such file or directory",
            ),
            (
                format!("geoip {}\n", db("GeoLite2-UnknownDbType.mmdb")),
                "reader does not support the \"UnknownDbType\" database type",
            ),
        ];
        for (input, want) in bad {
            let e =
                with_controller(NAME, &input, |c| parse(c).map(|_| ()).map_err(|e| e.to_string())).expect_err(&input);
            assert!(e.contains(want), "{input}: {e}");
            assert!(e.starts_with("plugin/geoip: "), "{e}");
        }
    }

    #[test]
    fn floats_like_go() {
        assert_eq!(format_float(52.2242), "52.2242");
        assert_eq!(format_float(-0.5), "-0.5");
        assert_eq!(format_float(52.0), "52");
    }
}
