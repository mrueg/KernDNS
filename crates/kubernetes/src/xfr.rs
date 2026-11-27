//! Zone transfers of the cluster zone, a port of
//! `plugin/kubernetes/xfr.go` (`Kubernetes.Transfer`): the `transfer`
//! plugin asks every source of the block, and this one answers for the
//! plugin's zones.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use kerndns_core::proto::rr::rdata::{A, AAAA, NS};
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record};
use kerndns_core::transfer::{TransferError, Transferer};
use kerndns_plugins::backend::{self, HostType, Service};

use crate::{Kubernetes, SVC, endpoint_hostname};

/// `kubernetes` as a zone source for `transfer`.
pub struct KubeTransfer(pub Arc<Kubernetes>);

impl Transferer for KubeTransfer {
    fn transfer(&self, zone: &str, serial: u32) -> Result<Vec<Vec<Record>>, TransferError> {
        self.0.transfer(zone, serial)
    }
}

fn rr(owner: &str, ttl: u32, data: RData) -> Record {
    let mut r = Record::from_rdata(Name::from_ascii(owner).unwrap_or_else(|_| Name::root()), ttl, data);
    r.dns_class = DNSClass::IN;
    r
}

/// An A/AAAA record (no TTL, like the `dns.RR`s `nsAddrs` builds).
pub(crate) fn address_record(owner: &str, ip: IpAddr, ttl: u32) -> Record {
    match ip {
        IpAddr::V4(v4) => rr(owner, ttl, RData::A(A(v4))),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => rr(owner, ttl, RData::A(A(v4))),
            None => rr(owner, ttl, RData::AAAA(AAAA(v6))),
        },
    }
}

/// `emitAddressRecord`: the A or AAAA record for `s` named after its key,
/// and that name ("" when the host isn't an address).
fn emit_address_record(out: &mut Vec<Vec<Record>>, s: &Service) -> String {
    let name = backend::domain(&s.key);
    match s.host_type() {
        HostType::A(ip) => {
            out.push(vec![s.new_a(&name, ip)]);
            name
        }
        HostType::Aaaa(ip) => {
            out.push(vec![s.new_aaaa(&name, ip)]);
            name
        }
        _ => String::new(),
    }
}

/// `calcSRVWeight`: the weight `plugin.SRV` gives each of `n` records of
/// the same priority.
fn calc_srv_weight(n: usize) -> u16 {
    ((100.0 / (n as f64 * 100.0)) * 100.0).floor().max(1.0) as u16
}

fn join_key(parts: &[&str]) -> String {
    parts.join("/")
}

impl Kubernetes {
    /// `Transfer`: the zone's records in transfer order.
    pub fn transfer(&self, zone: &str, serial: u32) -> Result<Vec<Vec<Record>>, TransferError> {
        // `plugin.Zones.Contains`: the zone or a name below one of ours
        let zone_lc = zone.to_ascii_lowercase();
        if !self
            .zones
            .iter()
            .any(|z| kerndns_core::zones::is_subdomain(z, &zone_lc))
        {
            return Err(TransferError::NotAuthoritative);
        }
        let soa = backend::soa(self, zone, &self.dummy_state(zone));
        let mut out = Vec::new();
        let soa_serial = match soa.first().map(|r| &r.data) {
            Some(RData::SOA(s)) => s.serial,
            _ => 0,
        };
        // ixfr fallback
        if serial != 0 && soa_serial == serial {
            out.push(soa);
            return Ok(out);
        }
        out.push(soa.clone());

        let ns_addrs = self.ns_addrs(zone);
        let mut ns_hosts = HashSet::new();
        for (host, _) in &ns_addrs {
            if ns_hosts.insert(host.clone()) {
                let target = Name::from_ascii(host).unwrap_or_else(|_| Name::root());
                out.push(vec![rr(zone, self.ttl, RData::NS(NS(target)))]);
            }
        }
        out.push(ns_addrs.iter().map(|(host, ip)| address_record(host, *ip, 0)).collect());

        let zone_path = backend::path(zone, "coredns");
        self.transfer_services(&mut out, &zone_path);

        out.push(soa);
        Ok(out)
    }

    fn transfer_services(&self, out: &mut Vec<Vec<Record>>, zone_path: &str) {
        let Some(api) = self.api() else { return };
        let mut services = api.service_list();
        services.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.namespace.cmp(&b.namespace)));

        for svc in services {
            if !self.namespace_exposed(&svc.namespace) {
                continue;
            }
            let base = [zone_path, SVC, svc.namespace.as_str(), svc.name.as_str()];
            match svc.type_.as_str() {
                "ClusterIP" | "NodePort" | "LoadBalancer" => {
                    let has_cluster_ip = svc.cluster_ips.first().and_then(|ip| backend::parse_ip(ip)).is_some();
                    if has_cluster_ip {
                        let mut host = String::new();
                        for ip in &svc.cluster_ips {
                            let s = Service {
                                host: ip.clone(),
                                ttl: self.ttl,
                                key: join_key(&base),
                                ..Default::default()
                            };
                            // the SRV records point at the address record's name
                            host = emit_address_record(out, &s);
                        }
                        for p in &svc.ports {
                            let mut s = Service {
                                host: host.clone(),
                                port: p.port,
                                ttl: self.ttl,
                                key: join_key(&base),
                                ..Default::default()
                            };
                            // needed for peer-finder (coredns/coredns#823)
                            out.push(vec![s.new_srv(&backend::domain(&s.key), 100)]);
                            // unnamed ports have no SRV record of their own
                            if p.name.is_empty() {
                                continue;
                            }
                            let proto = format!("_{}", p.protocol).to_lowercase();
                            let name = format!("_{}", p.name).to_lowercase();
                            s.key = join_key(&[&base[..], &[proto.as_str(), name.as_str()]].concat());
                            out.push(vec![s.new_srv(&backend::domain(&s.key), 100)]);
                        }
                        // no endpoints for a service with a cluster IP
                        continue;
                    }
                    for ep in api.ep_index(&format!("{}.{}", svc.name, svc.namespace)) {
                        for sub in &ep.subsets {
                            let weight = calc_srv_weight(sub.addresses.len());
                            for addr in &sub.addresses {
                                let mut s = Service {
                                    host: addr.ip.clone(),
                                    ttl: self.ttl,
                                    key: join_key(&base),
                                    ..Default::default()
                                };
                                emit_address_record(out, &s);
                                let hostname = endpoint_hostname(addr, self.endpoint_name_mode);
                                s.key = join_key(&[&base[..], &[hostname.as_str()]].concat());
                                s.host = emit_address_record(out, &s);
                                for p in &sub.ports {
                                    if p.name.is_empty() {
                                        continue;
                                    }
                                    s.port = p.port;
                                    let proto = format!("_{}", p.protocol).to_lowercase();
                                    let name = format!("_{}", p.name).to_lowercase();
                                    s.key = join_key(&[&base[..], &[proto.as_str(), name.as_str()]].concat());
                                    out.push(vec![s.new_srv(&backend::domain(&s.key), weight)]);
                                }
                            }
                        }
                    }
                }
                "ExternalName" => {
                    let s = Service {
                        key: join_key(&base),
                        host: svc.external_name.clone(),
                        ttl: self.ttl,
                        ..Default::default()
                    };
                    if s.host_type() == HostType::Cname {
                        out.push(vec![s.new_cname(&backend::domain(&s.key), &s.host)]);
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srv_weights() {
        assert_eq!(calc_srv_weight(1), 100);
        assert_eq!(calc_srv_weight(2), 50);
        assert_eq!(calc_srv_weight(6), 16);
        assert_eq!(calc_srv_weight(200), 1);
    }
}
