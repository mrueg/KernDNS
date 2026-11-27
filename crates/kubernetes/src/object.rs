//! The minimal objects kept from the API, like `plugin/kubernetes/object`:
//! only what DNS needs, never whole API objects.

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct ServicePort {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub port: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Service {
    pub name: String,
    pub namespace: String,
    /// `name.namespace`.
    #[serde(default)]
    pub index: String,
    #[serde(rename = "ClusterIPs", default, deserialize_with = "null_vec")]
    pub cluster_ips: Vec<String>,
    /// `ClusterIP`, `NodePort`, `LoadBalancer` or `ExternalName`.
    #[serde(rename = "Type", default)]
    pub type_: String,
    #[serde(default)]
    pub external_name: String,
    #[serde(default, deserialize_with = "null_vec")]
    pub ports: Vec<ServicePort>,
    #[serde(rename = "ExternalIPs", default, deserialize_with = "null_vec")]
    pub external_ips: Vec<String>,
}

fn null_vec<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

pub const EXTERNAL_NAME: &str = "ExternalName";

impl Service {
    pub fn key(name: &str, namespace: &str) -> String {
        format!("{name}.{namespace}")
    }

    /// `clusterIP: None`.
    pub fn headless(&self) -> bool {
        self.cluster_ips.first().is_some_and(|ip| ip == "None")
    }

    pub fn is_external_name(&self) -> bool {
        self.type_ == EXTERNAL_NAME
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EndpointAddress {
    #[serde(rename = "IP")]
    pub ip: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub target_ref_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EndpointPort {
    pub port: i32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EndpointSubset {
    #[serde(default, deserialize_with = "null_vec")]
    pub addresses: Vec<EndpointAddress>,
    #[serde(default, deserialize_with = "null_vec")]
    pub ports: Vec<EndpointPort>,
}

/// One EndpointSlice, keyed to its service by `index`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Endpoints {
    pub name: String,
    pub namespace: String,
    /// `service.namespace`, from the `kubernetes.io/service-name` label.
    pub index: String,
    #[serde(rename = "IndexIP", default, deserialize_with = "null_vec")]
    pub index_ip: Vec<String>,
    #[serde(default, deserialize_with = "null_vec")]
    pub subsets: Vec<EndpointSubset>,
    #[serde(default, deserialize_with = "null_map")]
    pub zones: HashMap<String, String>,
}

fn null_map<'de, D: serde::Deserializer<'de>>(d: D) -> Result<HashMap<String, String>, D::Error> {
    Ok(Option::<HashMap<String, String>>::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Pod {
    #[serde(rename = "PodIPs", default, deserialize_with = "null_vec")]
    pub pod_ips: Vec<String>,
    pub name: String,
    pub namespace: String,
}

/// Convert API objects (k8s-openapi) to the minimal objects.
pub mod convert {
    use super::*;
    use k8s_openapi::api::core::v1 as core;
    use k8s_openapi::api::discovery::v1 as discovery;

    pub fn service(s: &core::Service) -> Service {
        let name = s.metadata.name.clone().unwrap_or_default();
        let namespace = s.metadata.namespace.clone().unwrap_or_default();
        let spec = s.spec.clone().unwrap_or_default();
        let cluster_ips = match spec.cluster_ips.filter(|v| !v.is_empty()) {
            Some(v) => v,
            None => vec![spec.cluster_ip.unwrap_or_default()],
        };
        let ports = match spec.ports.filter(|p| !p.is_empty()) {
            Some(ps) => ps
                .into_iter()
                .map(|p| ServicePort {
                    name: p.name.unwrap_or_default(),
                    protocol: p.protocol.unwrap_or_else(|| "TCP".into()),
                    port: p.port,
                })
                .collect(),
            None => vec![ServicePort {
                port: -1,
                ..Default::default()
            }],
        };
        let mut external_ips = spec.external_ips.unwrap_or_default();
        if let Some(ing) = s
            .status
            .as_ref()
            .and_then(|st| st.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
        {
            for i in ing {
                external_ips.push(i.ip.clone().or_else(|| i.hostname.clone()).unwrap_or_default());
            }
        }
        Service {
            index: Service::key(&name, &namespace),
            name,
            namespace,
            cluster_ips,
            type_: spec.type_.unwrap_or_else(|| "ClusterIP".into()),
            external_name: spec.external_name.unwrap_or_default(),
            ports,
            external_ips,
        }
    }

    pub const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

    pub fn endpoint_slice(e: &discovery::EndpointSlice, with_zones: bool) -> Endpoints {
        let name = e.metadata.name.clone().unwrap_or_default();
        let namespace = e.metadata.namespace.clone().unwrap_or_default();
        let svc = e
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(SERVICE_NAME_LABEL))
            .cloned()
            .unwrap_or_default();
        let ports = match e.ports.as_ref().filter(|p| !p.is_empty()) {
            Some(ps) => ps
                .iter()
                .map(|p| EndpointPort {
                    port: p.port.unwrap_or(-1),
                    name: p.name.clone().unwrap_or_default(),
                    protocol: p.protocol.clone().unwrap_or_default(),
                })
                .collect(),
            None => vec![EndpointPort {
                port: -1,
                ..Default::default()
            }],
        };
        let mut sub = EndpointSubset {
            addresses: Vec::new(),
            ports,
        };
        let mut index_ip = Vec::new();
        let mut zones = HashMap::new();
        for end in e.endpoints.iter().flatten() {
            // a missing ready condition means ready
            if end.conditions.as_ref().and_then(|c| c.ready) == Some(false) {
                continue;
            }
            for a in &end.addresses {
                let target = end
                    .target_ref
                    .as_ref()
                    .and_then(|t| t.name.clone())
                    .filter(|n| n.len() < 64);
                sub.addresses.push(EndpointAddress {
                    ip: a.clone(),
                    hostname: end.hostname.clone().unwrap_or_default(),
                    node_name: end.node_name.clone().unwrap_or_default(),
                    target_ref_name: target.unwrap_or_default(),
                });
                if with_zones && let Some(z) = &end.zone {
                    zones.insert(a.clone(), z.to_ascii_lowercase());
                }
                index_ip.push(a.clone());
            }
        }
        Endpoints {
            index: Service::key(&svc, &namespace),
            name,
            namespace,
            index_ip,
            subsets: vec![sub],
            zones,
        }
    }

    /// `None` for a terminating pod (it is removed from the index).
    pub fn pod(p: &core::Pod) -> Option<Pod> {
        if p.metadata.deletion_timestamp.is_some() {
            return None;
        }
        Some(Pod {
            pod_ips: p
                .status
                .as_ref()
                .and_then(|s| s.pod_ips.as_ref())
                .map(|ips| ips.iter().map(|i| i.ip.clone()).collect())
                .unwrap_or_default(),
            name: p.metadata.name.clone().unwrap_or_default(),
            namespace: p.metadata.namespace.clone().unwrap_or_default(),
        })
    }
}
