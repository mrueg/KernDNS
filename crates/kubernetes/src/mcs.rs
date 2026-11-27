//! The Multi-Cluster Services API's ServiceImport
//! (`multicluster.x-k8s.io/v1alpha1`, sigs.k8s.io/mcs-api), the part
//! `multicluster` reads.

use std::borrow::Cow;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServiceImport {
    #[serde(default)]
    pub metadata: ObjectMeta,
    pub spec: Option<ServiceImportSpec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServiceImportSpec {
    #[serde(default)]
    pub ports: Vec<ServicePort>,
    #[serde(default)]
    pub ips: Vec<String>,
    /// `ClusterSetIP` or `Headless`.
    #[serde(rename = "type", default)]
    pub type_: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServicePort {
    pub name: Option<String>,
    pub protocol: Option<String>,
    pub port: i32,
}

impl kube::Resource for ServiceImport {
    type DynamicType = ();
    type Scope = k8s_openapi::NamespaceResourceScope;

    fn kind(_: &()) -> Cow<'_, str> {
        "ServiceImport".into()
    }
    fn group(_: &()) -> Cow<'_, str> {
        "multicluster.x-k8s.io".into()
    }
    fn version(_: &()) -> Cow<'_, str> {
        "v1alpha1".into()
    }
    fn plural(_: &()) -> Cow<'_, str> {
        "serviceimports".into()
    }
    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
    fn meta_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}
