// SPDX-License-Identifier: Apache-2.0

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const API_GROUP: &str = "pki.usg.mil";
pub const ISSUER_KIND: &str = "EstIssuer";

#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "pki.usg.mil",
    version = "v1alpha1",
    kind = "EstIssuer",
    plural = "estissuers",
    namespaced,
    status = "EstIssuerStatus",
    shortname = "esti"
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EstIssuerSpec {
    /// HTTPS base URL of the RFC 7030 EST server.
    pub server_url: String,

    /// Optional EST CA label.
    #[serde(default)]
    pub ca_label: Option<String>,

    /// EST server trust and enrollment authentication.
    pub authentication: AuthenticationSpec,

    /// CertificateRequest constraints applied before any EST network call.
    #[serde(default)]
    pub policy: IssuancePolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationSpec {
    /// Secret holding the explicit EST server CA in `ca.crt`.
    pub trust_secret_name: String,

    pub method: AuthenticationMethod,

    /// Basic-auth username. Required only when `method` is `basic`.
    #[serde(default)]
    pub username: Option<String>,

    /// Secret holding either `password` or the mTLS `tls.crt` and `tls.key`.
    pub secret_name: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationMethod {
    Basic,
    MutualTls,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuancePolicy {
    /// DNS suffixes permitted in a request. Empty means deny every request.
    #[serde(default)]
    pub allowed_dns_suffixes: Vec<String>,

    /// Maximum DNS SAN count.
    #[serde(default = "default_max_dns_sans")]
    pub max_dns_sans: u16,

    /// Maximum certificate duration requested through cert-manager.
    #[serde(default = "default_max_duration")]
    pub max_duration: String,
}

impl Default for IssuancePolicy {
    fn default() -> Self {
        Self {
            allowed_dns_suffixes: Vec::new(),
            max_dns_sans: default_max_dns_sans(),
            max_duration: default_max_duration(),
        }
    }
}

fn default_max_dns_sans() -> u16 {
    20
}

fn default_max_duration() -> String {
    "720h".to_string()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EstIssuerStatus {
    #[serde(default)]
    pub conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition>,
}
