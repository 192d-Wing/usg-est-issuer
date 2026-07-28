// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("request is not approved")]
    NotApproved,

    #[error("request is denied")]
    Denied,

    #[error("request violates issuer policy: {0}")]
    Policy(String),

    #[error("issuer configuration is invalid: {0}")]
    Configuration(String),

    #[error("referenced secret is unavailable or invalid: {0}")]
    Secret(String),

    #[error("EST enrollment failed: {0}")]
    Est(#[from] usg_est_client::EstError),

    #[error("Kubernetes API operation failed: {0}")]
    Kubernetes(#[from] kube::Error),

    #[error("certificate encoding failed: {0}")]
    Encoding(String),
}

impl IssuerError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotApproved => "NotApproved",
            Self::Denied => "Denied",
            Self::Policy(_) => "PolicyDenied",
            Self::Configuration(_) => "InvalidIssuer",
            Self::Secret(_) => "InvalidSecret",
            Self::Est(_) => "EstFailure",
            Self::Kubernetes(_) => "KubernetesFailure",
            Self::Encoding(_) => "InvalidCertificate",
        }
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Est(error) if error.is_retryable() => {
                Some(Duration::from_secs(error.retry_after().unwrap_or(60)))
            }
            Self::Kubernetes(_) => Some(Duration::from_secs(30)),
            _ => None,
        }
    }
}
