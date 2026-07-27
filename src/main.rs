// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use kube::Client;
use tracing_subscriber::EnvFilter;
use usg_est_issuer::controller;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    usg_est_client::fips_tls::install_fips_provider()
        .context("installing required AWS-LC FIPS cryptographic provider")?;
    if !usg_est_client::fips_tls::is_fips_active() {
        anyhow::bail!("AWS-LC FIPS cryptographic provider is not active");
    }

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,security_audit=info")),
        )
        .with_current_span(true)
        .with_span_list(true)
        .init();

    let namespace = std::env::var("WATCH_NAMESPACE")
        .context("WATCH_NAMESPACE is required; cluster-wide mode is prohibited")?;
    if namespace.trim().is_empty() {
        anyhow::bail!("WATCH_NAMESPACE must not be empty");
    }

    let client = Client::try_default()
        .await
        .context("creating Kubernetes client")?;
    tracing::info!(namespace, "starting namespaced EST external issuer");
    controller::run(client, namespace).await
}
