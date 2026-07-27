// SPDX-License-Identifier: Apache-2.0

use kube::CustomResourceExt;
use usg_est_issuer::api::EstIssuer;

fn main() -> anyhow::Result<()> {
    println!("{}", serde_saphyr::to_string(&EstIssuer::crd())?);
    Ok(())
}
