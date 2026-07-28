// SPDX-License-Identifier: Apache-2.0

use k8s_crds_cert_manager::CertificateRequest;
use kube::{Resource, ResourceExt};
use tracing::{Level, event};
use uuid::Uuid;

/// Emit a structured, secret-free audit event suitable for immutable log export.
///
/// NIST SP 800-53 Rev. 5: AU-2, AU-3, AU-8, AU-9, AU-12.
pub fn emit(
    request: &CertificateRequest,
    issuer: &str,
    action: &'static str,
    outcome: &'static str,
    reason: &'static str,
) {
    let correlation_id = request
        .meta()
        .uid
        .clone()
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    event!(
        target: "security_audit",
        Level::INFO,
        event_schema = "usg.est.issuer.audit.v1",
        event_action = action,
        event_outcome = outcome,
        reason,
        correlation_id,
        namespace = request.namespace().as_deref().unwrap_or(""),
        certificate_request = request.name_any(),
        certificate_request_uid = request.meta().uid.as_deref().unwrap_or(""),
        issuer,
        actor_uid = request.spec.uid.as_deref().unwrap_or(""),
        "certificate issuance audit event"
    );
}
