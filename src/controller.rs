// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use base64::Engine;
use der::{EncodePem, pem::LineEnding};
use futures::StreamExt;
use k8s_crds_cert_manager::CertificateRequest;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use serde_json::json;
use usg_est_client::{EnrollmentResultV2, EstClient, EstClientConfig};
use x509_parser::{
    certification_request::X509CertificationRequest,
    extensions::{GeneralName, ParsedExtension},
    prelude::FromDer,
};

use crate::{
    api::{API_GROUP, AuthenticationMethod, EstIssuer, EstIssuerSpec, ISSUER_KIND, IssuancePolicy},
    audit,
    error::IssuerError,
};

const FIELD_MANAGER: &str = "usg-est-issuer";
const ECDSA_SHA384_OID: &str = "1.2.840.10045.4.3.3";
const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
const P384_CURVE_OID: &str = "1.3.132.0.34";

#[derive(Clone)]
pub struct Context {
    client: Client,
    namespace: String,
}

pub async fn run(client: Client, namespace: String) -> anyhow::Result<()> {
    let requests = Api::<CertificateRequest>::namespaced(client.clone(), &namespace);
    let context = Arc::new(Context { client, namespace });

    Controller::new(requests, watcher::Config::default())
        .run(reconcile, error_policy, context)
        .for_each(|result| async move {
            if let Err(error) = result {
                tracing::error!(error = %error, "controller stream error");
            }
        })
        .await;
    Ok(())
}

async fn reconcile(
    request: Arc<CertificateRequest>,
    context: Arc<Context>,
) -> Result<Action, IssuerError> {
    if !targets_this_controller(&request) || is_complete(&request) {
        return Ok(Action::await_change());
    }

    let issuer_name = request.spec.issuer_ref.name.as_str();
    match reconcile_inner(&request, &context).await {
        Ok(ActionResult::Issued { certificate }) => {
            audit::emit(
                &request,
                issuer_name,
                "certificate.issue",
                "success",
                "Issued",
            );
            patch_status(&request, &context, "True", "Issued", certificate, None).await?;
            Ok(Action::await_change())
        }
        Ok(ActionResult::Pending(delay)) => {
            audit::emit(
                &request,
                issuer_name,
                "certificate.issue",
                "pending",
                "Pending",
            );
            patch_status(&request, &context, "False", "Pending", None, None).await?;
            Ok(Action::requeue(clamp_retry(delay)))
        }
        Err(error) => {
            let reason = error.reason();
            tracing::warn!(
                reason,
                error = %error,
                namespace = request.namespace().as_deref().unwrap_or(""),
                certificate_request = request.name_any(),
                certificate_request_uid = request.meta().uid.as_deref().unwrap_or(""),
                issuer = issuer_name,
                "certificate issuance rejected or failed"
            );
            audit::emit(
                &request,
                issuer_name,
                "certificate.issue",
                "failure",
                reason,
            );
            patch_status(&request, &context, "False", reason, None, None).await?;
            if let Some(delay) = error.retry_after() {
                Ok(Action::requeue(clamp_retry(delay)))
            } else {
                Ok(Action::await_change())
            }
        }
    }
}

async fn reconcile_inner(
    request: &CertificateRequest,
    context: &Context,
) -> Result<ActionResult, IssuerError> {
    enforce_approval(request)?;
    let issuer = load_issuer(request, context).await?;
    let csr_der = decode_and_validate_csr(request, &issuer.spec.policy)?;
    let client = build_est_client(context, &issuer.spec).await?;

    match client.simple_enroll_v2(&csr_der).await? {
        EnrollmentResultV2::Issued {
            certificate,
            intermediates,
        } => {
            let mut certificate_pem = encode_certificate(&certificate)?;
            for intermediate in &intermediates {
                certificate_pem.push_str(&encode_certificate(intermediate)?);
            }
            Ok(ActionResult::Issued {
                certificate: Some(
                    base64::engine::general_purpose::STANDARD.encode(certificate_pem),
                ),
            })
        }
        EnrollmentResultV2::Pending { retry_after } => Ok(ActionResult::Pending(retry_after)),
    }
}

fn targets_this_controller(request: &CertificateRequest) -> bool {
    request.spec.issuer_ref.group.as_deref() == Some(API_GROUP)
        && request.spec.issuer_ref.kind.as_deref() == Some(ISSUER_KIND)
}

fn is_complete(request: &CertificateRequest) -> bool {
    request
        .status
        .as_ref()
        .and_then(|status| status.certificate.as_ref())
        .is_some()
}

fn enforce_approval(request: &CertificateRequest) -> Result<(), IssuerError> {
    let conditions = request
        .status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .ok_or(IssuerError::NotApproved)?;
    if conditions
        .iter()
        .any(|condition| condition.type_ == "Denied" && condition.status == "True")
    {
        return Err(IssuerError::Denied);
    }
    if !conditions
        .iter()
        .any(|condition| condition.type_ == "Approved" && condition.status == "True")
    {
        return Err(IssuerError::NotApproved);
    }
    Ok(())
}

async fn load_issuer(
    request: &CertificateRequest,
    context: &Context,
) -> Result<EstIssuer, IssuerError> {
    let namespace = request
        .namespace()
        .ok_or_else(|| IssuerError::Configuration("request has no namespace".to_string()))?;
    if namespace != context.namespace {
        return Err(IssuerError::Configuration(
            "cross-namespace issuance is disabled".to_string(),
        ));
    }
    let issuers = Api::<EstIssuer>::namespaced(context.client.clone(), &namespace);
    Ok(issuers.get(&request.spec.issuer_ref.name).await?)
}

async fn build_est_client(
    context: &Context,
    spec: &EstIssuerSpec,
) -> Result<EstClient, IssuerError> {
    if !spec.server_url.starts_with("https://") {
        return Err(IssuerError::Configuration(
            "EST server URL must use HTTPS".to_string(),
        ));
    }

    let secrets = Api::<Secret>::namespaced(context.client.clone(), &context.namespace);
    let trust = secrets.get(&spec.authentication.trust_secret_name).await?;
    let ca = secret_bytes(&trust, "ca.crt")?;
    let mut builder = EstClientConfig::builder()
        .server_url(&spec.server_url)
        .map_err(|error| IssuerError::Configuration(error.to_string()))?
        .trust_explicit(vec![ca])
        .verify_csr_signatures();
    if let Some(label) = &spec.ca_label {
        builder = builder.ca_label(label);
    }

    builder = match spec.authentication.method {
        AuthenticationMethod::Basic => {
            let username = spec
                .authentication
                .username
                .as_deref()
                .filter(|username| !username.is_empty())
                .ok_or_else(|| {
                    IssuerError::Configuration(
                        "Basic authentication requires a non-empty username".to_string(),
                    )
                })?;
            if spec.authentication.secret_name.is_empty() {
                return Err(IssuerError::Configuration(
                    "Basic authentication secret name must not be empty".to_string(),
                ));
            }
            let secret = secrets.get(&spec.authentication.secret_name).await?;
            let password = String::from_utf8(secret_bytes(&secret, "password")?)
                .map_err(|_| IssuerError::Secret("password is not valid UTF-8".to_string()))?;
            builder.http_auth(username, password)
        }
        AuthenticationMethod::MutualTls => {
            if spec.authentication.username.is_some() {
                return Err(IssuerError::Configuration(
                    "mTLS authentication must not specify a username".to_string(),
                ));
            }
            if spec.authentication.secret_name.is_empty() {
                return Err(IssuerError::Configuration(
                    "mTLS authentication secret name must not be empty".to_string(),
                ));
            }
            let secret = secrets.get(&spec.authentication.secret_name).await?;
            builder.client_identity_pem(
                secret_bytes(&secret, "tls.crt")?,
                secret_bytes(&secret, "tls.key")?,
            )
        }
    };
    let config = builder
        .build()
        .map_err(|error| IssuerError::Configuration(error.to_string()))?;
    Ok(EstClient::new(config).await?)
}

fn secret_bytes(secret: &Secret, key: &str) -> Result<Vec<u8>, IssuerError> {
    let authorized = secret
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get("pki.usg.mil/est-issuer"))
        .is_some_and(|value| value == "true");
    if !authorized || secret.immutable != Some(true) {
        return Err(IssuerError::Secret(
            "Secret must be immutable and explicitly labeled for EST issuer use".to_string(),
        ));
    }
    secret
        .data
        .as_ref()
        .and_then(|data| data.get(key))
        .map(|value| value.0.clone())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| IssuerError::Secret(format!("required key {key:?} is missing")))
}

fn decode_and_validate_csr(
    request: &CertificateRequest,
    policy: &IssuancePolicy,
) -> Result<Vec<u8>, IssuerError> {
    if request.spec.is_ca.unwrap_or(false) {
        return Err(IssuerError::Policy(
            "CA certificate requests are prohibited".to_string(),
        ));
    }
    validate_usages(request)?;
    validate_duration(request, policy)?;

    let request_bytes = base64::engine::general_purpose::STANDARD
        .decode(request.spec.request.as_bytes())
        .map_err(|_| IssuerError::Policy("request is not valid base64".to_string()))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&request_bytes)
        .map_err(|_| IssuerError::Policy("request is not valid PEM".to_string()))?;
    if pem.label != "CERTIFICATE REQUEST" && pem.label != "NEW CERTIFICATE REQUEST" {
        return Err(IssuerError::Policy(
            "PEM object is not a certificate request".to_string(),
        ));
    }
    let (remaining, csr) = X509CertificationRequest::from_der(&pem.contents)
        .map_err(|_| IssuerError::Policy("CSR is not valid DER".to_string()))?;
    if !remaining.is_empty() {
        return Err(IssuerError::Policy(
            "trailing data after CSR is prohibited".to_string(),
        ));
    }
    validate_public_key(&csr)?;
    if csr.signature_algorithm.algorithm.to_id_string() != ECDSA_SHA384_OID {
        return Err(IssuerError::Policy(
            "only ECDSA P-384 with SHA-384 is permitted".to_string(),
        ));
    }
    let dns_names = validate_dns_sans(&csr, policy)?;
    validate_common_name(&csr, &dns_names)?;
    Ok(pem.contents)
}

fn validate_public_key(csr: &X509CertificationRequest<'_>) -> Result<(), IssuerError> {
    let algorithm = &csr.certification_request_info.subject_pki.algorithm;
    let curve = algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok());
    if algorithm.algorithm.to_id_string() != EC_PUBLIC_KEY_OID
        || curve.is_none_or(|curve| curve.to_id_string() != P384_CURVE_OID)
    {
        return Err(IssuerError::Policy(
            "only ECDSA P-384 public keys are permitted".to_string(),
        ));
    }
    Ok(())
}

fn validate_usages(request: &CertificateRequest) -> Result<(), IssuerError> {
    const ALLOWED: &[&str] = &["digital signature", "server auth"];
    let usages = request.spec.usages.as_deref().unwrap_or(&[]);
    if usages.is_empty()
        || usages
            .iter()
            .any(|usage| !ALLOWED.contains(&usage.as_str()))
    {
        return Err(IssuerError::Policy(
            "usages must be limited to digital signature and server auth".to_string(),
        ));
    }
    Ok(())
}

fn validate_duration(
    request: &CertificateRequest,
    policy: &IssuancePolicy,
) -> Result<(), IssuerError> {
    let requested = request
        .spec
        .duration
        .as_deref()
        .ok_or_else(|| IssuerError::Policy("certificate duration is required".to_string()))?;
    let requested = humantime::parse_duration(requested)
        .map_err(|_| IssuerError::Policy("certificate duration is invalid".to_string()))?;
    let maximum = humantime::parse_duration(&policy.max_duration)
        .map_err(|_| IssuerError::Configuration("maxDuration is invalid".to_string()))?;
    if requested > maximum {
        return Err(IssuerError::Policy(
            "requested certificate duration exceeds issuer policy".to_string(),
        ));
    }
    Ok(())
}

fn validate_dns_sans(
    csr: &X509CertificationRequest<'_>,
    policy: &IssuancePolicy,
) -> Result<Vec<String>, IssuerError> {
    if policy.allowed_dns_suffixes.is_empty() {
        return Err(IssuerError::Configuration(
            "allowedDnsSuffixes must not be empty".to_string(),
        ));
    }
    let extensions = csr
        .requested_extensions()
        .ok_or_else(|| IssuerError::Policy("CSR must contain a DNS SAN".to_string()))?;
    let mut dns_names = Vec::new();
    for extension in extensions {
        if let ParsedExtension::SubjectAlternativeName(san) = extension {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => dns_names.push(dns.to_ascii_lowercase()),
                    _ => {
                        return Err(IssuerError::Policy(
                            "only DNS subject alternative names are permitted".to_string(),
                        ));
                    }
                }
            }
        }
    }
    if dns_names.is_empty() || dns_names.len() > usize::from(policy.max_dns_sans) {
        return Err(IssuerError::Policy(
            "DNS SAN count violates issuer policy".to_string(),
        ));
    }
    for dns in &dns_names {
        if dns.contains('*')
            || !policy.allowed_dns_suffixes.iter().any(|suffix| {
                let suffix = suffix.trim_start_matches('.').to_ascii_lowercase();
                dns == &suffix || dns.ends_with(&format!(".{suffix}"))
            })
        {
            return Err(IssuerError::Policy(
                "DNS SAN is outside the permitted namespace".to_string(),
            ));
        }
    }
    Ok(dns_names)
}

fn validate_common_name(
    csr: &X509CertificationRequest<'_>,
    dns_names: &[String],
) -> Result<(), IssuerError> {
    let mut common_names = csr.certification_request_info.subject.iter_common_name();
    let Some(common_name) = common_names.next() else {
        return Ok(());
    };
    if common_names.next().is_some() {
        return Err(IssuerError::Policy(
            "CSR must not contain multiple common names".to_string(),
        ));
    }
    let common_name = common_name
        .as_str()
        .map_err(|_| IssuerError::Policy("CSR common name is not valid UTF-8".to_string()))?
        .to_ascii_lowercase();
    if !dns_names.iter().any(|dns| dns == &common_name) {
        return Err(IssuerError::Policy(
            "CSR common name must match a DNS subject alternative name".to_string(),
        ));
    }
    Ok(())
}

fn encode_certificate(certificate: &x509_cert::Certificate) -> Result<String, IssuerError> {
    certificate
        .to_pem(LineEnding::LF)
        .map_err(|_| IssuerError::Encoding("certificate could not be encoded".to_string()))
}

async fn patch_status(
    request: &CertificateRequest,
    context: &Context,
    status: &str,
    reason: &str,
    certificate: Option<String>,
    ca: Option<String>,
) -> Result<(), IssuerError> {
    let api = Api::<CertificateRequest>::namespaced(context.client.clone(), &context.namespace);
    let conditions = status_conditions(request, status, reason)?;
    let patch = json!({
        "status": {
            "certificate": certificate,
            "ca": ca,
            "conditions": conditions
        }
    });
    api.patch_status(
        &request.name_any(),
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(&patch),
    )
    .await?;
    Ok(())
}

fn status_conditions(
    request: &CertificateRequest,
    status: &str,
    reason: &str,
) -> Result<Vec<serde_json::Value>, IssuerError> {
    let mut conditions = request
        .status
        .as_ref()
        .and_then(|existing| existing.conditions.as_ref())
        .into_iter()
        .flatten()
        .filter(|condition| condition.type_ != "Ready")
        .map(|condition| {
            serde_json::to_value(condition).map_err(|_| {
                IssuerError::Encoding("status condition could not be encoded".to_string())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    conditions.push(json!({
        "type": "Ready",
        "status": status,
        "reason": reason,
        "message": safe_condition_message(reason),
        "lastTransitionTime": chrono::Utc::now().to_rfc3339(),
        "observedGeneration": request.meta().generation
    }));
    Ok(conditions)
}

fn safe_condition_message(reason: &str) -> &'static str {
    match reason {
        "Issued" => "Certificate issued successfully",
        "Pending" => "EST server deferred enrollment",
        "NotApproved" => "CertificateRequest has not been approved",
        "Denied" => "CertificateRequest was denied",
        "PolicyDenied" => "CertificateRequest violates issuer policy",
        "InvalidIssuer" => "Issuer configuration is invalid",
        "InvalidSecret" => "Issuer credential or trust configuration is invalid",
        "EstFailure" => "EST enrollment failed",
        "KubernetesFailure" => "Kubernetes API operation failed",
        _ => "Certificate issuance failed",
    }
}

fn clamp_retry(delay: Duration) -> Duration {
    delay.clamp(Duration::from_secs(10), Duration::from_secs(3600))
}

fn error_policy(
    request: Arc<CertificateRequest>,
    error: &IssuerError,
    _context: Arc<Context>,
) -> Action {
    tracing::error!(
        reason = error.reason(),
        "reconciliation failed before status update"
    );
    audit::emit(
        &request,
        request.spec.issuer_ref.name.as_str(),
        "certificate.reconcile",
        "failure",
        error.reason(),
    );
    Action::requeue(clamp_retry(
        error.retry_after().unwrap_or(Duration::from_secs(300)),
    ))
}

enum ActionResult {
    Issued { certificate: Option<String> },
    Pending(Duration),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, SignatureAlgorithm};

    fn test_request(dns_name: &str) -> CertificateRequest {
        test_request_with(Some(dns_name), dns_name, &PKCS_ECDSA_P384_SHA384)
    }

    fn test_request_with(
        common_name: Option<&str>,
        dns_name: &str,
        algorithm: &'static SignatureAlgorithm,
    ) -> CertificateRequest {
        let key = KeyPair::generate_for(algorithm).unwrap();
        let mut builder = usg_est_client::csr::CsrBuilder::new().san_dns(dns_name);
        if let Some(common_name) = common_name {
            builder = builder.common_name(common_name);
        }
        let (csr_der, _) = builder.with_key_pair(key).build().unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(csr_der);
        let pem = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
            encoded
                .as_bytes()
                .chunks(64)
                .map(|chunk| std::str::from_utf8(chunk).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );
        let encoded_request = base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());
        serde_json::from_value(json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "CertificateRequest",
            "metadata": {"name": "test", "namespace": "jitpw"},
            "spec": {
                "request": encoded_request,
                "duration": "24h",
                "isCA": false,
                "usages": ["digital signature", "server auth"],
                "issuerRef": {
                    "name": "enterprise-est",
                    "kind": "EstIssuer",
                    "group": "pki.usg.mil"
                }
            }
        }))
        .unwrap()
    }

    fn test_policy() -> IssuancePolicy {
        IssuancePolicy {
            allowed_dns_suffixes: vec!["lab.example.mil".to_string()],
            max_dns_sans: 4,
            max_duration: "720h".to_string(),
        }
    }

    #[test]
    fn retry_delay_is_bounded() {
        assert_eq!(clamp_retry(Duration::ZERO), Duration::from_secs(10));
        assert_eq!(
            clamp_retry(Duration::from_secs(7200)),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn condition_messages_do_not_include_internal_errors() {
        assert_eq!(
            safe_condition_message("EstFailure"),
            "EST enrollment failed"
        );
        assert_eq!(
            safe_condition_message("unknown internal detail"),
            "Certificate issuance failed"
        );
    }

    #[test]
    fn valid_p384_request_inside_dns_boundary_is_accepted() {
        let request = test_request("jitpw-api.lab.example.mil");
        assert!(decode_and_validate_csr(&request, &test_policy()).is_ok());
    }

    #[test]
    fn request_outside_dns_boundary_fails_closed() {
        let request = test_request("attacker.example.net");
        let error = decode_and_validate_csr(&request, &test_policy()).unwrap_err();
        assert!(matches!(error, IssuerError::Policy(_)));
    }

    #[test]
    fn p256_public_key_is_rejected() {
        let request = test_request_with(
            Some("jitpw-api.lab.example.mil"),
            "jitpw-api.lab.example.mil",
            &PKCS_ECDSA_P256_SHA256,
        );
        let error = decode_and_validate_csr(&request, &test_policy()).unwrap_err();
        assert!(error.to_string().contains("P-384 public keys"));
    }

    #[test]
    fn common_name_must_match_a_dns_san() {
        let request = test_request_with(
            Some("attacker.example.net"),
            "jitpw-api.lab.example.mil",
            &PKCS_ECDSA_P384_SHA384,
        );
        let error = decode_and_validate_csr(&request, &test_policy()).unwrap_err();
        assert!(error.to_string().contains("must match a DNS"));
    }

    #[test]
    fn ready_status_preserves_approval_conditions() {
        let mut request_value =
            serde_json::to_value(test_request("jitpw-api.lab.example.mil")).unwrap();
        request_value["status"] = json!({
            "conditions": [{
                "type": "Approved",
                "status": "True",
                "reason": "cert-manager.io",
                "message": "Approved by policy",
                "lastTransitionTime": "2026-01-01T00:00:00Z"
            }]
        });
        let request: CertificateRequest = serde_json::from_value(request_value).unwrap();
        let conditions = status_conditions(&request, "True", "Issued").unwrap();

        assert!(
            conditions.iter().any(|condition| {
                condition["type"] == "Approved" && condition["status"] == "True"
            })
        );
        assert!(
            conditions
                .iter()
                .any(|condition| { condition["type"] == "Ready" && condition["status"] == "True" })
        );
    }
}
