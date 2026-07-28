# NIST SP 800-53 Rev. 5 control mapping

This mapping describes software-provided mechanisms. It does not assert an
authorization to operate or replace organizational assessment.

| Control | Implementation evidence |
|---|---|
| AC-3 Access Enforcement | Approved/Denied gate, issuer policy, namespaced RBAC |
| AC-4 Information Flow Enforcement | CSR-only boundary; no workload private-key access |
| AC-6 Least Privilege | Namespaced Role, single replica, no Secret writes |
| AU-2 Event Logging | Issuance success, failure, denial, and pending events |
| AU-3 Content of Audit Records | Actor, object UID, issuer, correlation, outcome, reason |
| AU-8 Time Stamps | UTC timestamps emitted by structured tracing and Kubernetes conditions |
| AU-9 Protection of Audit Information | Secret-free output designed for external immutable transport |
| AU-12 Audit Record Generation | Stable `usg.est.issuer.audit.v1` event schema |
| CM-6 Configuration Settings | Kubernetes-compatible structural CRD schema, serde unknown-field rejection, controller authentication validation, and deny-by-default policy defaults |
| IA-5 Authenticator Management | Immutable, explicitly labeled bootstrap Secrets; mTLS support |
| SC-8 Transmission Confidentiality and Integrity | HTTPS-only EST and authenticated server trust |
| SC-12 Cryptographic Key Establishment and Management | cert-manager key custody; no key export to issuer |
| SC-13 Cryptographic Protection | P-384/SHA-384 request profile; startup assertion of the AWS-LC FIPS rustls provider |
| SI-10 Information Input Validation | Strict PEM/DER, signature, SAN, usage, duration, and response validation |
| SI-11 Error Handling | Sanitized conditions; detailed internal reason codes without secret material |
| SI-16 Memory Protection | Rust memory safety, forbidden unsafe code, non-root read-only container |
| CA-2 Security Assessments | Automated cert-manager/OstrichPKI certificate-lifecycle assessment |
| CA-7 Continuous Monitoring | Required integration check and retained failure diagnostics |
| SA-11 Developer Testing and Evaluation | Success, policy-denial, key-match, and log-leakage assertions |

The Kubernetes API schema intentionally avoids JSON Schema conditionals,
`additionalProperties: false`, and quadratic array uniqueness checks that are
rejected by current apiextensions validation. Equivalent security checks remain
fail-closed in Rust: serde rejects unknown spec fields, the controller validates
authentication-method requirements, and policy evaluation denies empty or
unauthorized DNS suffix sets before an EST network call.

The integration assessment explicitly records cert-manager approval before the
external issuer may process a request, providing evidence for AC-3 and AC-5.
Approval does not imply authorization: issuer policy independently denies an
approved request whose DNS identity is outside the configured ABAC boundary.

## Operator-provided controls

The operator must provide certificate-request approval policy, Kubernetes audit
logging, network policy, image admission and signature verification, immutable
log retention, time synchronization, backup, incident response, vulnerability
management, and separation of duties for PKI Secret labeling.

Integration evidence and its SoftHSM limitation are documented in
[INTEGRATION_TESTING.md](INTEGRATION_TESTING.md).
