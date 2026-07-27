# Audit logging

The controller emits newline-delimited JSON to standard output using the
`security_audit` tracing target and schema `usg.est.issuer.audit.v1`.

Required fields:

| Field | Meaning |
|---|---|
| `event_action` | Stable action, currently `certificate.issue` |
| `event_outcome` | `success`, `failure`, or `pending` |
| `reason` | Stable machine-readable reason |
| `correlation_id` | CertificateRequest UID, or UUIDv7 if unavailable |
| `namespace` | Watched namespace |
| `certificate_request` | Resource name |
| `certificate_request_uid` | Immutable Kubernetes UID |
| `issuer` | Referenced EstIssuer |
| `actor_uid` | UID recorded by cert-manager admission |

Forward logs over authenticated, encrypted transport to append-only storage.
Apply synchronized UTC time, access controls, integrity monitoring, retention,
and legal-hold policy outside the controller. Alert on `Denied`,
`PolicyDenied`, `InvalidSecret`, repeated `EstFailure`, and missing audit data.

Never enable payload logging at an HTTP or Kubernetes client layer. Audit
records must not contain CSR PEM, Secret data, passwords, keys, certificates,
Authorization headers, or TLS session material.
