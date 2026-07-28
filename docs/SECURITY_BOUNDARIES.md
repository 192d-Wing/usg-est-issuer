# Security boundaries

## Private-key boundary

cert-manager generates the workload key and CSR. The issuer reads only the
immutable `CertificateRequest.spec.request`. It does not read destination TLS
Secrets, generate workload keys, use EST `serverkeygen`, or return private-key
material.

## Approval boundary

The issuer never approves requests. It requires `Approved=True`, rejects
`Denied=True`, and performs its own policy validation after approval. Approval
and issuance policy are independent gates; either gate can deny issuance.

## Namespace boundary

One controller deployment watches exactly one namespace. `WATCH_NAMESPACE` is
mandatory and cannot be empty. RBAC is a namespaced Role. `ClusterEstIssuer` is
not implemented. This prevents a credential authorized for one namespace from
becoming a cluster-wide signing identity.

## Secret boundary

The Role can read Secrets in its namespace because Kubernetes RBAC cannot
restrict dynamically referenced Secret names. The controller compensates by
accepting only Secrets that:

1. carry `pki.usg.mil/est-issuer: "true"`; and
2. have `immutable: true`.

Only a tightly controlled PKI administrator may create or label these Secrets.
Application administrators must not receive that permission.

## EST trust boundary

Every issuer references an explicit CA Secret. Plain HTTP, implicit trust,
TOFU, and insecure certificate validation are prohibited. Basic credentials
are permitted only inside authenticated TLS; mTLS is preferred.

The process installs and verifies the AWS-LC FIPS rustls provider before
creating any Kubernetes or EST client. Startup fails if the provider is absent,
not operating in FIPS mode, or another process-wide provider was installed
first.

## Certificate policy boundary

The initial API permits only:

- ECDSA P-384 CSRs signed with SHA-384;
- end-entity certificates;
- DNS SANs without wildcards;
- configured DNS suffixes;
- bounded SAN counts and durations; and
- `digital signature` and `server auth` usages.

Malformed, ambiguous, unsupported, or incomplete input is rejected before the
EST request. The EST response must contain exactly one certificate whose SPKI
matches the CSR.

## Availability and concurrency boundary

Version 0.1 runs one replica and does not claim highly available leader
election. Pending responses honor bounded retry delays. A controller crash
before status persistence can cause a repeated enrollment request; the EST
server must apply idempotency or duplicate-request controls. HA deployment is
prohibited until leader election and replay tests are implemented.

## Audit boundary

Audit events contain resource identifiers, immutable Kubernetes UIDs, actor
UID, issuer name, outcome, and reason code. They exclude CSR bodies, private
keys, passwords, authentication certificates, certificate bodies, and Secret
contents. Cluster log transport and immutable retention are operator
responsibilities.

## Failure behavior

Authorization, parsing, policy, trust, credential, network, and response
validation errors do not issue a certificate. Conditions contain sanitized
messages. Retryable failures use bounded backoff; permanent failures wait for a
resource change.
