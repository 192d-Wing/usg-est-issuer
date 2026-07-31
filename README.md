# USG EST Issuer

`usg-est-issuer` is a namespaced, fail-closed RFC 7030 external issuer for
[cert-manager](https://cert-manager.io/). It submits cert-manager-generated
PKCS#10 requests through `usg-est-client`; it never receives or generates the
workload private key.

The initial release deliberately supports only `EstIssuer`. It does not provide
a cluster-scoped issuer, wildcard certificates, CA certificates, non-DNS SANs,
plaintext EST, automatic approval, or server-side key generation.

## Security defaults

- A `CertificateRequest` must have `Approved=True` and must not have
  `Denied=True`.
- Requests are restricted to ECDSA P-384 with SHA-384.
- A CSR common name, when present, must match one of its DNS SANs.
- Only `digital signature` and `server auth` usages are accepted.
- DNS SANs must fall within an issuer allowlist; an empty allowlist denies all.
- EST trust is explicit. System or implicit roots are not used.
- Bootstrap Secrets must be immutable and labeled
  `pki.usg.mil/est-issuer: "true"`.
- The controller is restricted to `WATCH_NAMESPACE`.
- Errors are represented by sanitized conditions and structured audit events.

See [Security boundaries](docs/SECURITY_BOUNDARIES.md),
[audit logging](docs/AUDIT_LOGGING.md), and the
[NIST SP 800-53 Rev. 5 control mapping](docs/NIST_800_53_REV5.md).

## Example

Create immutable trust and authentication Secrets:

```shell
kubectl -n pki create secret generic est-server-trust \
  --from-file=ca.crt=./est-server-ca.pem \
  --dry-run=client -o yaml |
  kubectl label --local -f - pki.usg.mil/est-issuer=true -o yaml |
  kubectl patch --local -f - --type=merge -p '{"immutable":true}' -o yaml |
  kubectl apply -f -
```

```yaml
apiVersion: pki.usg.mil/v1alpha1
kind: EstIssuer
metadata:
  name: enterprise-est
  namespace: jitpw
spec:
  serverUrl: https://est.example.mil/.well-known/est
  authentication:
    trustSecretName: est-server-trust
    method: mutualTls
    secretName: est-bootstrap-identity
  policy:
    allowedDnsSuffixes:
      - lab.example.mil
      - jitpw.svc.cluster.local
    maxDnsSans: 10
    maxDuration: 720h
```

Applications declare ordinary cert-manager `Certificate` resources referencing:

```yaml
issuerRef:
  name: enterprise-est
  kind: EstIssuer
  group: pki.usg.mil
```

The cert-manager approver remains a separate authorization component.

## Releases

Pushing a semantic-version tag such as `v0.1.0` runs the Rust, Helm, and full
Kubernetes EST integration gates before publishing
`ghcr.io/192d-wing/usg-est-issuer`. The tag must match the versions in
`Cargo.toml`, the Helm chart, and the chart's default image tag.

The release workflow rejects high or critical known vulnerabilities, publishes
the image by immutable digest with OCI SBOM and provenance attestations, signs
the digest with GitHub Actions OIDC through Cosign, and attaches an SPDX SBOM
and digest record to the GitHub Release. Production Helm deployments should set
`image.digest` to the released digest rather than relying on a mutable tag.

## Integration testing

The required Kubernetes integration workflow exercises a complete cert-manager
certificate lifecycle against the pinned OstrichPKI EST implementation,
including fail-closed DNS-policy and secret-leakage assertions. See
[Kubernetes EST integration testing](docs/INTEGRATION_TESTING.md).
