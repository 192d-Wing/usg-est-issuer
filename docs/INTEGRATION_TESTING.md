# Kubernetes EST integration testing

The required Kubernetes integration workflow creates a disposable kind cluster
and exercises a real certificate lifecycle through cert-manager,
`usg-est-issuer`, and OstrichPKI.

## Trust boundaries

- cert-manager alone generates and stores the workload P-384 private key.
- The issuer receives only the approved PKCS#10 request and never reads or
  writes the resulting TLS Secret.
- The issuer authenticates to OstrichPKI using an immutable, explicitly labeled
  Secret containing a randomly generated test-only password.
- OstrichPKI protects its P-384 CA key in a disposable SoftHSM token volume.
- Transport trust, EST credentials, database credentials, and HSM PINs are
  generated at runtime and destroyed with the cluster.
- Every external action, tool, image, chart source, and Kubernetes node image is
  pinned by commit, version plus checksum, or digest.

SoftHSM provides interface and lifecycle emulation only. It is not treated as
evidence that a production HSM or cryptographic module is FIPS validated.

## Assertions

The workflow fails unless:

1. cert-manager approves and creates a request for the external issuer.
2. OstrichPKI enrolls that request through RFC 7030 over authenticated TLS.
3. cert-manager creates a `kubernetes.io/tls` Secret.
4. The certificate contains the allowed DNS SAN.
5. The P-384 certificate public key matches the cert-manager-held private key.
6. A request outside the allowed DNS suffix receives `PolicyDenied`.
7. The denied request never creates its requested Secret.
8. Issuer logs contain neither the EST password, authorization headers, nor
   private-key PEM material.

Diagnostics are retained for 14 days and contain Kubernetes object summaries,
events, and service logs. Secret data is never deliberately exported.

## Local execution

The harness targets Linux with Docker, `kubectl`, OpenSSL, and the
checksum-verified kind version defined in the workflow:

```sh
docker build --tag usg-est-issuer:integration .
export KUBECONFIG="${HOME}/.kube/config"
export OSTRICH_CHART_DIR=/path/to/pinned/OstrichPKI/deploy/helm/ostrich-pki
export OSTRICH_IMAGE_TAG=sha-75508e0
bash test/integration/run.sh
```

The harness uses random ephemeral credentials and does not accept production
credentials.
The lab installs the CRD into the pinned kind Kubernetes release before
starting the controller. This verifies that the structural schema remains
accepted by current apiextensions validation while controller-side
authentication and policy checks remain fail-closed.

The isolated cluster-admin identity explicitly adds the cert-manager
`Approved=True` condition to each generated CertificateRequest. This models the
independent approval boundary required by cert-manager without weakening the
issuer: the valid request proceeds to EST, while the approved but unauthorized
DNS request must still fail with `PolicyDenied` and produce no certificate
Secret. Production deployments must use their organizational approver policy
and separation of duties rather than this lab-only transition.

The pinned OstrichPKI bootstrap initially creates its Basic-auth account as an
Administrator, a role that deliberately cannot submit certificate requests.
After the one-shot bootstrap completes, the disposable lab changes exactly that
account to the machine-only `est_enrollee` role directly in the isolated test
database. This is test fixture setup, not a production account-provisioning
procedure; production must use the PKI platform's audited identity lifecycle.
