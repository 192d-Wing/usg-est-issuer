#!/usr/bin/env bash
# NIST SP 800-53 Rev. 5: CA-2, CA-7, SA-11, SC-8, SC-12, SC-17, SI-10.
set -euo pipefail

readonly CLUSTER_NAME="${CLUSTER_NAME:-est-integration}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ROOT_DIR
readonly TEST_DIR="${ROOT_DIR}/test/integration"
readonly ARTIFACT_DIR="${TEST_DIR}/artifacts"
readonly OSTRICH_CHART_DIR="${OSTRICH_CHART_DIR:?OSTRICH_CHART_DIR is required}"
readonly OSTRICH_IMAGE_TAG="${OSTRICH_IMAGE_TAG:?OSTRICH_IMAGE_TAG is required}"
readonly HELM_IMAGE="docker.io/alpine/helm@sha256:1e4409103989b4ed9e34c132c2ac350b744ce2514aaa1440df0ea59063d83ae6"

mkdir -p "${ARTIFACT_DIR}"
chmod 700 "${ARTIFACT_DIR}"
TMP_DIR="$(mktemp -d)"
readonly TMP_DIR
chmod 700 "${TMP_DIR}"
mkdir -p "${TMP_DIR}/helm/config" "${TMP_DIR}/helm/cache" "${TMP_DIR}/helm/data"

helm_cmd() {
  docker run --rm --network host \
    --user "$(id -u):$(id -g)" \
    -e KUBECONFIG="${KUBECONFIG}" \
    -e HELM_CONFIG_HOME=/helm/config \
    -e HELM_CACHE_HOME=/helm/cache \
    -e HELM_DATA_HOME=/helm/data \
    -v "$(dirname "${KUBECONFIG}")":"$(dirname "${KUBECONFIG}")":ro \
    -v "${TMP_DIR}/helm:/helm" \
    -v "${ROOT_DIR}:${ROOT_DIR}" \
    -v "${OSTRICH_CHART_DIR}:${OSTRICH_CHART_DIR}" \
    -w "${ROOT_DIR}" \
    "${HELM_IMAGE}" "$@"
}

cleanup_and_collect() {
  local result=$?
  if kubectl cluster-info >/dev/null 2>&1; then
    kubectl get pods,jobs,certificates,certificaterequests,secrets \
      --all-namespaces -o wide >"${ARTIFACT_DIR}/resources.txt" 2>&1 || true
    kubectl get events --all-namespaces --sort-by=.lastTimestamp \
      >"${ARTIFACT_DIR}/events.txt" 2>&1 || true
    kubectl logs -n integration deployment/usg-est-issuer --all-containers \
      >"${ARTIFACT_DIR}/issuer.log" 2>&1 || true
    kubectl logs -n ostrich-ci deployment/ostrich-ci-ostrich-pki-est --all-containers \
      >"${ARTIFACT_DIR}/ostrich-est.log" 2>&1 || true
    kubectl logs -n ostrich-ci deployment/ostrich-ci-ostrich-pki-ca --all-containers \
      >"${ARTIFACT_DIR}/ostrich-ca.log" 2>&1 || true
    kubectl logs -n ostrich-ci job/ostrich-ci-ostrich-pki-ca-bootstrap --all-containers \
      >"${ARTIFACT_DIR}/ostrich-bootstrap.log" 2>&1 || true
  fi
  rm -rf "${TMP_DIR}"
  return "${result}"
}
trap cleanup_and_collect EXIT

kind create cluster --name "${CLUSTER_NAME}" --config "${TEST_DIR}/kind-config.yaml"
kind load docker-image usg-est-issuer:integration --name "${CLUSTER_NAME}"

helm_cmd upgrade --install cert-manager \
  oci://quay.io/jetstack/charts/cert-manager \
  --version v1.21.0 \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true \
  --wait --timeout 5m

kubectl create namespace ostrich-ci
kubectl create namespace integration

openssl ecparam -name secp384r1 -genkey -noout -out "${TMP_DIR}/lab-ca.key"
openssl req -x509 -new -sha384 -days 2 \
  -key "${TMP_DIR}/lab-ca.key" \
  -subj "/CN=EST Integration Transport Root" \
  -out "${TMP_DIR}/lab-ca.crt"
openssl ecparam -name secp384r1 -genkey -noout -out "${TMP_DIR}/est-server.key"
openssl req -new -sha384 \
  -key "${TMP_DIR}/est-server.key" \
  -subj "/CN=ostrich-ci-ostrich-pki-est.ostrich-ci.svc" \
  -out "${TMP_DIR}/est-server.csr"
cat >"${TMP_DIR}/est-server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyAgreement
extendedKeyUsage=serverAuth
subjectAltName=DNS:ostrich-ci-ostrich-pki-est,DNS:ostrich-ci-ostrich-pki-est.ostrich-ci,DNS:ostrich-ci-ostrich-pki-est.ostrich-ci.svc,DNS:ostrich-ci-ostrich-pki-est.ostrich-ci.svc.cluster.local
EOF
openssl x509 -req -sha384 -days 2 \
  -in "${TMP_DIR}/est-server.csr" \
  -CA "${TMP_DIR}/lab-ca.crt" \
  -CAkey "${TMP_DIR}/lab-ca.key" \
  -CAcreateserial \
  -extfile "${TMP_DIR}/est-server.ext" \
  -out "${TMP_DIR}/est-server.crt"

DB_PASSWORD="$(openssl rand -hex 24)"
HSM_PIN="$(openssl rand -hex 16)"
ADMIN_PASSWORD="$(openssl rand -base64 36 | tr -d '\n')"
readonly DB_PASSWORD HSM_PIN ADMIN_PASSWORD

kubectl create secret generic ostrich-ci-postgres -n ostrich-ci \
  --from-literal=password="${DB_PASSWORD}"
kubectl create secret generic ostrich-ci-bootstrap -n ostrich-ci \
  --from-literal=pkcs11-pin="${HSM_PIN}" \
  --from-literal=pkcs11-so-pin="${HSM_PIN}" \
  --from-literal=admin-password="${ADMIN_PASSWORD}"
kubectl create secret generic ostrich-ci-est-tls -n ostrich-ci \
  --from-file=tls.crt="${TMP_DIR}/est-server.crt" \
  --from-file=tls.key="${TMP_DIR}/est-server.key" \
  --from-file=client-ca.crt="${TMP_DIR}/lab-ca.crt"

kubectl apply -f "${TEST_DIR}/manifests/postgres.yaml"
kubectl rollout status deployment/ostrich-ci-postgres -n ostrich-ci --timeout=3m

helm_cmd repo add bitnami https://charts.bitnami.com/bitnami
helm_cmd dependency build "${OSTRICH_CHART_DIR}"
helm_cmd upgrade --install ostrich-ci "${OSTRICH_CHART_DIR}" \
  --namespace ostrich-ci \
  --values "${OSTRICH_CHART_DIR}/values-est-issuer-ci.yaml" \
  --set image.tag="${OSTRICH_IMAGE_TAG}" \
  --set postgresql.enabled=false \
  --set externalDatabase.host=ostrich-ci-postgres \
  --set externalDatabase.sslMode=disable \
  --set externalDatabase.existingSecret=ostrich-ci-postgres \
  --set externalDatabase.existingSecretPasswordKey=password \
  --wait --wait-for-jobs --timeout 8m

kubectl wait -n ostrich-ci job/ostrich-ci-ostrich-pki-ca-bootstrap \
  --for=condition=Complete --timeout=5m
kubectl rollout status -n ostrich-ci deployment/ostrich-ci-ostrich-pki-ca --timeout=5m
kubectl rollout status -n ostrich-ci deployment/ostrich-ci-ostrich-pki-est --timeout=5m

kubectl create secret generic ostrich-est-trust -n integration \
  --from-file=ca.crt="${TMP_DIR}/lab-ca.crt" \
  --dry-run=client -o yaml |
  kubectl label --local -f - pki.usg.mil/est-issuer=true -o yaml |
  kubectl patch --local -f - --type=merge -p '{"immutable":true}' -o yaml |
  kubectl apply -f -
kubectl create secret generic ostrich-est-basic -n integration \
  --from-literal=password="${ADMIN_PASSWORD}" \
  --dry-run=client -o yaml |
  kubectl label --local -f - pki.usg.mil/est-issuer=true -o yaml |
  kubectl patch --local -f - --type=merge -p '{"immutable":true}' -o yaml |
  kubectl apply -f -

helm_cmd upgrade --install usg-est-issuer "${ROOT_DIR}/deploy/charts/usg-est-issuer" \
  --namespace integration \
  --set image.repository=usg-est-issuer \
  --set image.tag=integration \
  --set image.pullPolicy=Never \
  --wait --timeout 3m

kubectl apply -f "${TEST_DIR}/manifests/est-issuer.yaml"
kubectl apply -f "${TEST_DIR}/manifests/certificates.yaml"

# cert-manager deliberately blocks external issuers until an independent
# approver records an Approved condition. The lab's cluster-admin identity acts
# as the explicit test approver; production must use organizational approval
# policy and separation of duties.
for certificate_name in valid-est denied-est; do
  request_name=""
  for _ in $(seq 1 60); do
    request_name="$(
      kubectl get certificaterequest -n integration \
        -l "cert-manager.io/certificate-name=${certificate_name}" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
    )"
    [[ -n "${request_name}" ]] && break
    sleep 1
  done
  [[ -n "${request_name}" ]]
  approved_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kubectl patch certificaterequest "${request_name}" -n integration \
    --subresource=status --type=merge \
    -p "{\"status\":{\"conditions\":[{\"type\":\"Approved\",\"status\":\"True\",\"reason\":\"IntegrationLabApproval\",\"message\":\"Approved by the isolated integration lab\",\"lastTransitionTime\":\"${approved_at}\"}]}}"
done

kubectl wait -n integration certificate/valid-est \
  --for=condition=Ready --timeout=3m

kubectl get secret valid-est-tls -n integration -o jsonpath='{.data.tls\.crt}' |
  base64 --decode >"${TMP_DIR}/issued.crt"
kubectl get secret valid-est-tls -n integration -o jsonpath='{.data.tls\.key}' |
  base64 --decode >"${TMP_DIR}/issued.key"

openssl x509 -in "${TMP_DIR}/issued.crt" -noout \
  -checkhost integration.lab.example.mil
openssl x509 -in "${TMP_DIR}/issued.crt" -pubkey -noout |
  openssl pkey -pubin -outform DER >"${TMP_DIR}/cert-public.der"
openssl pkey -in "${TMP_DIR}/issued.key" -pubout -outform DER \
  >"${TMP_DIR}/key-public.der"
cmp "${TMP_DIR}/cert-public.der" "${TMP_DIR}/key-public.der"
openssl ec -in "${TMP_DIR}/issued.key" -noout -text 2>&1 |
  grep -q '384 bit'

denied_status=""
denied_reason=""
for _ in $(seq 1 90); do
  denied_status="$(
    kubectl get certificaterequest -n integration \
      -l cert-manager.io/certificate-name=denied-est \
      -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true
  )"
  denied_reason="$(
    kubectl get certificaterequest -n integration \
      -l cert-manager.io/certificate-name=denied-est \
      -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || true
  )"
  if [[ "${denied_status}" == "False" && "${denied_reason}" == "PolicyDenied" ]]; then
    break
  fi
  sleep 2
done
[[ "${denied_status}" == "False" && "${denied_reason}" == "PolicyDenied" ]]
if kubectl get secret denied-est-tls -n integration >/dev/null 2>&1; then
  echo "policy-denied request unexpectedly produced a TLS Secret" >&2
  exit 1
fi

kubectl logs -n integration deployment/usg-est-issuer --all-containers \
  >"${ARTIFACT_DIR}/issuer.log"
if grep -Fq "${ADMIN_PASSWORD}" "${ARTIFACT_DIR}/issuer.log"; then
  echo "issuer audit log exposed the EST password" >&2
  exit 1
fi
if grep -Eq 'BEGIN (EC |RSA |)PRIVATE KEY|Authorization:[[:space:]]*(Basic|Bearer)' \
  "${ARTIFACT_DIR}/issuer.log"; then
  echo "issuer log exposed private-key or authorization material" >&2
  exit 1
fi

echo "OstrichPKI EST external-issuer integration passed"
