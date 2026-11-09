#!/usr/bin/env bash
# Create and remove our own disposable kind cluster; never use a caller's kubeconfig.
set -euo pipefail

nyctr_test_dir=$(mktemp -d)
nyctr_cluster_name="nyctr-ci-${GITHUB_RUN_ID:-$$}"
nyctr_port_forward_pid=""
export KUBECONFIG="$nyctr_test_dir/kubeconfig"
export NYCTR_SMOKE_URL=http://127.0.0.1:8080
export NYCTR_SMOKE_ORIGIN=http://localhost:8080
export NYCTR_SMOKE_STATE="$nyctr_test_dir/smoke-state.json"

# Preserve the failing exit code while collecting only this test cluster's evidence.
cleanup() {
  nyctr_exit_code=$?
  if [ "$nyctr_exit_code" -ne 0 ]; then
    kubectl --context "kind-$nyctr_cluster_name" -n nyctr-test get pods || true
    kubectl --context "kind-$nyctr_cluster_name" -n nyctr-test logs deployment/nyctr --tail=100 || true
    cat "$nyctr_test_dir/port-forward.log" 2>/dev/null || true
  fi
  if [ -n "$nyctr_port_forward_pid" ]; then
    kill "$nyctr_port_forward_pid" 2>/dev/null || true
    wait "$nyctr_port_forward_pid" 2>/dev/null || true
  fi
  kind delete cluster --name "$nyctr_cluster_name" || true
  rm -rf "$nyctr_test_dir"
  exit "$nyctr_exit_code"
}
trap cleanup EXIT

# A new forwarding process is needed after replacing the selected application pod.
forward_application() {
  kubectl --context "kind-$nyctr_cluster_name" -n nyctr-test \
    port-forward service/nyctr 8080:8080 --address=127.0.0.1 \
    > "$nyctr_test_dir/port-forward.log" 2>&1 &
  nyctr_port_forward_pid=$!
}

docker build -t nyctr:ci-smoke .
kind create cluster --name "$nyctr_cluster_name" \
  --image kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d \
  --wait 120s
kind load docker-image nyctr:ci-smoke --name "$nyctr_cluster_name"
kubectl --context "kind-$nyctr_cluster_name" create namespace nyctr-test
kubectl --context "kind-$nyctr_cluster_name" -n nyctr-test \
  apply -f tests/acceptance/kubernetes-postgres.yaml
kubectl --context "kind-$nyctr_cluster_name" -n nyctr-test \
  rollout status deployment/postgres --timeout=180s
helm upgrade --install nyctr charts/nyctr --namespace nyctr-test \
  --kube-context "kind-$nyctr_cluster_name" \
  --values charts/nyctr/ci/demo-postgres-values.yaml --wait --timeout 3m
forward_application
python3 scripts/smoke.py
kill "$nyctr_port_forward_pid"
wait "$nyctr_port_forward_pid" 2>/dev/null || true
nyctr_port_forward_pid=""
kubectl --context "kind-$nyctr_cluster_name" -n nyctr-test rollout restart deployment/nyctr
kubectl --context "kind-$nyctr_cluster_name" -n nyctr-test rollout status deployment/nyctr --timeout=180s
forward_application
python3 scripts/smoke.py --verify-persistence
