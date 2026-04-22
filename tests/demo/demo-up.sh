#!/usr/bin/env bash
# demo-up.sh — idempotent bootstrap for the mcp-k8s-secure-ops conference demo
# Usage: ./tests/demo/demo-up.sh
# Idempotent: safe to re-run; tears down previous cluster first.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER_NAME="secureops-demo"
OPA_CONTAINER="secureops-opa"
OPA_IMAGE="openpolicyagent/opa:0.68.0-static"
OPA_POLICY_DIR="${REPO_ROOT}/policies/opa/secureops"

# ── colour helpers ────────────────────────────────────────────────────────────
_bold() { printf '\033[1m%s\033[0m\n' "$*"; }
_step() { printf '\033[1;36m[STEP] %s\033[0m\n' "$*"; }
_ok()   { printf '\033[1;32m[ OK ] %s\033[0m\n' "$*"; }
_warn() { printf '\033[1;33m[WARN] %s\033[0m\n' "$*"; }
_err()  { printf '\033[1;31m[ERR ] %s\033[0m\n' "$*" >&2; }

banner() {
  echo ""
  _bold "╔══════════════════════════════════════════════════════════╗"
  _bold "║    mcp-k8s-secure-ops  ·  conference demo bootstrap     ║"
  _bold "╚══════════════════════════════════════════════════════════╝"
  echo ""
}

# ── prerequisite checks ───────────────────────────────────────────────────────
check_prereqs() {
  _step "Checking prerequisites…"
  local missing=0

  for cmd in kind kubectl helm docker uv; do
    if ! command -v "$cmd" &>/dev/null; then
      _err "Missing required tool: $cmd"
      missing=1
    else
      _ok "$cmd found"
    fi
  done

  if [[ $missing -eq 1 ]]; then
    echo ""
    echo "Install missing tools:"
    echo "  kind:    https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    echo "  kubectl: https://kubernetes.io/docs/tasks/tools/"
    echo "  helm:    https://helm.sh/docs/intro/install/"
    echo "  docker:  https://docs.docker.com/engine/install/"
    echo "  uv:      https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
  fi

  if ! docker info &>/dev/null; then
    _err "Docker daemon is not running. Please start Docker Desktop."
    exit 1
  fi
  _ok "Docker daemon reachable"
}

# ── kind cluster ──────────────────────────────────────────────────────────────
setup_kind_cluster() {
  _step "Tearing down any existing '${CLUSTER_NAME}' cluster…"
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true

  _step "Creating kind cluster '${CLUSTER_NAME}'…"
  kind create cluster --name "${CLUSTER_NAME}" --wait 60s
  _ok "kind cluster ready"
}

# ── Kyverno ───────────────────────────────────────────────────────────────────
install_kyverno() {
  _step "Adding Kyverno Helm repo…"
  helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update 2>/dev/null || true
  helm repo update

  _step "Installing Kyverno (this takes ~60 s)…"
  helm upgrade --install kyverno kyverno/kyverno \
    -n kyverno --create-namespace \
    --set admissionController.replicas=1 \
    --set backgroundController.enabled=false \
    --set cleanupController.enabled=false \
    --set reportsController.enabled=false \
    --wait --timeout 300s
  _ok "Kyverno installed"

  _step "Installing secureops-kyverno ClusterPolicies…"
  helm upgrade --install secureops-kyverno \
    "${REPO_ROOT}/helm/secureops-kyverno" \
    --namespace kyverno \
    --wait --timeout 120s
  _ok "secureops-kyverno ClusterPolicies applied"
}

# ── namespaces ────────────────────────────────────────────────────────────────
setup_namespaces() {
  _step "Creating demo namespaces…"
  kubectl create namespace demo-staging 2>/dev/null || true
  kubectl create namespace demo-prod    2>/dev/null || true
  kubectl label namespace demo-prod tier=prod --overwrite
  _ok "Namespaces: demo-staging, demo-prod (demo-prod labelled tier=prod)"
}

# ── RBAC seed ─────────────────────────────────────────────────────────────────
apply_rbac() {
  _step "Applying per-action RBAC manifests…"
  kubectl apply -f "${REPO_ROOT}/tests/demo/seed/rbac.yaml"
  _ok "RBAC applied"
}

# ── workloads ─────────────────────────────────────────────────────────────────
deploy_workloads() {
  _step "Deploying checkout workloads…"
  kubectl apply -f "${REPO_ROOT}/tests/demo/seed/checkout-staging.yaml"
  kubectl apply -f "${REPO_ROOT}/tests/demo/seed/checkout-prod.yaml"
  kubectl apply -f "${REPO_ROOT}/tests/demo/seed/pdb-prod.yaml"

  _step "Waiting for rollouts…"
  kubectl -n demo-staging rollout status deployment/checkout --timeout=120s
  kubectl -n demo-prod    rollout status deployment/checkout --timeout=120s
  _ok "Workloads ready"
}

# ── local OPA ─────────────────────────────────────────────────────────────────
start_opa() {
  _step "Starting local OPA container…"
  docker rm -f "${OPA_CONTAINER}" 2>/dev/null || true
  docker run -d \
    --name "${OPA_CONTAINER}" \
    -p 8181:8181 \
    -v "${OPA_POLICY_DIR}:/policies:ro" \
    "${OPA_IMAGE}" \
    run --server --log-level info --addr :8181 /policies
  _ok "OPA running at http://localhost:8181"

  # readiness wait — fail hard if OPA doesn't come up (demo needs it).
  local retries=30
  while [[ $retries -gt 0 ]]; do
    if curl -sf http://localhost:8181/health &>/dev/null; then
      _ok "OPA health check passed"
      # Smoke-test policy evaluation to catch rego parse errors early.
      local probe
      probe="$(curl -sf -X POST http://localhost:8181/v1/data/secureops/allow \
        -H 'content-type: application/json' \
        -d '{"input":{"tool_category":"read"}}' 2>/dev/null || true)"
      if echo "$probe" | grep -q '"allow":true'; then
        _ok "OPA policy smoke-test passed (read allowed)"
        return 0
      fi
      _err "OPA /v1/data/secureops/allow returned unexpected output: $probe"
      _err "Policy bundle may be malformed. See: docker logs ${OPA_CONTAINER}"
      exit 1
    fi
    retries=$((retries - 1))
    sleep 1
  done
  _err "OPA health check timed out after 30 s. See: docker logs ${OPA_CONTAINER}"
  exit 1
}

# ── audit DB ──────────────────────────────────────────────────────────────────
init_audit_db() {
  _step "Initialising audit DB directory…"
  mkdir -p "${HOME}/.secureops"
  rm -f "${HOME}/.secureops/audit.db"
  _ok "Audit DB path cleared: ${HOME}/.secureops/audit.db (MCP server will init schema on first use)"
}

# ── final instructions ────────────────────────────────────────────────────────
print_instructions() {
  echo ""
  _bold "══════════════════════════════════════════════════════════"
  _bold " Demo cluster is ready.  Set these env vars in your shell:"
  _bold "══════════════════════════════════════════════════════════"
  echo ""
  cat <<EOF
export KUBECONFIG=\$HOME/.kube/config
export SECUREOPS_OPA_URL=http://localhost:8181
export SECUREOPS_AUDIT_DB=\$HOME/.secureops/audit.db
EOF
  echo ""
  _bold "Claude Desktop mcpServers config snippet (paste into"
  _bold "\$HOME/Library/Application Support/Claude/claude_desktop_config.json):"
  echo ""
  cat <<EOF
{
  "mcpServers": {
    "secureops": {
      "command": "uv",
      "args": ["run", "--project", "${REPO_ROOT}", "mcp-k8s-secure-ops", "serve-mcp"],
      "env": {
        "KUBECONFIG": "${HOME}/.kube/config",
        "SECUREOPS_OPA_URL": "http://localhost:8181",
        "SECUREOPS_AUDIT_DB": "${HOME}/.secureops/audit.db"
      }
    }
  }
}
EOF
  echo ""
  _bold "Run the scenario scripts (operator cheat-sheets):"
  echo "  tests/demo/scenario_a_happy_path.sh"
  echo "  tests/demo/scenario_b_opa_denial.sh"
  echo "  tests/demo/scenario_c_audit_tamper.sh"
  echo "  tests/demo/scenario_d_blast_radius.sh"
  echo "  tests/demo/scenario_e_token_ttl.sh"
  echo ""
  _bold "When done: tests/demo/demo-down.sh"
  echo ""
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
  banner
  check_prereqs
  setup_kind_cluster
  install_kyverno
  setup_namespaces
  apply_rbac
  deploy_workloads
  start_opa
  init_audit_db
  print_instructions
}

main "$@"
