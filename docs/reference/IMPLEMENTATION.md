# Implementation Plan: mcp-k8s-secure-ops

## Build Order (4 weeks total)

Tasks are ordered by dependency. Each phase produces a working, testable system.

---

## Phase 1: Foundation (Week 1)

### Task 1.1: Kind Cluster + Sample Workloads
**What:** Create a reproducible demo environment.

**Files to create:**
- `deploy/kind/cluster-config.yaml` — 3-node kind cluster (1 control plane, 2 workers)
- `deploy/kind/sample-workloads.yaml` — 4 microservices:
  - `checkout-service` (Go or nginx stub, 3 replicas)
  - `payment-service` (Go or nginx stub, 2 replicas)
  - `order-service` (Go or nginx stub, 2 replicas)
  - `inventory-service` (Go or nginx stub, 2 replicas)
- `deploy/kind/prometheus-values.yaml` — Prometheus via kube-prometheus-stack Helm chart
- `deploy/kind/opensearch-values.yaml` — OpenSearch single-node for demo

**Sample workloads must:**
- Expose `/health`, `/metrics` (Prometheus format), and a `/api` endpoint
- Generate synthetic traffic (use a simple Go binary or `hey` load generator as a CronJob)
- Have realistic resource requests/limits (so resource utilization queries return real data)
- Include at least one workload configured for failure injection (e.g., environment variable to trigger OOM)

**Validation:** `kubectl get pods -A` shows all workloads running. Prometheus has metrics. OpenSearch is reachable.

### Task 1.2: Go Backend Skeleton
**What:** HTTP server with health check and basic routing structure.

**Files to create:**
- `cmd/server/main.go` — entry point, wire up dependencies
- `internal/server/handler.go` — HTTP handlers (health, query endpoint)
- `internal/server/middleware.go` — request logging, CORS
- `go.mod`, `go.sum`
- `Dockerfile.backend`

**The query endpoint contract:**
```
POST /api/query
Content-Type: application/json

Request:
{
  "query": "How many pods in prod-checkout?",
  "session_id": "optional-session-id"
}

Response (direct path):
{
  "type": "direct",
  "result": { ... structured data ... },
  "source": "kubernetes-api",
  "latency_ms": 142
}

Response (AI path):
{
  "type": "ai",
  "mcp_session": "forwarded to MCP server",
  "trace_id": "abc123"
}
```

**Validation:** Server starts, health check returns 200, query endpoint accepts POST.

### Task 1.3: Query Router (Classifier)
**What:** Classify incoming queries as DIRECT or AI_PATH.

**Files to create:**
- `internal/router/classifier.go`
- `internal/router/classifier_test.go` — at least 30 test cases
- `internal/router/patterns.go` — regex and keyword patterns

**Test cases must cover:**
```
DIRECT:
- "list pods in namespace checkout"         → DIRECT
- "get logs for pod checkout-abc123"        → DIRECT
- "how many replicas does payment have?"    → DIRECT
- "show events in staging"                  → DIRECT
- "cpu usage of checkout-service"           → DIRECT
- "what image is payment-service running?"  → DIRECT

AI_PATH:
- "why is checkout returning errors?"       → AI_PATH
- "should I scale payment-service?"         → AI_PATH
- "investigate the latency spike"           → AI_PATH
- "run the high error rate runbook"         → AI_PATH
- "what caused the outage at 3am?"          → AI_PATH
- "correlate the alerts in prod"            → AI_PATH

EDGE CASES:
- "pods"                                    → DIRECT (simple, single resource)
- "what's wrong?"                           → AI_PATH (vague, needs investigation)
- "scale checkout to 5 replicas"            → AI_PATH (write operation, needs safety)
```

**Validation:** All 30+ test cases pass. `go test ./internal/router/ -v`

---

## Phase 2: Direct Path (Week 2, first half)

### Task 2.1: Kubernetes Client Operations
**What:** Go functions that query the Kubernetes API for direct-path responses.

**Files to create:**
- `internal/k8s/client.go` — client initialization, kubeconfig handling
- `internal/k8s/pods.go` — ListPods, GetPodLogs, GetPodStatus
- `internal/k8s/deployments.go` — GetDeployment, GetReplicas, GetImage, GetHistory
- `internal/k8s/events.go` — ListEvents (filtered by namespace, type, object)
- `internal/k8s/metrics.go` — GetResourceUsage (from metrics-server)

**Each function must:**
- Accept structured parameters (namespace, name, filters)
- Return structured JSON (not raw kubectl output)
- Handle errors gracefully (namespace not found, pod not found, metrics-server unavailable)
- Include timeout (10 seconds per call)

**Example function signature:**
```go
func (c *K8sClient) ListPods(ctx context.Context, namespace string, labelSelector string) (*PodListResult, error)

type PodListResult struct {
    Total    int         `json:"total"`
    Running  int         `json:"running"`
    Pending  int         `json:"pending"`
    Failed   int         `json:"failed"`
    Pods     []PodSummary `json:"pods"`
}

type PodSummary struct {
    Name          string    `json:"name"`
    Status        string    `json:"status"`
    Restarts      int       `json:"restarts"`
    Age           string    `json:"age"`
    Node          string    `json:"node"`
    CPUUsage      string    `json:"cpu_usage,omitempty"`
    MemoryUsage   string    `json:"memory_usage,omitempty"`
}
```

**Validation:** Unit tests with fake clientset. Integration test against kind cluster.

### Task 2.2: Prometheus Client Operations
**What:** Go functions that query Prometheus for direct-path metric responses.

**Files to create:**
- `internal/prometheus/client.go` — Prometheus HTTP API client
- `internal/prometheus/queries.go` — template-based PromQL query builder

**Supported queries:**
- CPU usage by deployment: `sum(rate(container_cpu_usage_seconds_total{namespace="X", pod=~"deployment-.*"}[5m]))`
- Memory usage by deployment: `sum(container_memory_working_set_bytes{namespace="X", pod=~"deployment-.*"})`
- Error rate by service: `rate(http_requests_total{namespace="X", service="Y", status=~"5.."}[5m])`
- Request rate by service: `rate(http_requests_total{namespace="X", service="Y"}[5m])`

**Validation:** Queries return data from the Prometheus instance running in kind cluster.

---

## Phase 3: AI Path — MCP Server + OPA (Week 2, second half + Week 3)

### Task 3.1: FastMCP Server with Diagnostic Tools
**What:** Python MCP server exposing read-only diagnostic tools.

**Files to create:**
- `mcp/server.py` — FastMCP server initialization
- `mcp/tools/diagnostic.py` — 9 diagnostic tools (see ARCHITECTURE.md for full list)
- `mcp/requirements.txt`
- `Dockerfile.mcp`

**Each tool must:**
- Have a clear docstring (the AI agent reads this to decide when to use the tool)
- Accept typed parameters with validation
- Return structured JSON (not free text)
- Include error handling that returns useful error messages (not stack traces)
- Call the Go backend's internal API for actual Kubernetes/Prometheus operations

**Example tool definition:**
```python
from fastmcp import FastMCP

mcp = FastMCP("mcp-k8s-secure-ops")

@mcp.tool()
async def check_pod_health(
    namespace: str,
    label_selector: str = ""
) -> dict:
    """Check health status of pods in a namespace.

    Returns pod count, status breakdown, and details for any unhealthy pods.
    Use this when investigating service issues to see if pods are crashing,
    pending, or in error states.

    Args:
        namespace: Kubernetes namespace to check
        label_selector: Optional label filter (e.g., "app=checkout-service")
    """
    # Call Go backend internal API
    response = await http_client.get(
        f"{GO_BACKEND_URL}/internal/k8s/pods",
        params={"namespace": namespace, "labelSelector": label_selector}
    )
    return response.json()
```

**Validation:** MCP server starts. Tools are listed via MCP protocol. Each tool returns valid JSON when called.

### Task 3.2: Remediation Tools with OPA Integration
**What:** Write-operation MCP tools that check OPA before executing.

**Files to create:**
- `mcp/tools/remediation.py` — 5 remediation tools
- `mcp/middleware/policy_gate.py` — OPA check middleware
- `mcp/middleware/token_request.py` — Token request from Go backend
- `policies/scale_limits.rego`
- `policies/namespace_restrictions.rego`
- `policies/time_restrictions.rego`
- `policies/destructive_operations.rego`
- `policies/data.json`

**Policy gate flow (in policy_gate.py):**
```python
async def check_policy(tool_name: str, parameters: dict) -> PolicyDecision:
    """Check OPA before tool execution. Returns allow/deny with reason."""
    payload = {
        "input": {
            "tool_name": tool_name,
            "parameters": parameters,
            "timestamp": datetime.utcnow().isoformat(),
        }
    }
    response = await http_client.post(
        f"{OPA_URL}/v1/data/mcpops/{tool_name.split('_')[0]}",
        json=payload
    )
    result = response.json().get("result", {})
    return PolicyDecision(
        allowed=result.get("allow", False),
        reason=result.get("reason", "Policy evaluation failed"),
        policy_name=result.get("policy", "unknown")
    )
```

**If policy denies, the tool returns:**
```json
{
  "status": "denied",
  "reason": "Requested replicas (15) exceeds maximum allowed (10) for deployment checkout-service",
  "policy": "scale_limits",
  "suggestion": "Request replicas between 1 and 10"
}
```
This is a structured response the AI agent can understand and adjust to — NOT a crash or exception.

**Validation:** OPA sidecar running. Remediation tools correctly blocked when policy denies. Allowed when policy permits.

### Task 3.3: Token Issuer
**What:** Go backend component that issues short-lived scoped tokens.

**Files to create:**
- `internal/token/issuer.go`
- `internal/token/issuer_test.go`
- `internal/token/rbac_mapping.go`

**Token issuance flow:**
```go
func (i *TokenIssuer) IssueToken(ctx context.Context, toolCategory string, targetNamespace string) (*Token, error) {
    // 1. Look up ServiceAccount for this tool category
    sa := i.rbacMapping[toolCategory] // e.g., "diagnostic" → "mcp-diagnostic-sa"

    // 2. Create TokenRequest via K8s API
    tokenRequest := &authv1.TokenRequest{
        Spec: authv1.TokenRequestSpec{
            ExpirationSeconds: int64Ptr(300), // 5 minutes
            Audiences:         []string{"https://kubernetes.default.svc"},
        },
    }
    result, err := i.clientset.CoreV1().ServiceAccounts("mcp-system").
        CreateToken(ctx, sa, tokenRequest, metav1.CreateOptions{})

    // 3. Return token with metadata
    return &Token{
        Value:     result.Status.Token,
        ExpiresAt: result.Status.ExpirationTimestamp.Time,
        Scope:     toolCategory,
        Namespace: targetNamespace,
    }, nil
}
```

**Validation:** Token is issued, used for a K8s API call, and fails after expiry (5 min).

### Task 3.4: Correlation and Meta Tools
**What:** Tools that cross-reference multiple data sources (these always go through AI path).

**Files to create:**
- `mcp/tools/correlation.py` — correlate_alerts, build_incident_timeline
- `mcp/tools/meta.py` — estimate_blast_radius

**blast_radius estimation logic:**
```python
async def estimate_blast_radius(namespace: str, deployment_name: str, action: str) -> dict:
    """Estimate the impact of a remediation action before execution.

    This tool MUST be called before any remediation tool. It returns:
    - Number of pods affected
    - List of dependent services (from Prometheus traffic data)
    - Percentage of total namespace traffic affected
    - Risk level: low/medium/high/critical

    The AI agent should present this to the user before proceeding.
    """
    # 1. Get current pod count
    pods = await call_go_backend("/internal/k8s/pods", namespace=namespace,
                                  labelSelector=f"app={deployment_name}")

    # 2. Get dependent services from Prometheus
    # Query: which services send traffic TO this deployment?
    dependents = await call_go_backend("/internal/prometheus/query",
        query=f'sum by (source_service) (rate(istio_requests_total{{destination_service="{deployment_name}"}}[5m]))')

    # 3. Calculate traffic percentage
    total_traffic = await call_go_backend("/internal/prometheus/query",
        query=f'sum(rate(http_requests_total{{namespace="{namespace}"}}[5m]))')
    service_traffic = await call_go_backend("/internal/prometheus/query",
        query=f'sum(rate(http_requests_total{{namespace="{namespace}", service="{deployment_name}"}}[5m]))')

    traffic_pct = (service_traffic / total_traffic * 100) if total_traffic > 0 else 0

    # 4. Risk level
    risk = "low"
    if traffic_pct > 50: risk = "critical"
    elif traffic_pct > 25: risk = "high"
    elif traffic_pct > 10: risk = "medium"

    return {
        "affected_pods": pods["total"],
        "dependent_services": [d["source_service"] for d in dependents],
        "traffic_percentage": round(traffic_pct, 1),
        "risk_level": risk,
        "recommendation": f"{'Requires human approval' if risk in ['high', 'critical'] else 'Proceed with caution'}"
    }
```

**Validation:** Blast radius tool returns accurate data for sample workloads. Correlation tools produce sensible timelines.

---

## Phase 4: Audit Trail + Integration (Week 3, second half)

### Task 4.1: OpenTelemetry Integration
**What:** Add distributed tracing across all components.

**Files to create:**
- `internal/audit/logger.go` — structured audit log entries
- `internal/audit/otel_exporter.go` — export traces to OpenSearch/Jaeger
- `mcp/middleware/__init__.py` — OTel middleware for FastMCP

**Instrumentation points:**
1. Go backend: trace each incoming request (span: `query.classify`, `query.direct`, `query.forward_to_mcp`)
2. MCP server: trace each tool call (span: `mcp.tool.{tool_name}`)
3. OPA check: trace policy evaluation (span: `policy.evaluate`)
4. Token issuance: trace token creation (span: `token.issue`)
5. K8s API call: trace the actual cluster operation (span: `k8s.api.{verb}.{resource}`)

**Use the opentelemetry-instrumentation-mcp PyPI package** for automatic MCP-level tracing. Add custom spans for the security layer.

**Validation:** A single query produces a complete trace visible in Jaeger/OpenSearch with all spans connected.

### Task 4.2: Helm Chart
**What:** Deployable Helm chart for the full system.

**Files to create:**
- `deploy/helm/mcp-k8s-secure-ops/Chart.yaml`
- `deploy/helm/mcp-k8s-secure-ops/values.yaml`
- `deploy/helm/mcp-k8s-secure-ops/templates/*.yaml` (10+ template files)

**values.yaml must expose:**
```yaml
goBackend:
  image: mcp-k8s-secure-ops/backend:latest
  replicas: 1
  resources:
    requests: {cpu: 100m, memory: 128Mi}
    limits: {cpu: 500m, memory: 256Mi}

mcpServer:
  image: mcp-k8s-secure-ops/mcp:latest
  transport: sse  # or stdio
  resources:
    requests: {cpu: 100m, memory: 128Mi}
    limits: {cpu: 500m, memory: 512Mi}

opa:
  image: openpolicyagent/opa:latest-static
  policies: {}  # Override default policies

tokenIssuer:
  defaultTTL: 300  # seconds
  maxTTL: 600

audit:
  enabled: true
  opensearchUrl: http://opensearch:9200
  traceExporter: otlp  # or jaeger

# Namespaces the MCP server is allowed to operate in
allowedNamespaces:
  - staging
  - prod-checkout
  - prod-payment
```

**Validation:** `helm install mcp-ops ./deploy/helm/mcp-k8s-secure-ops` succeeds on kind cluster. All pods running.

---

## Phase 5: Demo Scenarios + Polish (Week 4)

### Task 5.1: Demo Scenarios
**What:** Scripted failure injection and demo walkthrough.

**Files to create:**
- `demo/scenarios/01-working-incident.sh` — Triggers OOMKill on checkout-service
- `demo/scenarios/02-security-block.sh` — Attempts unauthorized operations
- `demo/scenarios/03-wrong-correlation.sh` — Injects two simultaneous unrelated failures
- `demo/scenarios/inject-failure.sh` — Helper script for failure injection
- `demo/DEMO_SCRIPT.md` — Minute-by-minute talk script with fallback plans

**Failure injection methods:**
```bash
# OOMKill: set memory limit to 32Mi on a pod doing work
kubectl set resources deployment/checkout-service -c app --limits=memory=32Mi -n prod-checkout

# Network latency: use tc via ephemeral debug container (or Chaos Mesh if installed)
kubectl exec -it checkout-pod -- tc qdisc add dev eth0 root netem delay 5000ms

# Simultaneous unrelated failures (for wrong-correlation demo):
# 1. OOMKill on checkout-service
# 2. Network latency on payment-service (unrelated)
# Both generate alerts at the same time
```

### Task 5.2: Makefile + CI
**What:** One-command setup, test, and demo.

```makefile
.PHONY: setup deploy demo test clean

setup:
	kind create cluster --config deploy/kind/cluster-config.yaml --name mcp-demo
	kubectl apply -f deploy/kind/sample-workloads.yaml
	helm install prometheus prometheus-community/kube-prometheus-stack -f deploy/kind/prometheus-values.yaml
	helm install opensearch opensearch/opensearch -f deploy/kind/opensearch-values.yaml

build:
	docker build -t mcp-k8s-secure-ops/backend -f Dockerfile.backend .
	docker build -t mcp-k8s-secure-ops/mcp -f Dockerfile.mcp .
	kind load docker-image mcp-k8s-secure-ops/backend mcp-k8s-secure-ops/mcp --name mcp-demo

deploy: build
	helm install mcp-ops deploy/helm/mcp-k8s-secure-ops/

test:
	go test ./... -v
	cd mcp && python -m pytest tests/ -v

demo:
	@echo "Starting demo scenario..."
	bash demo/scenarios/01-working-incident.sh

clean:
	kind delete cluster --name mcp-demo
```

### Task 5.3: Documentation
**What:** README, contribution guide, and configuration reference.

**Validation:** A new developer can clone the repo, run `make setup && make deploy && make demo`, and see the full system working within 15 minutes.

---

## Dependency Versions (Pin Everything)

```
# Go
go: 1.22+
k8s.io/client-go: v0.30.0
github.com/open-policy-agent/opa: v0.68.0
go.opentelemetry.io/otel: v1.28.0
github.com/prometheus/client_golang: v1.19.0

# Python
python: 3.11+
fastmcp: >=2.0.0
opentelemetry-sdk: >=1.25.0
opentelemetry-instrumentation-mcp: >=0.3.0
httpx: >=0.27.0
pytest: >=8.0.0

# Infrastructure
kind: v0.23.0
kubectl: v1.30+
helm: v3.15+
opa: v0.68.0 (Docker image)
prometheus: via kube-prometheus-stack chart v61+
opensearch: v2.15+ (single-node for demo)
```
