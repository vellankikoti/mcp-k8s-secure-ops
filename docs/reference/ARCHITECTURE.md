# Architecture: mcp-k8s-secure-ops

## System Overview

```
                                    ┌─────────────────────────────────────────────────┐
                                    │              Kubernetes Cluster                  │
                                    │                                                 │
┌──────────────┐                    │  ┌─────────────────────────────────────────┐    │
│  MCP Client  │                    │  │         Go Backend (API Server)          │    │
│  (Claude /   │───HTTP/SSE────────▶│  │                                         │    │
│   Cursor /   │                    │  │  ┌─────────────┐  ┌──────────────────┐  │    │
│   CLI)       │                    │  │  │   Query      │  │   MCP Protocol   │  │    │
└──────────────┘                    │  │  │   Router     │  │   Handler        │  │    │
                                    │  │  │              │  │   (FastMCP)      │  │    │
                                    │  │  │  Simple? ────│──│──▶ Tool Registry │  │    │
                                    │  │  │  │Yes   │No  │  │                  │  │    │
                                    │  │  │  ▼      ▼    │  └────────┬─────────┘  │    │
                                    │  │  │ Direct  AI   │           │            │    │
                                    │  │  │ Response Path│           │            │    │
                                    │  │  └──┬──────┬───┘           │            │    │
                                    │  │     │      │               │            │    │
                                    │  └─────┼──────┼───────────────┼────────────┘    │
                                    │        │      │               │                 │
                                    │        ▼      ▼               ▼                 │
                                    │  ┌──────────────┐   ┌─────────────────┐         │
                                    │  │  Direct K8s  │   │   OPA Policy    │         │
                                    │  │  Client (Go) │   │   Gate (Sidecar)│         │
                                    │  │              │   │                 │         │
                                    │  │  - List pods │   │  Evaluates tool │         │
                                    │  │  - Get logs  │   │  call against   │         │
                                    │  │  - Get metrics│  │  Rego policies  │         │
                                    │  │  (no AI)     │   │  BEFORE exec    │         │
                                    │  └──────┬───────┘   └────────┬────────┘         │
                                    │         │                    │                  │
                                    │         │                    ▼                  │
                                    │         │           ┌─────────────────┐         │
                                    │         │           │  Token Issuer   │         │
                                    │         │           │  (Go)           │         │
                                    │         │           │                 │         │
                                    │         │           │  Issues scoped  │         │
                                    │         │           │  SA token per   │         │
                                    │         │           │  tool call      │         │
                                    │         │           │  (5 min TTL)    │         │
                                    │         │           └────────┬────────┘         │
                                    │         │                    │                  │
                                    │         ▼                    ▼                  │
                                    │  ┌───────────────────────────────────┐           │
                                    │  │        Kubernetes API Server      │           │
                                    │  └───────────────────────────────────┘           │
                                    │                                                 │
                                    │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
                                    │  │Prometheus │  │OpenSearch│  │ Sample       │  │
                                    │  │          │  │          │  │ Workloads    │  │
                                    │  └──────────┘  └──────────┘  └──────────────┘  │
                                    └─────────────────────────────────────────────────┘
```

## The Hybrid Engine: When AI Is Used vs When It Is Not

This is the core architectural decision. Every query is classified before it touches any AI model.

### Classification Rules (implemented in Go backend)

```
DIRECT PATH (No AI, no token cost):
├── Pattern: Single-resource lookups
│   ├── "List pods in namespace X"          → kubectl get pods -n X
│   ├── "Get logs for pod Y"                → kubectl logs Y
│   ├── "CPU usage of deployment Z"         → Prometheus instant query
│   ├── "How many replicas for service W?"  → kubectl get deployment W
│   ├── "Show recent events in namespace X" → kubectl get events -n X
│   └── "What image is deployment Y using?" → kubectl get deployment Y -o jsonpath
│
│   Implementation: Go backend parses the query using keyword matching
│   and regex patterns. If it matches a known single-resource pattern,
│   it calls the Kubernetes/Prometheus API directly and returns
│   structured JSON. No MCP tool call, no AI inference.
│
│   Cost: $0 per query. Latency: <200ms.
│
AI PATH (MCP tools + LLM reasoning):
├── Pattern: Multi-source correlation
│   ├── "Why is checkout-service returning 500s?"
│   │   → Needs: pod status + logs + metrics + recent deploys + events
│   │   → Requires reasoning across multiple data sources
│   │
│   ├── "Should I scale payment-service?"
│   │   → Needs: current load + historical patterns + resource headroom
│   │   → Requires judgment based on context
│   │
│   ├── "What caused the latency spike 10 minutes ago?"
│   │   → Needs: metrics timeline + deployment history + log correlation
│   │   → Requires temporal reasoning
│   │
│   └── "Run the high-error-rate runbook for order-service"
│       → Needs: sequential tool chaining with conditional logic
│       → Requires decision-making at each step
│
│   Implementation: Query is forwarded to the MCP protocol handler.
│   The AI agent receives the tool list, decides which tools to call
│   and in what order, chains results, and produces a reasoned response.
│
│   Cost: LLM tokens per query. Latency: 5-30s depending on tool chain.
```

### How the Router Decides

The Go backend uses a simple, fast classification system — NOT another AI model:

```go
// Simplified classification logic
func ClassifyQuery(query string) QueryType {
    // 1. Check for exact command patterns (fastest)
    if matchesDirectPattern(query) {
        return DIRECT
    }

    // 2. Check for multi-resource indicators
    keywords := []string{"why", "should", "investigate", "diagnose",
                         "correlate", "compare", "runbook", "analyze",
                         "what caused", "root cause", "recommend"}
    for _, kw := range keywords {
        if containsInsensitive(query, kw) {
            return AI_PATH
        }
    }

    // 3. Check query complexity (multiple resource types mentioned)
    resourceMentions := countResourceTypes(query) // pods, deployments, services, etc.
    if resourceMentions > 1 {
        return AI_PATH
    }

    // 4. Default: direct path for simple queries
    return DIRECT
}
```

This is not a perfect classifier — it doesn't need to be. The worst case is a simple query goes through AI (costs a few cents extra) or a complex query gets a direct response that's incomplete (user can rephrase). In practice, the keyword approach catches 90%+ of cases correctly.

## Component Details

### 1. Go Backend (API Server + Query Router)

**Purpose:** Entry point for all requests. Routes between direct path and AI path. Handles Kubernetes client operations for direct queries. Manages token issuance.

**Key responsibilities:**
- HTTP server accepting queries from MCP clients
- Query classification (direct vs AI path)
- Direct Kubernetes API calls for simple queries (using client-go)
- Direct Prometheus API calls for simple metric queries
- Token issuance for MCP tool calls (projected service account tokens)
- Health check endpoint
- Metrics endpoint (Prometheus format)

**Why Go, not Python:**
- client-go is the canonical Kubernetes client — no wrapper, no translation layer
- Lower memory footprint for a sidecar deployment
- Better concurrency model for handling multiple simultaneous queries
- Faster startup time (matters for pod scheduling)
- Token operations and crypto are faster in Go

**Key dependencies:**
- `k8s.io/client-go` — Kubernetes API interaction
- `github.com/prometheus/client_golang` — Prometheus client and metrics exposition
- `github.com/open-policy-agent/opa/sdk` — OPA evaluation (can also use REST API)
- `go.opentelemetry.io/otel` — Tracing
- `github.com/gin-gonic/gin` or `net/http` — HTTP server

### 2. MCP Server (FastMCP Python)

**Purpose:** Exposes runbook-derived tools to AI agents via the MCP protocol. Only used when the query router sends a request down the AI path.

**Tools exposed (18 tools across 4 categories):**

```
DIAGNOSTIC TOOLS (read-only, low risk):
├── check_pod_health(namespace, label_selector)
│   → Returns: pod statuses, restart counts, conditions
│   → K8s API: GET /api/v1/namespaces/{ns}/pods
│
├── query_error_rate(service_name, time_range_minutes)
│   → Returns: error rate percentage, trend direction
│   → Prometheus: rate(http_requests_total{status=~"5.."}[{range}])
│
├── query_latency(service_name, percentile, time_range_minutes)
│   → Returns: latency value at percentile, trend
│   → Prometheus: histogram_quantile({pct}, rate(http_request_duration_seconds_bucket[{range}]))
│
├── get_pod_logs(namespace, pod_name, container, tail_lines, since_minutes)
│   → Returns: log lines (last N lines or since timestamp)
│   → K8s API: GET /api/v1/namespaces/{ns}/pods/{pod}/log
│
├── get_recent_events(namespace, involved_object, event_type)
│   → Returns: Kubernetes events filtered by type/object
│   → K8s API: GET /api/v1/namespaces/{ns}/events
│
├── get_deployment_history(namespace, deployment_name)
│   → Returns: rollout history with revisions, change causes, timestamps
│   → K8s API: GET /apis/apps/v1/namespaces/{ns}/deployments/{name}/revisions
│
├── check_resource_utilization(namespace, deployment_name)
│   → Returns: CPU/memory requests, limits, actual usage from metrics-server
│   → K8s API: metrics.k8s.io + resource specs
│
├── check_node_pressure(node_name)
│   → Returns: node conditions (MemoryPressure, DiskPressure, PIDPressure)
│   → K8s API: GET /api/v1/nodes/{name}
│
└── search_logs(namespace, service_name, query_string, time_range_minutes)
    → Returns: matching log entries from OpenSearch
    → OpenSearch API: POST /{index}/_search

REMEDIATION TOOLS (write operations, require approval):
├── scale_deployment(namespace, deployment_name, replicas)
│   → Action: scales deployment to specified replicas
│   → K8s API: PATCH /apis/apps/v1/namespaces/{ns}/deployments/{name}/scale
│   → Constraint: replicas must be 1-20 (configurable per deployment)
│
├── restart_deployment(namespace, deployment_name)
│   → Action: triggers rolling restart via annotation update
│   → K8s API: PATCH deployment with restart annotation
│   → Constraint: requires human approval if >5 replicas
│
├── cordon_node(node_name)
│   → Action: marks node as unschedulable
│   → K8s API: PATCH /api/v1/nodes/{name}
│   → Constraint: cannot cordon if <3 ready nodes remain
│
├── rollback_deployment(namespace, deployment_name, revision)
│   → Action: rolls back to specified revision
│   → K8s API: rollout undo
│   → Constraint: ALWAYS requires human approval
│
└── update_resource_limits(namespace, deployment_name, cpu_limit, memory_limit)
    → Action: patches deployment resource limits
    → K8s API: PATCH deployment spec
    → Constraint: limits must be within namespace quota

CORRELATION TOOLS (read-only, multi-source):
├── correlate_alerts(namespace, time_range_minutes)
│   → Returns: active alerts + their likely related resources
│   → Sources: Prometheus alertmanager API + K8s events
│
└── build_incident_timeline(namespace, service_name, time_range_minutes)
    → Returns: chronological timeline of events, deploys, metric changes
    → Sources: K8s events + deployment history + Prometheus range queries

META TOOLS:
└── estimate_blast_radius(namespace, deployment_name, action)
    → Returns: affected pods count, dependent services, traffic percentage
    → Sources: K8s API + Prometheus service-mesh metrics
    → Purpose: called before any remediation tool to assess risk
```

**Why Python for MCP tools:**
- FastMCP is the most mature MCP SDK — battle-tested, well-documented
- opentelemetry-instrumentation-mcp is a Python package — automatic tracing
- MCP tool definitions are declarative — Python's decorator syntax is clean for this
- The tools are thin wrappers — they call the Go backend or APIs directly

### 3. OPA Policy Gate (Sidecar)

**Purpose:** Evaluates every MCP tool call against Rego policies before the tool executes.

**How it works:**
1. MCP server receives tool call from AI agent
2. Before executing, it sends a policy check to OPA sidecar:
   ```json
   {
     "input": {
       "tool_name": "scale_deployment",
       "parameters": {"namespace": "prod", "deployment": "checkout", "replicas": 15},
       "caller_context": {"session_id": "abc123", "timestamp": "2026-04-20T03:00:00Z"},
       "cluster_state": {"current_replicas": 3, "namespace_quota_remaining_cpu": "4"}
     }
   }
   ```
3. OPA evaluates against policies and returns allow/deny with reason:
   ```json
   {
     "allow": false,
     "reason": "Requested replicas (15) exceeds maximum allowed (10) for deployment checkout",
     "policy": "scale_limits"
   }
   ```
4. If denied, the MCP tool returns a structured error to the AI agent (not a crash — a reason the agent can understand and adjust)

**Sample Rego policies:**

```rego
# policy: scale_limits.rego
package mcpops.scale

default allow = false

allow {
    input.parameters.replicas <= max_replicas[input.parameters.deployment]
    input.parameters.replicas >= 1
}

max_replicas := {
    "checkout-service": 10,
    "payment-service": 8,
    "user-service": 15,
}

# Default max if deployment not in list
max_replicas[d] = 5 {
    not max_replicas[d]
}
```

```rego
# policy: time_restrictions.rego
package mcpops.time

default allow = true

# Block destructive operations during peak hours without explicit approval
allow = false {
    input.tool_name == "rollback_deployment"
    is_peak_hours
    not input.parameters.explicit_approval
}

is_peak_hours {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour <= 18
}
```

```rego
# policy: namespace_restrictions.rego
package mcpops.namespace

default allow = false

# Only allow operations in permitted namespaces
allow {
    input.parameters.namespace == allowed_namespaces[_]
}

allowed_namespaces := ["staging", "dev", "prod-checkout", "prod-payment"]

# Never allow operations in kube-system
deny {
    input.parameters.namespace == "kube-system"
}
```

### 4. Token Issuer (Go, part of backend)

**Purpose:** Issues short-lived, scoped Kubernetes service account tokens for each MCP tool call.

**How it works:**
1. When an MCP tool is about to execute a K8s API call, it requests a token from the issuer
2. The issuer creates a projected service account token via the TokenRequest API
3. Token has:
   - 5-minute expiry (configurable per tool)
   - Audience scoped to the specific API group the tool needs
   - Bound to a service account with minimum RBAC for that specific tool
4. After the tool call completes (or 5 minutes pass), the token is invalid

**RBAC mapping (one ServiceAccount per tool category):**

```yaml
# ServiceAccount for diagnostic tools (read-only)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mcp-diagnostic-sa
  namespace: mcp-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: mcp-diagnostic-role
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "events", "nodes", "services"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets"]
    verbs: ["get", "list"]
  - apiGroups: ["metrics.k8s.io"]
    resources: ["pods", "nodes"]
    verbs: ["get", "list"]
---
# ServiceAccount for remediation tools (write, namespace-scoped)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: mcp-remediation-sa
  namespace: mcp-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role  # Note: Role not ClusterRole — namespace-scoped
metadata:
  name: mcp-remediation-role
  namespace: prod-checkout  # One Role per target namespace
rules:
  - apiGroups: ["apps"]
    resources: ["deployments", "deployments/scale"]
    verbs: ["get", "patch", "update"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "patch"]  # For cordon
```

### 5. Audit Logger (OpenTelemetry → OpenSearch)

**Purpose:** Creates a complete, searchable audit trail for every MCP tool interaction.

**What gets logged (structured, not free text):**

```json
{
  "trace_id": "abc123def456",
  "span_id": "span789",
  "timestamp": "2026-04-20T03:15:22Z",
  "event_type": "mcp_tool_call",
  "tool_name": "scale_deployment",
  "parameters": {
    "namespace": "prod-checkout",
    "deployment": "checkout-service",
    "replicas": 5
  },
  "policy_decision": {
    "allowed": true,
    "policy_name": "scale_limits",
    "evaluation_time_ms": 3
  },
  "token": {
    "service_account": "mcp-remediation-sa",
    "ttl_seconds": 300,
    "scoped_to_namespace": "prod-checkout"
  },
  "execution": {
    "status": "success",
    "duration_ms": 450,
    "cluster_action": "deployment.apps/checkout-service scaled to 5",
    "previous_state": {"replicas": 3},
    "new_state": {"replicas": 5}
  },
  "blast_radius": {
    "affected_pods": 5,
    "dependent_services": ["api-gateway", "order-service"],
    "traffic_percentage": 12.5
  }
}
```

**Trace propagation:** W3C TraceContext flows from MCP client → Go backend → MCP server → OPA → K8s API call. A single trace_id connects the entire chain.

## Directory Structure

```
mcp-k8s-secure-ops/
├── cmd/
│   └── server/
│       └── main.go                    # Go backend entry point
├── internal/
│   ├── router/
│   │   ├── classifier.go             # Query classification (direct vs AI)
│   │   ├── classifier_test.go
│   │   └── patterns.go               # Direct query patterns
│   ├── k8s/
│   │   ├── client.go                 # Kubernetes client wrapper
│   │   ├── pods.go                   # Pod operations (direct path)
│   │   ├── deployments.go            # Deployment operations
│   │   ├── events.go                 # Event queries
│   │   └── metrics.go                # Metrics-server queries
│   ├── prometheus/
│   │   ├── client.go                 # Prometheus HTTP API client
│   │   └── queries.go                # Common PromQL templates
│   ├── token/
│   │   ├── issuer.go                 # TokenRequest API wrapper
│   │   ├── issuer_test.go
│   │   └── rbac_mapping.go           # Tool → ServiceAccount mapping
│   ├── policy/
│   │   ├── opa_client.go             # OPA REST API client
│   │   └── opa_client_test.go
│   ├── audit/
│   │   ├── logger.go                 # Structured audit logging
│   │   └── otel_exporter.go          # OpenTelemetry trace exporter
│   └── server/
│       ├── handler.go                # HTTP handlers
│       └── middleware.go             # Auth, logging, tracing middleware
├── mcp/
│   ├── server.py                     # FastMCP server entry point
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── diagnostic.py             # Read-only diagnostic tools
│   │   ├── remediation.py            # Write operation tools
│   │   ├── correlation.py            # Multi-source correlation tools
│   │   └── meta.py                   # Blast radius estimation
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── policy_gate.py            # OPA check before tool execution
│   │   └── token_request.py          # Token request before K8s calls
│   └── requirements.txt
├── policies/
│   ├── scale_limits.rego
│   ├── namespace_restrictions.rego
│   ├── time_restrictions.rego
│   ├── destructive_operations.rego
│   └── data.json                     # Policy data (deployment configs)
├── deploy/
│   ├── helm/
│   │   └── mcp-k8s-secure-ops/
│   │       ├── Chart.yaml
│   │       ├── values.yaml
│   │       └── templates/
│   │           ├── deployment.yaml
│   │           ├── service.yaml
│   │           ├── serviceaccount.yaml
│   │           ├── clusterrole.yaml
│   │           ├── clusterrolebinding.yaml
│   │           ├── role.yaml
│   │           ├── rolebinding.yaml
│   │           ├── configmap-policies.yaml
│   │           └── opa-sidecar.yaml
│   └── kind/
│       ├── cluster-config.yaml        # Kind cluster with 3 nodes
│       └── sample-workloads.yaml      # Demo microservices
├── demo/
│   ├── scenarios/
│   │   ├── 01-working-incident.sh     # OOMKill scenario
│   │   ├── 02-security-block.sh       # Escalation attempt
│   │   ├── 03-wrong-correlation.sh    # 3 AM failure replay
│   │   └── inject-failure.sh          # Failure injection helper
│   └── DEMO_SCRIPT.md                # Minute-by-minute talk script
├── Dockerfile.backend                 # Go backend
├── Dockerfile.mcp                     # Python MCP server
├── docker-compose.yaml                # Local dev setup
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

## Data Flow: Complete Request Lifecycle

### Direct Path (simple query, no AI)
```
1. User asks: "How many pods in prod-checkout?"
2. Go backend receives HTTP request
3. Query Router classifies → DIRECT
4. Go backend calls K8s API: client.CoreV1().Pods("prod-checkout").List()
5. Returns JSON: {"pods": 8, "running": 7, "pending": 1}
6. Total time: ~150ms. AI tokens used: 0.
```

### AI Path (complex query, needs reasoning)
```
1. User asks: "Why is checkout-service throwing 500s?"
2. Go backend receives HTTP request
3. Query Router classifies → AI_PATH
4. Request forwarded to MCP Protocol Handler
5. AI agent receives tool list, decides to call:
   a. check_pod_health("prod-checkout", "app=checkout")
      → Policy gate: ALLOW (read-only)
      → Token: diagnostic-sa, 5min TTL
      → Result: 2 of 8 pods in CrashLoopBackOff
   b. get_pod_logs("prod-checkout", "checkout-abc123", "app", 100, 30)
      → Policy gate: ALLOW (read-only)
      → Token: diagnostic-sa, 5min TTL
      → Result: "java.lang.OutOfMemoryError: Java heap space"
   c. check_resource_utilization("prod-checkout", "checkout-service")
      → Result: memory limit 512Mi, actual usage 498Mi
   d. get_deployment_history("prod-checkout", "checkout-service")
      → Result: v2.3.1 deployed 45 min ago, changed JAVA_OPTS
6. AI agent reasons: "OOM because v2.3.1 removed -Xmx flag from JAVA_OPTS"
7. AI agent suggests: "Rollback to v2.3.0 or add -Xmx512m to JAVA_OPTS"
8. Total time: ~15s. AI tokens used: ~2000 input, ~500 output.
9. Full audit trail in OpenSearch with trace_id linking all 4 tool calls.
```

## Deployment Model

All components run inside the target Kubernetes cluster:

```yaml
# Single Pod with 3 containers
Pod:
  containers:
    - name: go-backend          # Port 8080
      image: mcp-k8s-secure-ops/backend:latest
      resources:
        requests: {cpu: 100m, memory: 128Mi}
        limits: {cpu: 500m, memory: 256Mi}

    - name: mcp-server          # Port 8081 (stdio or SSE)
      image: mcp-k8s-secure-ops/mcp:latest
      resources:
        requests: {cpu: 100m, memory: 128Mi}
        limits: {cpu: 500m, memory: 512Mi}

    - name: opa-sidecar         # Port 8181
      image: openpolicyagent/opa:latest
      args: ["run", "--server", "--addr", ":8181", "/policies"]
      resources:
        requests: {cpu: 50m, memory: 64Mi}
        limits: {cpu: 200m, memory: 128Mi}
```

## Security Boundaries Summary

| Layer | What It Prevents | How |
|-------|-----------------|-----|
| Query Router | Unnecessary AI token spend | Keyword classification |
| OPA Policy Gate | Unauthorized tool calls | Rego policy evaluation |
| Scoped RBAC | Over-permissioned API access | Per-tool ServiceAccount |
| Short-lived Tokens | Persistent credential abuse | 5-min TTL projected tokens |
| Blast Radius Check | Unchecked destructive actions | Pre-execution impact estimation |
| Human Approval Gate | Autonomous destructive ops | Mandatory confirm for rollback/delete |
| Audit Trail | Untracked actions | OTel traces + OpenSearch indexing |
