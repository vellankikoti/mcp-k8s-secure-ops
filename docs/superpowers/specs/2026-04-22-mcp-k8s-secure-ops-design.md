# mcp-k8s-secure-ops — Design Spec

**Status:** draft for review
**Date:** 2026-04-22
**Target release:** v1.0.0 — single tagged release containing 18 tools, OPA + Kyverno + TokenRequest stack, cosign-signed image, SBOM, two Helm charts.

## Goal

Turn Kubernetes incident-response runbooks into secure, auditable MCP tools. An LLM agent can assist with real cluster writes (restart, drain, scale, rollback, cordon, evict) without ever holding cluster credentials or being the decision point on a write — OPA + Kyverno + short-lived ServiceAccount tokens are the gates.

## Positioning in the series

Fourth and final conference project. Depends on no other project at runtime but reuses primitives:

- `DeployContext.guard(needs=…)` pattern from 03 (deploy-intel).
- Check-pattern + kind golden-isolation from 04 (prod-readiness).
- `observatory-sdk` as runtime dep for self-instrumentation.

Project 00 (`mcp-k8s-utility`, capstone) will depend on this project's secure-ops *broker* for every write action it ships. No other conference project writes to clusters.

## Scope decisions (locked during brainstorming)

| # | Decision |
|---|----------|
| 1 | v1.0.0 ships full writes. OPA + Kyverno + short-lived tokens are the guardrails. |
| 2 | Defense-in-depth: OPA pre-flight inside the MCP server *and* Kyverno admission inside the cluster. |
| 3 | Short-lived identity via K8s `TokenRequest` API, minting 5-min tokens bound to per-action ServiceAccounts. |
| 4 | Blast-radius: transitive dependency graph + Prometheus traffic awareness. |
| 5 | Audit: aiosqlite source-of-truth + OTel span export + K8s Event emission, composable via flags. |
| 6 | Full 18-tool surface in v1.0.0 (no MVP slice). |
| 7 | LLM confined to `explain_*` tools; deterministic core. LLM never touches cluster, never decides writes. |
| 8 | Deterministic router for `plan_incident_response`; LLM can narrate plans but not produce them. |
| 9 | Policy distribution: ConfigMap (quickstart) *and* OCI bundle registry (prod), flag-selected. |
| 10 | Demo: happy-path restart (2 min) + explicit OPA denial for `scale=0` + safe alternative (1 min). |

## Architecture

### Topology

Per cluster, one Helm release installs:

- **mcp-secure-ops server** (Python 3.11 / FastMCP 3.x; stdio or HTTP transport).
- **OPA sidecar** (official `openpolicyagent/opa` image) on `localhost:8181`.
- **Kyverno** — cluster-wide, shipped as a sibling Helm subchart (`secureops-kyverno`), not per-release. Admission-time backstop.

Stateful dependency: aiosqlite audit ledger on a PVC. OTel exporter + K8s Event emitter are stateless side-effects on every write.

### Identity model

- Broker SA (`secureops-broker`) — cluster-wide, can `create` on `serviceaccounts/token` for per-action SAs, `get/list/watch` read-only on core resources for blast-radius. Never has write verbs directly.
- Per-action SAs (`secureops-action-<verb>-<ns>`) — one per (action-kind, namespace) tuple, holding the minimum RBAC for that action only (e.g. `patch` on `deployments/scale` in namespace X).
- At tool-call time: broker mints a 5-min token against the per-action SA via `TokenRequest`; the write executes with that token and nothing else.

### Tool call flow (write)

```
Claude → MCP tool call
  → Python tool builds ActionProposal (blast_radius graph included)
  → POST /v1/data/secureops/allow to OPA sidecar → OPADecision
  → if denied: return structured denial + optional LLM narration, audit row
  → if allowed: TokenRequest mints per-action token (5 min TTL)
  → execute write with minted token
  → Kyverno admission validates at apiserver (second gate)
  → ActionResult + audit row (SQLite source of truth; OTel + K8s Event sinks)
```

Read flow skips OPA / TokenRequest / Kyverno and uses the broker SA's read-only RBAC directly. Audit is still recorded.

### LLM boundary (critical invariant)

1. LLM has no kubeconfig, no token, no K8s client.
2. LLM never decides writes. OPA + Kyverno are the gates.
3. LLM sees only post-hoc structured summaries (redacted `ActionProposal` / `ActionResult`). Raw manifests and Secrets are never passed.
4. LLM surface is the `explain_*` tool family only; all `explain_*` tools have deterministic templated fallbacks (`--no-llm` gives identical behavior).
5. No LLM in the hot path. Incident demo works with `--no-llm`.

## Tool surface (18 tools)

**Cluster state (5, read-only):**
1. `list_workloads(namespace?, kind?)`
2. `describe_workload(ref)`
3. `get_recent_events(namespace?, since?)`
4. `get_pod_logs(ref, tail?, since?)`
5. `find_unhealthy_workloads(namespace?)`

**Blast-radius (4, read-only):**
6. `compute_blast_radius(action_proposal)` — returns full `BlastRadius`.
7. `check_pdb_impact(target)`
8. `get_traffic_snapshot(target)` — Prometheus RPS/error-rate.
9. `find_dependents(target)` — transitive graph.

**Remediation (6, writes, OPA-gated):**
10. `restart_deployment(ref)`
11. `scale_workload(ref, replicas)`
12. `rollback_deployment(ref, to_revision?)`
13. `drain_node(node, plan)` — honors PDBs via plan from `recommend_node_drain_plan` (note: *recommend* lives in project 00; here we only execute an externally-provided plan).
14. `cordon_node(node)` / uncordon variant via a parameter.
15. `evict_pod(ref, reason)`

**Audit (3, read-only):**
16. `query_audit(filters)` — time, actor, target, status.
17. `export_audit(format, since)` — JSON or NDJSON.
18. `verify_chain(since)` — walks the hash chain, reports any break.

**Explain family (companions, not counted in 18):**
- `explain_opa_decision(decision)`, `explain_blast_radius(blast)`, `explain_incident_plan(plan)`, `explain_audit_row(row)`. All have deterministic fallbacks.

**Router (deterministic):**
- `plan_incident_response(symptom)` — rule-based routing to the above tools; no LLM.

## Package layout

Two packages in a monorepo.

```
packages/
  server/                          # mcp-k8s-secure-ops (PyPI)
    src/secureops_server/
      cli.py
      mcp_server.py
      context.py
      tools/
        cluster_state/
        blast_radius/
        remediation/
        audit/
      policy/
        opa_client.py
        opa_bundles.py
        kyverno_manifests.py
      tokens/
        broker.py
        rbac_templates.py
      audit/
        ledger.py
        otel_exporter.py
        event_emitter.py
      blast_radius/
        graph.py
        traffic.py
      models.py

  policy_sdk/                      # mcp-secureops-policy-sdk (PyPI, small)
    src/secureops_policy_sdk/
      __init__.py
      testing.py

helm/
  secureops/                       # main chart
  secureops-kyverno/               # sibling subchart

policies/
  opa/secureops/
    allow.rego
    blast_radius.rego
    denial_reasons.rego
  kyverno/

tests/
  unit/
  policy/
  golden/
  integration/
  mcp_contract/
```

## Data models (pydantic v2, `from __future__ import annotations`)

```python
class K8sRef(BaseModel):
    kind: str
    api_version: str
    namespace: str | None
    name: str
    uid: str | None

class Actor(BaseModel):
    mcp_client_id: str
    human_subject: str | None

class TrafficSnapshot(BaseModel):
    rps: float
    error_rate: float
    p99_latency_ms: float
    source: Literal["prometheus", "unavailable"]

class PDBViolation(BaseModel):
    pdb: K8sRef
    current_available: int
    min_available: int

class BlastRadius(BaseModel):
    direct: list[K8sRef]
    one_hop: list[K8sRef]
    transitive: list[K8sRef]
    traffic: TrafficSnapshot
    pdb_violations: list[PDBViolation]
    data_loss_risk: Literal["none", "pvc_unmounted", "pvc_deleted"]

class ActionProposal(BaseModel):
    action_id: str
    tool_name: str
    actor: Actor
    target: K8sRef
    parameters: dict[str, Any]
    blast_radius: BlastRadius
    requested_at: datetime

class OPADecision(BaseModel):
    allow: bool
    reasons: list[str]
    matched_policies: list[str]
    evaluated_at: datetime

class ActionResult(BaseModel):
    action_id: str
    status: Literal["allowed_executed", "allowed_failed",
                    "denied_opa", "denied_kyverno", "denied_preflight"]
    opa_decision: OPADecision
    kyverno_warnings: list[str]
    token_ttl_remaining_s: int | None
    k8s_response: dict[str, Any] | None
    error: str | None
    completed_at: datetime

class AuditRow(BaseModel):
    row_id: int
    action_id: str
    prev_hash: str
    row_hash: str
    proposal: ActionProposal
    result: ActionResult
    exported_to: list[Literal["otel", "k8s_event"]]
```

Invariants:
- Same `ActionProposal` instance feeds OPA and the audit row. No shadow state.
- `AuditRow.prev_hash` chains rows; `verify_chain` tool proves tamper-evidence.

## Error handling

- All tool entry points return typed results; no exceptions cross MCP boundary.
- OPA unreachable → fail-closed: `status="denied_preflight"`, reason `opa_unavailable`.
- TokenRequest failure → `status="denied_preflight"`, reason `token_mint_failed`.
- Kyverno denial captured from admission → `status="denied_kyverno"` with webhook message.
- K8s API timeout mid-write → `status="allowed_failed"`, audit still recorded. No auto-retry on writes.
- LLM failure in `explain_*` → deterministic template fallback. Never blocks action path.

## Testing pyramid

| Layer | Tooling | Scope |
|---|---|---|
| unit | pytest, mocked kubernetes_asyncio / OPA / Prometheus | per-tool logic, models |
| policy | `opa test` (rego), `kyverno test` | policies alone, no cluster |
| golden | pytest + pinned JSON fixtures | `ActionProposal` → expected `OPADecision` |
| integration | kind + real OPA sidecar + Kyverno installed | full flow, per-check isolation per Docker-flakiness lesson |
| mcp_contract | stdio JSON-RPC harness | 18-tool enumeration, happy-path + denial scenarios |

## Release pipeline

- PyPI trusted publishers with GitHub environments: `pypi-server`, `pypi-policy-sdk`.
- Multi-arch GHCR image: `ghcr.io/vellankikoti/mcp-k8s-secure-ops`.
- cosign keyless signing via Sigstore (identity regex pinned).
- CycloneDX SBOM via anchore/sbom-action, attached to GitHub Release.
- Helm charts published to GHCR OCI: `secureops`, `secureops-kyverno`.
- OPA policy bundle published as separate OCI artifact: `ghcr.io/vellankikoti/secureops-policies:<tag>`.
- CI gates: ruff check, ruff format --check, mypy --strict, `opa test`, `kyverno test`, unit, integration (kind), mcp_contract.

## Implementation phasing (internal to the single v1.0.0 tag)

Subagent-driven TDD, one phase per subagent dispatch, each ending at green CI + commit.

1. **Foundations** — models, `SecureOpsContext.guard`, CLI skeleton, empty MCP server, audit ledger schema.
2. **Cluster-state tools (5)** + audit ledger impl + OTel/Event sinks.
3. **Blast-radius engine** (graph + Prometheus traffic) + 4 blast-radius tools.
4. **Policy stack** — OPA sidecar integration, policy bundle loader (ConfigMap + OCI), `TokenRequest` broker, per-action RBAC templates, **one** exemplar write tool (`restart_deployment`) end-to-end through the full flow. Demo scenario A runnable here.
5. **Remaining 5 write tools** + Kyverno subchart + `explain_*` family + `plan_incident_response` router + audit query/export/verify + demo scenario B (denial) + release pipeline + tag **v1.0.0**.

## Success criteria for v1.0.0

- 18 tools reachable via MCP stdio; contract test green.
- Happy-path demo: wedged Deployment → `plan_incident_response` → `restart_deployment` → green, under 3 min in a kind cluster.
- Denial demo: `scale_workload(replicas=0)` on a prod-labelled namespace → OPA denial with structured reason + `explain_opa_decision` narration; safe alternative (`restart_deployment`) allowed.
- All writes audited to SQLite + OTel span + K8s Event; `verify_chain` clean.
- PyPI + GHCR image + Helm charts + policy OCI bundle all published via trusted publisher / cosign.
- README claims "auditable AI-assisted K8s remediation" backed by reproducible demo timings.

## Non-goals

- Cert lifecycle, node patching, resource right-sizing, PDB management, disk/log hygiene, eviction diagnostics — all belong to Project 00 (`mcp-k8s-utility`).
- LLM-driven incident planning — router is deterministic in v1.0.0. May ship as `--llm-plan` opt-in in v1.x.
- Multi-cluster federation — single cluster per release. Federation pattern is a v1.x follow-up.
