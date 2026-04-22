# Demo harness — mcp-k8s-secure-ops

Everything you need to run the conference demo live or rehearse it offline.

## Quick start

```bash
# 1. Bootstrap the demo environment (kind cluster + OPA + seeded workloads)
./tests/demo/demo-up.sh

# 2. Export the printed env vars, then wire Claude Desktop (see docs/claude-desktop-config.md)

# 3. Run scenarios in order
./tests/demo/scenario_a_happy_path.sh
./tests/demo/scenario_b_opa_denial.sh
./tests/demo/scenario_c_audit_tamper.sh
./tests/demo/scenario_d_blast_radius.sh
./tests/demo/scenario_e_token_ttl.sh

# 4. Tear down when done
./tests/demo/demo-down.sh
```

## What's in `tests/demo/`

| File | Purpose |
|------|---------|
| `demo-up.sh` | Idempotent bootstrap: kind cluster, Kyverno, OPA container, seeded workloads |
| `demo-down.sh` | Tear down cluster, OPA container, audit DB |
| `seed/checkout-staging.yaml` | nginx:1.27 Deployment in `demo-staging` (3 replicas) |
| `seed/checkout-prod.yaml` | nginx:1.27 Deployment in `demo-prod` (3 replicas) |
| `seed/pdb-prod.yaml` | PodDisruptionBudget for checkout in `demo-prod` (minAvailable=2) |
| `seed/rbac.yaml` | Per-action ServiceAccounts, Roles, RoleBindings for restart and scale verbs |
| `scenario_a_happy_path.sh` | Operator cheat-sheet: happy-path restart in demo-staging |
| `scenario_b_opa_denial.sh` | Operator cheat-sheet: OPA denies scale-to-zero in demo-prod |
| `scenario_c_audit_tamper.sh` | Operator cheat-sheet: tamper with audit row, verify_chain fails |
| `scenario_d_blast_radius.sh` | Operator cheat-sheet: compute_blast_radius output and PDB |
| `scenario_e_token_ttl.sh` | Operator cheat-sheet: per-action token TTL and RBAC can-i checks |

Each `scenario_*.sh` is an **operator cheat-sheet**, not an automated test. It:
- Prints the Claude Desktop prompt to use on stage
- Shows what tools Claude should call and what to expect
- Provides CLI equivalents for rehearsal or as a fallback if Claude Desktop flakes

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| `kind` | ≥ 0.20 | https://kind.sigs.k8s.io |
| `kubectl` | ≥ 1.28 | https://kubernetes.io/docs/tasks/tools/ |
| `helm` | ≥ 3.12 | https://helm.sh/docs/intro/install/ |
| `docker` | ≥ 24 | https://docs.docker.com/engine/install/ |
| `uv` | ≥ 0.4 | https://docs.astral.sh/uv/ |
| `sqlite3` | any | pre-installed on macOS |

## Demo architecture

```
Claude Desktop (stdio MCP)
        │
        ▼
MCP server — uv run mcp-k8s-secure-ops serve-mcp
        │
        ├── OPA — docker (localhost:8181, policies/opa/secureops/ mounted)
        ├── kind cluster (KUBECONFIG ~/.kube/config)
        │     ├── demo-staging ns  (no labels)
        │     └── demo-prod ns     (tier=prod label)
        │           └── Kyverno ClusterPolicies (in-cluster admission guard)
        └── SQLite audit DB (~/.secureops/audit.db)
```

The in-cluster Helm chart (`helm/secureops/`) is NOT used in the local demo.
It exists for the "adopt this in production" story shown in the talk.

## Related docs

- [Talk outline (speaker notes)](talk-outline.md) — 30-minute timing, segment-by-segment notes
- [Claude Desktop config](claude-desktop-config.md) — exact JSON, troubleshooting
