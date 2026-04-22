# Changelog

## v1.0.0 — 2026-04-22

**First stable release.**

### Added
- 18 MCP tools across cluster-state (5), blast-radius (4), remediation (6), audit (3).
- OPA pre-flight with fail-closed HTTP client and ConfigMap / OCI bundle loading.
- Kyverno subchart (`secureops-kyverno`) as admission-time backstop.
- `TokenRequest`-based broker minting 5-min per-action ServiceAccount tokens.
- Transitive blast-radius engine: direct → one-hop (Service, PVC, PDB, HPA) → transitive Ingress, with Prometheus traffic enrichment.
- Hash-chained aiosqlite audit ledger + OTel span export + K8s Event emission.
- Deterministic `plan_incident_response` router + LLM-narrated `explain_*` family with deterministic fallbacks.
- Multi-arch GHCR image, cosign keyless signing, CycloneDX SBOM, Helm OCI charts, OPA policy OCI bundle.

### Invariants
- LLM never holds cluster credentials and never decides writes.
- Every tool call produces an audit row; `verify_chain` proves tamper-evidence.
- Fail-closed on OPA unreachable or token-mint failure.

### Known deferrals (v1.x)
- OCI bundle runtime loading (requires `oras-py`); policies ship via ConfigMap for v1.0.
- `--llm-plan` opt-in for LLM-driven incident planning (router is deterministic in v1.0).
- Multi-cluster federation.
