# Changelog

## v1.0.2 — 2026-04-22

Demo-readiness + policy-correctness fixes discovered during conference-talk dry-run.

### Fixed
- Write tool wrappers now fetch and forward target namespace labels (`parameters._namespace_labels`), so OPA rules that key on `input.target.namespace_labels["tier"]` actually evaluate correctly. Previously `prod_scale_zero_denied` and `p99_elevated_require_sre_ack` never fired.
- `verify_chain` now returns `{ok, rows_checked, first_broken_row, reason}` instead of just `{ok}` — richer evidence when the ledger is tampered.
- Demo harness: Kyverno install timeout bumped to 5 min (first pull is slow on fresh machines).
- Demo RBAC seed: cover all 6 action verbs (restart, scale, rollback, evict in demo-staging/demo-prod; cordon, drain in kube-system) so TokenBroker doesn't fail on any tool call.
- Demo RBAC cluster-reader now includes `networking.k8s.io/ingresses` for `find_dependents`.
- Scenario cheat-sheets: corrected `$.result.opa_decision.reasons` JSON path and real `BlastRadius` shape.

## v1.0.1 — 2026-04-22

Release-pipeline fixes; no functional changes in the package.

### Fixed
- Dockerfile: use `uv build --out-dir packages/server/dist` so the multi-stage COPY can find the wheel.
- Dockerfile: run `pip install` as root before switching to USER 10001 to avoid permission error on pip's home-dir cache.
- release.yml: iterate Helm chart tarballs individually so `helm push` doesn't interpret a second .tgz as the remote URL.

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
