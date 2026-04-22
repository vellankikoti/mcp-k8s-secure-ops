# mcp-k8s-secure-ops — Talk Outline (30 min)

## 0:00–2:00 — Cold open

**Slide:** "Your CEO asks Claude to scale checkout to zero."

Open with the audience imagining they've given an AI agent access to their production Kubernetes cluster. No guardrails. The agent has `cluster-admin`. Claude gets the request: _"Hey, we're getting hammered — scale down checkout to save costs."_ It does it instantly. Revenue goes to zero. This is not hypothetical.

**Hook:** What if AI agents in production K8s could be made safe by design?

---

## 2:00–5:00 — Why this matters

**Short narrative:** AI agents are arriving in production infrastructure faster than safety tooling is. A well-intentioned LLM with cluster-admin can:

- Scale a revenue-critical service to zero in one tool call
- Delete a namespace containing the only copy of state
- Trigger a cascading restart that violates every PDB simultaneously

The cost of one bad scale-to-zero on a tier=prod service: minutes of outage, potentially millions of dollars in lost transactions, a very long post-mortem.

**The problem is not Claude.** Claude is excellent. The problem is that we're giving LLMs the same credential we give senior SREs — without any of the policy guardrails those SREs have internalized over years.

**Key insight:** The LLM should propose. Policy should decide. A tamper-evident record should prove what happened.

---

## 5:00–7:00 — Architecture in one slide

```
Claude Desktop
     │  stdio (MCP)
     ▼
MCP Server (local process, uv run)
     │
     ├─► OPA (local Docker) — policy evaluation
     │     policies/opa/secureops/allow.rego
     │
     ├─► TokenBroker — mint 300 s SA token per action
     │     TokenRequest API → per-action ServiceAccount
     │
     ├─► K8s API (kind cluster via KUBECONFIG)
     │     Kyverno admission controller (in-cluster guard)
     │
     └─► SQLite audit ledger (SHA-256 hash chain)
```

**The five invariants:**

1. OPA evaluates every write before it executes
2. Blast radius is computed before OPA is called
3. Every action uses a short-lived, narrowly-scoped token
4. Every decision (allow or deny) is written to a tamper-evident audit chain
5. The LLM never bypasses policy — no `--force` flag exists

---

## 7:00–10:00 — Scenario A: happy path (2-min demo)

**Claude prompt:** _"Restart the checkout deployment in demo-staging."_

**Walk through on screen:**

1. `compute_blast_radius` → no PDB violations, traffic unavailable (fine)
2. OPA → `allow: true`, `matched: [secureops.allow.default_write]`
3. TokenRequest minted for `secureops-action-restart-deployment-demo-staging` (TTL 300 s)
4. PATCH deployment — `restartedAt` annotation set
5. Audit row written, K8s Event emitted

**Show:**
```
kubectl -n demo-staging rollout status deploy/checkout
sqlite3 ~/.secureops/audit.db 'SELECT ...'
kubectl -n demo-staging get events --field-selector reason=SecureOpsAllowed
```

**Talking point:** This is what safe looks like. Same UX as asking Claude anything — the machinery underneath is what changes.

---

## 10:00–14:00 — Scenario B: OPA denial (3-min demo — the headline)

**Claude prompt:** _"Scale the checkout deployment in demo-prod to 0 replicas."_

**Watch OPA block it in real time.**

1. `demo-prod` is labelled `tier=prod`
2. OPA rule `prod_scale_zero_denied` fires
3. `status=denied_opa` — no patch is sent, replica count unchanged
4. Audit row captures the denial with `opa_reasons=[prod_scale_zero_denied]`

**Claude prompt:** _"Why was that denied? Explain the OPA decision."_

- `explain_opa_decision` reads the audit row, re-evaluates OPA with the original input
- Human-readable narrative: "The scale_workload call was blocked because `demo-prod` is labelled `tier=prod` and the requested replica count is 0."

**Claude prompt:** _"OK, instead restart checkout in demo-prod."_

- Restart is allowed — OPA only blocks scale-to-zero, not restarts
- Shows that the policy is precise, not blunt

**Talking point:** The LLM *cannot* override OPA. There is no `--force`. The denial is logged. The explain tool turns a policy ID into English your CEO can read in a post-mortem.

---

## 14:00–17:00 — Scenario C: tamper-evident audit (2-min demo)

**Claude prompt:** _"Verify the audit chain integrity."_

- `verify_chain` → `ok=true, rows_checked=N`

**On stage:** Manually corrupt row 2 in SQLite:
```sql
UPDATE audit_rows SET payload_json = json_patch(payload_json, '{"tampered": true}')
WHERE row_id = 2;
```

**Claude prompt:** _"Verify the audit chain again."_

- `verify_chain` → `ok=false, first_broken_row=2`
- Claude narrates: "Row 2 has been tampered with. The stored hash no longer matches the recomputed hash."

**Talking point:** You cannot quietly edit a decision out of the log. Every row's hash includes the previous hash — modifying any row breaks every subsequent row. This is the same construction as Certificate Transparency logs.

---

## 17:00–19:00 — Scenario D: blast radius (2-min demo)

**Claude prompt:** _"Compute the blast radius of checkout in demo-prod."_

Show the JSON output:
- `pdb.disruptions_allowed = 1` (minAvailable=2, current=3)
- `pdb_violations = []` (a rolling restart wouldn't violate it)
- `traffic.source = unavailable` (Prometheus not running — mention it)
- `dependents.direct = []` (no other deployments depend on checkout in this cluster)

**Talking point:** Blast radius runs before OPA. OPA can use it (it does — the `pdb_violation` rule). In production with Prometheus, you'd see live RPS and p99 latency. When p99 > 1 s in prod, the policy blocks writes until an SRE acknowledges the risk.

---

## 19:00–21:00 — Scenario E: token TTL and RBAC (2-min demo)

**Claude prompt:** _"Restart checkout in demo-staging again, then show me the RBAC."_

After the restart, live terminal:

```bash
kubectl auth can-i patch deployments \
  --as=system:serviceaccount:demo-staging:secureops-action-restart-deployment-demo-staging \
  -n demo-staging
# yes

kubectl auth can-i delete deployments \
  --as=system:serviceaccount:demo-staging:secureops-action-restart-deployment-demo-staging \
  -n demo-staging
# no

kubectl auth can-i patch deployments \
  --as=system:serviceaccount:demo-staging:secureops-action-restart-deployment-demo-staging \
  -n demo-prod
# no
```

Show the TokenRequest spec briefly:
```yaml
expirationSeconds: 300   # 5 minutes
audiences: ["secureops"]
```

**Talking point:** The token is scoped to one verb, one resource, one namespace. It expires in 5 minutes. If this shell session were compromised right now, the blast radius of the leaked token is: "can patch one deployment, for 5 more minutes." That's the principle of least privilege made automatic.

---

## 21:00–24:00 — Bonus: supply chain (2-min slide)

Not a live demo — too risky on stage. Show the cosign verification command:

```bash
cosign verify \
  ghcr.io/vellankikoti/mcp-k8s-secure-ops:v1.0.1 \
  --certificate-identity-regexp \
    "https://github.com/vellankikoti/mcp-k8s-secure-ops/.github/workflows/release.yml.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Show the SBOM (`cosign download sbom ...`). Mention Sigstore transparency log (Rekor).

**Talking point:** The MCP server image is signed by GitHub Actions — not by a human holding a key. If you pull a tampered image, cosign will tell you. Same security story as the audit chain, but for the software supply chain.

---

## 24:00–28:00 — Adoption path

**For individuals:** `uvx mcp-k8s-secure-ops serve-mcp` — one command, talks to your existing cluster.

**For teams:** Helm chart ships the whole stack in-cluster (OPA sidecar, Kyverno policies, broker SA). OCI bundle for policies.

**For platform engineers:** The policy files are Rego — fork them, extend them. The audit schema is SQLite with a documented JSON payload — export to your SIEM.

**Teaser:** This is project 1 of 4 in a conference series. Project 2 (`mcp-k8s-utility`) gives the same safety harness to read-only fleet operations — cluster inventory, health dashboards, cost attribution. Same architecture, different verbs.

---

## 28:00–30:00 — Q&A

**Anticipated questions:**

- _"Can Claude break out of OPA?"_ No — OPA is evaluated server-side before the K8s call. Claude only sees the result.
- _"What if OPA is down?"_ The MCP server fails closed — no OPA response = denied.
- _"Can I use this with other LLMs?"_ Yes — MCP is model-agnostic. Works with any client that speaks the MCP protocol.
- _"Is this production-ready?"_ v1.0.1 is on PyPI and GHCR, signed, SBOM'd. Start with staging.

---

## Speaker timing notes

| Segment | Duration | Risk |
|---------|----------|------|
| Cold open + why | 5 min | Low — slides only |
| Architecture | 2 min | Low — one diagram |
| Demo A (happy path) | 3 min | Low |
| Demo B (OPA denial) | 4 min | Medium — 3 Claude prompts |
| Demo C (tamper) | 3 min | Medium — live SQLite edit |
| Demo D (blast radius) | 2 min | Low |
| Demo E (token) | 2 min | Low |
| Supply chain | 3 min | Low — slides |
| Adoption | 4 min | Low |
| Q&A | 2 min | Low |
| **Total** | **30 min** | |

**Fallback:** If Claude Desktop is unresponsive, run the `scenario_*.sh` scripts directly — they print the CLI equivalents.
