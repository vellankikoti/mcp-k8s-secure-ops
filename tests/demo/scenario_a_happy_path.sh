#!/usr/bin/env bash
# scenario_a_happy_path.sh
# Operator cheat-sheet: happy-path restart of checkout in demo-staging.
# The ACTUAL demo runs through Claude Desktop (MCP).  This script is for
# rehearsal and as a fallback if Claude Desktop flakes on stage.
set -euo pipefail

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Scenario A — happy-path restart (demo-staging)        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "▶ CLAUDE DESKTOP PROMPT:"
echo "  \"Restart the checkout deployment in demo-staging.\""
echo ""
echo "── PRE-CHECK: deployment state ─────────────────────────────"
kubectl -n demo-staging get deploy checkout -o wide
echo ""
echo "── PRE-CHECK: last restartedAt annotation ──────────────────"
kubectl -n demo-staging get deploy checkout \
  -o jsonpath='{.spec.template.metadata.annotations.kubectl\.kubernetes\.io/restartedAt}' \
  2>/dev/null && echo "" || echo "(none yet)"
echo ""
echo "── WHAT TO EXPECT (Claude calls MCP tools) ─────────────────"
echo "  1. compute_blast_radius(name=checkout, namespace=demo-staging)"
echo "     → no PDB violations, Prometheus source=unavailable — that's fine"
echo "  2. OPA evaluates: tool=restart_deployment, tier=staging"
echo "     → allow: true, matched=[secureops.allow.default_write]"
echo "  3. TokenRequest minted for secureops-action-restart-deployment-demo-staging (TTL 300 s)"
echo "  4. PATCH deployment with restartedAt annotation"
echo "  5. Audit row written to SQLite, K8s Event emitted"
echo ""
echo "── VERIFY (run these after Claude responds) ────────────────"
echo ""
echo "  # Rollout status:"
echo "  kubectl -n demo-staging rollout status deploy/checkout"
echo ""
echo "  # Audit trail (last 3 rows):"
echo "  sqlite3 \$SECUREOPS_AUDIT_DB \\"
echo "    'SELECT row_id, json_extract(payload_json,\"$.proposal.tool_name\"), json_extract(payload_json,\"$.result.status\") FROM audit_rows ORDER BY row_id DESC LIMIT 3'"
echo ""
echo "  # Kubernetes Events:"
echo "  kubectl -n demo-staging get events \\"
echo "    --field-selector reason=SecureOpsAllowed \\"
echo "    --sort-by='.lastTimestamp' | tail -5"
echo ""
echo "  # OTel span (if local Jaeger/stdout exporter configured):"
echo "  grep 'restart_deployment' /tmp/secureops-otel.log 2>/dev/null || echo '(OTel stdout not wired in local demo)'"
echo ""
echo "── EXPECTED OUTPUT SUMMARY ─────────────────────────────────"
echo "  status=allowed_executed"
echo "  restartedAt annotation updated on the deployment"
echo "  audit row with prev_hash chain intact"
echo ""
