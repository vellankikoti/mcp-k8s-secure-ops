#!/usr/bin/env bash
# scenario_d_blast_radius.sh
# Operator cheat-sheet: compute_blast_radius for checkout in demo-prod.
# Shows direct + one-hop dependents, PDB, traffic (Prometheus may be unavailable).
set -euo pipefail

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Scenario D — blast radius analysis                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "▶ CLAUDE DESKTOP PROMPT:"
echo "  \"Compute the blast radius of the checkout deployment in demo-prod.\""
echo ""
echo "── PRE-CHECK: workloads and PDB ────────────────────────────"
kubectl -n demo-prod get deploy,pdb
echo ""
echo "── WHAT TO EXPECT ──────────────────────────────────────────"
echo "  Tool: compute_blast_radius(name=checkout, namespace=demo-prod)"
echo ""
echo "  Expected JSON structure:"
cat <<'JSON'
{
  "target": {
    "name": "checkout",
    "namespace": "demo-prod",
    "replicas": 3
  },
  "pdb": {
    "name": "checkout-pdb",
    "min_available": 2,
    "current_healthy": 3,
    "disruptions_allowed": 1
  },
  "pdb_violations": [],
  "dependents": {
    "direct": [],
    "one_hop": []
  },
  "traffic": {
    "source": "unavailable",
    "p99_latency_ms": null,
    "rps": null
  }
}
JSON
echo ""
echo "  Note: Prometheus is not running in the demo cluster,"
echo "  so traffic.source='unavailable' is correct and expected."
echo "  Mention on stage: 'In production with Prometheus, you'd see live RPS"
echo "  and p99 latency — the same data that would trigger the SRE-ack policy.'"
echo ""
echo "── CLI EQUIVALENT ──────────────────────────────────────────"
echo ""
echo "  # Show the PDB directly:"
echo "  kubectl -n demo-prod get pdb checkout-pdb -o yaml"
echo ""
echo "  # Show pods and their readiness:"
echo "  kubectl -n demo-prod get pods -l app=checkout -o wide"
echo ""
echo "  # Check for any services selecting checkout:"
echo "  kubectl -n demo-prod get svc -l app=checkout 2>/dev/null || echo '(no services)'"
echo ""
echo "  # Check for HPAs:"
echo "  kubectl -n demo-prod get hpa 2>/dev/null || echo '(no HPAs)'"
echo ""
echo "── EXPECTED OUTPUT SUMMARY ─────────────────────────────────"
echo "  pdb.disruptions_allowed=1 (can lose 1 pod of 3 and still satisfy minAvailable=2)"
echo "  traffic.source=unavailable"
echo "  pdb_violations=[] (a normal restart would not violate the PDB)"
echo "  Audience takeaway: blast radius is computed BEFORE any action is taken."
echo ""
