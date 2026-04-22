#!/usr/bin/env bash
# scenario_e_token_ttl.sh
# Operator cheat-sheet: demonstrate per-action short-lived TokenRequest.
# After a successful restart, show that the token SA exists, RBAC is tight,
# and the token would expire in 300 s.
set -euo pipefail

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Scenario E — per-action token TTL and RBAC            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "── PRE-REQUISITE ────────────────────────────────────────────"
echo "  Scenario A must have run (restart of checkout in demo-staging)."
echo "  The per-action SA was used to mint the TokenRequest."
echo ""
echo "▶ CLAUDE DESKTOP PROMPT:"
echo "  \"Restart the checkout deployment in demo-staging again,"
echo "   then show me the RBAC and token TTL details.\""
echo ""
echo "── AFTER THE RESTART: verify the per-action SA exists ──────"
kubectl -n demo-staging get sa secureops-action-restart-deployment-demo-staging
echo ""

echo "── WHAT RBAC DOES THE ACTION SA HAVE? ─────────────────────"
echo ""
echo "  Role rules:"
kubectl -n demo-staging get role \
  secureops-action-restart-deployment-demo-staging-role \
  -o jsonpath='{.rules}' | python3 -m json.tool 2>/dev/null || \
  kubectl -n demo-staging describe role secureops-action-restart-deployment-demo-staging-role
echo ""

echo "── CAN IT PATCH DEPLOYMENTS? (should be YES) ───────────────"
kubectl auth can-i patch deployments \
  --as="system:serviceaccount:demo-staging:secureops-action-restart-deployment-demo-staging" \
  -n demo-staging
echo "  Expected: yes"
echo ""

echo "── CAN IT DELETE DEPLOYMENTS? (should be NO) ───────────────"
kubectl auth can-i delete deployments \
  --as="system:serviceaccount:demo-staging:secureops-action-restart-deployment-demo-staging" \
  -n demo-staging || true
echo "  Expected: no"
echo ""

echo "── CAN IT PATCH IN demo-prod? (should be NO) ───────────────"
kubectl auth can-i patch deployments \
  --as="system:serviceaccount:demo-staging:secureops-action-restart-deployment-demo-staging" \
  -n demo-prod || true
echo "  Expected: no  (SA is namespace-scoped to demo-staging)"
echo ""

echo "── TOKEN MINTING MECHANIC (narrative for the audience) ─────"
echo ""
echo "  The MCP server calls the Kubernetes TokenRequest API:"
echo ""
cat <<'YAML'
# POST /api/v1/namespaces/demo-staging/serviceaccounts/
#       secureops-action-restart-deployment-demo-staging/token
apiVersion: authentication.k8s.io/v1
kind: TokenRequest
spec:
  expirationSeconds: 300      # 5 minutes
  audiences: ["secureops"]
YAML
echo ""
echo "  The returned token:"
echo "    - Is a signed JWT valid for exactly 300 seconds"
echo "    - Is only accepted by the Kubernetes API server (audience=secureops scope)"
echo "    - Is bound to the per-action SA (not cluster-admin)"
echo "    - Expires automatically — no rotation needed, no revocation needed"
echo "    - The MCP server uses this token ONLY for the duration of the action"
echo ""
echo "── VERIFY can-i while token is still live ──────────────────"
echo ""
echo "  Within 5 minutes of the restart, the token would pass can-i."
echo "  After 5 minutes: the token is expired and can-i would fail."
echo "  (We don't block on this in the demo — just narrate it.)"
echo ""
echo "  kubectl auth can-i patch deployments \\"
echo "    --as=system:serviceaccount:demo-staging:secureops-action-restart-deployment-demo-staging \\"
echo "    -n demo-staging"
echo ""
echo "── EXPECTED OUTPUT SUMMARY ─────────────────────────────────"
echo "  patch deployments in demo-staging: yes"
echo "  delete deployments in demo-staging: no"
echo "  patch deployments in demo-prod:    no  (RBAC is namespace-scoped)"
echo "  Token TTL: 300 s (then gone — no cluster-admin credential left behind)"
echo ""
