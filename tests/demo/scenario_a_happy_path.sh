#!/usr/bin/env bash
set -euo pipefail
kubectl create ns demo || true
kubectl -n demo create deployment checkout --image=nginx:1.27 || true
kubectl -n demo wait --for=condition=available deploy/checkout --timeout=60s
echo "=> plan_incident_response symptom=deployment_unhealthy"
echo "=> restart_deployment ns=demo name=checkout"
echo "(run via MCP client; expect status=allowed_executed)"
