#!/usr/bin/env bash
# demo-down.sh — tear down the mcp-k8s-secure-ops conference demo
set -euo pipefail

docker rm -f secureops-opa 2>/dev/null || true
kind delete cluster --name secureops-demo 2>/dev/null || true
rm -f "${HOME}/.secureops/audit.db"
echo "demo torn down"
