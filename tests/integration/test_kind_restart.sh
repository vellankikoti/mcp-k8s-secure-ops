#!/usr/bin/env bash
set -euo pipefail

CLUSTER="${CLUSTER:-secureops-p4}"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER"

docker build -t ghcr.io/vellankikoti/mcp-k8s-secure-ops:dev -f packages/server/Dockerfile .
kind load docker-image ghcr.io/vellankikoti/mcp-k8s-secure-ops:dev --name "$CLUSTER"

kubectl create ns secureops-system
helm install secureops helm/secureops -n secureops-system \
  --set image.tag=dev --set image.pullPolicy=IfNotPresent
kubectl -n secureops-system rollout status deploy/secureops --timeout=90s

kubectl create ns demo
kubectl -n demo create deployment checkout --image=nginx:1.27
kubectl -n demo wait --for=condition=available deploy/checkout --timeout=60s

POD=$(kubectl -n secureops-system get pod -l app=secureops -o name | head -1)
kubectl -n secureops-system exec "$POD" -c server -- mcp-k8s-secure-ops version

kind delete cluster --name "$CLUSTER"
