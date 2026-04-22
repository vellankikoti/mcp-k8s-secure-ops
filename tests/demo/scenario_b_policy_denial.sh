#!/usr/bin/env bash
set -euo pipefail
kubectl label ns demo tier=prod --overwrite
echo "=> scale_workload ns=demo name=checkout replicas=0"
echo "(expect status=denied_opa, reasons=[prod_scale_zero_denied])"
echo "=> explain_opa_decision"
echo "=> restart_deployment ns=demo name=checkout"
echo "(safe alternative; expect status=allowed_executed)"
