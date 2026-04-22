from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.context import Capability, SecureOpsContext
from secureops_server.models import K8sRef
from secureops_server.tools.blast_radius.check_pdb_impact import (
    check_pdb_impact,
)


def _pdb(name: str, min_available: int, current_healthy: int):
    p = MagicMock()
    p.metadata.name = name
    p.metadata.namespace = "prod"
    p.metadata.uid = f"u-{name}"
    p.spec.min_available = min_available
    p.spec.selector.match_labels = {"app": "checkout"}
    p.status.current_healthy = current_healthy
    return p


@pytest.mark.asyncio
async def test_check_pdb_impact_flags_violation_when_draining_would_fall_below_min():
    dep = MagicMock()
    dep.spec.template.metadata.labels = {"app": "checkout"}
    dep.spec.replicas = 3
    k8s = MagicMock()
    k8s.apps_v1 = MagicMock()
    k8s.apps_v1.read_namespaced_deployment = AsyncMock(return_value=dep)
    k8s.policy_v1 = MagicMock()
    k8s.policy_v1.list_namespaced_pod_disruption_budget = AsyncMock(
        return_value=MagicMock(items=[_pdb("pdb-a", min_available=2, current_healthy=3)])
    )
    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    violations = await check_pdb_impact(guarded, target, target_available=1)
    assert len(violations) == 1
    assert violations[0].pdb.name == "pdb-a"
    assert violations[0].min_available == 2
    assert violations[0].current_available == 1
