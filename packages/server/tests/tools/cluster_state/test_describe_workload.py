from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.context import Capability, SecureOpsContext
from secureops_server.models import K8sRef
from secureops_server.tools.cluster_state.describe_workload import describe_workload


@pytest.mark.asyncio
async def test_describe_deployment_returns_status_and_replicas():
    dep = MagicMock()
    dep.metadata.name = "checkout"
    dep.metadata.namespace = "prod"
    dep.metadata.uid = "u1"
    dep.spec.replicas = 3
    dep.status.ready_replicas = 2
    dep.status.available_replicas = 2
    dep.status.unavailable_replicas = 1
    dep.status.conditions = []

    k8s = MagicMock()
    k8s.apps_v1 = MagicMock()
    k8s.apps_v1.read_namespaced_deployment = AsyncMock(return_value=dep)

    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    ref = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    out = await describe_workload(guarded, ref)
    assert out["replicas_desired"] == 3
    assert out["replicas_ready"] == 2
    assert out["replicas_unavailable"] == 1
    assert out["name"] == "checkout"


@pytest.mark.asyncio
async def test_describe_unsupported_kind_raises():
    k8s = MagicMock()
    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    ref = K8sRef(kind="ConfigMap", api_version="v1", namespace="x", name="y")
    with pytest.raises(ValueError, match="unsupported kind"):
        await describe_workload(guarded, ref)
