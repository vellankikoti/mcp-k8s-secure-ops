from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.context import Capability, SecureOpsContext
from secureops_server.tools.cluster_state.find_unhealthy_workloads import find_unhealthy_workloads


def _dep(name: str, desired: int, ready: int):
    d = MagicMock()
    d.metadata.name = name
    d.metadata.namespace = "prod"
    d.metadata.uid = f"u-{name}"
    d.spec.replicas = desired
    d.status.ready_replicas = ready
    return d


@pytest.mark.asyncio
async def test_flags_deployment_with_missing_replicas():
    k8s = MagicMock()
    k8s.apps_v1 = MagicMock()
    k8s.apps_v1.list_deployment_for_all_namespaces = AsyncMock(
        return_value=MagicMock(items=[_dep("a", 3, 3), _dep("b", 3, 1)])
    )
    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    out = await find_unhealthy_workloads(guarded, namespace=None)
    names = {w["name"] for w in out}
    assert names == {"b"}
    assert out[0]["missing_replicas"] == 2
