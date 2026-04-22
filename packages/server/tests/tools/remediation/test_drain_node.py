from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.models import K8sRef
from secureops_server.tools.remediation.drain_node import execute_drain


@pytest.mark.asyncio
async def test_drain_cordons_then_evicts_each_pod_in_plan_order():
    calls: list[str] = []

    core = MagicMock()

    async def patch_node(name: str, body: dict):
        calls.append(f"cordon:{name}")
        resp = MagicMock()
        resp.spec.unschedulable = True
        return resp

    async def create_evict(name: str, namespace: str, body: dict):
        calls.append(f"evict:{namespace}/{name}")
        return MagicMock()

    core.patch_node = AsyncMock(side_effect=patch_node)
    core.create_namespaced_pod_eviction = AsyncMock(side_effect=create_evict)

    def build_core(token: str):
        return core

    node = K8sRef(kind="Node", api_version="v1", name="worker-1")
    plan = [
        K8sRef(kind="Pod", api_version="v1", namespace="default", name="a"),
        K8sRef(kind="Pod", api_version="v1", namespace="prod", name="b"),
    ]
    out = await execute_drain(node, plan=plan, token="tok", build_core=build_core)
    assert out["evicted_count"] == 2
    assert calls == ["cordon:worker-1", "evict:default/a", "evict:prod/b"]
