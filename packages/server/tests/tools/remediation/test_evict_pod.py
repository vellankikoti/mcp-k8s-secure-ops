from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.models import K8sRef
from secureops_server.tools.remediation.evict_pod import execute_evict


@pytest.mark.asyncio
async def test_evict_creates_eviction_subresource_with_reason_annotation():
    core = MagicMock()
    core.create_namespaced_pod_eviction = AsyncMock(return_value=MagicMock())

    def build_core(token: str):
        return core

    pod = K8sRef(kind="Pod", api_version="v1", namespace="prod", name="checkout-xyz")
    out = await execute_evict(pod, reason="OOM remediation", token="tok", build_core=build_core)
    assert out["evicted"] is True
    body = core.create_namespaced_pod_eviction.await_args.kwargs["body"]
    assert body["metadata"]["name"] == "checkout-xyz"
    assert body["metadata"]["annotations"]["secureops.io/reason"] == "OOM remediation"
