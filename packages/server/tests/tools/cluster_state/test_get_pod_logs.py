from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.context import Capability, SecureOpsContext
from secureops_server.models import K8sRef
from secureops_server.tools.cluster_state.get_pod_logs import get_pod_logs


@pytest.mark.asyncio
async def test_get_pod_logs_returns_tail():
    k8s = MagicMock()
    k8s.core_v1 = MagicMock()
    k8s.core_v1.read_namespaced_pod_log = AsyncMock(return_value="line1\nline2\n")
    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    ref = K8sRef(kind="Pod", api_version="v1", namespace="prod", name="checkout-xyz")
    out = await get_pod_logs(guarded, ref, tail_lines=100, since_seconds=None)
    assert out == "line1\nline2\n"
    k8s.core_v1.read_namespaced_pod_log.assert_awaited_once_with(
        name="checkout-xyz", namespace="prod", tail_lines=100, since_seconds=None
    )


@pytest.mark.asyncio
async def test_get_pod_logs_requires_pod_kind():
    k8s = MagicMock()
    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    ref = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="x")
    with pytest.raises(ValueError, match="Pod"):
        await get_pod_logs(guarded, ref)
