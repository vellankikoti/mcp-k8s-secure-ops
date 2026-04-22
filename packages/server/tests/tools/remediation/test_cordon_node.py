from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.models import K8sRef
from secureops_server.tools.remediation.cordon_node import execute_cordon


@pytest.mark.asyncio
async def test_cordon_sets_spec_unschedulable_true():
    core = MagicMock()
    resp = MagicMock()
    resp.spec.unschedulable = True
    core.patch_node = AsyncMock(return_value=resp)

    def build_core(token: str):
        assert token == "tok"
        return core

    ref = K8sRef(kind="Node", api_version="v1", name="worker-1")
    out = await execute_cordon(ref, cordon=True, token="tok", build_core=build_core)
    assert out["unschedulable"] is True
    core.patch_node.assert_awaited_once()
    kwargs = core.patch_node.await_args.kwargs
    assert kwargs["body"] == {"spec": {"unschedulable": True}}


@pytest.mark.asyncio
async def test_uncordon_sets_spec_unschedulable_false():
    core = MagicMock()
    resp = MagicMock()
    resp.spec.unschedulable = False
    core.patch_node = AsyncMock(return_value=resp)

    def build_core(token: str):
        return core

    ref = K8sRef(kind="Node", api_version="v1", name="worker-1")
    out = await execute_cordon(ref, cordon=False, token="tok", build_core=build_core)
    assert out["unschedulable"] is False
