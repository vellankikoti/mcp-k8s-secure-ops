from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.context import Capability, SecureOpsContext
from secureops_server.models import K8sRef
from secureops_server.tools.blast_radius.get_traffic_snapshot import (
    get_traffic_snapshot,
)


@pytest.mark.asyncio
async def test_get_traffic_snapshot_for_service_reference():
    prom = MagicMock()
    prom.query = AsyncMock(
        side_effect=[
            [{"value": [0, "5.0"]}],
            [{"value": [0, "0.0"]}],
            [{"value": [0, "100"]}],
        ]
    )
    ctx = SecureOpsContext(k8s=None, opa=None, prom=prom, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.PROM}))
    svc = K8sRef(kind="Service", api_version="v1", namespace="prod", name="checkout-svc")
    snap = await get_traffic_snapshot(guarded, svc)
    assert snap.rps == 5.0
    assert snap.source == "prometheus"


@pytest.mark.asyncio
async def test_get_traffic_snapshot_rejects_non_service():
    ctx = SecureOpsContext(k8s=None, opa=None, prom=MagicMock(), sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.PROM}))
    with pytest.raises(ValueError, match="Service"):
        await get_traffic_snapshot(
            guarded,
            K8sRef(kind="Deployment", api_version="apps/v1", name="x"),
        )
