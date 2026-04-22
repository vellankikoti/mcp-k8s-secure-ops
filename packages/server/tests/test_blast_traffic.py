from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.blast_radius.traffic import snapshot_for_service
from secureops_server.models import K8sRef


@pytest.mark.asyncio
async def test_snapshot_returns_prometheus_values_when_reachable():
    prom = MagicMock()
    prom.query = AsyncMock(
        side_effect=[
            [{"value": [0, "12.5"]}],
            [{"value": [0, "0.01"]}],
            [{"value": [0, "250"]}],
        ]
    )
    svc = K8sRef(kind="Service", api_version="v1", namespace="prod", name="checkout-svc")
    snap = await snapshot_for_service(prom, svc)
    assert snap.rps == 12.5
    assert snap.error_rate == 0.01
    assert snap.p99_latency_ms == 250.0
    assert snap.source == "prometheus"


@pytest.mark.asyncio
async def test_snapshot_returns_unavailable_on_error():
    prom = MagicMock()
    prom.query = AsyncMock(side_effect=RuntimeError("prom down"))
    svc = K8sRef(kind="Service", api_version="v1", namespace="prod", name="x")
    snap = await snapshot_for_service(prom, svc)
    assert snap.source == "unavailable"
    assert snap.rps == 0.0
