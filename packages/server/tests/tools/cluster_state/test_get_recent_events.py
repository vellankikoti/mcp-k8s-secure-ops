from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.context import Capability, SecureOpsContext
from secureops_server.tools.cluster_state.get_recent_events import get_recent_events


def _ev(reason: str, minutes_ago: int):
    e = MagicMock()
    e.metadata.name = f"ev-{reason}"
    e.metadata.namespace = "prod"
    e.type = "Warning"
    e.reason = reason
    e.message = f"{reason} happened"
    e.last_timestamp = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    e.involved_object.kind = "Pod"
    e.involved_object.name = "x"
    e.involved_object.namespace = "prod"
    return e


@pytest.mark.asyncio
async def test_get_recent_events_filters_by_window():
    events = MagicMock(items=[_ev("BackOff", 5), _ev("Old", 120)])
    k8s = MagicMock()
    k8s.core_v1 = MagicMock()
    k8s.core_v1.list_event_for_all_namespaces = AsyncMock(return_value=events)
    k8s.core_v1.list_namespaced_event = AsyncMock(return_value=events)

    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    out = await get_recent_events(guarded, namespace=None, since_minutes=30)
    reasons = {e["reason"] for e in out}
    assert "BackOff" in reasons
    assert "Old" not in reasons
