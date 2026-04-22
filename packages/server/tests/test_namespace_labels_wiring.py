from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.context import SecureOpsContext


@pytest.mark.asyncio
async def test_namespace_labels_helper_returns_labels():
    from secureops_server.mcp_server import _namespace_labels

    ns = MagicMock()
    ns.metadata.labels = {"tier": "prod", "team": "payments"}
    k8s = MagicMock()
    k8s.core_v1 = MagicMock()
    k8s.core_v1.read_namespace = AsyncMock(return_value=ns)
    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)

    labels = await _namespace_labels(ctx, "demo-prod")
    assert labels == {"tier": "prod", "team": "payments"}


@pytest.mark.asyncio
async def test_namespace_labels_helper_returns_empty_on_error():
    from secureops_server.mcp_server import _namespace_labels

    k8s = MagicMock()
    k8s.core_v1 = MagicMock()
    k8s.core_v1.read_namespace = AsyncMock(side_effect=RuntimeError("boom"))
    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)

    labels = await _namespace_labels(ctx, "demo-prod")
    assert labels == {}
