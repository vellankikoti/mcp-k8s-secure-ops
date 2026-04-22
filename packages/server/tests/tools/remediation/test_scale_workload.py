from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.models import K8sRef
from secureops_server.tools.remediation.scale_workload import (
    build_scale_body,
    execute_scale,
)


def test_build_scale_body_produces_scale_object():
    body = build_scale_body(replicas=5)
    assert body["spec"]["replicas"] == 5


@pytest.mark.asyncio
async def test_execute_scale_patches_scale_subresource():
    apps = MagicMock()
    mock_resp = MagicMock()
    mock_resp.spec.replicas = 5
    apps.patch_namespaced_deployment_scale = AsyncMock(return_value=mock_resp)

    def build_apps(token: str):
        assert token == "tok"
        return apps

    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    out = await execute_scale(target, replicas=5, token="tok", build_apps=build_apps)
    assert out["replicas"] == 5
