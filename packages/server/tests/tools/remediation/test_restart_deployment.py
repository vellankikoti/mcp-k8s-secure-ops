from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.models import K8sRef
from secureops_server.tools.remediation.restart_deployment import (
    build_restart_patch,
    execute_restart,
)


def test_build_restart_patch_adds_annotation():
    patch = build_restart_patch()
    ann = patch["spec"]["template"]["metadata"]["annotations"]
    assert "kubectl.kubernetes.io/restartedAt" in ann
    assert ann["kubectl.kubernetes.io/restartedAt"].endswith("+00:00") or ann[
        "kubectl.kubernetes.io/restartedAt"
    ].endswith("Z")


@pytest.mark.asyncio
async def test_execute_restart_uses_minted_token_and_patches_deployment():
    patched_apps = MagicMock()
    patched_apps.patch_namespaced_deployment = AsyncMock(
        return_value=MagicMock(metadata=MagicMock(resource_version="42"))
    )

    def make_apps_from_token(token: str):
        assert token == "minted-token"
        return patched_apps

    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    result = await execute_restart(target, token="minted-token", build_apps=make_apps_from_token)
    assert result["resource_version"] == "42"
    patched_apps.patch_namespaced_deployment.assert_awaited_once()
