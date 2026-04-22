from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.models import K8sRef
from secureops_server.tools.remediation.rollback_deployment import (
    execute_rollback,
    pick_previous_revision,
)


def _rs(name: str, revision: str):
    r = MagicMock()
    r.metadata.name = name
    r.metadata.namespace = "prod"
    r.metadata.annotations = {"deployment.kubernetes.io/revision": revision}
    r.spec.template = MagicMock()
    return r


def test_pick_previous_revision_returns_second_highest():
    dep_rev = "5"
    rss = [_rs("rs1", "3"), _rs("rs2", "5"), _rs("rs3", "4")]
    prev = pick_previous_revision(rss, current_revision=dep_rev)
    assert prev.metadata.annotations["deployment.kubernetes.io/revision"] == "4"


def test_pick_previous_revision_none_when_no_prior():
    dep_rev = "1"
    rss = [_rs("rs1", "1")]
    assert pick_previous_revision(rss, current_revision=dep_rev) is None


@pytest.mark.asyncio
async def test_execute_rollback_patches_deployment_with_prev_template():
    prev_rs = _rs("rs-prev", "4")
    curr_rs = _rs("rs-curr", "5")
    apps = MagicMock()
    apps.list_namespaced_replica_set = AsyncMock(return_value=MagicMock(items=[prev_rs, curr_rs]))
    dep_resp = MagicMock()
    dep_resp.metadata.annotations = {"deployment.kubernetes.io/revision": "5"}
    apps.read_namespaced_deployment = AsyncMock(return_value=dep_resp)
    patched = MagicMock()
    patched.metadata.resource_version = "99"
    apps.patch_namespaced_deployment = AsyncMock(return_value=patched)

    def build_apps(token: str):
        assert token == "tok"
        return apps

    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    out = await execute_rollback(target, token="tok", build_apps=build_apps, to_revision=None)
    assert out["rolled_back_to_revision"] == "4"
    assert out["resource_version"] == "99"
