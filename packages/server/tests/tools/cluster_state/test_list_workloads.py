from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.context import (
    Capability,
    SecureOpsContext,
)
from secureops_server.tools.cluster_state.list_workloads import list_workloads


def _mock_k8s():
    dep = MagicMock()
    dep.metadata.name = "checkout"
    dep.metadata.namespace = "prod"
    dep.metadata.uid = "u1"
    dep.kind = "Deployment"
    apps = MagicMock()
    apps.list_deployment_for_all_namespaces = AsyncMock(return_value=MagicMock(items=[dep]))
    apps.list_namespaced_deployment = AsyncMock(return_value=MagicMock(items=[dep]))

    core = MagicMock()
    ss = MagicMock()
    ss.list_stateful_set_for_all_namespaces = AsyncMock(return_value=MagicMock(items=[]))
    ds = MagicMock()
    ds.list_daemon_set_for_all_namespaces = AsyncMock(return_value=MagicMock(items=[]))

    k8s = MagicMock()
    k8s.apps_v1 = apps
    k8s.apps_v1.list_stateful_set_for_all_namespaces = ss.list_stateful_set_for_all_namespaces
    k8s.apps_v1.list_daemon_set_for_all_namespaces = ds.list_daemon_set_for_all_namespaces
    k8s.core_v1 = core
    return k8s


@pytest.mark.asyncio
async def test_list_workloads_returns_deployments_across_namespaces():
    k8s = _mock_k8s()
    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    result = await list_workloads(guarded, namespace=None, kind=None)
    assert any(w.name == "checkout" for w in result)
    assert result[0].kind == "Deployment"


@pytest.mark.asyncio
async def test_list_workloads_filters_by_namespace():
    k8s = _mock_k8s()
    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    result = await list_workloads(guarded, namespace="prod", kind="Deployment")
    assert len(result) == 1
    k8s.apps_v1.list_namespaced_deployment.assert_awaited_once_with(namespace="prod")
