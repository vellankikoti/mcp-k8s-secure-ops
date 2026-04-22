from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.context import Capability, SecureOpsContext
from secureops_server.models import K8sRef
from secureops_server.tools.blast_radius.find_dependents import find_dependents


@pytest.mark.asyncio
async def test_find_dependents_walks_ingress_pointing_at_service():
    dep = MagicMock()
    dep.spec.template.metadata.labels = {"app": "checkout"}

    svc = MagicMock()
    svc.metadata.name = "checkout-svc"
    svc.metadata.namespace = "prod"
    svc.metadata.uid = "u-svc"
    svc.spec.selector = {"app": "checkout"}

    backend_svc = MagicMock()
    backend_svc.name = "checkout-svc"
    path = MagicMock()
    path.backend = MagicMock()
    path.backend.service = backend_svc

    rule = MagicMock()
    rule.http = MagicMock()
    rule.http.paths = [path]

    ing = MagicMock()
    ing.metadata.name = "checkout-ing"
    ing.metadata.namespace = "prod"
    ing.metadata.uid = "u-ing"
    ing.spec.rules = [rule]

    k8s = MagicMock()
    k8s.apps_v1 = MagicMock()
    k8s.apps_v1.read_namespaced_deployment = AsyncMock(return_value=dep)
    k8s.core_v1 = MagicMock()
    k8s.core_v1.list_namespaced_service = AsyncMock(return_value=MagicMock(items=[svc]))
    k8s.networking_v1 = MagicMock()
    k8s.networking_v1.list_namespaced_ingress = AsyncMock(return_value=MagicMock(items=[ing]))

    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    deps = await find_dependents(guarded, target)
    kinds = {d.kind for d in deps}
    assert "Ingress" in kinds
    assert any(d.name == "checkout-ing" for d in deps)
