from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.context import Capability, SecureOpsContext
from secureops_server.models import K8sRef, TrafficSnapshot
from secureops_server.tools.blast_radius.compute_blast_radius import compute_blast_radius


def _dep():
    d = MagicMock()
    d.metadata.name = "checkout"
    d.metadata.namespace = "prod"
    d.metadata.uid = "u-dep"
    d.spec.replicas = 3
    d.spec.selector.match_labels = {"app": "checkout"}
    d.spec.template.metadata.labels = {"app": "checkout", "version": "v1"}
    d.spec.template.spec.volumes = []
    return d


@pytest.mark.asyncio
async def test_compute_blast_radius_includes_services_and_pdbs_and_traffic():
    k8s = MagicMock()
    k8s.apps_v1 = MagicMock()
    k8s.apps_v1.read_namespaced_deployment = AsyncMock(return_value=_dep())

    svc = MagicMock()
    svc.metadata.name = "checkout-svc"
    svc.metadata.namespace = "prod"
    svc.metadata.uid = "u-svc"
    svc.spec.selector = {"app": "checkout"}
    k8s.core_v1 = MagicMock()
    k8s.core_v1.list_namespaced_service = AsyncMock(return_value=MagicMock(items=[svc]))

    pdb = MagicMock()
    pdb.metadata.name = "checkout-pdb"
    pdb.metadata.namespace = "prod"
    pdb.metadata.uid = "u-pdb"
    pdb.spec.selector.match_labels = {"app": "checkout"}
    k8s.policy_v1 = MagicMock()
    k8s.policy_v1.list_namespaced_pod_disruption_budget = AsyncMock(
        return_value=MagicMock(items=[pdb])
    )

    k8s.autoscaling_v2 = MagicMock()
    k8s.autoscaling_v2.list_namespaced_horizontal_pod_autoscaler = AsyncMock(
        return_value=MagicMock(items=[])
    )

    prom = MagicMock()
    prom.query = AsyncMock(side_effect=RuntimeError("prom down"))

    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=prom, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.PROM}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    br = await compute_blast_radius(guarded, target)
    assert any(r.name == "checkout-svc" for r in br.one_hop)
    assert any(r.kind == "PodDisruptionBudget" for r in br.one_hop)
    assert br.traffic.source == "unavailable"
    assert br.data_loss_risk == "none"
    assert br.direct[0].name == "checkout"
    assert isinstance(br.traffic, TrafficSnapshot)
