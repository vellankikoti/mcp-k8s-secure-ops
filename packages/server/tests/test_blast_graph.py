from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.blast_radius.graph import (
    hpas_for_deployment,
    pdbs_matching,
    pvcs_mounted_by_deployment,
    services_selecting,
)


def _svc(name: str, selector: dict[str, str]):
    s = MagicMock()
    s.metadata.name = name
    s.metadata.namespace = "prod"
    s.metadata.uid = f"u-{name}"
    s.spec.selector = selector
    return s


@pytest.mark.asyncio
async def test_services_selecting_matches_label_subset():
    core = MagicMock()
    core.list_namespaced_service = AsyncMock(
        return_value=MagicMock(
            items=[
                _svc("checkout-svc", {"app": "checkout"}),
                _svc("other-svc", {"app": "other"}),
            ]
        )
    )
    k8s = MagicMock(core_v1=core)
    labels = {"app": "checkout", "version": "v1"}
    refs = await services_selecting(k8s, namespace="prod", pod_labels=labels)
    assert len(refs) == 1
    assert refs[0].name == "checkout-svc"


def _dep_with_pvcs(pvc_claims: list[str]):
    d = MagicMock()
    d.metadata.name = "checkout"
    d.metadata.namespace = "prod"
    volumes = []
    for c in pvc_claims:
        v = MagicMock()
        v.persistent_volume_claim = MagicMock()
        v.persistent_volume_claim.claim_name = c
        volumes.append(v)
    d.spec.template.spec.volumes = volumes
    return d


@pytest.mark.asyncio
async def test_pvcs_mounted_by_deployment_extracts_claim_names():
    d = _dep_with_pvcs(["data", "cache"])
    refs = await pvcs_mounted_by_deployment(d)
    names = {r.name for r in refs}
    assert names == {"data", "cache"}


def _pdb(name: str, selector: dict[str, str]):
    p = MagicMock()
    p.metadata.name = name
    p.metadata.namespace = "prod"
    p.metadata.uid = f"u-{name}"
    p.spec.selector.match_labels = selector
    return p


@pytest.mark.asyncio
async def test_pdbs_matching_finds_by_selector_subset():
    policy = MagicMock()
    policy.list_namespaced_pod_disruption_budget = AsyncMock(
        return_value=MagicMock(
            items=[
                _pdb("pdb-a", {"app": "checkout"}),
                _pdb("pdb-b", {"app": "x"}),
            ]
        )
    )
    k8s = MagicMock(policy_v1=policy)
    pod_labels = {"app": "checkout", "version": "v1"}
    refs = await pdbs_matching(k8s, namespace="prod", pod_labels=pod_labels)
    assert len(refs) == 1
    assert refs[0].name == "pdb-a"


def _hpa(name: str, target_name: str):
    h = MagicMock()
    h.metadata.name = name
    h.metadata.namespace = "prod"
    h.metadata.uid = f"u-{name}"
    h.spec.scale_target_ref.kind = "Deployment"
    h.spec.scale_target_ref.name = target_name
    return h


@pytest.mark.asyncio
async def test_hpas_for_deployment_matches_target_ref():
    autoscaling = MagicMock()
    autoscaling.list_namespaced_horizontal_pod_autoscaler = AsyncMock(
        return_value=MagicMock(items=[_hpa("h1", "checkout"), _hpa("h2", "other")])
    )
    k8s = MagicMock(autoscaling_v2=autoscaling)
    refs = await hpas_for_deployment(k8s, namespace="prod", deployment_name="checkout")
    assert len(refs) == 1
    assert refs[0].name == "h1"
