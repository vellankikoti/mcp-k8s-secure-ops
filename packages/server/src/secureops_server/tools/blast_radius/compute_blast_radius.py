from __future__ import annotations

from typing import Literal

from secureops_server.blast_radius.graph import (
    hpas_for_deployment,
    pdbs_matching,
    pvcs_mounted_by_deployment,
    services_selecting,
)
from secureops_server.blast_radius.traffic import snapshot_for_service
from secureops_server.context import GuardedContext
from secureops_server.models import BlastRadius, K8sRef, TrafficSnapshot


async def compute_blast_radius(ctx: GuardedContext, target: K8sRef) -> BlastRadius:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("compute_blast_radius supports Deployment targets with a namespace")
    dep = await ctx.k8s.apps_v1.read_namespaced_deployment(
        name=target.name, namespace=target.namespace
    )
    pod_labels = dict(dep.spec.template.metadata.labels or {})
    direct = [
        K8sRef(
            kind="Deployment",
            api_version="apps/v1",
            namespace=dep.metadata.namespace,
            name=dep.metadata.name,
            uid=dep.metadata.uid,
        )
    ]
    svcs = await services_selecting(ctx.k8s, target.namespace, pod_labels)
    pdbs = await pdbs_matching(ctx.k8s, target.namespace, pod_labels)
    hpas = await hpas_for_deployment(ctx.k8s, target.namespace, target.name)
    pvcs = await pvcs_mounted_by_deployment(dep)
    one_hop = [*svcs, *pdbs, *hpas, *pvcs]

    if svcs:
        traffic = await snapshot_for_service(ctx.prom, svcs[0])
    else:
        traffic = TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable")

    data_loss_risk: Literal["none", "pvc_unmounted", "pvc_deleted"] = (
        "none" if not pvcs else "pvc_unmounted"
    )

    return BlastRadius(
        direct=direct,
        one_hop=one_hop,
        transitive=[],
        traffic=traffic,
        pdb_violations=[],
        data_loss_risk=data_loss_risk,
    )
