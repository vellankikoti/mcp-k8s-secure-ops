from __future__ import annotations

from typing import Any

from secureops_server.context import GuardedContext
from secureops_server.models import K8sRef


async def describe_workload(ctx: GuardedContext, ref: K8sRef) -> dict[str, Any]:
    if ref.kind != "Deployment":
        raise ValueError(f"unsupported kind for describe_workload in v1.0.0: {ref.kind}")
    if ref.namespace is None:
        raise ValueError("namespace required for Deployment")
    dep = await ctx.k8s.apps_v1.read_namespaced_deployment(name=ref.name, namespace=ref.namespace)
    return {
        "name": dep.metadata.name,
        "namespace": dep.metadata.namespace,
        "uid": dep.metadata.uid,
        "replicas_desired": dep.spec.replicas,
        "replicas_ready": dep.status.ready_replicas or 0,
        "replicas_available": dep.status.available_replicas or 0,
        "replicas_unavailable": dep.status.unavailable_replicas or 0,
        "conditions": [
            {"type": c.type, "status": c.status, "reason": c.reason}
            for c in (dep.status.conditions or [])
        ],
    }
