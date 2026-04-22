from __future__ import annotations

from typing import Any

from secureops_server.context import GuardedContext


async def find_unhealthy_workloads(
    ctx: GuardedContext, namespace: str | None = None
) -> list[dict[str, Any]]:
    if namespace:
        dl = await ctx.k8s.apps_v1.list_namespaced_deployment(namespace=namespace)
    else:
        dl = await ctx.k8s.apps_v1.list_deployment_for_all_namespaces()
    out: list[dict[str, Any]] = []
    for d in dl.items:
        desired = d.spec.replicas or 0
        ready = d.status.ready_replicas or 0
        missing = desired - ready
        if missing > 0:
            out.append(
                {
                    "kind": "Deployment",
                    "name": d.metadata.name,
                    "namespace": d.metadata.namespace,
                    "desired_replicas": desired,
                    "ready_replicas": ready,
                    "missing_replicas": missing,
                }
            )
    return out
