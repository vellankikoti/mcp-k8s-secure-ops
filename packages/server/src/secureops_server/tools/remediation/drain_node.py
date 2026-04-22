from __future__ import annotations

from collections.abc import Callable
from typing import Any

from secureops_server.models import K8sRef


async def execute_drain(
    node: K8sRef,
    *,
    plan: list[K8sRef],
    token: str,
    build_core: Callable[[str], Any],
) -> dict[str, Any]:
    if node.kind != "Node":
        raise ValueError("drain_node requires Node reference")
    core = build_core(token)
    await core.patch_node(name=node.name, body={"spec": {"unschedulable": True}})
    evicted = 0
    for pod in plan:
        if pod.kind != "Pod" or pod.namespace is None:
            raise ValueError(f"plan entry must be a Pod with namespace, got {pod}")
        body = {
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": {"name": pod.name, "namespace": pod.namespace},
        }
        await core.create_namespaced_pod_eviction(name=pod.name, namespace=pod.namespace, body=body)
        evicted += 1
    return {"node": node.name, "evicted_count": evicted}
