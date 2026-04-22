from __future__ import annotations

from collections.abc import Callable
from typing import Any

from secureops_server.models import K8sRef


async def execute_evict(
    pod: K8sRef, *, reason: str, token: str, build_core: Callable[[str], Any]
) -> dict[str, Any]:
    if pod.kind != "Pod" or pod.namespace is None:
        raise ValueError("evict_pod requires Pod reference with namespace")
    core = build_core(token)
    body = {
        "apiVersion": "policy/v1",
        "kind": "Eviction",
        "metadata": {
            "name": pod.name,
            "namespace": pod.namespace,
            "annotations": {"secureops.io/reason": reason},
        },
    }
    await core.create_namespaced_pod_eviction(name=pod.name, namespace=pod.namespace, body=body)
    return {"evicted": True, "name": pod.name, "namespace": pod.namespace, "reason": reason}
