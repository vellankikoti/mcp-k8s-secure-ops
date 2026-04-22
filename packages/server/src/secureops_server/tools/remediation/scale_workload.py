from __future__ import annotations

from collections.abc import Callable
from typing import Any

from secureops_server.models import K8sRef


def build_scale_body(replicas: int) -> dict[str, Any]:
    return {"spec": {"replicas": replicas}}


async def execute_scale(
    target: K8sRef, *, replicas: int, token: str, build_apps: Callable[[str], Any]
) -> dict[str, Any]:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("scale_workload requires Deployment target with namespace")
    if replicas < 0:
        raise ValueError("replicas must be >= 0")
    apps = build_apps(token)
    body = build_scale_body(replicas)
    resp = await apps.patch_namespaced_deployment_scale(
        name=target.name, namespace=target.namespace, body=body
    )
    return {"replicas": resp.spec.replicas}
