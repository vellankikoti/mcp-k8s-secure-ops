from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from secureops_server.models import K8sRef


def build_restart_patch() -> dict[str, Any]:
    now_iso = datetime.now(UTC).isoformat()
    return {
        "spec": {
            "template": {
                "metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": now_iso}}
            }
        }
    }


async def execute_restart(
    target: K8sRef,
    *,
    token: str,
    build_apps: Callable[[str], Any],
) -> dict[str, Any]:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("restart_deployment requires Deployment target with namespace")
    apps = build_apps(token)
    patch = build_restart_patch()
    resp = await apps.patch_namespaced_deployment(
        name=target.name, namespace=target.namespace, body=patch
    )
    return {
        "resource_version": resp.metadata.resource_version,
        "patched_at": patch["spec"]["template"]["metadata"]["annotations"][
            "kubectl.kubernetes.io/restartedAt"
        ],
    }
