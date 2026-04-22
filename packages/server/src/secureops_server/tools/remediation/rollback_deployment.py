from __future__ import annotations

from collections.abc import Callable
from typing import Any

from secureops_server.models import K8sRef

_REV_ANN = "deployment.kubernetes.io/revision"


def pick_previous_revision(replicasets: list[Any], *, current_revision: str) -> Any | None:
    candidates: list[tuple[int, Any]] = []
    for rs in replicasets:
        rev = (rs.metadata.annotations or {}).get(_REV_ANN)
        if rev is None or rev == current_revision:
            continue
        try:
            candidates.append((int(rev), rs))
        except ValueError:
            continue
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


async def execute_rollback(
    target: K8sRef,
    *,
    token: str,
    build_apps: Callable[[str], Any],
    to_revision: str | None,
) -> dict[str, Any]:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("rollback_deployment requires Deployment target with namespace")
    apps = build_apps(token)
    dep = await apps.read_namespaced_deployment(name=target.name, namespace=target.namespace)
    current_rev = (dep.metadata.annotations or {}).get(_REV_ANN, "")
    rss = (await apps.list_namespaced_replica_set(namespace=target.namespace)).items
    if to_revision is None:
        prev = pick_previous_revision(rss, current_revision=current_rev)
    else:
        prev = next(
            (r for r in rss if (r.metadata.annotations or {}).get(_REV_ANN) == to_revision), None
        )
    if prev is None:
        raise ValueError("no prior revision found to rollback to")
    body = {"spec": {"template": prev.spec.template}}
    resp = await apps.patch_namespaced_deployment(
        name=target.name, namespace=target.namespace, body=body
    )
    return {
        "rolled_back_to_revision": (prev.metadata.annotations or {})[_REV_ANN],
        "resource_version": resp.metadata.resource_version,
    }
