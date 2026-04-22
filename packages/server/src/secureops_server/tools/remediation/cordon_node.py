from __future__ import annotations

from collections.abc import Callable
from typing import Any

from secureops_server.models import K8sRef


async def execute_cordon(
    node: K8sRef, *, cordon: bool, token: str, build_core: Callable[[str], Any]
) -> dict[str, Any]:
    if node.kind != "Node":
        raise ValueError("cordon_node requires Node reference")
    core = build_core(token)
    body = {"spec": {"unschedulable": bool(cordon)}}
    resp = await core.patch_node(name=node.name, body=body)
    return {"unschedulable": bool(resp.spec.unschedulable)}
