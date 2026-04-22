from __future__ import annotations

from secureops_server.context import GuardedContext
from secureops_server.models import K8sRef


async def get_pod_logs(
    ctx: GuardedContext,
    ref: K8sRef,
    tail_lines: int = 100,
    since_seconds: int | None = None,
) -> str:
    if ref.kind != "Pod":
        raise ValueError(f"get_pod_logs requires Pod kind, got {ref.kind}")
    if ref.namespace is None:
        raise ValueError("namespace required")
    return await ctx.k8s.core_v1.read_namespaced_pod_log(  # type: ignore[no-any-return]
        name=ref.name,
        namespace=ref.namespace,
        tail_lines=tail_lines,
        since_seconds=since_seconds,
    )
