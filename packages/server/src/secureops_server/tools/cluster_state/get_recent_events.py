from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from secureops_server.context import GuardedContext


async def get_recent_events(
    ctx: GuardedContext, namespace: str | None = None, since_minutes: int = 30
) -> list[dict[str, Any]]:
    cutoff = datetime.now(UTC) - timedelta(minutes=since_minutes)
    if namespace:
        result = await ctx.k8s.core_v1.list_namespaced_event(namespace=namespace)
    else:
        result = await ctx.k8s.core_v1.list_event_for_all_namespaces()
    out: list[dict[str, Any]] = []
    for e in result.items:
        ts = e.last_timestamp
        if ts is None or ts < cutoff:
            continue
        out.append(
            {
                "name": e.metadata.name,
                "namespace": e.metadata.namespace,
                "type": e.type,
                "reason": e.reason,
                "message": e.message,
                "last_timestamp": ts.isoformat(),
                "involved_object": {
                    "kind": e.involved_object.kind,
                    "name": e.involved_object.name,
                    "namespace": e.involved_object.namespace,
                },
            }
        )
    return out
