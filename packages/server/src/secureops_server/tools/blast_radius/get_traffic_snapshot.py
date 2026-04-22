from __future__ import annotations

from secureops_server.blast_radius.traffic import snapshot_for_service
from secureops_server.context import GuardedContext
from secureops_server.models import K8sRef, TrafficSnapshot


async def get_traffic_snapshot(ctx: GuardedContext, svc: K8sRef) -> TrafficSnapshot:
    if svc.kind != "Service":
        raise ValueError("get_traffic_snapshot requires a Service reference")
    return await snapshot_for_service(ctx.prom, svc)
