from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from secureops_server.context import Capability
from secureops_server.models import K8sRef
from secureops_server.runtime import get_context
from secureops_server.tools.blast_radius.check_pdb_impact import check_pdb_impact
from secureops_server.tools.blast_radius.compute_blast_radius import compute_blast_radius
from secureops_server.tools.blast_radius.find_dependents import find_dependents
from secureops_server.tools.blast_radius.get_traffic_snapshot import get_traffic_snapshot
from secureops_server.tools.cluster_state.describe_workload import describe_workload
from secureops_server.tools.cluster_state.find_unhealthy_workloads import find_unhealthy_workloads
from secureops_server.tools.cluster_state.get_pod_logs import get_pod_logs
from secureops_server.tools.cluster_state.get_recent_events import get_recent_events
from secureops_server.tools.cluster_state.list_workloads import list_workloads

mcp: FastMCP = FastMCP("mcp-k8s-secure-ops")


@mcp.tool(name="list_workloads")
async def list_workloads_tool(
    namespace: str | None = None, kind: str | None = None
) -> list[dict[str, Any]]:
    """List workloads (Deployments, StatefulSets, DaemonSets)."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    refs = await list_workloads(guarded, namespace=namespace, kind=kind)
    return [r.model_dump() for r in refs]


@mcp.tool(name="describe_workload")
async def describe_workload_tool(kind: str, namespace: str, name: str) -> dict[str, Any]:
    """Return replicas + status conditions for a Deployment."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    ref = K8sRef(kind=kind, api_version="apps/v1", namespace=namespace, name=name)
    return await describe_workload(guarded, ref)


@mcp.tool(name="get_recent_events")
async def get_recent_events_tool(
    namespace: str | None = None, since_minutes: int = 30
) -> list[dict[str, Any]]:
    """Return recent Events within the window."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    return await get_recent_events(guarded, namespace=namespace, since_minutes=since_minutes)


@mcp.tool(name="get_pod_logs")
async def get_pod_logs_tool(
    namespace: str,
    name: str,
    tail_lines: int = 100,
    since_seconds: int | None = None,
) -> str:
    """Return tail of pod logs."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    ref = K8sRef(kind="Pod", api_version="v1", namespace=namespace, name=name)
    return await get_pod_logs(guarded, ref, tail_lines=tail_lines, since_seconds=since_seconds)


@mcp.tool(name="find_unhealthy_workloads")
async def find_unhealthy_workloads_tool(
    namespace: str | None = None,
) -> list[dict[str, Any]]:
    """List deployments with missing replicas."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    return await find_unhealthy_workloads(guarded, namespace=namespace)


@mcp.tool(name="compute_blast_radius")
async def compute_blast_radius_tool(kind: str, namespace: str, name: str) -> dict[str, Any]:
    """Compute blast radius for a target Deployment."""
    ctx = await get_context()
    needs: frozenset[Capability] = (
        frozenset({Capability.K8S, Capability.PROM}) if ctx.prom else frozenset({Capability.K8S})
    )
    guarded = ctx.guard(needs=needs)
    target = K8sRef(kind=kind, api_version="apps/v1", namespace=namespace, name=name)
    br = await compute_blast_radius(guarded, target)
    return br.model_dump()


@mcp.tool(name="check_pdb_impact")
async def check_pdb_impact_tool(
    kind: str, namespace: str, name: str, target_available: int
) -> list[dict[str, Any]]:
    """Check whether a target-available count would violate any PDB."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    target = K8sRef(kind=kind, api_version="apps/v1", namespace=namespace, name=name)
    violations = await check_pdb_impact(guarded, target, target_available=target_available)
    return [v.model_dump() for v in violations]


@mcp.tool(name="get_traffic_snapshot")
async def get_traffic_snapshot_tool(namespace: str, name: str) -> dict[str, Any]:
    """Return a Prometheus-derived traffic snapshot for a Service."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.PROM}))
    svc = K8sRef(kind="Service", api_version="v1", namespace=namespace, name=name)
    return (await get_traffic_snapshot(guarded, svc)).model_dump()


@mcp.tool(name="find_dependents")
async def find_dependents_tool(kind: str, namespace: str, name: str) -> list[dict[str, Any]]:
    """Return transitive dependents (Ingresses beyond selecting Services) of a Deployment."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    target = K8sRef(kind=kind, api_version="apps/v1", namespace=namespace, name=name)
    deps = await find_dependents(guarded, target)
    return [d.model_dump() for d in deps]


def run_stdio() -> None:
    """Run the MCP server over stdio transport."""
    mcp.run(transport="stdio")
