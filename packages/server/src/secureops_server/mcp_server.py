from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastmcp import FastMCP
from kubernetes_asyncio import client as _k8s_client

from secureops_server.audit.wrapper import audited_write
from secureops_server.context import Capability
from secureops_server.models import ActionProposal, ActionResult, Actor, K8sRef, OPADecision
from secureops_server.runtime import get_context, get_ledger
from secureops_server.tokens.broker import TokenBroker
from secureops_server.tools.blast_radius.check_pdb_impact import check_pdb_impact
from secureops_server.tools.blast_radius.compute_blast_radius import compute_blast_radius
from secureops_server.tools.blast_radius.find_dependents import find_dependents
from secureops_server.tools.blast_radius.get_traffic_snapshot import get_traffic_snapshot
from secureops_server.tools.cluster_state.describe_workload import describe_workload
from secureops_server.tools.cluster_state.find_unhealthy_workloads import find_unhealthy_workloads
from secureops_server.tools.cluster_state.get_pod_logs import get_pod_logs
from secureops_server.tools.cluster_state.get_recent_events import get_recent_events
from secureops_server.tools.cluster_state.list_workloads import list_workloads
from secureops_server.tools.remediation.restart_deployment import execute_restart

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


def _apps_from_token(token: str) -> Any:
    cfg_default = _k8s_client.Configuration.get_default_copy()
    cfg = _k8s_client.Configuration()
    cfg.host = cfg_default.host
    cfg.verify_ssl = cfg_default.verify_ssl
    cfg.ssl_ca_cert = cfg_default.ssl_ca_cert
    cfg.api_key = {"authorization": f"Bearer {token}"}
    api = _k8s_client.ApiClient(cfg)
    return _k8s_client.AppsV1Api(api)


@mcp.tool(name="restart_deployment")
async def restart_deployment_tool(namespace: str, name: str) -> dict[str, Any]:
    """Restart a Deployment via a rolling rollout (OPA-gated, 5-min token)."""
    ctx = await get_context()
    ledger = await get_ledger()
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.OPA}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace=namespace, name=name)

    br_needs: frozenset[Capability] = (
        frozenset({Capability.K8S, Capability.PROM}) if ctx.prom else frozenset({Capability.K8S})
    )
    br_ctx = ctx.guard(needs=br_needs)
    blast = await compute_blast_radius(br_ctx, target)

    proposal = ActionProposal(
        action_id=str(uuid.uuid4()),
        tool_name="restart_deployment",
        actor=Actor(mcp_client_id="mcp", human_subject=None),
        target=target,
        parameters={},
        blast_radius=blast,
        requested_at=datetime.now(UTC),
    )

    async def _opa_eval(input_doc: dict[str, Any]) -> OPADecision:
        result: OPADecision = await guarded.opa.evaluate_allow(input_doc)
        return result

    async def _do_write() -> ActionResult:
        broker = TokenBroker(core_v1=ctx.k8s.core_v1, ttl_seconds=300)
        token, ttl = await broker.mint(
            action_verb="restart", kind="Deployment", namespace=namespace
        )
        resp = await execute_restart(target, token=token, build_apps=_apps_from_token)
        return ActionResult(
            action_id=proposal.action_id,
            status="allowed_executed",
            opa_decision=OPADecision(
                allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)
            ),
            kyverno_warnings=[],
            token_ttl_remaining_s=ttl,
            k8s_response=resp,
            error=None,
            completed_at=datetime.now(UTC),
        )

    row = await audited_write(
        ledger=ledger, proposal=proposal, opa_eval=_opa_eval, do_write=_do_write
    )
    return row.result.model_dump()


def run_stdio() -> None:
    """Run the MCP server over stdio transport."""
    mcp.run(transport="stdio")
