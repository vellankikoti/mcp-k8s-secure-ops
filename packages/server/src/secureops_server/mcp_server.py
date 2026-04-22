from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any

from fastmcp import FastMCP
from kubernetes_asyncio import client as _k8s_client

from secureops_server.audit.wrapper import audited_write
from secureops_server.context import Capability
from secureops_server.models import (
    ActionProposal,
    ActionResult,
    Actor,
    BlastRadius,
    K8sRef,
    OPADecision,
)
from secureops_server.router.plan_incident_response import plan_incident_response
from secureops_server.runtime import get_context, get_ledger
from secureops_server.tokens.broker import TokenBroker
from secureops_server.tools.audit.export_audit import export_audit as _export_audit
from secureops_server.tools.audit.query_audit import query_audit as _query_audit
from secureops_server.tools.audit.verify_chain import verify_chain as _verify_chain
from secureops_server.tools.blast_radius.check_pdb_impact import check_pdb_impact
from secureops_server.tools.blast_radius.compute_blast_radius import compute_blast_radius
from secureops_server.tools.blast_radius.find_dependents import find_dependents
from secureops_server.tools.blast_radius.get_traffic_snapshot import get_traffic_snapshot
from secureops_server.tools.cluster_state.describe_workload import describe_workload
from secureops_server.tools.cluster_state.find_unhealthy_workloads import find_unhealthy_workloads
from secureops_server.tools.cluster_state.get_pod_logs import get_pod_logs
from secureops_server.tools.cluster_state.get_recent_events import get_recent_events
from secureops_server.tools.cluster_state.list_workloads import list_workloads
from secureops_server.tools.explain.explain_audit_row import explain_audit_row
from secureops_server.tools.explain.explain_blast_radius import explain_blast_radius
from secureops_server.tools.explain.explain_incident_plan import explain_incident_plan
from secureops_server.tools.explain.explain_opa_decision import explain_opa_decision
from secureops_server.tools.remediation.cordon_node import execute_cordon
from secureops_server.tools.remediation.drain_node import execute_drain
from secureops_server.tools.remediation.evict_pod import execute_evict
from secureops_server.tools.remediation.restart_deployment import execute_restart
from secureops_server.tools.remediation.rollback_deployment import execute_rollback
from secureops_server.tools.remediation.scale_workload import execute_scale

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


def _core_from_token(token: str) -> Any:
    cfg_default = _k8s_client.Configuration.get_default_copy()
    cfg = _k8s_client.Configuration()
    cfg.host = cfg_default.host
    cfg.verify_ssl = cfg_default.verify_ssl
    cfg.ssl_ca_cert = cfg_default.ssl_ca_cert
    cfg.api_key = {"authorization": f"Bearer {token}"}
    api = _k8s_client.ApiClient(cfg)
    return _k8s_client.CoreV1Api(api)


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
    ns_labels = await _namespace_labels(ctx, namespace)

    proposal = ActionProposal(
        action_id=str(uuid.uuid4()),
        tool_name="restart_deployment",
        actor=Actor(mcp_client_id="mcp", human_subject=None),
        target=target,
        parameters={"_namespace_labels": ns_labels},
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


@mcp.tool(name="scale_workload")
async def scale_workload_tool(namespace: str, name: str, replicas: int) -> dict[str, Any]:
    """Scale a Deployment to `replicas` (OPA-gated, 5-min token)."""
    ctx = await get_context()
    ledger = await get_ledger()
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.OPA}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace=namespace, name=name)

    br_needs: frozenset[Capability] = (
        frozenset({Capability.K8S, Capability.PROM}) if ctx.prom else frozenset({Capability.K8S})
    )
    br_ctx = ctx.guard(needs=br_needs)
    blast = await compute_blast_radius(br_ctx, target)
    ns_labels = await _namespace_labels(ctx, namespace)

    proposal = ActionProposal(
        action_id=str(uuid.uuid4()),
        tool_name="scale_workload",
        actor=Actor(mcp_client_id="mcp", human_subject=None),
        target=target,
        parameters={"replicas": replicas, "_namespace_labels": ns_labels},
        blast_radius=blast,
        requested_at=datetime.now(UTC),
    )

    async def _opa_eval(input_doc: dict[str, Any]) -> OPADecision:
        result: OPADecision = await guarded.opa.evaluate_allow(input_doc)
        return result

    async def _do_write() -> ActionResult:
        broker = TokenBroker(core_v1=ctx.k8s.core_v1, ttl_seconds=300)
        token, ttl = await broker.mint(action_verb="scale", kind="Deployment", namespace=namespace)
        resp = await execute_scale(
            target, replicas=replicas, token=token, build_apps=_apps_from_token
        )
        return ActionResult(
            action_id=proposal.action_id,
            status="allowed_executed",
            opa_decision=OPADecision(
                allow=True,
                reasons=[],
                matched_policies=[],
                evaluated_at=datetime.now(UTC),
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


@mcp.tool(name="rollback_deployment")
async def rollback_deployment_tool(
    namespace: str, name: str, to_revision: str | None = None
) -> dict[str, Any]:
    """Rollback a Deployment to a prior revision (OPA-gated, 5-min token)."""
    ctx = await get_context()
    ledger = await get_ledger()
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.OPA}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace=namespace, name=name)

    br_needs: frozenset[Capability] = (
        frozenset({Capability.K8S, Capability.PROM}) if ctx.prom else frozenset({Capability.K8S})
    )
    br_ctx = ctx.guard(needs=br_needs)
    blast = await compute_blast_radius(br_ctx, target)
    ns_labels = await _namespace_labels(ctx, namespace)

    proposal = ActionProposal(
        action_id=str(uuid.uuid4()),
        tool_name="rollback_deployment",
        actor=Actor(mcp_client_id="mcp", human_subject=None),
        target=target,
        parameters={"to_revision": to_revision, "_namespace_labels": ns_labels},
        blast_radius=blast,
        requested_at=datetime.now(UTC),
    )

    async def _opa_eval(input_doc: dict[str, Any]) -> OPADecision:
        result: OPADecision = await guarded.opa.evaluate_allow(input_doc)
        return result

    async def _do_write() -> ActionResult:
        broker = TokenBroker(core_v1=ctx.k8s.core_v1, ttl_seconds=300)
        token, ttl = await broker.mint(
            action_verb="rollback", kind="Deployment", namespace=namespace
        )
        resp = await execute_rollback(
            target, token=token, build_apps=_apps_from_token, to_revision=to_revision
        )
        return ActionResult(
            action_id=proposal.action_id,
            status="allowed_executed",
            opa_decision=OPADecision(
                allow=True,
                reasons=[],
                matched_policies=[],
                evaluated_at=datetime.now(UTC),
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


@mcp.tool(name="drain_node")
async def drain_node_tool(name: str, plan: list[dict[str, Any]]) -> dict[str, Any]:
    """Drain a Node by evicting pods per plan (OPA-gated, 5-min token)."""
    ctx = await get_context()
    ledger = await get_ledger()
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.OPA}))
    target = K8sRef(kind="Node", api_version="v1", name=name)

    pods = [
        K8sRef(kind="Pod", api_version="v1", namespace=p["namespace"], name=p["name"]) for p in plan
    ]
    ns_labels = await _namespace_labels(ctx, "kube-system")

    proposal = ActionProposal(
        action_id=str(uuid.uuid4()),
        tool_name="drain_node",
        actor=Actor(mcp_client_id="mcp", human_subject=None),
        target=target,
        parameters={"plan": plan, "_namespace_labels": ns_labels},
        blast_radius=BlastRadius(
            direct=pods,
            one_hop=[],
            transitive=[],
            traffic=_unavailable_traffic(),
            pdb_violations=[],
            data_loss_risk="none",
        ),
        requested_at=datetime.now(UTC),
    )

    async def _opa_eval(input_doc: dict[str, Any]) -> OPADecision:
        result: OPADecision = await guarded.opa.evaluate_allow(input_doc)
        return result

    async def _do_write() -> ActionResult:
        broker = TokenBroker(core_v1=ctx.k8s.core_v1, ttl_seconds=300)
        token, ttl = await broker.mint(action_verb="drain", kind="Node", namespace="kube-system")
        resp = await execute_drain(target, plan=pods, token=token, build_core=_core_from_token)
        return ActionResult(
            action_id=proposal.action_id,
            status="allowed_executed",
            opa_decision=OPADecision(
                allow=True,
                reasons=[],
                matched_policies=[],
                evaluated_at=datetime.now(UTC),
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


@mcp.tool(name="cordon_node")
async def cordon_node_tool(name: str, cordon: bool = True) -> dict[str, Any]:
    """Cordon or uncordon a Node (OPA-gated, 5-min token)."""
    ctx = await get_context()
    ledger = await get_ledger()
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.OPA}))
    target = K8sRef(kind="Node", api_version="v1", name=name)

    ns_labels = await _namespace_labels(ctx, "kube-system")

    proposal = ActionProposal(
        action_id=str(uuid.uuid4()),
        tool_name="cordon_node",
        actor=Actor(mcp_client_id="mcp", human_subject=None),
        target=target,
        parameters={"cordon": cordon, "_namespace_labels": ns_labels},
        blast_radius=BlastRadius(
            direct=[],
            one_hop=[],
            transitive=[],
            traffic=_unavailable_traffic(),
            pdb_violations=[],
            data_loss_risk="none",
        ),
        requested_at=datetime.now(UTC),
    )

    async def _opa_eval(input_doc: dict[str, Any]) -> OPADecision:
        result: OPADecision = await guarded.opa.evaluate_allow(input_doc)
        return result

    async def _do_write() -> ActionResult:
        broker = TokenBroker(core_v1=ctx.k8s.core_v1, ttl_seconds=300)
        token, ttl = await broker.mint(action_verb="cordon", kind="Node", namespace="kube-system")
        resp = await execute_cordon(target, cordon=cordon, token=token, build_core=_core_from_token)
        return ActionResult(
            action_id=proposal.action_id,
            status="allowed_executed",
            opa_decision=OPADecision(
                allow=True,
                reasons=[],
                matched_policies=[],
                evaluated_at=datetime.now(UTC),
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


@mcp.tool(name="evict_pod")
async def evict_pod_tool(namespace: str, name: str, reason: str) -> dict[str, Any]:
    """Evict a Pod with an explicit reason (OPA-gated, 5-min token)."""
    ctx = await get_context()
    ledger = await get_ledger()
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.OPA}))
    target = K8sRef(kind="Pod", api_version="v1", namespace=namespace, name=name)

    ns_labels = await _namespace_labels(ctx, namespace)

    proposal = ActionProposal(
        action_id=str(uuid.uuid4()),
        tool_name="evict_pod",
        actor=Actor(mcp_client_id="mcp", human_subject=None),
        target=target,
        parameters={"reason": reason, "_namespace_labels": ns_labels},
        blast_radius=BlastRadius(
            direct=[target],
            one_hop=[],
            transitive=[],
            traffic=_unavailable_traffic(),
            pdb_violations=[],
            data_loss_risk="none",
        ),
        requested_at=datetime.now(UTC),
    )

    async def _opa_eval(input_doc: dict[str, Any]) -> OPADecision:
        result: OPADecision = await guarded.opa.evaluate_allow(input_doc)
        return result

    async def _do_write() -> ActionResult:
        broker = TokenBroker(core_v1=ctx.k8s.core_v1, ttl_seconds=300)
        token, ttl = await broker.mint(action_verb="evict", kind="Pod", namespace=namespace)
        resp = await execute_evict(target, reason=reason, token=token, build_core=_core_from_token)
        return ActionResult(
            action_id=proposal.action_id,
            status="allowed_executed",
            opa_decision=OPADecision(
                allow=True,
                reasons=[],
                matched_policies=[],
                evaluated_at=datetime.now(UTC),
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


# ---------------------------------------------------------------------------
# Audit read tools (no OPA gate, no token — direct DB access)
# ---------------------------------------------------------------------------


@mcp.tool(name="query_audit")
async def query_audit_tool(
    tool: str | None = None, action_id: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    """Query the audit ledger."""
    db = os.environ.get("SECUREOPS_AUDIT_DB", "/var/lib/secureops/audit.db")
    return await _query_audit(db, tool=tool, action_id=action_id, limit=limit)


@mcp.tool(name="export_audit")
async def export_audit_tool(out_path: str, format: str = "ndjson") -> dict[str, Any]:
    """Export the audit ledger."""
    db = os.environ.get("SECUREOPS_AUDIT_DB", "/var/lib/secureops/audit.db")
    if format not in {"ndjson", "json"}:
        raise ValueError(f"unsupported format: {format}")
    n = await _export_audit(db, format=format, out_path=out_path)  # type: ignore[arg-type]
    return {"exported": n, "out_path": out_path}


@mcp.tool(name="verify_chain")
async def verify_chain_tool() -> dict[str, Any]:
    """Verify audit chain integrity."""
    db = os.environ.get("SECUREOPS_AUDIT_DB", "/var/lib/secureops/audit.db")
    return await _verify_chain(db)


# ---------------------------------------------------------------------------
# Router wrapper
# ---------------------------------------------------------------------------


@mcp.tool(name="plan_incident_response")
async def plan_incident_response_tool(
    symptom: str, target_kind: str, target_name: str, namespace: str | None = None
) -> list[dict[str, Any]]:
    """Deterministic plan for a known symptom (LLM-free)."""
    return plan_incident_response(
        symptom=symptom, target_kind=target_kind, target_name=target_name, namespace=namespace
    )


# ---------------------------------------------------------------------------
# Explain companion wrappers
# ---------------------------------------------------------------------------


@mcp.tool(name="explain_opa_decision")
async def explain_opa_decision_tool(
    allow: bool, reasons: list[str], matched_policies: list[str]
) -> str:
    """Narrate an OPA decision (LLM w/ deterministic fallback)."""
    d = OPADecision(
        allow=allow,
        reasons=reasons,
        matched_policies=matched_policies,
        evaluated_at=datetime.now(UTC),
    )
    return await explain_opa_decision(d)


@mcp.tool(name="explain_blast_radius")
async def explain_blast_radius_tool(blast_radius: dict[str, Any]) -> str:
    """Narrate a blast radius (LLM w/ deterministic fallback)."""
    br = BlastRadius.model_validate(blast_radius)
    return await explain_blast_radius(br)


@mcp.tool(name="explain_incident_plan")
async def explain_incident_plan_tool(plan: list[dict[str, Any]]) -> str:
    """Narrate an incident-response plan (LLM w/ deterministic fallback)."""
    return await explain_incident_plan(plan)


@mcp.tool(name="explain_audit_row")
async def explain_audit_row_tool(audit_row: dict[str, Any]) -> str:
    """Narrate an audit row (LLM w/ deterministic fallback)."""
    from secureops_server.models import AuditRow

    row = AuditRow.model_validate(audit_row)
    return await explain_audit_row(row)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _unavailable_traffic() -> Any:
    from secureops_server.models import TrafficSnapshot

    return TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable")


async def _namespace_labels(ctx: Any, namespace: str) -> dict[str, str]:
    """Fetch the labels on a namespace; returns empty dict on any error."""
    try:
        ns = await ctx.k8s.core_v1.read_namespace(name=namespace)
        labels: dict[str, str] = ns.metadata.labels or {}
        return labels
    except Exception:
        return {}


def run_stdio() -> None:
    """Run the MCP server over stdio transport."""
    mcp.run(transport="stdio")
