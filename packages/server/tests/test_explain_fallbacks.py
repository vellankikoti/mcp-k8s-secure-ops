from __future__ import annotations

from datetime import UTC, datetime

from secureops_server.models import (
    ActionProposal,
    ActionResult,
    Actor,
    AuditRow,
    BlastRadius,
    K8sRef,
    OPADecision,
    TrafficSnapshot,
)
from secureops_server.tools.explain.explain_audit_row import explain_audit_row_fallback
from secureops_server.tools.explain.explain_blast_radius import (
    explain_blast_radius_fallback,
)
from secureops_server.tools.explain.explain_incident_plan import (
    explain_incident_plan_fallback,
)
from secureops_server.tools.explain.explain_opa_decision import (
    explain_opa_decision_fallback,
)


def test_explain_opa_decision_fallback_names_reasons():
    d = OPADecision(
        allow=False,
        reasons=["prod_scale_zero_denied"],
        matched_policies=["secureops.allow.prod_scale_zero"],
        evaluated_at=datetime.now(UTC),
    )
    out = explain_opa_decision_fallback(d)
    assert "denied" in out.lower()
    assert "prod_scale_zero_denied" in out


def test_explain_blast_radius_fallback_mentions_pdb_when_violated():
    br = BlastRadius(
        direct=[K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="x")],
        one_hop=[],
        transitive=[],
        traffic=TrafficSnapshot(
            rps=10.0, error_rate=0.01, p99_latency_ms=150.0, source="prometheus"
        ),
        pdb_violations=[],
        data_loss_risk="none",
    )
    out = explain_blast_radius_fallback(br)
    assert ("1 direct" in out) or ("Deployment/x" in out)
    assert ("150" in out) or ("150.0" in out)


def test_explain_incident_plan_fallback_numbers_steps():
    plan = [{"tool": "a", "args": {}}, {"tool": "b", "args": {}}]
    out = explain_incident_plan_fallback(plan)
    assert "1. a" in out
    assert "2. b" in out


def test_explain_audit_row_fallback_includes_tool_and_status():
    prop = ActionProposal(
        action_id="01HY",
        tool_name="restart_deployment",
        actor=Actor(mcp_client_id="c", human_subject=None),
        target=K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="x"),
        parameters={},
        blast_radius=BlastRadius(
            direct=[],
            one_hop=[],
            transitive=[],
            traffic=TrafficSnapshot(
                rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable"
            ),
            pdb_violations=[],
            data_loss_risk="none",
        ),
        requested_at=datetime.now(UTC),
    )
    res = ActionResult(
        action_id="01HY",
        status="allowed_executed",
        opa_decision=OPADecision(
            allow=True,
            reasons=[],
            matched_policies=[],
            evaluated_at=datetime.now(UTC),
        ),
        kyverno_warnings=[],
        token_ttl_remaining_s=280,
        k8s_response=None,
        error=None,
        completed_at=datetime.now(UTC),
    )
    row = AuditRow(
        row_id=1,
        action_id="01HY",
        prev_hash="0" * 64,
        row_hash="a" * 64,
        proposal=prop,
        result=res,
        exported_to=[],
    )
    out = explain_audit_row_fallback(row)
    assert "restart_deployment" in out
    assert "allowed_executed" in out
