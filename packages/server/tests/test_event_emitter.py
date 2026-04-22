from __future__ import annotations

from datetime import UTC, datetime

from secureops_server.audit.event_emitter import build_event_body
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


def _row(status: str = "allowed_executed") -> AuditRow:
    aid = "01HY"
    proposal = ActionProposal(
        action_id=aid,
        tool_name="restart_deployment",
        actor=Actor(mcp_client_id="c", human_subject=None),
        target=K8sRef(
            kind="Deployment",
            api_version="apps/v1",
            namespace="prod",
            name="checkout",
        ),
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
    result = ActionResult(
        action_id=aid,
        status=status,  # type: ignore[arg-type]
        opa_decision=OPADecision(
            allow=True,
            reasons=[],
            matched_policies=[],
            evaluated_at=datetime.now(UTC),
        ),
        kyverno_warnings=[],
        token_ttl_remaining_s=None,
        k8s_response=None,
        error=None,
        completed_at=datetime.now(UTC),
    )
    return AuditRow(
        row_id=1,
        action_id=aid,
        prev_hash="0" * 64,
        row_hash="a" * 64,
        proposal=proposal,
        result=result,
        exported_to=[],
    )


def test_event_type_is_normal_for_allowed() -> None:
    body = build_event_body(_row("allowed_executed"))
    assert body["type"] == "Normal"
    assert body["reason"] == "SecureOpsAllowed"


def test_event_type_is_warning_for_denied() -> None:
    body = build_event_body(_row("denied_opa"))
    assert body["type"] == "Warning"
    assert body["reason"] == "SecureOpsDenied"


def test_event_involves_target_object() -> None:
    body = build_event_body(_row())
    assert body["involvedObject"]["kind"] == "Deployment"
    assert body["involvedObject"]["name"] == "checkout"
    assert body["involvedObject"]["namespace"] == "prod"
