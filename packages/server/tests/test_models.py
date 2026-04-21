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
    PDBViolation,
    TrafficSnapshot,
)


def _ref(kind: str = "Deployment", name: str = "checkout") -> K8sRef:
    return K8sRef(
        kind=kind,
        api_version="apps/v1",
        namespace="default",
        name=name,
        uid="00000000-0000-0000-0000-000000000000",
    )


def test_k8sref_roundtrip_json():
    r = _ref()
    j = r.model_dump_json()
    r2 = K8sRef.model_validate_json(j)
    assert r == r2


def test_blast_radius_defaults_compose():
    br = BlastRadius(
        direct=[_ref()],
        one_hop=[],
        transitive=[],
        traffic=TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable"),
        pdb_violations=[],
        data_loss_risk="none",
    )
    assert br.direct[0].name == "checkout"
    assert br.data_loss_risk == "none"


def test_action_proposal_has_action_id_and_timestamp_utc():
    prop = ActionProposal(
        action_id="01HY0000000000000000000000",
        tool_name="restart_deployment",
        actor=Actor(mcp_client_id="claude-desktop", human_subject=None),
        target=_ref(),
        parameters={},
        blast_radius=BlastRadius(
            direct=[_ref()],
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
    assert prop.requested_at.tzinfo is UTC
    assert prop.tool_name == "restart_deployment"


def test_opa_decision_enforces_reason_list():
    d = OPADecision(
        allow=False,
        reasons=["prod_namespace_scale_zero"],
        matched_policies=["secureops.allow.prod_scale_zero_denied"],
        evaluated_at=datetime.now(UTC),
    )
    assert d.allow is False
    assert "prod_namespace_scale_zero" in d.reasons


def test_action_result_status_literal_enforced():
    import pydantic

    try:
        ActionResult(
            action_id="x",
            status="maybe_allowed",  # type: ignore[arg-type]
            opa_decision=OPADecision(
                allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)
            ),
            kyverno_warnings=[],
            token_ttl_remaining_s=None,
            k8s_response=None,
            error=None,
            completed_at=datetime.now(UTC),
        )
    except pydantic.ValidationError:
        return
    raise AssertionError("status literal should have rejected 'maybe_allowed'")


def test_audit_row_roundtrip():
    prop = ActionProposal(
        action_id="01HY0000000000000000000000",
        tool_name="restart_deployment",
        actor=Actor(mcp_client_id="c", human_subject=None),
        target=_ref(),
        parameters={},
        blast_radius=BlastRadius(
            direct=[_ref()],
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
        action_id=prop.action_id,
        status="allowed_executed",
        opa_decision=OPADecision(
            allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)
        ),
        kyverno_warnings=[],
        token_ttl_remaining_s=280,
        k8s_response={"kind": "Deployment"},
        error=None,
        completed_at=datetime.now(UTC),
    )
    row = AuditRow(
        row_id=1,
        action_id=prop.action_id,
        prev_hash="0" * 64,
        row_hash="a" * 64,
        proposal=prop,
        result=res,
        exported_to=["otel"],
    )
    j = row.model_dump_json()
    row2 = AuditRow.model_validate_json(j)
    assert row2 == row


def test_pdb_violation_fields():
    v = PDBViolation(
        pdb=_ref(kind="PodDisruptionBudget", name="checkout-pdb"),
        current_available=1,
        min_available=2,
    )
    assert v.current_available < v.min_available
