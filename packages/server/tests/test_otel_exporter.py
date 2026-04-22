from __future__ import annotations

from datetime import UTC, datetime

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from secureops_server.audit.otel_exporter import export_audit_span
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


def _audit_row() -> AuditRow:
    aid = "01HY0000000000000000000000"
    proposal = ActionProposal(
        action_id=aid,
        tool_name="restart_deployment",
        actor=Actor(mcp_client_id="c", human_subject=None),
        target=K8sRef(kind="Deployment", api_version="apps/v1", namespace="default", name="x"),
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
    return AuditRow(
        row_id=1,
        action_id=aid,
        prev_hash="0" * 64,
        row_hash="a" * 64,
        proposal=proposal,
        result=result,
        exported_to=[],
    )


def test_export_audit_span_emits_one_span_with_expected_attributes():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    row = _audit_row()
    export_audit_span(row)

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "secureops.action"
    assert span.attributes["secureops.tool"] == "restart_deployment"
    assert span.attributes["secureops.status"] == "allowed_executed"
    assert span.attributes["secureops.action_id"] == row.action_id
    assert span.attributes["secureops.opa_allow"] is True
