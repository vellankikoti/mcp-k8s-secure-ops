from __future__ import annotations

from opentelemetry import trace

from secureops_server.models import AuditRow

_TRACER_NAME = "mcp-k8s-secure-ops"


def export_audit_span(row: AuditRow) -> None:
    tracer = trace.get_tracer(_TRACER_NAME)
    with tracer.start_as_current_span("secureops.action") as span:
        span.set_attribute("secureops.action_id", row.action_id)
        span.set_attribute("secureops.tool", row.proposal.tool_name)
        span.set_attribute("secureops.status", row.result.status)
        span.set_attribute("secureops.opa_allow", row.result.opa_decision.allow)
        span.set_attribute("secureops.target.kind", row.proposal.target.kind)
        span.set_attribute("secureops.target.name", row.proposal.target.name)
        if row.proposal.target.namespace:
            span.set_attribute("secureops.target.namespace", row.proposal.target.namespace)
