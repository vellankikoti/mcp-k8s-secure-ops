from __future__ import annotations

from secureops_server.models import AuditRow
from secureops_server.tools.explain.common import narrate_or_fallback


def explain_audit_row_fallback(row: AuditRow) -> str:
    p = row.proposal
    r = row.result
    return (
        f"[{p.tool_name}] on {p.target.kind}/{p.target.name} "
        f"in ns={p.target.namespace} -> status={r.status}, "
        f"opa_allow={r.opa_decision.allow}, token_ttl={r.token_ttl_remaining_s}"
    )


async def explain_audit_row(row: AuditRow) -> str:
    return await narrate_or_fallback(
        prompt="Narrate this audit row in plain English for an SRE reviewing the ledger.",
        structured=row.model_dump(mode="json"),
        fallback=explain_audit_row_fallback(row),
    )
