from __future__ import annotations

from secureops_server.models import OPADecision
from secureops_server.tools.explain.common import narrate_or_fallback


def explain_opa_decision_fallback(d: OPADecision) -> str:
    verdict = "allowed" if d.allow else "denied"
    reasons = ", ".join(d.reasons) if d.reasons else "(no reasons)"
    matched = ", ".join(d.matched_policies) if d.matched_policies else "(none)"
    return f"OPA {verdict}. Reasons: {reasons}. Matched: {matched}."


async def explain_opa_decision(d: OPADecision) -> str:
    return await narrate_or_fallback(
        prompt="Explain this OPA policy decision in 2-3 plain-English sentences for an SRE.",
        structured=d.model_dump(mode="json"),
        fallback=explain_opa_decision_fallback(d),
    )
