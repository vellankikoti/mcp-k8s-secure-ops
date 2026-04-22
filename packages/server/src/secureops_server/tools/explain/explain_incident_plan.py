from __future__ import annotations

from typing import Any

from secureops_server.tools.explain.common import narrate_or_fallback


def explain_incident_plan_fallback(plan: list[dict[str, Any]]) -> str:
    return "\n".join(f"{i + 1}. {step['tool']}" for i, step in enumerate(plan))


async def explain_incident_plan(plan: list[dict[str, Any]]) -> str:
    return await narrate_or_fallback(
        prompt="Narrate this incident-response plan for an SRE in 1-2 sentences per step.",
        structured={"plan": plan},
        fallback=explain_incident_plan_fallback(plan),
    )
