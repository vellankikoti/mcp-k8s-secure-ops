from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, TypeVar

from secureops_server.audit.ledger import AuditLedger
from secureops_server.models import (
    ActionProposal,
    ActionResult,
    AuditRow,
    OPADecision,
)

T = TypeVar("T")


def _empty_decision(*, allow: bool = True) -> OPADecision:
    return OPADecision(allow=allow, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC))


async def audited_read(
    ledger: AuditLedger,
    proposal: ActionProposal,
    fn: Callable[[], Awaitable[T]],
) -> tuple[T, AuditRow]:
    try:
        value = await fn()
    except Exception as e:
        result = ActionResult(
            action_id=proposal.action_id,
            status="allowed_failed",
            opa_decision=_empty_decision(allow=True),
            kyverno_warnings=[],
            token_ttl_remaining_s=None,
            k8s_response=None,
            error=repr(e),
            completed_at=datetime.now(UTC),
        )
        await ledger.append(proposal, result)
        raise
    result = ActionResult(
        action_id=proposal.action_id,
        status="allowed_executed",
        opa_decision=_empty_decision(allow=True),
        kyverno_warnings=[],
        token_ttl_remaining_s=None,
        k8s_response=None,
        error=None,
        completed_at=datetime.now(UTC),
    )
    row = await ledger.append(proposal, result)
    return value, row


async def audited_write(
    *,
    ledger: AuditLedger,
    proposal: ActionProposal,
    opa_eval: Callable[[dict[str, Any]], Awaitable[OPADecision]],
    do_write: Callable[[], Awaitable[ActionResult]],
) -> AuditRow:
    try:
        decision = await opa_eval(_input_for_opa(proposal))
    except Exception as e:
        result = ActionResult(
            action_id=proposal.action_id,
            status="denied_preflight",
            opa_decision=_empty_decision(allow=False),
            kyverno_warnings=[],
            token_ttl_remaining_s=None,
            k8s_response=None,
            error=repr(e),
            completed_at=datetime.now(UTC),
        )
        return await ledger.append(proposal, result)

    if not decision.allow:
        result = ActionResult(
            action_id=proposal.action_id,
            status="denied_opa",
            opa_decision=decision,
            kyverno_warnings=[],
            token_ttl_remaining_s=None,
            k8s_response=None,
            error=None,
            completed_at=datetime.now(UTC),
        )
        return await ledger.append(proposal, result)

    result = await do_write()
    return await ledger.append(proposal, result)


def _input_for_opa(p: ActionProposal) -> dict[str, Any]:
    return {
        "tool": p.tool_name,
        "tool_category": "write",
        "actor": p.actor.model_dump(),
        "target": {
            "kind": p.target.kind,
            "namespace": p.target.namespace,
            "name": p.target.name,
            "namespace_labels": p.parameters.get("_namespace_labels", {}),
        },
        "parameters": {k: v for k, v in p.parameters.items() if not k.startswith("_")},
        "blast_radius": p.blast_radius.model_dump(),
    }
