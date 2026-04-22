from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from secureops_server.audit.ledger import AuditLedger
from secureops_server.audit.schema import init_db
from secureops_server.models import (
    ActionProposal,
    ActionResult,
    Actor,
    BlastRadius,
    K8sRef,
    OPADecision,
    TrafficSnapshot,
)
from secureops_server.tools.audit.query_audit import query_audit


def _prop(tool: str = "restart_deployment") -> ActionProposal:
    return ActionProposal(
        action_id="01HY",
        tool_name=tool,
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


def _res() -> ActionResult:
    return ActionResult(
        action_id="01HY",
        status="allowed_executed",
        opa_decision=OPADecision(
            allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)
        ),
        kyverno_warnings=[],
        token_ttl_remaining_s=None,
        k8s_response=None,
        error=None,
        completed_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_query_audit_filters_by_tool(tmp_path: Path):
    db = tmp_path / "a.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))
    await ledger.append(_prop("restart_deployment"), _res())
    await ledger.append(_prop("scale_workload"), _res())
    rows = await query_audit(str(db), tool="restart_deployment", limit=10)
    assert len(rows) == 1
    assert rows[0]["tool"] == "restart_deployment"
