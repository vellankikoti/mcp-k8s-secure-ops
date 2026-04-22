from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from secureops_server.audit.ledger import AuditLedger
from secureops_server.audit.schema import init_db
from secureops_server.audit.wrapper import audited_read, audited_write
from secureops_server.models import (
    ActionProposal,
    ActionResult,
    Actor,
    BlastRadius,
    K8sRef,
    OPADecision,
    TrafficSnapshot,
)


def _prop(tool_name: str = "list_workloads") -> ActionProposal:
    return ActionProposal(
        action_id="01HY",
        tool_name=tool_name,
        actor=Actor(mcp_client_id="c", human_subject=None),
        target=K8sRef(kind="Namespace", api_version="v1", name="default"),
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


@pytest.mark.asyncio
async def test_audited_read_records_row_and_returns_result(tmp_path: Path):
    db = tmp_path / "a.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))

    async def fn() -> list[str]:
        return ["a", "b"]

    out, row = await audited_read(ledger, _prop(), fn)
    assert out == ["a", "b"]
    assert row.result.status == "allowed_executed"
    assert row.row_id == 1


@pytest.mark.asyncio
async def test_audited_write_records_denied_preflight_when_opa_unavailable(tmp_path: Path):
    db = tmp_path / "a.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))

    async def fake_opa_eval(_input) -> OPADecision:
        raise RuntimeError("opa_unavailable")

    async def fake_write() -> ActionResult:
        raise AssertionError("should not be called")

    row = await audited_write(
        ledger=ledger,
        proposal=_prop("restart_deployment"),
        opa_eval=fake_opa_eval,
        do_write=fake_write,
    )
    assert row.result.status == "denied_preflight"
    assert "opa_unavailable" in (row.result.error or "")
    assert row.result.opa_decision.allow is False
