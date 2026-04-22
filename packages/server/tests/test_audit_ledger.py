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


def _proposal(aid: str = "01HY0000000000000000000000") -> ActionProposal:
    return ActionProposal(
        action_id=aid,
        tool_name="list_workloads",
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


def _result(aid: str) -> ActionResult:
    return ActionResult(
        action_id=aid,
        status="allowed_executed",
        opa_decision=OPADecision(
            allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)
        ),
        kyverno_warnings=[],
        token_ttl_remaining_s=None,
        k8s_response={"items_count": 0},
        error=None,
        completed_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_append_chains_row_hashes(tmp_path: Path):
    db = tmp_path / "audit.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))
    p1 = _proposal("a1")
    p2 = _proposal("a2")
    r1 = await ledger.append(p1, _result("a1"))
    r2 = await ledger.append(p2, _result("a2"))
    assert r1.row_id == 1
    assert r2.row_id == 2
    assert r1.prev_hash == "0" * 64
    assert r2.prev_hash == r1.row_hash


@pytest.mark.asyncio
async def test_verify_chain_returns_ok_for_unbroken(tmp_path: Path):
    db = tmp_path / "audit.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))
    for i in range(3):
        await ledger.append(_proposal(f"a{i}"), _result(f"a{i}"))
    assert await ledger.verify_chain() is True


@pytest.mark.asyncio
async def test_verify_chain_detects_tamper(tmp_path: Path):
    import aiosqlite

    db = tmp_path / "audit.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))
    for i in range(3):
        await ledger.append(_proposal(f"a{i}"), _result(f"a{i}"))
    async with aiosqlite.connect(str(db)) as conn:
        await conn.execute("UPDATE audit_rows SET payload_json='{}' WHERE row_id=2")
        await conn.commit()
    assert await ledger.verify_chain() is False
