from __future__ import annotations

import json
from datetime import UTC, datetime

import aiosqlite

from secureops_server.audit.schema import hash_row_payload
from secureops_server.models import ActionProposal, ActionResult, AuditRow


class AuditLedger:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    async def append(self, proposal: ActionProposal, result: ActionResult) -> AuditRow:
        payload = {
            "proposal": proposal.model_dump(mode="json"),
            "result": result.model_dump(mode="json"),
        }
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        async with aiosqlite.connect(self._db_path) as conn:
            async with conn.execute(
                "SELECT row_hash FROM audit_rows ORDER BY row_id DESC LIMIT 1"
            ) as cur:
                last = await cur.fetchone()
            prev_hash = last[0] if last else "0" * 64
            row_hash = hash_row_payload(prev_hash=prev_hash, payload_json=payload_json)
            now = datetime.now(UTC).isoformat()
            cur2 = await conn.execute(
                "INSERT INTO audit_rows(action_id, prev_hash, row_hash, payload_json, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (proposal.action_id, prev_hash, row_hash, payload_json, now),
            )
            row_id = cur2.lastrowid
            await conn.commit()
        return AuditRow(
            row_id=row_id or 0,
            action_id=proposal.action_id,
            prev_hash=prev_hash,
            row_hash=row_hash,
            proposal=proposal,
            result=result,
            exported_to=[],
        )

    async def verify_chain(self) -> bool:
        async with (
            aiosqlite.connect(self._db_path) as conn,
            conn.execute(
                "SELECT row_id, prev_hash, row_hash, payload_json "
                "FROM audit_rows ORDER BY row_id ASC"
            ) as cur,
        ):
            rows = await cur.fetchall()
        expected_prev = "0" * 64
        for _row_id, prev_hash, row_hash, payload_json in rows:
            if prev_hash != expected_prev:
                return False
            if hash_row_payload(prev_hash=prev_hash, payload_json=payload_json) != row_hash:
                return False
            expected_prev = row_hash
        return True
