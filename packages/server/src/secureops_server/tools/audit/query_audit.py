from __future__ import annotations

import json
from typing import Any

import aiosqlite


async def query_audit(
    db_path: str, *, tool: str | None = None, action_id: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    clauses = []
    params: list[Any] = []
    if tool:
        clauses.append("json_extract(payload_json, '$.proposal.tool_name') = ?")
        params.append(tool)
    if action_id:
        clauses.append("action_id = ?")
        params.append(action_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (
        f"SELECT row_id, action_id, payload_json, created_at FROM audit_rows "
        f"{where} ORDER BY row_id DESC LIMIT ?"
    )
    params.append(limit)
    out: list[dict[str, Any]] = []
    async with aiosqlite.connect(db_path) as conn, conn.execute(sql, params) as cur:
        async for row_id, aid, payload_json, created_at in cur:
            p = json.loads(payload_json)
            out.append(
                {
                    "row_id": row_id,
                    "action_id": aid,
                    "tool": p["proposal"]["tool_name"],
                    "status": p["result"]["status"],
                    "created_at": created_at,
                }
            )
    return out
