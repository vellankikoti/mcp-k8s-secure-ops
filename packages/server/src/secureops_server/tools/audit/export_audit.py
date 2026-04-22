from __future__ import annotations

import json as _json
from typing import Literal

import aiosqlite


async def export_audit(
    db_path: str,
    *,
    format: Literal["ndjson", "json"],
    out_path: str,
) -> int:
    if format not in {"ndjson", "json"}:
        raise ValueError(f"unsupported format: {format}")
    rows: list[str] = []
    async with (
        aiosqlite.connect(db_path) as conn,
        conn.execute("SELECT payload_json FROM audit_rows ORDER BY row_id ASC") as cur,
    ):
        async for (payload_json,) in cur:
            rows.append(payload_json)
    if format == "ndjson":
        with open(out_path, "w") as f:
            for r in rows:
                f.write(r)
                f.write("\n")
    else:
        with open(out_path, "w") as f:
            _json.dump([_json.loads(r) for r in rows], f)
    return len(rows)
