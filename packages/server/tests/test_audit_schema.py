from __future__ import annotations

from pathlib import Path

import aiosqlite
import pytest
from secureops_server.audit.schema import SCHEMA_SQL, hash_row_payload, init_db


@pytest.mark.asyncio
async def test_init_db_creates_audit_table(tmp_path: Path):
    db = tmp_path / "audit.db"
    await init_db(str(db))
    async with (
        aiosqlite.connect(str(db)) as conn,
        conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_rows'"
        ) as cur,
    ):
        row = await cur.fetchone()
    assert row is not None
    assert row[0] == "audit_rows"


def test_schema_sql_contains_hash_chain_columns():
    assert "prev_hash" in SCHEMA_SQL
    assert "row_hash" in SCHEMA_SQL


def test_hash_row_payload_is_deterministic_and_depends_on_prev_hash():
    h1 = hash_row_payload(prev_hash="0" * 64, payload_json='{"a":1}')
    h2 = hash_row_payload(prev_hash="0" * 64, payload_json='{"a":1}')
    h3 = hash_row_payload(prev_hash="f" * 64, payload_json='{"a":1}')
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64
