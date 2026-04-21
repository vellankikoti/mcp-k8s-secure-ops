from __future__ import annotations

import hashlib

import aiosqlite

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_rows (
  row_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  action_id    TEXT NOT NULL,
  prev_hash    TEXT NOT NULL,
  row_hash     TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_action_id ON audit_rows(action_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_rows(created_at);
"""


async def init_db(path: str) -> None:
    async with aiosqlite.connect(path) as conn:
        await conn.executescript(SCHEMA_SQL)
        await conn.commit()


def hash_row_payload(*, prev_hash: str, payload_json: str) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"\x1e")
    h.update(payload_json.encode("utf-8"))
    return h.hexdigest()
