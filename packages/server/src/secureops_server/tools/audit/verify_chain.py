from __future__ import annotations

from typing import Any

from secureops_server.audit.ledger import AuditLedger


async def verify_chain(db_path: str) -> dict[str, Any]:
    ledger = AuditLedger(db_path)
    return await ledger.verify_chain()
