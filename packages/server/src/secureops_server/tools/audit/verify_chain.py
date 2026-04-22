from __future__ import annotations

from secureops_server.audit.ledger import AuditLedger


async def verify_chain(db_path: str) -> dict[str, bool]:
    ledger = AuditLedger(db_path)
    ok = await ledger.verify_chain()
    return {"ok": ok}
