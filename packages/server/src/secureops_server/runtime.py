from __future__ import annotations

import os

from secureops_server.audit.ledger import AuditLedger
from secureops_server.audit.schema import init_db
from secureops_server.context import SecureOpsContext
from secureops_server.k8s_client import build_clients

_ctx: SecureOpsContext | None = None
_ledger: AuditLedger | None = None


async def get_context() -> SecureOpsContext:
    global _ctx
    if _ctx is None:
        kubeconfig = os.environ.get("KUBECONFIG")
        k8s = await build_clients(kubeconfig=kubeconfig)
        _ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    return _ctx


async def get_ledger() -> AuditLedger:
    global _ledger
    if _ledger is None:
        path = os.environ.get("SECUREOPS_AUDIT_DB", "/var/lib/secureops/audit.db")
        await init_db(path)
        _ledger = AuditLedger(path)
    return _ledger


def reset_for_tests() -> None:
    global _ctx, _ledger
    _ctx = None
    _ledger = None


def override_for_tests(ctx: SecureOpsContext, ledger: AuditLedger) -> None:
    global _ctx, _ledger
    _ctx = ctx
    _ledger = ledger
