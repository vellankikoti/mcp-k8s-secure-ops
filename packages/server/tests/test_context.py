from __future__ import annotations

import pytest
from secureops_server.context import Capability, SecureOpsContext


def test_guard_allows_declared_capabilities():
    ctx = SecureOpsContext(
        k8s=object(),
        opa=object(),
        prom=None,
        sqlite=object(),
        llm=None,
    )
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.OPA, Capability.SQLITE}))
    assert guarded.k8s is ctx.k8s
    assert guarded.opa is ctx.opa
    assert guarded.sqlite is ctx.sqlite


def test_guard_raises_for_undeclared_access():
    ctx = SecureOpsContext(k8s=object(), opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    with pytest.raises(PermissionError, match="OPA"):
        _ = guarded.opa


def test_guard_raises_when_needed_capability_not_wired():
    ctx = SecureOpsContext(k8s=None, opa=None, prom=None, sqlite=None, llm=None)
    with pytest.raises(ValueError, match="K8S"):
        ctx.guard(needs=frozenset({Capability.K8S}))
