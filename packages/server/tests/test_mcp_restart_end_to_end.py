from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.audit.ledger import AuditLedger
from secureops_server.audit.schema import init_db
from secureops_server.context import SecureOpsContext
from secureops_server.models import OPADecision
from secureops_server.runtime import override_for_tests


def _dep():
    d = MagicMock()
    d.metadata.name = "checkout"
    d.metadata.namespace = "prod"
    d.metadata.uid = "u"
    d.spec.replicas = 3
    d.spec.selector.match_labels = {"app": "checkout"}
    d.spec.template.metadata.labels = {"app": "checkout"}
    d.spec.template.spec.volumes = []
    return d


@pytest.mark.asyncio
async def test_restart_deployment_happy_path_records_allowed_executed(tmp_path: Path):
    db = tmp_path / "a.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))

    apps = MagicMock()
    apps.read_namespaced_deployment = AsyncMock(return_value=_dep())
    apps.patch_namespaced_deployment = AsyncMock(
        return_value=MagicMock(metadata=MagicMock(resource_version="42"))
    )
    core = MagicMock()
    core.list_namespaced_service = AsyncMock(return_value=MagicMock(items=[]))
    core.create_namespaced_service_account_token = AsyncMock(
        return_value=MagicMock(status=MagicMock(token="t", expiration_timestamp=None))
    )
    policy = MagicMock()
    policy.list_namespaced_pod_disruption_budget = AsyncMock(return_value=MagicMock(items=[]))
    autoscaling = MagicMock()
    autoscaling.list_namespaced_horizontal_pod_autoscaler = AsyncMock(
        return_value=MagicMock(items=[])
    )
    networking = MagicMock()

    k8s = MagicMock()
    k8s.apps_v1 = apps
    k8s.core_v1 = core
    k8s.policy_v1 = policy
    k8s.autoscaling_v2 = autoscaling
    k8s.networking_v1 = networking

    opa = MagicMock()
    opa.evaluate_allow = AsyncMock(
        return_value=OPADecision(
            allow=True,
            reasons=[],
            matched_policies=["secureops.allow.default_write"],
            evaluated_at=datetime.now(UTC),
        )
    )

    ctx = SecureOpsContext(k8s=k8s, opa=opa, prom=None, sqlite=None, llm=None)
    override_for_tests(ctx, ledger)

    # Patch the _apps_from_token helper so the test does not require a real kube config
    import secureops_server.mcp_server as mcp_mod

    original = mcp_mod._apps_from_token
    mcp_mod._apps_from_token = lambda _token: apps  # type: ignore[attr-defined]
    try:
        out = await mcp_mod.restart_deployment_tool(namespace="prod", name="checkout")
    finally:
        mcp_mod._apps_from_token = original  # type: ignore[attr-defined]

    assert out["status"] == "allowed_executed"
    assert out["k8s_response"]["resource_version"] == "42"
    assert (await ledger.verify_chain())["ok"] is True
