from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from secureops_server.tokens.broker import TokenBroker


@pytest.mark.asyncio
async def test_mint_calls_token_request_with_5min_ttl():
    core = MagicMock()
    core.create_namespaced_service_account_token = AsyncMock(
        return_value=MagicMock(status=MagicMock(token="eyJ...", expiration_timestamp=None))
    )
    broker = TokenBroker(core_v1=core, ttl_seconds=300)
    token, ttl = await broker.mint(action_verb="restart", kind="Deployment", namespace="prod")
    assert token == "eyJ..."
    assert ttl == 300
    _args, kwargs = core.create_namespaced_service_account_token.await_args
    assert kwargs["namespace"] == "prod"
    assert kwargs["name"] == "secureops-action-restart-deployment-prod"
    tr_body = kwargs["body"]
    assert tr_body["spec"]["expirationSeconds"] == 300


@pytest.mark.asyncio
async def test_mint_failure_raises_token_mint_failed():
    core = MagicMock()
    core.create_namespaced_service_account_token = AsyncMock(side_effect=RuntimeError("boom"))
    broker = TokenBroker(core_v1=core, ttl_seconds=300)
    with pytest.raises(RuntimeError, match="token_mint_failed"):
        await broker.mint(action_verb="restart", kind="Deployment", namespace="prod")
