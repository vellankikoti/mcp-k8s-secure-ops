from __future__ import annotations

from typing import Any

from secureops_server.tokens.rbac_templates import per_action_sa_name


class TokenBroker:
    def __init__(self, core_v1: Any, ttl_seconds: int = 300) -> None:
        self._core = core_v1
        self._ttl = ttl_seconds

    async def mint(self, *, action_verb: str, kind: str, namespace: str) -> tuple[str, int]:
        sa = per_action_sa_name(action_verb=action_verb, kind=kind, namespace=namespace)
        body = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "spec": {"expirationSeconds": self._ttl, "audiences": ["secureops"]},
        }
        try:
            resp = await self._core.create_namespaced_service_account_token(
                namespace=namespace, name=sa, body=body
            )
        except Exception as e:
            raise RuntimeError("token_mint_failed") from e
        token = resp.status.token
        return token, self._ttl
