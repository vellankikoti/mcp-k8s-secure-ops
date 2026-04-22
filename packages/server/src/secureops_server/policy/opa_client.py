from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from secureops_server.models import OPADecision


class OPAClient:
    def __init__(self, base_url: str, timeout_s: float = 2.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout_s

    async def evaluate_allow(self, input_doc: dict[str, Any]) -> OPADecision:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                r = await client.post(
                    f"{self._base}/v1/data/secureops/allow",
                    json={"input": input_doc},
                )
                r.raise_for_status()
                raw = r.json().get("result") or {}
        except Exception as e:
            raise RuntimeError("opa_unavailable") from e
        return OPADecision(
            allow=bool(raw.get("allow", False)),
            reasons=list(raw.get("reasons", [])),
            matched_policies=list(raw.get("matched", [])),
            evaluated_at=datetime.now(UTC),
        )
