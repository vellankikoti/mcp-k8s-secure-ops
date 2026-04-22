from __future__ import annotations

from typing import Any

import httpx


class PromClient:
    def __init__(self, base_url: str, timeout_s: float = 5.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout_s

    async def query(self, expr: str) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.get(f"{self._base}/api/v1/query", params={"query": expr})
            r.raise_for_status()
            data = r.json()
            if data.get("status") != "success":
                raise RuntimeError(f"prometheus query failed: {data}")
            return list(data["data"]["result"])
