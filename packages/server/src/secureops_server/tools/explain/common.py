from __future__ import annotations

from typing import Any

from secureops_server.llm_client import llm_narrate


async def narrate_or_fallback(prompt: str, structured: dict[str, Any], fallback: str) -> str:
    text = await llm_narrate(prompt, structured)
    return text if text else fallback
