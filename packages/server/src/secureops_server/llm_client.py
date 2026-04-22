from __future__ import annotations

import os
from typing import Any


async def llm_narrate(prompt: str, structured_input: dict[str, Any]) -> str | None:
    if os.environ.get("SECUREOPS_NO_LLM") == "1":
        return None
    try:
        import instructor  # noqa: F401
        import litellm

        model = os.environ.get("SECUREOPS_LLM_MODEL", "gpt-4o-mini")
        resp = await litellm.acompletion(
            model=model,
            messages=[{"role": "user", "content": f"{prompt}\n\n{structured_input}"}],
            max_tokens=300,
        )
        return str(resp["choices"][0]["message"]["content"])
    except Exception:
        return None
