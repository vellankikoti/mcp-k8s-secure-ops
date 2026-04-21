from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Capability(StrEnum):
    K8S = "K8S"
    OPA = "OPA"
    PROM = "PROM"
    SQLITE = "SQLITE"
    LLM = "LLM"


@dataclass(frozen=True)
class SecureOpsContext:
    k8s: Any
    opa: Any
    prom: Any
    sqlite: Any
    llm: Any

    def guard(self, needs: frozenset[Capability]) -> GuardedContext:
        missing = [c for c in needs if getattr(self, c.value.lower()) is None]
        if missing:
            raise ValueError(f"context missing required capabilities: {missing}")
        return GuardedContext(_ctx=self, _allowed=needs)


@dataclass(frozen=True)
class GuardedContext:
    _ctx: SecureOpsContext
    _allowed: frozenset[Capability]

    def _check(self, cap: Capability) -> Any:
        if cap not in self._allowed:
            raise PermissionError(
                f"tool did not declare capability {cap.value}; "
                "add it to the `needs` set at guard() time"
            )
        return getattr(self._ctx, cap.value.lower())

    @property
    def k8s(self) -> Any:
        return self._check(Capability.K8S)

    @property
    def opa(self) -> Any:
        return self._check(Capability.OPA)

    @property
    def prom(self) -> Any:
        return self._check(Capability.PROM)

    @property
    def sqlite(self) -> Any:
        return self._check(Capability.SQLITE)

    @property
    def llm(self) -> Any:
        return self._check(Capability.LLM)
