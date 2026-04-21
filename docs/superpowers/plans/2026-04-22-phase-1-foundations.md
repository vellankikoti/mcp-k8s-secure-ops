# mcp-k8s-secure-ops — Phase 1: Foundations

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scaffold the monorepo, ship the pydantic v2 data models, the `SecureOpsContext.guard` capability pattern, an empty Typer CLI + empty FastMCP server, audit ledger schema (no writes yet), and CI gates (ruff, ruff format --check, mypy strict, pytest). Green CI and a commit ends the phase.

**Architecture:** Monorepo with two packages (`packages/server` and `packages/policy_sdk`). Python 3.11, `uv`, FastMCP 3.x, Typer CLI. Same conventions as prior conference projects: `from __future__ import annotations`, `datetime.UTC`, `StrEnum`, pydantic v2, mypy strict.

**Tech Stack:** Python 3.11, uv, FastMCP 3.x, Typer, pydantic v2, aiosqlite, kubernetes_asyncio, httpx, litellm+instructor, opentelemetry-api, ruff, mypy, pytest, pytest-asyncio.

---

## File structure for this phase

```
.
├── pyproject.toml                            # workspace root (uv workspaces)
├── uv.lock
├── .python-version
├── .gitignore
├── .github/workflows/ci.yml
├── packages/
│   ├── server/
│   │   ├── pyproject.toml
│   │   ├── README.md
│   │   ├── src/secureops_server/
│   │   │   ├── __init__.py
│   │   │   ├── models.py
│   │   │   ├── context.py
│   │   │   ├── cli.py
│   │   │   ├── mcp_server.py
│   │   │   └── audit/
│   │   │       ├── __init__.py
│   │   │       └── schema.py
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── test_models.py
│   │       ├── test_context.py
│   │       ├── test_cli.py
│   │       └── test_audit_schema.py
│   └── policy_sdk/
│       ├── pyproject.toml
│       ├── README.md
│       └── src/secureops_policy_sdk/__init__.py
└── docs/
    └── superpowers/
        ├── specs/2026-04-22-mcp-k8s-secure-ops-design.md
        └── plans/                             # this directory
```

---

### Task 1: Repo scaffold, workspace pyproject, python-version, gitignore

**Files:**
- Create: `pyproject.toml`
- Create: `.python-version`
- Create: `.gitignore`
- Create: `README.md`

- [ ] **Step 1: Write root `pyproject.toml`**

```toml
[tool.uv.workspace]
members = ["packages/*"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "N", "SIM", "RUF"]
ignore = ["B008"]

[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
addopts = "-ra -q"
testpaths = ["packages/server/tests", "packages/policy_sdk/tests"]
```

- [ ] **Step 2: Write `.python-version`**

```
3.11
```

- [ ] **Step 3: Write `.gitignore`**

```
__pycache__/
*.pyc
.venv/
dist/
dist-*/
*.egg-info/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/
.env
```

- [ ] **Step 4: Write `README.md`**

```markdown
# mcp-k8s-secure-ops

Auditable AI-assisted Kubernetes incident remediation via MCP. OPA pre-flight + Kyverno admission + short-lived per-action ServiceAccount tokens. LLM narrates, never decides.

See `docs/superpowers/specs/2026-04-22-mcp-k8s-secure-ops-design.md` for the full design.
```

- [ ] **Step 5: Commit**

```bash
git init
git add pyproject.toml .python-version .gitignore README.md
git commit -m "chore: scaffold workspace pyproject and repo metadata"
```

---

### Task 2: Package skeletons (server + policy_sdk)

**Files:**
- Create: `packages/server/pyproject.toml`
- Create: `packages/server/README.md`
- Create: `packages/server/src/secureops_server/__init__.py`
- Create: `packages/policy_sdk/pyproject.toml`
- Create: `packages/policy_sdk/README.md`
- Create: `packages/policy_sdk/src/secureops_policy_sdk/__init__.py`

- [ ] **Step 1: Write `packages/server/pyproject.toml`**

```toml
[project]
name = "mcp-k8s-secure-ops"
version = "0.1.0"
description = "Auditable AI-assisted Kubernetes incident remediation via MCP."
readme = "README.md"
requires-python = ">=3.11"
license = { text = "Apache-2.0" }
authors = [{ name = "vellankikoti", email = "vellankikoti@gmail.com" }]
classifiers = [
  "Development Status :: 4 - Beta",
  "License :: OSI Approved :: Apache Software License",
  "Programming Language :: Python :: 3.11",
  "Topic :: System :: Systems Administration",
]
dependencies = [
  "pydantic>=2.7",
  "httpx>=0.27",
  "typer>=0.12",
  "fastmcp>=3.0",
  "litellm>=1.40",
  "instructor>=1.3",
  "opentelemetry-api>=1.25",
  "rich>=13.7",
  "aiosqlite>=0.20",
  "kubernetes-asyncio>=30.0",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.2",
  "pytest-asyncio>=0.23",
  "pytest-cov>=5.0",
  "pytest-httpx>=0.30",
  "ruff>=0.4",
  "mypy>=1.10",
  "PyYAML>=6.0",
  "types-PyYAML",
]

[project.scripts]
mcp-k8s-secure-ops = "secureops_server.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/secureops_server"]
```

- [ ] **Step 2: Write `packages/server/README.md`**

```markdown
# mcp-k8s-secure-ops

MCP server for auditable Kubernetes incident remediation with OPA + Kyverno + short-lived tokens.

## Install

```bash
uvx mcp-k8s-secure-ops --help
# or
pip install mcp-k8s-secure-ops
```

See the [main repo](https://github.com/vellankikoti/mcp-k8s-secure-ops) for design, workshop, and Helm chart docs.
```

- [ ] **Step 3: Write `packages/server/src/secureops_server/__init__.py`**

```python
"""mcp-k8s-secure-ops — auditable AI-assisted K8s incident remediation."""

__version__ = "0.1.0"
```

- [ ] **Step 4: Write `packages/policy_sdk/pyproject.toml`**

```toml
[project]
name = "mcp-secureops-policy-sdk"
version = "0.1.0"
description = "Helpers for writing OPA rego + Kyverno policies against mcp-k8s-secure-ops models."
readme = "README.md"
requires-python = ">=3.11"
license = { text = "Apache-2.0" }
authors = [{ name = "vellankikoti", email = "vellankikoti@gmail.com" }]
dependencies = ["pydantic>=2.7"]

[project.optional-dependencies]
dev = ["pytest>=8.2"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/secureops_policy_sdk"]
```

- [ ] **Step 5: Write `packages/policy_sdk/README.md`**

```markdown
# mcp-secureops-policy-sdk

Helpers for testing OPA rego policies and Kyverno ClusterPolicies against `mcp-k8s-secure-ops` pydantic models.
```

- [ ] **Step 6: Write `packages/policy_sdk/src/secureops_policy_sdk/__init__.py`**

```python
"""mcp-secureops-policy-sdk — policy authoring helpers."""

__version__ = "0.1.0"
```

- [ ] **Step 7: Sync and verify install**

Run: `uv sync --all-extras`
Expected: resolves and installs both packages editably, no errors.

- [ ] **Step 8: Commit**

```bash
git add packages/
git commit -m "feat: scaffold server + policy_sdk packages"
```

---

### Task 3: Data models (pydantic v2) with failing tests first

**Files:**
- Create: `packages/server/tests/__init__.py` (empty)
- Create: `packages/server/tests/test_models.py`
- Create: `packages/server/src/secureops_server/models.py`

- [ ] **Step 1: Write the failing test file**

```python
# packages/server/tests/test_models.py
from __future__ import annotations

from datetime import UTC, datetime

from secureops_server.models import (
    Actor,
    ActionProposal,
    ActionResult,
    AuditRow,
    BlastRadius,
    K8sRef,
    OPADecision,
    PDBViolation,
    TrafficSnapshot,
)


def _ref(kind: str = "Deployment", name: str = "checkout") -> K8sRef:
    return K8sRef(
        kind=kind,
        api_version="apps/v1",
        namespace="default",
        name=name,
        uid="00000000-0000-0000-0000-000000000000",
    )


def test_k8sref_roundtrip_json():
    r = _ref()
    j = r.model_dump_json()
    r2 = K8sRef.model_validate_json(j)
    assert r == r2


def test_blast_radius_defaults_compose():
    br = BlastRadius(
        direct=[_ref()],
        one_hop=[],
        transitive=[],
        traffic=TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable"),
        pdb_violations=[],
        data_loss_risk="none",
    )
    assert br.direct[0].name == "checkout"
    assert br.data_loss_risk == "none"


def test_action_proposal_has_action_id_and_timestamp_utc():
    prop = ActionProposal(
        action_id="01HY0000000000000000000000",
        tool_name="restart_deployment",
        actor=Actor(mcp_client_id="claude-desktop", human_subject=None),
        target=_ref(),
        parameters={},
        blast_radius=BlastRadius(
            direct=[_ref()],
            one_hop=[],
            transitive=[],
            traffic=TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable"),
            pdb_violations=[],
            data_loss_risk="none",
        ),
        requested_at=datetime.now(UTC),
    )
    assert prop.requested_at.tzinfo is UTC
    assert prop.tool_name == "restart_deployment"


def test_opa_decision_enforces_reason_list():
    d = OPADecision(
        allow=False,
        reasons=["prod_namespace_scale_zero"],
        matched_policies=["secureops.allow.prod_scale_zero_denied"],
        evaluated_at=datetime.now(UTC),
    )
    assert d.allow is False
    assert "prod_namespace_scale_zero" in d.reasons


def test_action_result_status_literal_enforced():
    import pydantic

    try:
        ActionResult(
            action_id="x",
            status="maybe_allowed",  # type: ignore[arg-type]
            opa_decision=OPADecision(
                allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)
            ),
            kyverno_warnings=[],
            token_ttl_remaining_s=None,
            k8s_response=None,
            error=None,
            completed_at=datetime.now(UTC),
        )
    except pydantic.ValidationError:
        return
    raise AssertionError("status literal should have rejected 'maybe_allowed'")


def test_audit_row_roundtrip():
    prop = ActionProposal(
        action_id="01HY0000000000000000000000",
        tool_name="restart_deployment",
        actor=Actor(mcp_client_id="c", human_subject=None),
        target=_ref(),
        parameters={},
        blast_radius=BlastRadius(
            direct=[_ref()],
            one_hop=[],
            transitive=[],
            traffic=TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable"),
            pdb_violations=[],
            data_loss_risk="none",
        ),
        requested_at=datetime.now(UTC),
    )
    res = ActionResult(
        action_id=prop.action_id,
        status="allowed_executed",
        opa_decision=OPADecision(
            allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)
        ),
        kyverno_warnings=[],
        token_ttl_remaining_s=280,
        k8s_response={"kind": "Deployment"},
        error=None,
        completed_at=datetime.now(UTC),
    )
    row = AuditRow(
        row_id=1,
        action_id=prop.action_id,
        prev_hash="0" * 64,
        row_hash="a" * 64,
        proposal=prop,
        result=res,
        exported_to=["otel"],
    )
    j = row.model_dump_json()
    row2 = AuditRow.model_validate_json(j)
    assert row2 == row


def test_pdb_violation_fields():
    v = PDBViolation(pdb=_ref(kind="PodDisruptionBudget", name="checkout-pdb"), current_available=1, min_available=2)
    assert v.current_available < v.min_available
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest packages/server/tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'secureops_server.models'`.

- [ ] **Step 3: Implement `models.py`**

```python
# packages/server/src/secureops_server/models.py
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class K8sRef(BaseModel):
    kind: str
    api_version: str
    namespace: str | None = None
    name: str
    uid: str | None = None


class Actor(BaseModel):
    mcp_client_id: str
    human_subject: str | None = None


class TrafficSnapshot(BaseModel):
    rps: float
    error_rate: float
    p99_latency_ms: float
    source: Literal["prometheus", "unavailable"]


class PDBViolation(BaseModel):
    pdb: K8sRef
    current_available: int
    min_available: int


class BlastRadius(BaseModel):
    direct: list[K8sRef]
    one_hop: list[K8sRef]
    transitive: list[K8sRef]
    traffic: TrafficSnapshot
    pdb_violations: list[PDBViolation]
    data_loss_risk: Literal["none", "pvc_unmounted", "pvc_deleted"]


class ActionProposal(BaseModel):
    action_id: str
    tool_name: str
    actor: Actor
    target: K8sRef
    parameters: dict[str, Any] = Field(default_factory=dict)
    blast_radius: BlastRadius
    requested_at: datetime


class OPADecision(BaseModel):
    allow: bool
    reasons: list[str]
    matched_policies: list[str]
    evaluated_at: datetime


ActionStatus = Literal[
    "allowed_executed",
    "allowed_failed",
    "denied_opa",
    "denied_kyverno",
    "denied_preflight",
]


class ActionResult(BaseModel):
    action_id: str
    status: ActionStatus
    opa_decision: OPADecision
    kyverno_warnings: list[str]
    token_ttl_remaining_s: int | None
    k8s_response: dict[str, Any] | None
    error: str | None
    completed_at: datetime


AuditSink = Literal["otel", "k8s_event"]


class AuditRow(BaseModel):
    row_id: int
    action_id: str
    prev_hash: str
    row_hash: str
    proposal: ActionProposal
    result: ActionResult
    exported_to: list[AuditSink]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest packages/server/tests/test_models.py -v`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/secureops_server/models.py packages/server/tests/test_models.py packages/server/tests/__init__.py
git commit -m "feat(models): add core pydantic v2 data models"
```

---

### Task 4: `SecureOpsContext.guard` capability pattern

**Files:**
- Create: `packages/server/tests/test_context.py`
- Create: `packages/server/src/secureops_server/context.py`

- [ ] **Step 1: Write failing test**

```python
# packages/server/tests/test_context.py
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
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest packages/server/tests/test_context.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `context.py`**

```python
# packages/server/src/secureops_server/context.py
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
```

- [ ] **Step 4: Run tests to verify pass**

Run: `uv run pytest packages/server/tests/test_context.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/secureops_server/context.py packages/server/tests/test_context.py
git commit -m "feat(context): capability-guarded SecureOpsContext"
```

---

### Task 5: Audit ledger schema (DDL + hash helpers, no write path yet)

**Files:**
- Create: `packages/server/tests/test_audit_schema.py`
- Create: `packages/server/src/secureops_server/audit/__init__.py`
- Create: `packages/server/src/secureops_server/audit/schema.py`

- [ ] **Step 1: Write failing test**

```python
# packages/server/tests/test_audit_schema.py
from __future__ import annotations

from pathlib import Path

import aiosqlite
import pytest

from secureops_server.audit.schema import SCHEMA_SQL, hash_row_payload, init_db


@pytest.mark.asyncio
async def test_init_db_creates_audit_table(tmp_path: Path):
    db = tmp_path / "audit.db"
    await init_db(str(db))
    async with aiosqlite.connect(str(db)) as conn:
        async with conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_rows'"
        ) as cur:
            row = await cur.fetchone()
    assert row is not None
    assert row[0] == "audit_rows"


def test_schema_sql_contains_hash_chain_columns():
    assert "prev_hash" in SCHEMA_SQL
    assert "row_hash" in SCHEMA_SQL


def test_hash_row_payload_is_deterministic_and_depends_on_prev_hash():
    h1 = hash_row_payload(prev_hash="0" * 64, payload_json='{"a":1}')
    h2 = hash_row_payload(prev_hash="0" * 64, payload_json='{"a":1}')
    h3 = hash_row_payload(prev_hash="f" * 64, payload_json='{"a":1}')
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest packages/server/tests/test_audit_schema.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `audit/__init__.py` and `audit/schema.py`**

```python
# packages/server/src/secureops_server/audit/__init__.py
"""audit ledger (sqlite source-of-truth + otel + k8s event sinks)."""
```

```python
# packages/server/src/secureops_server/audit/schema.py
from __future__ import annotations

import hashlib

import aiosqlite

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_rows (
  row_id       INTEGER PRIMARY KEY AUTOINCREMENT,
  action_id    TEXT NOT NULL,
  prev_hash    TEXT NOT NULL,
  row_hash     TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_action_id ON audit_rows(action_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_rows(created_at);
"""


async def init_db(path: str) -> None:
    async with aiosqlite.connect(path) as conn:
        await conn.executescript(SCHEMA_SQL)
        await conn.commit()


def hash_row_payload(*, prev_hash: str, payload_json: str) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"\x1e")
    h.update(payload_json.encode("utf-8"))
    return h.hexdigest()
```

- [ ] **Step 4: Run tests to verify pass**

Run: `uv run pytest packages/server/tests/test_audit_schema.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/secureops_server/audit/ packages/server/tests/test_audit_schema.py
git commit -m "feat(audit): ledger schema + deterministic row hash"
```

---

### Task 6: Typer CLI skeleton (version + serve-mcp stubs)

**Files:**
- Create: `packages/server/tests/test_cli.py`
- Create: `packages/server/src/secureops_server/cli.py`
- Create: `packages/server/src/secureops_server/mcp_server.py`

- [ ] **Step 1: Write failing test**

```python
# packages/server/tests/test_cli.py
from __future__ import annotations

from typer.testing import CliRunner

from secureops_server.cli import app

runner = CliRunner()


def test_cli_version_prints_package_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_cli_has_serve_mcp_command():
    result = runner.invoke(app, ["serve-mcp", "--help"])
    assert result.exit_code == 0
    assert "stdio" in result.stdout.lower() or "mcp" in result.stdout.lower()
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest packages/server/tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `mcp_server.py` stub**

```python
# packages/server/src/secureops_server/mcp_server.py
from __future__ import annotations

from fastmcp import FastMCP

mcp: FastMCP = FastMCP("mcp-k8s-secure-ops")


def run_stdio() -> None:
    mcp.run()
```

- [ ] **Step 4: Implement `cli.py`**

```python
# packages/server/src/secureops_server/cli.py
from __future__ import annotations

import typer

from secureops_server import __version__
from secureops_server.mcp_server import run_stdio

app = typer.Typer(
    name="mcp-k8s-secure-ops",
    help="Auditable AI-assisted K8s incident remediation via MCP.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the package version."""
    typer.echo(__version__)


@app.command("serve-mcp")
def serve_mcp() -> None:
    """Run the MCP server over stdio."""
    run_stdio()
```

- [ ] **Step 5: Run tests to verify pass**

Run: `uv run pytest packages/server/tests/test_cli.py -v`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add packages/server/src/secureops_server/cli.py packages/server/src/secureops_server/mcp_server.py packages/server/tests/test_cli.py
git commit -m "feat(cli): Typer skeleton with version + serve-mcp"
```

---

### Task 7: CI workflow (ruff check + ruff format --check + mypy strict + pytest)

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write workflow**

```yaml
# .github/workflows/ci.yml
name: ci
on:
  push:
    branches: [main]
  pull_request:

jobs:
  lint-type-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv python install 3.11
      - run: uv sync --all-extras
      - name: ruff check
        run: uv run ruff check .
      - name: ruff format --check
        run: uv run ruff format --check .
      - name: mypy strict
        run: uv run mypy packages/server/src packages/policy_sdk/src
      - name: pytest
        run: uv run pytest -v
```

- [ ] **Step 2: Run all local gates**

Run in order:
```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy packages/server/src packages/policy_sdk/src
uv run pytest -v
```
Expected: all pass. If ruff format fails, run `uv run ruff format .` and commit the formatting.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: ruff + mypy strict + pytest on push/pr"
```

- [ ] **Step 4: Push and verify CI green**

```bash
# after creating GitHub repo and adding remote
git push -u origin main
gh run watch
```
Expected: workflow succeeds.

---

## Self-review for this phase

- **Spec coverage:** This phase covers spec sections "Package layout" (partial — only `models.py`, `context.py`, `cli.py`, `mcp_server.py`, `audit/schema.py` created) and "Data models" (complete). Tools, OPA, TokenRequest, blast-radius, Helm, release pipeline are explicitly deferred to phases 2–5.
- **Placeholder scan:** none.
- **Type consistency:** `AuditSink`, `ActionStatus` literals are defined once in `models.py` and referenced by type. `Capability` is a `StrEnum` used consistently.

Phase 1 ends with green CI and six commits. Phase 2 begins after merge.
