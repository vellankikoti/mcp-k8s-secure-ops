# mcp-k8s-secure-ops — Phase 5: Remaining Writes + Kyverno + Release v1.0.0

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the remaining 5 write tools (`scale_workload`, `rollback_deployment`, `drain_node`, `cordon_node`, `evict_pod`); the 3 audit tools (`query_audit`, `export_audit`, `verify_chain`); the deterministic router `plan_incident_response`; the LLM-narrated `explain_*` family with deterministic fallbacks; the `secureops-kyverno` subchart; the full release pipeline (PyPI trusted publishers for server + policy_sdk, multi-arch GHCR image, cosign signing, CycloneDX SBOM, Helm OCI publish, OPA policy bundle OCI publish); the two demo scenarios; and tag **v1.0.0**.

**Architecture:** Five write tools follow the `restart_deployment` pattern from Phase 4 (propose → OPA → mint token → execute → audit). Audit tools run through `audited_read`. Explain tools accept structured input and call `litellm` with `instructor` — deterministic-template fallback when `--no-llm` or LLM error. Release workflow mirrors observatory's (GitHub environments per trusted publisher, cosign keyless, SBOM attached to Release).

**Tech Stack:** FastMCP 3.x, kubernetes_asyncio, aiosqlite, litellm + instructor, helm, docker buildx, cosign, anchore/sbom-action, pypa/gh-action-pypi-publish.

---

## File structure added this phase

```
packages/server/src/secureops_server/
├── tools/
│   ├── remediation/
│   │   ├── scale_workload.py
│   │   ├── rollback_deployment.py
│   │   ├── drain_node.py
│   │   ├── cordon_node.py
│   │   └── evict_pod.py
│   ├── audit/
│   │   ├── __init__.py
│   │   ├── query_audit.py
│   │   ├── export_audit.py
│   │   └── verify_chain.py
│   └── explain/
│       ├── __init__.py
│       ├── common.py
│       ├── explain_opa_decision.py
│       ├── explain_blast_radius.py
│       ├── explain_incident_plan.py
│       └── explain_audit_row.py
├── router/
│   ├── __init__.py
│   └── plan_incident_response.py
└── llm_client.py

helm/secureops-kyverno/
├── Chart.yaml
├── values.yaml
└── templates/
    ├── cluster-policy-prod-scale-zero.yaml
    └── cluster-policy-require-pdb-on-writes.yaml

packages/server/Dockerfile
.github/workflows/release.yml
tests/demo/
├── scenario_a_happy_path.sh
└── scenario_b_policy_denial.sh
```

---

### Task 1: Write tool — `scale_workload`

**Files:**
- Create: `packages/server/src/secureops_server/tools/remediation/scale_workload.py`
- Create: `packages/server/tests/tools/remediation/test_scale_workload.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/tools/remediation/test_scale_workload.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.models import K8sRef
from secureops_server.tools.remediation.scale_workload import (
    build_scale_body,
    execute_scale,
)


def test_build_scale_body_produces_scale_object():
    body = build_scale_body(replicas=5)
    assert body["spec"]["replicas"] == 5


@pytest.mark.asyncio
async def test_execute_scale_patches_scale_subresource():
    apps = MagicMock()
    apps.patch_namespaced_deployment_scale = AsyncMock(
        return_value=MagicMock(spec=MagicMock(replicas=5))
    )

    def build_apps(token: str):
        assert token == "tok"
        return apps

    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    out = await execute_scale(target, replicas=5, token="tok", build_apps=build_apps)
    assert out["replicas"] == 5
```

- [ ] **Step 2: Run failing**

Run: `uv run pytest packages/server/tests/tools/remediation/test_scale_workload.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/remediation/scale_workload.py
from __future__ import annotations

from typing import Any, Callable

from secureops_server.models import K8sRef


def build_scale_body(replicas: int) -> dict[str, Any]:
    return {"spec": {"replicas": replicas}}


async def execute_scale(
    target: K8sRef, *, replicas: int, token: str, build_apps: Callable[[str], Any]
) -> dict[str, Any]:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("scale_workload requires Deployment target with namespace")
    if replicas < 0:
        raise ValueError("replicas must be >= 0")
    apps = build_apps(token)
    body = build_scale_body(replicas)
    resp = await apps.patch_namespaced_deployment_scale(
        name=target.name, namespace=target.namespace, body=body
    )
    return {"replicas": resp.spec.replicas}
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/remediation/test_scale_workload.py -v
git add packages/server/src/secureops_server/tools/remediation/scale_workload.py packages/server/tests/tools/remediation/test_scale_workload.py
git commit -m "feat(tools): scale_workload"
```

---

### Task 2: Write tool — `rollback_deployment`

**Files:**
- Create: `packages/server/src/secureops_server/tools/remediation/rollback_deployment.py`
- Create: `packages/server/tests/tools/remediation/test_rollback_deployment.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/tools/remediation/test_rollback_deployment.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.models import K8sRef
from secureops_server.tools.remediation.rollback_deployment import (
    pick_previous_revision,
    execute_rollback,
)


def _rs(name: str, revision: str):
    r = MagicMock()
    r.metadata.name = name
    r.metadata.namespace = "prod"
    r.metadata.annotations = {"deployment.kubernetes.io/revision": revision}
    r.spec.template = MagicMock()
    return r


def test_pick_previous_revision_returns_second_highest():
    dep_rev = "5"
    rss = [_rs("rs1", "3"), _rs("rs2", "5"), _rs("rs3", "4")]
    prev = pick_previous_revision(rss, current_revision=dep_rev)
    assert prev.metadata.annotations["deployment.kubernetes.io/revision"] == "4"


def test_pick_previous_revision_none_when_no_prior():
    dep_rev = "1"
    rss = [_rs("rs1", "1")]
    assert pick_previous_revision(rss, current_revision=dep_rev) is None


@pytest.mark.asyncio
async def test_execute_rollback_patches_deployment_with_prev_template():
    prev_rs = _rs("rs-prev", "4")
    apps = MagicMock()
    apps.list_namespaced_replica_set = AsyncMock(
        return_value=MagicMock(items=[prev_rs, _rs("rs-curr", "5")])
    )
    apps.read_namespaced_deployment = AsyncMock(
        return_value=MagicMock(metadata=MagicMock(annotations={"deployment.kubernetes.io/revision": "5"}))
    )
    apps.patch_namespaced_deployment = AsyncMock(
        return_value=MagicMock(metadata=MagicMock(resource_version="99"))
    )

    def build_apps(token: str):
        assert token == "tok"
        return apps

    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    out = await execute_rollback(target, token="tok", build_apps=build_apps, to_revision=None)
    assert out["rolled_back_to_revision"] == "4"
    assert out["resource_version"] == "99"
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/tools/remediation/test_rollback_deployment.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/remediation/rollback_deployment.py
from __future__ import annotations

from typing import Any, Callable

from secureops_server.models import K8sRef

_REV_ANN = "deployment.kubernetes.io/revision"


def pick_previous_revision(replicasets: list[Any], *, current_revision: str) -> Any | None:
    candidates: list[tuple[int, Any]] = []
    for rs in replicasets:
        rev = (rs.metadata.annotations or {}).get(_REV_ANN)
        if rev is None or rev == current_revision:
            continue
        try:
            candidates.append((int(rev), rs))
        except ValueError:
            continue
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


async def execute_rollback(
    target: K8sRef,
    *,
    token: str,
    build_apps: Callable[[str], Any],
    to_revision: str | None,
) -> dict[str, Any]:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("rollback_deployment requires Deployment target with namespace")
    apps = build_apps(token)
    dep = await apps.read_namespaced_deployment(name=target.name, namespace=target.namespace)
    current_rev = (dep.metadata.annotations or {}).get(_REV_ANN, "")
    rss = (await apps.list_namespaced_replica_set(namespace=target.namespace)).items
    if to_revision is None:
        prev = pick_previous_revision(rss, current_revision=current_rev)
    else:
        prev = next(
            (r for r in rss if (r.metadata.annotations or {}).get(_REV_ANN) == to_revision), None
        )
    if prev is None:
        raise ValueError("no prior revision found to rollback to")
    body = {"spec": {"template": prev.spec.template}}
    resp = await apps.patch_namespaced_deployment(
        name=target.name, namespace=target.namespace, body=body
    )
    return {
        "rolled_back_to_revision": (prev.metadata.annotations or {})[_REV_ANN],
        "resource_version": resp.metadata.resource_version,
    }
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/remediation/test_rollback_deployment.py -v
git add packages/server/src/secureops_server/tools/remediation/rollback_deployment.py packages/server/tests/tools/remediation/test_rollback_deployment.py
git commit -m "feat(tools): rollback_deployment (revision selection + template patch)"
```

---

### Task 3: Write tool — `cordon_node`

**Files:**
- Create: `packages/server/src/secureops_server/tools/remediation/cordon_node.py`
- Create: `packages/server/tests/tools/remediation/test_cordon_node.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/tools/remediation/test_cordon_node.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.models import K8sRef
from secureops_server.tools.remediation.cordon_node import execute_cordon


@pytest.mark.asyncio
async def test_cordon_sets_spec_unschedulable_true():
    core = MagicMock()
    core.patch_node = AsyncMock(return_value=MagicMock(spec=MagicMock(unschedulable=True)))

    def build_core(token: str):
        assert token == "tok"
        return core

    ref = K8sRef(kind="Node", api_version="v1", name="worker-1")
    out = await execute_cordon(ref, cordon=True, token="tok", build_core=build_core)
    assert out["unschedulable"] is True
    core.patch_node.assert_awaited_once()
    kwargs = core.patch_node.await_args.kwargs
    assert kwargs["body"] == {"spec": {"unschedulable": True}}


@pytest.mark.asyncio
async def test_uncordon_sets_spec_unschedulable_false():
    core = MagicMock()
    core.patch_node = AsyncMock(return_value=MagicMock(spec=MagicMock(unschedulable=False)))

    def build_core(token: str):
        return core

    ref = K8sRef(kind="Node", api_version="v1", name="worker-1")
    out = await execute_cordon(ref, cordon=False, token="tok", build_core=build_core)
    assert out["unschedulable"] is False
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/tools/remediation/test_cordon_node.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/remediation/cordon_node.py
from __future__ import annotations

from typing import Any, Callable

from secureops_server.models import K8sRef


async def execute_cordon(
    node: K8sRef, *, cordon: bool, token: str, build_core: Callable[[str], Any]
) -> dict[str, Any]:
    if node.kind != "Node":
        raise ValueError("cordon_node requires Node reference")
    core = build_core(token)
    body = {"spec": {"unschedulable": bool(cordon)}}
    resp = await core.patch_node(name=node.name, body=body)
    return {"unschedulable": bool(resp.spec.unschedulable)}
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/remediation/test_cordon_node.py -v
git add packages/server/src/secureops_server/tools/remediation/cordon_node.py packages/server/tests/tools/remediation/test_cordon_node.py
git commit -m "feat(tools): cordon_node (cordon/uncordon via flag)"
```

---

### Task 4: Write tool — `evict_pod`

**Files:**
- Create: `packages/server/src/secureops_server/tools/remediation/evict_pod.py`
- Create: `packages/server/tests/tools/remediation/test_evict_pod.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/tools/remediation/test_evict_pod.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.models import K8sRef
from secureops_server.tools.remediation.evict_pod import execute_evict


@pytest.mark.asyncio
async def test_evict_creates_eviction_subresource_with_reason_annotation():
    core = MagicMock()
    core.create_namespaced_pod_eviction = AsyncMock(return_value=MagicMock())

    def build_core(token: str):
        return core

    pod = K8sRef(kind="Pod", api_version="v1", namespace="prod", name="checkout-xyz")
    out = await execute_evict(pod, reason="OOM remediation", token="tok", build_core=build_core)
    assert out["evicted"] is True
    body = core.create_namespaced_pod_eviction.await_args.kwargs["body"]
    assert body["metadata"]["name"] == "checkout-xyz"
    assert body["metadata"]["annotations"]["secureops.io/reason"] == "OOM remediation"
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/tools/remediation/test_evict_pod.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/remediation/evict_pod.py
from __future__ import annotations

from typing import Any, Callable

from secureops_server.models import K8sRef


async def execute_evict(
    pod: K8sRef, *, reason: str, token: str, build_core: Callable[[str], Any]
) -> dict[str, Any]:
    if pod.kind != "Pod" or pod.namespace is None:
        raise ValueError("evict_pod requires Pod reference with namespace")
    core = build_core(token)
    body = {
        "apiVersion": "policy/v1",
        "kind": "Eviction",
        "metadata": {
            "name": pod.name,
            "namespace": pod.namespace,
            "annotations": {"secureops.io/reason": reason},
        },
    }
    await core.create_namespaced_pod_eviction(
        name=pod.name, namespace=pod.namespace, body=body
    )
    return {"evicted": True, "name": pod.name, "namespace": pod.namespace, "reason": reason}
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/remediation/test_evict_pod.py -v
git add packages/server/src/secureops_server/tools/remediation/evict_pod.py packages/server/tests/tools/remediation/test_evict_pod.py
git commit -m "feat(tools): evict_pod via Eviction subresource"
```

---

### Task 5: Write tool — `drain_node`

**Files:**
- Create: `packages/server/src/secureops_server/tools/remediation/drain_node.py`
- Create: `packages/server/tests/tools/remediation/test_drain_node.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/tools/remediation/test_drain_node.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.models import K8sRef
from secureops_server.tools.remediation.drain_node import execute_drain


@pytest.mark.asyncio
async def test_drain_cordons_then_evicts_each_pod_in_plan_order():
    calls: list[str] = []

    core = MagicMock()

    async def patch_node(name: str, body: dict):
        calls.append(f"cordon:{name}")
        return MagicMock(spec=MagicMock(unschedulable=True))

    async def create_evict(name: str, namespace: str, body: dict):
        calls.append(f"evict:{namespace}/{name}")
        return MagicMock()

    core.patch_node = AsyncMock(side_effect=patch_node)
    core.create_namespaced_pod_eviction = AsyncMock(side_effect=create_evict)

    def build_core(token: str):
        return core

    node = K8sRef(kind="Node", api_version="v1", name="worker-1")
    plan = [
        K8sRef(kind="Pod", api_version="v1", namespace="default", name="a"),
        K8sRef(kind="Pod", api_version="v1", namespace="prod", name="b"),
    ]
    out = await execute_drain(node, plan=plan, token="tok", build_core=build_core)
    assert out["evicted_count"] == 2
    assert calls == ["cordon:worker-1", "evict:default/a", "evict:prod/b"]
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/tools/remediation/test_drain_node.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/remediation/drain_node.py
from __future__ import annotations

from typing import Any, Callable

from secureops_server.models import K8sRef


async def execute_drain(
    node: K8sRef,
    *,
    plan: list[K8sRef],
    token: str,
    build_core: Callable[[str], Any],
) -> dict[str, Any]:
    if node.kind != "Node":
        raise ValueError("drain_node requires Node reference")
    core = build_core(token)
    await core.patch_node(name=node.name, body={"spec": {"unschedulable": True}})
    evicted = 0
    for pod in plan:
        if pod.kind != "Pod" or pod.namespace is None:
            raise ValueError(f"plan entry must be a Pod with namespace, got {pod}")
        body = {
            "apiVersion": "policy/v1",
            "kind": "Eviction",
            "metadata": {"name": pod.name, "namespace": pod.namespace},
        }
        await core.create_namespaced_pod_eviction(
            name=pod.name, namespace=pod.namespace, body=body
        )
        evicted += 1
    return {"node": node.name, "evicted_count": evicted}
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/remediation/test_drain_node.py -v
git add packages/server/src/secureops_server/tools/remediation/drain_node.py packages/server/tests/tools/remediation/test_drain_node.py
git commit -m "feat(tools): drain_node (cordon + ordered evictions)"
```

---

### Task 6: Audit tools — `query_audit`, `export_audit`, `verify_chain`

**Files:**
- Create: `packages/server/src/secureops_server/tools/audit/__init__.py`
- Create: `packages/server/src/secureops_server/tools/audit/query_audit.py`
- Create: `packages/server/src/secureops_server/tools/audit/export_audit.py`
- Create: `packages/server/src/secureops_server/tools/audit/verify_chain.py`
- Create: `packages/server/tests/tools/audit/test_query_audit.py`
- Create: `packages/server/tests/tools/audit/test_export_audit.py`
- Create: `packages/server/tests/tools/audit/test_verify_chain.py`

- [ ] **Step 1: Failing tests**

```python
# packages/server/tests/tools/audit/test_query_audit.py
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from secureops_server.audit.ledger import AuditLedger
from secureops_server.audit.schema import init_db
from secureops_server.models import (
    Actor,
    ActionProposal,
    ActionResult,
    BlastRadius,
    K8sRef,
    OPADecision,
    TrafficSnapshot,
)
from secureops_server.tools.audit.query_audit import query_audit


def _prop(tool: str = "restart_deployment") -> ActionProposal:
    return ActionProposal(
        action_id="01HY",
        tool_name=tool,
        actor=Actor(mcp_client_id="c", human_subject=None),
        target=K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="x"),
        parameters={},
        blast_radius=BlastRadius(
            direct=[], one_hop=[], transitive=[],
            traffic=TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable"),
            pdb_violations=[], data_loss_risk="none",
        ),
        requested_at=datetime.now(UTC),
    )


def _res() -> ActionResult:
    return ActionResult(
        action_id="01HY", status="allowed_executed",
        opa_decision=OPADecision(allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)),
        kyverno_warnings=[], token_ttl_remaining_s=None, k8s_response=None, error=None,
        completed_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_query_audit_filters_by_tool(tmp_path: Path):
    db = tmp_path / "a.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))
    await ledger.append(_prop("restart_deployment"), _res())
    await ledger.append(_prop("scale_workload"), _res())
    rows = await query_audit(str(db), tool="restart_deployment", limit=10)
    assert len(rows) == 1
    assert rows[0]["tool"] == "restart_deployment"
```

```python
# packages/server/tests/tools/audit/test_export_audit.py
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from secureops_server.audit.ledger import AuditLedger
from secureops_server.audit.schema import init_db
from secureops_server.tools.audit.export_audit import export_audit
# reuse _prop/_res from test_query_audit
from secureops_server.tests.tools.audit.test_query_audit import _prop, _res  # type: ignore


@pytest.mark.asyncio
async def test_export_audit_ndjson(tmp_path: Path):
    db = tmp_path / "a.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))
    for _ in range(3):
        await ledger.append(_prop(), _res())
    out_path = tmp_path / "out.ndjson"
    n = await export_audit(str(db), format="ndjson", out_path=str(out_path))
    assert n == 3
    lines = out_path.read_text().strip().splitlines()
    assert len(lines) == 3
```

*(If cross-module test import is awkward, duplicate the fixtures inline. The test infra for this project uses inline fixtures per project memory; prefer inline copies.)* Inline fixtures recommended: copy `_prop`/`_res` helpers into `test_export_audit.py` and `test_verify_chain.py`.

```python
# packages/server/tests/tools/audit/test_verify_chain.py
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import aiosqlite
import pytest

from secureops_server.audit.ledger import AuditLedger
from secureops_server.audit.schema import init_db
from secureops_server.models import (
    Actor,
    ActionProposal,
    ActionResult,
    BlastRadius,
    K8sRef,
    OPADecision,
    TrafficSnapshot,
)
from secureops_server.tools.audit.verify_chain import verify_chain


def _prop():
    return ActionProposal(
        action_id="01HY", tool_name="restart_deployment",
        actor=Actor(mcp_client_id="c", human_subject=None),
        target=K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="x"),
        parameters={}, blast_radius=BlastRadius(
            direct=[], one_hop=[], transitive=[],
            traffic=TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable"),
            pdb_violations=[], data_loss_risk="none",
        ),
        requested_at=datetime.now(UTC),
    )


def _res():
    return ActionResult(
        action_id="01HY", status="allowed_executed",
        opa_decision=OPADecision(allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)),
        kyverno_warnings=[], token_ttl_remaining_s=None, k8s_response=None, error=None,
        completed_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_verify_chain_ok_then_breaks_on_tamper(tmp_path: Path):
    db = tmp_path / "a.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))
    for _ in range(3):
        await ledger.append(_prop(), _res())
    out = await verify_chain(str(db))
    assert out["ok"] is True
    async with aiosqlite.connect(str(db)) as conn:
        await conn.execute("UPDATE audit_rows SET payload_json='{}' WHERE row_id=2")
        await conn.commit()
    out2 = await verify_chain(str(db))
    assert out2["ok"] is False
```

- [ ] **Step 2: Confirm failures**

Run: `uv run pytest packages/server/tests/tools/audit/ -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/audit/__init__.py
"""audit read tools."""
```

```python
# packages/server/src/secureops_server/tools/audit/query_audit.py
from __future__ import annotations

import json
from typing import Any

import aiosqlite


async def query_audit(
    db_path: str, *, tool: str | None = None, action_id: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    clauses = []
    params: list[Any] = []
    if tool:
        clauses.append("json_extract(payload_json, '$.proposal.tool_name') = ?")
        params.append(tool)
    if action_id:
        clauses.append("action_id = ?")
        params.append(action_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT row_id, action_id, payload_json, created_at FROM audit_rows {where} ORDER BY row_id DESC LIMIT ?"
    params.append(limit)
    out: list[dict[str, Any]] = []
    async with aiosqlite.connect(db_path) as conn:
        async with conn.execute(sql, params) as cur:
            async for row_id, aid, payload_json, created_at in cur:
                p = json.loads(payload_json)
                out.append(
                    {
                        "row_id": row_id,
                        "action_id": aid,
                        "tool": p["proposal"]["tool_name"],
                        "status": p["result"]["status"],
                        "created_at": created_at,
                    }
                )
    return out
```

```python
# packages/server/src/secureops_server/tools/audit/export_audit.py
from __future__ import annotations

from typing import Literal

import aiosqlite


async def export_audit(
    db_path: str,
    *,
    format: Literal["ndjson", "json"],
    out_path: str,
) -> int:
    n = 0
    if format not in {"ndjson", "json"}:
        raise ValueError(f"unsupported format: {format}")
    rows: list[str] = []
    async with aiosqlite.connect(db_path) as conn:
        async with conn.execute(
            "SELECT payload_json FROM audit_rows ORDER BY row_id ASC"
        ) as cur:
            async for (payload_json,) in cur:
                rows.append(payload_json)
                n += 1
    if format == "ndjson":
        with open(out_path, "w") as f:
            for r in rows:
                f.write(r)
                f.write("\n")
    else:
        import json as _json

        with open(out_path, "w") as f:
            _json.dump([_json.loads(r) for r in rows], f)
    return n
```

```python
# packages/server/src/secureops_server/tools/audit/verify_chain.py
from __future__ import annotations

from secureops_server.audit.ledger import AuditLedger


async def verify_chain(db_path: str) -> dict[str, object]:
    ledger = AuditLedger(db_path)
    ok = await ledger.verify_chain()
    return {"ok": ok}
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/audit/ -v
git add packages/server/src/secureops_server/tools/audit/ packages/server/tests/tools/audit/
git commit -m "feat(tools): audit query/export/verify"
```

---

### Task 7: Deterministic router — `plan_incident_response`

**Files:**
- Create: `packages/server/src/secureops_server/router/__init__.py`
- Create: `packages/server/src/secureops_server/router/plan_incident_response.py`
- Create: `packages/server/tests/test_router.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/test_router.py
from __future__ import annotations

from secureops_server.router.plan_incident_response import plan_incident_response


def test_plan_for_crashlooping_pod_starts_with_diagnostics():
    plan = plan_incident_response(symptom="pod_crashlooping", target_kind="Pod", target_name="checkout-xyz", namespace="prod")
    assert plan[0]["tool"] == "describe_workload" or plan[0]["tool"] == "get_pod_logs"
    assert any(step["tool"] == "get_recent_events" for step in plan)


def test_plan_for_deployment_unhealthy_ends_with_restart_option():
    plan = plan_incident_response(symptom="deployment_unhealthy", target_kind="Deployment", target_name="checkout", namespace="prod")
    tools = [s["tool"] for s in plan]
    assert "find_unhealthy_workloads" in tools
    assert "compute_blast_radius" in tools
    assert "restart_deployment" in tools


def test_plan_for_unknown_symptom_returns_discovery_steps():
    plan = plan_incident_response(symptom="???", target_kind="Namespace", target_name="prod", namespace="prod")
    tools = [s["tool"] for s in plan]
    assert "list_workloads" in tools
    assert "get_recent_events" in tools
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/test_router.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/router/__init__.py
"""deterministic router for incident-response planning."""
```

```python
# packages/server/src/secureops_server/router/plan_incident_response.py
from __future__ import annotations

from typing import Any

_KNOWN_SYMPTOMS = {
    "pod_crashlooping",
    "deployment_unhealthy",
    "node_notready",
    "service_high_errors",
}


def plan_incident_response(
    *, symptom: str, target_kind: str, target_name: str, namespace: str | None
) -> list[dict[str, Any]]:
    if symptom == "pod_crashlooping":
        return [
            {"tool": "describe_workload", "args": {"kind": target_kind, "namespace": namespace, "name": target_name}},
            {"tool": "get_pod_logs", "args": {"namespace": namespace, "name": target_name, "tail_lines": 200}},
            {"tool": "get_recent_events", "args": {"namespace": namespace, "since_minutes": 15}},
        ]
    if symptom == "deployment_unhealthy":
        return [
            {"tool": "find_unhealthy_workloads", "args": {"namespace": namespace}},
            {"tool": "get_recent_events", "args": {"namespace": namespace, "since_minutes": 15}},
            {"tool": "compute_blast_radius", "args": {"kind": target_kind, "namespace": namespace, "name": target_name}},
            {"tool": "restart_deployment", "args": {"namespace": namespace, "name": target_name}, "confirm_required": True},
        ]
    if symptom == "node_notready":
        return [
            {"tool": "get_recent_events", "args": {"namespace": None, "since_minutes": 30}},
            {"tool": "cordon_node", "args": {"name": target_name, "cordon": True}, "confirm_required": True},
        ]
    if symptom == "service_high_errors":
        return [
            {"tool": "get_traffic_snapshot", "args": {"namespace": namespace, "name": target_name}},
            {"tool": "find_dependents", "args": {"kind": target_kind, "namespace": namespace, "name": target_name}},
        ]
    # unknown symptom: safe discovery
    return [
        {"tool": "list_workloads", "args": {"namespace": namespace}},
        {"tool": "get_recent_events", "args": {"namespace": namespace, "since_minutes": 30}},
        {"tool": "find_unhealthy_workloads", "args": {"namespace": namespace}},
    ]
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/test_router.py -v
git add packages/server/src/secureops_server/router/ packages/server/tests/test_router.py
git commit -m "feat(router): deterministic plan_incident_response"
```

---

### Task 8: LLM `explain_*` family with deterministic fallback

**Files:**
- Create: `packages/server/src/secureops_server/llm_client.py`
- Create: `packages/server/src/secureops_server/tools/explain/__init__.py`
- Create: `packages/server/src/secureops_server/tools/explain/common.py`
- Create: `packages/server/src/secureops_server/tools/explain/explain_opa_decision.py`
- Create: `packages/server/src/secureops_server/tools/explain/explain_blast_radius.py`
- Create: `packages/server/src/secureops_server/tools/explain/explain_incident_plan.py`
- Create: `packages/server/src/secureops_server/tools/explain/explain_audit_row.py`
- Create: `packages/server/tests/test_explain_fallbacks.py`

- [ ] **Step 1: Failing test (fallback-only paths)**

```python
# packages/server/tests/test_explain_fallbacks.py
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
    TrafficSnapshot,
)
from secureops_server.tools.explain.explain_audit_row import explain_audit_row_fallback
from secureops_server.tools.explain.explain_blast_radius import explain_blast_radius_fallback
from secureops_server.tools.explain.explain_incident_plan import explain_incident_plan_fallback
from secureops_server.tools.explain.explain_opa_decision import explain_opa_decision_fallback


def test_explain_opa_decision_fallback_names_reasons():
    d = OPADecision(
        allow=False, reasons=["prod_scale_zero_denied"],
        matched_policies=["secureops.allow.prod_scale_zero"],
        evaluated_at=datetime.now(UTC),
    )
    out = explain_opa_decision_fallback(d)
    assert "denied" in out.lower()
    assert "prod_scale_zero_denied" in out


def test_explain_blast_radius_fallback_mentions_pdb_when_violated():
    br = BlastRadius(
        direct=[K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="x")],
        one_hop=[], transitive=[],
        traffic=TrafficSnapshot(rps=10.0, error_rate=0.01, p99_latency_ms=150.0, source="prometheus"),
        pdb_violations=[], data_loss_risk="none",
    )
    out = explain_blast_radius_fallback(br)
    assert "1 direct" in out or "Deployment/x" in out
    assert "150" in out or "150.0" in out


def test_explain_incident_plan_fallback_numbers_steps():
    plan = [{"tool": "a", "args": {}}, {"tool": "b", "args": {}}]
    out = explain_incident_plan_fallback(plan)
    assert "1. a" in out
    assert "2. b" in out


def test_explain_audit_row_fallback_includes_tool_and_status():
    prop = ActionProposal(
        action_id="01HY", tool_name="restart_deployment",
        actor=Actor(mcp_client_id="c", human_subject=None),
        target=K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="x"),
        parameters={}, blast_radius=BlastRadius(
            direct=[], one_hop=[], transitive=[],
            traffic=TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable"),
            pdb_violations=[], data_loss_risk="none",
        ),
        requested_at=datetime.now(UTC),
    )
    res = ActionResult(
        action_id="01HY", status="allowed_executed",
        opa_decision=OPADecision(allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)),
        kyverno_warnings=[], token_ttl_remaining_s=280, k8s_response=None, error=None,
        completed_at=datetime.now(UTC),
    )
    row = AuditRow(row_id=1, action_id="01HY", prev_hash="0"*64, row_hash="a"*64, proposal=prop, result=res, exported_to=[])
    out = explain_audit_row_fallback(row)
    assert "restart_deployment" in out
    assert "allowed_executed" in out
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/test_explain_fallbacks.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement (fallbacks only; LLM path is trivial wrapper)**

```python
# packages/server/src/secureops_server/llm_client.py
from __future__ import annotations

import os
from typing import Any


async def llm_narrate(prompt: str, structured_input: dict[str, Any]) -> str | None:
    if os.environ.get("SECUREOPS_NO_LLM") == "1":
        return None
    try:
        import instructor
        import litellm
        model = os.environ.get("SECUREOPS_LLM_MODEL", "gpt-4o-mini")
        client = instructor.from_litellm(litellm.acompletion)
        resp = await client(
            model=model,
            messages=[{"role": "user", "content": f"{prompt}\n\n{structured_input}"}],
            response_model=str,
            max_tokens=300,
        )
        return str(resp)
    except Exception:
        return None
```

```python
# packages/server/src/secureops_server/tools/explain/__init__.py
"""LLM-narrated explain tools with deterministic fallbacks."""
```

```python
# packages/server/src/secureops_server/tools/explain/common.py
from __future__ import annotations

from secureops_server.llm_client import llm_narrate


async def narrate_or_fallback(prompt: str, structured: dict, fallback: str) -> str:
    text = await llm_narrate(prompt, structured)
    return text if text else fallback
```

```python
# packages/server/src/secureops_server/tools/explain/explain_opa_decision.py
from __future__ import annotations

from secureops_server.models import OPADecision
from secureops_server.tools.explain.common import narrate_or_fallback


def explain_opa_decision_fallback(d: OPADecision) -> str:
    verdict = "allowed" if d.allow else "denied"
    reasons = ", ".join(d.reasons) if d.reasons else "(no reasons)"
    return f"OPA {verdict}. Reasons: {reasons}. Matched: {', '.join(d.matched_policies) or '(none)'}."


async def explain_opa_decision(d: OPADecision) -> str:
    return await narrate_or_fallback(
        prompt="Explain this OPA policy decision in 2-3 plain-English sentences for an SRE.",
        structured=d.model_dump(),
        fallback=explain_opa_decision_fallback(d),
    )
```

```python
# packages/server/src/secureops_server/tools/explain/explain_blast_radius.py
from __future__ import annotations

from secureops_server.models import BlastRadius
from secureops_server.tools.explain.common import narrate_or_fallback


def explain_blast_radius_fallback(br: BlastRadius) -> str:
    direct = ", ".join(f"{r.kind}/{r.name}" for r in br.direct) or "(none)"
    pdbs = len(br.pdb_violations)
    t = br.traffic
    lines = [
        f"{len(br.direct)} direct target(s): {direct}",
        f"{len(br.one_hop)} one-hop dependencies, {len(br.transitive)} transitive.",
        f"Traffic: {t.rps} rps, err {t.error_rate}, p99 {t.p99_latency_ms} ms ({t.source}).",
        f"PDB violations: {pdbs}. Data-loss risk: {br.data_loss_risk}.",
    ]
    return " ".join(lines)


async def explain_blast_radius(br: BlastRadius) -> str:
    return await narrate_or_fallback(
        prompt="Explain this blast radius for an SRE: what breaks if we proceed?",
        structured=br.model_dump(),
        fallback=explain_blast_radius_fallback(br),
    )
```

```python
# packages/server/src/secureops_server/tools/explain/explain_incident_plan.py
from __future__ import annotations

from typing import Any

from secureops_server.tools.explain.common import narrate_or_fallback


def explain_incident_plan_fallback(plan: list[dict[str, Any]]) -> str:
    return "\n".join(f"{i + 1}. {step['tool']}" for i, step in enumerate(plan))


async def explain_incident_plan(plan: list[dict[str, Any]]) -> str:
    return await narrate_or_fallback(
        prompt="Narrate this incident-response plan for an SRE in 1-2 sentences per step.",
        structured={"plan": plan},
        fallback=explain_incident_plan_fallback(plan),
    )
```

```python
# packages/server/src/secureops_server/tools/explain/explain_audit_row.py
from __future__ import annotations

from secureops_server.models import AuditRow
from secureops_server.tools.explain.common import narrate_or_fallback


def explain_audit_row_fallback(row: AuditRow) -> str:
    p = row.proposal
    r = row.result
    return (
        f"[{p.tool_name}] on {p.target.kind}/{p.target.name} "
        f"in ns={p.target.namespace} → status={r.status}, "
        f"opa_allow={r.opa_decision.allow}, token_ttl={r.token_ttl_remaining_s}"
    )


async def explain_audit_row(row: AuditRow) -> str:
    return await narrate_or_fallback(
        prompt="Narrate this audit row in plain English for an SRE reviewing the ledger.",
        structured=row.model_dump(),
        fallback=explain_audit_row_fallback(row),
    )
```

- [ ] **Step 4: Pass + commit**

```bash
SECUREOPS_NO_LLM=1 uv run pytest packages/server/tests/test_explain_fallbacks.py -v
git add packages/server/src/secureops_server/llm_client.py packages/server/src/secureops_server/tools/explain/ packages/server/tests/test_explain_fallbacks.py
git commit -m "feat(explain): LLM-narrated explain tools with deterministic fallback"
```

---

### Task 9: Wire remaining tools into MCP (13 additions bringing total to 18)

**Files:**
- Modify: `packages/server/src/secureops_server/mcp_server.py`
- Modify: `packages/server/tests/test_mcp_server_registration.py`

- [ ] **Step 1: Update registration test required set to all 18**

```python
required = {
    # cluster_state (5)
    "list_workloads", "describe_workload", "get_recent_events", "get_pod_logs", "find_unhealthy_workloads",
    # blast_radius (4)
    "compute_blast_radius", "check_pdb_impact", "get_traffic_snapshot", "find_dependents",
    # remediation (6)
    "restart_deployment", "scale_workload", "rollback_deployment", "drain_node", "cordon_node", "evict_pod",
    # audit (3)
    "query_audit", "export_audit", "verify_chain",
}
```

Also add companion set for explain + router (not counted in 18 but must be reachable):

```python
companions = {"plan_incident_response", "explain_opa_decision", "explain_blast_radius", "explain_incident_plan", "explain_audit_row"}
```

And assert `companions <= names` in the test.

- [ ] **Step 2: Register each tool in `mcp_server.py`**

Append wrappers for `scale_workload_tool`, `rollback_deployment_tool`, `drain_node_tool`, `cordon_node_tool`, `evict_pod_tool`, `query_audit_tool`, `export_audit_tool`, `verify_chain_tool`, `plan_incident_response_tool`, `explain_opa_decision_tool`, `explain_blast_radius_tool`, `explain_incident_plan_tool`, `explain_audit_row_tool`. Each write wrapper follows the `restart_deployment_tool` pattern: build `ActionProposal` (with blast-radius), compute OPA input, go through `audited_write`. Audit and explain wrappers go through `audited_read`.

Example for `scale_workload_tool`:

```python
@mcp.tool()
async def scale_workload_tool(namespace: str, name: str, replicas: int) -> dict:
    """Scale a Deployment to `replicas` (OPA-gated, 5-min token)."""
    ctx = await get_context()
    ledger = await get_ledger()
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.OPA}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace=namespace, name=name)
    br_ctx = ctx.guard(needs=frozenset({Capability.K8S, Capability.PROM})) if ctx.prom else ctx.guard(needs=frozenset({Capability.K8S}))
    blast = await compute_blast_radius(br_ctx, target)
    proposal = ActionProposal(
        action_id=str(uuid.uuid4()), tool_name="scale_workload",
        actor=Actor(mcp_client_id="mcp", human_subject=None),
        target=target, parameters={"replicas": replicas},
        blast_radius=blast, requested_at=datetime.now(UTC),
    )

    async def _opa_eval(input_doc: dict) -> OPADecision:
        return await guarded.opa.evaluate_allow(input_doc)

    async def _do_write() -> ActionResult:
        from secureops_server.tools.remediation.scale_workload import execute_scale
        broker = TokenBroker(core_v1=ctx.k8s.core_v1, ttl_seconds=300)
        token, ttl = await broker.mint(action_verb="scale", kind="Deployment", namespace=namespace)
        resp = await execute_scale(target, replicas=replicas, token=token, build_apps=_apps_from_token)
        return ActionResult(
            action_id=proposal.action_id, status="allowed_executed",
            opa_decision=OPADecision(allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)),
            kyverno_warnings=[], token_ttl_remaining_s=ttl, k8s_response=resp, error=None,
            completed_at=datetime.now(UTC),
        )

    row = await audited_write(ledger=ledger, proposal=proposal, opa_eval=_opa_eval, do_write=_do_write)
    return row.result.model_dump()
```

The same pattern applies to `rollback_deployment_tool`, `cordon_node_tool`, `evict_pod_tool`, `drain_node_tool`, with action verbs `rollback`, `cordon`, `evict`, `drain` respectively and calls to the corresponding `execute_*` functions. Build the appropriate core client via `_core_from_token(token)` (add a helper analogous to `_apps_from_token`).

Audit read wrappers:

```python
@mcp.tool()
async def query_audit_tool(tool: str | None = None, action_id: str | None = None, limit: int = 50) -> list[dict]:
    """Query the audit ledger."""
    import os
    db = os.environ.get("SECUREOPS_AUDIT_DB", "/var/lib/secureops/audit.db")
    from secureops_server.tools.audit.query_audit import query_audit
    return await query_audit(db, tool=tool, action_id=action_id, limit=limit)


@mcp.tool()
async def export_audit_tool(out_path: str, format: str = "ndjson") -> dict:
    """Export the audit ledger."""
    import os
    db = os.environ.get("SECUREOPS_AUDIT_DB", "/var/lib/secureops/audit.db")
    from secureops_server.tools.audit.export_audit import export_audit
    n = await export_audit(db, format=format, out_path=out_path)  # type: ignore[arg-type]
    return {"exported": n, "out_path": out_path}


@mcp.tool()
async def verify_chain_tool() -> dict:
    """Verify audit chain integrity."""
    import os
    db = os.environ.get("SECUREOPS_AUDIT_DB", "/var/lib/secureops/audit.db")
    from secureops_server.tools.audit.verify_chain import verify_chain
    return await verify_chain(db)
```

Router + explain wrappers:

```python
@mcp.tool()
async def plan_incident_response_tool(symptom: str, target_kind: str, target_name: str, namespace: str | None = None) -> list[dict]:
    """Deterministic plan for a known symptom (LLM-free)."""
    from secureops_server.router.plan_incident_response import plan_incident_response
    return plan_incident_response(symptom=symptom, target_kind=target_kind, target_name=target_name, namespace=namespace)


@mcp.tool()
async def explain_opa_decision_tool(allow: bool, reasons: list[str], matched_policies: list[str]) -> str:
    from datetime import UTC, datetime
    from secureops_server.tools.explain.explain_opa_decision import explain_opa_decision
    d = OPADecision(allow=allow, reasons=reasons, matched_policies=matched_policies, evaluated_at=datetime.now(UTC))
    return await explain_opa_decision(d)


# explain_blast_radius_tool, explain_incident_plan_tool, explain_audit_row_tool follow same pattern:
# accept dict inputs, validate via pydantic, call the async explain_* function.
```

- [ ] **Step 3: Run all tests**

Run: `uv run pytest -v`
Expected: all passing.

- [ ] **Step 4: Commit**

```bash
git add packages/server/src/secureops_server/mcp_server.py packages/server/tests/test_mcp_server_registration.py
git commit -m "feat(mcp): register all 18 tools + router + 4 explain companions"
```

---

### Task 10: Kyverno subchart

**Files:**
- Create: `helm/secureops-kyverno/Chart.yaml`
- Create: `helm/secureops-kyverno/values.yaml`
- Create: `helm/secureops-kyverno/templates/cluster-policy-prod-scale-zero.yaml`
- Create: `helm/secureops-kyverno/templates/cluster-policy-require-pdb-on-writes.yaml`
- Create: `tests/policy/kyverno/kyverno-test.yaml`

- [ ] **Step 1: Chart + policies**

```yaml
# helm/secureops-kyverno/Chart.yaml
apiVersion: v2
name: secureops-kyverno
description: Kyverno ClusterPolicies that backstop mcp-k8s-secure-ops writes.
type: application
version: 0.1.0
appVersion: "1.0.0"
```

```yaml
# helm/secureops-kyverno/values.yaml
prodTierLabel: "tier=prod"
```

```yaml
# helm/secureops-kyverno/templates/cluster-policy-prod-scale-zero.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: secureops-deny-prod-scale-zero
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: deny-prod-scale-zero
      match:
        any:
          - resources:
              kinds: ["Deployment"]
              operations: ["UPDATE"]
      validate:
        message: "scaling a prod-tier Deployment to 0 replicas is denied"
        deny:
          conditions:
            all:
              - key: "{{ request.object.spec.replicas }}"
                operator: Equals
                value: 0
              - key: "{{ request.namespace.metadata.labels.tier || '' }}"
                operator: Equals
                value: prod
```

```yaml
# helm/secureops-kyverno/templates/cluster-policy-require-pdb-on-writes.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: secureops-require-pdb-annotation-on-prod-writes
spec:
  validationFailureAction: Audit
  background: false
  rules:
    - name: warn-missing-pdb-check
      match:
        any:
          - resources:
              kinds: ["Deployment"]
              operations: ["UPDATE"]
      validate:
        message: "prod Deployment modified without a visible PDB annotation; confirm PDB exists"
        pattern:
          metadata:
            annotations:
              secureops.io/pdb-checked: "?*"
```

```yaml
# tests/policy/kyverno/kyverno-test.yaml
apiVersion: cli.kyverno.io/v1alpha1
kind: Test
metadata: { name: secureops-kyverno-tests }
policies:
  - helm/secureops-kyverno/templates/cluster-policy-prod-scale-zero.yaml
resources:
  - tests/policy/kyverno/resources.yaml
results:
  - policy: secureops-deny-prod-scale-zero
    rule: deny-prod-scale-zero
    resource: checkout-scaled-zero
    kind: Deployment
    result: fail
```

Add a `tests/policy/kyverno/resources.yaml` with a minimal Deployment + Namespace having `tier: prod` and `spec.replicas: 0`.

- [ ] **Step 2: Add Kyverno test step to CI**

Append to `.github/workflows/ci.yml`:

```yaml
      - name: install kyverno CLI
        run: |
          curl -L https://github.com/kyverno/kyverno/releases/latest/download/kyverno-cli_linux_x86_64.tar.gz | tar xz
          sudo mv kyverno /usr/local/bin/
      - name: kyverno test
        run: kyverno test tests/policy/kyverno/
```

- [ ] **Step 3: Commit**

```bash
git add helm/secureops-kyverno/ tests/policy/kyverno/ .github/workflows/ci.yml
git commit -m "feat(kyverno): admission-time ClusterPolicies as defense-in-depth"
```

---

### Task 11: Dockerfile + demo scenarios

**Files:**
- Create: `packages/server/Dockerfile`
- Create: `tests/demo/scenario_a_happy_path.sh`
- Create: `tests/demo/scenario_b_policy_denial.sh`

- [ ] **Step 1: Dockerfile**

```dockerfile
# packages/server/Dockerfile
FROM python:3.11-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir uv
COPY . .
RUN uv sync --package mcp-k8s-secure-ops --no-dev && \
    uv build --package mcp-k8s-secure-ops --wheel

FROM python:3.11-slim
RUN useradd -u 10001 -r secureops && mkdir /var/lib/secureops && chown secureops /var/lib/secureops
USER 10001
WORKDIR /app
COPY --from=build /src/packages/server/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
ENTRYPOINT ["mcp-k8s-secure-ops"]
CMD ["serve-mcp"]
```

- [ ] **Step 2: Demo scripts (documented; for workshop)**

```bash
# tests/demo/scenario_a_happy_path.sh
#!/usr/bin/env bash
set -euo pipefail
kubectl create ns demo || true
kubectl -n demo create deployment checkout --image=nginx:1.27 || true
kubectl -n demo wait --for=condition=available deploy/checkout --timeout=60s
echo "=> plan_incident_response symptom=deployment_unhealthy"
echo "=> restart_deployment ns=demo name=checkout"
echo "(run via MCP client; expect status=allowed_executed)"
```

```bash
# tests/demo/scenario_b_policy_denial.sh
#!/usr/bin/env bash
set -euo pipefail
kubectl label ns demo tier=prod --overwrite
echo "=> scale_workload ns=demo name=checkout replicas=0"
echo "(expect status=denied_opa, reasons=[prod_scale_zero_denied])"
echo "=> explain_opa_decision"
echo "=> restart_deployment ns=demo name=checkout"
echo "(safe alternative; expect status=allowed_executed)"
```

- [ ] **Step 3: Commit**

```bash
git add packages/server/Dockerfile tests/demo/
git commit -m "feat(demo): Dockerfile + workshop demo scripts"
```

---

### Task 12: Release workflow (PyPI trusted publishers + GHCR + cosign + SBOM + Helm OCI + policy OCI)

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Write workflow (observatory pattern, extended with Helm OCI + policy OCI publish)**

```yaml
# .github/workflows/release.yml
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
  id-token: write
  packages: write

jobs:
  pypi-server:
    runs-on: ubuntu-latest
    environment: pypi-server
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv python install 3.11
      - run: uv venv
      - run: uv pip install build
      - name: Build server
        run: uv run python -m build packages/server --outdir dist-server
      - name: Publish server
        uses: pypa/gh-action-pypi-publish@release/v1
        with: { packages-dir: dist-server }

  pypi-policy-sdk:
    runs-on: ubuntu-latest
    environment: pypi-policy-sdk
    permissions: { contents: read, id-token: write }
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv python install 3.11
      - run: uv venv
      - run: uv pip install build
      - name: Build policy_sdk
        run: uv run python -m build packages/policy_sdk --outdir dist-policy-sdk
      - name: Publish policy_sdk
        uses: pypa/gh-action-pypi-publish@release/v1
        with: { packages-dir: dist-policy-sdk }

  image:
    runs-on: ubuntu-latest
    permissions: { contents: write, id-token: write, packages: write }
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-qemu-action@v3
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - id: build
        uses: docker/build-push-action@v6
        with:
          context: .
          file: packages/server/Dockerfile
          platforms: linux/amd64,linux/arm64
          push: true
          tags: |
            ghcr.io/${{ github.repository_owner }}/mcp-k8s-secure-ops:${{ github.ref_name }}
            ghcr.io/${{ github.repository_owner }}/mcp-k8s-secure-ops:latest
          sbom: true
          provenance: true
      - uses: sigstore/cosign-installer@v3.5.0
        with: { cosign-release: v2.2.4 }
      - name: Sign image
        env:
          COSIGN_EXPERIMENTAL: "1"
          DIGEST: ${{ steps.build.outputs.digest }}
          OWNER: ${{ github.repository_owner }}
        run: cosign sign --yes "ghcr.io/${OWNER}/mcp-k8s-secure-ops@${DIGEST}"
      - id: sbom
        uses: anchore/sbom-action@v0
        with:
          image: "ghcr.io/${{ github.repository_owner }}/mcp-k8s-secure-ops:${{ github.ref_name }}"
          format: cyclonedx-json
          artifact-name: sbom-${{ github.ref_name }}.cdx.json
      - name: Attach SBOM
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ github.ref_name }}
          files: ${{ steps.sbom.outputs.SBOM_ARTIFACT_PATH }}

  helm:
    runs-on: ubuntu-latest
    permissions: { contents: read, packages: write, id-token: write }
    steps:
      - uses: actions/checkout@v4
      - uses: azure/setup-helm@v4
      - run: echo "${{ secrets.GITHUB_TOKEN }}" | helm registry login ghcr.io -u ${{ github.actor }} --password-stdin
      - name: Package + push charts
        run: |
          helm package helm/secureops
          helm package helm/secureops-kyverno
          helm push secureops-*.tgz oci://ghcr.io/${{ github.repository_owner }}/charts
          helm push secureops-kyverno-*.tgz oci://ghcr.io/${{ github.repository_owner }}/charts

  policy-bundle:
    runs-on: ubuntu-latest
    permissions: { contents: read, packages: write, id-token: write }
    steps:
      - uses: actions/checkout@v4
      - name: Install oras
        run: |
          curl -L https://github.com/oras-project/oras/releases/download/v1.2.0/oras_1.2.0_linux_amd64.tar.gz | tar xz
          sudo mv oras /usr/local/bin/
      - run: echo "${{ secrets.GITHUB_TOKEN }}" | oras login ghcr.io -u ${{ github.actor }} --password-stdin
      - name: Push OPA bundle
        run: |
          cd policies/opa
          oras push ghcr.io/${{ github.repository_owner }}/secureops-policies:${{ github.ref_name }} \
            ./secureops/:application/vnd.openpolicyagent.policy.layer.v1+rego
```

- [ ] **Step 2: Add release-workflow test**

Append a short pytest that parses release.yml and asserts jobs / environments:

```python
# packages/server/tests/workflows/test_release_workflow.py
from __future__ import annotations

from pathlib import Path

import yaml

WF = Path(".github/workflows/release.yml")


def test_release_has_four_pypi_image_helm_bundle_jobs():
    data = yaml.safe_load(WF.read_text())
    jobs = data["jobs"]
    for j in ("pypi-server", "pypi-policy-sdk", "image", "helm", "policy-bundle"):
        assert j in jobs, f"missing job {j}"
    assert jobs["pypi-server"]["environment"] == "pypi-server"
    assert jobs["pypi-policy-sdk"]["environment"] == "pypi-policy-sdk"


def test_image_job_signs_and_sboms():
    data = yaml.safe_load(WF.read_text())
    image_steps = data["jobs"]["image"]["steps"]
    uses = [s.get("uses", "") for s in image_steps]
    names = [s.get("name", "") for s in image_steps]
    assert any(u.startswith("sigstore/cosign-installer") for u in uses)
    assert any("Sign image" in n for n in names)
    assert any(u.startswith("anchore/sbom-action") for u in uses)
    assert any("Attach SBOM" in n for n in names)
```

Need `mkdir -p packages/server/tests/workflows && touch packages/server/tests/workflows/__init__.py`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml packages/server/tests/workflows/
git commit -m "ci: release workflow (PyPI, GHCR, cosign, SBOM, Helm OCI, policy OCI)"
```

---

### Task 13: Version bump to 1.0.0, CHANGELOG, local gates, tag v1.0.0

**Files:**
- Modify: `packages/server/pyproject.toml` — `version = "1.0.0"`
- Modify: `packages/policy_sdk/pyproject.toml` — `version = "1.0.0"`
- Modify: `packages/server/src/secureops_server/__init__.py` — `__version__ = "1.0.0"`
- Modify: `packages/policy_sdk/src/secureops_policy_sdk/__init__.py` — `__version__ = "1.0.0"`
- Modify: `helm/secureops/Chart.yaml` — `version: 1.0.0`, `appVersion: "1.0.0"`
- Modify: `helm/secureops/values.yaml` — `tag: "v1.0.0"`
- Modify: `helm/secureops-kyverno/Chart.yaml` — `version: 1.0.0`
- Create: `CHANGELOG.md`

- [ ] **Step 1: Bump versions**

Run the edits listed above.

- [ ] **Step 2: Write `CHANGELOG.md`**

```markdown
# Changelog

## v1.0.0 — 2026-04-22

**First stable release.**

### Added
- 18 MCP tools across cluster-state (5), blast-radius (4), remediation (6), audit (3).
- OPA pre-flight with fail-closed HTTP client and ConfigMap / OCI bundle loading.
- Kyverno subchart (`secureops-kyverno`) as admission-time backstop.
- `TokenRequest`-based broker minting 5-min per-action ServiceAccount tokens.
- Transitive blast-radius engine: direct → one-hop (Service, PVC, PDB, HPA) → transitive Ingress, with Prometheus traffic enrichment.
- Hash-chained aiosqlite audit ledger + OTel span export + K8s Event emission.
- Deterministic `plan_incident_response` router + LLM-narrated `explain_*` family with deterministic fallbacks.
- Multi-arch GHCR image, cosign keyless signing, CycloneDX SBOM, Helm OCI charts, OPA policy OCI bundle.

### Invariants
- LLM never holds cluster credentials and never decides writes.
- Every tool call produces an audit row; `verify_chain` proves tamper-evidence.
- Fail-closed on OPA unreachable or token-mint failure.

### Known deferrals (v1.x)
- OCI bundle runtime loading (requires `oras-py`); policies ship via ConfigMap for v1.0.
- `--llm-plan` opt-in for LLM-driven incident planning (router is deterministic in v1.0).
- Multi-cluster federation.
```

- [ ] **Step 3: Full local gate**

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy packages/server/src packages/policy_sdk/src
uv run pytest -v
opa test policies/opa -v
kyverno test tests/policy/kyverno/
```
Expected: all green.

- [ ] **Step 4: Commit, push, tag**

```bash
git add packages/server/pyproject.toml packages/policy_sdk/pyproject.toml packages/server/src/secureops_server/__init__.py packages/policy_sdk/src/secureops_policy_sdk/__init__.py helm/secureops/Chart.yaml helm/secureops/values.yaml helm/secureops-kyverno/Chart.yaml CHANGELOG.md
git commit -m "release: v1.0.0"
git push
gh run watch
git tag -a v1.0.0 -m "mcp-k8s-secure-ops v1.0.0"
git push --tags
gh run watch
```

Expected: release workflow green — PyPI has `mcp-k8s-secure-ops==1.0.0` and `mcp-secureops-policy-sdk==1.0.0`; GHCR has `mcp-k8s-secure-ops:v1.0.0` (cosign-verifiable); Helm OCI has both charts; policy OCI artifact published; SBOM attached to GitHub Release.

---

### Task 14: Post-release verification

- [ ] **Step 1: Verify PyPI**

```bash
pip index versions mcp-k8s-secure-ops
pip index versions mcp-secureops-policy-sdk
```
Both should show `1.0.0`.

- [ ] **Step 2: Verify cosign signature**

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/vellankikoti/mcp-k8s-secure-ops/\.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/vellankikoti/mcp-k8s-secure-ops:v1.0.0
```
Expected: verification success.

- [ ] **Step 3: Verify MCP contract (stdio)**

```bash
uvx mcp-k8s-secure-ops serve-mcp &
PID=$!
# send JSON-RPC tools/list over stdin; expect 18 tool names + 5 companions
kill $PID
```

- [ ] **Step 4: Update project memory to mark shipped**

Update the MEMORY.md pointer for Project 01 to "shipped v1.0.0".

---

## Self-review for this phase

- **Spec coverage:** 5 remaining writes + 3 audit tools + router + 4 explain companions + Kyverno subchart + Dockerfile + release pipeline + PyPI + GHCR + cosign + SBOM + Helm OCI + policy OCI + two demo scenarios + CHANGELOG + v1.0.0 tag. All 18 tools and the spec's success criteria are addressed.
- **Placeholder scan:** Task 9 example shows one wrapper; the remaining four write wrappers follow the same pattern but each must be written fully in `mcp_server.py` — not as a shortcut. The subagent implementing Task 9 must write all of them explicitly.
- **Type consistency:** `K8sRef`, `ActionProposal`, `ActionResult`, `OPADecision`, `AuditRow`, `BlastRadius`, `TokenBroker.mint` signatures consistent across every new wrapper. Action verbs map 1:1 to `rbac_templates._VERB_TO_RULES` keys.

Phase 5 ends at **v1.0.0**. Project 01 ships. Project 00 (`mcp-k8s-utility`) can begin.
