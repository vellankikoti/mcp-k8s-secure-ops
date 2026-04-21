# mcp-k8s-secure-ops — Phase 3: Blast-Radius Engine + 4 Tools

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the transitive dependency graph (direct → one-hop Services/PVCs/PDBs/HPAs → transitive dependents) and the Prometheus traffic enricher. Ship 4 blast-radius tools: `compute_blast_radius`, `check_pdb_impact`, `get_traffic_snapshot`, `find_dependents`. Green CI + tag `v0.3.0`.

**Architecture:** `blast_radius/graph.py` computes the K8s-only portion (no Prometheus). `blast_radius/traffic.py` enriches with PromQL. Tool functions compose them and return pydantic `BlastRadius` instances built in Phase 1.

**Tech Stack:** kubernetes_asyncio, httpx (for Prometheus HTTP API), pydantic v2.

---

## File structure added this phase

```
packages/server/src/secureops_server/
├── prom_client.py
├── blast_radius/
│   ├── __init__.py
│   ├── graph.py
│   └── traffic.py
└── tools/
    └── blast_radius/
        ├── __init__.py
        ├── compute_blast_radius.py
        ├── check_pdb_impact.py
        ├── get_traffic_snapshot.py
        └── find_dependents.py

packages/server/tests/
├── test_blast_graph.py
├── test_blast_traffic.py
└── tools/blast_radius/
    ├── test_compute_blast_radius.py
    ├── test_check_pdb_impact.py
    ├── test_get_traffic_snapshot.py
    └── test_find_dependents.py
```

---

### Task 1: Graph — selector-to-services resolver

**Files:**
- Create: `packages/server/src/secureops_server/blast_radius/__init__.py`
- Create: `packages/server/src/secureops_server/blast_radius/graph.py`
- Create: `packages/server/tests/test_blast_graph.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/test_blast_graph.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.blast_radius.graph import (
    services_selecting,
    pvcs_mounted_by_deployment,
    pdbs_matching,
    hpas_for_deployment,
)
from secureops_server.models import K8sRef


def _svc(name: str, selector: dict[str, str]):
    s = MagicMock()
    s.metadata.name = name
    s.metadata.namespace = "prod"
    s.metadata.uid = f"u-{name}"
    s.spec.selector = selector
    return s


@pytest.mark.asyncio
async def test_services_selecting_matches_label_subset():
    core = MagicMock()
    core.list_namespaced_service = AsyncMock(
        return_value=MagicMock(items=[
            _svc("checkout-svc", {"app": "checkout"}),
            _svc("other-svc", {"app": "other"}),
        ])
    )
    k8s = MagicMock(core_v1=core)
    labels = {"app": "checkout", "version": "v1"}
    refs = await services_selecting(k8s, namespace="prod", pod_labels=labels)
    assert len(refs) == 1
    assert refs[0].name == "checkout-svc"


def _dep_with_pvcs(pvc_claims: list[str]):
    d = MagicMock()
    d.metadata.name = "checkout"
    d.metadata.namespace = "prod"
    d.spec.template.spec.volumes = [
        MagicMock(persistent_volume_claim=MagicMock(claim_name=c)) for c in pvc_claims
    ]
    for v in d.spec.template.spec.volumes:
        v.persistent_volume_claim.claim_name = v.persistent_volume_claim.claim_name
    return d


@pytest.mark.asyncio
async def test_pvcs_mounted_by_deployment_extracts_claim_names():
    d = _dep_with_pvcs(["data", "cache"])
    refs = await pvcs_mounted_by_deployment(d)
    names = {r.name for r in refs}
    assert names == {"data", "cache"}


def _pdb(name: str, selector: dict[str, str]):
    p = MagicMock()
    p.metadata.name = name
    p.metadata.namespace = "prod"
    p.metadata.uid = f"u-{name}"
    p.spec.selector.match_labels = selector
    return p


@pytest.mark.asyncio
async def test_pdbs_matching_finds_by_selector_subset():
    policy = MagicMock()
    policy.list_namespaced_pod_disruption_budget = AsyncMock(
        return_value=MagicMock(items=[_pdb("pdb-a", {"app": "checkout"}), _pdb("pdb-b", {"app": "x"})])
    )
    k8s = MagicMock(policy_v1=policy)
    refs = await pdbs_matching(k8s, namespace="prod", pod_labels={"app": "checkout", "version": "v1"})
    assert len(refs) == 1
    assert refs[0].name == "pdb-a"


def _hpa(name: str, target_name: str):
    h = MagicMock()
    h.metadata.name = name
    h.metadata.namespace = "prod"
    h.metadata.uid = f"u-{name}"
    h.spec.scale_target_ref.kind = "Deployment"
    h.spec.scale_target_ref.name = target_name
    return h


@pytest.mark.asyncio
async def test_hpas_for_deployment_matches_target_ref():
    autoscaling = MagicMock()
    autoscaling.list_namespaced_horizontal_pod_autoscaler = AsyncMock(
        return_value=MagicMock(items=[_hpa("h1", "checkout"), _hpa("h2", "other")])
    )
    k8s = MagicMock(autoscaling_v2=autoscaling)
    refs = await hpas_for_deployment(k8s, namespace="prod", deployment_name="checkout")
    assert len(refs) == 1
    assert refs[0].name == "h1"
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/test_blast_graph.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `graph.py`**

```python
# packages/server/src/secureops_server/blast_radius/__init__.py
"""blast-radius computation (K8s graph + Prometheus traffic)."""
```

```python
# packages/server/src/secureops_server/blast_radius/graph.py
from __future__ import annotations

from typing import Any

from secureops_server.models import K8sRef


def _selector_matches(svc_or_pdb_selector: dict[str, str], pod_labels: dict[str, str]) -> bool:
    if not svc_or_pdb_selector:
        return False
    for k, v in svc_or_pdb_selector.items():
        if pod_labels.get(k) != v:
            return False
    return True


async def services_selecting(
    k8s: Any, namespace: str, pod_labels: dict[str, str]
) -> list[K8sRef]:
    svcs = await k8s.core_v1.list_namespaced_service(namespace=namespace)
    out: list[K8sRef] = []
    for s in svcs.items:
        sel = getattr(s.spec, "selector", None) or {}
        if _selector_matches(sel, pod_labels):
            out.append(
                K8sRef(kind="Service", api_version="v1", namespace=s.metadata.namespace,
                       name=s.metadata.name, uid=s.metadata.uid)
            )
    return out


async def pvcs_mounted_by_deployment(deployment: Any) -> list[K8sRef]:
    volumes = getattr(deployment.spec.template.spec, "volumes", None) or []
    out: list[K8sRef] = []
    for v in volumes:
        pvc = getattr(v, "persistent_volume_claim", None)
        if pvc is None:
            continue
        name = getattr(pvc, "claim_name", None)
        if name:
            out.append(
                K8sRef(kind="PersistentVolumeClaim", api_version="v1",
                       namespace=deployment.metadata.namespace, name=name)
            )
    return out


async def pdbs_matching(
    k8s: Any, namespace: str, pod_labels: dict[str, str]
) -> list[K8sRef]:
    pdbs = await k8s.policy_v1.list_namespaced_pod_disruption_budget(namespace=namespace)
    out: list[K8sRef] = []
    for p in pdbs.items:
        sel = getattr(p.spec.selector, "match_labels", None) or {}
        if _selector_matches(sel, pod_labels):
            out.append(
                K8sRef(kind="PodDisruptionBudget", api_version="policy/v1",
                       namespace=p.metadata.namespace, name=p.metadata.name, uid=p.metadata.uid)
            )
    return out


async def hpas_for_deployment(
    k8s: Any, namespace: str, deployment_name: str
) -> list[K8sRef]:
    hpas = await k8s.autoscaling_v2.list_namespaced_horizontal_pod_autoscaler(namespace=namespace)
    out: list[K8sRef] = []
    for h in hpas.items:
        ref = getattr(h.spec.scale_target_ref, "name", None)
        kind = getattr(h.spec.scale_target_ref, "kind", None)
        if kind == "Deployment" and ref == deployment_name:
            out.append(
                K8sRef(kind="HorizontalPodAutoscaler", api_version="autoscaling/v2",
                       namespace=h.metadata.namespace, name=h.metadata.name, uid=h.metadata.uid)
            )
    return out
```

Add to `K8sClients` in `k8s_client.py`:

```python
# packages/server/src/secureops_server/k8s_client.py — replace K8sClients
@dataclass
class K8sClients:
    core_v1: Any
    apps_v1: Any
    policy_v1: Any
    autoscaling_v2: Any
    api_client: Any


async def build_clients(kubeconfig: str | None = None) -> K8sClients:
    if kubeconfig:
        await k8s_config.load_kube_config(config_file=kubeconfig)
    else:
        try:
            await k8s_config.load_kube_config()
        except Exception:
            k8s_config.load_incluster_config()
    api = k8s_client.ApiClient()
    return K8sClients(
        core_v1=k8s_client.CoreV1Api(api),
        apps_v1=k8s_client.AppsV1Api(api),
        policy_v1=k8s_client.PolicyV1Api(api),
        autoscaling_v2=k8s_client.AutoscalingV2Api(api),
        api_client=api,
    )
```

- [ ] **Step 4: Pass**

Run: `uv run pytest packages/server/tests/test_blast_graph.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/secureops_server/blast_radius/ packages/server/src/secureops_server/k8s_client.py packages/server/tests/test_blast_graph.py
git commit -m "feat(blast): graph resolvers (svc, pvc, pdb, hpa)"
```

---

### Task 2: Prometheus traffic enricher

**Files:**
- Create: `packages/server/src/secureops_server/prom_client.py`
- Create: `packages/server/src/secureops_server/blast_radius/traffic.py`
- Create: `packages/server/tests/test_blast_traffic.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/test_blast_traffic.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.blast_radius.traffic import snapshot_for_service
from secureops_server.models import K8sRef


@pytest.mark.asyncio
async def test_snapshot_returns_prometheus_values_when_reachable():
    prom = MagicMock()
    prom.query = AsyncMock(side_effect=[
        [{"value": [0, "12.5"]}],   # rps
        [{"value": [0, "0.01"]}],   # error rate
        [{"value": [0, "250"]}],    # p99 ms
    ])
    svc = K8sRef(kind="Service", api_version="v1", namespace="prod", name="checkout-svc")
    snap = await snapshot_for_service(prom, svc)
    assert snap.rps == 12.5
    assert snap.error_rate == 0.01
    assert snap.p99_latency_ms == 250.0
    assert snap.source == "prometheus"


@pytest.mark.asyncio
async def test_snapshot_returns_unavailable_on_error():
    prom = MagicMock()
    prom.query = AsyncMock(side_effect=RuntimeError("prom down"))
    svc = K8sRef(kind="Service", api_version="v1", namespace="prod", name="x")
    snap = await snapshot_for_service(prom, svc)
    assert snap.source == "unavailable"
    assert snap.rps == 0.0
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/test_blast_traffic.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement prom client + traffic**

```python
# packages/server/src/secureops_server/prom_client.py
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
```

```python
# packages/server/src/secureops_server/blast_radius/traffic.py
from __future__ import annotations

from typing import Any

from secureops_server.models import K8sRef, TrafficSnapshot


def _service_rps_query(svc: K8sRef) -> str:
    return (
        f'sum(rate(istio_requests_total{{destination_service_namespace="{svc.namespace}",'
        f'destination_service_name="{svc.name}"}}[5m]))'
    )


def _service_errors_query(svc: K8sRef) -> str:
    return (
        f'sum(rate(istio_requests_total{{destination_service_namespace="{svc.namespace}",'
        f'destination_service_name="{svc.name}",response_code=~"5.."}}[5m]))'
        f' / clamp_min(sum(rate(istio_requests_total{{destination_service_namespace="{svc.namespace}",'
        f'destination_service_name="{svc.name}"}}[5m])), 1)'
    )


def _service_p99_query(svc: K8sRef) -> str:
    return (
        f'histogram_quantile(0.99, sum by (le) (rate('
        f'istio_request_duration_milliseconds_bucket{{destination_service_namespace="{svc.namespace}",'
        f'destination_service_name="{svc.name}"}}[5m])))'
    )


def _first_value(result: list[dict[str, Any]], default: float = 0.0) -> float:
    if not result:
        return default
    val = result[0].get("value")
    if not val or len(val) < 2:
        return default
    try:
        return float(val[1])
    except (TypeError, ValueError):
        return default


async def snapshot_for_service(prom: Any, svc: K8sRef) -> TrafficSnapshot:
    try:
        rps_r = await prom.query(_service_rps_query(svc))
        err_r = await prom.query(_service_errors_query(svc))
        p99_r = await prom.query(_service_p99_query(svc))
        return TrafficSnapshot(
            rps=_first_value(rps_r),
            error_rate=_first_value(err_r),
            p99_latency_ms=_first_value(p99_r),
            source="prometheus",
        )
    except Exception:
        return TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable")
```

- [ ] **Step 4: Pass**

Run: `uv run pytest packages/server/tests/test_blast_traffic.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/secureops_server/prom_client.py packages/server/src/secureops_server/blast_radius/traffic.py packages/server/tests/test_blast_traffic.py
git commit -m "feat(blast): Prometheus-backed TrafficSnapshot with fail-safe"
```

---

### Task 3: Tool — `compute_blast_radius`

**Files:**
- Create: `packages/server/src/secureops_server/tools/blast_radius/__init__.py`
- Create: `packages/server/src/secureops_server/tools/blast_radius/compute_blast_radius.py`
- Create: `packages/server/tests/tools/blast_radius/__init__.py`
- Create: `packages/server/tests/tools/blast_radius/test_compute_blast_radius.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/tools/blast_radius/test_compute_blast_radius.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.context import Capability, SecureOpsContext
from secureops_server.models import K8sRef, TrafficSnapshot
from secureops_server.tools.blast_radius.compute_blast_radius import compute_blast_radius


def _dep():
    d = MagicMock()
    d.metadata.name = "checkout"
    d.metadata.namespace = "prod"
    d.metadata.uid = "u-dep"
    d.spec.replicas = 3
    d.spec.selector.match_labels = {"app": "checkout"}
    d.spec.template.metadata.labels = {"app": "checkout", "version": "v1"}
    d.spec.template.spec.volumes = []
    return d


@pytest.mark.asyncio
async def test_compute_blast_radius_includes_services_and_pdbs_and_traffic():
    k8s = MagicMock()
    k8s.apps_v1 = MagicMock()
    k8s.apps_v1.read_namespaced_deployment = AsyncMock(return_value=_dep())

    svc = MagicMock()
    svc.metadata.name = "checkout-svc"
    svc.metadata.namespace = "prod"
    svc.metadata.uid = "u-svc"
    svc.spec.selector = {"app": "checkout"}
    k8s.core_v1 = MagicMock()
    k8s.core_v1.list_namespaced_service = AsyncMock(return_value=MagicMock(items=[svc]))

    pdb = MagicMock()
    pdb.metadata.name = "checkout-pdb"
    pdb.metadata.namespace = "prod"
    pdb.metadata.uid = "u-pdb"
    pdb.spec.selector.match_labels = {"app": "checkout"}
    k8s.policy_v1 = MagicMock()
    k8s.policy_v1.list_namespaced_pod_disruption_budget = AsyncMock(return_value=MagicMock(items=[pdb]))

    k8s.autoscaling_v2 = MagicMock()
    k8s.autoscaling_v2.list_namespaced_horizontal_pod_autoscaler = AsyncMock(
        return_value=MagicMock(items=[])
    )

    prom = MagicMock()
    prom.query = AsyncMock(side_effect=RuntimeError("prom down"))  # unavailable path

    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=prom, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.PROM}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    br = await compute_blast_radius(guarded, target)
    assert any(r.name == "checkout-svc" for r in br.one_hop)
    assert any(r.kind == "PodDisruptionBudget" for r in br.one_hop)
    assert br.traffic.source == "unavailable"
    assert br.data_loss_risk == "none"  # no PVC in this test
    assert br.direct[0].name == "checkout"
    assert isinstance(br.traffic, TrafficSnapshot)
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/tools/blast_radius/test_compute_blast_radius.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/blast_radius/__init__.py
"""blast-radius tools."""
```

```python
# packages/server/src/secureops_server/tools/blast_radius/compute_blast_radius.py
from __future__ import annotations

from secureops_server.blast_radius.graph import (
    hpas_for_deployment,
    pdbs_matching,
    pvcs_mounted_by_deployment,
    services_selecting,
)
from secureops_server.blast_radius.traffic import snapshot_for_service
from secureops_server.context import GuardedContext
from secureops_server.models import BlastRadius, K8sRef, TrafficSnapshot


async def compute_blast_radius(ctx: GuardedContext, target: K8sRef) -> BlastRadius:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("compute_blast_radius supports Deployment targets with a namespace")
    dep = await ctx.k8s.apps_v1.read_namespaced_deployment(
        name=target.name, namespace=target.namespace
    )
    pod_labels = dict(dep.spec.template.metadata.labels or {})
    direct = [
        K8sRef(
            kind="Deployment", api_version="apps/v1",
            namespace=dep.metadata.namespace, name=dep.metadata.name, uid=dep.metadata.uid,
        )
    ]
    svcs = await services_selecting(ctx.k8s, target.namespace, pod_labels)
    pdbs = await pdbs_matching(ctx.k8s, target.namespace, pod_labels)
    hpas = await hpas_for_deployment(ctx.k8s, target.namespace, target.name)
    pvcs = await pvcs_mounted_by_deployment(dep)
    one_hop = [*svcs, *pdbs, *hpas, *pvcs]

    if svcs:
        traffic = await snapshot_for_service(ctx.prom, svcs[0])
    else:
        traffic = TrafficSnapshot(
            rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable"
        )

    data_loss_risk = "none" if not pvcs else "pvc_unmounted"

    return BlastRadius(
        direct=direct,
        one_hop=one_hop,
        transitive=[],  # transitive graph deferred to find_dependents tool
        traffic=traffic,
        pdb_violations=[],  # violations computed only when proposing an action that would reduce replicas
        data_loss_risk=data_loss_risk,
    )
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/blast_radius/test_compute_blast_radius.py -v
git add packages/server/src/secureops_server/tools/blast_radius/__init__.py packages/server/src/secureops_server/tools/blast_radius/compute_blast_radius.py packages/server/tests/tools/blast_radius/__init__.py packages/server/tests/tools/blast_radius/test_compute_blast_radius.py
git commit -m "feat(tools): compute_blast_radius"
```

---

### Task 4: Tool — `check_pdb_impact`

**Files:**
- Create: `packages/server/src/secureops_server/tools/blast_radius/check_pdb_impact.py`
- Create: `packages/server/tests/tools/blast_radius/test_check_pdb_impact.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/tools/blast_radius/test_check_pdb_impact.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.context import Capability, SecureOpsContext
from secureops_server.models import K8sRef
from secureops_server.tools.blast_radius.check_pdb_impact import check_pdb_impact


def _pdb(name: str, min_available: int, current_healthy: int):
    p = MagicMock()
    p.metadata.name = name
    p.metadata.namespace = "prod"
    p.metadata.uid = f"u-{name}"
    p.spec.min_available = min_available
    p.spec.selector.match_labels = {"app": "checkout"}
    p.status.current_healthy = current_healthy
    return p


@pytest.mark.asyncio
async def test_check_pdb_impact_flags_violation_when_draining_would_fall_below_min():
    dep = MagicMock()
    dep.spec.template.metadata.labels = {"app": "checkout"}
    dep.spec.replicas = 3
    k8s = MagicMock()
    k8s.apps_v1 = MagicMock()
    k8s.apps_v1.read_namespaced_deployment = AsyncMock(return_value=dep)
    k8s.policy_v1 = MagicMock()
    k8s.policy_v1.list_namespaced_pod_disruption_budget = AsyncMock(
        return_value=MagicMock(items=[_pdb("pdb-a", min_available=2, current_healthy=3)])
    )
    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    violations = await check_pdb_impact(guarded, target, target_available=1)
    assert len(violations) == 1
    assert violations[0].pdb.name == "pdb-a"
    assert violations[0].min_available == 2
    assert violations[0].current_available == 1
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/tools/blast_radius/test_check_pdb_impact.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/blast_radius/check_pdb_impact.py
from __future__ import annotations

from secureops_server.blast_radius.graph import pdbs_matching
from secureops_server.context import GuardedContext
from secureops_server.models import K8sRef, PDBViolation


async def check_pdb_impact(
    ctx: GuardedContext, target: K8sRef, target_available: int
) -> list[PDBViolation]:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("check_pdb_impact supports Deployment targets with a namespace")
    dep = await ctx.k8s.apps_v1.read_namespaced_deployment(
        name=target.name, namespace=target.namespace
    )
    pod_labels = dict(dep.spec.template.metadata.labels or {})
    pdb_refs = await pdbs_matching(ctx.k8s, target.namespace, pod_labels)
    if not pdb_refs:
        return []

    all_pdbs = await ctx.k8s.policy_v1.list_namespaced_pod_disruption_budget(
        namespace=target.namespace
    )
    name_to_pdb = {p.metadata.name: p for p in all_pdbs.items}

    violations: list[PDBViolation] = []
    for ref in pdb_refs:
        pdb = name_to_pdb.get(ref.name)
        if pdb is None:
            continue
        min_available = getattr(pdb.spec, "min_available", None)
        if isinstance(min_available, int) and target_available < min_available:
            violations.append(
                PDBViolation(pdb=ref, current_available=target_available, min_available=min_available)
            )
    return violations
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/blast_radius/test_check_pdb_impact.py -v
git add packages/server/src/secureops_server/tools/blast_radius/check_pdb_impact.py packages/server/tests/tools/blast_radius/test_check_pdb_impact.py
git commit -m "feat(tools): check_pdb_impact"
```

---

### Task 5: Tool — `get_traffic_snapshot`

**Files:**
- Create: `packages/server/src/secureops_server/tools/blast_radius/get_traffic_snapshot.py`
- Create: `packages/server/tests/tools/blast_radius/test_get_traffic_snapshot.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/tools/blast_radius/test_get_traffic_snapshot.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.context import Capability, SecureOpsContext
from secureops_server.models import K8sRef
from secureops_server.tools.blast_radius.get_traffic_snapshot import get_traffic_snapshot


@pytest.mark.asyncio
async def test_get_traffic_snapshot_for_service_reference():
    prom = MagicMock()
    prom.query = AsyncMock(side_effect=[
        [{"value": [0, "5.0"]}],
        [{"value": [0, "0.0"]}],
        [{"value": [0, "100"]}],
    ])
    ctx = SecureOpsContext(k8s=None, opa=None, prom=prom, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.PROM}))
    svc = K8sRef(kind="Service", api_version="v1", namespace="prod", name="checkout-svc")
    snap = await get_traffic_snapshot(guarded, svc)
    assert snap.rps == 5.0
    assert snap.source == "prometheus"


@pytest.mark.asyncio
async def test_get_traffic_snapshot_rejects_non_service():
    ctx = SecureOpsContext(k8s=None, opa=None, prom=MagicMock(), sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.PROM}))
    with pytest.raises(ValueError, match="Service"):
        await get_traffic_snapshot(guarded, K8sRef(kind="Deployment", api_version="apps/v1", name="x"))
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/tools/blast_radius/test_get_traffic_snapshot.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/blast_radius/get_traffic_snapshot.py
from __future__ import annotations

from secureops_server.blast_radius.traffic import snapshot_for_service
from secureops_server.context import GuardedContext
from secureops_server.models import K8sRef, TrafficSnapshot


async def get_traffic_snapshot(ctx: GuardedContext, svc: K8sRef) -> TrafficSnapshot:
    if svc.kind != "Service":
        raise ValueError("get_traffic_snapshot requires a Service reference")
    return await snapshot_for_service(ctx.prom, svc)
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/blast_radius/test_get_traffic_snapshot.py -v
git add packages/server/src/secureops_server/tools/blast_radius/get_traffic_snapshot.py packages/server/tests/tools/blast_radius/test_get_traffic_snapshot.py
git commit -m "feat(tools): get_traffic_snapshot"
```

---

### Task 6: Tool — `find_dependents` (transitive dependency walk)

**Files:**
- Create: `packages/server/src/secureops_server/tools/blast_radius/find_dependents.py`
- Create: `packages/server/tests/tools/blast_radius/test_find_dependents.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/tools/blast_radius/test_find_dependents.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.context import Capability, SecureOpsContext
from secureops_server.models import K8sRef
from secureops_server.tools.blast_radius.find_dependents import find_dependents


@pytest.mark.asyncio
async def test_find_dependents_walks_ingress_pointing_at_service():
    # Deployment -> Service(checkout-svc) selected via labels (tested in graph);
    # here we go one more hop: Ingress backend referring to checkout-svc.
    dep = MagicMock()
    dep.spec.template.metadata.labels = {"app": "checkout"}

    svc = MagicMock()
    svc.metadata.name = "checkout-svc"
    svc.metadata.namespace = "prod"
    svc.metadata.uid = "u-svc"
    svc.spec.selector = {"app": "checkout"}

    ing = MagicMock()
    ing.metadata.name = "checkout-ing"
    ing.metadata.namespace = "prod"
    ing.metadata.uid = "u-ing"
    ing.spec.rules = [
        MagicMock(http=MagicMock(paths=[
            MagicMock(backend=MagicMock(service=MagicMock(name="checkout-svc")))
        ]))
    ]

    k8s = MagicMock()
    k8s.apps_v1 = MagicMock()
    k8s.apps_v1.read_namespaced_deployment = AsyncMock(return_value=dep)
    k8s.core_v1 = MagicMock()
    k8s.core_v1.list_namespaced_service = AsyncMock(return_value=MagicMock(items=[svc]))
    k8s.networking_v1 = MagicMock()
    k8s.networking_v1.list_namespaced_ingress = AsyncMock(return_value=MagicMock(items=[ing]))

    ctx = SecureOpsContext(k8s=k8s, opa=None, prom=None, sqlite=None, llm=None)
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    deps = await find_dependents(guarded, target)
    kinds = {d.kind for d in deps}
    assert "Ingress" in kinds
    assert any(d.name == "checkout-ing" for d in deps)
```

Add networking client to `K8sClients`:

```python
# packages/server/src/secureops_server/k8s_client.py — extend K8sClients
# add field: networking_v1: Any
# add construction: networking_v1=k8s_client.NetworkingV1Api(api),
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/tools/blast_radius/test_find_dependents.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/blast_radius/find_dependents.py
from __future__ import annotations

from secureops_server.blast_radius.graph import services_selecting
from secureops_server.context import GuardedContext
from secureops_server.models import K8sRef


async def find_dependents(ctx: GuardedContext, target: K8sRef) -> list[K8sRef]:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("find_dependents supports Deployment targets with a namespace")
    dep = await ctx.k8s.apps_v1.read_namespaced_deployment(
        name=target.name, namespace=target.namespace
    )
    pod_labels = dict(dep.spec.template.metadata.labels or {})
    svcs = await services_selecting(ctx.k8s, target.namespace, pod_labels)
    svc_names = {s.name for s in svcs}

    out: list[K8sRef] = []
    ingresses = await ctx.k8s.networking_v1.list_namespaced_ingress(namespace=target.namespace)
    for ing in ingresses.items:
        for rule in (ing.spec.rules or []):
            http = getattr(rule, "http", None)
            if http is None:
                continue
            for path in (http.paths or []):
                backend_svc = getattr(path.backend.service, "name", None)
                if backend_svc in svc_names:
                    out.append(
                        K8sRef(
                            kind="Ingress", api_version="networking.k8s.io/v1",
                            namespace=ing.metadata.namespace, name=ing.metadata.name, uid=ing.metadata.uid,
                        )
                    )
                    break
    return out
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/blast_radius/test_find_dependents.py -v
git add packages/server/src/secureops_server/tools/blast_radius/find_dependents.py packages/server/tests/tools/blast_radius/test_find_dependents.py packages/server/src/secureops_server/k8s_client.py
git commit -m "feat(tools): find_dependents (Ingress one hop beyond Service)"
```

---

### Task 7: Wire 4 blast-radius tools in MCP

**Files:**
- Modify: `packages/server/src/secureops_server/mcp_server.py`
- Modify: `packages/server/tests/test_mcp_server_registration.py`

- [ ] **Step 1: Extend registration test**

Add to the `required` set in `test_cluster_state_tools_registered`:

```python
required = {
    "list_workloads", "describe_workload", "get_recent_events", "get_pod_logs",
    "find_unhealthy_workloads",
    "compute_blast_radius", "check_pdb_impact", "get_traffic_snapshot", "find_dependents",
}
```

- [ ] **Step 2: Add tool wrappers in `mcp_server.py`**

```python
# append to packages/server/src/secureops_server/mcp_server.py
from secureops_server.tools.blast_radius.check_pdb_impact import check_pdb_impact
from secureops_server.tools.blast_radius.compute_blast_radius import compute_blast_radius
from secureops_server.tools.blast_radius.find_dependents import find_dependents
from secureops_server.tools.blast_radius.get_traffic_snapshot import get_traffic_snapshot


@mcp.tool()
async def compute_blast_radius_tool(kind: str, namespace: str, name: str) -> dict:
    """Compute blast radius for a target Deployment."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.PROM}))
    target = K8sRef(kind=kind, api_version="apps/v1", namespace=namespace, name=name)
    br = await compute_blast_radius(guarded, target)
    return br.model_dump()


@mcp.tool()
async def check_pdb_impact_tool(
    kind: str, namespace: str, name: str, target_available: int
) -> list[dict]:
    """Check whether a target-available count would violate any PDB."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    target = K8sRef(kind=kind, api_version="apps/v1", namespace=namespace, name=name)
    violations = await check_pdb_impact(guarded, target, target_available=target_available)
    return [v.model_dump() for v in violations]


@mcp.tool()
async def get_traffic_snapshot_tool(namespace: str, name: str) -> dict:
    """Return a Prometheus-derived traffic snapshot for a Service."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.PROM}))
    svc = K8sRef(kind="Service", api_version="v1", namespace=namespace, name=name)
    return (await get_traffic_snapshot(guarded, svc)).model_dump()


@mcp.tool()
async def find_dependents_tool(kind: str, namespace: str, name: str) -> list[dict]:
    """Return transitive dependents (Ingresses beyond selecting Services) of a Deployment."""
    ctx = await get_context()
    guarded = ctx.guard(needs=frozenset({Capability.K8S}))
    target = K8sRef(kind=kind, api_version="apps/v1", namespace=namespace, name=name)
    deps = await find_dependents(guarded, target)
    return [d.model_dump() for d in deps]
```

Rename-suffix loop remains unchanged.

Also wire the PromClient into `runtime.get_context`:

```python
# packages/server/src/secureops_server/runtime.py — replace get_context
async def get_context() -> SecureOpsContext:
    global _ctx
    if _ctx is None:
        kubeconfig = os.environ.get("KUBECONFIG")
        prom_url = os.environ.get("SECUREOPS_PROM_URL")
        k8s = await build_clients(kubeconfig=kubeconfig)
        prom = PromClient(prom_url) if prom_url else None
        _ctx = SecureOpsContext(k8s=k8s, opa=None, prom=prom, sqlite=None, llm=None)
    return _ctx
```

Add import: `from secureops_server.prom_client import PromClient`.

- [ ] **Step 3: Run all tests, commit**

```bash
uv run pytest -v
git add packages/server/src/secureops_server/mcp_server.py packages/server/src/secureops_server/runtime.py packages/server/tests/test_mcp_server_registration.py
git commit -m "feat(mcp): register 4 blast-radius tools; wire PromClient"
```

---

### Task 8: Local gate, push, tag v0.3.0

- [ ] **Step 1: Local gate**

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy packages/server/src packages/policy_sdk/src
uv run pytest -v
```
Expected: green.

- [ ] **Step 2: Push + tag**

```bash
git push
gh run watch
git tag -a v0.3.0 -m "phase 3: blast-radius engine + 4 tools"
git push --tags
```

---

## Self-review for this phase

- **Spec coverage:** 4/4 blast-radius tools done. Transitive walk is Service → Ingress for v1.0.0 (one extra hop beyond direct Services). Deeper transitive graphs (NetworkPolicies, ServiceMonitors) deferred to v1.x.
- **Placeholder scan:** none.
- **Type consistency:** `BlastRadius`, `TrafficSnapshot`, `PDBViolation`, `K8sRef` reused across tools and tests.

Phase 3 ends at tag v0.3.0. Phase 4 begins.
