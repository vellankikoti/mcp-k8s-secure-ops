# mcp-k8s-secure-ops — Phase 4: Policy Stack + Exemplar Write

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the full OPA pre-flight integration (HTTP sidecar client + ConfigMap / OCI bundle loader), the `TokenRequest` broker with per-action ServiceAccount RBAC templates, the audit-writer side-effect wrapper (audit row on every tool call), the default rego policy bundle, and **one** exemplar write tool (`restart_deployment`) end-to-end through the full flow. Kyverno wiring is stubbed (admission trust is deferred to phase 5). Demo scenario A (happy-path restart) runs in kind. Tag `v0.4.0`.

**Architecture:** OPA runs as a sidecar at `localhost:8181` in-cluster; tests hit a mocked OPA. Bundle loader mounts ConfigMap-as-file or polls OCI artifact. Broker mints 5-min tokens bound to per-action SAs whose RBAC is generated from a declarative template. The audit wrapper makes every tool call — read or write — produce an `AuditRow`.

**Tech Stack:** httpx (OPA + OCI), kubernetes_asyncio `AuthenticationV1Api.create_namespaced_token`, aiosqlite, opa test.

---

## File structure added this phase

```
packages/server/src/secureops_server/
├── policy/
│   ├── __init__.py
│   ├── opa_client.py
│   └── opa_bundles.py
├── tokens/
│   ├── __init__.py
│   ├── broker.py
│   └── rbac_templates.py
├── audit/
│   └── wrapper.py
└── tools/
    └── remediation/
        ├── __init__.py
        └── restart_deployment.py

policies/opa/secureops/
├── allow.rego
├── blast_radius.rego
└── denial_reasons.rego
policies/opa/secureops_test.rego

packages/server/tests/
├── test_opa_client.py
├── test_opa_bundles.py
├── test_token_broker.py
├── test_rbac_templates.py
├── test_audit_wrapper.py
└── tools/remediation/
    └── test_restart_deployment.py

policies/opa/test-cmd.sh
```

---

### Task 1: OPA HTTP client

**Files:**
- Create: `packages/server/src/secureops_server/policy/__init__.py`
- Create: `packages/server/src/secureops_server/policy/opa_client.py`
- Create: `packages/server/tests/test_opa_client.py`

- [ ] **Step 1: Failing test (using pytest-httpx)**

```python
# packages/server/tests/test_opa_client.py
from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from secureops_server.policy.opa_client import OPAClient


@pytest.mark.asyncio
async def test_opa_allow_true(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://localhost:8181/v1/data/secureops/allow",
        method="POST",
        json={"result": {"allow": True, "reasons": [], "matched": ["secureops.allow.default"]}},
    )
    c = OPAClient("http://localhost:8181")
    d = await c.evaluate_allow(input_doc={"tool": "restart_deployment"})
    assert d.allow is True
    assert d.matched_policies == ["secureops.allow.default"]


@pytest.mark.asyncio
async def test_opa_allow_false_with_reasons(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://localhost:8181/v1/data/secureops/allow",
        method="POST",
        json={"result": {"allow": False, "reasons": ["prod_scale_zero"], "matched": ["secureops.allow.prod_scale_zero"]}},
    )
    c = OPAClient("http://localhost:8181")
    d = await c.evaluate_allow(input_doc={"tool": "scale_workload", "parameters": {"replicas": 0}})
    assert d.allow is False
    assert "prod_scale_zero" in d.reasons


@pytest.mark.asyncio
async def test_opa_unavailable_raises_specific_error():
    c = OPAClient("http://127.0.0.1:1")  # guaranteed unreachable
    with pytest.raises(RuntimeError, match="opa_unavailable"):
        await c.evaluate_allow(input_doc={})
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/test_opa_client.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/policy/__init__.py
"""OPA client + policy bundle loader."""
```

```python
# packages/server/src/secureops_server/policy/opa_client.py
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
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/test_opa_client.py -v
git add packages/server/src/secureops_server/policy/__init__.py packages/server/src/secureops_server/policy/opa_client.py packages/server/tests/test_opa_client.py
git commit -m "feat(policy): OPAClient with fail-closed evaluate_allow"
```

---

### Task 2: Default rego bundle + `opa test`

**Files:**
- Create: `policies/opa/secureops/allow.rego`
- Create: `policies/opa/secureops/blast_radius.rego`
- Create: `policies/opa/secureops/denial_reasons.rego`
- Create: `policies/opa/secureops_test.rego`
- Create: `policies/opa/test-cmd.sh`

- [ ] **Step 1: Write rego**

```rego
# policies/opa/secureops/allow.rego
package secureops

default allow := {"allow": false, "reasons": ["no_matching_rule"], "matched": []}

# Reads always allowed — reads are enforced by RBAC, not OPA.
allow := {"allow": true, "reasons": [], "matched": ["secureops.allow.read"]} if {
    input.tool_category == "read"
}

# Block scale to 0 on prod-labelled namespace.
allow := {"allow": false, "reasons": ["prod_scale_zero_denied"], "matched": ["secureops.allow.prod_scale_zero"]} if {
    input.tool == "scale_workload"
    input.target.namespace_labels["tier"] == "prod"
    input.parameters.replicas == 0
}

# Block any write that would violate a PDB.
allow := {"allow": false, "reasons": ["pdb_violation"], "matched": ["secureops.allow.pdb"]} if {
    input.tool_category == "write"
    count(input.blast_radius.pdb_violations) > 0
}

# Block writes on prod namespaces when current p99 latency is elevated (> 1s) —
# implies active incident, require SRE ack.
allow := {"allow": false, "reasons": ["p99_elevated_require_sre_ack"], "matched": ["secureops.allow.p99_elevated"]} if {
    input.tool_category == "write"
    input.target.namespace_labels["tier"] == "prod"
    input.blast_radius.traffic.p99_latency_ms > 1000
    not input.actor.sre_ack
}

# Default allow for writes not caught above.
allow := {"allow": true, "reasons": [], "matched": ["secureops.allow.default_write"]} if {
    input.tool_category == "write"
    not _prod_scale_zero
    not _pdb_violates
    not _p99_elevated_no_ack
}

_prod_scale_zero if {
    input.tool == "scale_workload"
    input.target.namespace_labels["tier"] == "prod"
    input.parameters.replicas == 0
}

_pdb_violates if { count(input.blast_radius.pdb_violations) > 0 }

_p99_elevated_no_ack if {
    input.target.namespace_labels["tier"] == "prod"
    input.blast_radius.traffic.p99_latency_ms > 1000
    not input.actor.sre_ack
}
```

```rego
# policies/opa/secureops/blast_radius.rego
package secureops.blast_radius

# projections usable by UI / explain tools
summary[k] := v if {
    k := "pdb_count"
    v := count(input.blast_radius.pdb_violations)
}
```

```rego
# policies/opa/secureops/denial_reasons.rego
package secureops.denial_reasons

code_to_human := {
    "prod_scale_zero_denied": "scaling a prod-tier workload to zero replicas is denied; use drain or rolling restart instead",
    "pdb_violation": "the proposed action would violate a PodDisruptionBudget; reduce concurrency or wait for rollout",
    "p99_elevated_require_sre_ack": "prod p99 latency > 1s indicates active incident; require --sre-ack to proceed",
    "no_matching_rule": "no explicit allow rule matched; default denied",
}
```

```rego
# policies/opa/secureops_test.rego
package secureops

test_read_allowed if {
    result := allow with input as {"tool_category": "read"}
    result.allow == true
}

test_prod_scale_zero_denied if {
    result := allow with input as {
        "tool_category": "write",
        "tool": "scale_workload",
        "target": {"namespace_labels": {"tier": "prod"}},
        "parameters": {"replicas": 0},
        "blast_radius": {"pdb_violations": [], "traffic": {"p99_latency_ms": 50}},
        "actor": {}
    }
    result.allow == false
    "prod_scale_zero_denied" in result.reasons
}

test_pdb_violation_denied if {
    result := allow with input as {
        "tool_category": "write",
        "tool": "restart_deployment",
        "target": {"namespace_labels": {"tier": "staging"}},
        "parameters": {},
        "blast_radius": {
            "pdb_violations": [{"pdb": {"name": "p"}, "current_available": 0, "min_available": 1}],
            "traffic": {"p99_latency_ms": 10}
        },
        "actor": {}
    }
    result.allow == false
    "pdb_violation" in result.reasons
}

test_p99_elevated_requires_ack if {
    base := {
        "tool_category": "write",
        "tool": "restart_deployment",
        "target": {"namespace_labels": {"tier": "prod"}},
        "parameters": {},
        "blast_radius": {"pdb_violations": [], "traffic": {"p99_latency_ms": 1500}},
    }
    denied := allow with input as object.union(base, {"actor": {}})
    denied.allow == false
    "p99_elevated_require_sre_ack" in denied.reasons

    allowed := allow with input as object.union(base, {"actor": {"sre_ack": true}})
    allowed.allow == true
}

test_default_write_allowed if {
    result := allow with input as {
        "tool_category": "write",
        "tool": "restart_deployment",
        "target": {"namespace_labels": {"tier": "staging"}},
        "parameters": {},
        "blast_radius": {"pdb_violations": [], "traffic": {"p99_latency_ms": 20}},
        "actor": {}
    }
    result.allow == true
}
```

```bash
# policies/opa/test-cmd.sh
#!/usr/bin/env bash
set -euo pipefail
opa test policies/opa -v
```

- [ ] **Step 2: Run `opa test`**

Run: `bash policies/opa/test-cmd.sh`
Expected: 5 tests passed.

(If `opa` is not installed, install via `brew install opa` or the OPA GitHub release; CI image has it pre-installed.)

- [ ] **Step 3: Add OPA step to CI**

Modify `.github/workflows/ci.yml` — append after pytest step:

```yaml
      - name: opa test
        uses: open-policy-agent/setup-opa@v2
        with: { version: latest }
      - run: opa test policies/opa -v
```

- [ ] **Step 4: Commit**

```bash
git add policies/opa/ .github/workflows/ci.yml
git commit -m "feat(policy): default rego bundle with unit tests"
```

---

### Task 3: Bundle loader (ConfigMap + OCI)

**Files:**
- Create: `packages/server/src/secureops_server/policy/opa_bundles.py`
- Create: `packages/server/tests/test_opa_bundles.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/test_opa_bundles.py
from __future__ import annotations

from pathlib import Path

import pytest

from secureops_server.policy.opa_bundles import (
    BundleSource,
    materialize_bundle,
)


def test_bundle_source_from_env_picks_configmap(monkeypatch):
    monkeypatch.delenv("SECUREOPS_POLICY_OCI_REF", raising=False)
    monkeypatch.setenv("SECUREOPS_POLICY_CONFIGMAP_PATH", "/etc/policies")
    src = BundleSource.from_env()
    assert src.kind == "configmap"
    assert src.configmap_path == "/etc/policies"


def test_bundle_source_from_env_prefers_oci_when_set(monkeypatch):
    monkeypatch.setenv("SECUREOPS_POLICY_OCI_REF", "ghcr.io/vellankikoti/secureops-policies:v1.0.0")
    monkeypatch.setenv("SECUREOPS_POLICY_CONFIGMAP_PATH", "/etc/policies")
    src = BundleSource.from_env()
    assert src.kind == "oci"
    assert src.oci_ref and "secureops-policies" in src.oci_ref


def test_materialize_configmap_copies_to_target(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "allow.rego").write_text("package secureops\n")
    target = tmp_path / "out"
    src = BundleSource(kind="configmap", configmap_path=str(src_dir), oci_ref=None)
    materialize_bundle(src, str(target))
    assert (target / "allow.rego").read_text() == "package secureops\n"


def test_materialize_oci_not_implemented_raises(tmp_path: Path):
    src = BundleSource(kind="oci", configmap_path=None, oci_ref="ghcr.io/x/y:z")
    with pytest.raises(NotImplementedError, match="oras"):
        materialize_bundle(src, str(tmp_path))
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/test_opa_bundles.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/policy/opa_bundles.py
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from typing import Literal


@dataclass
class BundleSource:
    kind: Literal["configmap", "oci"]
    configmap_path: str | None
    oci_ref: str | None

    @staticmethod
    def from_env() -> BundleSource:
        oci = os.environ.get("SECUREOPS_POLICY_OCI_REF")
        cm = os.environ.get("SECUREOPS_POLICY_CONFIGMAP_PATH")
        if oci:
            return BundleSource(kind="oci", configmap_path=cm, oci_ref=oci)
        if cm:
            return BundleSource(kind="configmap", configmap_path=cm, oci_ref=None)
        raise RuntimeError(
            "no policy bundle source configured; set SECUREOPS_POLICY_CONFIGMAP_PATH or SECUREOPS_POLICY_OCI_REF"
        )


def materialize_bundle(src: BundleSource, target_dir: str) -> None:
    os.makedirs(target_dir, exist_ok=True)
    if src.kind == "configmap":
        if not src.configmap_path:
            raise ValueError("configmap_path required")
        for entry in os.listdir(src.configmap_path):
            s = os.path.join(src.configmap_path, entry)
            d = os.path.join(target_dir, entry)
            if os.path.isfile(s):
                shutil.copy2(s, d)
        return
    if src.kind == "oci":
        raise NotImplementedError(
            "OCI bundle loading requires oras-py; install as optional dep in v1.1"
        )
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/test_opa_bundles.py -v
git add packages/server/src/secureops_server/policy/opa_bundles.py packages/server/tests/test_opa_bundles.py
git commit -m "feat(policy): bundle loader (ConfigMap now; OCI stub)"
```

---

### Task 4: Per-action RBAC templates

**Files:**
- Create: `packages/server/src/secureops_server/tokens/__init__.py`
- Create: `packages/server/src/secureops_server/tokens/rbac_templates.py`
- Create: `packages/server/tests/test_rbac_templates.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/test_rbac_templates.py
from __future__ import annotations

from secureops_server.tokens.rbac_templates import (
    per_action_sa_name,
    rbac_manifests_for_action,
)


def test_per_action_sa_name_stable_and_safe():
    name = per_action_sa_name(action_verb="restart", kind="Deployment", namespace="prod")
    assert name == "secureops-action-restart-deployment-prod"
    assert len(name) <= 63


def test_rbac_manifests_for_restart_deployment():
    m = rbac_manifests_for_action(
        action_verb="restart", kind="Deployment", namespace="prod"
    )
    kinds = [r["kind"] for r in m]
    assert "ServiceAccount" in kinds
    assert "Role" in kinds
    assert "RoleBinding" in kinds
    role = next(r for r in m if r["kind"] == "Role")
    rules = role["rules"]
    assert any("deployments" in rr["resources"] and "patch" in rr["verbs"] for rr in rules)


def test_rbac_manifests_for_scale_uses_scale_subresource():
    m = rbac_manifests_for_action(
        action_verb="scale", kind="Deployment", namespace="prod"
    )
    role = next(r for r in m if r["kind"] == "Role")
    rules = role["rules"]
    assert any("deployments/scale" in rr["resources"] for rr in rules)
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/test_rbac_templates.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tokens/__init__.py
"""token broker + per-action RBAC templates."""
```

```python
# packages/server/src/secureops_server/tokens/rbac_templates.py
from __future__ import annotations

from typing import Any


def per_action_sa_name(*, action_verb: str, kind: str, namespace: str) -> str:
    raw = f"secureops-action-{action_verb}-{kind.lower()}-{namespace}"
    return raw[:63]


_VERB_TO_RULES: dict[str, list[dict[str, Any]]] = {
    "restart": [
        {
            "apiGroups": ["apps"],
            "resources": ["deployments"],
            "verbs": ["get", "patch"],
        }
    ],
    "scale": [
        {
            "apiGroups": ["apps"],
            "resources": ["deployments/scale"],
            "verbs": ["get", "patch", "update"],
        }
    ],
    "rollback": [
        {
            "apiGroups": ["apps"],
            "resources": ["deployments", "replicasets"],
            "verbs": ["get", "patch", "update"],
        }
    ],
    "cordon": [
        {
            "apiGroups": [""],
            "resources": ["nodes"],
            "verbs": ["get", "patch"],
        }
    ],
    "drain": [
        {
            "apiGroups": [""],
            "resources": ["nodes", "pods", "pods/eviction"],
            "verbs": ["get", "list", "patch", "create", "delete"],
        }
    ],
    "evict": [
        {
            "apiGroups": [""],
            "resources": ["pods/eviction"],
            "verbs": ["create"],
        }
    ],
}


def rbac_manifests_for_action(
    *, action_verb: str, kind: str, namespace: str
) -> list[dict[str, Any]]:
    if action_verb not in _VERB_TO_RULES:
        raise ValueError(f"unknown action verb: {action_verb}")
    sa = per_action_sa_name(action_verb=action_verb, kind=kind, namespace=namespace)
    role_name = f"{sa}-role"
    binding_name = f"{sa}-binding"
    return [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": sa, "namespace": namespace},
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": role_name, "namespace": namespace},
            "rules": _VERB_TO_RULES[action_verb],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": binding_name, "namespace": namespace},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": role_name,
            },
            "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": namespace}],
        },
    ]
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/test_rbac_templates.py -v
git add packages/server/src/secureops_server/tokens/ packages/server/tests/test_rbac_templates.py
git commit -m "feat(tokens): per-action RBAC templates"
```

---

### Task 5: TokenRequest broker

**Files:**
- Create: `packages/server/src/secureops_server/tokens/broker.py`
- Create: `packages/server/tests/test_token_broker.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/test_token_broker.py
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
    token, ttl = await broker.mint(
        action_verb="restart", kind="Deployment", namespace="prod"
    )
    assert token == "eyJ..."
    assert ttl == 300
    args, kwargs = core.create_namespaced_service_account_token.await_args
    assert kwargs["namespace"] == "prod"
    assert kwargs["name"] == "secureops-action-restart-deployment-prod"
    tr_body = kwargs["body"]
    assert tr_body["spec"]["expirationSeconds"] == 300


@pytest.mark.asyncio
async def test_mint_failure_raises_token_mint_failed():
    core = MagicMock()
    core.create_namespaced_service_account_token = AsyncMock(
        side_effect=RuntimeError("boom")
    )
    broker = TokenBroker(core_v1=core, ttl_seconds=300)
    with pytest.raises(RuntimeError, match="token_mint_failed"):
        await broker.mint(action_verb="restart", kind="Deployment", namespace="prod")
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/test_token_broker.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tokens/broker.py
from __future__ import annotations

from typing import Any

from secureops_server.tokens.rbac_templates import per_action_sa_name


class TokenBroker:
    def __init__(self, core_v1: Any, ttl_seconds: int = 300) -> None:
        self._core = core_v1
        self._ttl = ttl_seconds

    async def mint(
        self, *, action_verb: str, kind: str, namespace: str
    ) -> tuple[str, int]:
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
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/test_token_broker.py -v
git add packages/server/src/secureops_server/tokens/broker.py packages/server/tests/test_token_broker.py
git commit -m "feat(tokens): TokenBroker minting 5-min per-action tokens"
```

---

### Task 6: Audit wrapper — every tool call produces AuditRow

**Files:**
- Create: `packages/server/src/secureops_server/audit/wrapper.py`
- Create: `packages/server/tests/test_audit_wrapper.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/test_audit_wrapper.py
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from secureops_server.audit.ledger import AuditLedger
from secureops_server.audit.schema import init_db
from secureops_server.audit.wrapper import audited_read, audited_write
from secureops_server.models import (
    ActionProposal,
    ActionResult,
    Actor,
    BlastRadius,
    K8sRef,
    OPADecision,
    TrafficSnapshot,
)


def _prop(tool_name: str = "list_workloads") -> ActionProposal:
    return ActionProposal(
        action_id="01HY",
        tool_name=tool_name,
        actor=Actor(mcp_client_id="c", human_subject=None),
        target=K8sRef(kind="Namespace", api_version="v1", name="default"),
        parameters={},
        blast_radius=BlastRadius(
            direct=[], one_hop=[], transitive=[],
            traffic=TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable"),
            pdb_violations=[], data_loss_risk="none",
        ),
        requested_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_audited_read_records_row_and_returns_result(tmp_path: Path):
    db = tmp_path / "a.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))

    async def fn() -> list[str]:
        return ["a", "b"]

    out, row = await audited_read(ledger, _prop(), fn)
    assert out == ["a", "b"]
    assert row.result.status == "allowed_executed"
    assert row.row_id == 1


@pytest.mark.asyncio
async def test_audited_write_records_denied_preflight_when_opa_unavailable(tmp_path: Path):
    db = tmp_path / "a.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))

    async def fake_opa_eval(_input) -> OPADecision:
        raise RuntimeError("opa_unavailable")

    async def fake_write() -> ActionResult:
        raise AssertionError("should not be called")

    row = await audited_write(
        ledger=ledger,
        proposal=_prop("restart_deployment"),
        opa_eval=fake_opa_eval,
        do_write=fake_write,
    )
    assert row.result.status == "denied_preflight"
    assert "opa_unavailable" in row.result.error or ""
    assert row.result.opa_decision.allow is False
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/test_audit_wrapper.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/audit/wrapper.py
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Awaitable, Callable, TypeVar

from secureops_server.audit.ledger import AuditLedger
from secureops_server.models import (
    ActionProposal,
    ActionResult,
    AuditRow,
    OPADecision,
)

T = TypeVar("T")


def _empty_decision(allow: bool = True) -> OPADecision:
    return OPADecision(
        allow=allow, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)
    )


async def audited_read(
    ledger: AuditLedger,
    proposal: ActionProposal,
    fn: Callable[[], Awaitable[T]],
) -> tuple[T, AuditRow]:
    try:
        value = await fn()
        result = ActionResult(
            action_id=proposal.action_id,
            status="allowed_executed",
            opa_decision=_empty_decision(True),
            kyverno_warnings=[],
            token_ttl_remaining_s=None,
            k8s_response=None,
            error=None,
            completed_at=datetime.now(UTC),
        )
    except Exception as e:
        result = ActionResult(
            action_id=proposal.action_id,
            status="allowed_failed",
            opa_decision=_empty_decision(True),
            kyverno_warnings=[],
            token_ttl_remaining_s=None,
            k8s_response=None,
            error=repr(e),
            completed_at=datetime.now(UTC),
        )
        row = await ledger.append(proposal, result)
        raise
    row = await ledger.append(proposal, result)
    return value, row


async def audited_write(
    *,
    ledger: AuditLedger,
    proposal: ActionProposal,
    opa_eval: Callable[[dict[str, Any]], Awaitable[OPADecision]],
    do_write: Callable[[], Awaitable[ActionResult]],
) -> AuditRow:
    # 1. OPA pre-flight
    try:
        decision = await opa_eval(_input_for_opa(proposal))
    except Exception as e:
        result = ActionResult(
            action_id=proposal.action_id,
            status="denied_preflight",
            opa_decision=_empty_decision(False),
            kyverno_warnings=[],
            token_ttl_remaining_s=None,
            k8s_response=None,
            error=repr(e),
            completed_at=datetime.now(UTC),
        )
        return await ledger.append(proposal, result)

    if not decision.allow:
        result = ActionResult(
            action_id=proposal.action_id,
            status="denied_opa",
            opa_decision=decision,
            kyverno_warnings=[],
            token_ttl_remaining_s=None,
            k8s_response=None,
            error=None,
            completed_at=datetime.now(UTC),
        )
        return await ledger.append(proposal, result)

    # 2. Execute write; do_write is responsible for minting token + K8s call + returning result
    result = await do_write()
    return await ledger.append(proposal, result)


def _input_for_opa(p: ActionProposal) -> dict[str, Any]:
    return {
        "tool": p.tool_name,
        "tool_category": "write",
        "actor": p.actor.model_dump(),
        "target": {
            "kind": p.target.kind,
            "namespace": p.target.namespace,
            "name": p.target.name,
            "namespace_labels": p.parameters.get("_namespace_labels", {}),
        },
        "parameters": {k: v for k, v in p.parameters.items() if not k.startswith("_")},
        "blast_radius": p.blast_radius.model_dump(),
    }
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/test_audit_wrapper.py -v
git add packages/server/src/secureops_server/audit/wrapper.py packages/server/tests/test_audit_wrapper.py
git commit -m "feat(audit): read + write wrappers producing AuditRow"
```

---

### Task 7: Exemplar write tool — `restart_deployment`

**Files:**
- Create: `packages/server/src/secureops_server/tools/remediation/__init__.py`
- Create: `packages/server/src/secureops_server/tools/remediation/restart_deployment.py`
- Create: `packages/server/tests/tools/remediation/__init__.py`
- Create: `packages/server/tests/tools/remediation/test_restart_deployment.py`

- [ ] **Step 1: Failing test**

```python
# packages/server/tests/tools/remediation/test_restart_deployment.py
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.models import K8sRef
from secureops_server.tools.remediation.restart_deployment import (
    build_restart_patch,
    execute_restart,
)


def test_build_restart_patch_adds_annotation():
    patch = build_restart_patch()
    ann = patch["spec"]["template"]["metadata"]["annotations"]
    assert "kubectl.kubernetes.io/restartedAt" in ann
    # value must be ISO-8601 UTC
    assert ann["kubectl.kubernetes.io/restartedAt"].endswith("+00:00") or ann[
        "kubectl.kubernetes.io/restartedAt"
    ].endswith("Z")


@pytest.mark.asyncio
async def test_execute_restart_uses_minted_token_and_patches_deployment():
    # build a fresh AppsV1Api mock patched-with minted token
    patched_apps = MagicMock()
    patched_apps.patch_namespaced_deployment = AsyncMock(
        return_value=MagicMock(metadata=MagicMock(resource_version="42"))
    )

    def make_apps_from_token(token: str):
        assert token == "minted-token"
        return patched_apps

    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace="prod", name="checkout")
    result = await execute_restart(target, token="minted-token", build_apps=make_apps_from_token)
    assert result["resource_version"] == "42"
    patched_apps.patch_namespaced_deployment.assert_awaited_once()
```

- [ ] **Step 2: Confirm failure**

Run: `uv run pytest packages/server/tests/tools/remediation/test_restart_deployment.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

```python
# packages/server/src/secureops_server/tools/remediation/__init__.py
"""write tools (OPA-gated)."""
```

```python
# packages/server/src/secureops_server/tools/remediation/restart_deployment.py
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable

from secureops_server.models import K8sRef


def build_restart_patch() -> dict[str, Any]:
    now_iso = datetime.now(UTC).isoformat()
    return {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {"kubectl.kubernetes.io/restartedAt": now_iso}
                }
            }
        }
    }


async def execute_restart(
    target: K8sRef,
    *,
    token: str,
    build_apps: Callable[[str], Any],
) -> dict[str, Any]:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("restart_deployment requires Deployment target with namespace")
    apps = build_apps(token)
    patch = build_restart_patch()
    resp = await apps.patch_namespaced_deployment(
        name=target.name, namespace=target.namespace, body=patch
    )
    return {
        "resource_version": resp.metadata.resource_version,
        "patched_at": patch["spec"]["template"]["metadata"]["annotations"][
            "kubectl.kubernetes.io/restartedAt"
        ],
    }
```

- [ ] **Step 4: Pass + commit**

```bash
uv run pytest packages/server/tests/tools/remediation/test_restart_deployment.py -v
git add packages/server/src/secureops_server/tools/remediation/ packages/server/tests/tools/remediation/
git commit -m "feat(tools): restart_deployment (exemplar write)"
```

---

### Task 8: Wire `restart_deployment` end-to-end through MCP

**Files:**
- Modify: `packages/server/src/secureops_server/mcp_server.py`
- Modify: `packages/server/src/secureops_server/runtime.py`
- Create: `packages/server/tests/test_mcp_restart_end_to_end.py`

- [ ] **Step 1: Failing test — simulate full flow (mocks for OPA, K8s, ledger)**

```python
# packages/server/tests/test_mcp_restart_end_to_end.py
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from secureops_server.audit.ledger import AuditLedger
from secureops_server.audit.schema import init_db
from secureops_server.context import SecureOpsContext
from secureops_server.models import OPADecision
from secureops_server.runtime import override_for_tests


@pytest.mark.asyncio
async def test_restart_deployment_happy_path_records_allowed_executed(tmp_path: Path):
    db = tmp_path / "a.db"
    await init_db(str(db))
    ledger = AuditLedger(str(db))

    apps = MagicMock()
    apps.read_namespaced_deployment = AsyncMock(return_value=_dep())
    apps.patch_namespaced_deployment = AsyncMock(
        return_value=MagicMock(metadata=MagicMock(resource_version="42"))
    )
    core = MagicMock()
    core.list_namespaced_service = AsyncMock(return_value=MagicMock(items=[]))
    core.create_namespaced_service_account_token = AsyncMock(
        return_value=MagicMock(status=MagicMock(token="t", expiration_timestamp=None))
    )
    policy = MagicMock()
    policy.list_namespaced_pod_disruption_budget = AsyncMock(return_value=MagicMock(items=[]))
    autoscaling = MagicMock()
    autoscaling.list_namespaced_horizontal_pod_autoscaler = AsyncMock(return_value=MagicMock(items=[]))

    k8s = MagicMock()
    k8s.apps_v1 = apps
    k8s.core_v1 = core
    k8s.policy_v1 = policy
    k8s.autoscaling_v2 = autoscaling

    opa = MagicMock()
    opa.evaluate_allow = AsyncMock(
        return_value=OPADecision(
            allow=True, reasons=[], matched_policies=["secureops.allow.default_write"],
            evaluated_at=datetime.now(UTC),
        )
    )

    ctx = SecureOpsContext(k8s=k8s, opa=opa, prom=None, sqlite=None, llm=None)
    override_for_tests(ctx, ledger)

    from secureops_server.mcp_server import restart_deployment_tool  # type: ignore[attr-defined]
    out = await restart_deployment_tool(namespace="prod", name="checkout")

    assert out["status"] == "allowed_executed"
    assert out["k8s_response"]["resource_version"] == "42"
    assert await ledger.verify_chain() is True


def _dep():
    d = MagicMock()
    d.metadata.name = "checkout"
    d.metadata.namespace = "prod"
    d.metadata.uid = "u"
    d.spec.replicas = 3
    d.spec.selector.match_labels = {"app": "checkout"}
    d.spec.template.metadata.labels = {"app": "checkout"}
    d.spec.template.spec.volumes = []
    return d
```

- [ ] **Step 2: Implement MCP wrapper + runtime wiring**

Append to `mcp_server.py`:

```python
# packages/server/src/secureops_server/mcp_server.py — append
import uuid
from datetime import UTC, datetime

from kubernetes_asyncio import client as _k8s_client

from secureops_server.audit.wrapper import audited_write
from secureops_server.models import ActionProposal, ActionResult, Actor, OPADecision
from secureops_server.runtime import get_context, get_ledger
from secureops_server.tokens.broker import TokenBroker
from secureops_server.tools.blast_radius.compute_blast_radius import compute_blast_radius
from secureops_server.tools.remediation.restart_deployment import execute_restart


def _apps_from_token(token: str):
    cfg = _k8s_client.Configuration()
    cfg.host = _k8s_client.Configuration.get_default_copy().host  # reuse API host
    cfg.api_key = {"authorization": f"Bearer {token}"}
    api = _k8s_client.ApiClient(cfg)
    return _k8s_client.AppsV1Api(api)


@mcp.tool()
async def restart_deployment_tool(namespace: str, name: str) -> dict:
    """Restart a Deployment via a rolling rollout (OPA-gated, 5-min token)."""
    ctx = await get_context()
    ledger = await get_ledger()
    guarded = ctx.guard(needs=frozenset({Capability.K8S, Capability.OPA}))
    target = K8sRef(kind="Deployment", api_version="apps/v1", namespace=namespace, name=name)
    blast = await compute_blast_radius(
        ctx.guard(needs=frozenset({Capability.K8S, Capability.PROM})) if ctx.prom else
        ctx.guard(needs=frozenset({Capability.K8S})), target,
    ) if ctx.prom else await compute_blast_radius(
        ctx.guard(needs=frozenset({Capability.K8S})), target
    )  # tolerate missing prom
    proposal = ActionProposal(
        action_id=str(uuid.uuid4()),
        tool_name="restart_deployment",
        actor=Actor(mcp_client_id="mcp", human_subject=None),
        target=target,
        parameters={},
        blast_radius=blast,
        requested_at=datetime.now(UTC),
    )

    async def _opa_eval(input_doc: dict) -> OPADecision:
        return await guarded.opa.evaluate_allow(input_doc)

    async def _do_write() -> ActionResult:
        broker = TokenBroker(core_v1=ctx.k8s.core_v1, ttl_seconds=300)
        token, ttl = await broker.mint(action_verb="restart", kind="Deployment", namespace=namespace)
        resp = await execute_restart(target, token=token, build_apps=_apps_from_token)
        return ActionResult(
            action_id=proposal.action_id,
            status="allowed_executed",
            opa_decision=OPADecision(allow=True, reasons=[], matched_policies=[], evaluated_at=datetime.now(UTC)),
            kyverno_warnings=[],
            token_ttl_remaining_s=ttl,
            k8s_response=resp,
            error=None,
            completed_at=datetime.now(UTC),
        )

    row = await audited_write(
        ledger=ledger, proposal=proposal, opa_eval=_opa_eval, do_write=_do_write
    )
    return row.result.model_dump()
```

Allow `compute_blast_radius` to tolerate missing prom by passing `None` — simplest change: in Phase 3, it already catches prom failure inside `snapshot_for_service` when `prom` is None (adjust `traffic.py` to early-return `unavailable` when `prom is None`):

```python
# packages/server/src/secureops_server/blast_radius/traffic.py — modify snapshot_for_service
async def snapshot_for_service(prom: Any, svc: K8sRef) -> TrafficSnapshot:
    if prom is None:
        return TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable")
    # rest unchanged
    ...
```

- [ ] **Step 3: Run test, pass**

Run: `uv run pytest packages/server/tests/test_mcp_restart_end_to_end.py -v`
Expected: 1 passed.

- [ ] **Step 4: Extend registration test**

Add `"restart_deployment"` to the required set in `test_cluster_state_tools_registered`.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/secureops_server/mcp_server.py packages/server/src/secureops_server/blast_radius/traffic.py packages/server/tests/test_mcp_restart_end_to_end.py packages/server/tests/test_mcp_server_registration.py
git commit -m "feat(mcp): restart_deployment end-to-end through OPA + TokenBroker + audit"
```

---

### Task 9: Integration test in kind + Helm chart skeleton (OPA sidecar only)

**Files:**
- Create: `helm/secureops/Chart.yaml`
- Create: `helm/secureops/values.yaml`
- Create: `helm/secureops/templates/_helpers.tpl`
- Create: `helm/secureops/templates/deployment.yaml`
- Create: `helm/secureops/templates/serviceaccount.yaml`
- Create: `helm/secureops/templates/clusterrole.yaml`
- Create: `helm/secureops/templates/clusterrolebinding.yaml`
- Create: `helm/secureops/templates/configmap-policies.yaml`
- Create: `tests/integration/test_kind_restart.sh`

- [ ] **Step 1: Chart.yaml and values**

```yaml
# helm/secureops/Chart.yaml
apiVersion: v2
name: secureops
description: mcp-k8s-secure-ops server with OPA sidecar
type: application
version: 0.1.0
appVersion: "0.4.0"
```

```yaml
# helm/secureops/values.yaml
image:
  repository: ghcr.io/vellankikoti/mcp-k8s-secure-ops
  tag: "v0.4.0"
  pullPolicy: IfNotPresent
opa:
  image: openpolicyagent/opa:0.65.0
  logLevel: info
policy:
  source: configmap    # or: oci
  ociRef: ""           # used when source=oci
serviceAccount:
  name: secureops-broker
auditDb:
  pvcSize: 1Gi
```

```yaml
# helm/secureops/templates/_helpers.tpl
{{- define "secureops.name" -}}
{{- default "secureops" .Values.nameOverride -}}
{{- end -}}
```

```yaml
# helm/secureops/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "secureops.name" . }}
spec:
  replicas: 1
  selector:
    matchLabels: { app: {{ include "secureops.name" . }} }
  template:
    metadata:
      labels: { app: {{ include "secureops.name" . }} }
    spec:
      serviceAccountName: {{ .Values.serviceAccount.name }}
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      volumes:
        - name: policies
          configMap: { name: {{ include "secureops.name" . }}-policies }
        - name: audit
          persistentVolumeClaim: { claimName: {{ include "secureops.name" . }}-audit }
      containers:
        - name: server
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          args: ["serve-mcp"]
          env:
            - name: SECUREOPS_POLICY_CONFIGMAP_PATH
              value: /etc/policies
            - name: SECUREOPS_AUDIT_DB
              value: /var/lib/secureops/audit.db
            - name: SECUREOPS_OPA_URL
              value: http://localhost:8181
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          volumeMounts:
            - { name: policies, mountPath: /etc/policies, readOnly: true }
            - { name: audit, mountPath: /var/lib/secureops }
        - name: opa
          image: {{ .Values.opa.image }}
          args: ["run", "--server", "--log-level={{ .Values.opa.logLevel }}", "/etc/policies"]
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          volumeMounts:
            - { name: policies, mountPath: /etc/policies, readOnly: true }
```

```yaml
# helm/secureops/templates/serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ .Values.serviceAccount.name }}
```

```yaml
# helm/secureops/templates/clusterrole.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ .Values.serviceAccount.name }}-read
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "events", "nodes", "namespaces", "persistentvolumeclaims", "configmaps", "serviceaccounts"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["policy"]
    resources: ["poddisruptionbudgets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create"]
```

```yaml
# helm/secureops/templates/clusterrolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ .Values.serviceAccount.name }}-read
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ .Values.serviceAccount.name }}-read
subjects:
  - kind: ServiceAccount
    name: {{ .Values.serviceAccount.name }}
    namespace: "{{ .Release.Namespace }}"
```

```yaml
# helm/secureops/templates/configmap-policies.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "secureops.name" . }}-policies
data:
{{- range $path, $_ := .Files.Glob "../../policies/opa/secureops/*.rego" }}
  {{ base $path }}: |-
{{ $.Files.Get $path | indent 4 }}
{{- end }}
```

```yaml
# helm/secureops/templates/pvc-audit.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ include "secureops.name" . }}-audit
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: {{ .Values.auditDb.pvcSize }}
```

- [ ] **Step 2: Integration script for kind**

```bash
# tests/integration/test_kind_restart.sh
#!/usr/bin/env bash
set -euo pipefail

CLUSTER="${CLUSTER:-secureops-p4}"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER"

# load locally-built image
docker build -t ghcr.io/vellankikoti/mcp-k8s-secure-ops:dev .
kind load docker-image ghcr.io/vellankikoti/mcp-k8s-secure-ops:dev --name "$CLUSTER"

kubectl create ns secureops-system
helm install secureops helm/secureops -n secureops-system \
  --set image.tag=dev --set image.pullPolicy=IfNotPresent
kubectl -n secureops-system rollout status deploy/secureops --timeout=90s

# seed a demo deployment to restart
kubectl create ns demo
kubectl -n demo create deployment checkout --image=nginx:1.27
kubectl -n demo wait --for=condition=available deploy/checkout --timeout=60s

# exercise the tool via stdio (simple jq probe)
POD=$(kubectl -n secureops-system get pod -l app=secureops -o name | head -1)
kubectl -n secureops-system exec "$POD" -c server -- mcp-k8s-secure-ops version

kind delete cluster --name "$CLUSTER"
```

Make executable: `chmod +x tests/integration/test_kind_restart.sh`.

- [ ] **Step 3: Commit**

```bash
git add helm/secureops/ tests/integration/
git commit -m "feat(helm): secureops chart with OPA sidecar + read-only ClusterRole"
```

---

### Task 10: Local gate, push, tag v0.4.0

- [ ] **Step 1: Local gate + opa test**

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy packages/server/src packages/policy_sdk/src
uv run pytest -v
opa test policies/opa -v
```

- [ ] **Step 2: Push + tag**

```bash
git push
gh run watch
git tag -a v0.4.0 -m "phase 4: OPA + TokenBroker + restart_deployment e2e"
git push --tags
```

---

## Self-review for this phase

- **Spec coverage:** OPA pre-flight, bundle loader (ConfigMap), TokenRequest broker, per-action RBAC templates, audit wrapper, one exemplar write tool (`restart_deployment`) end-to-end. Kyverno admission wiring is deferred to phase 5 (the spec says "defense-in-depth" — phase 4 establishes the first gate, phase 5 adds the second).
- **Placeholder scan:** OCI bundle loader raises `NotImplementedError` — intentional; filling in v1.1 per VISION. Flagged in the test.
- **Type consistency:** `OPADecision`, `ActionProposal`, `ActionResult`, `AuditRow`, `TokenBroker.mint` signature consistent across modules.

Phase 4 ends at tag v0.4.0. Phase 5 begins — remaining 5 writes, Kyverno, explain_*, router, audit query tools, release pipeline, v1.0.0 tag.
