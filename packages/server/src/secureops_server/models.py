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
