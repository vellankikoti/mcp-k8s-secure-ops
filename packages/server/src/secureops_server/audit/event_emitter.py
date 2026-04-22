from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from secureops_server.models import AuditRow


def build_event_body(row: AuditRow) -> dict[str, Any]:
    is_allow = row.result.status in {"allowed_executed", "allowed_failed"}
    now_iso = datetime.now(UTC).isoformat()
    return {
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {
            "generateName": "secureops-",
            "namespace": row.proposal.target.namespace or "default",
        },
        "type": "Normal" if is_allow else "Warning",
        "reason": "SecureOpsAllowed" if is_allow else "SecureOpsDenied",
        "message": (
            f"tool={row.proposal.tool_name} status={row.result.status} action_id={row.action_id}"
        ),
        "involvedObject": {
            "kind": row.proposal.target.kind,
            "namespace": row.proposal.target.namespace,
            "name": row.proposal.target.name,
            "apiVersion": row.proposal.target.api_version,
            "uid": row.proposal.target.uid,
        },
        "source": {"component": "mcp-k8s-secure-ops"},
        "firstTimestamp": now_iso,
        "lastTimestamp": now_iso,
    }


async def emit_event(k8s_core_v1: Any, row: AuditRow) -> None:
    body = build_event_body(row)
    await k8s_core_v1.create_namespaced_event(namespace=body["metadata"]["namespace"], body=body)
