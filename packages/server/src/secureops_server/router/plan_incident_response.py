from __future__ import annotations

from typing import Any


def plan_incident_response(
    *, symptom: str, target_kind: str, target_name: str, namespace: str | None
) -> list[dict[str, Any]]:
    if symptom == "pod_crashlooping":
        return [
            {
                "tool": "describe_workload",
                "args": {"kind": target_kind, "namespace": namespace, "name": target_name},
            },
            {
                "tool": "get_pod_logs",
                "args": {"namespace": namespace, "name": target_name, "tail_lines": 200},
            },
            {
                "tool": "get_recent_events",
                "args": {"namespace": namespace, "since_minutes": 15},
            },
        ]
    if symptom == "deployment_unhealthy":
        return [
            {
                "tool": "find_unhealthy_workloads",
                "args": {"namespace": namespace},
            },
            {
                "tool": "get_recent_events",
                "args": {"namespace": namespace, "since_minutes": 15},
            },
            {
                "tool": "compute_blast_radius",
                "args": {"kind": target_kind, "namespace": namespace, "name": target_name},
            },
            {
                "tool": "restart_deployment",
                "args": {"namespace": namespace, "name": target_name},
                "confirm_required": True,
            },
        ]
    if symptom == "node_notready":
        return [
            {
                "tool": "get_recent_events",
                "args": {"namespace": None, "since_minutes": 30},
            },
            {
                "tool": "cordon_node",
                "args": {"name": target_name, "cordon": True},
                "confirm_required": True,
            },
        ]
    if symptom == "service_high_errors":
        return [
            {
                "tool": "get_traffic_snapshot",
                "args": {"namespace": namespace, "name": target_name},
            },
            {
                "tool": "find_dependents",
                "args": {"kind": target_kind, "namespace": namespace, "name": target_name},
            },
        ]
    return [
        {"tool": "list_workloads", "args": {"namespace": namespace}},
        {"tool": "get_recent_events", "args": {"namespace": namespace, "since_minutes": 30}},
        {"tool": "find_unhealthy_workloads", "args": {"namespace": namespace}},
    ]
