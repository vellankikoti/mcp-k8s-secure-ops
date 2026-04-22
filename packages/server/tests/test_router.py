from __future__ import annotations

from secureops_server.router.plan_incident_response import plan_incident_response


def test_plan_for_crashlooping_pod_starts_with_diagnostics():
    plan = plan_incident_response(
        symptom="pod_crashlooping", target_kind="Pod", target_name="checkout-xyz", namespace="prod"
    )
    assert plan[0]["tool"] in {"describe_workload", "get_pod_logs"}
    assert any(step["tool"] == "get_recent_events" for step in plan)


def test_plan_for_deployment_unhealthy_ends_with_restart_option():
    plan = plan_incident_response(
        symptom="deployment_unhealthy",
        target_kind="Deployment",
        target_name="checkout",
        namespace="prod",
    )
    tools = [s["tool"] for s in plan]
    assert "find_unhealthy_workloads" in tools
    assert "compute_blast_radius" in tools
    assert "restart_deployment" in tools


def test_plan_for_unknown_symptom_returns_discovery_steps():
    plan = plan_incident_response(
        symptom="???", target_kind="Namespace", target_name="prod", namespace="prod"
    )
    tools = [s["tool"] for s in plan]
    assert "list_workloads" in tools
    assert "get_recent_events" in tools
