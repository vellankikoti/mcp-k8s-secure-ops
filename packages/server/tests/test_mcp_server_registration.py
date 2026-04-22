from __future__ import annotations

from secureops_server.mcp_server import mcp


async def test_cluster_state_tools_registered():
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    required = {
        # cluster_state (5)
        "list_workloads",
        "describe_workload",
        "get_recent_events",
        "get_pod_logs",
        "find_unhealthy_workloads",
        # blast_radius (4)
        "compute_blast_radius",
        "check_pdb_impact",
        "get_traffic_snapshot",
        "find_dependents",
        # remediation (6)
        "restart_deployment",
        "scale_workload",
        "rollback_deployment",
        "drain_node",
        "cordon_node",
        "evict_pod",
        # audit (3)
        "query_audit",
        "export_audit",
        "verify_chain",
    }
    missing = required - names
    assert not missing, f"missing tools: {missing}"

    companions = {
        "plan_incident_response",
        "explain_opa_decision",
        "explain_blast_radius",
        "explain_incident_plan",
        "explain_audit_row",
    }
    assert companions <= names, f"missing companions: {companions - names}"
