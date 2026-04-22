from __future__ import annotations

from secureops_server.mcp_server import mcp

# FastMCP 3.x exposes tool enumeration via the async `list_tools()` method,
# which returns a list of FunctionTool objects each with a `.name` attribute.
# No sync accessor exists, so we use asyncio_mode="auto" (configured in
# pyproject.toml) to run the coroutine without a manual @pytest.mark.asyncio.


async def test_cluster_state_tools_registered() -> None:
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    required = {
        "list_workloads",
        "describe_workload",
        "get_recent_events",
        "get_pod_logs",
        "find_unhealthy_workloads",
        "compute_blast_radius",
        "check_pdb_impact",
        "get_traffic_snapshot",
        "find_dependents",
    }
    missing = required - names
    assert not missing, f"missing tools: {missing}"
