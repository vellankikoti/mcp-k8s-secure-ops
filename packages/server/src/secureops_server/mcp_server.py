from __future__ import annotations

from fastmcp import FastMCP

mcp: FastMCP = FastMCP("mcp-k8s-secure-ops")


def run_stdio() -> None:
    """Run the MCP server over stdio transport."""
    mcp.run(transport="stdio")
