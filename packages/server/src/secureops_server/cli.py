from __future__ import annotations

import typer

from secureops_server import __version__
from secureops_server.mcp_server import run_stdio

app = typer.Typer(
    name="mcp-k8s-secure-ops",
    help="Auditable AI-assisted K8s incident remediation via MCP.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the package version."""
    typer.echo(__version__)


@app.command("serve-mcp")
def serve_mcp() -> None:
    """Run the MCP server over stdio."""
    run_stdio()
