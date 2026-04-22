# Claude Desktop configuration for mcp-k8s-secure-ops

This document explains how to wire Claude Desktop to the local MCP server so
you can drive the demo through natural language prompts.

## Config file location

On **macOS**:

```
~/Library/Application Support/Claude/claude_desktop_config.json
```

## Config JSON

Replace `<REPO>` with the absolute path to this repository and `<HOME>` with
your home directory path (e.g. `/Users/yourname`).

```json
{
  "mcpServers": {
    "secureops": {
      "command": "uv",
      "args": [
        "run",
        "--project",
        "<REPO>",
        "mcp-k8s-secure-ops",
        "serve-mcp"
      ],
      "env": {
        "KUBECONFIG": "<HOME>/.kube/config",
        "SECUREOPS_OPA_URL": "http://localhost:8181",
        "SECUREOPS_AUDIT_DB": "<HOME>/.secureops/audit.db"
      }
    }
  }
}
```

**Example** (replace with your actual paths):

```json
{
  "mcpServers": {
    "secureops": {
      "command": "uv",
      "args": [
        "run",
        "--project",
        "/Users/koti/myFuture/writings/conferences/01-mcp-k8s-secure-ops",
        "mcp-k8s-secure-ops",
        "serve-mcp"
      ],
      "env": {
        "KUBECONFIG": "/Users/koti/.kube/config",
        "SECUREOPS_OPA_URL": "http://localhost:8181",
        "SECUREOPS_AUDIT_DB": "/Users/koti/.secureops/audit.db"
      }
    }
  }
}
```

## How it works

- Claude Desktop launches the MCP server as a **stdio subprocess** using `uv run`.
- The server reads `KUBECONFIG` to talk to your `kind` cluster.
- The server reads `SECUREOPS_OPA_URL` to evaluate policies against the local OPA container.
- All audit rows are written to the SQLite file at `SECUREOPS_AUDIT_DB`.
- No port-forwards, no in-cluster MCP server, no Docker networking — just local processes.

## Steps

1. Run `tests/demo/demo-up.sh` to start the kind cluster and OPA container.
2. Edit `~/Library/Application Support/Claude/claude_desktop_config.json` with
   the snippet above (fill in your paths).
3. **Quit and relaunch Claude Desktop** — it must restart to pick up the new config.
4. In Claude Desktop, look for the MCP tools icon (a plug/wrench symbol in the
   input bar). Click it to confirm `secureops` tools are loaded.
5. Type a prompt such as _"Restart the checkout deployment in demo-staging."_

## Troubleshooting

### MCP server does not appear in Claude Desktop

Check the MCP server logs:

```bash
ls ~/Library/Logs/Claude/
# Look for mcp-server-secureops.log or similar
tail -100 ~/Library/Logs/Claude/mcp-server-secureops.log
```

Common causes:

| Symptom | Fix |
|---------|-----|
| `command not found: uv` | Install uv: `curl -Ls https://astral.sh/uv/install.sh \| sh` |
| `No module named secureops_server` | Run `uv sync` in the repo root first |
| `connection refused` on OPA URL | Start OPA: `docker start secureops-opa` or re-run `demo-up.sh` |
| `KUBECONFIG` points to wrong cluster | `kubectl config current-context` — should be `kind-secureops-demo` |
| Config JSON syntax error | Validate with `python3 -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json` |

### Tools are listed but calls fail

```bash
# Check that the kind cluster is running:
kubectl cluster-info --context kind-secureops-demo

# Check OPA is up:
curl -s http://localhost:8181/health

# Check audit DB is writable:
ls -la ~/.secureops/audit.db
```

### Re-running demo-up.sh mid-session

If you re-run `demo-up.sh`, the audit DB is cleared and the cluster is
recreated. You must also **restart Claude Desktop** so the MCP server process
re-initialises its in-memory context (it holds the K8s client connection).

## Environment variables reference

| Variable | Default in server | Demo value |
|----------|-------------------|------------|
| `KUBECONFIG` | system default | `~/.kube/config` |
| `SECUREOPS_OPA_URL` | none (OPA disabled) | `http://localhost:8181` |
| `SECUREOPS_AUDIT_DB` | `/var/lib/secureops/audit.db` | `~/.secureops/audit.db` |
| `SECUREOPS_PROM_URL` | none (Prometheus disabled) | omit — `traffic.source=unavailable` in blast radius |
