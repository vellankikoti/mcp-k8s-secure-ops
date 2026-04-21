# mcp-k8s-secure-ops

## One-Line Summary
Turn dead runbooks into secure, auditable MCP tools with OPA policy gates, short-lived tokens, and blast-radius guardrails — so AI agents can help with incidents without becoming incidents themselves.

## The Problem
1. Oncall engineers don't read runbooks during incidents. They fumble through kubectl from memory.
2. Giving AI agents direct kubectl access is dangerous — broad permissions, no expiry, no audit trail.
3. The MCP protocol has no built-in auth/authz for infrastructure tools. The 2026 roadmap lists this as priority #1.

## What This Project Does
- Decomposes runbook procedures into typed, scoped MCP tools
- Adds a security layer: OPA policy gate checks every tool call before execution
- Issues short-lived Kubernetes tokens per tool call (5-minute TTL, minimum RBAC)
- Logs every action with full tracing: prompt → tool call → policy decision → cluster action → result
- Includes blast-radius estimation and human approval gates for destructive operations

## The Hybrid Engine Philosophy (from kotg.ai)
NOT every query needs AI. This project routes intelligently:
- **Direct path (no AI tokens burned):** "How many pods in namespace X?" → Go backend queries Kubernetes API directly, returns JSON
- **Direct path:** "What's the CPU usage of deployment Y?" → Go backend queries Prometheus directly
- **AI path (reasoning needed):** "Why is the checkout service throwing 500s?" → AI agent chains multiple MCP tools, correlates metrics with logs, reasons about root cause
- **AI path:** "Should I scale this deployment?" → AI cross-references current load, historical patterns, and resource headroom

The routing decision is made by the Go backend based on query classification — simple CRUD/lookup queries never touch the AI.

## Tech Stack
- **Go** — Backend API server, query router, Kubernetes client operations, token issuer
- **Python (FastMCP)** — MCP server tools (the MCP protocol layer)
- **OPA** — Policy engine (sidecar deployment)
- **OpenTelemetry** — Distributed tracing
- **Prometheus** — Metrics source for runbook tools
- **OpenSearch** — Audit log storage and search
- **Kubernetes** — Target cluster (kind/k3d for demo)
- **Docker** — Containerization for all components

## Quick Start (for development)
```bash
# Prerequisites: Go 1.22+, Python 3.11+, Docker, kind, kubectl, helm
git clone https://github.com/vellankikoti/mcp-k8s-secure-ops.git
cd mcp-k8s-secure-ops
make setup          # Creates kind cluster, installs deps
make deploy         # Deploys all components
make demo           # Runs the demo scenario
```

## Conference Talk
See PROPOSAL.md for the full CFP submission text.
See DEMO_SCRIPT.md for the 25-minute demo walkthrough.
