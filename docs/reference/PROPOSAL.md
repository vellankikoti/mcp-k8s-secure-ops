# CFP Proposal: Dead Runbooks, Dangerous Agents, and the Security Model That Saved Us

## Title
Dead Runbooks, Dangerous Agents, and the Security Model That Saved Us

## Abstract

We had 47 runbooks sitting in Confluence. During incidents, nobody opened them. The oncall engineer would fumble through kubectl commands from memory, mistype a namespace, and escalate at 3 AM anyway.

So I did what seemed obvious — I turned those runbooks into MCP server tools. Not documents for an AI to read, but actual executable steps. Check pod logs. Query Prometheus for error rates. Cordon a node. Restart a deployment with canary checks. The AI agent chains these tools together based on what it sees happening in the cluster, not based on some doc written six months ago.

It worked. MTTR dropped. Engineers stopped dreading oncall.

Then two things happened that changed everything.

First, I realized the MCP server had the same service account our CI automation uses. Broad permissions. No expiry. Within minutes of connecting, the agent had listed every secret in the namespace. Not on purpose. It was just doing its job thoroughly. That's when I understood — the MCP security story for infrastructure tools is basically nonexistent right now.

Second, at 3 AM on a Tuesday, the agent correlated two unrelated alerts, confidently restarted the wrong deployment, and turned a small incident into a big one.

This talk covers both problems and how I solved them together. I'll walk through how I broke runbooks into MCP tools with proper boundaries. How I built a security layer using scoped Kubernetes RBAC per tool (not per server), short-lived tokens that expire after each action, and OPA policies that check every tool call before it touches the cluster. And the guardrails I added after the 3 AM mess — blast radius estimation, confidence checks on correlations, mandatory human approval for anything destructive.

You'll see all of this live. An agent diagnosing a real pod failure, getting policy-checked, executing with a temporary token, and leaving an audit trail you can trace from the original prompt all the way to the cluster action. Then I'll show what happens when the agent tries something it shouldn't — and how the system catches it cleanly.

This is not a talk about how AI will replace oncall. It's about what actually happens when you hand an AI agent the keys to your cluster, and the engineering required to make that safe.

## Target Conference
- MCP Dev Summit Bengaluru 2026
- MCP Dev Summit Mumbai 2026 (co-located with KubeCon India)

## Session Length
25 minutes

## CFP Track Alignment
- Primary: Security models, permissioning, sandboxing, observability, governance, and operating MCP systems in production environments
- Secondary: Practical implementations, design patterns, tools, integrations, and real-world experiences building MCP servers

## Why This Will Be Selected
1. Directly addresses the #1 gap in the 2026 MCP roadmap (authentication/authorization) with a working implementation
2. Opens with a real staging security incident — reviewers remember failure stories
3. The 3 AM wrong-correlation incident adds emotional weight and operational credibility
4. References tools the audience already uses (OPA, K8s RBAC, OTel) applied to MCP
5. Every claim is backed by a live demo, not slides
6. Evaluation criteria match: high Content (production architecture), high Originality (OPA + MCP combo), high Relevance (security is top priority), strong Speaker fit (10yr DevOps architect)
