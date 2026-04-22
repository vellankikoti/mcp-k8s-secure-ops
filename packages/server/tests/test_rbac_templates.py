from __future__ import annotations

from secureops_server.tokens.rbac_templates import (
    per_action_sa_name,
    rbac_manifests_for_action,
)


def test_per_action_sa_name_stable_and_safe():
    name = per_action_sa_name(action_verb="restart", kind="Deployment", namespace="prod")
    assert name == "secureops-action-restart-deployment-prod"
    assert len(name) <= 63


def test_rbac_manifests_for_restart_deployment():
    m = rbac_manifests_for_action(action_verb="restart", kind="Deployment", namespace="prod")
    kinds = [r["kind"] for r in m]
    assert "ServiceAccount" in kinds
    assert "Role" in kinds
    assert "RoleBinding" in kinds
    role = next(r for r in m if r["kind"] == "Role")
    rules = role["rules"]
    assert any("deployments" in rr["resources"] and "patch" in rr["verbs"] for rr in rules)


def test_rbac_manifests_for_scale_uses_scale_subresource():
    m = rbac_manifests_for_action(action_verb="scale", kind="Deployment", namespace="prod")
    role = next(r for r in m if r["kind"] == "Role")
    rules = role["rules"]
    assert any("deployments/scale" in rr["resources"] for rr in rules)
