from __future__ import annotations

from typing import Any


def per_action_sa_name(*, action_verb: str, kind: str, namespace: str) -> str:
    raw = f"secureops-action-{action_verb}-{kind.lower()}-{namespace}"
    return raw[:63]


_VERB_TO_RULES: dict[str, list[dict[str, Any]]] = {
    "restart": [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "patch"]}],
    "scale": [
        {
            "apiGroups": ["apps"],
            "resources": ["deployments/scale"],
            "verbs": ["get", "patch", "update"],
        }
    ],
    "rollback": [
        {
            "apiGroups": ["apps"],
            "resources": ["deployments", "replicasets"],
            "verbs": ["get", "patch", "update"],
        }
    ],
    "cordon": [{"apiGroups": [""], "resources": ["nodes"], "verbs": ["get", "patch"]}],
    "drain": [
        {
            "apiGroups": [""],
            "resources": ["nodes", "pods", "pods/eviction"],
            "verbs": ["get", "list", "patch", "create", "delete"],
        }
    ],
    "evict": [{"apiGroups": [""], "resources": ["pods/eviction"], "verbs": ["create"]}],
}


def rbac_manifests_for_action(
    *, action_verb: str, kind: str, namespace: str
) -> list[dict[str, Any]]:
    if action_verb not in _VERB_TO_RULES:
        raise ValueError(f"unknown action verb: {action_verb}")
    sa = per_action_sa_name(action_verb=action_verb, kind=kind, namespace=namespace)
    role_name = f"{sa}-role"
    binding_name = f"{sa}-binding"
    return [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": sa, "namespace": namespace},
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": role_name, "namespace": namespace},
            "rules": _VERB_TO_RULES[action_verb],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": binding_name, "namespace": namespace},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": role_name,
            },
            "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": namespace}],
        },
    ]
