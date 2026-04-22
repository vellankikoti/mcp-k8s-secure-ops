from __future__ import annotations

from secureops_server.blast_radius.graph import pdbs_matching
from secureops_server.context import GuardedContext
from secureops_server.models import K8sRef, PDBViolation


async def check_pdb_impact(
    ctx: GuardedContext, target: K8sRef, target_available: int
) -> list[PDBViolation]:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("check_pdb_impact supports Deployment targets with a namespace")
    dep = await ctx.k8s.apps_v1.read_namespaced_deployment(
        name=target.name, namespace=target.namespace
    )
    pod_labels = dict(dep.spec.template.metadata.labels or {})
    pdb_refs = await pdbs_matching(ctx.k8s, target.namespace, pod_labels)
    if not pdb_refs:
        return []

    all_pdbs = await ctx.k8s.policy_v1.list_namespaced_pod_disruption_budget(
        namespace=target.namespace
    )
    name_to_pdb = {p.metadata.name: p for p in all_pdbs.items}

    violations: list[PDBViolation] = []
    for ref in pdb_refs:
        pdb = name_to_pdb.get(ref.name)
        if pdb is None:
            continue
        min_available = getattr(pdb.spec, "min_available", None)
        if isinstance(min_available, int) and target_available < min_available:
            violations.append(
                PDBViolation(
                    pdb=ref,
                    current_available=target_available,
                    min_available=min_available,
                )
            )
    return violations
