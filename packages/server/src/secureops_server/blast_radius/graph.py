from __future__ import annotations

from typing import Any

from secureops_server.models import K8sRef


def _selector_matches(svc_or_pdb_selector: dict[str, str], pod_labels: dict[str, str]) -> bool:
    if not svc_or_pdb_selector:
        return False
    return all(pod_labels.get(k) == v for k, v in svc_or_pdb_selector.items())


async def services_selecting(k8s: Any, namespace: str, pod_labels: dict[str, str]) -> list[K8sRef]:
    svcs = await k8s.core_v1.list_namespaced_service(namespace=namespace)
    out: list[K8sRef] = []
    for s in svcs.items:
        sel = getattr(s.spec, "selector", None) or {}
        if _selector_matches(sel, pod_labels):
            out.append(
                K8sRef(
                    kind="Service",
                    api_version="v1",
                    namespace=s.metadata.namespace,
                    name=s.metadata.name,
                    uid=s.metadata.uid,
                )
            )
    return out


async def pvcs_mounted_by_deployment(deployment: Any) -> list[K8sRef]:
    volumes = getattr(deployment.spec.template.spec, "volumes", None) or []
    out: list[K8sRef] = []
    for v in volumes:
        pvc = getattr(v, "persistent_volume_claim", None)
        if pvc is None:
            continue
        name = getattr(pvc, "claim_name", None)
        if name:
            out.append(
                K8sRef(
                    kind="PersistentVolumeClaim",
                    api_version="v1",
                    namespace=deployment.metadata.namespace,
                    name=name,
                )
            )
    return out


async def pdbs_matching(k8s: Any, namespace: str, pod_labels: dict[str, str]) -> list[K8sRef]:
    pdbs = await k8s.policy_v1.list_namespaced_pod_disruption_budget(namespace=namespace)
    out: list[K8sRef] = []
    for p in pdbs.items:
        sel = getattr(p.spec.selector, "match_labels", None) or {}
        if _selector_matches(sel, pod_labels):
            out.append(
                K8sRef(
                    kind="PodDisruptionBudget",
                    api_version="policy/v1",
                    namespace=p.metadata.namespace,
                    name=p.metadata.name,
                    uid=p.metadata.uid,
                )
            )
    return out


async def hpas_for_deployment(k8s: Any, namespace: str, deployment_name: str) -> list[K8sRef]:
    hpas = await k8s.autoscaling_v2.list_namespaced_horizontal_pod_autoscaler(namespace=namespace)
    out: list[K8sRef] = []
    for h in hpas.items:
        ref = getattr(h.spec.scale_target_ref, "name", None)
        kind = getattr(h.spec.scale_target_ref, "kind", None)
        if kind == "Deployment" and ref == deployment_name:
            out.append(
                K8sRef(
                    kind="HorizontalPodAutoscaler",
                    api_version="autoscaling/v2",
                    namespace=h.metadata.namespace,
                    name=h.metadata.name,
                    uid=h.metadata.uid,
                )
            )
    return out
