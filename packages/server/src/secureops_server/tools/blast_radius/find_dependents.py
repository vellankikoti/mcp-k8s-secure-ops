from __future__ import annotations

from secureops_server.blast_radius.graph import services_selecting
from secureops_server.context import GuardedContext
from secureops_server.models import K8sRef


async def find_dependents(ctx: GuardedContext, target: K8sRef) -> list[K8sRef]:
    if target.kind != "Deployment" or target.namespace is None:
        raise ValueError("find_dependents supports Deployment targets with a namespace")
    dep = await ctx.k8s.apps_v1.read_namespaced_deployment(
        name=target.name, namespace=target.namespace
    )
    pod_labels = dict(dep.spec.template.metadata.labels or {})
    svcs = await services_selecting(ctx.k8s, target.namespace, pod_labels)
    svc_names = {s.name for s in svcs}

    out: list[K8sRef] = []
    ingresses = await ctx.k8s.networking_v1.list_namespaced_ingress(namespace=target.namespace)
    for ing in ingresses.items:
        for rule in ing.spec.rules or []:
            http = getattr(rule, "http", None)
            if http is None:
                continue
            for path in http.paths or []:
                backend_svc = getattr(path.backend.service, "name", None)
                if backend_svc in svc_names:
                    out.append(
                        K8sRef(
                            kind="Ingress",
                            api_version="networking.k8s.io/v1",
                            namespace=ing.metadata.namespace,
                            name=ing.metadata.name,
                            uid=ing.metadata.uid,
                        )
                    )
                    break
    return out
