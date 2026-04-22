from __future__ import annotations

from secureops_server.context import GuardedContext
from secureops_server.models import K8sRef


async def list_workloads(
    ctx: GuardedContext,
    namespace: str | None = None,
    kind: str | None = None,
) -> list[K8sRef]:
    k8s = ctx.k8s
    refs: list[K8sRef] = []
    wanted_kinds = {kind} if kind else {"Deployment", "StatefulSet", "DaemonSet"}

    if "Deployment" in wanted_kinds:
        if namespace:
            dl = await k8s.apps_v1.list_namespaced_deployment(namespace=namespace)
        else:
            dl = await k8s.apps_v1.list_deployment_for_all_namespaces()
        for d in dl.items:
            refs.append(
                K8sRef(
                    kind="Deployment",
                    api_version="apps/v1",
                    namespace=d.metadata.namespace,
                    name=d.metadata.name,
                    uid=d.metadata.uid,
                )
            )

    if "StatefulSet" in wanted_kinds and not namespace:
        sl = await k8s.apps_v1.list_stateful_set_for_all_namespaces()
        for s in sl.items:
            refs.append(
                K8sRef(
                    kind="StatefulSet",
                    api_version="apps/v1",
                    namespace=s.metadata.namespace,
                    name=s.metadata.name,
                    uid=s.metadata.uid,
                )
            )

    if "DaemonSet" in wanted_kinds and not namespace:
        dsl = await k8s.apps_v1.list_daemon_set_for_all_namespaces()
        for ds in dsl.items:
            refs.append(
                K8sRef(
                    kind="DaemonSet",
                    api_version="apps/v1",
                    namespace=ds.metadata.namespace,
                    name=ds.metadata.name,
                    uid=ds.metadata.uid,
                )
            )

    return refs
