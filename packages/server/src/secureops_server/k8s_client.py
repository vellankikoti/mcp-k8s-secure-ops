from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kubernetes_asyncio import client as k8s_client
from kubernetes_asyncio import config as k8s_config


@dataclass
class K8sClients:
    core_v1: Any
    apps_v1: Any
    policy_v1: Any
    autoscaling_v2: Any
    networking_v1: Any
    api_client: Any


async def build_clients(kubeconfig: str | None = None) -> K8sClients:
    if kubeconfig:
        await k8s_config.load_kube_config(config_file=kubeconfig)
    else:
        try:
            await k8s_config.load_kube_config()
        except Exception:
            k8s_config.load_incluster_config()  # type: ignore[no-untyped-call]
    api = k8s_client.ApiClient()
    return K8sClients(
        core_v1=k8s_client.CoreV1Api(api),
        apps_v1=k8s_client.AppsV1Api(api),
        policy_v1=k8s_client.PolicyV1Api(api),
        autoscaling_v2=k8s_client.AutoscalingV2Api(api),
        networking_v1=k8s_client.NetworkingV1Api(api),
        api_client=api,
    )
