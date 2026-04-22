from __future__ import annotations

from typing import Any

from secureops_server.models import K8sRef, TrafficSnapshot


def _service_rps_query(svc: K8sRef) -> str:
    return (
        f'sum(rate(istio_requests_total{{destination_service_namespace="{svc.namespace}",'
        f'destination_service_name="{svc.name}"}}[5m]))'
    )


def _service_errors_query(svc: K8sRef) -> str:
    ns = svc.namespace
    name = svc.name
    total = (
        f"istio_requests_total{{"
        f'destination_service_namespace="{ns}",'
        f'destination_service_name="{name}"}}'
    )
    errors = (
        f"istio_requests_total{{"
        f'destination_service_namespace="{ns}",'
        f'destination_service_name="{name}",response_code=~"5.."}}'
    )
    return f"sum(rate({errors}[5m])) / clamp_min(sum(rate({total}[5m])), 1)"


def _service_p99_query(svc: K8sRef) -> str:
    return (
        f"histogram_quantile(0.99, sum by (le) (rate("
        f'istio_request_duration_milliseconds_bucket{{destination_service_namespace="{svc.namespace}",'
        f'destination_service_name="{svc.name}"}}[5m])))'
    )


def _first_value(result: list[dict[str, Any]], default: float = 0.0) -> float:
    if not result:
        return default
    val = result[0].get("value")
    if not val or len(val) < 2:
        return default
    try:
        return float(val[1])
    except (TypeError, ValueError):
        return default


async def snapshot_for_service(prom: Any, svc: K8sRef) -> TrafficSnapshot:
    if prom is None:
        return TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable")
    try:
        rps_r = await prom.query(_service_rps_query(svc))
        err_r = await prom.query(_service_errors_query(svc))
        p99_r = await prom.query(_service_p99_query(svc))
        return TrafficSnapshot(
            rps=_first_value(rps_r),
            error_rate=_first_value(err_r),
            p99_latency_ms=_first_value(p99_r),
            source="prometheus",
        )
    except Exception:
        return TrafficSnapshot(rps=0.0, error_rate=0.0, p99_latency_ms=0.0, source="unavailable")
