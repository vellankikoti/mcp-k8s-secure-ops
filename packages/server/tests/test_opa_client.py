from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock
from secureops_server.policy.opa_client import OPAClient


async def test_opa_allow_true(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://localhost:8181/v1/data/secureops/allow",
        method="POST",
        json={"result": {"allow": True, "reasons": [], "matched": ["secureops.allow.default"]}},
    )
    c = OPAClient("http://localhost:8181")
    d = await c.evaluate_allow(input_doc={"tool": "restart_deployment"})
    assert d.allow is True
    assert d.matched_policies == ["secureops.allow.default"]


async def test_opa_allow_false_with_reasons(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url="http://localhost:8181/v1/data/secureops/allow",
        method="POST",
        json={
            "result": {
                "allow": False,
                "reasons": ["prod_scale_zero"],
                "matched": ["secureops.allow.prod_scale_zero"],
            }
        },
    )
    c = OPAClient("http://localhost:8181")
    d = await c.evaluate_allow(input_doc={"tool": "scale_workload", "parameters": {"replicas": 0}})
    assert d.allow is False
    assert "prod_scale_zero" in d.reasons


async def test_opa_unavailable_raises_specific_error():
    c = OPAClient("http://127.0.0.1:1")  # guaranteed unreachable
    with pytest.raises(RuntimeError, match="opa_unavailable"):
        await c.evaluate_allow(input_doc={})
