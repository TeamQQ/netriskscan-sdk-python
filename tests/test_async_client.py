from __future__ import annotations

import httpx
import pytest

from netriskscan import AsyncNetRiskScan, ValidationError, get_response_meta

from .conftest import SAMPLE_IP_RISK_BODY, SAMPLE_USAGE_BODY, json_response


async def test_async_ip_risk_with_api_key():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return json_response(200, SAMPLE_IP_RISK_BODY)

    async with AsyncNetRiskScan(
        api_key="nrs_live_test_key",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    ) as client:
        result = await client.ip_risk("8.8.8.8")

    assert seen["auth"] == "Bearer nrs_live_test_key"
    assert result.risk.index == 95


async def test_async_ip_risk_anonymous():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(200, SAMPLE_IP_RISK_BODY)

    async with AsyncNetRiskScan(
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    ) as client:
        assert client.api_key is None
        result = await client.ip_risk("8.8.8.8")

    assert result.risk.band == "excellent"


async def test_async_usage_requires_api_key():
    async with AsyncNetRiskScan(
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: json_response(200, SAMPLE_USAGE_BODY))
        ),
    ) as client:
        with pytest.raises(ValidationError):
            await client.usage()


async def test_async_usage_with_api_key_and_meta():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            200,
            SAMPLE_USAGE_BODY,
            headers={
                "X-Quota-Limit": "50000",
                "X-Quota-Used": "1200",
                "X-Quota-Remaining": "48800",
            },
        )

    async with AsyncNetRiskScan(
        api_key="nrs_live_test_key",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    ) as client:
        result = await client.usage()

    meta = get_response_meta(result)
    assert meta is not None
    assert meta.quota.used == 1200


async def test_async_context_manager_closes_owned_client():
    owned_client = AsyncNetRiskScan()
    async with owned_client:
        assert owned_client._owns_client is True
    assert owned_client._client.is_closed is True
