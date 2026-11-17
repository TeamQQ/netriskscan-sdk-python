from __future__ import annotations

import httpx
import pytest

from netriskscan import AsyncNetRiskScan, NetRiskScan, ValidationError, get_response_meta

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


@pytest.mark.parametrize("legacy", [False, True], ids=["schema-1.6.0", "legacy"])
async def test_schema_160_fields_match_sync_with_one_request(schema_160_body, legacy):
    body = SAMPLE_IP_RISK_BODY if legacy else schema_160_body
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return json_response(200, body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        async with AsyncNetRiskScan(http_client=http_client) as client:
            result = await client.ip_risk(body["ip"])

    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].url.path == f"/v1/ip-risk/{body['ip']}"
    assert result.network.domain == (None if legacy else "operator.example")
    assert result.network.range == (None if legacy else "192.0.2.0/24")
    assert result.location is not None
    assert result.location.continent_code == (None if legacy else "NA")
    assert result.location.continent == (None if legacy else "North America")
    assert result.location.postal_code == (None if legacy else "00501")
    assert result.location.latitude == (None if legacy else 40.81)
    assert result.location.longitude == (None if legacy else -73.04)

    requests.clear()
    with httpx.Client(transport=httpx.MockTransport(handler)) as sync_http_client:
        with NetRiskScan(http_client=sync_http_client) as sync_client:
            assert result == sync_client.ip_risk(body["ip"])
    assert len(requests) == 1
