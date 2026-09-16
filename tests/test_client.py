from __future__ import annotations

import httpx
import pytest

from netriskscan import (
    ConfigurationError,
    NetRiskScan,
    ValidationError,
    get_response_meta,
)

from .conftest import (
    SAMPLE_IP_RISK_BODY,
    SAMPLE_UNSCOREABLE_IP_RISK_BODY,
    SAMPLE_USAGE_BODY,
    json_response,
    make_sync_transport,
)


def test_ip_risk_ipv4_with_api_key_sends_bearer_header():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = request.url.path
        return json_response(200, SAMPLE_IP_RISK_BODY, headers={"X-Request-Id": "req_abc12345"})

    client = NetRiskScan(
        api_key="nrs_live_test_key",
        http_client=httpx.Client(transport=make_sync_transport(handler)),
    )
    result = client.ip_risk("8.8.8.8")

    assert seen["auth"] == "Bearer nrs_live_test_key"
    assert seen["path"] == "/v1/ip-risk/8.8.8.8"
    assert result.risk.index == 95
    assert result.risk.band == "excellent"
    assert result.network.asn == "AS15169"


def test_ip_risk_ipv6_round_trips():
    def handler(request: httpx.Request) -> httpx.Response:
        body = dict(SAMPLE_IP_RISK_BODY, ip="2001:4860:4860::8888")
        return json_response(200, body)

    client = NetRiskScan(http_client=httpx.Client(transport=make_sync_transport(handler)))
    result = client.ip_risk("2001:4860:4860::8888")

    assert result.ip == "2001:4860:4860::8888"


def test_ip_risk_anonymous_mode_sends_no_authorization_header():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        body = dict(SAMPLE_IP_RISK_BODY)
        body["usage"] = {
            "mode": "anonymous",
            "dailyLimit": 30,
            "used": 1,
            "remaining": 29,
            "resetAt": "2026-09-17T00:00:00Z",
        }
        return json_response(200, body)

    client = NetRiskScan(http_client=httpx.Client(transport=make_sync_transport(handler)))
    result = client.ip_risk("8.8.8.8")

    assert "auth" in seen and seen["auth"] is None
    assert result.usage is not None
    assert result.usage.daily_limit == 30


def test_unscoreable_address_is_a_success_not_an_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(200, SAMPLE_UNSCOREABLE_IP_RISK_BODY)

    client = NetRiskScan(http_client=httpx.Client(transport=make_sync_transport(handler)))
    result = client.ip_risk("127.0.0.1")

    assert result.risk.index is None
    assert result.risk.band is None
    assert result.risk.assessment_grade == "insufficient"
    assert result.flags.proxy is None  # unknown, never coerced to False
    assert result.location is None


def test_usage_requires_api_key_without_network_call():
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return json_response(200, SAMPLE_USAGE_BODY)

    client = NetRiskScan(http_client=httpx.Client(transport=make_sync_transport(handler)))
    with pytest.raises(ValidationError):
        client.usage()
    assert called["count"] == 0


def test_usage_with_api_key():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/usage"
        return json_response(
            200,
            SAMPLE_USAGE_BODY,
            headers={
                "X-Quota-Limit": "50000",
                "X-Quota-Used": "1200",
                "X-Quota-Remaining": "48800",
            },
        )

    client = NetRiskScan(
        api_key="nrs_live_test_key",
        http_client=httpx.Client(transport=make_sync_transport(handler)),
    )
    result = client.usage()

    assert result.plan == "growth"
    assert result.units.remaining == 48800
    meta = get_response_meta(result)
    assert meta is not None
    assert meta.quota.remaining == 48800


def test_empty_api_key_string_is_a_configuration_error():
    with pytest.raises(ConfigurationError):
        NetRiskScan(api_key="   ")


def test_api_key_env_var_used_when_not_passed_explicitly(monkeypatch):
    monkeypatch.setenv("NETRISKSCAN_API_KEY", "nrs_live_from_env")
    client = NetRiskScan(
        http_client=httpx.Client(
            transport=make_sync_transport(lambda r: json_response(200, SAMPLE_IP_RISK_BODY))
        )
    )
    assert client.api_key == "nrs_live_from_env"


def test_explicit_api_key_takes_precedence_over_env_var(monkeypatch):
    monkeypatch.setenv("NETRISKSCAN_API_KEY", "nrs_live_from_env")
    client = NetRiskScan(
        api_key="nrs_live_explicit",
        http_client=httpx.Client(
            transport=make_sync_transport(lambda r: json_response(200, SAMPLE_IP_RISK_BODY))
        ),
    )
    assert client.api_key == "nrs_live_explicit"


def test_no_api_key_and_no_env_var_is_anonymous(monkeypatch):
    monkeypatch.delenv("NETRISKSCAN_API_KEY", raising=False)
    client = NetRiskScan(
        http_client=httpx.Client(
            transport=make_sync_transport(lambda r: json_response(200, SAMPLE_IP_RISK_BODY))
        )
    )
    assert client.api_key is None


def test_base_url_override():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith("https://staging.example.com")
        return json_response(200, SAMPLE_IP_RISK_BODY)

    client = NetRiskScan(
        base_url="https://staging.example.com/",
        http_client=httpx.Client(transport=make_sync_transport(handler)),
    )
    client.ip_risk("8.8.8.8")


def test_context_manager_closes_only_the_client_it_created():
    injected = httpx.Client(
        transport=make_sync_transport(lambda r: json_response(200, SAMPLE_IP_RISK_BODY))
    )
    with NetRiskScan(http_client=injected) as client:
        assert client._owns_client is False
    assert injected.is_closed is False  # caller-supplied client is never closed for them

    owned_client = NetRiskScan()
    with owned_client:
        assert owned_client._owns_client is True
    assert owned_client._client.is_closed is True
