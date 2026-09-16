from __future__ import annotations

import httpx
import pytest

from netriskscan import (
    ApiError,
    AuthenticationError,
    FeatureNotAvailableError,
    NetRiskScan,
    NetworkError,
    NotFoundError,
    QuotaExceededError,
    RateLimitError,
    ValidationError,
)
from netriskscan import (
    TimeoutError as NetRiskScanTimeoutError,
)

from .conftest import json_response, make_sync_transport


def _client(handler, max_retries: int = 0) -> NetRiskScan:
    return NetRiskScan(
        api_key="nrs_live_test_key",
        max_retries=max_retries,
        http_client=httpx.Client(transport=make_sync_transport(handler)),
    )


def test_400_invalid_ip_raises_validation_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            400,
            {
                "error": {
                    "code": "invalid_ip",
                    "message": "not a valid IP address",
                    "requestId": "req_1",
                }
            },
        )

    with pytest.raises(ValidationError) as exc_info:
        _client(handler).ip_risk("not-an-ip")
    assert exc_info.value.code == "invalid_ip"
    assert exc_info.value.status_code == 400
    assert exc_info.value.request_id == "req_1"


def test_401_invalid_api_key_raises_authentication_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            401, {"error": {"code": "invalid_api_key", "message": "bad key", "requestId": "req_2"}}
        )

    with pytest.raises(AuthenticationError) as exc_info:
        _client(handler).ip_risk("8.8.8.8")
    assert exc_info.value.code == "invalid_api_key"


def test_403_api_key_disabled_raises_authentication_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            403,
            {"error": {"code": "api_key_disabled", "message": "disabled", "requestId": "req_3"}},
        )

    with pytest.raises(AuthenticationError) as exc_info:
        _client(handler).ip_risk("8.8.8.8")
    assert exc_info.value.code == "api_key_disabled"


def test_404_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            404, {"error": {"code": "not_found", "message": "no route", "requestId": "req_4"}}
        )

    with pytest.raises(NotFoundError):
        _client(handler).ip_risk("8.8.8.8")


def test_404_feature_not_available():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            404,
            {
                "error": {
                    "code": "feature_not_available",
                    "message": "not open yet",
                    "requestId": "req_5",
                }
            },
        )

    with pytest.raises(FeatureNotAvailableError):
        _client(handler).ip_risk("8.8.8.8")


def test_429_rate_limit_exceeded_carries_retry_after():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            429,
            {
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "slow down",
                    "requestId": "req_6",
                }
            },
            headers={"Retry-After": "5"},
        )

    with pytest.raises(RateLimitError) as exc_info:
        _client(handler).ip_risk("8.8.8.8")
    assert exc_info.value.retry_after == 5.0
    assert not isinstance(exc_info.value, QuotaExceededError)


def test_429_quota_exceeded_is_a_distinct_subclass():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            429,
            {"error": {"code": "quota_exceeded", "message": "quota gone", "requestId": "req_7"}},
        )

    with pytest.raises(QuotaExceededError):
        _client(handler).ip_risk("8.8.8.8")


def test_429_anonymous_daily_limit_reached_exposes_extra_fields():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            429,
            {
                "error": {
                    "code": "anonymous_daily_limit_reached",
                    "message": "daily limit reached",
                    "requestId": "req_8",
                    "dailyLimit": 30,
                    "used": 30,
                    "remaining": 0,
                    "resetAt": "2026-09-17T00:00:00Z",
                    "signupUrl": "https://www.netriskscan.com/",
                },
            },
        )

    client = NetRiskScan(http_client=httpx.Client(transport=make_sync_transport(handler)))
    with pytest.raises(QuotaExceededError) as exc_info:
        client.ip_risk("8.8.8.8")
    assert exc_info.value.daily_limit == 30
    assert exc_info.value.remaining == 0
    assert exc_info.value.signup_url == "https://www.netriskscan.com/"


def test_503_temporarily_unavailable_is_generic_api_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return json_response(
            503,
            {
                "error": {
                    "code": "temporarily_unavailable",
                    "message": "try again",
                    "requestId": "req_9",
                }
            },
        )

    with pytest.raises(ApiError):
        _client(handler).ip_risk("8.8.8.8")


def test_unparseable_error_body_still_raises_with_generic_message():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"not json")

    with pytest.raises(ApiError) as exc_info:
        _client(handler).ip_risk("8.8.8.8")
    assert exc_info.value.status_code == 500


def test_invalid_json_success_body_raises_network_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"not json", headers={"content-type": "application/json"}
        )

    with pytest.raises(NetworkError):
        _client(handler).ip_risk("8.8.8.8")


def test_timeout_is_never_retried():
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        raise httpx.ReadTimeout("timed out", request=request)

    client = NetRiskScan(
        max_retries=3, http_client=httpx.Client(transport=make_sync_transport(handler))
    )
    with pytest.raises(NetRiskScanTimeoutError):
        client.ip_risk("8.8.8.8")
    assert attempts["count"] == 1


def test_transport_failure_is_retried_up_to_max_retries():
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        raise httpx.ConnectError("connection refused", request=request)

    client = NetRiskScan(
        max_retries=2, http_client=httpx.Client(transport=make_sync_transport(handler))
    )
    with pytest.raises(NetworkError):
        client.ip_risk("8.8.8.8")
    assert attempts["count"] == 3  # initial attempt + 2 retries


def test_400_is_never_retried():
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        return json_response(
            400, {"error": {"code": "invalid_ip", "message": "bad", "requestId": "req_x"}}
        )

    client = NetRiskScan(
        max_retries=3, http_client=httpx.Client(transport=make_sync_transport(handler))
    )
    with pytest.raises(ValidationError):
        client.ip_risk("bad-ip")
    assert attempts["count"] == 1
