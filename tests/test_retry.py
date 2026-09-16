from __future__ import annotations

import httpx
import pytest

from netriskscan import NetRiskScan, RateLimitError

from .conftest import SAMPLE_IP_RISK_BODY, json_response, make_sync_transport


def test_429_with_short_retry_after_succeeds_on_retry():
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return json_response(
                429,
                {
                    "error": {
                        "code": "rate_limit_exceeded",
                        "message": "slow down",
                        "requestId": "req_1",
                    }
                },
                headers={"Retry-After": "0"},
            )
        return json_response(200, SAMPLE_IP_RISK_BODY)

    client = NetRiskScan(
        max_retries=2, http_client=httpx.Client(transport=make_sync_transport(handler))
    )
    result = client.ip_risk("8.8.8.8")

    assert attempts["count"] == 2
    assert result.risk.index == 95


def test_503_is_retried_and_can_succeed():
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        if attempts["count"] < 3:
            return json_response(
                503,
                {
                    "error": {
                        "code": "temporarily_unavailable",
                        "message": "retry",
                        "requestId": "req_2",
                    }
                },
            )
        return json_response(200, SAMPLE_IP_RISK_BODY)

    client = NetRiskScan(
        max_retries=3, http_client=httpx.Client(transport=make_sync_transport(handler))
    )
    result = client.ip_risk("8.8.8.8")

    assert attempts["count"] == 3
    assert result.risk.index == 95


def test_retry_after_exceeding_max_retry_delay_gives_up_immediately():
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        return json_response(
            429,
            {
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "slow down",
                    "requestId": "req_3",
                }
            },
            headers={"Retry-After": "3600"},
        )

    client = NetRiskScan(
        max_retries=3,
        max_retry_delay=10.0,
        http_client=httpx.Client(transport=make_sync_transport(handler)),
    )
    with pytest.raises(RateLimitError) as exc_info:
        client.ip_risk("8.8.8.8")

    assert attempts["count"] == 1  # never slept for an hour; gave up on the first response
    assert exc_info.value.retry_after == 3600.0


def test_max_retries_zero_never_retries():
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        return json_response(
            429,
            {
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": "slow down",
                    "requestId": "req_4",
                }
            },
        )

    client = NetRiskScan(
        max_retries=0, http_client=httpx.Client(transport=make_sync_transport(handler))
    )
    with pytest.raises(RateLimitError):
        client.ip_risk("8.8.8.8")
    assert attempts["count"] == 1
