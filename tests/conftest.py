"""Shared test helpers.

Every test builds an ``httpx.Client``/``httpx.AsyncClient`` around an
``httpx.MockTransport`` -- CI never depends on the real NetRiskScan API.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Callable

import httpx
import pytest

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture(autouse=True)
def isolate_api_key_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep anonymous tests independent of credentials on the host machine."""
    monkeypatch.delenv("NETRISKSCAN_API_KEY", raising=False)


def json_response(
    status_code: int,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status_code,
        content=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json", **(headers or {})},
    )


def make_sync_transport(handler: Handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


SAMPLE_IP_RISK_BODY: dict[str, Any] = {
    "requestId": "req_abc12345",
    "ip": "8.8.8.8",
    "risk": {
        "index": 95,
        "band": "excellent",
        "assessmentGrade": "complete",
        "reasons": [],
    },
    "network": {
        "type": "public_infrastructure",
        "connectionType": "direct",
        "asn": "AS15169",
        "organization": "Google LLC",
        "profile": "public_dns_resolver",
        "service": "Google Public DNS",
    },
    "flags": {
        "proxy": False,
        "proxyType": None,
        "vpn": False,
        "tor": False,
        "datacenter": True,
        "scanner": False,
        "abuse": False,
        "searchCrawler": None,
        "searchCrawlerName": None,
    },
    "location": {
        "countryCode": "US",
        "country": "United States",
        "regionCode": None,
        "region": None,
        "city": None,
        "timeZone": "America/Chicago",
    },
}

SAMPLE_UNSCOREABLE_IP_RISK_BODY: dict[str, Any] = {
    "requestId": "req_def45678",
    "ip": "127.0.0.1",
    "risk": {"index": None, "band": None, "assessmentGrade": "insufficient", "reasons": []},
    "network": {
        "type": "unknown",
        "connectionType": "unknown",
        "asn": None,
        "organization": None,
    },
    "flags": {
        "proxy": None,
        "proxyType": None,
        "vpn": None,
        "tor": None,
        "datacenter": None,
        "scanner": None,
        "abuse": None,
        "searchCrawler": None,
        "searchCrawlerName": None,
    },
    "location": None,
}


@pytest.fixture
def schema_160_body() -> dict[str, Any]:
    """Synthetic unicast response, independent of live IP geolocation."""
    body = deepcopy(SAMPLE_IP_RISK_BODY)
    body["ip"] = "192.0.2.10"
    body["network"].update(domain="operator.example", range="192.0.2.0/24")
    body["location"].update(
        continentCode="NA",
        continent="North America",
        postalCode="00501",
        latitude=40.81,
        longitude=-73.04,
    )
    return body


SAMPLE_USAGE_BODY: dict[str, Any] = {
    "plan": "growth",
    "period": {"start": "2026-09-01T00:00:00Z", "end": "2026-10-01T00:00:00Z"},
    "units": {"used": 1200, "limit": 50000, "remaining": 48800},
    "rateLimit": {"requestsPerMinute": 120},
}
