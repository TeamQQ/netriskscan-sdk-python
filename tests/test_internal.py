from __future__ import annotations

import pytest

from netriskscan._internal import (
    build_ip_risk_url,
    normalize_base_url,
    normalize_ip,
    parse_response_meta,
    parse_retry_after,
    resolve_api_key,
)
from netriskscan.exceptions import ConfigurationError, ValidationError


def test_build_ip_risk_url_percent_encodes_ipv6():
    url = build_ip_risk_url("https://api.netriskscan.com", "2001:4860:4860::8888")
    assert url == "https://api.netriskscan.com/v1/ip-risk/2001%3A4860%3A4860%3A%3A8888"


def test_build_ip_risk_url_ipv4():
    url = build_ip_risk_url("https://api.netriskscan.com", "8.8.8.8")
    assert url == "https://api.netriskscan.com/v1/ip-risk/8.8.8.8"


def test_normalize_ip_trims_whitespace():
    assert normalize_ip("  8.8.8.8  ") == "8.8.8.8"


def test_normalize_ip_rejects_empty_string():
    with pytest.raises(ValidationError) as exc_info:
        normalize_ip("   ")
    assert exc_info.value.code == "invalid_ip"


def test_normalize_base_url_strips_trailing_slash():
    assert normalize_base_url("https://api.netriskscan.com/") == "https://api.netriskscan.com"


def test_normalize_base_url_defaults_when_none():
    assert normalize_base_url(None) == "https://api.netriskscan.com"


def test_normalize_base_url_rejects_empty_string():
    with pytest.raises(ConfigurationError):
        normalize_base_url("   ")


def test_resolve_api_key_explicit_wins():
    assert resolve_api_key("nrs_live_x") == "nrs_live_x"


def test_resolve_api_key_none_is_anonymous(monkeypatch):
    monkeypatch.delenv("NETRISKSCAN_API_KEY", raising=False)
    assert resolve_api_key(None) is None


def test_resolve_api_key_reads_env_var(monkeypatch):
    monkeypatch.setenv("NETRISKSCAN_API_KEY", "nrs_live_env")
    assert resolve_api_key(None) == "nrs_live_env"


def test_resolve_api_key_rejects_whitespace_only_explicit_value():
    with pytest.raises(ConfigurationError):
        resolve_api_key("   ")


def test_parse_retry_after_integer_seconds():
    assert parse_retry_after({"Retry-After": "12"}) == 12.0


def test_parse_retry_after_missing_header():
    assert parse_retry_after({}) is None


def test_parse_retry_after_ignores_http_date_form():
    # This API always sends delta-seconds; an HTTP-date is not produced and
    # deliberately not guessed at rather than mis-parsed.
    assert parse_retry_after({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}) is None


def test_parse_response_meta_missing_headers_are_none_not_zero():
    meta = parse_response_meta(200, {})
    assert meta.rate_limit.limit is None
    assert meta.rate_limit.remaining is None
    assert meta.quota.used is None
    assert meta.request_id is None


def test_parse_response_meta_reads_all_headers():
    headers = {
        "X-RateLimit-Limit": "120",
        "X-RateLimit-Remaining": "119",
        "X-RateLimit-Reset": "1234567890",
        "X-Quota-Limit": "50000",
        "X-Quota-Used": "1",
        "X-Quota-Remaining": "49999",
        "X-Request-Id": "req_xyz",
        "X-NetRiskScan-Scoring-Version": "risk-v4.35",
    }
    meta = parse_response_meta(200, headers)
    assert meta.rate_limit.limit == 120
    assert meta.rate_limit.remaining == 119
    assert meta.rate_limit.reset == 1234567890
    assert meta.quota.limit == 50000
    assert meta.request_id == "req_xyz"
    assert meta.scoring_version == "risk-v4.35"
