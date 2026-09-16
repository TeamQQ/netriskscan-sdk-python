"""Shared, transport-agnostic plumbing used by both the sync and async client.

Nothing in this module touches the network -- it only builds requests,
parses responses/errors, and computes retry/backoff decisions. Keeping this
logic here (instead of duplicated between ``client.py`` and
``async_client.py``) is what lets the sync and async clients share one
implementation of the request/response contract.
"""

from __future__ import annotations

import json
import os
import random
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from netriskscan.exceptions import (
    ApiError,
    AuthenticationError,
    ConfigurationError,
    FeatureNotAvailableError,
    NotFoundError,
    QuotaExceededError,
    RateLimitError,
    ValidationError,
)
from netriskscan.models.meta import QuotaInfo, RateLimitInfo, ResponseMeta

DEFAULT_BASE_URL = "https://api.netriskscan.com"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_MAX_RETRY_DELAY = 10.0
API_KEY_ENV_VAR = "NETRISKSCAN_API_KEY"

# 502/504 are not currently observed from the NetRiskScan application itself
# (only 503 `temporarily_unavailable` is documented/implemented), but they are
# included here defensively for the reverse-proxy/gateway layer in front of
# it, matching the official JS SDK's retry policy.
RETRYABLE_STATUS_CODES = frozenset({429, 502, 503, 504})
RETRYABLE_METHODS = frozenset({"GET", "HEAD"})

_BASE_DELAY_MS = 250
_JITTER_RATIO = 0.25


def resolve_api_key(explicit: str | None) -> str | None:
    """Resolve the effective API key: explicit constructor argument, then the
    ``NETRISKSCAN_API_KEY`` environment variable, then anonymous (``None``).

    An explicit empty/whitespace-only string is treated as a configuration
    mistake (not as "use anonymous mode"), since that is almost always an
    unset variable interpolated into the argument by the caller.
    """
    if explicit is not None:
        if not explicit.strip():
            raise ConfigurationError(
                "api_key must not be empty or whitespace; omit it entirely for anonymous access"
            )
        return explicit
    env_value = os.environ.get(API_KEY_ENV_VAR)
    if env_value is not None and env_value.strip():
        return env_value
    return None


def normalize_base_url(base_url: str | None) -> str:
    value = base_url if base_url is not None else DEFAULT_BASE_URL
    if not value.strip():
        raise ConfigurationError("base_url must not be empty")
    return value.rstrip("/")


def validate_positive_number(name: str, value: float) -> float:
    if value <= 0:
        raise ConfigurationError(f"{name} must be a positive number, got {value!r}")
    return value


def normalize_ip(ip: str) -> str:
    """Trim the address and reject only definitely-invalid input.

    This SDK deliberately does not re-implement strict IP syntax validation:
    the server accepts some lenient/shorthand forms (for example octal
    octets) that Python's standard :mod:`ipaddress` module would reject.
    Rejecting client-side on a stricter rule than the server's own parser
    would produce false negatives for addresses the API actually accepts, so
    syntax validation is left entirely to the server's ``400 invalid_ip``
    response -- the SDK only guards against empty input, which can never be
    valid and would otherwise turn into a confusing ``.../ip-risk/`` request.
    """
    trimmed = ip.strip() if isinstance(ip, str) else ""
    if not trimmed:
        raise ValidationError("ip must not be empty", code="invalid_ip")
    return trimmed


def build_ip_risk_url(base_url: str, ip: str) -> str:
    return f"{base_url}/v1/ip-risk/{quote(normalize_ip(ip), safe='')}"


def build_usage_url(base_url: str) -> str:
    return f"{base_url}/v1/usage"


def build_headers(
    api_key: str | None,
    user_agent: str,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": user_agent}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if extra:
        headers.update(extra)
    return headers


def _parse_int_header(headers: Mapping[str, str], name: str) -> int | None:
    value = headers.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def parse_response_meta(status: int, headers: Mapping[str, str]) -> ResponseMeta:
    return ResponseMeta(
        status=status,
        request_id=headers.get("X-Request-Id"),
        scoring_version=headers.get("X-NetRiskScan-Scoring-Version"),
        rate_limit=RateLimitInfo(
            limit=_parse_int_header(headers, "X-RateLimit-Limit"),
            remaining=_parse_int_header(headers, "X-RateLimit-Remaining"),
            reset=_parse_int_header(headers, "X-RateLimit-Reset"),
        ),
        quota=QuotaInfo(
            limit=_parse_int_header(headers, "X-Quota-Limit"),
            used=_parse_int_header(headers, "X-Quota-Used"),
            remaining=_parse_int_header(headers, "X-Quota-Remaining"),
        ),
    )


def parse_retry_after(headers: Mapping[str, str]) -> float | None:
    """Parse ``Retry-After`` as delta-seconds only (the server always sends an
    integer number of seconds for this API); an HTTP-date form is not
    produced by this API and is deliberately not guessed at.
    """
    value = headers.get("Retry-After")
    if value is None:
        return None
    if not re.fullmatch(r"\d+", value.strip()):
        return None
    seconds = int(value.strip())
    return float(seconds) if seconds >= 0 else None


def parse_error_response(
    status: int,
    headers: Mapping[str, str],
    body: bytes,
) -> Exception:
    """Build the appropriate exception for a non-2xx HTTP response."""
    code: str | None = None
    message = f"NetRiskScan API request failed with status {status}"
    request_id = headers.get("X-Request-Id")
    extra: dict[str, Any] = {}

    try:
        parsed = json.loads(body) if body else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        parsed = {}

    error_body = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(error_body, dict):
        code = error_body.get("code")
        message = error_body.get("message", message)
        request_id = error_body.get("requestId", request_id)
        # Extra fields present only on the anonymous daily-limit 429 superset envelope.
        for key in ("dailyLimit", "used", "remaining", "resetAt", "signupUrl"):
            if key in error_body:
                extra[key] = error_body[key]

    retry_after = parse_retry_after(headers)
    rate_limit = RateLimitInfo(
        limit=_parse_int_header(headers, "X-RateLimit-Limit"),
        remaining=_parse_int_header(headers, "X-RateLimit-Remaining"),
        reset=_parse_int_header(headers, "X-RateLimit-Reset"),
    )
    quota = QuotaInfo(
        limit=_parse_int_header(headers, "X-Quota-Limit"),
        used=_parse_int_header(headers, "X-Quota-Used"),
        remaining=_parse_int_header(headers, "X-Quota-Remaining"),
    )

    if status == 400:
        return ValidationError(message, status_code=status, code=code, request_id=request_id)
    if status in (401, 403):
        return AuthenticationError(message, status_code=status, code=code, request_id=request_id)
    if status == 404:
        if code == "feature_not_available":
            return FeatureNotAvailableError(
                message, status_code=status, code=code, request_id=request_id
            )
        return NotFoundError(message, status_code=status, code=code, request_id=request_id)
    if status == 429:
        if code in ("quota_exceeded", "anonymous_daily_limit_reached"):
            return QuotaExceededError(
                message,
                status_code=status,
                code=code,
                request_id=request_id,
                retry_after=retry_after,
                rate_limit=rate_limit,
                quota=quota,
                daily_limit=extra.get("dailyLimit"),
                used=extra.get("used"),
                remaining=extra.get("remaining"),
                reset_at=extra.get("resetAt"),
                signup_url=extra.get("signupUrl"),
            )
        return RateLimitError(
            message,
            status_code=status,
            code=code,
            request_id=request_id,
            retry_after=retry_after,
            rate_limit=rate_limit,
        )
    return ApiError(message, status_code=status, code=code, request_id=request_id)


def is_retryable_method(method: str) -> bool:
    return method.upper() in RETRYABLE_METHODS


def is_retryable_status(status: int) -> bool:
    return status in RETRYABLE_STATUS_CODES


def compute_backoff_seconds(attempt: int) -> float:
    """Exponential backoff with jitter, used when the server did not send a
    usable ``Retry-After`` header. ``attempt`` is 0-indexed (0 = delay before
    the first retry).
    """
    step_ms: float = _BASE_DELAY_MS * (2**attempt)
    jitter_ms: float = random.random() * step_ms * _JITTER_RATIO
    return (step_ms + jitter_ms) / 1000.0
