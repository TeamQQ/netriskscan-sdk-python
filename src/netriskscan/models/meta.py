"""Response metadata: rate limit / quota headers and request id.

These come from HTTP response headers, not the JSON body, so they are kept
out-of-band from the result objects themselves (see
:func:`netriskscan.get_response_meta`) rather than bolted onto every model as
an extra field nobody asked for.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitInfo:
    """Parsed ``X-RateLimit-*`` headers. Any field is ``None`` when the header
    was absent -- never coerced to ``0``, which would be a real (very low) limit.
    """

    limit: int | None = None
    remaining: int | None = None
    reset: int | None = None  # Unix seconds


@dataclass(frozen=True)
class QuotaInfo:
    """Parsed ``X-Quota-*`` headers. ``None`` means the header was absent."""

    limit: int | None = None
    used: int | None = None
    remaining: int | None = None


@dataclass(frozen=True)
class ResponseMeta:
    """Out-of-band metadata for a single HTTP response."""

    status: int
    request_id: str | None = None
    scoring_version: str | None = None
    rate_limit: RateLimitInfo = RateLimitInfo()
    quota: QuotaInfo = QuotaInfo()
