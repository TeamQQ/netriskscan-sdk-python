"""Typed models for ``GET /v1/usage``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class UsagePeriod:
    start: str
    end: str

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> UsagePeriod:
        return cls(start=data["start"], end=data["end"])


@dataclass(frozen=True)
class UsageUnits:
    used: int
    limit: int
    remaining: int

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> UsageUnits:
        return cls(used=data["used"], limit=data["limit"], remaining=data["remaining"])


@dataclass(frozen=True)
class UsageRateLimit:
    requests_per_minute: int

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> UsageRateLimit:
        return cls(requests_per_minute=data["requestsPerMinute"])


@dataclass(frozen=True)
class UsageResult:
    """The full response of ``GET /v1/usage``. Requires an API key -- there is
    no anonymous account to report usage for.
    """

    plan: str
    period: UsagePeriod
    units: UsageUnits
    rate_limit: UsageRateLimit

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> UsageResult:
        return cls(
            plan=data["plan"],
            period=UsagePeriod._from_json(data["period"]),
            units=UsageUnits._from_json(data["units"]),
            rate_limit=UsageRateLimit._from_json(data["rateLimit"]),
        )
