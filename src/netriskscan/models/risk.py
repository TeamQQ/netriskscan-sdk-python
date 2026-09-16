"""Typed models for ``GET /v1/ip-risk/{ip}``.

These are plain, immutable data holders -- not a scoring engine. The SDK never
recomputes ``risk.index``/``risk.band`` or derives flags from other fields;
every value here is exactly what the server returned. ``None`` means "unknown
/ insufficient evidence" and is never coerced to ``False`` or ``0``: for the
tri-state detection flags below, ``None`` is a distinct outcome from both
``True`` and ``False``. See the "Null is not False" section of the README.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _get(data: dict[str, Any], key: str) -> Any:
    return data.get(key)


@dataclass(frozen=True)
class RiskReason:
    """One factor that contributed to (or explains the absence of) a risk index.

    ``code`` is an open vocabulary: new codes may appear before this SDK
    version knows about them -- treat unrecognized values as informational.
    """

    code: str
    category: str
    severity: str

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> RiskReason:
        return cls(
            code=data["code"],
            category=data["category"],
            severity=data["severity"],
        )


@dataclass(frozen=True)
class IpRisk:
    """The risk assessment itself.

    ``index`` is a 0-100 *cleanliness* score -- higher means cleaner/more
    trustworthy, it is not a threat score. ``index`` and ``band`` are both
    ``None`` together exactly when the address cannot be scored at all (for
    example a private, loopback, or otherwise special-purpose address);
    ``assessment_grade`` is ``"insufficient"`` in that case. Never treat a
    ``None`` index as ``0`` -- ``0`` would mean "confidently the worst score,"
    which is a very different claim from "not scored."
    """

    index: int | None
    band: str | None
    assessment_grade: str
    reasons: list[RiskReason] = field(default_factory=list)

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> IpRisk:
        return cls(
            index=_get(data, "index"),
            band=_get(data, "band"),
            assessment_grade=data["assessmentGrade"],
            reasons=[RiskReason._from_json(r) for r in data.get("reasons") or []],
        )


@dataclass(frozen=True)
class IpNetwork:
    """Network classification for the address.

    ``profile`` and ``service`` are ``None`` both when the server omits them
    (no first-party record) and when it sends an explicit null -- both mean
    the same thing: nothing to report.
    """

    type: str | None
    connection_type: str | None
    asn: str | None
    organization: str | None
    profile: str | None = None
    service: str | None = None

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> IpNetwork:
        return cls(
            type=_get(data, "type"),
            connection_type=_get(data, "connectionType"),
            asn=_get(data, "asn"),
            organization=_get(data, "organization"),
            profile=_get(data, "profile"),
            service=_get(data, "service"),
        )


@dataclass(frozen=True)
class IpFlags:
    """Tri-state detection flags.

    Every boolean-ish field below is ``True`` (detected), ``False`` (checked,
    not detected), or ``None`` (unknown / not checked this round) -- three
    distinct outcomes. Collapsing ``None`` into ``False`` turns "we don't
    know" into "we checked and it's clean," which is not the same claim.

    ``proxy_type`` is populated only when ``proxy is True``.
    ``search_crawler_name`` is populated only when ``search_crawler is True``,
    and identifies the crawler's *operator* (e.g. "Google"), not the fetcher.
    ``search_crawler`` answers a narrower question than "is this a bot" --
    see ``scanner`` for behavioral bot/scanner detection, which is tracked
    independently.
    """

    proxy: bool | None
    proxy_type: str | None
    vpn: bool | None
    tor: bool | None
    datacenter: bool | None
    scanner: bool | None
    abuse: bool | None
    search_crawler: bool | None
    search_crawler_name: str | None

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> IpFlags:
        return cls(
            proxy=_get(data, "proxy"),
            proxy_type=_get(data, "proxyType"),
            vpn=_get(data, "vpn"),
            tor=_get(data, "tor"),
            datacenter=_get(data, "datacenter"),
            scanner=_get(data, "scanner"),
            abuse=_get(data, "abuse"),
            search_crawler=_get(data, "searchCrawler"),
            search_crawler_name=_get(data, "searchCrawlerName"),
        )


@dataclass(frozen=True)
class IpLocation:
    """Network-level geolocation (registration/routing), not device GPS."""

    country_code: str | None
    country: str | None
    region_code: str | None
    region: str | None
    city: str | None
    time_zone: str | None

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> IpLocation:
        return cls(
            country_code=_get(data, "countryCode"),
            country=_get(data, "country"),
            region_code=_get(data, "regionCode"),
            region=_get(data, "region"),
            city=_get(data, "city"),
            time_zone=_get(data, "timeZone"),
        )


@dataclass(frozen=True)
class TorInfo:
    """Present only when the address participates in the Tor network as a relay.

    ``is_exit`` carries the same fact as ``flags.tor``. ``is_bad_exit`` is
    tracked independently of ``is_exit``.
    """

    is_relay: bool
    is_exit: bool
    is_bad_exit: bool
    role: str

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> TorInfo:
        return cls(
            is_relay=data["isRelay"],
            is_exit=data["isExit"],
            is_bad_exit=data["isBadExit"],
            role=data["role"],
        )


@dataclass(frozen=True)
class AnonymousUsage:
    """Present only on anonymous (no API key) ``check`` responses."""

    mode: str
    daily_limit: int
    used: int
    remaining: int
    reset_at: str

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> AnonymousUsage:
        return cls(
            mode=data["mode"],
            daily_limit=data["dailyLimit"],
            used=data["used"],
            remaining=data["remaining"],
            reset_at=data["resetAt"],
        )


@dataclass(frozen=True)
class IpRiskResult:
    """The full response of ``GET /v1/ip-risk/{ip}``."""

    request_id: str
    ip: str
    risk: IpRisk
    network: IpNetwork
    flags: IpFlags
    location: IpLocation | None
    tor: TorInfo | None = None
    usage: AnonymousUsage | None = None

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> IpRiskResult:
        location_data = data.get("location")
        tor_data = data.get("tor")
        usage_data = data.get("usage")
        return cls(
            request_id=data["requestId"],
            ip=data["ip"],
            risk=IpRisk._from_json(data["risk"]),
            network=IpNetwork._from_json(data["network"]),
            flags=IpFlags._from_json(data["flags"]),
            location=IpLocation._from_json(location_data) if location_data else None,
            tor=TorInfo._from_json(tor_data) if tor_data else None,
            usage=AnonymousUsage._from_json(usage_data) if usage_data else None,
        )
