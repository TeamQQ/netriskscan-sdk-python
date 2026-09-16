"""Official Python SDK for the NetRiskScan IP Risk & Network Intelligence API."""

from netriskscan._internal import API_KEY_ENV_VAR, DEFAULT_BASE_URL
from netriskscan._meta_registry import get_response_meta
from netriskscan.async_client import AsyncNetRiskScan
from netriskscan.client import NetRiskScan
from netriskscan.exceptions import (
    ApiError,
    AuthenticationError,
    ConfigurationError,
    FeatureNotAvailableError,
    NetRiskScanError,
    NetworkError,
    NotFoundError,
    QuotaExceededError,
    RateLimitError,
    TimeoutError,
    ValidationError,
)
from netriskscan.models import (
    AnonymousUsage,
    IpFlags,
    IpLocation,
    IpNetwork,
    IpRisk,
    IpRiskResult,
    QuotaInfo,
    RateLimitInfo,
    ResponseMeta,
    RiskReason,
    TorInfo,
    UsagePeriod,
    UsageRateLimit,
    UsageResult,
    UsageUnits,
)
from netriskscan.version import VERSION

__version__ = VERSION

__all__ = [
    "NetRiskScan",
    "AsyncNetRiskScan",
    "get_response_meta",
    "API_KEY_ENV_VAR",
    "DEFAULT_BASE_URL",
    "__version__",
    # Errors
    "NetRiskScanError",
    "ConfigurationError",
    "ValidationError",
    "AuthenticationError",
    "RateLimitError",
    "QuotaExceededError",
    "NotFoundError",
    "FeatureNotAvailableError",
    "ApiError",
    "TimeoutError",
    "NetworkError",
    # Models
    "IpRiskResult",
    "IpRisk",
    "RiskReason",
    "IpNetwork",
    "IpFlags",
    "IpLocation",
    "TorInfo",
    "AnonymousUsage",
    "UsageResult",
    "UsagePeriod",
    "UsageUnits",
    "UsageRateLimit",
    "ResponseMeta",
    "RateLimitInfo",
    "QuotaInfo",
]
