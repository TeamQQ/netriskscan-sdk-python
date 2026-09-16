"""Exception hierarchy for the NetRiskScan SDK.

The `/v1` API returns a flat error envelope: ``{"error": {"code", "message",
"requestId"}}``. ``code`` is an open string vocabulary (the server may add new
codes over time), so every exception keeps the raw ``code`` string alongside
its Python type -- switch on ``code`` for fine-grained handling, or on the
exception class for coarse handling.
"""

from __future__ import annotations

from typing import Any


class NetRiskScanError(Exception):
    """Base class for every error raised by this SDK."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.request_id = request_id

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"{type(self).__name__}(message={self.message!r}, "
            f"status_code={self.status_code!r}, code={self.code!r}, "
            f"request_id={self.request_id!r})"
        )


class ConfigurationError(NetRiskScanError):
    """Raised for invalid client configuration (bad options passed to the constructor).

    Never carries request details: this is raised before any network call is made.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)


class ValidationError(NetRiskScanError):
    """Raised for invalid input, either caught client-side before a request is
    sent (no unit is spent), or returned by the server as an HTTP 400.

    Server-side codes mapped here: ``invalid_ip``, ``invalid_request``,
    ``unsupported_parameter``.
    """


class AuthenticationError(NetRiskScanError):
    """Raised for HTTP 401/403 responses about the API key itself.

    Server-side codes mapped here: ``invalid_api_key`` (401), ``api_key_disabled``
    (403), ``scope_not_allowed`` (403). Never retried automatically.
    """


class RateLimitError(NetRiskScanError):
    """Raised for HTTP 429 ``rate_limit_exceeded`` -- a short-lived, per-minute
    throughput limit. This clears quickly; see ``retry_after``.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        request_id: str | None = None,
        retry_after: float | None = None,
        rate_limit: Any | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, code=code, request_id=request_id)
        self.retry_after = retry_after
        self.rate_limit = rate_limit


class QuotaExceededError(RateLimitError):
    """Raised for HTTP 429 ``quota_exceeded`` (billing-period unit quota
    exhausted) and ``anonymous_daily_limit_reached`` (anonymous daily
    allowance exhausted).

    Unlike a plain :class:`RateLimitError`, this does not necessarily clear
    once ``retry_after`` elapses -- a billing-period quota or a daily
    anonymous allowance can still be exhausted at that time. Waiting for
    ``retry_after`` is a floor, not a guarantee.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        request_id: str | None = None,
        retry_after: float | None = None,
        rate_limit: Any | None = None,
        quota: Any | None = None,
        daily_limit: int | None = None,
        used: int | None = None,
        remaining: int | None = None,
        reset_at: str | None = None,
        signup_url: str | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            code=code,
            request_id=request_id,
            retry_after=retry_after,
            rate_limit=rate_limit,
        )
        self.quota = quota
        # Populated only for the anonymous daily-limit variant of this error.
        self.daily_limit = daily_limit
        self.used = used
        self.remaining = remaining
        self.reset_at = reset_at
        self.signup_url = signup_url


class NotFoundError(NetRiskScanError):
    """Raised for HTTP 404 ``not_found`` -- no such route."""


class FeatureNotAvailableError(NetRiskScanError):
    """Raised for HTTP 404 ``feature_not_available`` -- a documented but not
    yet enabled capability (for example a future batch endpoint).
    """


class ApiError(NetRiskScanError):
    """Catch-all for any other non-2xx response, including HTTP 503
    ``temporarily_unavailable`` and any error code not yet known to this SDK
    version (forward compatible with new server-side codes).
    """


class TimeoutError(NetRiskScanError):  # noqa: A001 - intentional shadow, matches JS SDK naming
    """Raised when a request does not complete within ``timeout`` seconds."""

    def __init__(self, message: str, *, timeout: float) -> None:
        super().__init__(message)
        self.timeout = timeout


class NetworkError(NetRiskScanError):
    """Raised when a request never receives an HTTP response (DNS failure,
    connection reset, TLS error, malformed response body, ...).
    """

    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.__cause__ = cause
