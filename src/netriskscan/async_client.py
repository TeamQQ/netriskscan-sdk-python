from __future__ import annotations

import asyncio
from typing import Any

import httpx

from netriskscan._internal import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_MAX_RETRY_DELAY,
    DEFAULT_TIMEOUT,
    build_headers,
    build_ip_risk_url,
    build_usage_url,
    compute_backoff_seconds,
    is_retryable_method,
    is_retryable_status,
    normalize_base_url,
    parse_error_response,
    parse_response_meta,
    resolve_api_key,
    validate_positive_number,
)
from netriskscan._meta_registry import attach as _attach_meta
from netriskscan.exceptions import ConfigurationError, NetworkError, ValidationError
from netriskscan.exceptions import TimeoutError as NetRiskScanTimeoutError
from netriskscan.models.meta import ResponseMeta
from netriskscan.models.risk import IpRiskResult
from netriskscan.models.usage import UsageResult
from netriskscan.version import VERSION


class AsyncNetRiskScan:
    """Asyncio client for the NetRiskScan Developer API.

    Same configuration, models, and error hierarchy as :class:`NetRiskScan`
    (the sync client) -- only the transport is async. Use as an async context
    manager so the underlying connection pool is closed for you::

        async with AsyncNetRiskScan() as client:
            result = await client.ip_risk("8.8.8.8")
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        max_retry_delay: float = DEFAULT_MAX_RETRY_DELAY,
        user_agent: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = resolve_api_key(api_key)
        self.base_url = normalize_base_url(base_url)
        self.timeout = validate_positive_number("timeout", timeout)
        if max_retries < 0:
            raise ConfigurationError(f"max_retries must be >= 0, got {max_retries!r}")
        self.max_retries = max_retries
        self.max_retry_delay = validate_positive_number("max_retry_delay", max_retry_delay)
        self.user_agent = user_agent or f"netriskscan-python/{VERSION}"
        self._client = http_client or httpx.AsyncClient()
        self._owns_client = http_client is None

    async def __aenter__(self) -> AsyncNetRiskScan:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def ip_risk(self, ip: str, *, timeout: float | None = None) -> IpRiskResult:
        """``GET /v1/ip-risk/{ip}``. Works with or without an API key.

        An address that cannot be scored (private, loopback, reserved, ...)
        is a normal, successful response with ``result.risk.index is None`` --
        it is not raised as an error.
        """
        url = build_ip_risk_url(self.base_url, ip)
        data, meta = await self._request("GET", url, timeout=timeout)
        result = IpRiskResult._from_json(data)
        _attach_meta(result, meta)
        return result

    async def usage(self, *, timeout: float | None = None) -> UsageResult:
        """``GET /v1/usage``. Requires an API key -- there is no anonymous
        account to report usage for.
        """
        if not self.api_key:
            raise ValidationError(
                "usage() requires an API key; anonymous access has no account to report on",
                code="invalid_api_key",
            )
        url = build_usage_url(self.base_url)
        data, meta = await self._request("GET", url, timeout=timeout)
        result = UsageResult._from_json(data)
        _attach_meta(result, meta)
        return result

    async def _request(
        self, method: str, url: str, *, timeout: float | None
    ) -> tuple[Any, ResponseMeta]:
        effective_timeout = timeout if timeout is not None else self.timeout
        headers = build_headers(self.api_key, self.user_agent)
        attempt = 0
        while True:
            try:
                response = await self._client.request(
                    method, url, headers=headers, timeout=effective_timeout
                )
            except httpx.TimeoutException as exc:
                raise NetRiskScanTimeoutError(
                    f"Request to {url} timed out after {effective_timeout}s",
                    timeout=effective_timeout,
                ) from exc
            except httpx.HTTPError as exc:
                if attempt < self.max_retries and is_retryable_method(method):
                    delay = compute_backoff_seconds(attempt)
                    if delay <= self.max_retry_delay:
                        await asyncio.sleep(delay)
                        attempt += 1
                        continue
                raise NetworkError(
                    f"Network error while requesting {url}: {exc}", cause=exc
                ) from exc

            meta = parse_response_meta(response.status_code, response.headers)
            if 200 <= response.status_code < 300:
                try:
                    data = response.json()
                except ValueError as exc:
                    raise NetworkError(f"Invalid JSON response from {url}", cause=exc) from exc
                return data, meta

            error = parse_error_response(response.status_code, response.headers, response.content)
            if (
                attempt < self.max_retries
                and is_retryable_method(method)
                and is_retryable_status(response.status_code)
            ):
                retry_after = getattr(error, "retry_after", None)
                delay = retry_after if retry_after is not None else compute_backoff_seconds(attempt)
                if delay <= self.max_retry_delay:
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
            raise error
