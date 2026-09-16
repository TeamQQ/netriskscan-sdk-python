# NetRiskScan Python SDK

[![PyPI version](https://img.shields.io/pypi/v/netriskscan.svg)](https://pypi.org/project/netriskscan/)
[![Python versions](https://img.shields.io/pypi/pyversions/netriskscan.svg)](https://pypi.org/project/netriskscan/)
[![CI](https://github.com/TeamQQ/netriskscan-sdk-python/actions/workflows/ci.yml/badge.svg)](https://github.com/TeamQQ/netriskscan-sdk-python/actions/workflows/ci.yml)

Official Python SDK for the [NetRiskScan](https://www.netriskscan.com/) IP Risk & Network Intelligence API: IP reputation, proxy/VPN/Tor detection, datacenter and search-crawler identification, and network intelligence.

```bash
pip install netriskscan
```

```python
from netriskscan import NetRiskScan

client = NetRiskScan()  # no signup, no API key required

result = client.ip_risk("8.8.8.8")

print(result.risk.index)  # 0-100, higher = cleaner. Example output; live scores can change.
print(result.risk.band)  # "excellent" | "good" | "fair" | "poor" | "high_risk" | "unknown"
```

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Anonymous usage](#anonymous-usage)
- [Authentication](#authentication)
- [IP risk lookup](#ip-risk-lookup)
- [Usage / quota](#usage--quota)
- [Async client](#async-client)
- [Error handling](#error-handling)
- [Rate limits](#rate-limits)
- [Configuration](#configuration)
- [Type hints](#type-hints)
- [Use cases](#use-cases)
- [API documentation](#api-documentation)
- [NetRiskScan ecosystem](#netriskscan-ecosystem)
- [Examples](#examples)
- [Security](#security)
- [License](#license)

## Installation

Requires Python 3.9+.

```bash
pip install netriskscan
```

## Quick start

```python
from netriskscan import NetRiskScan

client = NetRiskScan()
result = client.ip_risk("8.8.8.8")

print(result.risk.index, result.risk.band)
print(result.network.organization, result.network.asn)
print(result.flags.proxy, result.flags.vpn, result.flags.tor)
```

## Anonymous usage

The API can be called without an account, metered by the server (a daily allowance per source IP, currently 30 requests/day -- the SDK does not hardcode this limit; read it from the response):

```python
from netriskscan import NetRiskScan

client = NetRiskScan()
result = client.ip_risk("8.8.8.8")

if result.usage is not None:  # only present on anonymous calls
    print(result.usage.remaining, "of", result.usage.daily_limit, "requests left today")
```

Anonymous quota, rate limits, and eligibility are decided entirely by the server -- the SDK never re-implements or assumes those business rules.

## Authentication

Pass an API key explicitly, or set the `NETRISKSCAN_API_KEY` environment variable. Precedence: explicit argument > environment variable > anonymous.

```python
from netriskscan import NetRiskScan

client = NetRiskScan(api_key="nrs_live_xxxxxxxxxxxxxxxxxxxx")
```

```bash
export NETRISKSCAN_API_KEY="nrs_live_xxxxxxxxxxxxxxxxxxxx"
```

```python
from netriskscan import NetRiskScan

client = NetRiskScan()  # reads NETRISKSCAN_API_KEY if set, else anonymous
```

The key is always sent as `Authorization: Bearer <api-key>` -- never as a URL query parameter, never logged, and never included in exception messages.

## IP risk lookup

```python
result = client.ip_risk("8.8.8.8")

result.risk.index  # int | None -- 0-100 cleanliness score (higher = cleaner), None if unscoreable
result.risk.band  # str | None -- "excellent" | "good" | "fair" | "poor" | "high_risk" | "unknown"
result.risk.assessment_grade  # str -- "complete" | "partial" | "limited" | "insufficient"
result.risk.reasons  # list[RiskReason] -- may be empty, never a signal by itself

result.network.type  # "residential" | "mobile" | "hosting" | "datacenter" | "public_infrastructure" | ...
result.network.connection_type  # "direct" | "vpn" | "proxy" | "tor" | ...
result.network.asn  # e.g. "AS15169"
result.network.organization  # e.g. "Google LLC"

result.flags.proxy  # bool | None -- see "null is not false" below
result.flags.proxy_type  # populated only when flags.proxy is True
result.flags.vpn  # bool | None
result.flags.tor  # bool | None -- Tor *exit* node specifically
result.flags.datacenter  # bool | None
result.flags.scanner  # bool | None -- behavioral scanner/bot activity
result.flags.abuse  # bool | None
result.flags.search_crawler  # bool | None -- verified search-engine crawler identity
result.flags.search_crawler_name  # e.g. "Google", populated only when search_crawler is True

result.location  # IpLocation | None -- network-level geolocation, not device GPS
result.tor  # TorInfo | None -- present only when the address is a Tor relay
```

### The index is a cleanliness score, not a threat score

`risk.index` runs 0-100 where **higher means cleaner / more trustworthy**. It is not a fraud or threat score where higher is worse. Never invert or rescale it client-side.

### `None` is not `False`

Every detection flag (`proxy`, `vpn`, `tor`, `datacenter`, `scanner`, `abuse`, `search_crawler`) is a three-valued signal:

- `True` -- detected
- `False` -- checked, and confirmed not detected
- `None` -- unknown / not evaluated this round

Treating `None` as `False` turns "we don't know" into "we checked and it's clean," which is a different and stronger claim than the data supports. This SDK never performs that coercion, and code consuming these fields should not either.

### An unscoreable address is a success, not an error

Private, loopback, and other special-purpose addresses return `200 OK` with `risk.index is None`, `risk.band is None`, and `risk.assessment_grade == "insufficient"` -- not an exception. Check for `None` explicitly rather than assuming every successful call returns a numeric score.

### Search crawler identity vs. scanner behavior

`flags.search_crawler` answers a narrow question: is this address in a range list the search-engine operator itself publishes? It is independent of `flags.scanner`, which tracks behavioral scanning/bot activity. A verified crawler is not automatically "not a scanner," and vice versa -- read both.

## Usage / quota

Requires an API key (there is no anonymous account to report usage for):

```python
usage = client.usage()

print(usage.plan)
print(usage.units.used, "/", usage.units.limit)
print(usage.rate_limit.requests_per_minute)
```

Calling `usage()` without an API key raises `ValidationError` immediately, without a network call.

## Async client

Identical API, `httpx`-based async transport:

```python
from netriskscan import AsyncNetRiskScan


async def main():
    async with AsyncNetRiskScan() as client:
        result = await client.ip_risk("8.8.8.8")
        print(result.risk.index)
```

## Error handling

```python
from netriskscan import (
    NetRiskScan,
    ValidationError,
    AuthenticationError,
    RateLimitError,
    QuotaExceededError,
    NotFoundError,
    FeatureNotAvailableError,
    ApiError,
    TimeoutError,
    NetworkError,
)

client = NetRiskScan(api_key="nrs_live_xxxxxxxxxxxxxxxxxxxx")

try:
    result = client.ip_risk("8.8.8.8")
except ValidationError as e:
    ...  # bad IP address / bad request (HTTP 400)
except AuthenticationError as e:
    ...  # missing, invalid, or disabled API key (HTTP 401/403)
except QuotaExceededError as e:
    ...  # billing-period quota or anonymous daily limit exhausted (HTTP 429)
except RateLimitError as e:
    ...  # short-lived per-minute rate limit (HTTP 429); e.retry_after in seconds
except (NotFoundError, FeatureNotAvailableError):
    ...  # unknown route, or a documented capability not open yet (HTTP 404)
except ApiError as e:
    ...  # any other non-2xx response, e.g. HTTP 503 temporarily_unavailable
except TimeoutError as e:
    ...  # request did not complete in time; never retried automatically
except NetworkError as e:
    ...  # DNS/connection failure -- never reached the server
```

Every exception carries `.message`, `.status_code`, `.code` (the server's open-vocabulary error code), and `.request_id` where available -- include `request_id` when reporting issues. `QuotaExceededError` is a subclass of `RateLimitError`, so `except RateLimitError` alone catches both.

## Rate limits

```python
from netriskscan import get_response_meta

result = client.ip_risk("8.8.8.8")
meta = get_response_meta(result)

if meta:
    print(meta.rate_limit.remaining, "/", meta.rate_limit.limit)
    print(meta.quota.remaining, "/", meta.quota.limit)
    print(meta.request_id)
```

`get_response_meta()` returns `None` for a header that was never sent -- it is never coerced to `0`.

### Automatic retries

`GET` requests are retried automatically for HTTP `429`/`502`/`503`/`504` and for transient network failures, honoring the server's `Retry-After` header when present, otherwise using exponential backoff with jitter. Retries are capped by `max_retries` (default `2`) and `max_retry_delay` (default `10` seconds); a `Retry-After` longer than `max_retry_delay` raises immediately instead of blocking. `400`/`401`/`403`/`404` responses and request timeouts are never retried.

## Configuration

```python
from netriskscan import NetRiskScan

client = NetRiskScan(
    api_key="nrs_live_xxxxxxxxxxxxxxxxxxxx",  # optional; falls back to NETRISKSCAN_API_KEY, then anonymous
    base_url="https://api.netriskscan.com",  # override for testing/staging/mocking
    timeout=10.0,  # seconds, per attempt
    max_retries=2,
    max_retry_delay=10.0,  # seconds
)
```

Pass `http_client=httpx.Client(...)` (or `httpx.AsyncClient(...)` for `AsyncNetRiskScan`) to inject your own transport, for example `httpx.MockTransport` in tests.

## Type hints

The package ships `py.typed` and is fully annotated. Results are plain, immutable `dataclasses` -- no ORM-style magic, easy to log, cache, or serialize with `dataclasses.asdict()`.

## Use cases

- Detect proxy, VPN, and Tor infrastructure before signup or login
- Evaluate IP reputation as one signal in a fraud-prevention pipeline
- Distinguish verified search-engine crawlers from generic bot/scanner traffic
- Inspect datacenter and hosting traffic separately from residential networks
- Add network intelligence (ASN, organization, connection type) to abuse-prevention systems
- Gate CI/CD or infrastructure checks on a minimum risk index

## API documentation

Base URL: `https://api.netriskscan.com`

- `GET /v1/ip-risk/{ip}` -- IP risk, reputation, and network intelligence (works with or without an API key)
- `GET /v1/usage` -- current billing-period usage and quota (requires an API key)

Full endpoint and error-code reference: [Developer API documentation](https://www.netriskscan.com/).

## NetRiskScan ecosystem

- **Python SDK** (this package) -- [`netriskscan` on PyPI](https://pypi.org/project/netriskscan/) (`pip install netriskscan`)
- **JavaScript / TypeScript SDK** -- [`@netriskscan/sdk`](https://www.npmjs.com/package/@netriskscan/sdk) on npm
- **CLI** -- [`netriskscan-cli`](https://www.npmjs.com/package/netriskscan-cli) (`npx netriskscan-cli check 8.8.8.8`)
- **Website / Developer API** -- [netriskscan.com](https://www.netriskscan.com/)
- **GitHub** -- [github.com/TeamQQ](https://github.com/TeamQQ)

Need JavaScript or TypeScript instead? See [`@netriskscan/sdk`](https://www.npmjs.com/package/@netriskscan/sdk).

## Examples

Runnable scripts in [`examples/`](examples/):

| File | Demonstrates |
| --- | --- |
| `examples/quickstart.py` | Sync client, anonymous IP risk lookup |
| `examples/async_quickstart.py` | Async client |
| `examples/anonymous.py` | Reading the anonymous daily allowance from a response |
| `examples/usage_quota.py` | Authenticated usage/quota lookup |
| `examples/error_handling.py` | Catching the full exception hierarchy |

## Security

- The API key is only ever sent as an `Authorization: Bearer` header, never in a URL, log line, or exception message.
- This SDK makes no calls to any host other than the configured `base_url`.
- No telemetry of any kind is collected or transmitted by this package.

Found a security issue? See [SECURITY.md](SECURITY.md).

## License

MIT -- see [LICENSE](LICENSE).
