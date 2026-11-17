# Changelog

All notable changes to this project are documented in this file.

## [0.2.0] - Unreleased

- Support API Schema 1.6.0 with optional `IpNetwork.domain` and `IpNetwork.range`.
- Add optional `IpLocation.continent_code`, `continent`, `postal_code`, `latitude`, and `longitude`.
- Preserve missing/null values as `None`, zero coordinates, string postal codes, frozen models, and existing positional constructors; older API responses remain compatible.
- Share the updated models between synchronous and asynchronous clients without new runtime dependencies.
- Add model and mock-transport regression coverage for all seven fields, null/missing/partial responses, anycast, IPv6, leading-zero postal codes, and immutability.
- Retain Python 3.9–3.13 compatibility and the existing CI matrix. SDK package version 0.2.0 is independent of API Schema 1.6.0.

## [0.1.0] - 2026-09-16

Initial release.

- `NetRiskScan` (sync) and `AsyncNetRiskScan` (async) clients for `GET /v1/ip-risk/{ip}` and `GET /v1/usage`.
- Anonymous access (no API key) and API key authentication via `NETRISKSCAN_API_KEY` or an explicit argument.
- Typed, immutable dataclass models preserving tri-state (`True`/`False`/`None`) detection flags.
- Full exception hierarchy mapped to the documented `/v1` error codes.
- Automatic retry with backoff and `Retry-After` support for `429`/`502`/`503`/`504`.
- Rate limit and quota metadata via `get_response_meta()`.
