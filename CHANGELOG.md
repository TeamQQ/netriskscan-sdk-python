# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - Unreleased

Initial release.

- `NetRiskScan` (sync) and `AsyncNetRiskScan` (async) clients for `GET /v1/ip-risk/{ip}` and `GET /v1/usage`.
- Anonymous access (no API key) and API key authentication via `NETRISKSCAN_API_KEY` or an explicit argument.
- Typed, immutable dataclass models preserving tri-state (`True`/`False`/`None`) detection flags.
- Full exception hierarchy mapped to the documented `/v1` error codes.
- Automatic retry with backoff and `Retry-After` support for `429`/`502`/`503`/`504`.
- Rate limit and quota metadata via `get_response_meta()`.
