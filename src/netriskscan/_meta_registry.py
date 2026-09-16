"""Out-of-band storage linking a returned result object to its response
metadata (rate limit / quota headers, request id).

Result objects (``IpRiskResult``, ``UsageResult``) are plain, structurally-
equal dataclasses -- some contain list fields (e.g. ``risk.reasons``), which
makes them unhashable, so they cannot be used as ``WeakKeyDictionary`` keys
directly (a ``WeakKeyDictionary`` hashes its keys). Instead this keys on
``id(result)`` and uses :func:`weakref.finalize` to evict the entry exactly
when the result is garbage collected, so metadata never outlives -- or
leaks past -- the object it describes, without requiring that object to be
hashable.
"""

from __future__ import annotations

import weakref

from netriskscan.models.meta import ResponseMeta

_registry: dict[int, ResponseMeta] = {}


def attach(result: object, meta: ResponseMeta) -> None:
    key = id(result)
    _registry[key] = meta
    weakref.finalize(result, _registry.pop, key, None)


def get_response_meta(result: object) -> ResponseMeta | None:
    """Return the rate-limit/quota/request-id metadata for a result previously
    returned by :meth:`NetRiskScan.ip_risk`, :meth:`NetRiskScan.usage`, or
    their :class:`AsyncNetRiskScan` equivalents -- ``None`` if unavailable.
    """
    return _registry.get(id(result))
