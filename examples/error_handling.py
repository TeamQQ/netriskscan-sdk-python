"""Catching the full NetRiskScan exception hierarchy."""

from netriskscan import (
    ApiError,
    AuthenticationError,
    FeatureNotAvailableError,
    NetRiskScan,
    NetworkError,
    NotFoundError,
    QuotaExceededError,
    RateLimitError,
    TimeoutError,
    ValidationError,
)


def main() -> None:
    client = NetRiskScan()

    try:
        result = client.ip_risk("not-a-real-ip")
        print(result.risk.index)
    except ValidationError as e:
        print(f"invalid input ({e.code}): {e.message}")
    except AuthenticationError as e:
        print(f"authentication problem ({e.code}): {e.message}")
    except QuotaExceededError as e:
        # Subclass of RateLimitError -- catch this first if you need to tell
        # "billing period exhausted" apart from a short-lived rate limit.
        print(f"quota exhausted, resets at {e.reset_at}")
    except RateLimitError as e:
        print(f"rate limited, retry after {e.retry_after}s")
    except (NotFoundError, FeatureNotAvailableError) as e:
        print(f"not available: {e.message}")
    except ApiError as e:
        print(f"API error {e.status_code} ({e.code}): {e.message} [request_id={e.request_id}]")
    except TimeoutError as e:
        print(f"timed out after {e.timeout}s")
    except NetworkError as e:
        print(f"network failure: {e.message}")


if __name__ == "__main__":
    main()
