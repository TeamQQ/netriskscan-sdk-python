"""Reading the anonymous daily allowance from an unauthenticated response.

`result.usage` is only present when no API key was used; it is absent on
authenticated requests, where quota is checked via `client.usage()` instead.
"""

from netriskscan import NetRiskScan


def main() -> None:
    client = NetRiskScan()  # no api_key -> anonymous
    result = client.ip_risk("1.1.1.1")

    if result.usage is not None:
        print(
            f"{result.usage.remaining} of {result.usage.daily_limit} anonymous requests left today"
        )
        print("resets at:", result.usage.reset_at)


if __name__ == "__main__":
    main()
