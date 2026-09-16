"""Authenticated usage/quota lookup. Requires NETRISKSCAN_API_KEY to be set."""

from netriskscan import NetRiskScan, get_response_meta


def main() -> None:
    client = NetRiskScan()  # reads NETRISKSCAN_API_KEY from the environment
    usage = client.usage()

    print("plan:", usage.plan)
    print("period:", usage.period.start, "->", usage.period.end)
    print(f"units: {usage.units.used}/{usage.units.limit} (remaining {usage.units.remaining})")
    print("requests/minute limit:", usage.rate_limit.requests_per_minute)

    meta = get_response_meta(usage)
    if meta and meta.request_id:
        print("request id:", meta.request_id)


if __name__ == "__main__":
    main()
