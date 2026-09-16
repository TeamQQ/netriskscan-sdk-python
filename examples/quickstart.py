"""Anonymous IP risk lookup with the sync client. No API key required."""

from netriskscan import NetRiskScan


def main() -> None:
    client = NetRiskScan()
    result = client.ip_risk("8.8.8.8")

    print("index:", result.risk.index)
    print("band:", result.risk.band)
    print("network:", result.network.organization, result.network.asn)
    print("proxy:", result.flags.proxy, "vpn:", result.flags.vpn, "tor:", result.flags.tor)


if __name__ == "__main__":
    main()
