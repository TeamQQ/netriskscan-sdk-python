"""Same lookup as quickstart.py, using the asyncio client."""

import asyncio

from netriskscan import AsyncNetRiskScan


async def main() -> None:
    async with AsyncNetRiskScan() as client:
        result = await client.ip_risk("8.8.8.8")
        print("index:", result.risk.index)
        print("band:", result.risk.band)


if __name__ == "__main__":
    asyncio.run(main())
