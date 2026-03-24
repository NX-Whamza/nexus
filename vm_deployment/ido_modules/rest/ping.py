import asyncio
from fastapi import APIRouter, HTTPException
import functools
import concurrent.futures

try:
    from ping3 import ping
except Exception:
    ping = None

DEFAULT_PING_COUNT = 4

app = APIRouter()


def run_ping(address, ping_count):
    results = []
    for _ in range(ping_count):
        p = ping(address, unit="ms") if ping else None
        results.append(p or None)

    valid_results = [x for x in results if isinstance(x, float)]
    average = sum(valid_results) / len(valid_results) if valid_results else None

    return {
        "results": results,
        "average": average,
        "max": max(valid_results) if valid_results else None,
        "min": min(valid_results) if valid_results else None,
    }


@app.get("/api/ping")
async def ping_address(ip_address: str, ping_count: int = DEFAULT_PING_COUNT):
    try:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ProcessPoolExecutor() as pool:
            return await loop.run_in_executor(
                None,
                functools.partial(run_ping, ip_address, ping_count=ping_count),
            )

    except Exception as err:
        raise HTTPException(status_code=500, detail=f"{err}") from err
