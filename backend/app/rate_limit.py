"""Rate limiting, without extra infrastructure.

Counts requests per client IP in a sliding window held in process memory.
Deliberately simple: we have no Redis and do not need one for a single
FastAPI instance. This is a speed bump against scripted abuse, NOT a
replacement for a gateway/WAF, and it resets when the process restarts.
"""
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse

from . import config

_hits: dict[str, deque[float]] = defaultdict(deque)


def client_ip(request: Request) -> str:
    # Only trust X-Forwarded-For when we know we sit behind a proxy that sets it.
    # If exposed directly, this header is attacker-controlled and would let
    # anyone bypass the limit by forging it.
    if config.ALLOWED_HOSTS:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def enforce_rate_limit(request: Request) -> JSONResponse | None:
    if request.url.path == "/health":
        return None  # health checks must never be throttled

    now = time.monotonic()
    window = config.RATE_LIMIT_WINDOW_SECONDS
    ip = client_ip(request)
    bucket = _hits[ip]

    while bucket and now - bucket[0] > window:
        bucket.popleft()

    if len(bucket) >= config.RATE_LIMIT_REQUESTS:
        retry_after = int(window - (now - bucket[0])) + 1
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please slow down."},
            headers={"Retry-After": str(retry_after)},
        )

    bucket.append(now)

    # Keep memory bounded if we ever see a lot of distinct IPs.
    if len(_hits) > 10_000:
        for key in [k for k, v in _hits.items() if not v or now - v[-1] > window]:
            del _hits[key]

    return None
