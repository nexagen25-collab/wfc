"""Rate limiting and load shedding, without extra infrastructure.

Counts requests per client IP in a sliding window held in process memory.
Deliberately simple: we have no Redis and do not need one for a single
FastAPI instance. It is a speed bump against scripted abuse, NOT a
replacement for a gateway/WAF, and it resets when the process restarts.

Two controls live here, because per-IP counting alone does not protect the
server from the attack that actually matters.

1. STRICT_LIMITS - a much tighter budget for routes that are cheap for an
   attacker to spam and expensive for us to answer. A password check costs a
   measured 196 ms of scrypt CPU, so the general 120 requests/minute/IP budget
   lets one address force roughly 23 CPU-seconds per minute. On a single-worker
   host that is a denial of service served up politely, with a 200 at the end.

2. ConcurrencyGuard - a cap on total expensive work in flight at once. Per-IP
   limits do nothing against an attacker who spreads requests across many source
   addresses, which is exactly what a distributed attack does. The guard refuses
   immediately instead of queueing: queueing does not reduce the CPU demand, it
   just converts exhaustion into a pile of waiting sockets.

Both are per-process. On more than one instance each instance keeps its own
counts, so the effective limit multiplies by the instance count. Move both to
Redis before scaling out. That is written here so it is not discovered later.

NO ROUTE USES ANY OF THIS YET. There is no /auth/login, no database and no
user table. These controls are built and tested now so that the login route
cannot be built without them, and so the numbers can be tuned against real
measurements rather than guesses.
"""
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager

from fastapi import Request
from fastapi.responses import JSONResponse

from . import config

# Hard ceilings, (requests, window_seconds), keyed by path prefix.
#
# These are deliberately NOT environment-driven. An environment variable can be
# changed by anyone who can deploy, and a security limit that a deploy can
# quietly switch off is not a limit. config.py may only lower these.
STRICT_LIMITS: dict[str, tuple[int, int]] = {
    # 5 password attempts per 5 minutes per address.
    "/auth/login": (5, 300),
    # 3 SMS per 5 minutes. Each one costs real money at MSG91 and can be used
    # to spam a customer's phone.
    "/auth/otp/request": (3, 300),
    # 10 guesses per 5 minutes. The OTP is 6 digits and expires in 300s, so 10
    # guesses already makes a brute force hopeless; the limit exists to stop
    # the CPU cost, not to protect the secret.
    "/auth/otp/verify": (10, 300),
}

# Environment variables that may tighten, never loosen, the ceilings above.
_ENV_TIGHTENERS = {
    "/auth/login": "RATE_LIMIT_LOGIN_REQUESTS",
    "/auth/otp/request": "RATE_LIMIT_OTP_REQUEST",
    "/auth/otp/verify": "RATE_LIMIT_OTP_VERIFY",
}

# Paths served with no limit at all. A health check must never be throttled, or
# a rolling deploy will take the service down while the orchestrator decides it
# is unhealthy. Keep this list to endpoints that return nothing sensitive.
EXEMPT_PATHS = frozenset({"/health"})

# ip -> deque of timestamps, per policy. The policy is part of the key so that
# browsing the menu cannot exhaust the budget reserved for a real login.
_hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)


class RateLimited(Exception):
    """Raised by ConcurrencyGuard when there is no capacity left."""


def strict_limit_for(path: str) -> tuple[int, int] | None:
    """The (requests, window) budget for `path`, or None for the general limit.

    Longest matching prefix wins, so adding /auth/otp/verify/confirm later
    cannot be shadowed by a shorter, looser entry.
    """
    best: tuple[str, tuple[int, int]] | None = None
    for prefix, limit in STRICT_LIMITS.items():
        if path == prefix or path.startswith(prefix + "/"):
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, limit)
    if best is None:
        return None
    prefix, (hard_requests, hard_window) = best
    # min() so a deploy can only ever tighten the limit; max(1) so it can never
    # switch it off. An operator who sets RATE_LIMIT_LOGIN_REQUESTS=0 (or -5, or
    # types a stray minus sign) must not lock every customer out of logging in.
    # Found by this module's own tests: min(0, 5) is 0, and `len(bucket) >= 0`
    # is true for every request, so every login got a 429.
    requested = getattr(config, _ENV_TIGHTENERS[prefix])
    if isinstance(requested, bool) or not isinstance(requested, int):
        requested = hard_requests
    return (max(1, min(requested, hard_requests)), hard_window)


def client_ip(request: Request) -> str:
    # Only trust X-Forwarded-For when we know we sit behind a proxy that sets it.
    # If exposed directly, that header is attacker-controlled and would let
    # anyone bypass every per-IP limit in this file by forging it.
    if config.ALLOWED_HOSTS:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _trim(bucket: deque[float], now: float, window: int) -> None:
    while bucket and now - bucket[0] > window:
        bucket.popleft()


def enforce_rate_limit(request: Request) -> JSONResponse | None:
    """Return a 429 response if this request is over budget, else None."""
    path = request.url.path
    if path in EXEMPT_PATHS:
        return None

    strict = strict_limit_for(path)
    if strict is not None:
        allowed, window, policy = strict[0], strict[1], path
    else:
        allowed, window, policy = config.RATE_LIMIT_REQUESTS, config.RATE_LIMIT_WINDOW_SECONDS, "default"

    now = time.monotonic()
    key = (client_ip(request), policy)
    bucket = _hits[key]

    _trim(bucket, now, window)

    if len(bucket) >= allowed:
        retry_after = int(window - (now - bucket[0])) + 1
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please slow down."},
            headers={"Retry-After": str(retry_after)},
        )

    bucket.append(now)

    # Keep memory bounded if we ever see a lot of distinct IPs.
    if len(_hits) > 10_000:
        for stale in [k for k, v in _hits.items() if not v or now - v[-1] > window]:
            del _hits[stale]

    return None


class ConcurrencyGuard:
    """Caps how many expensive operations run at once, and refuses the rest.

    Refuses immediately. It does not queue, and it does not block, because
    blocking a request thread to wait for a CPU slot is the same denial of
    service wearing a queue.
    """

    def __init__(self, limit: int) -> None:
        # bool is a subclass of int; True must not become a limit of 1 by
        # accident.
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("Concurrency limit must be a positive whole number.")
        self._limit = limit
        self._in_flight = 0
        self._rejections = 0
        self._peak = 0
        self._lock = threading.Lock()

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    @property
    def rejections(self) -> int:
        with self._lock:
            return self._rejections

    @property
    def peak(self) -> int:
        """Highest concurrency ever observed. Lets a test prove the cap held."""
        with self._lock:
            return self._peak

    def reset_stats(self) -> None:
        with self._lock:
            self._rejections = 0
            self._peak = 0

    def try_acquire(self) -> bool:
        with self._lock:
            if self._in_flight >= self._limit:
                self._rejections += 1
                return False
            self._in_flight += 1
            if self._in_flight > self._peak:
                self._peak = self._in_flight
            return True

    def release(self) -> None:
        with self._lock:
            # Clamped, not raised. The safe direction for a guard whose only job
            # is to stop work from exceeding a ceiling is to stay closed on a
            # bookkeeping mistake, not to open the ceiling. A double release
            # therefore wedges the guard rather than admitting unlimited work,
            # which is a loud production symptom instead of a silent hole.
            if self._in_flight > 0:
                self._in_flight -= 1

    @contextmanager
    def slot(self):
        if not self.try_acquire():
            raise RateLimited("Server is busy; try again shortly.")
        try:
            yield
        finally:
            self.release()


# The guard for password hashing specifically. A route that hashes a password
# must wrap it:  with PASSWORD_HASH_GUARD.slot():  ... hash_password(pw) ...
PASSWORD_HASH_GUARD = ConcurrencyGuard(config.PASSWORD_HASH_CONCURRENCY)
