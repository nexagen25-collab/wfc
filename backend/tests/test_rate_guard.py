"""Attack tests for rate limiting, load shedding, and the strict-limit guard.

Run: python -m tests.test_rate_guard

Covers two things that only matter because a password check costs a measured
196 ms of CPU:

  * STRICT_LIMITS - a much tighter per-IP budget for /auth/ routes, which an
    environment variable may tighten but never loosen.
  * ConcurrencyGuard - a cap on expensive work in flight, which per-IP limits
    cannot provide because they lose to a distributed attacker.

The recurring theme of this file: every guard is also tested for the ability to
FAIL. A rate limiter that never throttles and a startup check that never fires
are indistinguishable from working ones until the attack.
"""
import os
import threading
import time

os.environ.setdefault("RATE_LIMIT_REQUESTS", "100000")
os.environ.setdefault("RATE_LIMIT_WINDOW_SECONDS", "60")
os.environ.setdefault("JWT_SECRET", "test-only-signing-secret-0123456789abcdefghijklmn")

from fastapi import Depends, FastAPI

from app import config
from app.auth_deps import (
    RouteProtectionError,
    enforce_strict_rate_limits,
    unthrottled_auth_routes,
)
from app.rate_limit import (
    EXEMPT_PATHS,
    STRICT_LIMITS,
    ConcurrencyGuard,
    PASSWORD_HASH_GUARD,
    RateLimited,
    _hits,
    client_ip,
    enforce_rate_limit,
    strict_limit_for,
)

results: list[tuple[str, bool, str]] = []


def ok(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, bool(cond), detail))


class FakeRequest:
    """Enough of a Starlette Request for the rate limiter."""

    def __init__(self, path: str, ip: str = "10.0.0.1", headers: dict | None = None):
        self.url = type("U", (), {"path": path})()
        self.client = type("C", (), {"host": ip})()
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}


def hit(path: str, ip: str = "10.0.0.1", n: int = 1, clear: bool = True) -> list[int]:
    """Fire n requests and return the status of each.

    clear=False keeps the existing counters, which is the only way to show that
    one route's budget is genuinely separate from another's.
    """
    if clear:
        _hits.clear()
    out = []
    for _ in range(n):
        r = enforce_rate_limit(FakeRequest(path, ip))
        out.append(r.status_code if r is not None else 200)
    return out


# ------------------------------------------------------------ strict budgets
ok("login has a strict budget", strict_limit_for("/auth/login") is not None)
ok("otp request has a strict budget", strict_limit_for("/auth/otp/request") is not None)
ok("otp verify has a strict budget", strict_limit_for("/auth/otp/verify") is not None)
ok("an ordinary route has no strict budget", strict_limit_for("/me") is None)
ok("an ordinary route has no strict budget (POST path)",
   strict_limit_for("/orders/123") is None)

login_limit, login_window = STRICT_LIMITS["/auth/login"]
ok("the login limit is far tighter than the general limit",
   login_limit < config.RATE_LIMIT_REQUESTS / 4,
   f"{login_limit} vs general {config.RATE_LIMIT_REQUESTS}")
ok("the login window is longer than the general window",
   login_window >= config.RATE_LIMIT_WINDOW_SECONDS,
   f"{login_window}s vs {config.RATE_LIMIT_WINDOW_SECONDS}s")
for path, (reqs, window) in STRICT_LIMITS.items():
    ok(f"{path} budget is {reqs} per {window}s", reqs >= 1 and window >= 60)
    ok(f"{path} allows at least one real attempt per window", reqs >= 1)

# otp/verify must not be shadowed by the otp/request prefix
ok("/auth/otp/verify is not charged against the otp/request budget",
   strict_limit_for("/auth/otp/verify") != strict_limit_for("/auth/otp/request"))
ok("/auth/otp/request/extra resolves to the otp/request budget",
   strict_limit_for("/auth/otp/request/extra") == STRICT_LIMITS["/auth/otp/request"])
ok("/auth/login/otp inherits the login budget rather than escaping it",
   strict_limit_for("/auth/login/otp") == STRICT_LIMITS["/auth/login"],
   "prefix matching is the safe direction: a new sub-path cannot slip past a limit")
ok("a route that merely contains /auth/ is not an auth route",
   strict_limit_for("/api/authenticated/thing") is None)

# ------------------------------------------- an env var can only tighten
saved = config.RATE_LIMIT_LOGIN_REQUESTS
try:
    config.RATE_LIMIT_LOGIN_REQUESTS = 999999
    ok("a huge env value cannot loosen the login limit",
       strict_limit_for("/auth/login")[0] == login_limit,
       f"clamped to {strict_limit_for('/auth/login')[0]}, env said 999999")
    config.RATE_LIMIT_LOGIN_REQUESTS = 1
    ok("a small env value does tighten the login limit",
       strict_limit_for("/auth/login")[0] == 1)
    config.RATE_LIMIT_LOGIN_REQUESTS = 0
    ok("a zero env value cannot disable login rate limiting entirely",
       strict_limit_for("/auth/login")[0] == 1, "floored at 1, never 0")
    config.RATE_LIMIT_LOGIN_REQUESTS = -5
    ok("a negative env value cannot produce a negative limit",
       strict_limit_for("/auth/login")[0] == 1)
finally:
    config.RATE_LIMIT_LOGIN_REQUESTS = saved

# ------------------------------------------------------------- it throttles
codes = hit("/auth/login", n=login_limit + 3)
ok("login serves exactly the budget then throttles",
   codes[:login_limit] == [200] * login_limit and all(c == 429 for c in codes[login_limit:]),
   str(codes))
r = enforce_rate_limit(FakeRequest("/auth/login"))
ok("a throttled login carries Retry-After", r is not None and r.headers.get("retry-after"))
ok("the general budget is much larger than the login budget",
   hit("/me", n=login_limit + 5)[-1] == 200,
   f"/me still served after {login_limit + 5} requests while /auth/login was cut off")

saved_general = config.RATE_LIMIT_REQUESTS
try:
    config.RATE_LIMIT_REQUESTS = 8
    # One shared counter set. Drain the general budget, then try to log in
    # without clearing: if the two shared a bucket, login would be dead.
    browse = hit("/me", n=8)
    ok("the general budget is spent", browse == [200] * 8, str(browse))
    ok("the general limit now refuses ordinary traffic", hit("/me", clear=False) == [429])
    login = hit("/auth/login", n=login_limit, clear=False)
    ok("browsing does not consume the login budget",
       login == [200] * login_limit, f"login after a drained general budget: {login}")
    ok("the login budget is still enforced on its own",
       hit("/auth/login", clear=False)[0] == 429)
    ok("the two budgets are independent in both directions",
       hit("/me", clear=False) == [429],
       "the login attempts did not refill the general budget, and did not "
       "extend it either - the two counters never touch")
finally:
    config.RATE_LIMIT_REQUESTS = saved_general

ok("a different IP has its own budget",
   hit("/auth/login", ip="10.0.0.1", n=login_limit)[-1] == 200
   and hit("/auth/login", ip="10.0.0.2")[0] == 200)

ok("/health is exempt from every limit",
   all(c == 200 for c in hit("/health", n=5000)))
ok("/health is the only exemption", EXEMPT_PATHS == {"/health"})

ok("a forged X-Forwarded-For is ignored when no proxy is configured",
   client_ip(FakeRequest("/me", "1.2.3.4", {"X-Forwarded-For": "9.9.9.9"})) == "1.2.3.4")
saved_hosts = config.ALLOWED_HOSTS
try:
    config.ALLOWED_HOSTS = ["wfc.example.com"]
    ok("X-Forwarded-For is honoured when a proxy is configured",
       client_ip(FakeRequest("/me", "1.2.3.4", {"X-Forwarded-For": "9.9.9.9, 8.8.8.8"})) == "9.9.9.9")
    ok("each X-Forwarded-For address gets a separate budget (defeats IP rotation)",
       hit("/auth/login", ip="9.9.9.9", n=login_limit)[-1] == 200
       and hit("/auth/login", ip="8.8.8.8")[0] == 200)
finally:
    config.ALLOWED_HOSTS = saved_hosts

# ------------------------------------------------------ concurrency guard
for bad in (0, -1, True, 1.5, "4", None):
    try:
        ConcurrencyGuard(bad)
        ok(f"guard rejects a bad limit: {bad!r}", False, "accepted")
    except ValueError:
        ok(f"guard rejects a bad limit: {bad!r}", True)

g = ConcurrencyGuard(3)
ok("a fresh guard has nothing in flight", g.in_flight == 0)
ok("acquire up to the limit succeeds", all(g.try_acquire() for _ in range(3)))
ok("the limit is respected", g.in_flight == 3)
ok("one more acquire is refused", g.try_acquire() is False)
ok("a refusal is counted", g.rejections == 1)
ok("refusals do not leak capacity", g.in_flight == 3)
g.release()
ok("release frees exactly one slot", g.in_flight == 2 and g.try_acquire() is True)
g.release()
g.release()
g.release()
ok("extra releases cannot drive in_flight negative", g.in_flight == 0,
   f"stays closed rather than opening the ceiling: {g.in_flight}")
ok("the guard is reusable after being drained", g.try_acquire() is True and g.in_flight == 1)
g.release()

g2 = ConcurrencyGuard(1)
try:
    with g2.slot():
        ok("the context manager holds the slot inside the block", g2.in_flight == 1)
        with g2.slot():
            ok("a nested acquire at capacity is refused", False, "not refused")
except RateLimited:
    ok("a nested acquire at capacity is refused", True)
ok("the slot is released even when the body raises", g2.in_flight == 0)
try:
    with ConcurrencyGuard(1).slot():
        raise ValueError("boom")
except ValueError:
    ok("an exception inside the block propagates", True)

# The real test: does the cap hold under actual concurrency?
hard = ConcurrencyGuard(4)
observed = []
stop = threading.Event()


def worker():
    while not stop.is_set():
        if hard.try_acquire():
            try:
                observed.append(hard.in_flight)
                time.sleep(0.004)
            finally:
                hard.release()
        else:
            time.sleep(0.001)


threads = [threading.Thread(target=worker, daemon=True) for _ in range(24)]
for t in threads:
    t.start()
time.sleep(1.0)
stop.set()
for t in threads:
    t.join(timeout=2)
ok("24 threads never exceeded the cap of 4", hard.peak <= 4, f"peak observed {hard.peak}")
ok("the cap was actually reached (not a test that proved nothing)", hard.peak == 4,
   f"peak {hard.peak}")
ok("work was actually attempted", len(observed) > 50, f"{len(observed)} slots taken")
ok("refusals happened, so the guard did real work", hard.rejections > 0,
   f"{hard.rejections} refused")
ok("the guard drained fully afterwards", hard.in_flight == 0)
ok("the module guard exists for password hashing",
   isinstance(PASSWORD_HASH_GUARD, ConcurrencyGuard))
ok("the module guard has a sane limit",
   1 <= PASSWORD_HASH_GUARD.limit <= 32, f"limit {PASSWORD_HASH_GUARD.limit}")

# ------------------------------------------- startup guard: no loose /auth/
def mini() -> FastAPI:
    return FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


loose = mini()
# /auth/refresh is the realistic case: a developer adds a token-refresh route
# and forgets that it, too, needs a strict budget. /auth/login would prove
# nothing here because it is already in STRICT_LIMITS.
loose.post("/auth/refresh")(lambda: {"ok": True})
ok("the startup check flags an /auth/ route with no strict limit",
   unthrottled_auth_routes(loose) == ["/auth/refresh"], str(unthrottled_auth_routes(loose)))
try:
    enforce_strict_rate_limits(loose)
    ok("enforce_strict_rate_limits raises on an unthrottled auth route", False, "did not raise")
except RouteProtectionError as exc:
    ok("enforce_strict_rate_limits raises on an unthrottled auth route", True)
    ok("the error names the route", "/auth/refresh" in str(exc))
    ok("the error says how to fix it", "STRICT_LIMITS" in str(exc))
ok("the check catches every unthrottled auth route at once",
   (lambda a: (a.post("/auth/password-reset")(lambda: {}), a.post("/auth/refresh")(lambda: {}),
               unthrottled_auth_routes(a) == ["/auth/password-reset", "/auth/refresh"])[-1])(mini()),
   str(unthrottled_auth_routes(loose)))

ok("a throttled auth route passes", strict_limit_for("/auth/login") is not None)
tolerated = mini()
tolerated.post("/auth/login")(lambda: {"ok": True})
tolerated.post("/auth/otp/request")(lambda: {"ok": True})
tolerated.post("/auth/otp/verify")(lambda: {"ok": True})
ok("a fully listed set of auth routes passes the check",
   unthrottled_auth_routes(tolerated) == [], str(unthrottled_auth_routes(tolerated)))
ok("the check does not fire on ordinary routes",
   unthrottled_auth_routes(mini()) == [])
inner = mini()
inner.post("/api/auth/thing")(lambda: {"ok": True})
ok("a path that merely contains auth is not caught by the guard",
   unthrottled_auth_routes(inner) == [])
bare = mini()
bare.post("/auth")(lambda: {"ok": True})
ok("a bare /auth path is caught too", unthrottled_auth_routes(bare) == ["/auth"])

# the real app must satisfy both guards
import app.main as main_module  # noqa: E402

ok("the real app has no unthrottled auth route",
   unthrottled_auth_routes(main_module.app) == [], str(unthrottled_auth_routes(main_module.app)))
ok("the real app has no unprotected route", __import__(
    "app.auth_deps", fromlist=["unprotected_routes"]).unprotected_routes(main_module.app) == [])
ok("the real app still imports with both guards satisfied", main_module.app is not None)

print("=" * 92)
print("WFC RATE-LIMIT + LOAD-SHEDDING ATTACK TESTS")
print("=" * 92)
passed = sum(1 for _, o, _ in results if o)
for name, o, detail in results:
    line = f"  [{'PASS' if o else 'FAIL'}] {name:<62} {detail}"
    print(line.encode("ascii", "replace").decode())
print("=" * 92)
print(f"  {passed}/{len(results)} passed")
print("=" * 92)
raise SystemExit(0 if passed == len(results) else 1)
