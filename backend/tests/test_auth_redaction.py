"""Attack tests for log redaction and deny-by-default route protection.

Run: python -m tests.test_auth_redaction

Two controls under test:

  1. app/logging_redaction.py  - secrets must not survive into log output.
  2. app/auth_deps.py          - a route with no auth dependency must make the
                                 application refuse to start.

The second control is only worth anything if the detector can actually fail, so
most of this file is about proving the detector is not a rubber stamp.
"""
import base64
import io
import json
import logging
import os
import time

# Set before importing anything from app/: config reads these at import time.
os.environ["RATE_LIMIT_REQUESTS"] = "100000"
os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "3600"
os.environ["JWT_SECRET"] = "test-only-signing-secret-0123456789abcdefghijklmnop"

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.routing import Route

import app.main as main_module
from app import config
from app.auth_deps import (
    PUBLIC_ROUTES,
    AUTH_ATTR,
    RouteProtectionError,
    enforce_route_protection,
    get_current_user,
    require_admin,
    require_role,
    require_staff_or_admin,
    route_is_protected,
    unprotected_routes,
)
from app.logging_redaction import (
    REDACTED,
    RedactingFilter,
    RedactingFormatter,
    install_redaction,
    redact,
)
from app.tokens import AUDIENCE, ISSUER, issue_token

results: list[tuple[str, bool, str]] = []


def ok(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, bool(cond), detail))


def gone(name: str, text: str, secrets: list[str]) -> None:
    """The named secrets must be absent, and the text must survive intact."""
    leaked = [s for s in secrets if s in text]
    ok(name, not leaked, f"leaked {leaked}" if leaked else "")


def b64u(obj) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


client = TestClient(main_module.app)
SECRET = config.JWT_SECRET


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ============================================================ 1. REDACTION
ok("clean English is untouched",
   redact("Order 4815 confirmed for table 3") == "Order 4815 confirmed for table 3")
ok("an 8-digit order token is NOT redacted",
   redact("order WFC48213311 ready") == "order WFC48213311 ready",
   "order tokens must stay searchable in logs")
ok("a rupee amount is NOT redacted",
   redact("total 5610 paid in full") == "total 5610 paid in full")
ok("the word 'passwordless' is not treated as a secret",
   redact("passwordless login is fine") == "passwordless login is fine")
ok("a route path is not mangled",
   redact("POST /auth/otp/verify 200") == "POST /auth/otp/verify 200")

gone("password= is redacted", redact("password=hunter2"), ["hunter2"])
gone("json \"password\" is redacted", redact('{"password": "hunter2"}'), ["hunter2"])
gone("single-quoted token is redacted", redact("{'token': 'abc123xyz'}"), ["abc123xyz"])
gone("api_key= is redacted", redact("api_key=AKIA9999"), ["AKIA9999"])
gone("apikey: is redacted", redact("apikey: AKIA9999"), ["AKIA9999"])
gone("api-key= is redacted", redact("api-key=AKIA9999"), ["AKIA9999"])
gone("a dashed header name is redacted", redact("X-Api-Key: AKIA9999"), ["AKIA9999"])
ok("prose that merely mentions a key is not mangled",
   redact("the token expired and the secret is safe") == "the token expired and the secret is safe",
   "requiring : or = is what keeps ordinary sentences readable")
gone("otp is redacted", redact("otp=483920"), ["483920"])
gone("secret is redacted", redact("client_secret: rzp_live_abc"), ["rzp_live_abc"])
gone("pin is redacted", redact("pin=1234"), ["1234"])
gone("cvv is redacted", redact('"cvv": "987"}'), ["987"])
gone("card_number is redacted", redact("card_number=4111111111111111"), ["4111111111111111"])
gone("razorpay_signature is redacted",
     redact("razorpay_signature=deadbeef"), ["deadbeef"])

jwt_text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.s3cr3t-s1gn4tur3"
gone("a JWT is redacted", redact(f"token={jwt_text}"), [jwt_text, "s3cr3t"])
gone("a bare JWT is redacted", redact(f"using {jwt_text} now"), [jwt_text])
gone("a JWT in an access log line is redacted",
     redact(f'GET /me?token={jwt_text} HTTP/1.1" 200'), [jwt_text])
none_tok = f"{b64u({'alg': 'none', 'typ': 'JWT'})}.{b64u({'sub': 'a'})}."
gone("an alg:none token (empty signature) is redacted", redact(none_tok), [none_tok])

gone("Bearer token is redacted", redact("Authorization: Bearer abc123def456"), ["abc123def456"])
gone("bearer in lower case is redacted", redact("bearer abc123def456"), ["abc123def456"])
gone("a non-Bearer scheme is still redacted by the key rule",
     redact("authorization: abc123def456"), ["abc123def456"])

gone("a postgres password is redacted",
     redact("DATABASE_URL=postgres://wfcuser:s3cr3tpw@db.railway.internal:5432/wfc"),
     ["s3cr3tpw"])
gone("a mysql password is redacted",
     redact("mysql://root:rootpw@10.0.0.5:3306/wfc"), ["rootpw"])
gone("a mongodb+srv password is redacted",
     redact("mongodb+srv://u:pw123@cluster0.abcde.mongodb.net/wfc"), ["pw123"])
ok("the database username and host survive for debugging",
   "wfcuser" in redact("postgres://wfcuser:s3cr3tpw@db.railway.internal:5432/wfc"))

gone("a 64-hex webhook signature is redacted",
     redact("63aee0fd15e41444f8327c2ed564a90fe0a33641711e334a39e1f43213a454cc"),
     ["63aee0fd15e41444f8327c2ed564a90fe0a33641711e334a39e1f43213a454cc"])
gone("a 10-digit phone number is redacted", redact("call +919876543210 today"), ["9876543210"])
gone("a phone with spaces is redacted", redact("call 98765 43210 today"), ["98765 43210"])
gone("a bare 10-digit mobile is redacted", redact("sms to 9876543210 failed"), ["9876543210"])
gone("an email address is redacted",
     redact("owner is warsi.fried@example.com"), ["warsi.fried@example.com"])

multi = redact('login password=hunter2 token=abc123def456 mail a@b.com db postgres://u:p@h/db')
gone("four secrets in one line are all redacted", multi,
     ["hunter2", "abc123def456", "a@b.com", "u:p@h"])
ok("the non-secret part of the line survives", "login" in multi and "db" in multi)

once = redact("password=hunter2")
ok("redaction is idempotent", redact(once) == once, once)
ok("None becomes an empty string", redact(None) == "")
ok("an int is stringified", redact(1234) == "1234")
ok("an empty string stays empty", redact("") == "")
ok("a str subclass survives", redact("token=abc1234567").count(REDACTED) >= 1,
   redact("token=abc1234567"))

t0 = time.perf_counter()
redact("eyJ" + "A" * 200_000)
redact("password=" + "a" * 200_000)
redact("A" * 200_000)
redact('"' * 200_000)
redact("token=" + "eyJ" + "A" * 100_000 + "." + "B" * 100_000)
elapsed = time.perf_counter() - t0
ok("1 MB of adversarial input does not blow up the regexes", elapsed < 3.0,
   f"{elapsed * 1000:.0f}ms for 1M chars")

# ---------------------------------------------- redaction through logging
stream = io.StringIO()
handler = logging.StreamHandler(stream)
root = logging.getLogger()
root.addHandler(handler)
root.setLevel(logging.DEBUG)
touched = install_redaction()
ok("install_redaction() attaches to a new handler", touched >= 1, f"{touched} loggers/handlers")
ok("install_redaction() is idempotent", install_redaction() == 0)

test_log = logging.getLogger("wfc.test.redaction")
test_log.info("user logged in with password=%s", "hunter2")
gone("a secret passed as a logging argument is redacted", stream.getvalue(), ["hunter2"])
ok("the surrounding message survives", "user logged in with" in stream.getvalue())

stream.truncate(0)
stream.seek(0)
test_log.info("db %s", "postgres://wfcuser:s3cr3tpw@db.internal:5432/wfc")
gone("a database URL passed as an argument is redacted", stream.getvalue(), ["s3cr3tpw"])

stream.truncate(0)
stream.seek(0)
try:
    raise ValueError("connect failed for password=hunter2")
except ValueError:
    test_log.exception("db error")
gone("a secret inside an exception traceback is redacted", stream.getvalue(), ["hunter2"])
ok("the traceback still explains itself", "ValueError" in stream.getvalue())

stream.truncate(0)
stream.seek(0)
test_log.info("order WFC48213311 total 5610 paid")
ok("useful debugging data still reaches the log",
   "order WFC48213311 total 5610 paid" in stream.getvalue())

rec = logging.LogRecord("x", logging.INFO, __file__, 1, "jwt %s", ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",), None)
RedactingFilter().filter(rec)
gone("RedactingFilter scrubs message and args", rec.getMessage(), ["eyJhbGciOiJIUzI1NiJ9"])
# This assertion used to be `rec.args == ()`. That was the bug, not the intent:
# emptying args destroyed the five values uvicorn's AccessFormatter unpacks, and
# every access log line in the app was silently discarded. The invariant worth
# protecting is the one below -- the secret must not survive anywhere in the
# record -- not the particular mechanism used to achieve it.
ok("no secret survives anywhere in the record, so nothing re-expands",
   "eyJhbGciOiJIUzI1NiJ9" not in rec.getMessage()
   and "eyJhbGciOiJIUzI1NiJ9" not in str(rec.args)
   and "%s" not in rec.getMessage(),
   f"args={rec.args!r} msg={rec.getMessage()!r}")
ok("the args tuple is left the right length for downstream formatters",
   len(rec.args) == 1, f"got {len(rec.args)}")

bad_fmt = logging.Formatter()
rec2 = logging.LogRecord("x", logging.INFO, __file__, 1, "safe message", (), None)
ok("RedactingFormatter leaves clean output alone",
   RedactingFormatter().format(rec2) == bad_fmt.format(rec2))
rec3 = logging.LogRecord("x", logging.INFO, __file__, 1, "token=%s", ("abc123def456",), None)
gone("RedactingFormatter scrubs even if no filter ran",
     RedactingFormatter().format(rec3), ["abc123def456"])
root.removeHandler(handler)

# ====================================================== 2. AUTH DEPENDENCIES
try:
    r = client.get("/me")
    ok("/me without a token is 401", r.status_code == 401, f"got {r.status_code}")
    ok("the 401 sends a WWW-Authenticate challenge",
       r.headers.get("www-authenticate") == "Bearer")
    ok("the 401 body says nothing about why", r.json() == {"detail": "Not authenticated."})
    ok("security headers are present on a 401 too", r.headers.get("x-content-type-options") == "nosniff")

    cust = client.get("/me", headers=auth(issue_token("user-1", "customer")))
    ok("/me with a valid customer token is 200", cust.status_code == 200, cust.text[:80])
    ok("/me returns the user id from the token", cust.json()["user_id"] == "user-1")
    ok("/me returns the role from the token", cust.json()["role"] == "customer")
    ok("/me never echoes the token back", issue_token("user-1", "customer") not in cust.text)

    admin = client.get("/admin/ping", headers=auth(issue_token("owner", "admin")))
    ok("/admin/ping as admin is 200", admin.status_code == 200)
    staff = client.get("/admin/ping", headers=auth(issue_token("s1", "staff")))
    ok("/admin/ping as staff is 403", staff.status_code == 403, f"got {staff.status_code}")
    ok("the 403 body is terse", staff.json() == {"detail": "Forbidden."})

    # --- forged and malformed tokens, all must look identical from outside
    now = int(time.time())
    base = {"sub": "attacker", "role": "admin", "iat": now, "nbf": now,
            "exp": now + 999, "iss": ISSUER, "aud": AUDIENCE}
    attacks = {
        "alg:none with no signature": f"{b64u({'alg': 'none'})}.{b64u(base)}.",
        "alg:None mixed case": f"{b64u({'alg': 'None'})}.{b64u(base)}.AAAA",
        "signed with the attacker's own key": jwt.encode(base, "attacker-secret-32-chars-long-xxx", algorithm="HS256"),
        "expired": jwt.encode({**base, "iat": now - 900, "nbf": now - 900, "exp": now - 600},
                              SECRET, algorithm="HS256"),
        "signed with the real secret but a swapped role": jwt.encode(
            {**base, "role": "customer"}, SECRET, algorithm="HS256")[:-4] + "AAAA",
        "not a token at all": "hello.world.again",
        "empty string": " ",
    }
    bodies = set()
    for label, token in attacks.items():
        r = client.get("/admin/ping", headers=auth(token))
        ok(f"forged token refused: {label}", r.status_code in (401, 403), f"got {r.status_code}")
        bodies.add(r.text)
    ok("all 7 failure modes return a byte-identical body (no oracle)",
       len(bodies) == 1, f"{len(bodies)} distinct response(s)")

    for label, headers in {
        "no Authorization header": {},
        "wrong scheme (Basic)": {"Authorization": "Basic dXNlcjpwYXNz"},
        "Bearer with no token": {"Authorization": "Bearer"},
        "Bearer with only spaces": {"Authorization": "Bearer    "},
        "raw token with no scheme": {"Authorization": issue_token("u", "admin")},
        "empty header": {"Authorization": ""},
    }.items():
        r = client.get("/me", headers=headers)
        ok(f"refused: {label}", r.status_code == 401, f"got {r.status_code}")

    r = client.get("/health")
    ok("/health stays public", r.status_code == 200 and r.json()["brand"] == "WFC")
    r = client.get("/openapi.json")
    ok("the schema is reachable in development", r.status_code == 200)
    ok("the schema lists the protected routes",
       "/admin/ping" in r.json()["paths"] and "/me" in r.json()["paths"])
    r = client.post("/me")
    ok("a wrong method is 405, not an open door", r.status_code == 405, f"got {r.status_code}")
    ok("/me is not reachable by POST even with no token",
       "user_id" not in r.text)

    # --- dependency factory sanity
    try:
        require_role("wizard")
        ok("require_role rejects an unknown role at build time", False, "accepted")
    except ValueError:
        ok("require_role rejects an unknown role at build time", True)
    try:
        require_role()
        ok("require_role rejects an empty role list at build time", False, "accepted")
    except ValueError:
        ok("require_role rejects an empty role list at build time", True)
    ok("require_admin carries the auth marker", getattr(require_admin, AUTH_ATTR, False) is True)
    ok("require_staff_or_admin covers both roles",
       getattr(require_staff_or_admin, "__wfc_roles__", set()) == {"staff", "admin"})
except Exception as exc:  # noqa: BLE001
    results.append((f"unexpected error in the HTTP section: {type(exc).__name__}: {exc}", False, ""))

# =============================================== 3. ROUTE-PROTECTION AUDITOR
ok("the real app has no unprotected route", unprotected_routes(main_module.app) == [],
   str(unprotected_routes(main_module.app)))
ok("enforce_route_protection() passes on the real app",
   enforce_route_protection(main_module.app) is None)
ok("the real app's public routes are all documented",
   all(isinstance(v, str) and len(v) > 10 for v in PUBLIC_ROUTES.values()))
app_paths = {getattr(r, "path", None) for r in main_module.app.routes}
ok("the public allowlist has no stale entries",
   set(PUBLIC_ROUTES) <= app_paths, f"stale: {sorted(set(PUBLIC_ROUTES) - app_paths)}")
ok("every allowlisted public route really is public",
   all(not route_is_protected(r) for r in main_module.app.routes
       if getattr(r, "path", None) in PUBLIC_ROUTES))
ok("every non-public APIRoute really is protected",
   all(route_is_protected(r) for r in main_module.app.routes
       if isinstance(r, APIRoute) and getattr(r, "path", None) not in PUBLIC_ROUTES))


def mini(**kwargs) -> FastAPI:
    return FastAPI(docs_url=None, redoc_url=None, openapi_url=None, **kwargs)


# The detector must be able to fail. A guard that always returns [] is not a guard.
vuln = mini()
vuln.get("/secret")(lambda: {"data": "everyone's orders"})
found = unprotected_routes(vuln)
ok("the detector flags a route with no auth dependency", "GET /secret" in found, str(found))
try:
    enforce_route_protection(vuln)
    ok("enforce_route_protection raises on an unprotected route", False, "did not raise")
except RouteProtectionError as exc:
    ok("enforce_route_protection raises on an unprotected route", True)
    ok("the error names the offending route", "/secret" in str(exc))
    ok("the error says how to fix it", "PUBLIC_ROUTES" in str(exc))

vuln2 = mini()
vuln2.post("/create-order")(lambda: {"ok": True})
ok("the detector covers POST too", "POST /create-order" in unprotected_routes(vuln2))
vuln3 = mini()
vuln3.delete("/wipe")(lambda: None)
vuln3.put("/edit")(lambda: None)
vuln3.patch("/edit2")(lambda: None)
ok("the detector covers PUT, PATCH and DELETE",
   set(unprotected_routes(vuln3)) == {"PUT /edit", "PATCH /edit2", "DELETE /wipe"},
   str(unprotected_routes(vuln3)))

# A plain Starlette Route carries no FastAPI dependency at all, so it is
# unprotected by construction. Skipping it would let StaticFiles be mounted on a
# public path and the auditor would still report all-clear.
vuln4 = mini()
vuln4.router.routes.append(Route("/uploads", lambda r: None, methods=["GET"]))
ok("a plain Starlette Route is flagged", "GET /uploads" in unprotected_routes(vuln4),
   str(unprotected_routes(vuln4)))

safe = mini()
safe.get("/x", dependencies=[Depends(require_admin)])(lambda: {"ok": True})
ok("a protected route is not flagged", unprotected_routes(safe) == [], str(unprotected_routes(safe)))
safe2 = mini()
safe2.get("/y", dependencies=[Depends(get_current_user)])(lambda: {"ok": True})
ok("a Depends(get_current_user) route is not flagged", unprotected_routes(safe2) == [])

# A helper that itself depends on auth must still count as protected.
def helper(user=Depends(get_current_user)):
    return user

safe3 = mini()
safe3.get("/z", dependencies=[Depends(helper)])(lambda: {"ok": True})
ok("auth hidden one level down in a helper still counts",
   unprotected_routes(safe3) == [], str(unprotected_routes(safe3)))
ok("route_is_protected finds it directly", route_is_protected(safe3.routes[0]) is True)

safe4 = mini()
safe4.get("/w")(lambda: {"ok": True})
ok("a genuinely public route is still flagged until it is allowlisted",
   "GET /w" in unprotected_routes(safe4))

# A 403 raised inside a nested helper must surface as a 403, not a 500, and the
# authentication step must still run first.
boom = mini()


def only_admin(user=Depends(require_admin)):
    if user.role != "admin":
        raise HTTPException(403)
    return user


boom.get("/q", dependencies=[Depends(only_admin)])(lambda: {"ok": True})
boom_client = TestClient(boom)
r = boom_client.get("/q")
ok("a nested helper still authenticates before it authorises (401, not 500)",
   r.status_code == 401, f"got {r.status_code}")
r = boom_client.get("/q", headers=auth(issue_token("c", "customer")))
ok("a 403 raised inside a nested helper is a 403, not a 500",
   r.status_code == 403, f"got {r.status_code}")
r = boom_client.get("/q", headers=auth(issue_token("a", "admin")))
ok("the nested helper allows the right role", r.status_code == 200, f"got {r.status_code}")

# A custom exception handler that forgets exc.headers silently strips them from
# every response. That is how WWW-Authenticate vanished from our own 401s.
# Tested against the real handler in app/main.py, not FastAPI's default, which
# would pass whether or not the bug was ever fixed.
import asyncio

from starlette.exceptions import HTTPException as StarletteHTTPException

teapot = StarletteHTTPException(
    status_code=418, detail="teapot", headers={"Retry-After": "30", "X-Teapot": "yes"}
)
resp = asyncio.run(main_module.http_handler(None, teapot))
ok("the real app's handler preserves a Retry-After header",
   resp.headers.get("retry-after") == "30", f"headers: {dict(resp.headers)}")
ok("a second custom header also survives", resp.headers.get("x-teapot") == "yes")
ok("the status code is still correct", resp.status_code == 418)
plain = asyncio.run(
    main_module.http_handler(None, StarletteHTTPException(status_code=404, detail="nope"))
)
ok("an exception with no headers does not break the handler",
   plain.status_code == 404 and plain.headers.get("retry-after") is None)


# ---------------------------------------------------------------------------
# REGRESSION: redaction must not break uvicorn's access log.
#
# This block exists because the bug it guards against was shipped once already.
# Redacting a record by collapsing it to a string and emptying record.args
# destroyed the exact five values uvicorn's AccessFormatter unpacks, so every
# single access log line raised "not enough values to unpack" and was discarded.
# All 114 tests still passed, because they fed the filter synthetic records
# whose args nobody else was reading. Nothing in the suite ever handed a real
# access-log record to a real AccessFormatter.
#
# The access log is the record of who called what. It is the first thing anyone
# wants when a rate limit trips or a token is forged, so a security control that
# silently disables it is worse than no control.
# ---------------------------------------------------------------------------
from uvicorn.logging import AccessFormatter  # noqa: E402

ACCESS_FMT = '%(client_addr)s - "%(request_line)s" %(status_code)s'


def access_record(path="/api/orders?token=SECRET123", status=200):
    """A LogRecord shaped exactly the way uvicorn's AccessLogger emits one."""
    r = logging.LogRecord(
        "uvicorn.access", logging.INFO, "", 0,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5000", "GET", path, "1.1", status),
        None,
    )
    r.client_addr = "127.0.0.1:5000"
    r.method = "GET"
    r.full_path = path
    r.http_version = "1.1"
    r.status_code = status
    return r


# Without the filter, uvicorn can format it. That is the control: it proves the
# failure below comes from redaction and not from how the record was built.
_r = access_record()
try:
    _out = AccessFormatter(ACCESS_FMT).format(_r)
    ok("uvicorn formats an access record with no filter attached", "200 OK" in _out, _out)
except Exception as _exc:  # noqa: BLE001
    ok("uvicorn formats an access record with no filter attached", False, repr(_exc))

_r = access_record()
RedactingFilter().filter(_r)
ok("the filter leaves five args for AccessFormatter to unpack",
   len(_r.args) == 5, f"got {len(_r.args)}: {_r.args!r}")
try:
    _out = AccessFormatter(ACCESS_FMT).format(_r)
    ok("a filtered access record still formats (THE regression)", True, _out.strip())
except Exception as _exc:  # noqa: BLE001
    ok("a filtered access record still formats (THE regression)", False, repr(_exc))
    _out = ""
ok("the access line still names the client", "127.0.0.1:5000" in _out, _out)
ok("the access line still shows the status", "200" in _out, _out)
ok("a token in the access query string is redacted", "SECRET123" not in _out, _out)
ok("the redaction is visible rather than silent", "REDACTED" in _out, _out)

_r = access_record(status=503)
RedactingFilter().filter(_r)
ok("the status code stays an int, not a string",
   isinstance(_r.args[4], int) and _r.args[4] == 503,
   f"{type(_r.args[4]).__name__} {_r.args[4]!r}")
ok("non-secret string args are untouched",
   _r.args[0] == "127.0.0.1:5000" and _r.args[3] == "1.1")


class _Opaque:
    pass


_sentinel = _Opaque()
_r = logging.LogRecord("x", logging.INFO, "", 0, "obj %s", (_sentinel,), None)
RedactingFilter().filter(_r)
ok("an opaque object arg is passed through unchanged", _r.args[0] is _sentinel)

_r = logging.LogRecord("x", logging.INFO, "", 0, "d %s", ({"password": "hunter2"},), None)
RedactingFilter().filter(_r)
# logging collapses a single mapping arg to the mapping itself, not a 1-tuple.
ok("a dict arg is scrubbed by KEY, not just by value",
   isinstance(_r.args, dict) and _r.args.get("password") == "[REDACTED]", str(_r.args))
ok("a non-secret dict key keeps its value",
   logging.LogRecord("x", logging.INFO, "", 0, "d %s", ({"user_id": "u-7"},), None)
   and (lambda r: (RedactingFilter().filter(r), r.args.get("user_id") == "u-7")[1])(
       logging.LogRecord("x", logging.INFO, "", 0, "d %s", ({"user_id": "u-7"},), None)))
_r = logging.LogRecord("x", logging.INFO, "", 0, "d %s", ({"token_count": 3},), None)
RedactingFilter().filter(_r)
ok("token_count is not mistaken for a token", _r.args.get("token_count") == 3, str(_r.args))
_r = logging.LogRecord("x", logging.INFO, "", 0, "d %s", ({"session_id": "s-1"},), None)
RedactingFilter().filter(_r)
ok("session_id is not mistaken for a session", _r.args.get("session_id") == "s-1", str(_r.args))
_r = logging.LogRecord("x", logging.INFO, "", 0, "d %s", ({"order_total": 5610},), None)
RedactingFilter().filter(_r)
ok("useful numbers survive redaction", _r.args.get("order_total") == 5610, str(_r.args))

_r = logging.LogRecord("x", logging.INFO, "", 0, "t %s", (("a", "password=b"),), None)
RedactingFilter().filter(_r)
ok("a tuple arg keeps its shape and is scrubbed",
   isinstance(_r.args[0], tuple) and "REDACTED" in _r.args[0][1], str(_r.args))

# With args present, msg is a printf template. Redacting it would eat the '%s'
# and break substitution -- a second, quieter way to lose a log line.
_r = logging.LogRecord("x", logging.INFO, "", 0, "token=%s for %s", ("abc123", "user"), None)
RedactingFilter().filter(_r)
ok("a printf template keeps both placeholders", _r.msg.count("%s") == 2, repr(_r.msg))
try:
    _msg = _r.getMessage()
    ok("substitution still works after filtering", "abc123" in _msg and "user" in _msg, _msg)
except Exception as _exc:  # noqa: BLE001
    ok("substitution still works after filtering", False, repr(_exc))

_r = logging.LogRecord("x", logging.INFO, "", 0, "no args here", (), None)
RedactingFilter().filter(_r)
ok("with no args the message itself is redacted",
   isinstance(_r.msg, str) and _r.getMessage() == "no args here")

_wrapper = RedactingFormatter(AccessFormatter(ACCESS_FMT))
_out = _wrapper.format(access_record())
ok("the wrapper delegates to uvicorn's formatter, not a plain one",
   "200 OK" in _out and "127.0.0.1:5000" in _out, _out)
ok("the wrapper keeps uvicorn's access format", '"GET' in _out, _out)
_out = RedactingFormatter().format(access_record())
ok("the wrapper also works with nothing to wrap", "REDACTED" in _out, _out)


class _Hostile:
    def __str__(self):
        raise RuntimeError("refuses to be a string")


_r = logging.LogRecord("x", logging.INFO, "", 0, "msg %s", (_Hostile(),), None)
ok("a filter that would raise still returns True, so the line is emitted",
   RedactingFilter().filter(_r) is True)
ok("the record is left usable rather than half-mutated", _r.args is not None)


print("=" * 88)
print("WFC LOG-REDACTION + ROUTE-PROTECTION ATTACK TESTS")
print("=" * 88)
passed = sum(1 for _, o, _ in results if o)
for name, o, detail in results:
    line = f"  [{'PASS' if o else 'FAIL'}] {name:<62} {detail}"
    print(line.encode("ascii", "replace").decode())
print("=" * 88)
print(f"  {passed}/{len(results)} passed")
print("=" * 88)
raise SystemExit(0 if passed == len(results) else 1)
