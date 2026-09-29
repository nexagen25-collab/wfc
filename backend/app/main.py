import logging

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import config
from .auth_deps import (
    enforce_route_protection,
    get_current_user,
    require_admin,
)
from .logging_redaction import install_redaction
from .rate_limit import enforce_rate_limit
from .tokens import Claims

# Strip secrets out of anything logged, including uvicorn's access logs. Done
# before the first line of this module is logged.
install_redaction()

logger = logging.getLogger("wfc.api")

# This API only ever returns JSON, never HTML. A restrictive CSP stops any
# injected <script> from executing even if a value were ever reflected back.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-site",
}

app = FastAPI(
    title="WFC - Warsi Fried Chicken API",
    # Docs expose the full API surface. Keep them off in production so attackers
    # cannot read your endpoint list for free.
    docs_url=None if config.IS_PRODUCTION else "/docs",
    redoc_url=None,
    openapi_url=None if config.IS_PRODUCTION else "/openapi.json",
)

# Only explicitly listed origins may call this API from a browser.
# allow_credentials=False and explicit methods/headers: no wildcard behaviour.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)

if config.ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.ALLOWED_HOSTS)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    limited = enforce_rate_limit(request)
    if limited is not None:
        return limited

    # Reject huge bodies before they are read into memory.
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > config.MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Payload too large."})

    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    # Return which fields failed, but never echo the submitted values back.
    fields = [str(e.get("loc", ["body"])[-1]) for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": "Invalid request.", "fields": fields})


@app.exception_handler(StarletteHTTPException)
async def http_handler(request: Request, exc: StarletteHTTPException):
    response = JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    # Preserve headers carried on the exception. FastAPI's built-in handler does
    # this and a hand-rolled one silently does not. The first symptom found by
    # the test suite: the WWW-Authenticate: Bearer challenge disappeared from
    # every 401, so a client had no way to learn it should send a token. Any
    # other HTTPException(headers=...) - Retry-After, Location - would have been
    # dropped the same way.
    for key, value in (getattr(exc, "headers", None) or {}).items():
        response.headers[key] = value
    return response


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    # Log the real error server-side, return nothing useful to the attacker.
    # Stack traces and database messages are how attackers map your system.
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


@app.get("/health")
def health():
    return {"status": "ok", "brand": "WFC"}


# --- Authenticated route stubs -------------------------------------------------
# These exist to prove the token and role layer is wired end to end. They return
# only what the token already carries and read no database, because there is no
# database yet. When real routes are added they must carry the same dependencies.
#
# These are `async def` on purpose. FastAPI runs a sync `def` endpoint in a
# threadpool, which measured 241 us per request more than `async def` on this
# machine. The work here is ~55 us of token verification and nothing that
# blocks, so there is no reason to pay for a thread hop. The rule for the
# codebase: `async def` for endpoints that only validate and do crypto, plain
# `def` for endpoints that do blocking I/O (database, HTTP calls), because an
# `async def` that blocks will stall every other request on the event loop.


@app.get("/me")
async def me(claims: Claims = Depends(get_current_user)):
    """Who the presented token says you are."""
    return {
        "user_id": claims.user_id,
        "role": claims.role,
        "expires_at": claims.expires_at.isoformat(),
    }


@app.get("/admin/ping")
async def admin_ping(claims: Claims = Depends(require_admin)):
    """Proves role enforcement: staff and customers must be refused here."""
    return {"ok": True, "role": claims.role}


# Refuse to import at all if any route above is reachable without a token.
# This runs on every startup and in CI, so forgetting auth on a new endpoint is
# a crash on the developer's machine rather than a hole in production.
enforce_route_protection(app)
