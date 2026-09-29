import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import config
from .rate_limit import enforce_rate_limit

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
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    # Log the real error server-side, return nothing useful to the attacker.
    # Stack traces and database messages are how attackers map your system.
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


@app.get("/health")
def health():
    return {"status": "ok", "brand": "WFC"}
