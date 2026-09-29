"""Central configuration. All secrets come from environment variables, never hardcoded."""
import os

# Comma-separated list of origins allowed to call this API from a browser.
# Never use "*" in production: it lets any website read authenticated responses.
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if o.strip()
]

# Comma-separated hostnames this API will answer to. Empty = disabled (dev only).
ALLOWED_HOSTS = [
    h.strip() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()
]

# Requests allowed per IP per window. Per-process only; if we ever scale to
# multiple instances this must move to Redis, otherwise each instance keeps its own count.
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "120"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# Reject oversized request bodies early, before any parsing work happens.
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(1024 * 1024)))

# Secrets are required in production. In development we allow a clearly-fake
# placeholder so the app boots, but it must never be used to protect real data.
JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-insecure-placeholder")
IS_PRODUCTION = os.getenv("ENVIRONMENT", "development") == "production"

if IS_PRODUCTION and JWT_SECRET == "dev-only-insecure-placeholder":
    raise RuntimeError("JWT_SECRET must be set to a strong random value in production.")
