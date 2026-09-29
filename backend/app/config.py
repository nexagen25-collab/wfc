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
#
# The placeholder is deliberately longer than 32 characters. app/tokens.py
# refuses to sign with a secret under 32 characters (HS256 wants 256 bits of
# entropy), so a shorter placeholder would make token issuing fail in
# development and tempt someone to "fix" it by loosening that check.
DEV_PLACEHOLDER_SECRET = "dev-only-insecure-placeholder-do-not-use-in-production"
JWT_SECRET = os.getenv("JWT_SECRET", DEV_PLACEHOLDER_SECRET)
IS_PRODUCTION = os.getenv("ENVIRONMENT", "development") == "production"

# Minimum length enforced on both sides: refusing at boot in production and at
# sign/verify time in app/tokens.py. Two independent guards, not one.
MIN_SECRET_LENGTH = 32

if IS_PRODUCTION and JWT_SECRET == DEV_PLACEHOLDER_SECRET:
    raise RuntimeError("JWT_SECRET must be set to a strong random value in production.")

if IS_PRODUCTION and len(JWT_SECRET) < MIN_SECRET_LENGTH:
    raise RuntimeError(
        f"JWT_SECRET must be at least {MIN_SECRET_LENGTH} characters in production."
    )
