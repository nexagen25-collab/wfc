"""Authentication and authorisation dependencies.

The control this module really provides is not "verify a token". It is *deny by
default*. The most common way a real application leaks data is not a broken
cipher, it is a new endpoint added six months from now with no auth on it
because the developer copied a route and forgot the dependency.

So: every route must be either explicitly listed in PUBLIC_ROUTES with a reason,
or it must depend on an auth dependency. `enforce_route_protection()` refuses to
let the application start otherwise, and a test asserts the detector can
actually detect (a guard that always passes is not a guard).

  PUBLIC_ROUTES   a short, documented allowlist. Adding a route here is a
                  decision, and the reason is written down next to it.
  get_current_user  requires a valid Bearer token, returns its claims.
  require_role      requires a valid token AND one of the listed roles.
  require_admin     require_role("admin").
  require_staff_or_admin  require_role("staff", "admin").

NOT WIRED TO A DATABASE. there is no user table, so a valid token is the only
evidence of identity and a token cannot be revoked before it expires. Nothing
here reads or writes user records.
"""
from __future__ import annotations

from typing import NoReturn

from fastapi import Depends, Header, HTTPException, status
from fastapi.routing import APIRoute

from .tokens import ROLES, Claims, TokenError, verify_token
from .rate_limit import strict_limit_for

# Marker attribute read by the route auditor. Set on every dependency that
# authenticates. Use an attribute rather than a name so a factory-created
# closure (require_role) is recognised too.
AUTH_ATTR = "__wfc_requires_auth__"
ROLES_ATTR = "__wfc_roles__"

# Routes that are deliberately reachable without a token. Every entry needs a
# reason, because an unexplained public route is how an endpoint leaks.
#
# When auth, OTP, menu or webhook routes are actually built they must be added
# here on purpose. Until then they are absent, so building one without deciding
# its auth status fails the startup check - which is the point.
PUBLIC_ROUTES: dict[str, str] = {
    "/health": "liveness probe; returns no data",
    "/openapi.json": "schema; development only, 404 in production",
    "/docs": "Swagger UI; development only, 404 in production",
    "/docs/oauth2-redirect": "Swagger OAuth helper; development only",
}


def _unauthorized() -> NoReturn:
    # 401 means "I do not know who you are". Include the RFC 6750 challenge
    # header so a client knows how to authenticate.
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def bearer_token(authorization: str | None = Header(default=None)) -> str:
    """Pull the token out of `Authorization: Bearer <token>`, strictly.

    Rejects a missing header, any scheme other than Bearer (case-insensitive,
    per RFC 7235), and an empty token.
    """
    if not authorization:
        _unauthorized()
    scheme, separator, value = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer":
        _unauthorized()
    token = value.strip()
    if not token:
        _unauthorized()
    return token


def get_current_user(token: str = Depends(bearer_token)) -> Claims:
    """Verify the bearer token and return its claims, or 401.

    Any failure - bad signature, expired, wrong issuer, `alg:none` forgery -
    is reported identically, so an attacker cannot tell which check failed.
    """
    try:
        return verify_token(token)
    except TokenError:
        _unauthorized()


get_current_user.__wfc_requires_auth__ = True  # type: ignore[attr-defined]


def require_role(*roles: str):
    """Build a dependency that requires a valid token with one of `roles`.

    Raises ValueError at import time for an empty or unknown role, so a typo is
    a startup crash rather than a route nobody can reach.
    """
    if not roles:
        raise ValueError("require_role() needs at least one role.")
    unknown = set(roles) - ROLES
    if unknown:
        raise ValueError(f"Unknown role(s): {sorted(unknown)}. Known: {sorted(ROLES)}.")

    allowed = frozenset(roles)

    def _guard(claims: Claims = Depends(get_current_user)) -> Claims:
        # 403, not 401: we know who this is, they are just not allowed.
        if claims.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden.",
            )
        return claims

    _guard.__wfc_requires_auth__ = True
    _guard.__wfc_roles__ = allowed
    _guard.__name__ = "require_role_" + "_".join(sorted(allowed))
    return _guard


require_admin = require_role("admin")
require_staff_or_admin = require_role("staff", "admin")


class RouteProtectionError(RuntimeError):
    """Raised at startup when a route can be reached without authentication."""


def _depends_on_auth(dependant) -> bool:
    """Walk the dependency tree looking for an authenticating dependency.

    Recurses, because a route may depend on a helper that itself depends on
    get_current_user, and that must count as protected.
    """
    if dependant is None:
        return False
    if getattr(dependant.call, AUTH_ATTR, False):
        return True
    return any(_depends_on_auth(sub) for sub in dependant.dependencies)


def route_is_protected(route: object) -> bool:
    return _depends_on_auth(getattr(route, "dependant", None))


def unprotected_routes(app) -> list[str]:
    """Return "<METHOD> <path>" for every route that is neither public nor
    protected. Empty list means the app is safe to start.

    Deliberately type-agnostic. A `Route` or `Mount` cannot carry a FastAPI
    dependency, so it is unprotected by construction and must be listed in
    PUBLIC_ROUTES on purpose. Skipping non-APIRoute objects would let someone
    add `app.mount("/uploads", StaticFiles(...))` and expose every customer's
    uploaded file with the auditor reporting all-clear.
    """
    problems: list[str] = []
    for route in app.routes:
        path = getattr(route, "path", None)
        if not isinstance(path, str):
            continue
        if path in PUBLIC_ROUTES:
            continue
        methods = sorted(
            m for m in (getattr(route, "methods", None) or set()) if m not in ("HEAD", "OPTIONS")
        )
        label = "/".join(methods) if methods else type(route).__name__.upper()
        if isinstance(route, APIRoute) and route_is_protected(route):
            continue
        problems.append(f"{label} {path}")
    return problems


def enforce_route_protection(app) -> None:
    """Fail loudly, at startup, if any route is reachable without a token."""
    problems = unprotected_routes(app)
    if problems:
        raise RouteProtectionError(
            "These routes are reachable without authentication: "
            + ", ".join(problems)
            + ". Add an auth dependency (Depends(get_current_user) or "
            "Depends(require_...)) or list the route in PUBLIC_ROUTES with a "
            "reason. See app/auth_deps.py."
        )


# ---------------------------------------------------------------------------
# Deny by default, part two: no authentication route may exist without a strict
# rate limit. Password hashing costs a measured 196 ms of CPU, so an /auth/
# route with only the general 120/min budget is a denial of service with a 200
# at the end of it.
#
# Vacuous today, because no /auth/ route exists yet. It is written now so that
# the login route cannot be added without the limit, and so the tests can prove
# the check actually fires rather than assuming it will.
AUTH_PATH_PREFIX = "/auth/"


def unthrottled_auth_routes(app) -> list[str]:
    """Auth routes that would inherit the general rate limit."""
    problems: list[str] = []
    for route in app.routes:
        path = getattr(route, "path", None)
        if not isinstance(path, str):
            continue
        if not (path == AUTH_PATH_PREFIX.rstrip("/") or path.startswith(AUTH_PATH_PREFIX)):
            continue
        if strict_limit_for(path) is None:
            problems.append(path)
    return problems


def enforce_strict_rate_limits(app) -> None:
    """Fail loudly at startup if an auth route has no strict rate limit."""
    problems = unthrottled_auth_routes(app)
    if problems:
        raise RouteProtectionError(
            "These authentication routes have no strict rate limit: "
            + ", ".join(sorted(problems))
            + ". A password check costs ~196 ms of CPU, so an unthrottled "
            "/auth/ route is a denial of service. Add the path to STRICT_LIMITS "
            "in app/rate_limit.py and wrap password hashing in "
            "PASSWORD_HASH_GUARD.slot(). See app/rate_limit.py."
        )
