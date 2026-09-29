"""Session tokens.

A JWT is only as safe as the checks around it. PyJWT does the cryptography;
this module does the policy, and the policy is where the attacks live.

Attacks this exists to defeat:

  `alg: none`     Strip the signature and set the algorithm to "none". Servers
                  that read the algorithm from the token accept this. We pin
                  HS256 and never look at what the token asks for.
  algorithm        Public key used as an HMAC secret (RS256 -> HS256
  confusion        confusion). Impossible when one symmetric algorithm is
                  pinned and no asymmetric key is ever loaded.
  no expiry        A token with no `exp` that is valid forever. `exp` is
                  required, not optional.
  future `nbf`     A token that is not valid yet, replayed early.
  future `iat`     A token minted "in the future" to dodge clock checks.
  claim smuggling  A validly signed payload carrying extra claims the server
                  then trusts. Unknown claims are rejected outright.
  type confusion   `sub` as an object or list instead of a string.
  role escalation  Any role string accepted. Only the three MVP roles pass.
  oversized token  A megabyte of base64 to force the JSON parser to work.
  algorithm/kid    `kid` used to select a key file. We never read `kid`.

NOT YET BUILT: this issues and verifies tokens, but no route uses them and
there is no database to store sessions or revoke them. A JWT cannot be
revoked before it expires. When logout and staff dismissal must take effect
immediately, a server-side session table or a short expiry plus a denylist is
required. That is a known gap, not an oversight.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt

from . import config

ALGORITHM = "HS256"          # pinned. Never configurable, never read from a token.
ISSUER = "wfc-api"
AUDIENCE = "wfc-web"

DEFAULT_TTL_MINUTES = 60 * 24 * 7      # 7 days, per the approved plan
MAX_TTL_MINUTES = 60 * 24 * 7

ROLES = frozenset({"customer", "staff", "admin"})

# A session token is a few hundred bytes. Anything larger is abuse or a mistake.
MAX_TOKEN_BYTES = 4096

# The only claims a token may contain. Anything else is refused.
ALLOWED_CLAIMS = frozenset({"sub", "role", "iat", "nbf", "exp", "iss", "aud"})

# Tolerance for clock drift between our machines. Small on purpose: a large
# leeway on exp means a token stays usable longer than intended.
LEEWAY_SECONDS = 30


class TokenError(Exception):
    """Raised for any token we will not accept. Never says which check failed
    in a way that helps an attacker iterate - see verify_token()."""


@dataclass(frozen=True)
class Claims:
    user_id: str
    role: str
    issued_at: datetime
    expires_at: datetime


def _secret() -> str:
    secret = config.JWT_SECRET
    # A short secret makes brute force trivial. HS256 wants 256 bits of entropy.
    if len(secret) < 32:
        raise TokenError("Server signing secret is too short; refusing to issue tokens.")
    return secret


def issue_token(user_id: str, role: str, ttl_minutes: int = DEFAULT_TTL_MINUTES) -> str:
    """Mint a session token. Only the three approved roles can be issued."""
    if not isinstance(user_id, str) or not user_id or len(user_id) > 128:
        raise TokenError("Invalid user id.")
    if role not in ROLES:
        raise TokenError("Unknown role.")
    if not isinstance(ttl_minutes, int) or isinstance(ttl_minutes, bool):
        raise TokenError("Invalid lifetime.")
    if not 1 <= ttl_minutes <= MAX_TTL_MINUTES:
        raise TokenError("Lifetime out of range.")

    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
        "iss": ISSUER,
        "aud": AUDIENCE,
    }
    token = jwt.encode(payload, _secret(), algorithm=ALGORITHM)
    if len(token) > MAX_TOKEN_BYTES:
        raise TokenError("Token unexpectedly large.")
    return token


def _reject() -> None:
    # One message for every failure. A caller that can tell "wrong signature"
    # from "expired" from "bad role" learns about the token and can iterate.
    raise TokenError("Invalid or expired token.")


def verify_token(token: object) -> Claims:
    """Verify a token and return its claims, or raise TokenError.

    Order matters: size, then shape, then signature, then claims.
    """
    if not isinstance(token, str) or not token:
        _reject()

    # Size first. Everything after this line is parser work an attacker controls.
    if len(token) > MAX_TOKEN_BYTES:
        _reject()

    # Exactly three segments. Rejects "a.b", "a.b.c.d", and empty segments
    # before they reach the parser.
    if token.count(".") != 2:
        _reject()

    try:
        # algorithms=[ALGORITHM] is the critical argument. Without it PyJWT will
        # honour whatever `alg` the token requests, which is the `alg: none`
        # and algorithm-confusion hole.
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            leeway=LEEWAY_SECONDS,
            options={
                "require": ["exp", "iat", "nbf", "sub", "role", "iss", "aud"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.PyJWTError:
        _reject()
    except Exception:
        # A malformed token must never surface as a 500 with a traceback.
        _reject()

    if not isinstance(payload, dict):
        _reject()

    # Reject unknown claims so a signed token cannot smuggle extra fields that
    # some later code might start trusting.
    if set(payload) - ALLOWED_CLAIMS:
        _reject()

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub or len(sub) > 128:
        _reject()

    role = payload.get("role")
    if not isinstance(role, str) or role not in ROLES:
        _reject()

    exp = payload.get("exp")
    iat = payload.get("iat")
    if not isinstance(exp, int) or not isinstance(iat, int):
        _reject()
    if isinstance(exp, bool) or isinstance(iat, bool):
        _reject()
    # A token issued in the future is a clock attack or a forged timestamp.
    if iat > datetime.now(timezone.utc).timestamp() + LEEWAY_SECONDS:
        _reject()

    return Claims(
        user_id=sub,
        role=role,
        issued_at=datetime.fromtimestamp(iat, tz=timezone.utc),
        expires_at=datetime.fromtimestamp(exp, tz=timezone.utc),
    )


def require_role(claims: Claims, *allowed: str) -> Claims:
    """Authorisation gate. Raises unless the token's role is listed.

    This is a helper, not a control: it is only as good as the routes that call
    it. There are no authenticated routes yet, so there is nothing to protect.
    """
    if claims.role not in allowed:
        # Deliberately not "you are a customer and this is admin-only".
        raise TokenError("Not permitted.")
    return claims
