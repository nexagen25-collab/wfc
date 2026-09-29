"""Password hashing, token generation and constant-time comparison.

Uses hashlib.scrypt from the Python standard library. It is memory-hard, has no
third-party dependency to rot, and is a sound choice for a single-service app.
Never store or compare passwords as plain text.
"""
import hashlib
import hmac
import secrets

# scrypt cost parameters. n=2**15 with r=8 needs roughly 32 MB per hash, which
# makes large-scale cracking expensive. Raise as hardware improves.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SCRYPT_MAXMEM = 128 * SCRYPT_N * SCRYPT_R * 2  # must be generous or scrypt raises

_PREFIX = "scrypt"


def hash_password(password: str) -> str:
    """Return a self-describing hash string: scrypt$n$r$p$salt$hash."""
    if not password:
        raise ValueError("Password must not be empty.")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return f"{_PREFIX}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification. Returns False on any malformed input."""
    try:
        algo, n, r, p, salt_hex, hash_hex = stored.split("$")
        if algo != _PREFIX:
            return False
        expected = bytes.fromhex(hash_hex)
        # Pin the derived length instead of trusting the stored one. Deriving
        # dklen from the stored hash would let a TRUNCATED hash verify: scrypt
        # would be asked for 62 bytes, produce the first 62 bytes of the real
        # digest, and compare equal. A shortened hash must never authenticate.
        if len(expected) != SCRYPT_DKLEN:
            return False
        # Guard the cost parameters. A stored value of n=2**30 would make a
        # login attempt consume unbounded memory and CPU, turning the login
        # endpoint into a denial-of-service amplifier.
        if (int(n), int(r), int(p)) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=SCRYPT_DKLEN,
            maxmem=SCRYPT_MAXMEM,
        )
    except (ValueError, AttributeError, TypeError):
        return False
    # compare_digest avoids leaking information through timing.
    return hmac.compare_digest(actual, expected)


# Order number space. 8 digits = 100,000,000 combinations. For a single outlet
# serving a few hundred orders a day that stays collision-free for decades.
# A 6-digit space (1,000,000) was measured to produce ~1,250 colliding tokens
# in just 50,000 draws, and by 200,000 orders roughly 1 in 5 numbers would be
# reused - at which point a customer could be shown someone else's order.
ORDER_TOKEN_DIGITS = 8
ORDER_TOKEN_SPACE = 10**ORDER_TOKEN_DIGITS


def generate_order_token() -> str:
    """Customer-facing order number, e.g. WFC48291347.

    Uses secrets, not random. Python's random module is predictable: with a few
    observed tokens an attacker could predict someone else's order number and
    read their order. This is exactly the bug we must not ship.
    """
    return "WFC" + "".join(secrets.choice("0123456789") for _ in range(ORDER_TOKEN_DIGITS))


def generate_unique_order_token(existing: set[str]) -> str:
    """Order token guaranteed absent from `existing`.

    The database must still hold a UNIQUE constraint on this column: two
    concurrent requests can both pass the in-memory check and then race to
    insert. The retry loop here is a convenience, the constraint is the
    actual guarantee.
    """
    for _ in range(50):
        token = generate_order_token()
        if token not in existing:
            return token
    raise RuntimeError("Could not allocate a unique order token.")


def generate_otp() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(6))


def generate_razorpay_receipt() -> str:
    return "rcpt_" + secrets.token_hex(8)
