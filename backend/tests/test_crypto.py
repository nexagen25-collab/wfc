"""Attack tests for password hashing and token generation.

Run: python -m tests.test_crypto
"""
import re
import time
from collections import Counter

from app.security import (
    ORDER_TOKEN_DIGITS,
    ORDER_TOKEN_SPACE,
    SCRYPT_DKLEN,
    SCRYPT_N,
    generate_order_token,
    generate_otp,
    generate_unique_order_token,
    hash_password,
    verify_password,
)

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))


def expect_true(name: str, fn) -> None:
    try:
        v = fn()
        check(name, bool(v), f"-> {v}" if not isinstance(v, bool) else "")
    except Exception as e:  # noqa: BLE001
        check(name, False, f"RAISED: {e}")


def expect_raise(name: str, fn, exc=Exception) -> None:
    try:
        fn()
        check(name, False, "DID NOT RAISE - HOLE!")
    except exc:
        check(name, True, "rejected")
    except Exception as e:  # noqa: BLE001
        check(name, False, f"wrong error: {type(e).__name__}")


# --- 1. Password round-trip ---
pw = "correct horse battery staple"
stored = hash_password(pw)
check("hash is not the password", pw not in stored, "")
check("password absent from hash", "correct" not in stored, "")
check("format scrypt$n$r$p$salt$hash",
      bool(re.fullmatch(rf"scrypt\$\d+\$\d+\$\d+\$[0-9a-f]{{32}}\$[0-9a-f]{{{SCRYPT_DKLEN * 2}}}", stored)), "")
check("correct password verifies", verify_password(pw, stored))
check("wrong password rejected", not verify_password("wrong password", stored))
check("empty password rejected", not verify_password("", stored))

# --- 2. Salt uniqueness: identical passwords must not collide ---
a = hash_password(pw)
b = hash_password(pw)
check("same password -> different hash (unique salt)", a != b)
check("both hashes still verify", verify_password(pw, a) and verify_password(pw, b))

# --- 3. Malformed stored hashes must not crash or pass ---
expect_true("verify(None) -> False", lambda: verify_password(pw, None) is False)
expect_true("verify('garbage') -> False", lambda: verify_password(pw, "not-a-hash") is False)
expect_true("verify('$') -> False", lambda: verify_password(pw, "$") is False)
expect_true("verify('bcrypt$x$1$2$a$b') -> False", lambda: verify_password(pw, "bcrypt$x$1$2$a$b") is False)
expect_true("verify('scrypt$x$1$2$a$b') -> False", lambda: verify_password(pw, "scrypt$x$1$2$a$b") is False)
expect_true("truncated hash -> False", lambda: verify_password(pw, stored[:-4]) is False)
expect_true("truncated by 1 byte -> False", lambda: verify_password(pw, stored[:-2]) is False)
# A stored hash with absurd cost params would make one login eat unbounded
# memory/CPU - a DoS amplifier. The parameters must match what we issue.
def with_n(v: str) -> str:
    return re.sub(r"^(scrypt\$)\d+", rf"\g<1>{v}", stored, count=1)


def with_p(v: str) -> str:
    return re.sub(r"^(scrypt\$\d+\$\d+\$)\d+", rf"\g<1>{v}", stored, count=1)


expect_true("inflated scrypt n rejected", lambda: verify_password(pw, with_n("1073741824")) is False)
expect_true("reduced scrypt n rejected", lambda: verify_password(pw, with_n("1024")) is False)
expect_true("zero scrypt p rejected", lambda: verify_password(pw, with_p("0")) is False)
expect_true("huge scrypt r rejected", lambda: verify_password(pw, re.sub(r"^(scrypt\$\d+\$)\d+", r"\g<1>999999", stored, count=1)) is False)
expect_true("hex tampered hash -> False", lambda: verify_password(pw, stored[:-1] + ("0" if stored[-1] != "0" else "1")) is False)
expect_true("salt tampered -> False", lambda: verify_password(pw, stored.replace(stored.split("$")[4], "0" * 32)) is False)
expect_true("password=None -> False", lambda: verify_password(None, stored) is False)
expect_raise("hash_password('') raises", lambda: hash_password(""), ValueError)

# --- 4. Unicode / very long passwords ---
uni = "pässwörd🔥ఠ_ఠ"
check("unicode password verifies", verify_password(uni, hash_password(uni)))
check("unicode wrong password rejected", not verify_password(uni + "x", hash_password(uni)))
long_pw = "A" * 10000
check("10k char password works", verify_password(long_pw, hash_password(long_pw)))

# --- 5. Order token format and uniqueness ---
# Uniqueness is judged against the birthday bound, expected = N^2 / (2M).
# Anything close to that is chance, not a bug; a result near N means the
# generator is broken or the space is far too small.
N = 50_000
tokens = [generate_order_token() for _ in range(N)]
expected_collisions = N * N / (2 * ORDER_TOKEN_SPACE)
check("token format WFC + 8 digits",
      all(re.fullmatch(rf"WFC\d{{{ORDER_TOKEN_DIGITS}}}", t) for t in tokens), f"e.g. {tokens[0]}")
dupes = [t for t, c in Counter(tokens).items() if c > 1]
colliding = sum(c for c in Counter(tokens).values() if c > 1)
check("collision count within birthday bound",
      colliding <= expected_collisions * 3 + 20,
      f"{colliding} vs expected ~{expected_collisions:.0f} in {ORDER_TOKEN_SPACE:,} space")

# A decade of trade must leave the number space almost untouched, so the
# retry loop always finds a free number on its first or second try.
orders_per_day = 300  # generous for a single outlet
years_of_orders = orders_per_day * 365 * 10
space_used = years_of_orders / ORDER_TOKEN_SPACE
check("10 yrs of 300 orders/day uses <5% of space", space_used < 0.05,
      f"{years_of_orders:,} orders = {space_used * 100:.2f}% of {ORDER_TOKEN_SPACE:,}")
check("retry loop succeeds on a full-ish space",
      generate_unique_order_token(set(tokens)) not in set(tokens))

# The helper must never hand back a token that already exists.
taken = {generate_order_token() for _ in range(200)}
fresh = [generate_unique_order_token(taken) for _ in range(500)]
check("unique helper never repeats", len(set(fresh)) == 500, f"{len(set(fresh))}/500 unique")
check("unique helper avoids taken set", not (set(fresh) & taken))
big = {generate_order_token() for _ in range(5000)}
check("unique helper works with 5000 taken", generate_unique_order_token(big) not in big)

# --- 6. Token distribution must not be predictable (no modulo bias) ---
digits = Counter(c for t in tokens for c in t[3:])
counts = sorted(digits.values())
check("all 10 digits appear", len(digits) == 10, f"digits seen: {len(digits)}")
check("digit spread is tight (no bias)", counts[-1] - counts[0] < 1500,
      f"min={counts[0]} max={counts[-1]} expected~{len(tokens) * 6 / 10:.0f}")

otps = [generate_otp() for _ in range(10_000)]
otp_dupes = 10_000 - len(set(otps))
otp_expected = 10_000 * 10_000 / (2 * 10**6)
check("otp format 6 digits", all(re.fullmatch(r"\d{6}", o) for o in otps), f"e.g. {otps[0]}")
check("otp uses all digits", len({c for o in otps for c in o}) == 10)
check("otp collisions within birthday bound", otp_dupes <= otp_expected * 3 + 20,
      f"{otp_dupes} vs expected ~{otp_expected:.0f} in 1,000,000 space")

# --- 7. No Math.random anywhere in the repo's token path ---
import pathlib
root = pathlib.Path(__file__).resolve().parents[2]
hits = []
for p in root.rglob("*.ts"):
    if "node_modules" in p.parts or ".next" in p.parts:
        continue
    txt = p.read_text(encoding="utf-8", errors="ignore")
    for m in re.finditer(r"Math\.random\([^)]*\)", txt):
        line = txt[:m.start()].count("\n") + 1
        ctx = txt.splitlines()[line - 1].strip()[:80]
        if re.search(r"token|order|otp|code|number", ctx, re.I):
            hits.append(f"{p.relative_to(root)}:{line} {ctx}")
check("no Math.random for tokens/orders/otp", not hits, "; ".join(hits) or "clean")

# --- 8. Timing: hashing is deliberately slow (proves it is work, not a lookup) ---
t0 = time.perf_counter()
hash_password(pw)
elapsed = time.perf_counter() - t0
check("hash takes real work (>20ms)", elapsed > 0.020, f"{elapsed * 1000:.0f}ms, n=2^{SCRYPT_N.bit_length() - 1}")
check("hash is not absurdly slow (<2s)", elapsed < 2.0, f"{elapsed * 1000:.0f}ms")

print("=" * 78)
print("WFC CRYPTO ATTACK TESTS")
print("=" * 78)
passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:<42} {detail}")
print("=" * 78)
print(f"  {passed}/{len(results)} passed")
print("=" * 78)
raise SystemExit(0 if passed == len(results) else 1)
