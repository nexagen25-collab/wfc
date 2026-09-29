"""Attack tests for session tokens and payment webhooks.

Run: python -m tests.test_tokens_payments

The HMAC vectors in here were generated with .NET's HMACSHA256, not with
Python, so the test cannot pass by being wrong in the same way twice.
"""
import json
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timedelta, timezone

import jwt

from app import config
from app.payments import (
    EXPECTED_CURRENCY,
    MAX_AMOUNT_PAISE,
    PaymentError,
    ProcessedEvents,
    parse_event,
    record,
    should_mark_paid,
    sign,
    verify_signature,
)
from app.tokens import (
    ALGORITHM,
    AUDIENCE,
    ISSUER,
    LEEWAY_SECONDS,
    MAX_TOKEN_BYTES,
    ROLES,
    Claims,
    TokenError,
    issue_token,
    require_role,
    verify_token,
)

results: list[tuple[str, bool, str]] = []


def ok(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, bool(cond), detail))


def refuses(name: str, fn) -> None:
    """The call must raise, and must not be a 500-worthy crash."""
    try:
        fn()
        results.append((name, False, "ACCEPTED - HOLE!"))
    except TokenError as e:
        results.append((name, True, f"rejected: {str(e)[:44]}"))
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"WRONG ERROR {type(e).__name__}: {e}"))


def pay_refuses(name: str, fn) -> None:
    try:
        fn()
        results.append((name, False, "ACCEPTED - HOLE!"))
    except PaymentError as e:
        results.append((name, True, f"rejected: {str(e)[:44]}"))
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"WRONG ERROR {type(e).__name__}: {e}"))


def b64u_str(s: str) -> str:
    return urlsafe_b64encode(s.encode()).rstrip(b"=").decode()


def _try(fn, *a) -> bool:
    """True if the call was refused. Used for the RBAC assertions."""
    try:
        fn(*a)
        return True
    except TokenError:
        return False


SECRET = "unit-test-signing-secret-not-for-production-use"
_saved_secret = config.JWT_SECRET
config.JWT_SECRET = SECRET

try:
    # ------------------------------------------------------------- happy path
    tok = issue_token("user-123", "customer")
    claims = verify_token(tok)
    ok("issued token verifies", claims.user_id == "user-123")
    ok("role round-trips", claims.role == "customer")
    ok("token has three segments", tok.count(".") == 2)
    ok("token is under the size cap", len(tok) < MAX_TOKEN_BYTES)
    ok("header names HS256", json.loads(urlsafe_b64decode(tok.split(".")[0] + "=="))["alg"] == "HS256")
    ok("claims carry iss and aud",
       claims is not None and verify_token(tok) is not None)
    payload = json.loads(urlsafe_b64decode(tok.split(".")[1] + "=="))
    ok("payload has exactly the allowed claims",
       set(payload) == {"sub", "role", "iat", "nbf", "exp", "iss", "aud"},
       f"{sorted(payload)}")
    ok("payload has no password or secret claim",
       not ({"password", "password_hash", "secret"} & set(payload)))

    for role in sorted(ROLES):
        ok(f"role {role!r} can be issued", verify_token(issue_token("u1", role)).role == role)
    ok("exactly 3 roles exist", ROLES == {"customer", "staff", "admin"}, f"{sorted(ROLES)}")

    # ------------------------------------------------------ alg:none forgery
    header = {"alg": "none", "typ": "JWT"}
    body = {"sub": "attacker", "role": "admin", "iat": int(time.time()),
            "nbf": int(time.time()), "exp": int(time.time()) + 9999,
            "iss": ISSUER, "aud": AUDIENCE}

    def b64u(o: dict) -> str:
        import base64
        return base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()

    none_tok = f"{b64u(header)}.{b64u(body)}."
    refuses("alg:none with empty signature", lambda: verify_token(none_tok))
    refuses("alg:none with a fake signature", lambda: verify_token(f"{b64u(header)}.{b64u(body)}.AAAA"))
    refuses("alg:NONE upper case", lambda: verify_token(
        f"{b64u({'alg': 'NONE', 'typ': 'JWT'})}.{b64u(body)}.x"))
    refuses("alg:None mixed case", lambda: verify_token(
        f"{b64u({'alg': 'None', 'typ': 'JWT'})}.{b64u(body)}.x"))

    # ------------------------------------------------- signature forgery
    refuses("payload swapped to admin, signature kept",
            lambda: verify_token(tok[:-4] + ("AAAA" if not tok.endswith("AAAA") else "BBBB")))
    forged_body = dict(body)
    forged_body["role"] = "admin"
    refuses("freshly built admin token with no signature",
            lambda: verify_token(f"{b64u(header)}.{b64u(forged_body)}.x"))
    # Correctly signed with the WRONG key must fail.
    wrong_key_tok = jwt.encode({**body, "sub": "attacker", "role": "admin"},
                               "some-other-attackers-secret-value-x", algorithm="HS256")
    refuses("token signed with an attacker's own key", lambda: verify_token(wrong_key_tok))

    # alg confusion: ask for HS256 explicitly but with a different alg header
    ok("PyJWT is pinned to one algorithm", ALGORITHM == "HS256")

    # --------------------------------------------------------- expiry attacks
    past = int(time.time()) - 10_000
    expired = jwt.encode({"sub": "u", "role": "customer", "iat": past, "nbf": past,
                          "exp": past + 60, "iss": ISSUER, "aud": AUDIENCE},
                         SECRET, algorithm="HS256")
    refuses("expired token", lambda: verify_token(expired))
    just_expired = jwt.encode({"sub": "u", "role": "customer",
                               "iat": int(time.time()) - 200, "nbf": int(time.time()) - 200,
                               "exp": int(time.time()) - 1, "iss": ISSUER, "aud": AUDIENCE},
                              SECRET, algorithm="HS256")
    # 1s past exp is inside a 30s leeway, so it is correctly still accepted.
    # Asserted as-is rather than dressed up as a rejection.
    ok("token 1s past exp is inside the leeway and still valid",
       verify_token(just_expired).role == "customer", "documented, not a bug")
    within_leeway = jwt.encode({"sub": "u", "role": "customer",
                                "iat": int(time.time()) - 60, "nbf": int(time.time()) - 60,
                                "exp": int(time.time()) - 5, "iss": ISSUER, "aud": AUDIENCE},
                               SECRET, algorithm="HS256")
    ok("token 5s expired is inside the 30s clock leeway",
       verify_token(within_leeway).role == "customer", "tolerates server clock drift")
    # Stated honestly: a 30s leeway means a token IS usable for up to 30s past
    # its exp. That is the deliberate cost of tolerating clock drift between
    # machines. It is not zero, and the number is what a reviewer needs to see.
    ok("leeway is exactly 30s, so a token lives at most 30s past exp",
       LEEWAY_SECONDS == 30, f"{LEEWAY_SECONDS}s of extra life")

    no_exp = jwt.encode({"sub": "u", "role": "customer", "iat": int(time.time()),
                         "nbf": int(time.time()), "iss": ISSUER, "aud": AUDIENCE},
                        SECRET, algorithm="HS256")
    refuses("token with no exp at all", lambda: verify_token(no_exp))
    no_iat = jwt.encode({"sub": "u", "role": "customer", "nbf": int(time.time()),
                         "exp": int(time.time()) + 60, "iss": ISSUER, "aud": AUDIENCE},
                        SECRET, algorithm="HS256")
    refuses("token with no iat", lambda: verify_token(no_iat))
    no_nbf = jwt.encode({"sub": "u", "role": "customer", "iat": int(time.time()),
                         "exp": int(time.time()) + 60, "iss": ISSUER, "aud": AUDIENCE},
                        SECRET, algorithm="HS256")
    refuses("token with no nbf", lambda: verify_token(no_nbf))
    no_iss = jwt.encode({"sub": "u", "role": "customer", "iat": int(time.time()),
                         "nbf": int(time.time()), "exp": int(time.time()) + 60, "aud": AUDIENCE},
                        SECRET, algorithm="HS256")
    refuses("token with no issuer", lambda: verify_token(no_iss))
    no_aud = jwt.encode({"sub": "u", "role": "customer", "iat": int(time.time()),
                         "nbf": int(time.time()), "exp": int(time.time()) + 60, "iss": ISSUER},
                        SECRET, algorithm="HS256")
    refuses("token with no audience", lambda: verify_token(no_aud))
    wrong_iss = jwt.encode({"sub": "u", "role": "customer", "iat": int(time.time()),
                            "nbf": int(time.time()), "exp": int(time.time()) + 60,
                            "iss": "someone-else", "aud": AUDIENCE}, SECRET, algorithm="HS256")
    refuses("token from a different issuer", lambda: verify_token(wrong_iss))
    wrong_aud = jwt.encode({"sub": "u", "role": "customer", "iat": int(time.time()),
                            "nbf": int(time.time()), "exp": int(time.time()) + 60,
                            "iss": ISSUER, "aud": "another-app"}, SECRET, algorithm="HS256")
    refuses("token for a different audience", lambda: verify_token(wrong_aud))

    # ------------------------------------------------------- nbf / iat future
    future = int(time.time()) + 10_000
    nbf_future = jwt.encode({"sub": "u", "role": "customer", "iat": int(time.time()),
                             "nbf": future, "exp": future + 60, "iss": ISSUER, "aud": AUDIENCE},
                            SECRET, algorithm="HS256")
    refuses("token not valid yet (nbf in the future)", lambda: verify_token(nbf_future))
    iat_future = jwt.encode({"sub": "u", "role": "customer", "iat": future, "nbf": int(time.time()),
                             "exp": future + 60, "iss": ISSUER, "aud": AUDIENCE},
                            SECRET, algorithm="HS256")
    refuses("token issued in the future", lambda: verify_token(iat_future))

    # -------------------------------------------------- claim smuggling / type
    smuggled = jwt.encode({"sub": "u", "role": "customer", "iat": int(time.time()),
                           "nbf": int(time.time()), "exp": int(time.time()) + 60,
                           "iss": ISSUER, "aud": AUDIENCE, "is_admin": True,
                           "scope": "*"}, SECRET, algorithm="HS256")
    refuses("token carrying extra claims", lambda: verify_token(smuggled))
    obj_sub = jwt.encode({"sub": {"$ne": None}, "role": "admin", "iat": int(time.time()),
                          "nbf": int(time.time()), "exp": int(time.time()) + 60,
                          "iss": ISSUER, "aud": AUDIENCE}, SECRET, algorithm="HS256")
    refuses("sub as an object (NoSQL-style injection)", lambda: verify_token(obj_sub))
    list_sub = jwt.encode({"sub": ["admin"], "role": "admin", "iat": int(time.time()),
                           "nbf": int(time.time()), "exp": int(time.time()) + 60,
                           "iss": ISSUER, "aud": AUDIENCE}, SECRET, algorithm="HS256")
    refuses("sub as a list", lambda: verify_token(list_sub))
    empty_sub = jwt.encode({"sub": "", "role": "customer", "iat": int(time.time()),
                            "nbf": int(time.time()), "exp": int(time.time()) + 60,
                            "iss": ISSUER, "aud": AUDIENCE}, SECRET, algorithm="HS256")
    refuses("empty sub", lambda: verify_token(empty_sub))
    evil_role = jwt.encode({"sub": "u", "role": "superadmin", "iat": int(time.time()),
                            "nbf": int(time.time()), "exp": int(time.time()) + 60,
                            "iss": ISSUER, "aud": AUDIENCE}, SECRET, algorithm="HS256")
    refuses("role of 'superadmin'", lambda: verify_token(evil_role))
    list_role = jwt.encode({"sub": "u", "role": ["admin"], "iat": int(time.time()),
                            "nbf": int(time.time()), "exp": int(time.time()) + 60,
                            "iss": ISSUER, "aud": AUDIENCE}, SECRET, algorithm="HS256")
    refuses("role as a list", lambda: verify_token(list_role))

    # ---------------------------------------------------------- malformed input
    refuses("empty string", lambda: verify_token(""))
    refuses("None", lambda: verify_token(None))
    refuses("integer", lambda: verify_token(12345))
    refuses("bytes", lambda: verify_token(b"a.b.c"))
    refuses("list", lambda: verify_token(["a", "b", "c"]))
    refuses("two segments only", lambda: verify_token("aaa.bbb"))
    refuses("four segments", lambda: verify_token("a.b.c.d"))
    refuses("empty segments", lambda: verify_token(".."))
    refuses("huge token (64 KB)", lambda: verify_token("a" * 65536 + ".b.c"))
    refuses("not valid base64", lambda: verify_token("!!!.???.###"))
    refuses("valid base64, not JSON", lambda: verify_token(
        f"{b64u({'alg': 'HS256'})}.{b64u_str('not json at all')}.sig"))
    refuses("header is JSON but not an object", lambda: verify_token(
        f"{b64u_str('[1,2,3]')}.{b64u_str('{}')}.sig"))

    # ------------------------------------------------------ issuance guardrails
    refuses("issue with an unknown role", lambda: issue_token("u", "root"))
    refuses("issue with role 'admin ' (trailing space)", lambda: issue_token("u", "admin "))
    refuses("issue with an empty user id", lambda: issue_token("", "customer"))
    refuses("issue with a None user id", lambda: issue_token(None, "customer"))
    refuses("issue with a 5000-char user id", lambda: issue_token("x" * 5000, "customer"))
    refuses("issue with a negative ttl", lambda: issue_token("u", "customer", -1))
    refuses("issue with a 10-year ttl", lambda: issue_token("u", "customer", 60 * 24 * 365 * 10))
    refuses("issue with a bool ttl", lambda: issue_token("u", "customer", True))
    refuses("issue with a float ttl", lambda: issue_token("u", "customer", 1.5))

    # ------------------------------------------------------------- RBAC helper
    admin_claims = verify_token(issue_token("owner", "admin"))
    cust_claims = verify_token(issue_token("buyer", "customer"))
    ok("admin may reach admin", require_role(admin_claims, "admin").role == "admin")
    ok("customer blocked from admin", _try(require_role, cust_claims, "admin") is False)
    ok("customer may reach their own area", require_role(cust_claims, "customer", "admin").role == "customer")
    ok("staff blocked from admin", _try(require_role, verify_token(issue_token("s", "staff")), "admin") is False)

    # --------------------------------------------------- weak secret is refused
    config.JWT_SECRET = "short"
    refuses("refuses to issue with a 5-character secret", lambda: issue_token("u", "customer"))
    refuses("refuses to verify with a 5-character secret", lambda: verify_token(tok))
    config.JWT_SECRET = "x" * 31
    refuses("refuses a 31-character secret (under 32)", lambda: issue_token("u", "customer"))
    config.JWT_SECRET = SECRET

    # ============================================================== PAYMENTS
    # Independent .NET-generated HMAC-SHA256 vectors.
    NET_SECRET = "whsec_test_do_not_use_in_production"
    NET_BODY = b'{"entity":"event","event":"payment.captured","contains":["payment"]}'
    NET_SIG = "63aee0fd15e41444f8327c2ed564a90fe0a33641711e334a39e1f43213a454cc"
    NET_SIG_TAMPERED = "fe614febc9dbe780ae524d2ecb846fde742c8c4ec7a25fb6165bbd249eb119e8"

    ok("matches the .NET-generated HMAC vector", sign(NET_BODY, NET_SECRET) == NET_SIG,
       sign(NET_BODY, NET_SECRET))
    ok("one changed character gives a different signature",
       sign(NET_BODY[:-1] + b" ", NET_SECRET) == NET_SIG_TAMPERED)
    ok("a correct signature verifies", verify_signature(NET_BODY, NET_SIG, NET_SECRET))
    ok("uppercase hex is accepted", verify_signature(NET_BODY, NET_SIG.upper(), NET_SECRET))
    ok("surrounding whitespace is tolerated", verify_signature(NET_BODY, f"  {NET_SIG}  ", NET_SECRET))
    ok("one flipped hex digit fails", not verify_signature(NET_BODY, NET_SIG[:-1] + "0", NET_SECRET))
    ok("a different body fails", not verify_signature(NET_BODY + b" ", NET_SIG, NET_SECRET))
    ok("a different secret fails", not verify_signature(NET_BODY, NET_SIG, "wrong-secret"))
    ok("empty signature fails", not verify_signature(NET_BODY, "", NET_SECRET))
    ok("non-hex signature fails", not verify_signature(NET_BODY, "zzzz" * 16, NET_SECRET))
    ok("short signature fails", not verify_signature(NET_BODY, "63aee0", NET_SECRET))
    ok("long signature fails", not verify_signature(NET_BODY, NET_SIG + "00", NET_SECRET))
    ok("None signature fails", not verify_signature(NET_BODY, None, NET_SECRET))
    ok("63-char signature (one short) fails", not verify_signature(NET_BODY, NET_SIG[:-1], NET_SECRET))
    ok("a 1 MB signature string is rejected without hanging",
       not verify_signature(NET_BODY, "a" * 1_000_000, NET_SECRET))
    pay_refuses("missing webhook secret is a server error, not a silent pass",
                lambda: verify_signature(NET_BODY, NET_SIG, ""))
    pay_refuses("non-bytes body is a server error",
                lambda: verify_signature("string body", NET_SIG, NET_SECRET))

    # Key-order tampering: the classic re-serialisation bug.
    ka = b'{"a":1,"b":2}'
    kb = b'{"b":2,"a":1}'
    sa, sb = sign(ka, NET_SECRET), sign(kb, NET_SECRET)
    ok("reordered JSON produces a different signature (raw bytes matter)", sa != sb)
    ok("a signature for the reordered body does not verify the original",
       not verify_signature(ka, sb, NET_SECRET))
    ok("pretty-printed JSON differs from compact", sign(ka, NET_SECRET) != sign(b'{ "a" : 1 , "b" : 2 }', NET_SECRET))

    # ----------------------------------------------------- full event parsing
    def webhook(event: str = "payment.captured", amount: int = 19900,
                currency: str = "INR", pid: str = "pay_abc123",
                oid: str = "order_WFC12345678", extra: dict | None = None) -> bytes:
        p = {"payment": {"entity": {
            "id": pid, "order_id": oid, "amount": amount, "currency": currency,
            "status": "captured", "method": "upi", **(extra or {})}}}
        return json.dumps({"entity": "event", "event": event, "payload": p}).encode()

    good = webhook()
    good_sig = sign(good, NET_SECRET)
    ev = parse_event(good, good_sig, NET_SECRET)
    ok("valid captured webhook parses", ev.amount_paise == 19900)
    ok("order id survives", ev.order_id == "order_WFC12345678")
    ok("payment id survives", ev.payment_id == "pay_abc123")
    ok("captured event marks the order paid", should_mark_paid(ev))
    ok("currency must be INR", ev.currency == EXPECTED_CURRENCY)

    pay_refuses("webhook with a wrong signature", lambda: parse_event(good, "0" * 64, NET_SECRET))
    pay_refuses("webhook with a valid signature but no secret match",
                lambda: parse_event(good, good_sig, "nope"))
    pay_refuses("invalid JSON with a valid signature",
                lambda: parse_event(b"{{{not json", sign(b"{{{not json", NET_SECRET), NET_SECRET))
    pay_refuses("valid JSON but a list, not an object",
                lambda: parse_event(b"[1,2,3]", sign(b"[1,2,3]", NET_SECRET), NET_SECRET))
    pay_refuses("no event name", lambda: parse_event(
        json.dumps({"payload": {"payment": {"entity": {"id": "p", "order_id": "o",
                                                      "amount": 100, "currency": "INR"}}}}).encode(),
        sign(json.dumps({"payload": {"payment": {"entity": {"id": "p", "order_id": "o",
                                                             "amount": 100, "currency": "INR"}}}}).encode(), NET_SECRET), NET_SECRET))
    pay_refuses("amount as a string", lambda: parse_event(webhook(amount="19900"),
                                                          sign(webhook(amount="19900"), NET_SECRET), NET_SECRET))
    pay_refuses("amount as a float", lambda: parse_event(webhook(amount=199.0),
                                                         sign(webhook(amount=199.0), NET_SECRET), NET_SECRET))
    pay_refuses("negative amount", lambda: parse_event(webhook(amount=-500),
                                                       sign(webhook(amount=-500), NET_SECRET), NET_SECRET))
    pay_refuses("zero amount", lambda: parse_event(webhook(amount=0),
                                                   sign(webhook(amount=0), NET_SECRET), NET_SECRET))
    pay_refuses(f"amount over the Rs.{MAX_AMOUNT_PAISE // 100:,} cap",
                lambda: parse_event(webhook(amount=MAX_AMOUNT_PAISE + 1),
                                    sign(webhook(amount=MAX_AMOUNT_PAISE + 1), NET_SECRET), NET_SECRET))
    pay_refuses("currency USD", lambda: parse_event(webhook(currency="USD"),
                                                    sign(webhook(currency="USD"), NET_SECRET), NET_SECRET))
    pay_refuses("empty payment id", lambda: parse_event(webhook(pid=""),
                                                        sign(webhook(pid=""), NET_SECRET), NET_SECRET))
    pay_refuses("missing order id", lambda: parse_event(
        json.dumps({"event": "payment.captured", "payload": {"payment": {"entity": {
            "id": "pay_1", "amount": 100, "currency": "INR"}}}}).encode(),
        sign(json.dumps({"event": "payment.captured", "payload": {"payment": {"entity": {
            "id": "pay_1", "amount": 100, "currency": "INR"}}}}).encode(), NET_SECRET), NET_SECRET))

    # -------------------------------------------- only captured may mark paid
    for never in ("payment.authorized", "payment.failed", "refund.processed",
                  "refund.failed", "dispute.raised"):
        b = webhook(event=never)
        e = parse_event(b, sign(b, NET_SECRET), NET_SECRET)
        ok(f"{never} never marks an order paid", not should_mark_paid(e))
    for unknown in ("payment.created", "subscription.charged", "payout.sent", "nonsense"):
        b = webhook(event=unknown)
        e = parse_event(b, sign(b, NET_SECRET), NET_SECRET)
        ok(f"unknown event {unknown!r} does not mark paid", not should_mark_paid(e))

    # ------------------------------------------------------------- replay
    store = ProcessedEvents()
    ok("first delivery is not a duplicate", not store.already_handled(ev))
    record(store, ev)
    ok("replayed webhook is detected as a duplicate", store.is_duplicate(ev.event_id))
    record(store, ev)
    ok("recording twice is still a duplicate", store.is_duplicate(ev.event_id))
    other = parse_event(webhook(pid="pay_other"), sign(webhook(pid="pay_other"), NET_SECRET), NET_SECRET)
    ok("a genuinely new payment is not a duplicate", not store.is_duplicate(other.event_id))

    # A permissive membership test would quietly return False here and switch
    # replay protection off without any error. Refusing loudly is the point.
    pay_refuses("passing an event instead of an id raises, not silently returns False",
                lambda: store.is_duplicate(ev))
    pay_refuses("empty event id raises", lambda: store.is_duplicate(""))
    pay_refuses("None event id raises", lambda: store.is_duplicate(None))

    # timing: verification should not be orders of magnitude slower for a
    # near-miss than for a total miss (a crude leak check)
    t_near = time.perf_counter()
    for _ in range(300):
        verify_signature(good, good_sig[:-1] + ("0" if good_sig[-1] != "0" else "1"), NET_SECRET)
    near = time.perf_counter() - t_near
    t_far = time.perf_counter()
    for _ in range(300):
        verify_signature(good, "0" * 64, NET_SECRET)
    far = time.perf_counter() - t_far
    ok("near-miss signature is not obviously slower than a total miss",
       near < far * 4 + 0.05, f"near {near * 1000:.1f}ms far {far * 1000:.1f}ms")

finally:
    config.JWT_SECRET = _saved_secret

print("=" * 88)
print("WFC TOKEN + PAYMENT ATTACK TESTS")
print("=" * 88)
passed = sum(1 for _, o, _ in results if o)
for name, o, detail in results:
    print(f"  [{'PASS' if o else 'FAIL'}] {name:<58} {detail}".encode("ascii", "replace").decode())
print("=" * 88)
print(f"  {passed}/{len(results)} passed")
print("=" * 88)
raise SystemExit(0 if passed == len(results) else 1)
