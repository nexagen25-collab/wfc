# WFC — Security

Honest status as of the date in the last commit. This file lists what is
protected, what is **not**, and what must happen before real money is involved.

> **This application is not secure today.** It is a UI prototype plus a hardened
> API shell. No authentication, no database, no payments are real. The controls
> below are real and tested, but they protect a system that is not yet finished.
> Do not launch this to customers.

## What is protected and verified

| Control | Where | Verified by |
|---|---|---|
| Security headers (CSP, HSTS, frame denial, nosniff, referrer, permissions) | `backend/app/main.py`, `frontend/next.config.ts` | Live HTTP checks |
| CORS allowlist, credentials off, explicit methods | `backend/app/main.py` | Request from `evil-hacker.com` got no ACAO header |
| Per-IP rate limiting with `Retry-After` | `backend/app/rate_limit.py` | 130 rapid requests → 429 |
| 1 MB request body cap | `backend/app/main.py` | 1.2 MB POST → 413 |
| No stack traces or DB errors in responses | `backend/app/main.py` | generic 500, detail logged server-side |
| Refuses to boot in production with a placeholder secret | `backend/app/config.py` | `ENVIRONMENT=production` raises RuntimeError |
| Strict input validation, unknown fields rejected | `backend/app/schemas.py` | 31/31 attack tests |
| Server-side pricing, clients cannot send price/total/discount/role | `backend/app/schemas.py` | attack tests |
| Password hashing (scrypt, unique salt, constant-time compare) | `backend/app/security.py` | 41/41 attack tests |
| `alg:none` and algorithm-confusion token forgery refused | `backend/app/tokens.py` | 122/122 token + payment tests |
| `exp`/`nbf`/`iat`/`iss`/`aud` all required and verified | `backend/app/tokens.py` | missing-claim and future-timestamp tests |
| Unknown claims, non-string `sub`, non-approved roles refused | `backend/app/tokens.py` | claim smuggling tests |
| Refuses to sign with a secret under 32 characters | `backend/app/tokens.py` | short-secret tests |
| Webhook HMAC verified against **raw bytes**, constant-time compare | `backend/app/payments.py` | .NET-generated HMAC vectors |
| Only `payment.captured` may mark an order paid | `backend/app/payments.py` | authorized/failed/refund/dispute tests |
| Replayed webhooks detected | `backend/app/payments.py` | duplicate-delivery tests |
| Truncated / re-costed hashes cannot authenticate | `backend/app/security.py` | regression tests in `test_crypto` |
| Order tokens from `secrets`, not `Math.random`; 100M number space | `backend/app/security.py` | measured collision rate + repo-wide `Math.random` scan |
| OTP lockout, expiry, resend cooldown, one-time use, replay-proof | `backend/app/otp.py` | 68/68 attack tests |
| Unknown phone and wrong code return identical replies | `backend/app/otp.py` | enumeration test |
| Image uploads: magic-byte type, no SVG, forced extension, sanitised name | `backend/app/uploads.py` | PHP/ELF/PE/ZIP/SVG/HTML all rejected |
| Pixel-bomb and size limits read from the header, fail closed | `backend/app/uploads.py` | 40000x40000 and 6 MB rejected |
| Path traversal, null bytes, unicode RTL overrides neutralised | `backend/app/uploads.py` | filename attack tests |
| No XSS sinks in frontend source | `frontend/` | `dangerouslySetInnerHTML`/`eval`/`innerHTML` scan |
| Server-side pricing, clients cannot send price/total/discount/role | `backend/app/schemas.py`, `backend/app/pricing.py` | 88/88 pricing + tamper tests |
| Integer-only money, no floats, discount can never exceed subtotal | `backend/app/pricing.py` | 200% and 1000% coupon clamp tests |
| Sold-out items cannot be ordered | `backend/app/menu.py` | 88/88 pricing tests |
| Backend and frontend menus cannot drift apart in price | `backend/app/menu.py` | `test_pricing` parses `menu.ts` and diffs 36/36 |
| Admin and Staff mocks fail closed in production builds | `frontend/components/MockGate.tsx` | production build HTML |
| No secrets in git | `.gitignore` | tracked-file scan |
| Known dependency CVEs | both | `npm audit` 0, `pip-audit` none |

Run all three attack suites:

```bash
cd backend
.\.venv\Scripts\python.exe -m tests.test_security
.\.venv\Scripts\python.exe -m tests.test_crypto
.\.venv\Scripts\python.exe -m tests.test_uploads_otp
.\.venv\Scripts\python.exe -m tests.test_pricing
.\.venv\Scripts\python.exe -m tests.test_tokens_payments
```

They also run automatically on every push via `.github/workflows/security.yml`,
along with the dependency audits and two guardrail assertions.

## What is NOT protected — the real risks

1. **No authentication.** `/admin` and `/staff` are mocks behind `MockGate`.
   Real login needs hashed passwords and sessions. **Blocked on a database.**
2. **No authorization.** No code checks whether a caller is the owner of an
   order. Anyone with a valid token can currently read any order. Tokens are
   now hard to guess, but guessing them is not the only way to get one.
3. **No database.** So no SQL parameterisation, migrations, or row-level
   protection exist yet. We use UUID primary keys to avoid guessable IDs, but
   that is not access control.
4. **No payments wired up.** The webhook verifier in `app/payments.py` is
   correct and tested, but there is no route, no Razorpay account, and no
   database row to mark paid. Until that is built, an order can never be marked
   paid at all — which is the safe failure direction.
5. **Tokens cannot be revoked.** A JWT is valid until it expires (7 days).
   Firing a staff member or handling a stolen token means the old token still
   works. This needs a server-side session table or a denylist, which needs the
   database. Do not treat logout as revocation.
6. **Replay protection is in-process.** `ProcessedEvents` resets on restart and
   is not shared between workers, so a second worker can accept a replayed
   webhook. Needs a UNIQUE constraint on the payment id in the database.
7. **The OTP store is in-process memory.** Attempt limits and expiry reset on
   restart and are **not shared between workers**, so on more than one instance
   the lockout can be side-stepped by spreading guesses across workers. It must
   move to the database or Redis before this scales. Written up in `app/otp.py`.
8. **The menu is duplicated in two places.** `backend/app/menu.py` and
   `frontend/lib/menu.ts` must agree, and `test_pricing` enforces that. It is a
   safety net, not a design: the database becomes the single source of truth.
   A test is not a substitute for one source of truth.
9. **No upload route exists yet.** `app/uploads.py` validates bytes correctly,
   but nothing calls it, and the owner still has to supply 36 menu photos.
   WebP is refused rather than half-validated.
10. **No secret rotation.** `.env` values are assumed good on day one.
11. **Rate limiting is per-process.** It resets on restart and does not share
    counts across instances. Fine for one server, wrong for more.
12. **CSP allows `'unsafe-inline'` for scripts**, required by the Next.js runtime.
    This weakens the policy and is a known limitation.
13. **Tokens get 30 seconds of extra life** past `exp`, the clock-drift leeway.
    Deliberate, small, and named in the tests so nobody "fixes" it by accident.
14. **No HTTPS locally, no penetration test, no security logging or alerting.**
15. **Input validation is not a substitute for authorisation.**

## Threat model — who attacks this and how

| Attacker | Goal | Main risk today | Control that must exist |
|---|---|---|---|
| Random internet scanner | Find any weakness | Security headers, CORS, rate limit | Already in place |
| Bot abusing OTP | Burn SMS credits, spam customers | Unthrottled `/auth/otp` | Per-phone cooldown + attempt cap in `app/otp.py` (in-process — move to DB) + CAPTCHA when real |
| Fraudulent customer | Order cheap food, pay nothing | COD abuse with fake numbers | OTP-verified phone, address validation, order limits |
| Malicious customer | Pay ₹1 for a ₹300 burger | Price tampering | `extra="forbid"`, no price field, server-side pricing — in place |
| XSS attacker | Steal admin session | Stored script in address fields | Field validation (in place) + React auto-escaping + CSP. No `dangerouslySetInnerHTML` in the codebase |
| Attacker with an order token | Read someone else's order | Token disclosure, no ownership check | 100M unguessable token space (in place) **plus** ownership checks — not built |
| Forger | Self-issue an admin JWT | `alg:none`, algorithm confusion, claim smuggling, no expiry | HS256 pinned, required claims, claim whitelist, 7-day max TTL — in place, but no route uses it yet |
| Forger | Mark an order paid without paying | Fake browser success callback | Only a signed `payment.captured` webhook may mark paid; verifier in place, route not built |
| Replay attacker | Reuse a captured webhook | Duplicate credit | Event-id dedupe (in place, in-process) + DB UNIQUE constraint — not built |
| Token thief | Reuse a stolen JWT | Logout does not revoke | Nothing yet. Needs server-side sessions — blocked on the database |
| Uploader | Put a webshell on the server | File upload | Magic-byte typing, no SVG, forced extension, size and pixel caps, sanitised names — in place, but no route yet |
| Database thief | Dump customers and orders | Plaintext credentials | Encrypted connections, least-privilege DB role, no prod data in dev |
| Attacker who reads `.env` | Full control | Secrets in git or logs | Gitignore, rotate keys, never commit |

## Incident already open — act on this

**The Railway PostgreSQL password was pasted into a chat conversation and must
be treated as compromised.** It was never written to a file in this repository.
Rotate it in Railway before that database is connected to anything.

## Rules for this codebase

1. Never trust a client-supplied price, total, discount, role, or user id.
   `price_cart()` takes product ids and quantities and nothing else. If you ever
   add a price argument to it, you have removed the shop's entire defence.
2. Validate every input with a schema in `app/schemas.py`, never ad hoc.
3. Never put a secret in frontend code. Only `NEXT_PUBLIC_*` may reach a browser,
   and the Razorpay *key id* is the only one of those that is safe.
4. Never return internal error text to a client.
5. Never mark an order paid without a verified Razorpay webhook signature, and
   only from `payment.captured`. A browser redirect is not proof of payment.
6. Always verify a webhook against the **raw request bytes**, never a
   re-serialised dict. Re-encoding changes the bytes and breaks the HMAC.
7. Pass `algorithms=["HS256"]` to `jwt.decode` and keep the algorithm pinned in
   `app/tokens.py`. Dropping that argument reopens `alg:none`.
8. Never log a password, token, OTP or webhook signature. They are credentials.
6. Never use `Math.random()` for anything an attacker benefits from guessing.
   Tokens, OTPs and nonces come from `secrets` in `app/security.py`.
7. Any file a user can upload goes through `app/uploads.py`. Never write an
   upload using the name the client sent; use `ValidatedImage.safe_name`.
9. Re-run the five attack suites and `npm audit` / `pip-audit` before every
   release. They are in CI, but CI is not a substitute for reading them.
