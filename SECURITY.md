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
| Passwords, JWTs, OTPs, signatures, DB URLs and phones scrubbed from logs | `backend/app/logging_redaction.py` | 114/114 redaction tests, incl. secrets in exception tracebacks |
| A route with no auth dependency stops the app from starting | `backend/app/auth_deps.py` | detector proven able to fail on GET/POST/PUT/PATCH/DELETE and on a plain `Route` |
| Every 401 response is byte-identical across all failure modes | `backend/app/auth_deps.py` | 7 forgery modes compared |
| Only the three approved roles can be issued or accepted | `backend/app/tokens.py`, `app/auth_deps.py` | `superadmin`, list-typed role, unknown role refused |
| Production refuses to boot on a missing or short signing secret | `backend/app/config.py` | 3 CI guardrail cases (placeholder, 31 chars, 32 chars) |
| Exception headers survive our custom error handler | `backend/app/main.py` | `Retry-After` / `X-Teapot` preservation test |
| `/auth/` routes get 5/3/10 per 5 min instead of 120/min, on separate buckets | `backend/app/rate_limit.py` | 74/74 rate tests |
| A strict limit cannot be loosened or disabled by an environment variable | `backend/app/rate_limit.py` | env 999999 clamped to 5; env 0 and -5 clamped to 1 |
| Concurrent password hashing capped; over-capacity refused, never queued | `backend/app/rate_limit.py` | 24 threads, peak held at 4/4, 13307 refusals |
| An `/auth/` route with no strict limit stops the app from starting | `backend/app/auth_deps.py` | startup check fires on `/auth/refresh`, proven able to fail |

Run all seven attack suites:

```bash
cd backend
.\.venv\Scripts\python.exe -m tests.test_security
.\.venv\Scripts\python.exe -m tests.test_crypto
.\.venv\Scripts\python.exe -m tests.test_uploads_otp
.\.venv\Scripts\python.exe -m tests.test_pricing
.\.venv\Scripts\python.exe -m tests.test_tokens_payments
.\.venv\Scripts\python.exe -m tests.test_auth_redaction
.\.venv\Scripts\python.exe -m tests.test_rate_guard
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
14. **Login CPU exhaustion: mitigated, not closed.** scrypt costs a measured
    196 ms of CPU per password check, which is the point — it is what makes
    stolen hashes expensive to crack. It also means each login attempt is
    ~3,500 times an authenticated request. The general 120/min/IP budget would
    have let one address force ~23 CPU-seconds per minute, so `/auth/login`,
    `/auth/otp/request` and `/auth/otp/verify` now have their own 5/3/10 per
    5-minute budgets on separate buckets, and `PASSWORD_HASH_GUARD` caps
    concurrent hashes at 4 per process. **No route uses any of this yet**, and
    both mechanisms are per-process: with N instances the effective limit is N
    times what is written here. Move both to Redis before scaling out.
15. **Log redaction is pattern matching, not a guarantee.** A key name with no
    `:` or `=` after it is not caught (`api-key ABC123` in bare prose), a secret
    split across two log lines is not caught, and it is O(log line length) at
    ~420 us/KB. It is a safety net behind rule 8, not a replacement for it.
16. **No HTTPS locally, no penetration test, no security logging or alerting.**
17. **Input validation is not a substitute for authorisation.**

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

## Performance budget — measured, not guessed

Recorded 2026-09-29 on a Windows dev machine, Python 3.14, uvicorn single
worker. These are here so that a future change which quietly makes a security
control ten times more expensive is visible rather than discovered in
production. They are measurements on one machine, not targets.

| Control | Cost | When it runs |
| --- | --- | --- |
| `verify_token()` (signature + all claim checks) | ~55 us | every authenticated request |
| `issue_token()` | ~34 us | login only |
| scrypt `hash_password` / `verify_password` | **196 ms** | login only |
| `redact()` typical log line | ~32 us | every log record |
| `redact()` line containing a JWT | ~11 us | every log record |
| `redact()` 1 KB log line | ~870 us | scales at ~420 us/KB |
| webhook HMAC verify | ~7 us | per webhook |
| `price_cart()` 20 items | ~39 us | per quote |
| route protection audit | ~5 us | **once at startup** |

End-to-end over localhost HTTP, position-rotated to remove ordering bias:

| Request | p50 | p95 |
| --- | --- | --- |
| `GET /health` (public) | 2.61 ms | 5.10 ms |
| `GET /me` no token -> 401 | 2.66 ms | 5.84 ms |
| `GET /me` valid token -> 200 | 3.65 ms | 5.68 ms |
| `GET /admin/ping` admin -> 200 | 3.72 ms | 5.85 ms |

The full authenticated request costs about **1.0 ms more** than an
unauthenticated one, and only ~55 us of that is token cryptography. The rest is
FastAPI dependency resolution and the HTTP layer. Profiling 1000 authenticated
requests (`cProfile`) shows the entire security stack — signature verification,
claim validation, rate limiting, the security-headers middleware — accounting
for under 0.01 ms per 1000 requests of cumulative time, while `solve_dependencies`
and the sync-endpoint threadpool hop dominate. **The security controls are not
the bottleneck and there is no case for weakening them on performance grounds.**

Two consequences that are real constraints, not trivia:

1. **scrypt is 196 ms of CPU per login attempt, by design.** That is the price
   of making stolen password hashes expensive to crack, and it is worth paying.
   It is also a CPU-exhaustion amplifier: at the current 120 requests/minute/IP
   limit, one IP can force ~23 CPU-seconds per minute, and per-process
   rate limiting does nothing against an attacker spreading attempts across IPs.
   Mitigation is a much tighter limit on the login and OTP-verify routes
   specifically, and eventually a global cap on concurrent password hashes.
   **Not implemented — it changes customer-facing behaviour, so it is your call.**
   Measured capacity: 5 hashes/sec on one thread, ~12/sec on four (scrypt
   releases the GIL only partly).
2. **`redact()` is O(log line length) at ~420 us/KB.** A 64 KB log line costs
   26 ms. Today nothing logs request bodies and request bodies are capped at
   1 MB, so exposure is low. Do not start logging raw bodies, payloads or large
   database error strings: redaction would then cost more than the request.
3. **`async def` vs `def` is worth 241 us per request** on these endpoints.
   FastAPI runs a sync `def` endpoint in a threadpool. `/me` and `/admin/ping`
   are `async def` because they only validate and do crypto. Keep that split.

### A benchmarking trap worth knowing about

A 429 from the rate limiter **short-circuits before token verification**, so a
throttled request is *cheaper* than a served one. A benchmark that quietly trips
the rate limit therefore measures the cheap path and will report the entire
security stack as free. This happened during the measurements above: the first
run showed authenticated routes appearing ~1 ms *faster* than `/health`, which
was impossible, and the cause was the limiter returning 429 for everything after
the first 120 requests. Always assert a 2xx in a latency harness before
believing it, and lift the limit for the run.

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
   `app/logging_redaction.py` is a safety net for the day that rule is broken,
   not a reason to log them.
9. Never use `Math.random()` for anything an attacker benefits from guessing.
   Tokens, OTPs and nonces come from `secrets` in `app/security.py`.
10. Any file a user can upload goes through `app/uploads.py`. Never write an
    upload using the name the client sent; use `ValidatedImage.safe_name`.
11. **Every new route needs an auth dependency or a `PUBLIC_ROUTES` entry.**
    `enforce_route_protection()` runs at import, so forgetting is a crash, not a
    hole. Do not add to `PUBLIC_ROUTES` to make a test pass.
12. `async def` for endpoints that only validate or do crypto. Plain `def` for
    endpoints that block on I/O, so FastAPI runs them off the event loop.
13. Do not log request bodies, payloads or long database error strings. Redaction
    is O(size) at ~420 us/KB and would become the most expensive part of a
    request.
14. **Wrap every password hash in `PASSWORD_HASH_GUARD.slot()`.** It refuses
    immediately when the process is already at capacity; do not add a queue or
    a retry loop around it.
15. Re-run the seven attack suites and `npm audit` / `pip-audit` before every
    release. They are in CI, but CI is not a substitute for reading them.
