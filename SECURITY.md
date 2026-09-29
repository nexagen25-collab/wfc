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
| Truncated / re-costed hashes cannot authenticate | `backend/app/security.py` | regression tests in `test_crypto` |
| Order tokens from `secrets`, not `Math.random`; 100M number space | `backend/app/security.py` | measured collision rate + repo-wide `Math.random` scan |
| OTP lockout, expiry, resend cooldown, one-time use, replay-proof | `backend/app/otp.py` | 68/68 attack tests |
| Unknown phone and wrong code return identical replies | `backend/app/otp.py` | enumeration test |
| Image uploads: magic-byte type, no SVG, forced extension, sanitised name | `backend/app/uploads.py` | PHP/ELF/PE/ZIP/SVG/HTML all rejected |
| Pixel-bomb and size limits read from the header, fail closed | `backend/app/uploads.py` | 40000x40000 and 6 MB rejected |
| Path traversal, null bytes, unicode RTL overrides neutralised | `backend/app/uploads.py` | filename attack tests |
| No XSS sinks in frontend source | `frontend/` | `dangerouslySetInnerHTML`/`eval`/`innerHTML` scan |
| Admin and Staff mocks fail closed in production builds | `frontend/components/MockGate.tsx` | production build HTML |
| No secrets in git | `.gitignore` | tracked-file scan |
| Known dependency CVEs | both | `npm audit` 0, `pip-audit` none |

Run all three attack suites:

```bash
cd backend
.\.venv\Scripts\python.exe -m tests.test_security
.\.venv\Scripts\python.exe -m tests.test_crypto
.\.venv\Scripts\python.exe -m tests.test_uploads_otp
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
4. **No payments.** No Razorpay integration, therefore **no webhook signature
   verification**. Never mark an order paid based on a browser redirect alone.
5. **The OTP store is in-process memory.** Attempt limits and expiry reset on
   restart and are **not shared between workers**, so on more than one instance
   the lockout can be side-stepped by spreading guesses across workers. It must
   move to the database or Redis before this scales. Written up in `app/otp.py`.
6. **No upload route exists yet.** `app/uploads.py` validates bytes correctly,
   but nothing calls it, and the owner still has to supply 36 menu photos.
   WebP is refused rather than half-validated.
7. **No secret rotation.** `.env` values are assumed good on day one.
8. **Rate limiting is per-process.** It resets on restart and does not share
   counts across instances. Fine for one server, wrong for more.
9. **CSP allows `'unsafe-inline'` for scripts**, required by the Next.js runtime.
   This weakens the policy and is a known limitation.
10. **No HTTPS locally, no penetration test, no security logging or alerting.**
11. **Input validation is not a substitute for authorisation.**

## Threat model — who attacks this and how

| Attacker | Goal | Main risk today | Control that must exist |
|---|---|---|---|
| Random internet scanner | Find any weakness | Security headers, CORS, rate limit | Already in place |
| Bot abusing OTP | Burn SMS credits, spam customers | Unthrottled `/auth/otp` | Per-phone cooldown + attempt cap in `app/otp.py` (in-process — move to DB) + CAPTCHA when real |
| Fraudulent customer | Order cheap food, pay nothing | COD abuse with fake numbers | OTP-verified phone, address validation, order limits |
| Malicious customer | Pay ₹1 for a ₹300 burger | Price tampering | `extra="forbid"`, no price field, server-side pricing — in place |
| XSS attacker | Steal admin session | Stored script in address fields | Field validation (in place) + React auto-escaping + CSP. No `dangerouslySetInnerHTML` in the codebase |
| Attacker with an order token | Read someone else's order | Token disclosure, no ownership check | 100M unguessable token space (in place) **plus** ownership checks — not built |
| Uploader | Put a webshell on the server | File upload | Magic-byte typing, no SVG, forced extension, size and pixel caps, sanitised names — in place, but no route yet |
| Database thief | Dump customers and orders | Plaintext credentials | Encrypted connections, least-privilege DB role, no prod data in dev |
| Attacker who reads `.env` | Full control | Secrets in git or logs | Gitignore, rotate keys, never commit |

## Incident already open — act on this

**The Railway PostgreSQL password was pasted into a chat conversation and must
be treated as compromised.** It was never written to a file in this repository.
Rotate it in Railway before that database is connected to anything.

## Rules for this codebase

1. Never trust a client-supplied price, total, discount, role, or user id.
2. Validate every input with a schema in `app/schemas.py`, never ad hoc.
3. Never put a secret in frontend code. Only `NEXT_PUBLIC_*` may reach a browser,
   and the Razorpay *key id* is the only one of those that is safe.
4. Never return internal error text to a client.
5. Never mark an order paid without verifying a Razorpay webhook signature.
6. Never use `Math.random()` for anything an attacker benefits from guessing.
   Tokens, OTPs and nonces come from `secrets` in `app/security.py`.
7. Any file a user can upload goes through `app/uploads.py`. Never write an
   upload using the name the client sent; use `ValidatedImage.safe_name`.
8. Re-run the three attack suites and `npm audit` / `pip-audit` before every
   release. They are in CI, but CI is not a substitute for reading them.
