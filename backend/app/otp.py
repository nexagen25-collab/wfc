"""Phone OTP issuing and verification.

A 6-digit OTP is only 1,000,000 possibilities. Without limits that is
guessable: at 100 requests/second an attacker cracks one code in under three
hours. Three independent limits make it impractical:

  1. a short expiry, so a leaked code is worthless quickly
  2. a hard attempt cap, so a single code cannot be brute forced
  3. a resend cooldown, so SMS credits cannot be burned by spamming

The store here is in-process memory. That is correct for one server and is NOT
correct for production: it resets on restart and is not shared between
instances, so on more than one worker the attempt cap can be side-stepped.
Move it to the database (or Redis) before scaling out. This is called out here
rather than left to be discovered in production.
"""
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field

OTP_LENGTH = 6
OTP_TTL_SECONDS = 300          # 5 minutes
MAX_VERIFY_ATTEMPTS = 5
RESEND_COOLDOWN_SECONDS = 60
# Bounded so an attacker cannot grow the store with junk phone numbers.
MAX_TRACKED_PHONES = 10_000


def _hash(phone: str, otp: str) -> str:
    """Bind the hash to the phone number so codes cannot be swapped between users."""
    return hashlib.sha256(f"{phone}:{otp}".encode()).hexdigest()


@dataclass
class _Entry:
    otp_hash: str
    expires_at: float
    attempts_left: int = MAX_VERIFY_ATTEMPTS
    cooldown_until: float = 0.0
    locked: bool = False


class OtpStore:
    def __init__(self, clock=time.monotonic) -> None:
        self._data: dict[str, _Entry] = {}
        self._clock = clock

    def _purge(self) -> None:
        now = self._clock()
        expired = [p for p, e in self._data.items() if e.expires_at < now and not e.locked]
        for p in expired:
            del self._data[p]
        if len(self._data) > MAX_TRACKED_PHONES:
            self._data = dict(list(self._data.items())[:MAX_TRACKED_PHONES // 2])

    def can_resend(self, phone: str) -> tuple[bool, int]:
        """Returns (allowed, seconds_remaining)."""
        self._purge()
        entry = self._data.get(phone)
        if not entry:
            return (True, 0)
        remaining = int(entry.cooldown_until - self._clock())
        if remaining > 0:
            return (False, remaining)
        return (True, 0)

    def issue(self, phone: str) -> str:
        """Generate and store a new OTP. Caller is responsible for sending it.

        Issuing replaces any previous code, so only the newest code ever works.
        """
        self._purge()
        otp = "".join(secrets.choice("0123456789") for _ in range(OTP_LENGTH))
        now = self._clock()
        self._data[phone] = _Entry(
            otp_hash=_hash(phone, otp),
            expires_at=now + OTP_TTL_SECONDS,
            attempts_left=MAX_VERIFY_ATTEMPTS,
            cooldown_until=now + RESEND_COOLDOWN_SECONDS,
        )
        return otp

    def verify(self, phone: str, otp: str) -> tuple[bool, str]:
        """Returns (ok, reason). Never reveals whether the phone exists."""
        self._purge()
        entry = self._data.get(phone)

        # Identical response for unknown phone, wrong code, and expired code.
        # Differing replies would let an attacker enumerate which numbers are
        # registered customers.
        if entry is None:
            return (False, "invalid_or_expired")
        if self._clock() > entry.expires_at:
            del self._data[phone]
            return (False, "invalid_or_expired")
        if entry.locked or entry.attempts_left <= 0:
            return (False, "too_many_attempts")

        if not hmac.compare_digest(_hash(phone, otp), entry.otp_hash):
            entry.attempts_left -= 1
            if entry.attempts_left <= 0:
                entry.locked = True
            return (False, "invalid_or_expired")

        # One-time use: a captured request must not be replayable.
        del self._data[phone]
        return (True, "ok")
