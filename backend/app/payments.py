"""Razorpay payment verification.

The rule: an order is marked paid ONLY from a webhook whose HMAC signature
verifies against the raw request body. Never from a browser redirect, never
from a client-side success callback, never from an amount the client sent.
Those are all things a customer can forge with curl.

Three mistakes this module is written to prevent:

  1. Verifying a re-serialised payload instead of the raw bytes. JSON key
     order and whitespace change the bytes, so a re-serialised body produces a
     different HMAC and every real webhook would be rejected. Conversely,
     signing the parsed object is what lets an attacker reorder keys freely.
     We hash exactly the bytes that arrived.
  2. Comparing signatures with `==`. That leaks timing. We use compare_digest.
  3. Processing the same event twice. Razorpay retries, so a replayed webhook
     would otherwise credit an order more than once. Processed event ids are
     remembered and a repeat is refused.

NOT WIRED UP: no route, no database, and no real webhook secret. The tests use
a published test vector and a throwaway secret.
"""
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field

# Razorpay sends a hex-encoded HMAC-SHA256 in the X-Razorpay-Signature header.
_SIG_RE = re.compile(r"^[0-9a-f]{64}$")

SIGNATURE_HEADER = "x-razorpay-signature"
EXPECTED_CURRENCY = "INR"
# Razorpay amounts are in the smallest unit: paise. Rs.199 is 19900.
MAX_AMOUNT_PAISE = 5_000_000          # Rs.50,000, matching the order cap
MIN_AMOUNT_PAISE = 1


class PaymentError(Exception):
    """Raised when a payment event cannot be trusted. Safe to log."""


@dataclass
class ProcessedEvents:
    """Remembers event ids already handled. In-process; see the note below.

    IN-PROCESS ONLY. This resets on restart and is not shared between workers,
    so on more than one instance a replayed webhook can be accepted again by a
    different worker. Move it to the database with a UNIQUE constraint on the
    payment id before scaling out. Until then, duplicate protection is a
    convenience against a single process retrying, not a guarantee.
    """
    seen: set[str] = field(default_factory=set)

    def is_duplicate(self, event_id: str) -> bool:
        # Strict on purpose. If a caller passes a PaymentEvent by mistake, a
        # permissive `in` check would quietly return False and replay protection
        # would silently do nothing. Failing loudly is the safe behaviour for
        # the control whose whole job is to stop a duplicate credit.
        if not isinstance(event_id, str) or not event_id:
            raise PaymentError("Event id must be a non-empty string.")
        return event_id in self.seen

    def mark(self, event_id: str) -> None:
        if not isinstance(event_id, str) or not event_id:
            raise PaymentError("Event id must be a non-empty string.")
        self.seen.add(event_id)

    def already_handled(self, event: "PaymentEvent") -> bool:
        """Convenience wrapper so callers do not pass the wrong thing."""
        return self.is_duplicate(event.event_id)


def sign(raw_body: bytes, secret: str) -> str:
    """Compute the expected signature. Used by tests; the server never signs."""
    if not secret:
        raise PaymentError("Webhook secret is not configured.")
    return hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()


def verify_signature(raw_body: bytes, provided: str, secret: str) -> bool:
    """True only if `provided` is the correct hex HMAC-SHA256 of `raw_body`.

    `raw_body` must be the exact bytes of the request, not a re-encoding.
    """
    if not isinstance(raw_body, (bytes, bytearray)):
        raise PaymentError("Raw body must be bytes.")
    if not isinstance(provided, str):
        return False
    # Normalise to lowercase; header case varies but hex content should not.
    candidate = provided.strip().lower()
    if not _SIG_RE.fullmatch(candidate):
        # Wrong shape entirely. Rejecting early also avoids handing a
        # gigabyte of junk to the comparison.
        return False
    if not secret:
        raise PaymentError("Webhook secret is not configured.")
    expected = sign(bytes(raw_body), secret)
    return hmac.compare_digest(expected, candidate)


@dataclass(frozen=True)
class PaymentEvent:
    event_id: str
    event: str
    payment_id: str
    order_id: str
    amount_paise: int
    currency: str


def parse_event(raw_body: bytes, signature: str, secret: str) -> PaymentEvent:
    """Verify then parse. Verification happens first, always.

    Parsing an unverified payload is how a forged webhook gets to influence
    the database, so the order of these two lines is the whole point.
    """
    if not verify_signature(raw_body, signature, secret):
        raise PaymentError("Invalid webhook signature.")

    try:
        data = json.loads(bytes(raw_body).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PaymentError("Webhook body is not valid JSON.") from None

    if not isinstance(data, dict):
        raise PaymentError("Webhook body is not an object.")

    event = data.get("event")
    if not isinstance(event, str) or not event:
        raise PaymentError("Webhook has no event name.")

    payload = data.get("payload")
    if not isinstance(payload, dict):
        raise PaymentError("Webhook has no payload.")

    entity = payload.get("payment", {}).get("entity") if isinstance(payload.get("payment"), dict) else None
    if not isinstance(entity, dict):
        raise PaymentError("Webhook has no payment entity.")

    event_id = entity.get("id")
    if not isinstance(event_id, str) or not event_id or len(event_id) > 128:
        raise PaymentError("Webhook has no usable payment id.")

    order_id = entity.get("order_id")
    if not isinstance(order_id, str) or not order_id or len(order_id) > 128:
        raise PaymentError("Webhook has no usable order id.")

    amount = entity.get("amount")
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise PaymentError("Payment amount is not an integer number of paise.")
    if not MIN_AMOUNT_PAISE <= amount <= MAX_AMOUNT_PAISE:
        raise PaymentError("Payment amount is out of range.")

    currency = entity.get("currency")
    if currency != EXPECTED_CURRENCY:
        raise PaymentError(f"Unexpected currency: {currency!r}.")

    return PaymentEvent(
        event_id=event_id,
        event=event,
        payment_id=event_id,
        order_id=order_id,
        amount_paise=amount,
        currency=currency,
    )


# Razorpay event names that mean the money is actually in the account.
CAPTURED_EVENTS = frozenset({"payment.captured"})
# Events that must never mark an order paid, whatever their signature says.
NEVER_PAID_EVENTS = frozenset({
    "payment.authorized",     # authorised, not captured - can still fail
    "payment.failed",
    "refund.processed",
    "refund.failed",
    "dispute.raised",
})


def should_mark_paid(event: PaymentEvent) -> bool:
    """Only an explicitly captured payment may mark an order paid."""
    if event.event in NEVER_PAID_EVENTS:
        return False
    return event.event in CAPTURED_EVENTS


def is_duplicate(processed: ProcessedEvents, event: PaymentEvent) -> bool:
    return processed.is_duplicate(event.event_id)


def record(processed: ProcessedEvents, event: PaymentEvent) -> None:
    processed.mark(event.event_id)
