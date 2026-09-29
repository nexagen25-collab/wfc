"""Scrub secrets out of log output.

Most breaches are not clever. They are a password, an OTP, an API key or a
database URL sitting in a log file that got shipped to a log aggregator, pasted
into a ticket, or read by someone who should not have it.

Metrics solved. Docker solved. Logs did not.

This module is a last line of defence, not the first. The rule in SECURITY.md
is still "never log a credential". This exists for the day someone breaks that
rule at 2am and does not notice.

What it catches:

  JWTs                     eyJ...eyJ...
  Bearer headers           "Authorization: Bearer <token>"
  Key/value pairs          password=..., "token": "...", api_key: ...
  Database URLs            postgres://user:pw@host  ->  postgres://user:[..]@host
  Razorpay signatures      64 hex characters
  Phone numbers            +91 98765 43210
  Email addresses          someone@example.com

Deliberate limits, stated plainly:

  * Phone redaction will also mangle any bare 10-digit number starting 6-9.
    That is a false positive we accept, because the alternative is leaking a
    customer's phone number. Order tokens are 8 digits and are not affected.
  * A key name is only treated as a secret when followed by `:` or `=`. Real
    headers and JSON always have one, but `api-key ABC123` in bare prose is not
    caught. Dropping the separator would mean redacting sentences like "the
    token expired", which is its own kind of unusable log.
  * A secret split across two log lines is not caught. Neither is one written
    as a bare hex string shorter than 64 characters.
  * This is pattern matching. It is not a guarantee, and it is not a reason to
    log things you should not log.
"""
from __future__ import annotations

import logging
import re

REDACTED = "[REDACTED]"

# 64 hex characters: SHA-256 digests and Razorpay webhook signatures.
_HEX64 = re.compile(r"\b[0-9a-fA-F]{64}\b")

_KEY_NAMES = (
    "client_secret",
    "refresh_token",
    "access_token",
    "razorpay_signature",
    "private_key",
    "card_number",
    "cardnumber",
    "authorization",
    "api[-_]?key",
    "password",
    "passwd",
    "apikey",
    "secret",
    "signature",
    "session",
    "token",
    "cookie",
    "otp",
    "pwd",
    "pin",
    "cvv2",
    "cvv",
    "jwt",
    "auth",
)

# Keys are matched with an optional closing quote so both `password=x` and
# `"password": "x"` are caught. The separator (: or =) is required, so the word
# "passwordless" and the phrase "no token here" are left alone.
_KEY_VALUE = re.compile(
    r"(?i)(\b(?:" + "|".join(_KEY_NAMES) + r")\b['\"]?\s*[:=]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # JWT: three base64url segments, the first decoding to '{"'. Handles the
    # empty third segment of an alg:none token too.
    (re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "[REDACTED-JWT]"),
    # Authorization: Bearer <token>
    (
        re.compile(r"(?i)\b(bearer)\s+([A-Za-z0-9._~+/=-]{4,})"),
        r"\1 " + REDACTED,
    ),
    # Connection strings: keep the scheme and the username, hide the password.
    (
        re.compile(
            r"(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
            r"([^:@/\s]+):([^@/\s]+)@"
        ),
        r"\1://\2:[REDACTED]@",
    ),
    # 64 hex chars: signatures and digests.
    (_HEX64, "[REDACTED-SIGNATURE]"),
    # Email addresses.
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED-EMAIL]",
    ),
    # Indian mobile numbers, with or without +91, and with spaces or dashes
    # between the groups. Lookarounds rather than \b, because "+91" and
    # "98765 43210" do not start on a word boundary.
    (
        re.compile(r"(?<![\d])(?:\+?91[-\s]?)?[6-9][-\s]?\d{4}[-\s]?\d{5}(?![\d])"),
        "[REDACTED-PHONE]",
    ),
    # Key/value secrets. Last, so the specific rules above win.
    (_KEY_VALUE, r"\1" + REDACTED),
]


def redact(value: object) -> str:
    """Return `value` as a string with recognised secrets replaced.

    Safe to call on anything. Never raises, never returns None, and is
    idempotent: redacting an already-redacted string changes nothing.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if not text:
        return text
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    """A handler or logger filter that scrubs a record before it is formatted.

    Attach to handlers, not only loggers. A filter on a parent *logger* is not
    applied to records that propagate up from child loggers, but a filter on a
    *handler* is applied to every record that handler emits. uvicorn's access
    and error logs are the ones most likely to carry a token in a query string.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - broken args must not break logging
            message = str(record.msg)
        record.msg = redact(message)
        record.args = ()

        # Exception text is formatted later, by whichever formatter the handler
        # has. Set exc_text here so a plain logging.Formatter still gets a
        # scrubbed traceback instead of regenerating an unredacted one.
        if record.exc_info and not record.exc_text:
            record.exc_text = redact(_EXC_FORMATTER.formatException(record.exc_info))
        elif record.exc_text:
            record.exc_text = redact(record.exc_text)

        return True


class RedactingFormatter(logging.Formatter):
    """Wraps any formatter and redacts the final string.

    Catches everything, including the parts of a record a filter cannot reach.
    Useful when the app installs its own logging config.
    """

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


_EXC_FORMATTER = logging.Formatter()

# Loggers the app and uvicorn actually emit through.
_TARGET_LOGGERS = ("", "uvicorn", "uvicorn.error", "uvicorn.access", "wfc")


def install_redaction() -> int:
    """Attach redaction to the app and uvicorn loggers and their handlers.

    Returns the number of loggers and handlers it touched. Idempotent: calling
    it twice does not stack filters.
    """
    touched = 0
    loggers = [logging.getLogger(name) for name in _TARGET_LOGGERS]

    handlers: list[logging.Handler] = []
    for logger in loggers:
        handlers.extend(logger.handlers)
    # lastResort is the handler used when a logger has no handler of its own,
    # which is exactly the "I forgot to configure logging" case.
    if logging.lastResort is not None:
        handlers.append(logging.lastResort)

    for handler in handlers:
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(RedactingFilter())
            touched += 1

    for logger in loggers:
        if not any(isinstance(f, RedactingFilter) for f in logger.filters):
            logger.addFilter(RedactingFilter())
            touched += 1

    return touched
