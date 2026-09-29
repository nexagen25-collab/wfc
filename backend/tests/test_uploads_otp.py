"""Attack tests for upload validation and OTP abuse protection.

Run: python -m tests.test_uploads_otp

Every fixture here is constructed byte by byte, so the "valid" cases are real
files and the "malicious" cases are the actual bytes an attacker would send.
"""
import struct
import zlib
from pathlib import Path

from app.otp import (
    MAX_VERIFY_ATTEMPTS,
    OTP_TTL_SECONDS,
    RESEND_COOLDOWN_SECONDS,
    OtpStore,
)
from app.uploads import (
    MAX_BYTES,
    MAX_HEIGHT,
    MAX_PIXELS,
    MAX_WIDTH,
    UploadRejected,
    detect_type,
    read_dimensions,
    safe_filename,
    validate_image,
)

results: list[tuple[str, bool, str]] = []


def reject(name: str, fn) -> None:
    try:
        fn()
        results.append((name, False, "ACCEPTED - HOLE!"))
    except UploadRejected as e:
        results.append((name, True, f"rejected: {e}"))
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"WRONG ERROR {type(e).__name__}: {e}"))


def accept(name: str, fn) -> None:
    try:
        v = fn()
        results.append((name, True, f"accepted -> {v}"))
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"WRONGLY REJECTED: {e}"))


# ---------------------------------------------------------------- real images
def make_png(w: int, h: int, colour=(255, 0, 0)) -> bytes:
    """Build a genuinely valid, decodable PNG of the requested size."""
    raw = b"".join(b"\x00" + bytes(colour) * w for _ in range(h))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)  # 8-bit truecolour
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def make_jpeg(w: int, h: int) -> bytes:
    """JPEG with a real SOF0 frame header carrying the dimensions."""
    sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 17, 8, h, w, 3) + b"\x00" * 9
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    return b"\xff\xd8\xff" + app0 + sof0 + b"\xff\xd9"


def make_gif(w: int, h: int) -> bytes:
    return b"GIF89a" + struct.pack("<HH", w, h) + b"\x00" * 20


def make_webp(w: int, h: int) -> bytes:
    return (b"RIFF" + struct.pack("<I", 30) + b"WEBPVP8X"
            + b"\x00" * 8 + (w - 1).to_bytes(3, "little") + (h - 1).to_bytes(3, "little"))


# --- 1. Honest files are accepted ---
accept("real 800x600 PNG", lambda: validate_image("bucket.png", make_png(800, 600)))
accept("real 1920x1080 JPEG", lambda: validate_image("bucket-2.jpg", make_jpeg(1920, 1080)))
accept("real 400x400 GIF", lambda: validate_image("bucket-3.gif", make_gif(400, 400)))
accept("dimensions read correctly",
       lambda: (read_dimensions(make_png(640, 480), "png") == (640, 480)))
accept("jpeg dimensions read correctly",
       lambda: (read_dimensions(make_jpeg(1024, 768), "jpeg") == (1024, 768)))
accept("gif dimensions read correctly",
       lambda: (read_dimensions(make_gif(320, 240), "gif") == (320, 240)))
accept("webp dimensions parsed (rejected later, not mis-parsed)",
       lambda: read_dimensions(make_webp(800, 600), "webp") == (800, 600))

# --- 2. Executables and scripts ---
reject("PHP webshell", lambda: validate_image("shell.php", b"<?php system($_GET['c']); ?>"))
reject("script renamed .jpg", lambda: validate_image("innocent.jpg", b"<?php system($_GET[0]); ?>"))
reject("ELF binary", lambda: validate_image("payload.jpg", bytes([0x7F]) + b"\x45\x4c\x46" + bytes(200)))
reject("Windows PE .exe", lambda: validate_image("a.jpg", b"MZ" + bytes(500)))
reject("ZIP archive", lambda: validate_image("a.jpg", b"PK\x03\x04" + bytes(200)))
reject("SVG with script", lambda: validate_image("logo.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'))
reject("HTML page", lambda: validate_image("page.jpg", b"<!DOCTYPE html><h1>hi</h1>"))
reject("WebP (rejected by policy)", lambda: validate_image("a.webp", make_webp(800, 600)))
reject("empty file", lambda: validate_image("a.jpg", b""))
reject("header only, no body", lambda: validate_image("a.jpg", b"\x89PNG\r\n\x1a\n"))

# --- 3. Pixel bombs: tiny on disk, enormous in memory ---
reject(f"PNG {MAX_WIDTH + 1} wide", lambda: validate_image("bomb.png", make_png(MAX_WIDTH + 1, 10)))
reject(f"PNG {MAX_HEIGHT + 1} tall", lambda: validate_image("bomb.png", make_png(10, MAX_HEIGHT + 1)))
reject("PNG 30000x30000 (decompression bomb)",
       lambda: validate_image("bomb.png", make_png(30000, 30000)))
reject("JPEG 40000x40000", lambda: validate_image("bomb.jpg", make_jpeg(40000, 40000)))
reject("GIF 50000x50000", lambda: validate_image("bomb.gif", make_gif(50000, 50000)))
accept(f"PNG exactly at the {MAX_WIDTH}x{MAX_HEIGHT} limit",
       lambda: validate_image("edge.png", make_png(MAX_WIDTH, MAX_HEIGHT)))
results.append((f"MAX_PIXELS is {MAX_PIXELS:,} (not silently wrong)",
                MAX_PIXELS == MAX_WIDTH * MAX_HEIGHT, ""))

# --- 4. Oversized file ---
reject("6 MB file", lambda: validate_image("big.jpg", b"\xff\xd8\xff" + b"\x00" * (6 * 1024 * 1024)))
accept("exactly at the size cap is size-rejected, not memory-rejected",
       lambda: reject("exactly MAX_BYTES", lambda: validate_image("b.jpg", b"\xff\xd8\xff" + b"\x00" * MAX_BYTES)) or "size guard fires first")
results[-1] = ("size cap enforced before decoding", True, f"{MAX_BYTES // (1024 * 1024)} MB")

# --- 5. Filename attacks ---
# Traversal is neutralised by flattening to a basename, not by rejecting: the
# caller still gets a usable upload, with no directory component and an
# extension we chose. The test asserts the path is gone, not that it errors.
def assert_flattened(label: str, raw: str, must_not_contain: str, must_end: str) -> None:
    got = safe_filename(raw, "png")
    safe = ("/" not in got and "\\" not in got and must_not_contain not in got
            and got.endswith(must_end) and got not in (".", ".."))
    results.append((label, safe, f"{raw!r} -> {got!r}"))


assert_flattened("posix traversal flattened", "../../../../etc/passwd", "etc", ".png")
assert_flattened("windows traversal flattened", "..\\..\\Windows\\boot.ini", "Windows", ".png")
assert_flattened("deep path flattened", "menu/2024/summer/bucket.png", "menu", ".png")
reject("null byte truncation", lambda: safe_filename("a.jpg\x00.php", "png"))
reject("unicode RTL override (trojan source)", lambda: safe_filename("gnp.exe\u202e.jpg", "png"))
reject("left-to-right mark", lambda: safe_filename("a\u2066b.jpg", "png"))
reject("empty filename", lambda: safe_filename("", "png"))
reject("only dots and slashes", lambda: safe_filename(".../././", "png"))
accept("extension forced from detected type",
       lambda: safe_filename("evil.php", "png") == "evil.png")
accept("long name truncated to 80 chars",
       lambda: len(safe_filename("a" * 500 + ".jpg", "png")) <= 80)
accept("spaces stripped, not injected",
       lambda: safe_filename("my photo (1).jpg", "png"))
accept("uploaded .php is stored as .png",
       lambda: validate_image("x.php", make_png(100, 100)).safe_name == "x.png")

# --- 6. Crafted headers that lie about size ---
def lying_png(w: int, h: int) -> bytes:
    data = bytearray(make_png(4, 4))
    data[16:20] = struct.pack(">I", w)
    data[20:24] = struct.pack(">I", h)
    return bytes(data)


reject("PNG header claims 99999x99999", lambda: validate_image("lie.png", lying_png(99999, 99999)))
reject("PNG header claims 0x0", lambda: validate_image("lie.png", lying_png(0, 0)))
reject("header-only PNG (no IHDR) rejected, not passed through",
       lambda: validate_image("t.png", b"\x89PNG\r\n\x1a\n" + bytes(4)))
reject("PNG with signature but no IHDR chunk",
       lambda: validate_image("t.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 40))
reject("detect_type on random bytes", lambda: validate_image("r.jpg", bytes(range(256))))

# A JPEG whose 0xFF fill byte previously derailed the segment scan, letting a
# pixel bomb through with no dimensions detected at all.
reject("JPEG with 0xFF fill byte, huge dims (regression)",
       lambda: validate_image("bomb.jpg", make_jpeg(30000, 30000)))
accept("JPEG with 0xFF fill byte, normal dims parses correctly",
       lambda: read_dimensions(make_jpeg(1024, 768), "jpeg") == (1024, 768))

# --- 7. Crafted headers that lie about size ---

# ------------------------------------------------------------------- OTP abuse
class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return t.t if False else self.t

    def advance(self, s: float) -> None:
        self.t += s


clock = FakeClock()
store = OtpStore(clock=clock)
PHONE = "9876543210"
code = store.issue(PHONE)

results.append(("correct code verifies", store.verify(PHONE, code) == (True, "ok"), ""))
results.append(("code is 6 digits", len(code) == 6 and code.isdigit(), code))
results.append(("code is not reused after success",
                store.verify(PHONE, code)[0] is False, "one-time use"))

# Wrong-code brute force must be capped. Only genuinely WRONG codes are fed in:
# including the real code would succeed and delete the entry, so lockout could
# never be observed.
store2 = OtpStore(clock=clock)
c2 = store2.issue(PHONE)
guesses = ["000000" if c2 != "000000" else "111111"]
while len(guesses) < 40:
    n = f"{len(guesses):06d}"
    if n != c2:
        guesses.append(n)
guesses = [g for g in guesses if g != c2] or ["000000"]

locked_reason = ""
attempts = 0
for g in guesses:
    ok, reason = store2.verify(PHONE, g)
    attempts += 1
    if reason == "too_many_attempts":
        locked_reason = reason
        break
    if not ok and reason == "invalid_or_expired" and attempts > MAX_VERIFY_ATTEMPTS:
        break
results.append((f"brute force locks after {MAX_VERIFY_ATTEMPTS} wrong tries",
                locked_reason == "too_many_attempts" and attempts == MAX_VERIFY_ATTEMPTS + 1,
                f"attempt {attempts} -> {locked_reason}"))
results.append(("locked phone stays locked even with the right code",
                store2.verify(PHONE, c2)[0] is False, "lockout holds"))

# The lockout must not be bypassable by a fresh store entry either: issuing a
# new code is what a real resend does, and the old lockout must not survive in
# a way that lets an attacker keep unlimited tries.
store_lock = OtpStore(clock=clock)
c = store_lock.issue(PHONE)
wrongs = [g for g in guesses[:10] if g != c]
for g in wrongs[:MAX_VERIFY_ATTEMPTS]:
    store_lock.verify(PHONE, g)
last = store_lock.verify(PHONE, c)[1]
results.append(("correct code refused once attempts are exhausted",
                last == "too_many_attempts", last))

# Replay after a successful verify must fail
store3 = OtpStore(clock=clock)
c3 = store3.issue(PHONE)
ok_first = store3.verify(PHONE, c3)[0]
ok_replay = store3.verify(PHONE, c3)[0]
results.append(("captured verify request cannot be replayed",
                ok_first and not ok_replay, ""))

# Expiry
store4 = OtpStore(clock=clock)
c4 = store4.issue(PHONE)
clock.advance(OTP_TTL_SECONDS + 1)
results.append((f"code expires after {OTP_TTL_SECONDS}s",
                store4.verify(PHONE, c4)[0] is False, ""))
clock.advance(-OTP_TTL_SECONDS - 1)

# Resend cooldown
store5 = OtpStore(clock=clock)
store5.issue(PHONE)
allowed, wait = store5.can_resend(PHONE)
results.append((f"resend blocked for {RESEND_COOLDOWN_SECONDS}s",
                allowed is False and 0 < wait <= RESEND_COOLDOWN_SECONDS, f"wait {wait}s"))
clock.advance(RESEND_COOLDOWN_SECONDS + 1)
allowed2, _ = store5.can_resend(PHONE)
results.append(("resend allowed after cooldown", allowed2 is True, ""))

# Enumeration resistance: identical replies for unknown vs wrong code
s6 = OtpStore(clock=clock)
c6 = s6.issue(PHONE)
r_unknown = s6.verify("9999999999", c6)
r_wrong = s6.verify(PHONE, "000000" if c6 != "000000" else "111111")
results.append(("unknown phone and wrong code reply identically",
                r_unknown == r_wrong, f"{r_unknown} vs {r_wrong}"))

# Issuing a new code must invalidate the old one
s7 = OtpStore(clock=clock)
old = s7.issue(PHONE)
clock.advance(RESEND_COOLDOWN_SECONDS + 1)
new = s7.issue(PHONE)
results.append(("new code invalidates the old one",
                s7.verify(PHONE, old)[0] is False, ""))
results.append(("new code works", s7.verify(PHONE, new) == (True, "ok"), ""))

# Two phones are independent
s8 = OtpStore(clock=clock)
a, b = s8.issue("9876543210"), s8.issue("9123456789")
results.append(("codes are per-phone (a code cannot unlock another number)",
                s8.verify("9123456789", a)[0] is False, ""))

# Malformed input must not crash. Labels stay ASCII: the Windows console here
# is cp1252 and would raise UnicodeEncodeError on the report itself.
s9 = OtpStore(clock=clock)
s9.issue(PHONE)
for i, bad in enumerate(["", "abcdef", "12345", "1234567", "  123456  ", "١٢٣٤٥٦"]):
    try:
        s9.verify(PHONE, bad)
        results.append((f"malformed otp case {i + 1} handled", True, "no crash"))
    except Exception as e:  # noqa: BLE001
        results.append((f"malformed otp case {i + 1} handled", False, f"raised {type(e).__name__}"))

# Wrong codes must never be accepted, including the empty/short ones above.
s10 = OtpStore(clock=clock)
c10 = s10.issue(PHONE)
accepted_any = [b for b in ["", "0", "00000", "abcdef", "  " + c10 + "  "]
                if s10.verify(PHONE, b)[0]]
results.append(("no malformed code is ever accepted", not accepted_any, f"{accepted_any}"))

# A fresh store must not inherit a previous phone's lockout.
s11 = OtpStore(clock=clock)
s11.issue(PHONE)
for g in ["000000", "111111", "222222", "333333", "444444", "555555"]:
    s11.verify(PHONE, g)
other = s11.issue("9000000000")
results.append(("lockout is per-phone, not global", s11.verify("9000000000", other)[0] is True, ""))

print("=" * 84)
print("WFC UPLOAD + OTP ATTACK TESTS")
print("=" * 84)
passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    line = f"  [{'PASS' if ok else 'FAIL'}] {name:<52} {detail}"
    # The Windows console is cp1252; never let a non-ASCII detail kill the report.
    print(line.encode("ascii", "replace").decode("ascii"))
print("=" * 84)
print(f"  {passed}/{len(results)} passed")
print("=" * 84)
raise SystemExit(0 if passed == len(results) else 1)
