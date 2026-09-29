"""Image upload validation.

An upload endpoint is one of the easiest places to get a server badly
compromised, so this module is deliberately strict: it rejects anything it
does not positively recognise as a safe raster image.

Why SVG is banned: an SVG file is a program. Serve one as an image and the
browser runs the <script> inside it, in your own domain. There is no safe way
to accept user SVG, so we do not.

Why the file extension is not trusted: `payload.php.jpg` and a PNG renamed to
`x.exe` are the whole problem. The extension is only ever taken from the bytes
we detected, never from what the caller sent.

Dimensions are read from the file header, not from a full decode. That gives
pixel-bomb protection (a 60,000x60,000 PNG is a few KB on disk and gigabytes
in memory) without pulling in an image library.
"""
from dataclasses import dataclass

# Pixel-bomb guard. A legitimate menu photo is nowhere near this.
MAX_WIDTH = 4000
MAX_HEIGHT = 4000
MAX_PIXELS = 4000 * 4000
# Single file cap. 5 MB is far above a menu photo and far below disk exhaustion.
MAX_BYTES = 5 * 1024 * 1024

# Only these three. Each entry is (magic prefix, offset the prefix starts at).
_SIGNATURES: tuple[tuple[bytes, int], ...] = (
    (b"\xff\xd8\xff", 0),                    # JPEG (SOI + next marker)
    (b"\x89PNG\r\n\x1a\n", 0),               # PNG
    (b"GIF87a", 0),                          # GIF
    (b"GIF89a", 0),                          # GIF
)

_EXT_FOR_TYPE = {"jpeg": ".jpg", "png": ".png", "gif": ".gif"}

# Characters that must never survive into a stored filename. Includes the
# bidirectional overrides used in "trojan source" attacks, where a file called
# gnp.exe can visually read as png.exe.
_UNSAFE_CHARS = set('/\\:*?"<>|') | {chr(c) for c in range(32)} | {chr(127)}


class UploadRejected(Exception):
    """Raised with a safe, specific reason. Never echo the payload back."""


@dataclass(frozen=True)
class ValidatedImage:
    detected_type: str
    safe_name: str
    width: int | None
    height: int | None
    size: int


def detect_type(head: bytes) -> str | None:
    """Identify the real format from magic bytes. Returns None if unknown."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    # RIFF....WEBP - the 4 bytes at offset 8 are the real tag.
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def read_dimensions(data: bytes, kind: str) -> tuple[int | None, int | None]:
    """Best-effort width/height from the header, without decoding pixels."""
    try:
        if kind == "png":
            # IHDR is always the first chunk: 8 sig + 4 len + 4 type = offset 16.
            if len(data) < 24 or data[12:16] != b"IHDR":
                return (None, None)
            w = int.from_bytes(data[16:20], "big")
            h = int.from_bytes(data[20:24], "big")
            return (w, h)

        if kind == "gif":
            if len(data) < 10:
                return (None, None)
            return (
                int.from_bytes(data[6:8], "little"),
                int.from_bytes(data[8:10], "little"),
            )

        if kind == "jpeg":
            # Walk marker segments to the start-of-frame, which holds the real
            # dimensions.
            #
            # Two details matter for security here. A 0xFF fill byte may legally
            # repeat before any marker; if it is treated as the start of a
            # marker, the two bytes after it get misread as a segment length
            # and the scan runs off the end of the file, returning NO
            # dimensions - which would skip the pixel-bomb check entirely. And
            # markers D0-D9 / 01 carry no payload, so their length must not be
            # read at all. The scan is bounded so a crafted file cannot spin us.
            i = 2
            end = min(len(data), 65_536)
            while i < end:
                if data[i] != 0xFF:
                    i += 1
                    continue
                while i < end and data[i] == 0xFF:      # skip fill bytes
                    i += 1
                if i >= end:
                    break
                marker = data[i]
                i += 1
                if marker == 0xD9 or marker == 0xDA:     # EOI / start of scan
                    break
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    continue                            # standalone, no payload
                if i + 2 > end:
                    break
                seg = int.from_bytes(data[i : i + 2], "big")
                if seg < 2:
                    break
                # SOF0-SOF15, excluding DHT (C4), JPG (C8) and DAC (CC).
                if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                    if i + 7 > end:
                        break
                    h = int.from_bytes(data[i + 3 : i + 5], "big")
                    w = int.from_bytes(data[i + 5 : i + 7], "big")
                    return (w, h)
                i += seg
            return (None, None)

        if kind == "webp":
            if len(data) < 30:
                return (None, None)
            chunk = data[12:16]
            if chunk == b"VP8X":
                w = int.from_bytes(data[24:27], "little") + 1
                h = int.from_bytes(data[27:30], "little") + 1
                return (w, h)
            if chunk == b"VP8 ":
                return (
                    int.from_bytes(data[26:28], "little") & 0x3FFF,
                    int.from_bytes(data[28:30], "little") & 0x3FFF,
                )
            if chunk == b"VP8L":
                bits = int.from_bytes(data[21:25], "little")
                return ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1)
            return (None, None)
    except (IndexError, ValueError):
        return (None, None)
    return (None, None)


def safe_filename(original: str, detected_type: str) -> str:
    """Reduce a caller-supplied name to a safe basename with our own extension.

    Directory components are discarded outright rather than sanitised, because
    there is no legitimate reason for a menu photo to contain a path.
    """
    if not original:
        raise UploadRejected("Missing filename.")

    # Null bytes truncate filenames in C libraries: "a.jpg\x00.php" can be
    # written as a .php file while the validator believes it saw a .jpg.
    if "\x00" in original:
        raise UploadRejected("Illegal character in filename.")

    # Unicode bidirectional overrides are invisible and can disguise an
    # extension from whoever reviews the uploads folder later.
    for ch in original:
        if ch in ("\u202e", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069"):
            raise UploadRejected("Illegal character in filename.")

    base = original.replace("\\", "/").split("/")[-1]
    base = "".join("_" if ch in _UNSAFE_CHARS else ch for ch in base).strip(". ")
    base = base[:80]

    if not base:
        raise UploadRejected("Missing filename.")

    stem = base.rsplit(".", 1)[0] if "." in base else base
    # Keep only characters that survive being a URL path segment.
    stem = "".join(c for c in stem if c.isalnum() or c in "-_")[:60] or "image"
    return f"{stem}{_EXT_FOR_TYPE[detected_type]}"


def validate_image(original_name: str, data: bytes) -> ValidatedImage:
    """Validate an upload end to end, or raise UploadRejected with the reason."""
    if not data:
        raise UploadRejected("File is empty.")
    if len(data) > MAX_BYTES:
        raise UploadRejected(
            f"File is too large (limit {MAX_BYTES // (1024 * 1024)} MB)."
        )

    kind = detect_type(data[:32])
    if kind is None:
        # Covers .php, .html, .svg, .exe, .zip, and a PNG that was truncated
        # below its signature. We never guess.
        raise UploadRejected("Unsupported file type. Use JPG, PNG, GIF or WebP.")

    if kind == "webp":
        # WebP header parsing is implemented but not covered by fixtures yet,
        # so it is refused rather than half-checked.
        raise UploadRejected("WebP uploads are not accepted yet.")

    width, height = read_dimensions(data, kind)
    if width is None or height is None:
        # Fail closed. A file whose header we cannot read has not been checked
        # for pixel bombs, and "we could not measure it" must never mean
        # "therefore it is safe". This also rejects truncated files that are
        # all signature and no image.
        raise UploadRejected("File is not a readable image (damaged or incomplete).")
    if width <= 0 or height <= 0:
        raise UploadRejected("Image dimensions are invalid.")
    if width > MAX_WIDTH or height > MAX_HEIGHT or width * height > MAX_PIXELS:
        raise UploadRejected(
            f"Image is too large ({width}x{height}). "
            f"Maximum is {MAX_WIDTH}x{MAX_HEIGHT}."
        )

    return ValidatedImage(
        detected_type=kind,
        safe_name=safe_filename(original_name, kind),
        width=width,
        height=height,
        size=len(data),
    )
