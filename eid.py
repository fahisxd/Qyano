import base64
import binascii
import quopri
import re
from html import unescape


def _result(kind, **details):
    return {"type": kind, **details}


def detect_hash(text):
    if not isinstance(text, str):
        return None
    value = text.strip()
    prefix = None
    for candidate in ("sha512", "sha384", "sha256", "sha224", "sha1", "md5"):
        marker = candidate + ":"
        if value.lower().startswith(marker):
            prefix, value = candidate, value[len(marker):]
            break

    if not re.fullmatch(r"[0-9a-fA-F]+", value):
        return None
    candidates = {
        32: ["MD5", "NTLM"], 40: ["SHA-1", "RIPEMD-160"],
        56: ["SHA-224"], 64: ["SHA-256", "SHA3-256", "BLAKE2s-256"],
        96: ["SHA-384", "SHA3-384"],
        128: ["SHA-512", "SHA3-512", "BLAKE2b-512"],
    }.get(len(value))
    if prefix:
        candidates = [name for name in (candidates or []) if name.lower().replace("-", "") == prefix.replace("-", "")]
        if not candidates:
            return None
    if not candidates:
        return None
    return _result("hash", algorithms=candidates, confidence="shape-only",
                   evidence=f"{len(value)} hexadecimal characters")


def detect_base64(text):
    """Detect canonical standard or URL-safe Base64 and report decoded bytes."""
    if not isinstance(text, str) or not text or any(ch.isspace() for ch in text):
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/_-]*={0,2}", text):
        return None
    if ("+" in text or "/" in text) and ("-" in text or "_" in text):
        return None
    body = text.rstrip("=")
    supplied_padding = len(text) - len(body)
    if len(body) % 4 == 1:
        return None
    normalized = body.translate(str.maketrans("-_", "+/"))
    try:
        decoded = base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)
    except (ValueError, binascii.Error):
        return None
    if base64.b64encode(decoded).decode("ascii").rstrip("=") != normalized:
        return None
    required_padding = (-len(body)) % 4
    if supplied_padding and supplied_padding != required_padding:
        return None
    try:
        decoded_text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        decoded_text = None
    url_safe = "-" in text or "_" in text
    return _result("base64-url" if url_safe else "base64", decoded_bytes=len(decoded),
                   decoded_text=decoded_text, confidence="canonical")


def detect_url_encoding(text):
    """Detect valid percent-encoded bytes and flag malformed percent signs."""
    if not isinstance(text, str) or "%" not in text:
        return None
    valid = re.findall(r"%[0-9a-fA-F]{2}", text)
    malformed = re.search(r"%(?![0-9a-fA-F]{2})", text)
    if not valid:
        return None
    return _result("url-percent-encoding", escapes=len(valid),
                   malformed_escape=bool(malformed))


def detect_binary(text):
    if not isinstance(text, str) or not text or not re.fullmatch(r"[01]+", text):
        return None
    complete_bytes, remainder = divmod(len(text), 8)
    return _result("binary", complete_bytes=complete_bytes,
                   bit_length=len(text), byte_aligned=(remainder == 0))


def detect_base32(text):
    if not isinstance(text, str) or not text or any(ch.isspace() for ch in text):
        return None
    candidate = text.upper()
    if not re.fullmatch(r"[A-Z2-7]+=*", candidate):
        return None
    body = candidate.rstrip("=")
    padding = len(candidate) - len(body)
    if len(body) % 8 in (1, 3, 6):
        return None
    required = (-len(body)) % 8
    if padding and padding != required:
        return None
    try:
        decoded = base64.b32decode(body + "=" * required, casefold=True)
    except (ValueError, binascii.Error):
        return None
    if base64.b32encode(decoded).decode("ascii").rstrip("=") != body:
        return None
    return _result("base32", decoded_bytes=len(decoded), confidence="canonical")


def detect_base85(text):
    if not isinstance(text, str) or len(text) < 5 or not text.isascii():
        return None
    raw = text.encode("ascii")
    matches = []
    for name, decoder, encoder in (
        ("ascii85", base64.a85decode, base64.a85encode),
        ("base85", base64.b85decode, base64.b85encode),
    ):
        try:
            decoded = decoder(raw)
            if encoder(decoded) == raw:
                matches.append(name)
        except (ValueError, binascii.Error):
            pass
    if not matches:
        return None
    return _result("base85", variants=matches, confidence="possible")


def detect_hex(text):
    if not isinstance(text, str) or not text or len(text) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", text):
        return None
    return _result("hex", decoded_bytes=len(text) // 2)


def detect_html_entities(text):
    if not isinstance(text, str) or not re.search(r"&(?:#[0-9]+|#x[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]+);", text):
        return None
    decoded = unescape(text)
    if decoded == text:
        return None
    return _result("html-entities", decoded_text=decoded)


def detect_unicode_escapes(text):
    if not isinstance(text, str):
        return None
    pattern = r"\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2})"
    escapes = re.findall(pattern, text)
    if not escapes:
        return None
    try:
        decoded = text.encode("utf-8").decode("unicode_escape")
    except UnicodeError:
        return _result("unicode-escape", escapes=len(escapes), decodable=False)
    return _result("unicode-escape", escapes=len(escapes), decoded_text=decoded)


def detect_quoted_printable(text):
    if not isinstance(text, str) or not re.search(r"(?:=[0-9a-fA-F]{2}|=\r?\n)", text):
        return None
    try:
        decoded = quopri.decodestring(text.encode("ascii")).decode("utf-8")
    except (UnicodeError, ValueError):
        decoded = None
    return _result("quoted-printable", decoded_text=decoded)


def identifier_engine(text):
    if not isinstance(text, str):
        return {"error": "error/engines/eid/input-must-be-text"}

    detectors = (
        detect_hash, detect_base64, detect_url_encoding, detect_binary,
        detect_base32, detect_base85, detect_html_entities,
        detect_unicode_escapes, detect_quoted_printable, detect_hex,
    )
    identifiers = [match for detector in detectors
                   if (match := detector(text)) is not None]
    if not identifiers:
        identifiers.append(_result("unknown"))
    return {"input": text, "identifiers": identifiers}
