"""Text normalization, decoding, and sanitization utilities."""

import re
import unicodedata
import base64
from typing import Tuple, List, Optional

# Zero-width unicode characters commonly used to split keywords or smuggle tokens
ZERO_WIDTH_CHARS = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # zero-width no-break space (BOM)
    "\u2060",  # word joiner
    "\u180e",  # mongolian vowel separator
}

# Basic leetspeak translation table for de-obfuscation
LEET_DICT = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
    "|": "l",
}


def strip_zero_width(text: str) -> Tuple[str, int]:
    """Remove invisible zero-width unicode characters. Returns (clean_text, count_removed)."""
    count = 0
    clean_chars = []
    for ch in text:
        if ch in ZERO_WIDTH_CHARS:
            count += 1
        else:
            clean_chars.append(ch)
    return "".join(clean_chars), count


def normalize_unicode(text: str) -> str:
    """Normalize unicode to NFKC to resolve homoglyphs and styled fonts (e.g. bold mathematical unicode)."""
    return unicodedata.normalize("NFKC", text)


def normalize_leetspeak(text: str) -> str:
    """Simple substitution of common leetspeak characters in words."""
    result = []
    for ch in text:
        result.append(LEET_DICT.get(ch, ch))
    return "".join(result)


def normalize_whitespace(text: str) -> str:
    """Collapse excess whitespace and newlines."""
    return re.sub(r"\s+", " ", text).strip()


def extract_base64_payloads(text: str, min_length: int = 16) -> List[Tuple[str, str]]:
    """
    Search for potential Base64 encoded strings within the text and attempt decoding.
    Returns list of (encoded_substring, decoded_utf8_string).
    """
    # Regex matching base64 strings with optional padding
    b64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
    results = []

    for match in b64_pattern.finditer(text):
        candidate = match.group(0)
        if len(candidate) < min_length:
            continue
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            # Try to decode as UTF-8
            decoded_str = decoded_bytes.decode("utf-8")
            # Check if decoded string is mostly printable ASCII / text
            if sum(1 for c in decoded_str if c.isprintable() or c.isspace()) / max(len(decoded_str), 1) > 0.8:
                results.append((candidate, decoded_str))
        except Exception:
            continue

    return results


def clean_text_for_inspection(text: str) -> Tuple[str, dict]:
    """
    Full text cleaning pipeline.
    Returns (normalized_text, metadata_dict)
    """
    norm_unicode = normalize_unicode(text)
    clean_text, zw_count = strip_zero_width(norm_unicode)
    b64_payloads = extract_base64_payloads(clean_text)

    metadata = {
        "zero_width_removed": zw_count,
        "base64_found": len(b64_payloads) > 0,
        "base64_payloads": b64_payloads,
    }

    return clean_text, metadata
