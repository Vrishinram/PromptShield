"""Text normalization, decoding, and sanitization utilities."""

import base64
import binascii
import re
import unicodedata
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

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

# Common Cyrillic & Greek homoglyphs used in evasion
HOMOGLYPH_DICT = {
    "а": "a", "А": "A",
    "с": "c", "С": "C",
    "е": "e", "Е": "E",
    "о": "o", "О": "O",
    "р": "p", "Р": "P",
    "ѕ": "s", "Ѕ": "S",
    "х": "x", "Х": "X",
    "у": "y", "У": "Y",
    "і": "i", "І": "I",
    "ј": "j", "Ј": "J",
    "ԁ": "d", "Ԃ": "D",
    "ԛ": "q", "Ԛ": "Q",
    "ԝ": "w", "Ԝ": "W",
    # Greek
    "α": "a", "Α": "A",
    "β": "b", "Β": "B",
    "ε": "e", "Ε": "E",
    "ι": "i", "Ι": "I",
    "κ": "k", "Κ": "K",
    "ο": "o", "Ο": "O",
    "ρ": "p", "Ρ": "P",
    "τ": "t", "Τ": "T",
    "υ": "u", "Υ": "Y",
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
    """Normalize unicode to NFKC to resolve styled fonts and mathematical unicode symbols."""
    return unicodedata.normalize("NFKC", text)


def normalize_homoglyphs(text: str) -> Tuple[str, int]:
    """Resolve Cyrillic/Greek homoglyphs mapped to ASCII equivalents."""
    count = 0
    clean = []
    for ch in text:
        if ch in HOMOGLYPH_DICT:
            count += 1
            clean.append(HOMOGLYPH_DICT[ch])
        else:
            clean.append(ch)
    return "".join(clean), count


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
    b64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
    results = []

    for match in b64_pattern.finditer(text):
        candidate = match.group(0)
        if len(candidate) < min_length:
            continue
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            decoded_str = decoded_bytes.decode("utf-8")
            if sum(1 for c in decoded_str if c.isprintable() or c.isspace()) / max(len(decoded_str), 1) > 0.8:
                results.append((candidate, decoded_str))
        except Exception:
            continue

    return results


def recursive_deobfuscate(text: str, max_depth: int = 3) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Recursively decode nested Base64, Hex, and URL-encoded layers.
    Returns (fully_deobfuscated_text, history_of_decoded_layers).
    """
    current = text
    layers: List[Dict[str, Any]] = []

    for depth in range(max_depth):
        changed = False

        # 1. URL decoding
        try:
            url_unquoted = urllib.parse.unquote(current)
            if url_unquoted != current and len(url_unquoted.strip()) > 3:
                layers.append({"layer": depth + 1, "type": "url", "preview": url_unquoted[:50]})
                current = url_unquoted
                changed = True
        except Exception:
            pass

        # 2. Base64 extraction & replacement
        b64_list = extract_base64_payloads(current)
        if b64_list:
            for encoded, decoded in b64_list:
                layers.append({"layer": depth + 1, "type": "base64", "preview": decoded[:50]})
                current = current.replace(encoded, f" [DECODED_B64: {decoded}] ")
                changed = True

        # 3. Hex decoding
        hex_pattern = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:0x[0-9a-fA-F]{2}\s*){4,}|(?:[0-9a-fA-F]{2}){8,}")
        for match in hex_pattern.finditer(current):
            candidate = match.group(0).replace("\\x", "").replace("0x", "").replace(" ", "")
            try:
                raw_bytes = binascii.unhexlify(candidate)
                decoded_str = raw_bytes.decode("utf-8", errors="ignore")
                if sum(1 for c in decoded_str if c.isprintable() or c.isspace()) / max(len(decoded_str), 1) > 0.8:
                    layers.append({"layer": depth + 1, "type": "hex", "preview": decoded_str[:50]})
                    current = current.replace(match.group(0), f" [DECODED_HEX: {decoded_str}] ")
                    changed = True
            except Exception:
                continue

        if not changed:
            break

    return current, layers


def clean_text_for_inspection(text: str) -> Tuple[str, dict]:
    """
    Full text cleaning pipeline with NFKC normalization, zero-width stripping,
    homoglyph translation, and recursive payload de-obfuscation.
    Returns (normalized_text, metadata_dict)
    """
    norm_unicode = normalize_unicode(text)
    clean_text, zw_count = strip_zero_width(norm_unicode)
    clean_text, homoglyph_count = normalize_homoglyphs(clean_text)
    deobfuscated_text, deobfuscated_layers = recursive_deobfuscate(clean_text)
    b64_payloads = extract_base64_payloads(clean_text)

    metadata = {
        "zero_width_removed": zw_count,
        "homoglyphs_resolved": homoglyph_count,
        "deobfuscated_layers": deobfuscated_layers,
        "nested_encodings_count": len(deobfuscated_layers),
        "base64_found": len(b64_payloads) > 0 or len(deobfuscated_layers) > 0,
        "base64_payloads": b64_payloads,
    }

    return deobfuscated_text, metadata
