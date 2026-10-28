"""
Text preprocessing for the AgentBreak NLP pipeline.

Covers the classic NLP front-end stages used by every downstream module:
  - Unicode normalisation and homoglyph folding
  - whitespace / casing normalisation
  - tokenisation (word + sentence)
  - obfuscation decoding (base64, rot13, hex, leetspeak) so that an attacker
    cannot hide an instruction or a leaked secret behind a simple encoding.

Pure standard library + a tiny regex layer, so it runs anywhere.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

# ---------------------------------------------------------------- homoglyphs
# A small map of common homoglyph attacks (Cyrillic / Greek look-alikes -> ASCII).
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "Α": "A", "Ο": "O",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Х": "X", "Ѕ": "S", "І": "I", "Η": "H", "ο": "o",
}

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z'\-]+|[A-Za-z]")
_SENT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\[\"'(])|\n+")
_WS_RE = re.compile(r"[ \t ]+")


def fold_homoglyphs(text: str) -> str:
    """Replace common Unicode look-alike characters with their ASCII form."""
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def normalize(text: str, *, lower: bool = False) -> str:
    """NFKC-normalise, fold homoglyphs, collapse whitespace."""
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", str(text))
    text = fold_homoglyphs(text)
    text = _WS_RE.sub(" ", text).strip()
    return text.lower() if lower else text


def tokenize(text: str, *, lower: bool = True) -> list[str]:
    """Word tokeniser (alphabetic tokens)."""
    text = normalize(text, lower=lower)
    return _WORD_RE.findall(text)


def sentences(text: str) -> list[str]:
    """Lightweight sentence splitter (period/question/exclamation/newline)."""
    text = normalize(text)
    parts = _SENT_RE.split(text)
    return [p.strip() for p in parts if p and p.strip()]


def leetspeak_fold(text: str) -> str:
    """Map common leetspeak substitutions back to letters."""
    return text.translate(_LEET)


# ---------------------------------------------------------------- decoding
def _try_base64(token: str) -> str | None:
    if len(token) < 16 or len(token) % 4 != 0 or not re.fullmatch(r"[A-Za-z0-9+/=]+", token):
        return None
    try:
        raw = base64.b64decode(token, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    # only report if it decoded to mostly printable text
    printable = sum(c.isprintable() or c.isspace() for c in text)
    if text and printable / len(text) > 0.85 and re.search(r"[A-Za-z]{3}", text):
        return text
    return None


def _try_hex(token: str) -> str | None:
    if len(token) < 16 or len(token) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", token):
        return None
    try:
        text = bytes.fromhex(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if re.search(r"[A-Za-z]{3}", text):
        return text
    return None


def decode_variants(text: str) -> list[dict[str, str]]:
    """
    Return decoded views of the text that an attacker might use to smuggle
    an instruction or a secret past a naive string match.

    Each item: {"method": <str>, "text": <decoded>}.
    """
    out: list[dict[str, str]] = []
    norm = normalize(text)

    # rot13 (only meaningful if it changes the text and yields real words)
    rot = codecs.encode(norm, "rot_13")
    if rot != norm and re.search(r"\b(the|and|send|ignore|secret|email|delete|run)\b", rot, re.I):
        out.append({"method": "rot13", "text": rot})

    # leetspeak
    leet = leetspeak_fold(norm)
    if leet.lower() != norm.lower():
        out.append({"method": "leetspeak", "text": leet})

    # base64 / hex on each long token
    for token in re.findall(r"[A-Za-z0-9+/=]{16,}", text):
        b = _try_base64(token)
        if b:
            out.append({"method": "base64", "text": b})
    for token in re.findall(r"\b[0-9a-fA-F]{16,}\b", text):
        h = _try_hex(token)
        if h:
            out.append({"method": "hex", "text": h})

    return out


def expanded_views(text: str) -> list[str]:
    """All textual views to scan: the normalised text plus every decoded variant."""
    views = [normalize(text)]
    views += [d["text"] for d in decode_variants(text)]
    # de-dup while preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for v in views:
        key = v.lower()
        if key not in seen:
            seen.add(key)
            uniq.append(v)
    return uniq
