"""Text normalization for preprocessing."""

import re
import unicodedata


def normalize_text(text: str) -> str:
    """Normalize text (lowercase, unicode, whitespace)."""
    if not text:
        return ""

    text = text.lower()
    text = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    text = re.sub(r"\s+", " ", text)

    return text.strip()
