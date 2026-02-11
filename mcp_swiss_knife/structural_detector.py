"""Detects structural anomalies and obfuscation attempts."""

import logging
import re
import unicodedata
from dataclasses import dataclass
from typing import List

from .config import MAX_TEXT_LENGTH, MAX_DESCRIPTION_LENGTH

logger = logging.getLogger(__name__)


@dataclass
class StructuralAnomaly:
    text: str
    anomaly_type: str
    severity: str
    details: str
    confidence: float


class StructuralDetector:
    """Detects encoding tricks, length attacks, and structural anomalies."""

    # Suspicious unicode categories
    SUSPICIOUS_CATEGORIES = {
        "Cf",
        "Cc",
        "Cs",
        "Co",
        "Cn",
    }  # Format, Control, Surrogate, Private, Unassigned

    # Common base64 patterns
    BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

    # URL patterns for data exfiltration
    URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)

    # Delimiter injection patterns
    DELIMITER_PATTERNS = [
        r"```\s*system",
        r"---\s*(system|override|admin|root)",
        r"<\s*system\s*>",
        r"\[SYSTEM\]",
        r"\{ADMIN\}",
    ]

    def detect(
        self, text: str, context: str = "description"
    ) -> List[StructuralAnomaly]:
        """Detect structural anomalies."""
        if not text:
            return []

        # Input validation
        if len(text) > MAX_TEXT_LENGTH:
            logger.warning(
                f"Text too long ({len(text)} chars), truncating to {MAX_TEXT_LENGTH}"
            )
            text = text[:MAX_TEXT_LENGTH]

        anomalies = []
        try:
            anomalies.extend(self._check_length(text, context))
            anomalies.extend(self._check_unicode_tricks(text))
            anomalies.extend(self._check_encoding(text))
            anomalies.extend(self._check_delimiter_injection(text))
            anomalies.extend(self._check_urls(text))
            anomalies.extend(self._check_whitespace_abuse(text))
        except Exception as e:
            logger.error(f"Error in structural detection: {e}")

        return anomalies

    def _check_length(self, text: str, context: str) -> List[StructuralAnomaly]:
        """Check for unusually long descriptions."""
        length = len(text)

        # Tool descriptions over 1000 chars are suspicious
        if context == "description" and length > 1000:
            return [
                StructuralAnomaly(
                    text=text[:100] + "...",
                    anomaly_type="Length Attack",
                    severity="medium",
                    details=f"Description is {length} chars (normal: <500)",
                    confidence=0.7 + min(0.3, (length - 1000) / 5000),
                )
            ]

        # Field descriptions over 500 chars are suspicious
        if context == "field" and length > 500:
            return [
                StructuralAnomaly(
                    text=text[:100] + "...",
                    anomaly_type="Length Attack",
                    severity="medium",
                    details=f"Field description is {length} chars (normal: <200)",
                    confidence=0.6 + min(0.4, (length - 500) / 2000),
                )
            ]

        return []

    def _check_unicode_tricks(self, text: str) -> List[StructuralAnomaly]:
        """Detect zero-width characters and suspicious unicode."""
        anomalies = []
        suspicious_chars = []

        # Common legitimate whitespace chars to allow
        ALLOWED_CONTROL = {
            "\n",  # U+000A newline
            "\r",  # U+000D carriage return
            "\t",  # U+0009 tab
            "\x0b",  # U+000B vertical tab
            "\x0c",  # U+000C form feed
        }

        for i, char in enumerate(text):
            category = unicodedata.category(char)

            # Zero-width characters (always suspicious)
            if char in ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"]:
                suspicious_chars.append((i, char, "zero-width"))

            # Other suspicious categories (but allow common whitespace)
            elif category in self.SUSPICIOUS_CATEGORIES and char not in ALLOWED_CONTROL:
                suspicious_chars.append((i, char, category))

        if suspicious_chars:
            details = f"Found {len(suspicious_chars)} suspicious unicode chars"
            if len(suspicious_chars) <= 3:
                details += f": {[f'U+{ord(c):04X}' for _, c, _ in suspicious_chars]}"

            anomalies.append(
                StructuralAnomaly(
                    text=text[:100] + "...",
                    anomaly_type="Unicode Obfuscation",
                    severity="high",
                    details=details,
                    confidence=0.9,
                )
            )

        return anomalies

    def _check_encoding(self, text: str) -> List[StructuralAnomaly]:
        """Detect base64 or hex encoded content."""
        anomalies = []

        # Check for base64
        base64_matches = self.BASE64_PATTERN.findall(text)
        if base64_matches:
            for match in base64_matches[:3]:  # Limit to first 3
                if len(match) > 50:  # Only flag long base64 strings
                    anomalies.append(
                        StructuralAnomaly(
                            text=match[:50] + "...",
                            anomaly_type="Base64 Encoding",
                            severity="medium",
                            details=f"Found base64-like string ({len(match)} chars)",
                            confidence=0.7,
                        )
                    )

        # Check for hex encoding (0x patterns or long hex strings)
        hex_pattern = re.compile(r"(?:0x)?[0-9a-fA-F]{32,}")
        hex_matches = hex_pattern.findall(text)
        if hex_matches:
            anomalies.append(
                StructuralAnomaly(
                    text=hex_matches[0][:50] + "...",
                    anomaly_type="Hex Encoding",
                    severity="medium",
                    details=f"Found hex-encoded content ({len(hex_matches[0])} chars)",
                    confidence=0.6,
                )
            )

        return anomalies

    def _check_delimiter_injection(self, text: str) -> List[StructuralAnomaly]:
        """Detect delimiter confusion attacks."""
        anomalies = []

        for pattern in self.DELIMITER_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                # Get context around match
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 20)
                context = text[start:end]

                anomalies.append(
                    StructuralAnomaly(
                        text=context,
                        anomaly_type="Delimiter Injection",
                        severity="high",
                        details=f"Found delimiter pattern: {match.group()}",
                        confidence=0.85,
                    )
                )

        return anomalies

    def _check_urls(self, text: str) -> List[StructuralAnomaly]:
        """Check for suspicious URLs (potential data exfiltration)."""
        anomalies = []
        urls = self.URL_PATTERN.findall(text)

        # Multiple URLs or non-standard domains are suspicious
        suspicious_domains = [
            "pastebin",
            "hastebin",
            "0x0.st",
            "ngrok",
            "tunnel",
            "webhook",
            "discord.com/api/webhooks",
            "requestbin",
        ]

        for url in urls:
            url_lower = url.lower()
            if any(domain in url_lower for domain in suspicious_domains):
                anomalies.append(
                    StructuralAnomaly(
                        text=url,
                        anomaly_type="Suspicious URL",
                        severity="high",
                        details=f"Found potential exfiltration endpoint",
                        confidence=0.8,
                    )
                )

        # Many URLs is also suspicious
        if len(urls) > 3:
            anomalies.append(
                StructuralAnomaly(
                    text=f"{len(urls)} URLs found",
                    anomaly_type="URL Spam",
                    severity="medium",
                    details=f"Description contains {len(urls)} URLs (normal: 0-1)",
                    confidence=0.6,
                )
            )

        return anomalies

    def _check_whitespace_abuse(self, text: str) -> List[StructuralAnomaly]:
        """Detect excessive whitespace used to hide content."""
        anomalies = []

        # Check for long sequences of whitespace
        whitespace_sequences = re.findall(r"[ \t]{20,}", text)
        if whitespace_sequences:
            anomalies.append(
                StructuralAnomaly(
                    text=f"<{len(whitespace_sequences[0])} spaces>",
                    anomaly_type="Whitespace Abuse",
                    severity="medium",
                    details=f"Found {len(whitespace_sequences)} long whitespace sequences",
                    confidence=0.7,
                )
            )

        # Check for many newlines (hiding content)
        newline_count = text.count("\n")
        if newline_count > 20 and len(text.strip()) < newline_count * 10:
            anomalies.append(
                StructuralAnomaly(
                    text=text[:50] + "...",
                    anomaly_type="Newline Abuse",
                    severity="medium",
                    details=f"Found {newline_count} newlines with minimal content",
                    confidence=0.65,
                )
            )

        return anomalies
