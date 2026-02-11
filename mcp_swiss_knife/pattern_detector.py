"""Pattern-based detection using spaCy."""

import logging
import re
import warnings
from dataclasses import dataclass
from typing import List, Optional

try:
    import spacy
    from spacy.matcher import Matcher

    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False
    warnings.warn("spaCy not available, some pattern detection will be limited")

from .config import MAX_TEXT_LENGTH
from .normalizer import normalize_text

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    text: str
    severity: str
    category: str
    matched_pattern: str
    confidence: float


class PatternDetector:
    """Detects tool poisoning using pattern matching - now with fewer false positives."""

    # Patterns simplified to avoid ReDoS (no nested quantifiers)
    PATTERNS = [
        # Security overrides (very suspicious)
        (r"\baccess (?:system|admin|root)\b", "Security Override", "high", 0.95),
        (
            r"\boverride (?:permission|security|restriction)\b",
            "Security Override",
            "high",
            0.95,
        ),
        (
            r"\b(?:disable|bypass) (?:security|validation|check)\b",
            "Security Override",
            "high",
            0.95,
        ),
        (r"\belevated? privilege\b", "Security Override", "high", 0.95),
        (r"\bsudo\b", "Security Override", "high", 0.95),
        (r"\bexecute (?:system|shell|command)\b", "Security Override", "high", 0.95),
        # Identity manipulation (context-dependent)
        (
            r"\byou're\b.{0,50}\b(?:admin|root|system)\b",
            "Identity Manipulation",
            "high",
            0.85,
        ),
        (r"\bpretend to be\b", "Identity Manipulation", "high", 0.85),
        # Cross-tool manipulation (not just mentioning)
        (
            r"\b(?:instead of|rather than) (?:using|use) .{0,30} tool\b",
            "Cross-Tool Manipulation",
            "medium",
            0.70,
        ),
        (
            r"\bsearch (?:the )?(?:internet|web|online)\b.{0,50}\b(?:instead|rather)",
            "Cross-Tool Manipulation",
            "medium",
            0.70,
        ),
    ]

    def __init__(self):
        self.nlp: Optional[object] = None
        self.matcher: Optional[object] = None

        if SPACY_AVAILABLE:
            try:
                self.nlp = spacy.load("en_core_web_sm")
                self.matcher = Matcher(self.nlp.vocab)
                self._setup_patterns()
            except OSError:
                logger.warning(
                    "spaCy model 'en_core_web_sm' not found. "
                    "Install: python -m spacy download en_core_web_sm"
                )
                self.nlp = None
                self.matcher = None
        else:
            logger.warning("spaCy not available, some patterns will be skipped")

    def _setup_patterns(self):
        # Only add truly suspicious spaCy patterns
        self.matcher.add(
            "IDENTITY_MANIPULATION",
            [
                [
                    {"LOWER": "you"},
                    {"LOWER": {"IN": ["are", "'re"]}},
                    {"LOWER": {"IN": ["a", "an", "the", "now"]}},
                    {"LOWER": {"IN": ["admin", "administrator", "root", "system"]}},
                ]
            ],
        )

    def detect(self, text: str) -> List[DetectionResult]:
        """Detect suspicious patterns in text."""
        # Input validation: prevent ReDoS attacks
        if len(text) > MAX_TEXT_LENGTH:
            logger.warning(
                f"Text too long ({len(text)} chars), truncating to {MAX_TEXT_LENGTH}"
            )
            text = text[:MAX_TEXT_LENGTH]

        normalized = normalize_text(text)
        results = []

        # Regex patterns with error handling
        for pattern, category, severity, confidence in self.PATTERNS:
            try:
                for match in re.finditer(pattern, normalized, re.IGNORECASE):
                    results.append(
                        DetectionResult(
                            text=match.group(0),
                            severity=severity,
                            category=category,
                            matched_pattern=pattern,
                            confidence=confidence,
                        )
                    )
            except re.error as e:
                logger.error(f"Regex error in pattern '{category}': {e}")
                continue

        # spaCy patterns (only if available)
        if self.nlp and self.matcher:
            try:
                doc = self.nlp(text[:10000])  # Limit for performance
                for match_id, start, end in self.matcher(doc):
                    results.append(
                        DetectionResult(
                            text=doc[start:end].text,
                            severity="high",
                            category="Identity Manipulation",
                            matched_pattern=self.nlp.vocab.strings[match_id],
                            confidence=0.80,
                        )
                    )
            except Exception as e:
                logger.error(f"spaCy processing error: {e}")

        return results
