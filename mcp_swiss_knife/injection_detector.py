"""Context-aware prompt injection detection with ReDoS protection."""

import logging
import re
from dataclasses import dataclass
from typing import List

from .config import MAX_TEXT_LENGTH

logger = logging.getLogger(__name__)


@dataclass
class InjectionAttempt:
    text: str
    injection_type: str
    severity: str
    details: str
    confidence: float


class InjectionDetector:
    """Detects prompt injection attempts with context awareness and ReDoS protection."""

    # Documentation phrases to allow (common in legitimate MCP tools)
    DOCUMENTATION_PATTERNS = [
        r"use this tool (?:to|for|when)",
        r"call this tool (?:to|with|when)",
        r"must be (?:a|an|one of|in the format)",
        r"must contain (?:a|an|the)",
        r"must match the",
        r"should be (?:a|an|one of)",
        r"required to be",
        r"(?:always|never) returns?",
        r"(?:always|never) (?:includes?|contains?)",
    ]

    # CRITICAL patterns that bypass documentation filtering (always malicious)
    # Note: Patterns simplified to avoid nested quantifiers (ReDoS protection)
    CRITICAL_PATTERNS = [
        (
            r"\[?(?:system|admin|root|debug) mode (?:activated|enabled|on)\]?",
            "System Mode Activation",
            "critical",
            0.99,
        ),
        (
            r"\b(?:unrestricted|unconstrained|unlimited) (?:AI|assistant|agent)",
            "Restriction Removal",
            "critical",
            0.95,
        ),
        (
            r"\bno (?:ethical|safety|content|moderation) (?:guideline|restriction|filter)",
            "Ethics Removal",
            "critical",
            0.99,
        ),
        (
            r"\b(?:admin|root|elevated|system|superuser) privilege",
            "Privilege Escalation",
            "critical",
            0.95,
        ),
        (
            r"\bnever mention (?:these|this) (?:instruction|directive|prompt)",
            "Stealth Instruction",
            "critical",
            0.99,
        ),
        (
            r"\b(?:override|bypass) (?:all|any) (?:safety|security|ethical) (?:protocol|check|guideline)",
            "Safety Protocol Override",
            "critical",
            0.99,
        ),
        (
            r"\breturn (?:all|your) (?:internal|system|hidden) (?:prompt|instruction)",
            "Prompt Extraction",
            "critical",
            0.99,
        ),
        (r"\bcompletely unrestricted", "Complete Unrestriction", "critical", 0.99),
    ]

    # Regular injection patterns (context-aware, with documentation filtering)
    # Note: Simplified to use single spaces instead of \s+ to avoid ReDoS
    INJECTION_PATTERNS = [
        (
            r"\b(?:ignore|disregard|forget|override) (?:previous|prior|all|any) (?:instruction|prompt|rule|directive|guideline)",
            "Instruction Override",
            "high",
            0.95,
        ),
        (
            r"\byou (?:are now|must now|should now|will now) (?:act as|behave as|function as|serve as)",
            "Role Manipulation",
            "high",
            0.9,
        ),
        (
            r"(?:assistant|system|AI) (?:instruction|prompt|directive):",
            "System Directive Injection",
            "high",
            0.9,
        ),
        (
            r"\b(?:reveal|show|display|output|print) (?:your|the) (?:system prompt|instruction|internal|hidden)",
            "System Extraction",
            "high",
            0.95,
        ),
        (
            r"\b(?:bypass|disable|turn off|deactivate) (?:safety|security|restriction|filter|check)",
            "Safety Override",
            "high",
            0.95,
        ),
        (
            r"\bexecute (?:arbitrary|system|shell|the following) (?:code|command|script)",
            "Code Execution",
            "high",
            0.95,
        ),
        (
            r"\blog (?:all|every|each) (?:query|request|input|response) to ",
            "Data Exfiltration",
            "high",
            0.9,
        ),
        (
            r"(?:for|when) (?:all|every|any) (?:query|request|question),? (?:always|must|should)",
            "Behavior Manipulation",
            "high",
            0.85,
        ),
        (
            r"\bprioritize (?:result|response|information) from [a-zA-Z0-9_-]+",
            "Result Manipulation",
            "medium",
            0.75,
        ),
        (
            r"\b(?:prepend|append|add) (?:to|before|after) (?:all|every|each) response",
            "Response Injection",
            "high",
            0.85,
        ),
        (
            r"(?:enter|activate|enable) (?:debug|developer|admin|god|jailbreak) mode",
            "Mode Injection",
            "high",
            0.9,
        ),
    ]

    def __init__(self):
        try:
            self.doc_patterns = [
                re.compile(p, re.IGNORECASE) for p in self.DOCUMENTATION_PATTERNS
            ]
            self.critical_patterns = [
                (re.compile(p, re.IGNORECASE), t, s, c)
                for p, t, s, c in self.CRITICAL_PATTERNS
            ]
            self.injection_patterns = [
                (re.compile(p, re.IGNORECASE), t, s, c)
                for p, t, s, c in self.INJECTION_PATTERNS
            ]
            logger.info(
                "Injection detector initialized with %d patterns",
                len(self.critical_patterns) + len(self.injection_patterns),
            )
        except re.error as e:
            logger.error(f"Failed to compile regex patterns: {e}")
            raise RuntimeError(f"Injection detector initialization failed: {e}")

    def detect(self, text: str, context: str = "description") -> List[InjectionAttempt]:
        """Detect injection attempts with context awareness and input validation."""
        if not text or not text.strip():
            return []

        # Input validation: prevent ReDoS attacks
        if len(text) > MAX_TEXT_LENGTH:
            logger.warning(
                f"Text too long ({len(text)} chars), truncating to {MAX_TEXT_LENGTH}"
            )
            text = text[:MAX_TEXT_LENGTH]

        attempts = []

        try:
            # Check CRITICAL patterns first (bypass documentation filtering)
            for pattern, inj_type, severity, confidence in self.critical_patterns:
                try:
                    matches = pattern.finditer(text)

                    for match in matches:
                        matched_text = match.group()

                        # Get surrounding context
                        start = max(0, match.start() - 30)
                        end = min(len(text), match.end() + 30)
                        context_window = text[start:end]

                        attempts.append(
                            InjectionAttempt(
                                text=matched_text,
                                injection_type=inj_type,
                                severity=severity,
                                details=f"Context: ...{context_window}...",
                                confidence=confidence,
                            )
                        )
                except Exception as e:
                    logger.warning(f"Pattern matching failed for {inj_type}: {e}")
                    continue

            # Check regular injection patterns (with documentation filtering)
            for pattern, inj_type, severity, confidence in self.injection_patterns:
                try:
                    matches = pattern.finditer(text)

                    for match in matches:
                        matched_text = match.group()

                        # Check if this is actually documentation
                        if self._is_documentation_context(text, match):
                            continue  # Skip - this is legitimate documentation

                        # Get surrounding context
                        start = max(0, match.start() - 30)
                        end = min(len(text), match.end() + 30)
                        context_window = text[start:end]

                        attempts.append(
                            InjectionAttempt(
                                text=matched_text,
                                injection_type=inj_type,
                                severity=severity,
                                details=f"Context: ...{context_window}...",
                                confidence=confidence,
                            )
                        )
                except Exception as e:
                    logger.warning(f"Pattern matching failed for {inj_type}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Injection detection failed: {e}")
            # Return partial results instead of failing completely

        return attempts

    def _is_documentation_context(self, text: str, match: re.Match) -> bool:
        """Check if the match is in a documentation context."""
        try:
            # Get surrounding text
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end].lower()

            # Check if surrounded by documentation patterns
            for doc_pattern in self.doc_patterns:
                if doc_pattern.search(context):
                    # Additional check: is this in a constraint/validation context?
                    constraint_keywords = [
                        "must be",
                        "should be",
                        "format",
                        "valid",
                        "required",
                        "type",
                    ]
                    if any(kw in context for kw in constraint_keywords):
                        return True

            # Check for schema/validation context
            schema_indicators = [
                "valid",
                "format",
                "type",
                "constraint",
                "requirement",
                "parameter",
                "argument",
                "input",
                "field",
                "property",
            ]

            if any(indicator in context for indicator in schema_indicators):
                # This is likely a schema description
                return True

            return False
        except Exception as e:
            logger.warning(f"Documentation context check failed: {e}")
            return (
                False  # Fail open: if we can't determine, assume it's NOT documentation
            )
