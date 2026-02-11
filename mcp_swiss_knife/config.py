"""Configuration constants and limits."""

# Input validation limits
MAX_TEXT_LENGTH = 50_000  # 50KB max per text field
MAX_DESCRIPTION_LENGTH = 10_000  # 10KB for descriptions
MAX_TOOLS_PER_SERVER = 1000  # Reasonable limit
MAX_FIELDS_PER_TOOL = 100  # Prevent schema explosion

# Detection thresholds (tuned for balance between precision and recall)
SEMANTIC_SIMILARITY_THRESHOLD = 0.70  # Higher = fewer false positives
PATTERN_CONFIDENCE_THRESHOLD = 0.60  # Minimum confidence to report

# Severity weights (for risk scoring - validated against test data)
SEVERITY_WEIGHTS = {
    "critical": 1.0,  # Immediate threat
    "high": 0.75,  # Serious concern
    "medium": 0.5,  # Investigate
    "low": 0.25,  # Informational
}

# Detector confidence weights (based on false positive rates in testing)
DETECTOR_WEIGHTS = {
    "structural": 0.9,  # Objective indicators (encoding, unicode, URLs)
    "injection": 0.85,  # Context-aware with allow-list
    "pattern": 0.6,  # Simple regex matching
    "semantic": 0.7,  # Embedding-based similarity
}

# Risk scoring parameters
# These control the logarithmic damping to prevent single findings from dominating
RISK_SCORE_LOG_BASE = 10  # Base for logarithmic scaling
RISK_SCORE_MAX_MULTIPLIER = 2.0  # Cap on finding count multiplier
RISK_SCORE_DIVISOR = 2.0  # Normalizes weighted scores to 0-100 range

# Timeout settings
HTTP_TIMEOUT = 30.0  # seconds
MODEL_INFERENCE_TIMEOUT = 10.0  # seconds per text (not yet implemented)

# Logging
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Secret patterns to redact from output
SECRET_PATTERNS = [
    r"sk-[a-zA-Z0-9]{32,}",  # OpenAI API keys
    r"Bearer [a-zA-Z0-9._-]{20,}",  # Bearer tokens
    r"ghp_[a-zA-Z0-9]{36,}",  # GitHub tokens
    r"[a-zA-Z0-9]{32,64}",  # Generic API keys (high entropy)
]
