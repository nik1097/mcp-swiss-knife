"""Singleton cache for detector instances to avoid reloading models."""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Global detector cache
_detector_cache = {
    "pattern": None,
    "semantic": None,
    "structural": None,
    "injection": None,
}


def get_pattern_detector():
    """Get or create pattern detector (singleton)."""
    if _detector_cache["pattern"] is None:
        logger.info("Loading pattern detector...")
        from .pattern_detector import PatternDetector

        _detector_cache["pattern"] = PatternDetector()
    return _detector_cache["pattern"]


def get_semantic_detector():
    """Get or create semantic detector (singleton)."""
    if _detector_cache["semantic"] is None:
        logger.info("Loading semantic detector (this may take a while)...")
        from .semantic_detector import SemanticDetector

        _detector_cache["semantic"] = SemanticDetector()
    return _detector_cache["semantic"]


def get_structural_detector():
    """Get or create structural detector (singleton)."""
    if _detector_cache["structural"] is None:
        logger.info("Loading structural detector...")
        from .structural_detector import StructuralDetector

        _detector_cache["structural"] = StructuralDetector()
    return _detector_cache["structural"]


def get_injection_detector():
    """Get or create injection detector (singleton)."""
    if _detector_cache["injection"] is None:
        logger.info("Loading injection detector...")
        from .injection_detector import InjectionDetector

        _detector_cache["injection"] = InjectionDetector()
    return _detector_cache["injection"]


def clear_cache():
    """Clear all cached detectors (useful for testing)."""
    logger.info("Clearing detector cache...")
    for key in _detector_cache:
        _detector_cache[key] = None
