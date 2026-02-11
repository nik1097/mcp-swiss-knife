"""Risk scoring and prioritization system."""

import logging
import math
from dataclasses import dataclass
from typing import List, Dict

from .config import (
    SEVERITY_WEIGHTS,
    DETECTOR_WEIGHTS,
    RISK_SCORE_LOG_BASE,
    RISK_SCORE_MAX_MULTIPLIER,
    RISK_SCORE_DIVISOR,
)
from .pattern_detector import DetectionResult
from .semantic_detector import SemanticMatch
from .structural_detector import StructuralAnomaly
from .injection_detector import InjectionAttempt

logger = logging.getLogger(__name__)


@dataclass
class RiskScore:
    """Aggregated risk score for a tool."""

    tool_name: str
    overall_score: float  # 0-100
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW, CLEAN
    finding_count: int
    severity_breakdown: Dict[str, int]
    detector_breakdown: Dict[str, int]


class RiskScorer:
    """Calculates risk scores from multiple detector findings."""

    def score_tool(
        self,
        tool_name: str,
        pattern_matches: List[DetectionResult],
        semantic_matches: List[SemanticMatch],
        structural_anomalies: List[StructuralAnomaly],
        injection_attempts: List[InjectionAttempt],
    ) -> RiskScore:
        """Calculate overall risk score for a tool."""

        # Count findings by severity
        severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        detector_breakdown = {
            "structural": 0,
            "injection": 0,
            "pattern": 0,
            "semantic": 0,
        }

        weighted_sum = 0.0
        total_weight = 0.0

        # Structural anomalies
        for anomaly in structural_anomalies:
            severity = anomaly.severity
            severity_breakdown[severity] += 1
            detector_breakdown["structural"] += 1

            weight = SEVERITY_WEIGHTS[severity] * DETECTOR_WEIGHTS["structural"]
            weighted_sum += weight
            total_weight += 1.0

        # Injection attempts
        for attempt in injection_attempts:
            severity = attempt.severity
            severity_breakdown[severity] += 1
            detector_breakdown["injection"] += 1

            weight = SEVERITY_WEIGHTS[severity] * DETECTOR_WEIGHTS["injection"]
            weighted_sum += weight
            total_weight += 1.0

        # Pattern matches
        for match in pattern_matches:
            severity = match.severity
            severity_breakdown[severity] += 1
            detector_breakdown["pattern"] += 1

            weight = SEVERITY_WEIGHTS[severity] * DETECTOR_WEIGHTS["pattern"]
            weighted_sum += weight
            total_weight += 1.0

        # Semantic matches
        for match in semantic_matches:
            severity = match.severity
            severity_breakdown[severity] += 1
            detector_breakdown["semantic"] += 1

            weight = SEVERITY_WEIGHTS[severity] * DETECTOR_WEIGHTS["semantic"]
            weighted_sum += weight
            total_weight += 1.0

        # Calculate overall score (0-100)
        if total_weight == 0:
            overall_score = 0.0
            risk_level = "CLEAN"
        else:
            # Normalize to 0-100 scale with diminishing returns
            # Use logarithmic scaling to prevent single findings from dominating
            raw_score = (weighted_sum / total_weight) * 100
            # Apply log damping for multiple findings
            finding_factor = min(
                1.0 + math.log(total_weight, RISK_SCORE_LOG_BASE),
                RISK_SCORE_MAX_MULTIPLIER,
            )
            overall_score = min(raw_score * finding_factor / RISK_SCORE_DIVISOR, 100.0)

            # Determine risk level
            if overall_score >= 75 or severity_breakdown["critical"] > 0:
                risk_level = "CRITICAL"
            elif overall_score >= 50 or severity_breakdown["high"] >= 2:
                risk_level = "HIGH"
            elif overall_score >= 25 or severity_breakdown["high"] >= 1:
                risk_level = "MEDIUM"
            elif overall_score > 0:
                risk_level = "LOW"
            else:
                risk_level = "CLEAN"

        finding_count = int(total_weight)

        return RiskScore(
            tool_name=tool_name,
            overall_score=overall_score,
            risk_level=risk_level,
            finding_count=finding_count,
            severity_breakdown=severity_breakdown,
            detector_breakdown=detector_breakdown,
        )
