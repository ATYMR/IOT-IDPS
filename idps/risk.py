"""Risk scoring: map a finding to a 0-100 score and a severity band.

The numbers below are engineering choices, not empirically fitted values.
They are kept in one table so they are easy to review and tune.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .findings import Category, Finding


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Base risk for deterministic rule findings. ML findings derive their base
# from the detector confidence instead.
RULE_BASE_RISK: dict[Category, int] = {
    Category.MALFORMED: 30,
    Category.UNKNOWN_DEVICE: 40,
    Category.DEVICE_OFFLINE: 40,
    Category.COMMAND_REJECTIONS: 45,
    Category.TELEMETRY_AUTH_FAILURE: 60,
    Category.REPLAY: 65,
    Category.DEVICE_REBOOT: 10,
}
# Scales finding.confidence (0..1) into extra risk for rule findings.
RULE_CONFIDENCE_WEIGHT = 30
# Added when the device has been flagged repeatedly in its recent windows.
PERSISTENCE_BONUS = 15


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: Severity


def severity_for(score: int) -> Severity:
    if score <= 30:
        return Severity.LOW
    if score <= 60:
        return Severity.MEDIUM
    if score <= 80:
        return Severity.HIGH
    return Severity.CRITICAL


def assess(finding: Finding, persistent: bool = False) -> RiskAssessment:
    confidence = min(max(float(finding.confidence), 0.0), 1.0)
    if finding.category is Category.ML_ANOMALY:
        score = 100 * confidence
    else:
        score = RULE_BASE_RISK[finding.category] + RULE_CONFIDENCE_WEIGHT * confidence
    if persistent:
        score += PERSISTENCE_BONUS
    score_int = int(round(min(max(score, 0.0), 100.0)))
    return RiskAssessment(score=score_int, severity=severity_for(score_int))
