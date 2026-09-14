"""
RiskEngine — Evaluates risk weight by compounding severity and confidence.
"""
from typing import List
from engine.models import Finding


class RiskEngine:
    SEVERITY_WEIGHTS = {
        "CRITICAL": 10.0,
        "HIGH": 7.0,
        "MEDIUM": 3.0,
        "LOW": 1.0,
    }

    CONFIDENCE_MULTIPLIERS = {
        "HIGH": 1.0,
        "MEDIUM": 0.75,
        "LOW": 0.5,
    }

    @classmethod
    def calculate_finding_risk(cls, finding: Finding) -> float:
        """Calculates risk score (0.5 to 10.0) for an individual finding."""
        base = cls.SEVERITY_WEIGHTS.get(finding.severity, 3.0)
        multiplier = cls.CONFIDENCE_MULTIPLIERS.get(finding.confidence, 1.0)
        return round(base * multiplier, 2)

    @classmethod
    def calculate_aggregate_risk(cls, findings: List[Finding]) -> float:
        """Calculates the total aggregate risk of all active findings."""
        return round(sum(cls.calculate_finding_risk(f) for f in findings if f.status != "RESOLVED"), 2)
