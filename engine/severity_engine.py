"""
SeverityEngine — Normalizes severity ratings across scanners into standard 4 tiers:
CRITICAL, HIGH, MEDIUM, LOW.
"""
from typing import Literal

NormalizedSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class SeverityEngine:
    MAPPINGS = {
        # Common lowercase / uppercase
        "critical": "CRITICAL",
        "crit": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "med": "MEDIUM",
        "low": "LOW",
        "info": "LOW",
        "informational": "LOW",
        "note": "LOW",
        # Semgrep severities
        "error": "HIGH",
        "warning": "MEDIUM",
        # CVSS v3 score bands
        "none": "LOW",
    }

    @classmethod
    def normalize(cls, raw_severity: str) -> NormalizedSeverity:
        if not raw_severity:
            return "MEDIUM"

        cleaned = str(raw_severity).strip().lower()
        return cls.MAPPINGS.get(cleaned, "MEDIUM")

    @classmethod
    def numeric_weight(cls, severity: NormalizedSeverity) -> int:
        """Returns relative deduction / risk weight."""
        weights = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 5,
            "LOW": 1,
        }
        return weights.get(severity, 5)
