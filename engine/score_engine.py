"""
ScoreEngine — Computes deterministic 0-100 security score based on active findings.
Base 100 minus weighted penalties per severity.
"""
from typing import List
from engine.models import Finding


class ScoreEngine:
    BASE_SCORE = 100

    DEDUCTIONS = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 5,
        "LOW": 1,
    }

    @classmethod
    def compute_score(cls, findings: List[Finding]) -> int:
        """
        Calculates deterministic security score bounded between 0 and 100.
        Only 'OPEN' or 'REOPENED' findings incur penalties; 'RESOLVED' do not.
        """
        active_findings = [f for f in findings if f.status in ("OPEN", "REOPENED")]
        if not active_findings:
            return cls.BASE_SCORE

        total_deductions = 0
        for f in active_findings:
            deduction = cls.DEDUCTIONS.get(f.severity, 5)
            total_deductions += deduction

        score = cls.BASE_SCORE - total_deductions
        return max(0, min(cls.BASE_SCORE, score))
