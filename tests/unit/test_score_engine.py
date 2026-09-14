"""
Unit tests for ScoreEngine.
"""
from engine.score_engine import ScoreEngine
from engine.models import Finding


def make_test_finding(severity: str, status: str = "OPEN") -> Finding:
    return Finding(
        rule_id="TEST_RULE",
        scanner="custom",
        title="Test Finding",
        category="Testing",
        severity=severity,
        confidence="HIGH",
        status=status,
        fingerprint=f"fp_{severity}_{status}",
    )


def test_clean_scan_gives_score_100():
    score = ScoreEngine.compute_score([])
    assert score == 100


def test_critical_deducts_25_points():
    f = make_test_finding("CRITICAL")
    score = ScoreEngine.compute_score([f])
    assert score == 75


def test_resolved_findings_do_not_deduct_points():
    f1 = make_test_finding("CRITICAL", status="RESOLVED")
    f2 = make_test_finding("HIGH", status="RESOLVED")
    score = ScoreEngine.compute_score([f1, f2])
    assert score == 100


def test_multiple_findings_compound_and_floor_at_zero():
    findings = [make_test_finding("CRITICAL") for _ in range(5)]  # 5 * 25 = 125
    score = ScoreEngine.compute_score(findings)
    assert score == 0
