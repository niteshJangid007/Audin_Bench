"""
Unit tests for VerificationEngine (Re-scan and Finding Lifecycle Transitions).
"""
from engine.verification_engine import VerificationEngine
from engine.models import Finding


def create_finding(fingerprint: str, status: str = "OPEN") -> Finding:
    return Finding(
        rule_id="RULE_SQLI",
        scanner="custom",
        title="SQL Injection",
        category="Injection",
        severity="CRITICAL",
        confidence="HIGH",
        status=status,
        fingerprint=fingerprint,
    )


def test_new_finding_starts_as_open():
    prior = []
    current = [create_finding("fp_sql_1")]
    reconciled, transitions, has_new = VerificationEngine.diff_scans(prior, current)

    assert len(reconciled) == 1
    assert reconciled[0].status == "OPEN"
    assert has_new is True
    assert transitions[0]["to_status"] == "OPEN"


def test_absent_finding_transitions_to_resolved():
    prior = [create_finding("fp_sql_1", status="OPEN")]
    current = []  # vulnerability was fixed!
    reconciled, transitions, has_new = VerificationEngine.diff_scans(prior, current)

    assert len(reconciled) == 1
    assert reconciled[0].status == "RESOLVED"
    assert reconciled[0].resolved_at is not None
    assert has_new is False
    assert any(t["to_status"] == "RESOLVED" for t in transitions)


def test_resolved_finding_reappears_as_reopened():
    prior = [create_finding("fp_sql_1", status="RESOLVED")]
    current = [create_finding("fp_sql_1")]  # reintroduced vulnerability
    reconciled, transitions, has_new = VerificationEngine.diff_scans(prior, current)

    assert len(reconciled) == 1
    assert reconciled[0].status == "REOPENED"
    assert has_new is True
    assert any(t["from_status"] == "RESOLVED" and t["to_status"] == "REOPENED" for t in transitions)
