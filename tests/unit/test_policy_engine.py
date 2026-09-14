"""
Unit tests for PolicyEngine.
"""
from engine.policy_engine import PolicyEngine
from engine.models import Finding, SecurityPolicyDefinition


def make_finding(severity: str, rule_id: str = "TEST_RULE") -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner="custom",
        title="Test Title",
        category="Injection",
        severity=severity,
        confidence="HIGH",
        status="OPEN",
        fingerprint=f"fp_{rule_id}_{severity}",
    )


def test_passes_when_no_violations():
    policy = SecurityPolicyDefinition(minimum_score=75, fail_on_critical=True)
    res = PolicyEngine.evaluate(score=85, findings=[], policy=policy)
    assert res.passed is True
    assert res.policy_result == "PASS"
    assert len(res.violations) == 0


def test_fails_when_score_below_minimum():
    policy = SecurityPolicyDefinition(minimum_score=80)
    res = PolicyEngine.evaluate(score=70, findings=[], policy=policy)
    assert res.passed is False
    assert res.policy_result == "FAIL"
    assert any("below the required minimum threshold" in v for v in res.violations)


def test_fails_on_critical_finding():
    policy = SecurityPolicyDefinition(fail_on_critical=True)
    crit = make_finding("CRITICAL")
    res = PolicyEngine.evaluate(score=90, findings=[crit], policy=policy)
    assert res.passed is False
    assert any("CRITICAL vulnerability" in v for v in res.violations)


def test_fails_on_hardcoded_secrets():
    policy = SecurityPolicyDefinition(fail_on_secrets=True)
    secret_finding = make_finding("HIGH", rule_id="RULE_A02_HARDCODED_KEY")
    res = PolicyEngine.evaluate(score=85, findings=[secret_finding], policy=policy)
    assert res.passed is False
    assert any("exposed secret" in v for v in res.violations)


def test_fails_on_exceeding_max_high_limit():
    policy = SecurityPolicyDefinition(max_high=1)
    findings = [make_finding("HIGH", f"HIGH_{i}") for i in range(2)]
    res = PolicyEngine.evaluate(score=80, findings=findings, policy=policy)
    assert res.passed is False
    assert any("exceeding allowed policy limit" in v for v in res.violations)
