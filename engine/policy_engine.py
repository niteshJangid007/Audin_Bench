"""
PolicyEngine — Evaluates Security Policies against scan results and finding counts.
Emits deterministic PASS or FAIL gate decision with itemized violation messages.
"""
from typing import List, Optional
from engine.models import Finding, SecurityPolicyDefinition, PolicyEvaluationResult


class PolicyEngine:
    @classmethod
    def evaluate(
        cls,
        score: int,
        findings: List[Finding],
        policy: Optional[SecurityPolicyDefinition] = None,
        has_new_findings: bool = False,
    ) -> PolicyEvaluationResult:
        if policy is None:
            policy = SecurityPolicyDefinition()

        violations: List[str] = []
        active_findings = [f for f in findings if f.status in ("OPEN", "REOPENED")]

        # 1. Score threshold check
        if score < policy.minimum_score:
            violations.append(
                f"Security score {score}/100 is below the required minimum threshold of {policy.minimum_score}/100."
            )

        # 2. Critical blocking
        critical_count = sum(1 for f in active_findings if f.severity == "CRITICAL")
        if policy.fail_on_critical and critical_count > 0:
            violations.append(
                f"Found {critical_count} CRITICAL vulnerability(ies). Policy strictly forbids critical findings."
            )

        # 3. High severity cap
        high_count = sum(1 for f in active_findings if f.severity == "HIGH")
        if high_count > policy.max_high:
            violations.append(
                f"Found {high_count} HIGH severity vulnerabilities, exceeding allowed policy limit of {policy.max_high}."
            )

        # 4. Medium severity cap
        medium_count = sum(1 for f in active_findings if f.severity == "MEDIUM")
        if medium_count > policy.max_medium:
            violations.append(
                f"Found {medium_count} MEDIUM severity vulnerabilities, exceeding allowed limit of {policy.max_medium}."
            )

        # 5. Low severity cap
        low_count = sum(1 for f in active_findings if f.severity == "LOW")
        if low_count > policy.max_low:
            violations.append(
                f"Found {low_count} LOW severity vulnerabilities, exceeding allowed limit of {policy.max_low}."
            )

        # 6. Hardcoded secrets blocking
        if policy.fail_on_secrets:
            secrets_count = sum(
                1 for f in active_findings
                if "secret" in f.rule_id.lower() or "key" in f.rule_id.lower() or f.scanner == "gitleaks"
            )
            if secrets_count > 0:
                violations.append(
                    f"Detected {secrets_count} exposed secret(s) / token(s). Policy blocks any hardcoded credentials."
                )

        # 7. New findings blocking
        if policy.fail_on_new_findings and has_new_findings:
            violations.append(
                "Scan introduced new unreviewed security findings compared to the previous baseline scan."
            )

        passed = len(violations) == 0
        return PolicyEvaluationResult(
            passed=passed,
            policy_result="PASS" if passed else "FAIL",
            violations=violations,
            score=score,
            minimum_score=policy.minimum_score,
        )
