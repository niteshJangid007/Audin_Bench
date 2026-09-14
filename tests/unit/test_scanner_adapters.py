"""
Unit tests for Scanner Adapters.
"""
import os
import tempfile
from scanners.custom_scanner import CustomRuleScanner
from scanners.gitleaks_scanner import GitleaksScanner
from scanners.trivy_scanner import TrivyScanner
from scanners.semgrep_scanner import SemgrepScanner


def test_custom_rule_scanner_finds_vulnerabilities():
    scanner = CustomRuleScanner()
    assert scanner.validate() is True

    # Scan the vulnerable fixture repository
    fixture_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures", "vulnerable_repo")
    res = scanner.scan(fixture_dir)
    assert res.exit_code == 0

    findings = scanner.parse(res.stdout, res.exit_code)
    assert len(findings) > 0
    rule_ids = {f.rule_id for f in findings}
    assert "RULE_A03_SQL_CONCAT" in rule_ids
    assert "RULE_A03_XSS_INNERHTML" in rule_ids
    assert "RULE_A02_WEAK_HASH" in rule_ids
    assert "RULE_A10_UNVALIDATED_FETCH" in rule_ids


def test_gitleaks_scanner_finds_secrets():
    scanner = GitleaksScanner()
    fixture_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures", "vulnerable_repo")
    res = scanner.scan(fixture_dir)
    assert res.exit_code == 0

    findings = scanner.parse(res.stdout, res.exit_code)
    assert any("AWS" in f.rule_id or "KEY" in f.rule_id or "SECRET" in f.rule_id for f in findings)


def test_trivy_scanner_finds_manifest_vulnerabilities():
    scanner = TrivyScanner()
    fixture_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures", "vulnerable_repo")
    res = scanner.scan(fixture_dir)
    assert res.exit_code == 0

    findings = scanner.parse(res.stdout, res.exit_code)
    assert any("TRIVY" in f.rule_id for f in findings)
    assert any("lodash" in f.title.lower() or "axios" in f.title.lower() for f in findings)


def test_semgrep_scanner_fallback_behavior():
    scanner = SemgrepScanner()
    fixture_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures", "vulnerable_repo")
    res = scanner.scan(fixture_dir)
    # Does not raise error and returns valid execution result
    assert res.exit_code == 0 or res.exit_code == 1
