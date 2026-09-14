"""
Unit tests for FindingNormalizer and deterministic fingerprinting.
"""
from engine.normalizer import FindingNormalizer
from engine.models import RawFinding


def test_fingerprint_is_deterministic_and_stable():
    fp1 = FindingNormalizer.compute_fingerprint(
        rule_id="RULE_A03_SQL_CONCAT",
        file_path="src/controllers/auth.ts",
        line_start=42,
        evidence="query = 'SELECT * FROM users WHERE email = ' + email",
    )
    fp2 = FindingNormalizer.compute_fingerprint(
        rule_id="rule_a03_sql_concat",  # case insensitive rule id
        file_path="src\\controllers\\auth.ts",  # Windows backslash
        line_start=42,
        evidence="query = 'SELECT * FROM users WHERE email = ' + email",
    )
    assert fp1 == fp2
    assert len(fp1) == 64  # valid sha256 hex string


def test_normalizer_enriches_owasp_category():
    raw = RawFinding(
        rule_id="RULE_A03_SQL_CONCAT",
        scanner="custom",
        title="SQL Injection",
        severity="critical",
        file_path="db.py",
        line_start=15,
        evidence="SELECT * FROM table WHERE id = " + "1",
    )
    normalized = FindingNormalizer.normalize(raw)
    assert normalized.severity == "CRITICAL"
    assert normalized.owasp_id == "A03:2021"
    assert normalized.owasp_name == "Injection"
    assert normalized.status == "OPEN"
    assert normalized.fingerprint is not None


def test_normalizer_deduplicates_batch():
    raw1 = RawFinding(
        rule_id="RULE_A01_IDOR",
        scanner="custom",
        title="IDOR",
        severity="high",
        file_path="api.js",
        line_start=10,
        evidence="findById(req.params.id)",
    )
    raw2 = RawFinding(
        rule_id="RULE_A01_IDOR",
        scanner="custom",
        title="IDOR Duplicate",
        severity="high",
        file_path="api.js",
        line_start=10,
        evidence="findById(req.params.id)",
    )
    batch = FindingNormalizer.normalize_batch([raw1, raw2])
    assert len(batch) == 1
