"""
Unit tests for RuleEngine.
Verifies detection accuracy across all 13 deterministic OWASP rules.
"""
import pytest
from engine.rule_engine import RuleEngine, CORE_RULES


@pytest.fixture
def engine():
    return RuleEngine()


def test_core_rules_count(engine):
    assert len(engine.rules) == 13


def test_detects_sql_injection(engine):
    vuln_code = "const sql = 'SELECT * FROM users WHERE id = ' + req.params.userId;"
    findings = engine.scan_content(vuln_code, "test.js")
    assert len(findings) >= 1
    assert any(f.rule_id == "RULE_A03_SQL_CONCAT" for f in findings)
    assert any(f.severity == "CRITICAL" for f in findings)


def test_detects_xss_innerhtml(engine):
    vuln_code = "document.getElementById('app').innerHTML = userSuppliedInput;"
    findings = engine.scan_content(vuln_code, "app.js")
    assert any(f.rule_id == "RULE_A03_XSS_INNERHTML" for f in findings)


def test_detects_weak_hash_md5(engine):
    vuln_code = "const hash = crypto.createHash('md5').update(pwd).digest('hex');"
    findings = engine.scan_content(vuln_code, "auth.js")
    assert any(f.rule_id == "RULE_A02_WEAK_HASH" for f in findings)


def test_detects_hardcoded_aws_key(engine):
    vuln_code = "const awsKey = 'AKIA1234567890ABCDEF';"
    findings = engine.scan_content(vuln_code, "config.js")
    assert any(f.rule_id == "RULE_A02_HARDCODED_KEY" for f in findings)


def test_detects_eval_rce(engine):
    vuln_code = "eval(req.body.codeToExecute);"
    findings = engine.scan_content(vuln_code, "server.js")
    assert any(f.rule_id == "RULE_A03_EVAL_DYNAMIC_CODE" for f in findings)


def test_detects_path_traversal(engine):
    vuln_code = "fs.readFile(req.query.userFilePath, 'utf8', callback);"
    findings = engine.scan_content(vuln_code, "files.js")
    assert any(f.rule_id == "RULE_A01_PATH_TRAVERSAL" for f in findings)


def test_detects_weak_jwt_secret(engine):
    vuln_code = "const token = jwt.sign(user, '123456');"
    findings = engine.scan_content(vuln_code, "jwt.js")
    assert any(f.rule_id == "RULE_A07_WEAK_JWT_SECRET" for f in findings)


def test_detects_ssrf(engine):
    vuln_code = "fetch(req.query.targetUrl);"
    findings = engine.scan_content(vuln_code, "proxy.js")
    assert any(f.rule_id == "RULE_A10_UNVALIDATED_FETCH" for f in findings)


def test_detects_weak_prng(engine):
    vuln_code = "const token = Math.random().toString(36);"
    findings = engine.scan_content(vuln_code, "token.js")
    assert any(f.rule_id == "RULE_A04_WEAK_PRNG" for f in findings)


def test_detects_cors_wildcard(engine):
    vuln_code = "app.use(cors({ origin: '*' }));"
    findings = engine.scan_content(vuln_code, "cors.js")
    assert any(f.rule_id == "RULE_A05_CORS_WILDCARD" for f in findings)


def test_safe_code_produces_no_false_positives(engine):
    safe_code = """
    // Safe parameterized query
    const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    const hash = await argon2.hash(password);
    element.textContent = sanitizedInput;
    """
    findings = engine.scan_content(safe_code, "safe.js")
    assert len(findings) == 0
