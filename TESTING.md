# Audit Bench — Testing Strategy & Verification Suite

## 1. Test Philosophy

Audit Bench tests adhere to real-world DevSecOps security verification standards:
1. **Never mock out the core security engine in tests**: Scanners and rules must be evaluated against real vulnerable code strings and fixture files.
2. **Deterministic outcomes**: Given the same codebase and commit, findings, scores, and policy decisions must match 100% across test runs.
3. **Diff verification**: Scan comparisons must accurately transition findings across `OPEN`, `RESOLVED`, and `REOPENED` states.

---

## 2. Test Pyramid

- **Unit Tests (`tests/unit/`)**:
  - `test_rule_engine.py`: Tests all 13 OWASP rules against positive and negative code samples.
  - `test_finding_normalizer.py`: Verifies raw tool outputs convert into canonical `Finding` objects with valid fingerprints.
  - `test_score_engine.py`: Verifies mathematical deduction model (base 100 with severity weights).
  - `test_policy_engine.py`: Verifies PASS/FAIL gate logic against diverse threshold policies.
  - `test_verification_engine.py`: Verifies fingerprint matching and lifecycle state transitions across sequential scans.
  - `test_scanner_adapters.py`: Tests adapter interfaces, error handling, and output parsing.

- **Integration Tests (`tests/integration/`)**:
  - `test_scan_pipeline.py`: End-to-end execution of the orchestrator from code input to database persistence.
  - `test_api_endpoints.py`: REST API contract testing for `/repositories`, `/scans`, `/findings`, `/policies`.
  - `test_github_webhooks.py`: Verifies HMAC-SHA256 signature verification and asynchronous scan dispatch.

- **Fixture Projects (`tests/fixtures/vulnerable_repo/`)**:
  - Contains deliberate OWASP vulnerabilities:
    - `vulnerable_sql.py`: SQL injection via string concatenation.
    - `vulnerable_xss.js`: Cross-Site Scripting via `innerHTML`.
    - `vulnerable_crypto.py`: MD5 and hardcoded secrets.
    - `vulnerable_ssrf.js`: Unvalidated external fetch.
    - `vulnerable_access.py`: Path traversal with `open()`.

---

## 3. Running the Test Suite

```bash
# Run all unit tests
pytest tests/unit/ -v

# Run integration tests
pytest tests/integration/ -v

# Run with test coverage report
pytest --cov=engine --cov=scanners --cov=apps/api tests/
```
