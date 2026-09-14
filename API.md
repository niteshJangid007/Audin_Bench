# Audit Bench — API Reference

Base URL: `/api/v1`  
Authentication: `Authorization: Bearer <jwt_or_api_token>` (except webhook endpoint which uses HMAC)

---

## 1. Health & Telemetry

### `GET /api/v1/health`
Returns system liveness, version, and component status.

**Response `200 OK`**:
```json
{
  "status": "online",
  "version": "1.0.0",
  "engine": "AuditBench-Orchestrator",
  "owasp_version": "OWASP Top 10 (2021)",
  "active_rules": 13,
  "scanners": ["semgrep", "trivy", "gitleaks", "custom"],
  "timestamp": "2026-09-14T12:00:00Z"
}
```

---

## 2. Repositories

### `GET /api/v1/repositories`
Lists all tracked repositories with recent scan status and score.

**Response `200 OK`**:
```json
[
  {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "full_name": "acme-corp/payment-service",
    "default_branch": "main",
    "is_active": true,
    "last_scan": {
      "id": "7ca85f64-5717-4562-b3fc-2c963f66afa7",
      "status": "COMPLETED",
      "security_score": 84,
      "policy_result": "PASS",
      "completed_at": "2026-09-14T11:45:00Z"
    }
  }
]
```

### `GET /api/v1/repositories/{id}`
Returns repository details, active security policy, and recent scan history.

### `POST /api/v1/repositories/{id}/scans`
Initiates a new audit scan for the repository.

**Request Body**:
```json
{
  "branch": "main",
  "commit_sha": "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
}
```

**Response `202 Accepted`**:
```json
{
  "scan_id": "7ca85f64-5717-4562-b3fc-2c963f66afa7",
  "status": "QUEUED",
  "queued_at": "2026-09-14T12:05:00Z"
}
```

---

## 3. Scans

### `GET /api/v1/scans?repository_id={repo_id}&status={status}&limit={limit}`
Queries scans with optional filters.

### `GET /api/v1/scans/{id}`
Returns complete scan execution details, score, policy decision, severity counts, and scanner execution status.

**Response `200 OK`**:
```json
{
  "id": "7ca85f64-5717-4562-b3fc-2c963f66afa7",
  "repository_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "branch": "main",
  "commit_sha": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
  "trigger": "push",
  "status": "COMPLETED",
  "security_score": 65,
  "policy_result": "FAIL",
  "policy_violations": [
    "Score 65 is below required minimum threshold 75",
    "Found 1 CRITICAL vulnerability (allowed: 0)"
  ],
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1,
    "total": 7
  },
  "owasp_distribution": {
    "A01:2021": 1,
    "A03:2021": 3,
    "A07:2021": 2,
    "A10:2021": 1
  },
  "scanners_executed": ["custom", "semgrep", "gitleaks"],
  "queued_at": "2026-09-14T12:00:00Z",
  "started_at": "2026-09-14T12:00:02Z",
  "completed_at": "2026-09-14T12:00:15Z"
}
```

### `POST /api/v1/scans/{id}/cancel`
Cancels a currently queued or executing scan.

---

## 4. Findings

### `GET /api/v1/findings?scan_id={scan_id}&repository_id={repo_id}&severity={sev}&status={status}`
Retrieves normalized findings with filtering.

**Response `200 OK`**:
```json
[
  {
    "finding_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "rule_id": "RULE_A03_SQL_CONCAT",
    "scanner": "custom",
    "title": "SQL Query Built with String Concatenation / Interpolation",
    "category": "Injection",
    "owasp_id": "A03:2021",
    "owasp_name": "Injection",
    "severity": "CRITICAL",
    "confidence": "HIGH",
    "file_path": "src/services/userService.ts",
    "line_start": 42,
    "line_end": 42,
    "evidence": "db.query(\"SELECT * FROM users WHERE email = '\" + email + \"'\")",
    "description": "Interpolating unescaped user input into raw SQL queries enables SQL injection (CWE-89).",
    "remediation": "Use parameterized queries or prepared statements: db.query('SELECT * FROM users WHERE email = $1', [email]);",
    "status": "OPEN",
    "detected_at": "2026-09-14T12:00:10Z"
  }
]
```

### `GET /api/v1/findings/{id}`
Returns finding details alongside historical transitions (`OPEN` -> `RESOLVED` -> `REOPENED`).

---

## 5. Security Policies

### `GET /api/v1/policies`
Lists active policies for an organization or repository.

### `POST /api/v1/policies`
Creates a new security policy. Validated against `policy.schema.json`.

**Request Body**:
```json
{
  "name": "Production Release Gate",
  "repository_id": null,
  "definition": {
    "minimum_score": 80,
    "fail_on_critical": true,
    "max_high": 2,
    "max_medium": 10,
    "max_low": 20,
    "fail_on_secrets": true,
    "fail_on_new_findings": true
  }
}
```

---

## 6. GitHub Integration & Webhooks

### `POST /api/v1/github/webhook`
Receives GitHub App event payloads (`push`, `pull_request`, `installation`).
- Signature header: `X-Hub-Signature-256: sha256=...`
- Responds with `200 OK` and dispatches asynchronous scan jobs.

### `POST /api/v1/github/install`
Completes GitHub App installation handshake and triggers initial repository discovery.

---

## 7. Interactive Developer Sandbox

### `POST /api/v1/scan/snippet`
Synchronous scan for developer testing and triage workbench.

**Request Body**:
```json
{
  "code": "const query = 'SELECT * FROM accounts WHERE id = ' + req.params.id;",
  "language": "javascript"
}
```

**Response `200 OK`**:
Returns normalized findings, OWASP distribution, and computed risk score.
