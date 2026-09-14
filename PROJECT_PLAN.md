# Audit Bench — Project Plan

## Implementation Roadmap

### Phase 0: Audit & Architecture Documentation (Completed)
- Forensic review of legacy assets and initial scaffolding.
- Complete definition of architectural invariants, data flow, and directory structure.
- Establishment of the 8 synchronized technical reference documents.

### Phase 1: Foundation (In Progress)
- Scaffold standard directory tree (`apps/web`, `apps/api`, `engine`, `scanners`, `github`, `database`, `tests`).
- Docker Compose configuration for PostgreSQL, Redis, API, and Worker services.
- FastAPI bootstrap with `/api/v1/health` and configuration management.
- Dual execution support (Docker and local developer workflow).

### Phase 2: Database Layer
- PostgreSQL relational schema and SQLAlchemy 2.0 ORM models.
- Core entities: `organizations`, `users`, `github_installations`, `repositories`, `branches`, `security_policies`, `scans`, `findings`, `scan_findings`, `rules`, `owasp_categories`, `remediations`, `finding_history`.
- Indexes, constraints, and scan lifecycle state transitions (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`).

### Phase 3: Finding Model & Normalization
- Canonical Pydantic schema based on `finding.schema.json`.
- Strict scanner abstraction: scanner-native SARIF/JSON is parsed and normalized into canonical `Finding` objects.
- Deterministic SHA-256 fingerprint generation.

### Phase 4: Rule Engine & OWASP Mapping
- 13 deterministic OWASP Top 10 rules ported to an extensible Python engine.
- OWASP Top 10 (2021) classification: A01 to A10.
- Detection strategies: `regex`, `ast`, `scanner_result`, `secret`, `dependency`, `config`.

### Phase 5: Scanner Adapters
- Abstract `ScannerAdapter` class defining `scan()`, `parse()`, `normalize()`, and `validate()`.
- Implementations for `SemgrepScanner`, `TrivyScanner`, `GitleaksScanner`, and `CustomRuleScanner`.
- Fault-tolerant error containment: individual scanner timeouts or errors are logged without terminating the scan pipeline.

### Phase 6: Scan Orchestrator Pipeline
- Sequential and concurrent orchestration pipeline:
  `create_scan` -> `queue_scan` -> `run_scanners` -> `collect_results` -> `normalize_findings` -> `deduplicate` -> `classify_owasp` -> `calculate_severity` -> `calculate_score` -> `evaluate_policy` -> `persist_results` -> `publish_github_check`.

### Phase 7: Scoring & Policy Engine
- Deterministic base-100 score engine with weighted severity/confidence penalties.
- Configurable policies: `minimum_score`, `fail_on_critical`, `max_high`, `fail_on_secrets`, `fail_on_new_findings`.
- Evaluation output: `PASS` / `FAIL` with itemized violation explanations.

### Phase 8: GitHub App Integration
- GitHub App authentication (RS256 JWT, installation tokens).
- HMAC-SHA256 signature verification for incoming webhooks (`push`, `pull_request`, `installation`).
- GitHub Check Runs API client publishing security score, summary, and file annotations.

### Phase 9: Verification Engine (Re-scan & Diff)
- Finding diffing between consecutive scans on the same branch.
- Finding lifecycle states: `OPEN`, `RESOLVED`, `REOPENED`.
- Detailed audit tracking in `finding_history`.

### Phase 10: Frontend UI (`apps/web`)
- Next.js 14+ application with Tailwind CSS and dark cybernetic design tokens.
- Modules: Dashboard, Repositories, Scan Inspector, Findings Explorer, Policies, Reports, Settings/GitHub, and Interactive Developer Sandbox.

### Phase 11: Security Hardening & Platform Audit
- Input validation, SSRF protection (DNS resolution, private CIDR filtering).
- Zip-bomb and zip-slip mitigation.
- Sanitized logging and credential protection.

### Phase 12: Testing & Fixture Repositories
- Unit tests for all engines and adapters.
- Integration tests for API endpoints and scan lifecycle.
- Vulnerable sample test projects (SQLi, XSS, SSRF, secrets, weak crypto).

### Phase 13: End-to-End Verification Demo
- Scripted end-to-end demonstration verifying discovery, scan execution, policy failure, code remediation, re-scan resolution, and Check Run pass.
