# Audit Bench — Database Architecture & Schema

## 1. Overview
The persistence layer runs on PostgreSQL 16+ using SQLAlchemy 2.0 ORM with connection pooling, UUID primary keys, and strict foreign-key cascades.

---

## 2. Entity Relationship Diagram

```
[organizations]
       │ 1
       ├───< [users]
       ├───< [github_installations]
       │            │ 1
       │            └───< [repositories]
       │                        │ 1
       │                        ├───< [branches]
       │                        ├───< [scans] ───────┐
       │                        │       │ 1          │
       │                        │       └───< [scan_findings] >───┐
       │                        │                                 │
       │                        └───< [findings] ─────────────────┤
       │                                │ 1                       │
       │                                └───< [finding_history]   │
       └───< [security_policies]                                  │
                                                                  │
[owasp_categories] <── [rules] <──────────────────────────────────┘
```

---

## 3. Schema Definitions

### `organizations`
- `id` (UUID PK): Unique organization identifier.
- `name` (TEXT NOT NULL): Organization display name.
- `created_at` (TIMESTAMPTZ NOT NULL).

### `users`
- `id` (UUID PK)
- `organization_id` (UUID FK -> organizations.id ON DELETE CASCADE)
- `email` (TEXT UNIQUE NOT NULL)
- `password_hash` (TEXT NULL)
- `role` (TEXT NOT NULL): `admin` | `member` | `auditor`
- `created_at` (TIMESTAMPTZ NOT NULL)

### `github_installations`
- `id` (UUID PK)
- `organization_id` (UUID FK -> organizations.id ON DELETE CASCADE)
- `github_installation_id` (BIGINT UNIQUE NOT NULL)
- `github_account_login` (TEXT NOT NULL)
- `installed_at` (TIMESTAMPTZ NOT NULL)
- `suspended_at` (TIMESTAMPTZ NULL)

### `repositories`
- `id` (UUID PK)
- `installation_id` (UUID FK -> github_installations.id ON DELETE CASCADE)
- `github_repo_id` (BIGINT NOT NULL)
- `full_name` (TEXT NOT NULL, e.g. `octocat/hello-world`)
- `default_branch` (TEXT NOT NULL DEFAULT `main`)
- `is_active` (BOOLEAN NOT NULL DEFAULT true)
- `created_at` (TIMESTAMPTZ NOT NULL)
- *Constraint*: UNIQUE (`installation_id`, `github_repo_id`)
- *Index*: `idx_repositories_installation` on `installation_id`

### `branches`
- `id` (UUID PK)
- `repository_id` (UUID FK -> repositories.id ON DELETE CASCADE)
- `name` (TEXT NOT NULL)
- `is_default` (BOOLEAN NOT NULL DEFAULT false)
- *Constraint*: UNIQUE (`repository_id`, `name`)

### `security_policies`
- `id` (UUID PK)
- `organization_id` (UUID FK -> organizations.id ON DELETE CASCADE)
- `repository_id` (UUID FK -> repositories.id NULL, NULL = org default)
- `name` (TEXT NOT NULL)
- `definition` (JSONB NOT NULL, conforms to `policy.schema.json`)
- `is_active` (BOOLEAN NOT NULL DEFAULT true)
- `created_at` (TIMESTAMPTZ NOT NULL)
- `updated_at` (TIMESTAMPTZ NOT NULL)

### `scans`
- `id` (UUID PK)
- `repository_id` (UUID FK -> repositories.id ON DELETE CASCADE)
- `branch_id` (UUID FK -> branches.id NULL)
- `commit_sha` (TEXT NOT NULL)
- `trigger` (TEXT NOT NULL): `push` | `pull_request` | `manual`
- `status` (TEXT NOT NULL): `QUEUED` | `RUNNING` | `COMPLETED` | `FAILED` | `CANCELLED`
- `error_detail` (JSONB NULL): Structured diagnostics on failure
- `security_score` (INTEGER NULL, 0-100)
- `policy_id` (UUID FK -> security_policies.id NULL)
- `policy_result` (TEXT NULL): `PASS` | `FAIL`
- `queued_at` (TIMESTAMPTZ NOT NULL)
- `started_at` (TIMESTAMPTZ NULL)
- `completed_at` (TIMESTAMPTZ NULL)
- *Indexes*: `idx_scans_repository`, `idx_scans_status`

### `owasp_categories`
- `id` (TEXT PK): e.g. `A01:2021`
- `name` (TEXT NOT NULL)

### `rules`
- `id` (TEXT PK): e.g. `RULE_A03_SQL_CONCAT`
- `title` (TEXT NOT NULL)
- `category` (TEXT NOT NULL)
- `owasp_id` (TEXT FK -> owasp_categories.id)
- `default_severity` (TEXT NOT NULL): `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`
- `default_confidence` (TEXT NOT NULL): `HIGH` | `MEDIUM` | `LOW`
- `detection_method` (TEXT NOT NULL): `regex` | `ast` | `scanner_result` | `dependency` | `secret` | `config`
- `supported_languages` (TEXT[] NOT NULL)
- `explanation` (TEXT NULL)
- `impact` (TEXT NULL)
- `remediation_text` (TEXT NULL)
- `is_active` (BOOLEAN NOT NULL DEFAULT true)

### `findings`
- `id` (UUID PK)
- `repository_id` (UUID FK -> repositories.id ON DELETE CASCADE)
- `fingerprint` (TEXT NOT NULL): Deterministic SHA-256 hash
- `rule_id` (TEXT FK -> rules.id NULL)
- `scanner` (TEXT NOT NULL): `semgrep` | `trivy` | `gitleaks` | `custom`
- `title` (TEXT NOT NULL)
- `category` (TEXT NULL)
- `owasp_id` (TEXT FK -> owasp_categories.id NULL)
- `severity` (TEXT NOT NULL): `CRITICAL` | `HIGH` | `MEDIUM` | `LOW`
- `confidence` (TEXT NOT NULL): `HIGH` | `MEDIUM` | `LOW`
- `file_path` (TEXT NULL)
- `line_start` (INTEGER NULL)
- `line_end` (INTEGER NULL)
- `evidence` (TEXT NULL)
- `description` (TEXT NULL)
- `remediation` (TEXT NULL)
- `status` (TEXT NOT NULL DEFAULT `OPEN`): `OPEN` | `RESOLVED` | `REOPENED`
- `first_detected_scan_id` (UUID FK -> scans.id)
- `last_seen_scan_id` (UUID FK -> scans.id)
- `detected_at` (TIMESTAMPTZ NOT NULL)
- `resolved_at` (TIMESTAMPTZ NULL)
- *Constraint*: UNIQUE (`repository_id`, `fingerprint`)
- *Indexes*: `idx_findings_repository`, `idx_findings_status`, `idx_findings_severity`

### `scan_findings` (Many-to-Many Scan Occurrences)
- `scan_id` (UUID FK -> scans.id ON DELETE CASCADE)
- `finding_id` (UUID FK -> findings.id ON DELETE CASCADE)
- `status_at_scan` (TEXT NOT NULL)
- *PK*: (`scan_id`, `finding_id`)

### `finding_history`
- `id` (UUID PK)
- `finding_id` (UUID FK -> findings.id ON DELETE CASCADE)
- `scan_id` (UUID FK -> scans.id)
- `from_status` (TEXT NULL)
- `to_status` (TEXT NOT NULL)
- `changed_at` (TIMESTAMPTZ NOT NULL)
- *Index*: `idx_finding_history_finding` on `finding_id`
