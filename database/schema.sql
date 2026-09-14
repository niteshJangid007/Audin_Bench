-- Audit Bench Core Database Schema (PostgreSQL)

CREATE TABLE IF NOT EXISTS organizations (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT,
    role            TEXT NOT NULL DEFAULT 'member', -- admin | member | auditor
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id);

CREATE TABLE IF NOT EXISTS github_installations (
    id                     UUID PRIMARY KEY,
    organization_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    github_installation_id BIGINT NOT NULL UNIQUE,
    github_account_login   TEXT NOT NULL,
    installed_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    suspended_at           TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_installations_org ON github_installations(organization_id);

CREATE TABLE IF NOT EXISTS repositories (
    id                  UUID PRIMARY KEY,
    installation_id     UUID NOT NULL REFERENCES github_installations(id) ON DELETE CASCADE,
    github_repo_id      BIGINT NOT NULL,
    full_name           TEXT NOT NULL,
    default_branch      TEXT NOT NULL DEFAULT 'main',
    is_active           BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (installation_id, github_repo_id)
);
CREATE INDEX IF NOT EXISTS idx_repositories_installation ON repositories(installation_id);

CREATE TABLE IF NOT EXISTS branches (
    id              UUID PRIMARY KEY,
    repository_id   UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    is_default      BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (repository_id, name)
);

CREATE TABLE IF NOT EXISTS security_policies (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id   UUID REFERENCES repositories(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    definition      JSONB NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_policies_repo ON security_policies(repository_id);

CREATE TABLE IF NOT EXISTS scans (
    id              UUID PRIMARY KEY,
    repository_id   UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    branch_id       UUID REFERENCES branches(id),
    commit_sha      TEXT NOT NULL,
    trigger         TEXT NOT NULL,                  -- push | pull_request | manual
    status          TEXT NOT NULL DEFAULT 'QUEUED', -- QUEUED | RUNNING | COMPLETED | FAILED | CANCELLED
    error_detail    JSONB,
    security_score  INTEGER,
    policy_id       UUID REFERENCES security_policies(id),
    policy_result   TEXT,                           -- PASS | FAIL | NULL
    summary         JSONB,
    owasp_breakdown JSONB,
    queued_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scans_repository ON scans(repository_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

CREATE TABLE IF NOT EXISTS owasp_categories (
    id              TEXT PRIMARY KEY,               -- e.g. 'A01:2021'
    name            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    id                  TEXT PRIMARY KEY,           -- e.g. 'RULE_A03_SQL_CONCAT'
    title               TEXT NOT NULL,
    category            TEXT NOT NULL,
    owasp_id            TEXT REFERENCES owasp_categories(id),
    default_severity    TEXT NOT NULL,              -- CRITICAL | HIGH | MEDIUM | LOW
    default_confidence  TEXT NOT NULL,              -- HIGH | MEDIUM | LOW
    detection_method    TEXT NOT NULL,              -- regex | ast | scanner_result | dependency | secret | config
    supported_languages TEXT[] NOT NULL DEFAULT '{}',
    explanation         TEXT,
    impact              TEXT,
    remediation_text    TEXT,
    is_active           BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS remediations (
    id              UUID PRIMARY KEY,
    rule_id         TEXT NOT NULL REFERENCES rules(id),
    summary         TEXT NOT NULL,
    detail          TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id                     UUID PRIMARY KEY,
    repository_id          UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint            TEXT NOT NULL,
    rule_id                TEXT REFERENCES rules(id),
    scanner                TEXT NOT NULL,           -- semgrep | trivy | gitleaks | custom
    title                  TEXT NOT NULL,
    category               TEXT,
    owasp_id               TEXT REFERENCES owasp_categories(id),
    severity               TEXT NOT NULL,           -- CRITICAL | HIGH | MEDIUM | LOW
    confidence             TEXT NOT NULL,           -- HIGH | MEDIUM | LOW
    file_path              TEXT,
    line_start             INTEGER,
    line_end               INTEGER,
    evidence               TEXT,
    description            TEXT,
    impact                 TEXT,
    remediation            TEXT,
    status                 TEXT NOT NULL DEFAULT 'OPEN', -- OPEN | RESOLVED | REOPENED
    first_detected_scan_id UUID REFERENCES scans(id),
    last_seen_scan_id      UUID REFERENCES scans(id),
    detected_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at            TIMESTAMPTZ,
    UNIQUE (repository_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_repository ON findings(repository_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS scan_findings (
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    status_at_scan  TEXT NOT NULL,                  -- OPEN | RESOLVED | REOPENED
    PRIMARY KEY (scan_id, finding_id)
);

CREATE TABLE IF NOT EXISTS finding_history (
    id              UUID PRIMARY KEY,
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id         UUID NOT NULL REFERENCES scans(id),
    from_status     TEXT,
    to_status       TEXT NOT NULL,
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_finding_history_finding ON finding_history(finding_id);
