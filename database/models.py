"""
SQLAlchemy ORM Models for Audit Bench.
Compatible with PostgreSQL and SQLite.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Any

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    BigInteger,
    UniqueConstraint,
    JSON,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    installations = relationship("GitHubInstallation", back_populates="organization", cascade="all, delete-orphan")
    policies = relationship("SecurityPolicy", back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=True)
    role = Column(String(50), default="member", nullable=False)  # admin | member | auditor
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    organization = relationship("Organization", back_populates="users")


class GitHubInstallation(Base):
    __tablename__ = "github_installations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    github_installation_id = Column(BigInteger, unique=True, nullable=False)
    github_account_login = Column(String(255), nullable=False)
    installed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    suspended_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="installations")
    repositories = relationship("Repository", back_populates="installation", cascade="all, delete-orphan")


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("installation_id", "github_repo_id", name="uq_repo_installation_github"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    installation_id = Column(String(36), ForeignKey("github_installations.id", ondelete="CASCADE"), nullable=False, index=True)
    github_repo_id = Column(BigInteger, nullable=False)
    full_name = Column(String(255), nullable=False)  # e.g. owner/repo
    default_branch = Column(String(100), default="main", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    installation = relationship("GitHubInstallation", back_populates="repositories")
    branches = relationship("Branch", back_populates="repository", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="repository", cascade="all, delete-orphan")
    policies = relationship("SecurityPolicy", back_populates="repository", cascade="all, delete-orphan")


class Branch(Base):
    __tablename__ = "branches"
    __table_args__ = (
        UniqueConstraint("repository_id", "name", name="uq_branch_repo_name"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    repository_id = Column(String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    is_default = Column(Boolean, default=False, nullable=False)

    repository = relationship("Repository", back_populates="branches")


class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    repository_id = Column(String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    definition = Column(JSON, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    organization = relationship("Organization", back_populates="policies")
    repository = relationship("Repository", back_populates="policies")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    repository_id = Column(String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    branch_id = Column(String(36), ForeignKey("branches.id", ondelete="SET NULL"), nullable=True)
    commit_sha = Column(String(64), nullable=False)
    trigger = Column(String(50), nullable=False)  # push | pull_request | manual
    status = Column(String(50), default="QUEUED", nullable=False, index=True)  # QUEUED | RUNNING | COMPLETED | FAILED | CANCELLED
    error_detail = Column(JSON, nullable=True)
    security_score = Column(Integer, nullable=True)
    policy_id = Column(String(36), ForeignKey("security_policies.id", ondelete="SET NULL"), nullable=True)
    policy_result = Column(String(20), nullable=True)  # PASS | FAIL
    summary = Column(JSON, nullable=True)
    owasp_breakdown = Column(JSON, nullable=True)
    queued_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    repository = relationship("Repository", back_populates="scans")
    scan_findings = relationship("ScanFinding", back_populates="scan", cascade="all, delete-orphan")


class OWASPCategory(Base):
    __tablename__ = "owasp_categories"

    id = Column(String(50), primary_key=True)  # e.g. A01:2021
    name = Column(String(255), nullable=False)

    rules = relationship("Rule", back_populates="owasp_category")
    findings = relationship("Finding", back_populates="owasp_category")


class Rule(Base):
    __tablename__ = "rules"

    id = Column(String(100), primary_key=True)  # e.g. RULE_A03_SQL_CONCAT
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False)
    owasp_id = Column(String(50), ForeignKey("owasp_categories.id"), nullable=True)
    default_severity = Column(String(20), nullable=False)  # CRITICAL | HIGH | MEDIUM | LOW
    default_confidence = Column(String(20), nullable=False)  # HIGH | MEDIUM | LOW
    detection_method = Column(String(50), nullable=False)  # regex | ast | scanner_result | dependency | secret | config
    supported_languages = Column(JSON, default=list, nullable=False)
    explanation = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation_text = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    owasp_category = relationship("OWASPCategory", back_populates="rules")
    findings = relationship("Finding", back_populates="rule")
    remediations = relationship("Remediation", back_populates="rule", cascade="all, delete-orphan")


class Remediation(Base):
    __tablename__ = "remediations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_id = Column(String(100), ForeignKey("rules.id", ondelete="CASCADE"), nullable=False)
    summary = Column(Text, nullable=False)
    detail = Column(Text, nullable=True)

    rule = relationship("Rule", back_populates="remediations")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("repository_id", "fingerprint", name="uq_finding_repo_fingerprint"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    repository_id = Column(String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    rule_id = Column(String(100), ForeignKey("rules.id", ondelete="SET NULL"), nullable=True)
    scanner = Column(String(50), nullable=False)  # semgrep | trivy | gitleaks | custom
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=True)
    owasp_id = Column(String(50), ForeignKey("owasp_categories.id", ondelete="SET NULL"), nullable=True)
    severity = Column(String(20), nullable=False, index=True)  # CRITICAL | HIGH | MEDIUM | LOW
    confidence = Column(String(20), nullable=False)  # HIGH | MEDIUM | LOW
    file_path = Column(String(1024), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    evidence = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    status = Column(String(20), default="OPEN", nullable=False, index=True)  # OPEN | RESOLVED | REOPENED
    first_detected_scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    last_seen_scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    detected_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    repository = relationship("Repository", back_populates="findings")
    rule = relationship("Rule", back_populates="findings")
    owasp_category = relationship("OWASPCategory", back_populates="findings")
    scan_findings = relationship("ScanFinding", back_populates="finding", cascade="all, delete-orphan")
    history = relationship("FindingHistory", back_populates="finding", cascade="all, delete-orphan")


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    status_at_scan = Column(String(20), nullable=False)  # OPEN | RESOLVED | REOPENED

    scan = relationship("Scan", back_populates="scan_findings")
    finding = relationship("Finding", back_populates="scan_findings")


class FindingHistory(Base):
    __tablename__ = "finding_history"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    from_status = Column(String(20), nullable=True)
    to_status = Column(String(20), nullable=False)
    changed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    finding = relationship("Finding", back_populates="history")
