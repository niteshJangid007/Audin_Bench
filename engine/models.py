"""
Pydantic Schemas for Audit Bench Engines.
Conforms strictly to schemas/finding.schema.json and schemas/policy.schema.json.
"""
from datetime import datetime, timezone
from typing import Optional, Literal, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
import uuid


def generate_uuid_str() -> str:
    return str(uuid.uuid4())


def current_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RawFinding(BaseModel):
    """Scanner-native intermediate finding representation."""
    rule_id: str
    scanner: Literal["semgrep", "trivy", "gitleaks", "custom"]
    title: str
    category: Optional[str] = None
    owasp_id: Optional[str] = None
    severity: str  # scanner-native (e.g. ERROR, WARNING, critical, high)
    confidence: str = "HIGH"
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    evidence: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None


class Finding(BaseModel):
    """Normalized finding conforming strictly to schemas/finding.schema.json."""
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=generate_uuid_str)
    rule_id: str
    scanner: Literal["semgrep", "trivy", "gitleaks", "custom"]
    title: str
    category: str
    owasp_id: Optional[str] = None
    owasp_name: Optional[str] = None
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    evidence: Optional[str] = Field(None, description="Exact matched snippet/context, truncated")
    description: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    status: Literal["OPEN", "RESOLVED", "REOPENED"] = "OPEN"
    fingerprint: str = Field(description="sha256 of rule_id + normalized file path + normalized location + evidence")
    detected_at: str = Field(default_factory=current_utc_iso)
    resolved_at: Optional[str] = None


class SecurityPolicyDefinition(BaseModel):
    """Security policy configuration matching schemas/policy.schema.json."""
    model_config = ConfigDict(extra="forbid")

    minimum_score: int = Field(default=75, ge=0, le=100)
    fail_on_critical: bool = True
    max_high: int = Field(default=2, ge=0)
    max_medium: int = Field(default=10, ge=0)
    max_low: int = Field(default=20, ge=0)
    fail_on_secrets: bool = True
    fail_on_new_findings: bool = True


class PolicyEvaluationResult(BaseModel):
    """Result of policy evaluation."""
    passed: bool
    policy_result: Literal["PASS", "FAIL"]
    violations: List[str]
    score: int
    minimum_score: int


class ScanSummary(BaseModel):
    """Severity counts and scan statistics."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0
    owasp_distribution: Dict[str, int] = Field(default_factory=dict)
    files_scanned: int = 0
    lines_scanned: int = 0
    duration_ms: int = 0
