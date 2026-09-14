"""
ScanOrchestrator — Coordinates the entire security analysis pipeline:
Repository -> Scanner Adapters -> Finding Normalizer -> OWASP Mapper ->
Severity/Risk -> ScoreEngine -> PolicyEngine -> VerificationEngine -> Persistence.
"""
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from engine.models import (
    Finding,
    RawFinding,
    SecurityPolicyDefinition,
    PolicyEvaluationResult,
    ScanSummary,
)
from engine.normalizer import FindingNormalizer
from engine.score_engine import ScoreEngine
from engine.policy_engine import PolicyEngine
from engine.verification_engine import VerificationEngine
from scanners.base import ScannerAdapter, ScanExecutionResult
from scanners.custom_scanner import CustomRuleScanner
from scanners.semgrep_scanner import SemgrepScanner
from scanners.gitleaks_scanner import GitleaksScanner
from scanners.trivy_scanner import TrivyScanner
from database.models import (
    Scan,
    Finding as DBFinding,
    ScanFinding as DBScanFinding,
    FindingHistory as DBFindingHistory,
    SecurityPolicy as DBSecurityPolicy,
)


class ScanOrchestrationPipelineResult:
    def __init__(
        self,
        scan_id: str,
        status: str,
        score: int,
        policy_result: str,
        violations: List[str],
        summary: ScanSummary,
        findings: List[Finding],
        scanner_results: Dict[str, ScanExecutionResult],
        duration_ms: int,
        error_detail: Optional[Dict[str, Any]] = None,
    ):
        self.scan_id = scan_id
        self.status = status
        self.score = score
        self.policy_result = policy_result
        self.violations = violations
        self.summary = summary
        self.findings = findings
        self.scanner_results = scanner_results
        self.duration_ms = duration_ms
        self.error_detail = error_detail


class ScanOrchestrator:
    def __init__(self, adapters: Optional[List[ScannerAdapter]] = None):
        self.adapters = adapters or [
            CustomRuleScanner(),
            GitleaksScanner(),
            TrivyScanner(),
            SemgrepScanner(),
        ]

    def execute_scan(
        self,
        scan_id: str,
        workspace_path: str,
        db: Optional[Session] = None,
        policy_definition: Optional[SecurityPolicyDefinition] = None,
        prior_findings: Optional[List[Finding]] = None,
    ) -> ScanOrchestrationPipelineResult:
        """
        Executes end-to-end scanning pipeline in strict sequence.
        Fault-tolerant: individual scanner errors do not fail the whole scan.
        """
        start_time = time.time()
        raw_findings: List[RawFinding] = []
        scanner_results: Dict[str, ScanExecutionResult] = {}
        warnings: List[str] = []

        # 1. Execute all scanner adapters
        for adapter in self.adapters:
            try:
                res = adapter.scan(workspace_path)
                scanner_results[adapter.name] = res

                if res.exit_code == 0:
                    adapter_findings = adapter.parse(res.stdout, res.exit_code)
                    raw_findings.extend(adapter_findings)
                else:
                    msg = f"Scanner '{adapter.name}' exited with code {res.exit_code}: {res.stderr or 'Error'}"
                    warnings.append(msg)
                    if res.warning:
                        warnings.append(res.warning)
            except Exception as ex:
                warnings.append(f"Scanner '{adapter.name}' encountered exception: {str(ex)}")

        # 2. Normalize and deduplicate findings
        current_normalized = FindingNormalizer.normalize_batch(raw_findings)

        # 3. Reconcile with prior scan findings via VerificationEngine
        prior = prior_findings or []
        if not prior and db:
            prior = self._load_prior_open_findings(db, scan_id)

        reconciled_findings, transitions, has_new_findings = VerificationEngine.diff_scans(
            prior_findings=prior,
            current_findings=current_normalized,
        )

        # 4. Calculate deterministic security score
        score = ScoreEngine.compute_score(reconciled_findings)

        # 5. Evaluate Security Policy gate
        if policy_definition is None and db:
            policy_definition = self._load_active_policy(db, scan_id)
        if policy_definition is None:
            policy_definition = SecurityPolicyDefinition()

        policy_eval = PolicyEngine.evaluate(
            score=score,
            findings=reconciled_findings,
            policy=policy_definition,
            has_new_findings=has_new_findings,
        )

        # 6. Build scan summary metrics
        active_findings = [f for f in reconciled_findings if f.status in ("OPEN", "REOPENED")]
        owasp_dist: Dict[str, int] = {}
        for f in active_findings:
            cat = f.owasp_id or "Unclassified"
            owasp_dist[cat] = owasp_dist.get(cat, 0) + 1

        total_duration = int((time.time() - start_time) * 1000)
        summary = ScanSummary(
            critical=sum(1 for f in active_findings if f.severity == "CRITICAL"),
            high=sum(1 for f in active_findings if f.severity == "HIGH"),
            medium=sum(1 for f in active_findings if f.severity == "MEDIUM"),
            low=sum(1 for f in active_findings if f.severity == "LOW"),
            total=len(active_findings),
            owasp_distribution=owasp_dist,
            duration_ms=total_duration,
        )

        error_detail = None
        if warnings:
            error_detail = {"warnings": warnings}

        # 7. Persist results if database session provided
        if db:
            self._persist_results(
                db=db,
                scan_id=scan_id,
                score=score,
                policy_result=policy_eval.policy_result,
                summary=summary,
                findings=reconciled_findings,
                transitions=transitions,
                error_detail=error_detail,
            )

        return ScanOrchestrationPipelineResult(
            scan_id=scan_id,
            status="COMPLETED",
            score=score,
            policy_result=policy_eval.policy_result,
            violations=policy_eval.violations,
            summary=summary,
            findings=reconciled_findings,
            scanner_results=scanner_results,
            duration_ms=total_duration,
            error_detail=error_detail,
        )

    def _load_prior_open_findings(self, db: Session, scan_id: str) -> List[Finding]:
        scan_record = db.query(Scan).filter_by(id=scan_id).first()
        if not scan_record:
            return []

        # Find previous scan on the same repository
        prev_scan = (
            db.query(Scan)
            .filter(
                Scan.repository_id == scan_record.repository_id,
                Scan.id != scan_id,
                Scan.status == "COMPLETED",
            )
            .order_by(Scan.completed_at.desc())
            .first()
        )
        if not prev_scan:
            return []

        # Retrieve findings from previous scan
        db_findings = (
            db.query(DBFinding)
            .join(DBScanFinding, DBScanFinding.finding_id == DBFinding.id)
            .filter(DBScanFinding.scan_id == prev_scan.id)
            .all()
        )

        results = []
        for df in db_findings:
            results.append(
                Finding(
                    finding_id=df.id,
                    rule_id=df.rule_id or "UNKNOWN",
                    scanner=df.scanner,
                    title=df.title,
                    category=df.category or "General",
                    owasp_id=df.owasp_id,
                    severity=df.severity,
                    confidence=df.confidence,
                    file_path=df.file_path,
                    line_start=df.line_start,
                    line_end=df.line_end,
                    evidence=df.evidence,
                    description=df.description,
                    impact=df.impact,
                    remediation=df.remediation,
                    status=df.status,
                    fingerprint=df.fingerprint,
                    detected_at=df.detected_at.isoformat() if df.detected_at else "",
                    resolved_at=df.resolved_at.isoformat() if df.resolved_at else None,
                )
            )
        return results

    def _load_active_policy(self, db: Session, scan_id: str) -> SecurityPolicyDefinition:
        scan_record = db.query(Scan).filter_by(id=scan_id).first()
        if scan_record:
            policy = (
                db.query(DBSecurityPolicy)
                .filter_by(repository_id=scan_record.repository_id, is_active=True)
                .first()
            )
            if not policy:
                policy = db.query(DBSecurityPolicy).filter_by(is_active=True).first()
            if policy and isinstance(policy.definition, dict):
                return SecurityPolicyDefinition(**policy.definition)

        return SecurityPolicyDefinition()

    def _persist_results(
        self,
        db: Session,
        scan_id: str,
        score: int,
        policy_result: str,
        summary: ScanSummary,
        findings: List[Finding],
        transitions: List[Dict[str, str]],
        error_detail: Optional[Dict[str, Any]],
    ) -> None:
        scan_record = db.query(Scan).filter_by(id=scan_id).first()
        if not scan_record:
            return

        now = datetime.now(timezone.utc)
        scan_record.status = "COMPLETED"
        scan_record.security_score = score
        scan_record.policy_result = policy_result
        scan_record.summary = summary.model_dump()
        scan_record.owasp_breakdown = summary.owasp_distribution
        scan_record.completed_at = now
        scan_record.error_detail = error_detail

        for f in findings:
            # Upsert into findings table
            db_finding = (
                db.query(DBFinding)
                .filter_by(repository_id=scan_record.repository_id, fingerprint=f.fingerprint)
                .first()
            )
            if not db_finding:
                db_finding = DBFinding(
                    id=f.finding_id,
                    repository_id=scan_record.repository_id,
                    fingerprint=f.fingerprint,
                    rule_id=f.rule_id,
                    scanner=f.scanner,
                    title=f.title,
                    category=f.category,
                    owasp_id=f.owasp_id,
                    severity=f.severity,
                    confidence=f.confidence,
                    file_path=f.file_path,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    evidence=f.evidence,
                    description=f.description,
                    impact=f.impact,
                    remediation=f.remediation,
                    status=f.status,
                    first_detected_scan_id=scan_id,
                    last_seen_scan_id=scan_id,
                )
                db.add(db_finding)
                db.flush()
            else:
                db_finding.status = f.status
                db_finding.last_seen_scan_id = scan_id
                if f.status == "RESOLVED":
                    db_finding.resolved_at = now
                else:
                    db_finding.resolved_at = None

            # Add to scan_findings link table
            existing_link = (
                db.query(DBScanFinding)
                .filter_by(scan_id=scan_id, finding_id=db_finding.id)
                .first()
            )
            if not existing_link:
                db.add(DBScanFinding(scan_id=scan_id, finding_id=db_finding.id, status_at_scan=f.status))

            # Record history entry if transitioned
            for t in transitions:
                if t["fingerprint"] == f.fingerprint and t["from_status"] != t["to_status"]:
                    db.add(
                        DBFindingHistory(
                            finding_id=db_finding.id,
                            scan_id=scan_id,
                            from_status=t["from_status"],
                            to_status=t["to_status"],
                        )
                    )

        db.commit()
