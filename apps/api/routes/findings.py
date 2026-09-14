"""
Findings API Route.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database.session import get_db
from database.models import Finding, ScanFinding, FindingHistory

router = APIRouter()


@router.get("/findings")
def list_findings(
    repository_id: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    owasp_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    query = db.query(Finding)

    if scan_id:
        query = query.join(ScanFinding, ScanFinding.finding_id == Finding.id).filter(
            ScanFinding.scan_id == scan_id
        )
    if repository_id:
        query = query.filter(Finding.repository_id == repository_id)
    if severity:
        query = query.filter(Finding.severity == severity.upper())
    if status:
        query = query.filter(Finding.status == status.upper())
    if owasp_id:
        query = query.filter(Finding.owasp_id == owasp_id)

    findings = query.order_by(Finding.detected_at.desc()).limit(limit).all()

    return [
        {
            "finding_id": f.id,
            "fingerprint": f.fingerprint,
            "rule_id": f.rule_id,
            "scanner": f.scanner,
            "title": f.title,
            "category": f.category,
            "owasp_id": f.owasp_id,
            "severity": f.severity,
            "confidence": f.confidence,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "evidence": f.evidence,
            "description": f.description,
            "impact": f.impact,
            "remediation": f.remediation,
            "status": f.status,
            "detected_at": f.detected_at.isoformat() if f.detected_at else None,
            "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        }
        for f in findings
    ]


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter_by(id=finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    history = (
        db.query(FindingHistory)
        .filter_by(finding_id=finding.id)
        .order_by(FindingHistory.changed_at.asc())
        .all()
    )

    return {
        "finding_id": finding.id,
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "scanner": finding.scanner,
        "title": finding.title,
        "category": finding.category,
        "owasp_id": finding.owasp_id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "evidence": finding.evidence,
        "description": finding.description,
        "impact": finding.impact,
        "remediation": finding.remediation,
        "status": finding.status,
        "detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "history": [
            {
                "scan_id": h.scan_id,
                "from_status": h.from_status,
                "to_status": h.to_status,
                "changed_at": h.changed_at.isoformat() if h.changed_at else None,
            }
            for h in history
        ],
    }
