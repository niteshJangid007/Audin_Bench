"""
Scans API Route.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database.session import get_db
from database.models import Scan, Finding, ScanFinding

router = APIRouter()


@router.get("/scans")
def list_scans(
    repository_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    query = db.query(Scan)
    if repository_id:
        query = query.filter(Scan.repository_id == repository_id)
    if status:
        query = query.filter(Scan.status == status)

    scans = query.order_by(Scan.queued_at.desc()).limit(limit).all()

    return [
        {
            "id": s.id,
            "repository_id": s.repository_id,
            "commit_sha": s.commit_sha,
            "trigger": s.trigger,
            "status": s.status,
            "security_score": s.security_score,
            "policy_result": s.policy_result,
            "summary": s.summary,
            "queued_at": s.queued_at.isoformat() if s.queued_at else None,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = (
        db.query(Finding)
        .join(ScanFinding, ScanFinding.finding_id == Finding.id)
        .filter(ScanFinding.scan_id == scan.id)
        .all()
    )

    return {
        "id": scan.id,
        "repository_id": scan.repository_id,
        "commit_sha": scan.commit_sha,
        "trigger": scan.trigger,
        "status": scan.status,
        "security_score": scan.security_score,
        "policy_result": scan.policy_result,
        "summary": scan.summary,
        "owasp_breakdown": scan.owasp_breakdown,
        "error_detail": scan.error_detail,
        "queued_at": scan.queued_at.isoformat() if scan.queued_at else None,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "findings_count": len(findings),
    }


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in ("COMPLETED", "FAILED", "CANCELLED"):
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan with status {scan.status}")

    scan.status = "CANCELLED"
    db.commit()

    return {"status": "CANCELLED", "scan_id": scan.id}
