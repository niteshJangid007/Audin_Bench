"""
Repositories API Route.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel

from database.session import get_db
from database.models import Repository, Scan, GitHubInstallation
from engine.orchestrator import ScanOrchestrator

router = APIRouter()


class TriggerScanRequest(BaseModel):
    branch: Optional[str] = "main"
    commit_sha: Optional[str] = "HEAD"


@router.get("/repositories")
def list_repositories(db: Session = Depends(get_db)):
    repos = db.query(Repository).filter_by(is_active=True).all()
    results = []
    for r in repos:
        last_scan = (
            db.query(Scan)
            .filter_by(repository_id=r.id)
            .order_by(Scan.queued_at.desc())
            .first()
        )
        results.append({
            "id": r.id,
            "full_name": r.full_name,
            "default_branch": r.default_branch,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_scan": {
                "id": last_scan.id,
                "status": last_scan.status,
                "security_score": last_scan.security_score,
                "policy_result": last_scan.policy_result,
                "completed_at": last_scan.completed_at.isoformat() if last_scan.completed_at else None,
            } if last_scan else None,
        })
    return results


@router.get("/repositories/{repo_id}")
def get_repository(repo_id: str, db: Session = Depends(get_db)):
    repo = db.query(Repository).filter_by(id=repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    recent_scans = (
        db.query(Scan)
        .filter_by(repository_id=repo.id)
        .order_by(Scan.queued_at.desc())
        .limit(10)
        .all()
    )

    return {
        "id": repo.id,
        "full_name": repo.full_name,
        "default_branch": repo.default_branch,
        "created_at": repo.created_at.isoformat() if repo.created_at else None,
        "recent_scans": [
            {
                "id": s.id,
                "commit_sha": s.commit_sha,
                "status": s.status,
                "security_score": s.security_score,
                "policy_result": s.policy_result,
                "queued_at": s.queued_at.isoformat() if s.queued_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            }
            for s in recent_scans
        ],
    }


@router.post("/repositories/{repo_id}/scans", status_code=202)
def trigger_repository_scan(
    repo_id: str,
    req: TriggerScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    repo = db.query(Repository).filter_by(id=repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    new_scan = Scan(
        repository_id=repo.id,
        commit_sha=req.commit_sha or "HEAD",
        trigger="manual",
        status="QUEUED",
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # In production/local mode, run scan via orchestrator in background task
    def run_async_scan(scan_id: str, target_dir: str):
        from database.session import SessionLocal
        with SessionLocal() as session:
            orchestrator = ScanOrchestrator()
            orchestrator.execute_scan(
                scan_id=scan_id,
                workspace_path=target_dir,
                db=session,
            )

    # For manual triggers, target the workspace or fixture path
    workspace_dir = "."
    background_tasks.add_task(run_async_scan, new_scan.id, workspace_dir)

    return {
        "scan_id": new_scan.id,
        "status": "QUEUED",
        "repository": repo.full_name,
        "queued_at": new_scan.queued_at.isoformat(),
    }
