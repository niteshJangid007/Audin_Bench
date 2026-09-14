"""
GitHub Webhook and App Integration Route.
"""
from fastapi import APIRouter, Request, Header, HTTPException, Depends
from sqlalchemy.orm import Session
from database.session import get_db
from database.models import GitHubInstallation, Organization
from github.webhooks import verify_webhook_signature, dispatch_webhook_event
from apps.api.config import get_settings
from pydantic import BaseModel

router = APIRouter()
settings = get_settings()


class InstallRequest(BaseModel):
    installation_id: int
    account_login: str = "auditbench-org"


@router.get("/github/status")
def get_github_status(db: Session = Depends(get_db)):
    installation = db.query(GitHubInstallation).first()
    return {
        "configured": bool(settings.github_app_id and settings.github_webhook_secret),
        "app_id": settings.github_app_id,
        "connected_installation": {
            "id": installation.github_installation_id,
            "account": installation.github_account_login,
            "installed_at": installation.installed_at.isoformat(),
        } if installation else None,
    }


@router.post("/github/install", status_code=201)
def install_github_app(req: InstallRequest, db: Session = Depends(get_db)):
    org = db.query(Organization).first()
    if not org:
        raise HTTPException(status_code=400, detail="Organization not initialized")

    existing = db.query(GitHubInstallation).filter_by(github_installation_id=req.installation_id).first()
    if not existing:
        existing = GitHubInstallation(
            organization_id=org.id,
            github_installation_id=req.installation_id,
            github_account_login=req.account_login,
        )
        db.add(existing)
        db.commit()
        db.refresh(existing)

    return {
        "status": "connected",
        "installation_id": existing.github_installation_id,
        "account": existing.github_account_login,
    }


@router.post("/github/webhook")
async def handle_github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header("ping"),
    db: Session = Depends(get_db),
):
    body_bytes = await request.body()

    # Verify HMAC-SHA256 signature
    secret = settings.github_webhook_secret
    if secret:
        is_valid = verify_webhook_signature(
            payload_bytes=body_bytes,
            signature_header=x_hub_signature_256 or "",
            secret=secret,
        )
        if not is_valid:
            raise HTTPException(status_code=401, detail="Invalid HMAC-SHA256 webhook signature")

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    result = dispatch_webhook_event(
        event_type=x_github_event,
        payload=payload,
        db=db,
    )

    return result
