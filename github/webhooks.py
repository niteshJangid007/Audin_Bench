"""
GitHub Webhook Verification and Event Dispatcher.
Enforces HMAC-SHA256 signature verification and triggers asynchronous scan jobs.
"""
import hmac
import hashlib
import os
from typing import Dict, Any, Tuple
from sqlalchemy.orm import Session
from database.models import GitHubInstallation, Repository, Scan, Branch


def verify_webhook_signature(
    payload_bytes: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    """
    Verifies X-Hub-Signature-256 header using constant-time HMAC-SHA256 comparison.
    """
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_sig = signature_header[7:].strip()
    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    computed_sig = mac.hexdigest()

    return hmac.compare_digest(computed_sig, expected_sig)


def dispatch_webhook_event(
    event_type: str,
    payload: Dict[str, Any],
    db: Session,
) -> Dict[str, Any]:
    """
    Processes verified GitHub webhook events and creates required database records.
    """
    if event_type == "ping":
        return {"status": "pong", "zen": payload.get("zen")}

    if event_type == "installation":
        action = payload.get("action")
        inst_data = payload.get("installation", {})
        inst_id = inst_data.get("id")
        account = inst_data.get("account", {}).get("login", "unknown")

        if action in ("created", "added"):
            existing = db.query(GitHubInstallation).filter_by(github_installation_id=inst_id).first()
            if not existing:
                # Associate with default organization
                from database.models import Organization
                org = db.query(Organization).first()
                if org:
                    inst = GitHubInstallation(
                        organization_id=org.id,
                        github_installation_id=inst_id,
                        github_account_login=account,
                    )
                    db.add(inst)
                    db.commit()
            return {"status": "installation_registered", "installation_id": inst_id}

    elif event_type in ("push", "pull_request"):
        repo_data = payload.get("repository", {})
        full_name = repo_data.get("full_name")
        repo_id = repo_data.get("id")
        default_branch = repo_data.get("default_branch", "main")

        # Find or create repository
        repo = db.query(Repository).filter_by(github_repo_id=repo_id).first()
        if not repo:
            from database.models import Organization
            org = db.query(Organization).first()
            if not org:
                org = Organization(name="Default Organization")
                db.add(org)
                db.commit()
                db.refresh(org)

            inst = db.query(GitHubInstallation).first()
            if not inst:
                inst = GitHubInstallation(
                    organization_id=org.id,
                    github_installation_id=payload.get("installation", {}).get("id", 10001),
                    github_account_login=payload.get("repository", {}).get("owner", {}).get("login", "default-owner"),
                )
                db.add(inst)
                db.commit()
                db.refresh(inst)

            repo = Repository(
                installation_id=inst.id,
                github_repo_id=repo_id,
                full_name=full_name,
                default_branch=default_branch,
            )
            db.add(repo)
            db.commit()
            db.refresh(repo)

        if not repo:
            return {"status": "ignored", "reason": "Repository not tracked by installation"}

        # Extract commit SHA and branch
        commit_sha = ""
        branch_name = default_branch

        if event_type == "push":
            commit_sha = payload.get("after") or payload.get("head_commit", {}).get("id", "00000000")
            ref = payload.get("ref", "")
            if ref.startswith("refs/heads/"):
                branch_name = ref[11:]
        elif event_type == "pull_request":
            pr_data = payload.get("pull_request", {})
            commit_sha = pr_data.get("head", {}).get("sha", "00000000")
            branch_name = pr_data.get("head", {}).get("ref", default_branch)

        # Enqueue new Scan record
        new_scan = Scan(
            repository_id=repo.id,
            commit_sha=commit_sha,
            trigger=event_type,
            status="QUEUED",
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)

        return {
            "status": "scan_enqueued",
            "scan_id": new_scan.id,
            "repository": full_name,
            "commit_sha": commit_sha,
            "branch": branch_name,
        }

    return {"status": "unhandled_event", "event_type": event_type}
