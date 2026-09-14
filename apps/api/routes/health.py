"""
Health Check & Telemetry Route.
"""
from fastapi import APIRouter
from datetime import datetime, timezone
from apps.api.config import get_settings

router = APIRouter()
settings = get_settings()


@router.get("/health")
def health_check():
    return {
        "status": "online",
        "service": "Audit Bench Security Gate API",
        "version": "1.0.0",
        "environment": settings.environment,
        "owasp_standard": "OWASP Top 10 (2021)",
        "active_rules": 13,
        "scanners": ["custom", "semgrep", "gitleaks", "trivy"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
