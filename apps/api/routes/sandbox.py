"""
Sandbox API Route — Interactive developer snippet testing and triage workbench.
Retains and enhances the interactive testing experience from the original Audit Bench.
"""
import ipaddress
import socket
import urllib.parse
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import httpx

from engine.rule_engine import RuleEngine
from engine.normalizer import FindingNormalizer
from engine.score_engine import ScoreEngine
from engine.policy_engine import PolicyEngine

router = APIRouter()
engine = RuleEngine()


class SnippetScanRequest(BaseModel):
    code: str = Field(..., max_length=500_000)
    language: Optional[str] = "auto"


class UrlScanRequest(BaseModel):
    url: str


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )
    except ValueError:
        return True


@router.post("/scan/snippet")
def scan_code_snippet(req: SnippetScanRequest):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Field 'code' cannot be empty.")

    detected_lang = (
        RuleEngine.detect_language(req.code)
        if req.language == "auto" or not req.language
        else req.language
    )

    raw_findings = engine.scan_content(req.code, file_path="snippet.txt")
    normalized = FindingNormalizer.normalize_batch(raw_findings)
    score = ScoreEngine.compute_score(normalized)
    policy_eval = PolicyEngine.evaluate(score=score, findings=normalized)

    owasp_breakdown = {}
    for f in normalized:
        cat = f.owasp_id or "Unclassified"
        owasp_breakdown[cat] = owasp_breakdown.get(cat, 0) + 1

    return {
        "status": "COMPLETED",
        "language": detected_lang,
        "security_score": score,
        "policy_result": policy_eval.policy_result,
        "violations": policy_eval.violations,
        "summary": {
            "critical": sum(1 for f in normalized if f.severity == "CRITICAL"),
            "high": sum(1 for f in normalized if f.severity == "HIGH"),
            "medium": sum(1 for f in normalized if f.severity == "MEDIUM"),
            "low": sum(1 for f in normalized if f.severity == "LOW"),
            "total": len(normalized),
        },
        "owasp_breakdown": owasp_breakdown,
        "findings": [f.model_dump() for f in normalized],
    }


@router.post("/scan/url")
async def scan_external_url(req: UrlScanRequest):
    """SSRF-protected endpoint to audit public endpoints."""
    url = req.url.strip()
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only http and https protocols are supported.")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid target URL.")

    # DNS pre-resolution and private CIDR defense
    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
        ip_addresses = [info[4][0] for info in resolved_ips]
    except Exception as ex:
        raise HTTPException(status_code=400, detail=f"DNS resolution failed for {hostname}: {str(ex)}")

    for ip in ip_addresses:
        if is_private_ip(ip):
            raise HTTPException(
                status_code=400,
                detail=f"SSRF Protection: Direct connection to private/reserved IP '{ip}' is blocked.",
            )

    # Fetch safe content with timeout and size cap
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            resp = await client.get(url, headers={"User-Agent": "AuditBenchSecurityScanner/1.0"})
            content = resp.text[:500_000]

            raw_findings = engine.scan_content(content, file_path=url)
            normalized = FindingNormalizer.normalize_batch(raw_findings)
            score = ScoreEngine.compute_score(normalized)

            return {
                "url": url,
                "status_code": resp.status_code,
                "security_score": score,
                "findings": [f.model_dump() for f in normalized],
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch URL safely: {str(e)}")
