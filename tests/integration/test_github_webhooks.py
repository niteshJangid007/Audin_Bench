"""
Integration tests for GitHub Webhooks and Signature Verification.
"""
import hmac
import hashlib
import json
from fastapi.testclient import TestClient
from apps.api.main import app
from apps.api.config import get_settings

client = TestClient(app)
settings = get_settings()


def compute_signature(payload_bytes: bytes, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def test_webhook_rejects_invalid_signature():
    payload = json.dumps({"zen": "Keep it logically awesome."}).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": "sha256=invalid_signature_hash_value_1234567890",
        "X-GitHub-Event": "ping",
        "Content-Type": "application/json",
    }
    resp = client.post("/api/v1/github/webhook", content=payload, headers=headers)
    assert resp.status_code == 401


def test_webhook_accepts_valid_ping():
    payload = json.dumps({"zen": "Keep it logically awesome."}).encode("utf-8")
    sig = compute_signature(payload, settings.github_webhook_secret)
    headers = {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "ping",
        "Content-Type": "application/json",
    }
    resp = client.post("/api/v1/github/webhook", content=payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "pong"


def test_webhook_enqueues_scan_on_push_event():
    push_payload = {
        "ref": "refs/heads/main",
        "after": "c0ffee123456789abcdef",
        "repository": {
            "id": 882001,
            "full_name": "acme/security-critical-app",
            "default_branch": "main",
        },
        "head_commit": {
            "id": "c0ffee123456789abcdef",
        },
    }
    payload_bytes = json.dumps(push_payload).encode("utf-8")
    sig = compute_signature(payload_bytes, settings.github_webhook_secret)

    headers = {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "push",
        "Content-Type": "application/json",
    }
    resp = client.post("/api/v1/github/webhook", content=payload_bytes, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "scan_enqueued"
    assert data["commit_sha"] == "c0ffee123456789abcdef"
