"""
Integration tests for FastAPI REST Endpoints.
Verifies API contracts for /repositories, /scans, /findings, /policies, and /scan/snippet.
"""
from fastapi.testclient import TestClient
from apps.api.main import app

client = TestClient(app)


def test_api_health():
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "online"
    assert data["active_rules"] == 13


def test_api_list_repositories():
    resp = client.get("/api/v1/repositories")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_list_policies():
    resp = client.get("/api/v1/policies")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) > 0
    assert "definition" in data[0]


def test_api_create_and_update_policy():
    create_payload = {
        "name": "Integration Test Gate Policy",
        "definition": {
            "minimum_score": 85,
            "fail_on_critical": True,
            "max_high": 1,
            "max_medium": 5,
            "max_low": 10,
            "fail_on_secrets": True,
            "fail_on_new_findings": True,
        },
    }
    resp = client.post("/api/v1/policies", json=create_payload)
    assert resp.status_code == 201
    policy_id = resp.json()["id"]

    # Update policy
    update_payload = {"name": "Updated Test Gate Policy"}
    update_resp = client.put(f"/api/v1/policies/{policy_id}", json=update_payload)
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "updated"


def test_api_scan_snippet():
    snippet = {
        "code": "const query = 'SELECT * FROM users WHERE id = ' + req.body.id;",
        "language": "javascript",
    }
    resp = client.post("/api/v1/scan/snippet", json=snippet)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "COMPLETED"
    assert data["security_score"] < 100
    assert data["summary"]["critical"] >= 1
    assert any(f["rule_id"] == "RULE_A03_SQL_CONCAT" for f in data["findings"])
