"""
Integration test for ScanOrchestrator pipeline and verification re-scan.
Demonstrates:
Scan -> Findings -> Dedupe -> Score -> Policy Fail -> Fix -> Re-scan -> Resolved -> Pass.
"""
import os
import shutil
import tempfile
import pytest
from engine.orchestrator import ScanOrchestrator
from engine.models import SecurityPolicyDefinition
from database.session import SessionLocal, init_db
from database.models import Organization, Repository, Scan, GitHubInstallation


@pytest.fixture(scope="module")
def setup_db():
    init_db()
    with SessionLocal() as db:
        org = db.query(Organization).first()
        if not org:
            org = Organization(name="Test Org")
            db.add(org)
            db.commit()

        inst = db.query(GitHubInstallation).first()
        if not inst:
            inst = GitHubInstallation(
                organization_id=org.id,
                github_installation_id=99999,
                github_account_login="test-org",
            )
            db.add(inst)
            db.commit()

        repo = db.query(Repository).filter_by(full_name="test-org/vuln-service").first()
        if not repo:
            repo = Repository(
                installation_id=inst.id,
                github_repo_id=123456,
                full_name="test-org/vuln-service",
            )
            db.add(repo)
            db.commit()
            db.refresh(repo)

        yield repo.id


def test_orchestrator_end_to_end_lifecycle(setup_db):
    repo_id = setup_db
    orchestrator = ScanOrchestrator()

    # Step 1: Create a temporary vulnerable workspace
    tmp_workspace = tempfile.mkdtemp()
    try:
        fixture_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures", "vulnerable_repo")
        for item in os.listdir(fixture_dir):
            s = os.path.join(fixture_dir, item)
            d = os.path.join(tmp_workspace, item)
            if os.path.isfile(s):
                shutil.copy2(s, d)

        # Create Scan 1 in DB
        with SessionLocal() as db:
            scan1 = Scan(
                repository_id=repo_id,
                commit_sha="commit_sha_vuln_1",
                trigger="push",
                status="QUEUED",
            )
            db.add(scan1)
            db.commit()
            db.refresh(scan1)
            scan1_id = scan1.id

        # Execute Scan 1 on vulnerable code
        with SessionLocal() as db:
            result1 = orchestrator.execute_scan(
                scan_id=scan1_id,
                workspace_path=tmp_workspace,
                db=db,
                policy_definition=SecurityPolicyDefinition(minimum_score=75, fail_on_critical=True),
            )

        assert result1.status == "COMPLETED"
        assert result1.score < 75  # Multiple critical findings deduct points
        assert result1.policy_result == "FAIL"
        assert len(result1.violations) > 0
        assert any(f.status in ("OPEN", "REOPENED") for f in result1.findings)
        assert any(f.severity == "CRITICAL" for f in result1.findings)

        # Step 2: Remediate the code in workspace (fix SQLi, XSS, secrets)
        with open(os.path.join(tmp_workspace, "vulnerable_sql.py"), "w") as f:
            f.write("# Safe parameterized query\ndef get_user_profile(uid):\n    return db.query('SELECT * FROM users WHERE id = $1', [uid])\n")

        with open(os.path.join(tmp_workspace, "vulnerable_xss.js"), "w") as f:
            f.write("// Safe textContent\nfunction renderUserProfile(u) {\n    document.getElementById('profile').textContent = u.name;\n}\n")

        with open(os.path.join(tmp_workspace, "vulnerable_crypto.py"), "w") as f:
            f.write("# Safe password hashing\ndef hash_user_password(pwd):\n    return argon2.hash(pwd)\n")

        with open(os.path.join(tmp_workspace, "vulnerable_ssrf.js"), "w") as f:
            f.write("// Safe fetch\nasync function fetchWebhook(req, res) {\n    res.json({ status: 'ok' });\n}\n")

        with open(os.path.join(tmp_workspace, "vulnerable_access.py"), "w") as f:
            f.write("# Safe path handling\ndef read_invoice_document(r):\n    return 'safe_invoice'\n")

        if os.path.exists(os.path.join(tmp_workspace, "package.json")):
            os.remove(os.path.join(tmp_workspace, "package.json"))

        # Create Scan 2 in DB
        with SessionLocal() as db:
            scan2 = Scan(
                repository_id=repo_id,
                commit_sha="commit_sha_remediated_2",
                trigger="push",
                status="QUEUED",
            )
            db.add(scan2)
            db.commit()
            db.refresh(scan2)
            scan2_id = scan2.id

        # Execute Scan 2 on remediated code
        with SessionLocal() as db:
            result2 = orchestrator.execute_scan(
                scan_id=scan2_id,
                workspace_path=tmp_workspace,
                db=db,
                policy_definition=SecurityPolicyDefinition(minimum_score=75, fail_on_critical=True),
            )

        assert result2.status == "COMPLETED"
        assert result2.score == 100  # All issues fixed!
        assert result2.policy_result == "PASS"
        assert len(result2.violations) == 0

        # Verify that previously open findings transitioned to RESOLVED
        resolved_findings = [f for f in result2.findings if f.status == "RESOLVED"]
        assert len(resolved_findings) > 0

    finally:
        shutil.rmtree(tmp_workspace, ignore_errors=True)
