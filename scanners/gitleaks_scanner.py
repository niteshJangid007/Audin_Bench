"""
GitleaksScanner Adapter — Detects hardcoded secrets, API keys, and credentials.
Invokes Gitleaks CLI if available, or executes high-entropy secret detection patterns.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import List
from scanners.base import ScannerAdapter, ScanExecutionResult
from engine.models import RawFinding

SECRET_PATTERNS = [
    ("GITLEAKS_AWS_KEY", r"AKIA[0-9A-Z]{16}", "AWS Access Key ID exposed"),
    ("GITLEAKS_GITHUB_TOKEN", r"(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
    ("GITLEAKS_SLACK_TOKEN", r"xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]+", "Slack Token exposed"),
    ("GITLEAKS_PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Cryptographic Key exposed"),
    ("GITLEAKS_STRIPE_KEY", r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live API Key exposed"),
    ("GITLEAKS_JWT_TOKEN", r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}", "Hardcoded JSON Web Token"),
]


class GitleaksScanner(ScannerAdapter):
    name = "gitleaks"

    def __init__(self, timeout_seconds: int = 180, binary_path: str = "gitleaks"):
        super().__init__(timeout_seconds)
        self.binary_path = os.environ.get("GITLEAKS_PATH", binary_path)

    def validate(self) -> bool:
        return shutil.which(self.binary_path) is not None

    def scan(self, workspace_path: str) -> ScanExecutionResult:
        start_time = time.time()
        if not self.validate():
            return self._scan_fallback(workspace_path, start_time)

        report_file = os.path.join(tempfile.gettempdir(), f"gitleaks_rep_{int(time.time())}.json")
        try:
            cmd = [
                self.binary_path,
                "detect",
                "--no-git",
                "--report-format", "json",
                "--report-path", report_file,
                "--source", workspace_path,
                "--exit-code", "0",
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )

            raw_json = "[]"
            if os.path.exists(report_file):
                with open(report_file, "r", encoding="utf-8") as rf:
                    raw_json = rf.read()
                os.remove(report_file)

            duration = int((time.time() - start_time) * 1000)
            return ScanExecutionResult(
                scanner_name=self.name,
                exit_code=proc.returncode,
                stdout=raw_json,
                stderr=proc.stderr,
                duration_ms=duration,
            )
        except subprocess.TimeoutExpired:
            return ScanExecutionResult(
                scanner_name=self.name,
                exit_code=124,
                timed_out=True,
                stderr=f"Gitleaks timeout after {self.timeout_seconds}s",
                duration_ms=int((time.time() - start_time) * 1000),
            )
        except Exception as e:
            return self._scan_fallback(workspace_path, start_time)

    def _scan_fallback(self, workspace_path: str, start_time: float) -> ScanExecutionResult:
        """High-entropy secret scanner fallback when Gitleaks binary is not installed."""
        findings: List[RawFinding] = []
        compiled = [(rule_id, re.compile(pat), desc) for rule_id, pat, desc in SECRET_PATTERNS]

        ignored = {"node_modules", ".git", "venv", "dist", "build"}
        for root, dirs, files in os.walk(workspace_path):
            dirs[:] = [d for d in dirs if d not in ignored]
            for file in files:
                if file.endswith((".png", ".jpg", ".zip", ".tar", ".gz", ".exe")):
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, workspace_path)

                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()

                    for line_idx, line in enumerate(lines):
                        for rule_id, regex, desc in compiled:
                            match = regex.search(line)
                            if match:
                                findings.append(
                                    RawFinding(
                                        rule_id=rule_id,
                                        scanner="gitleaks",
                                        title=f"Hardcoded Secret Detected: {desc}",
                                        category="Cryptographic Failures",
                                        owasp_id="A02:2021",
                                        severity="CRITICAL",
                                        confidence="HIGH",
                                        file_path=rel_path,
                                        line_start=line_idx + 1,
                                        line_end=line_idx + 1,
                                        evidence=f"Matched secret pattern: {match.group()[:4]}...[REDACTED]",
                                        description=f"{desc}. Secrets committed into version control are permanently exposed.",
                                        impact="Unauthorized account access, infrastructure takeover, or data breach.",
                                        remediation="Revoke exposed credentials immediately and inject via environment variables.",
                                    )
                                )
                except Exception:
                    continue

        duration = int((time.time() - start_time) * 1000)
        self._fallback_findings = findings
        return ScanExecutionResult(
            scanner_name=self.name,
            exit_code=0,
            stdout=json.dumps([f.model_dump() for f in findings]),
            duration_ms=duration,
        )

    def parse(self, raw_output: str, exit_code: int = 0) -> List[RawFinding]:
        findings: List[RawFinding] = []
        if hasattr(self, "_fallback_findings") and self._fallback_findings:
            return self._fallback_findings

        if not raw_output or not raw_output.strip().startswith("["):
            return findings

        try:
            items = json.loads(raw_output)
            for item in items:
                # Distinguish serialized RawFinding vs Gitleaks native report
                if "rule_id" in item:
                    findings.append(RawFinding(**item))
                else:
                    rule_id = f"GITLEAKS_{item.get('RuleID', 'SECRET').upper()}"
                    findings.append(
                        RawFinding(
                            rule_id=rule_id,
                            scanner="gitleaks",
                            title=f"Exposed Secret: {item.get('Description', 'Secret detected')}",
                            category="Cryptographic Failures",
                            owasp_id="A02:2021",
                            severity="CRITICAL",
                            confidence="HIGH",
                            file_path=item.get("File"),
                            line_start=item.get("StartLine"),
                            line_end=item.get("EndLine"),
                            evidence=item.get("Match", "")[:100],
                            description=item.get("Description", "Hardcoded credential detected by Gitleaks."),
                            impact="Credential leakage allowing unauthorized access to integrated services.",
                            remediation="Immediately revoke and rotate the secret, and remove it from git history.",
                        )
                    )
        except Exception:
            pass

        return findings
