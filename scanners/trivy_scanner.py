"""
TrivyScanner Adapter — Software Composition Analysis (SCA) and Vulnerability Detector.
Invokes Trivy CLI if installed, or runs built-in package manifest dependency auditor.
"""
import json
import os
import re
import shutil
import subprocess
import time
from typing import List, Dict, Any
from scanners.base import ScannerAdapter, ScanExecutionResult
from engine.models import RawFinding

KNOWN_VULNERABLE_PACKAGES: Dict[str, Dict[str, Any]] = {
    # JavaScript / Node.js
    "lodash": {"cve": "CVE-2021-23337", "fixed": "4.17.21", "severity": "HIGH", "desc": "Command Injection in lodash template function"},
    "axios": {"cve": "CVE-2023-45857", "fixed": "1.6.0", "severity": "HIGH", "desc": "Cross-Site Request Forgery / SSRF in Axios"},
    "jsonwebtoken": {"cve": "CVE-2022-23529", "fixed": "9.0.0", "severity": "CRITICAL", "desc": "Remote Code Execution via crafted secret"},
    "express": {"cve": "CVE-2024-29041", "fixed": "4.19.2", "severity": "MEDIUM", "desc": "Open redirect vulnerability in express router"},
    # Python
    "requests": {"cve": "CVE-2023-32681", "fixed": "2.31.0", "severity": "MEDIUM", "desc": "Proxy-Authorization header leakage on redirect"},
    "flask": {"cve": "CVE-2023-30861", "fixed": "2.3.2", "severity": "HIGH", "desc": "Session cookie disclosure under certain configurations"},
    "urllib3": {"cve": "CVE-2023-45803", "fixed": "2.0.7", "severity": "HIGH", "desc": "Request body not stripped after 303 redirect"},
    "django": {"cve": "CVE-2023-41164", "fixed": "4.2.5", "severity": "CRITICAL", "desc": "Denial of service in django.utils.encoding.uri_to_iri"},
}


class TrivyScanner(ScannerAdapter):
    name = "trivy"

    def __init__(self, timeout_seconds: int = 300, binary_path: str = "trivy"):
        super().__init__(timeout_seconds)
        self.binary_path = os.environ.get("TRIVY_PATH", binary_path)

    def validate(self) -> bool:
        return shutil.which(self.binary_path) is not None

    def scan(self, workspace_path: str) -> ScanExecutionResult:
        start_time = time.time()
        if not self.validate():
            return self._scan_fallback(workspace_path, start_time)

        try:
            cmd = [
                self.binary_path,
                "fs",
                "--format", "json",
                "--quiet",
                workspace_path,
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            duration = int((time.time() - start_time) * 1000)
            return ScanExecutionResult(
                scanner_name=self.name,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=duration,
            )
        except subprocess.TimeoutExpired:
            return ScanExecutionResult(
                scanner_name=self.name,
                exit_code=124,
                timed_out=True,
                stderr=f"Trivy scan timed out after {self.timeout_seconds}s",
                duration_ms=int((time.time() - start_time) * 1000),
            )
        except Exception as e:
            return self._scan_fallback(workspace_path, start_time)

    def _scan_fallback(self, workspace_path: str, start_time: float) -> ScanExecutionResult:
        """SCA dependency manifest auditor fallback when Trivy binary is not installed."""
        findings: List[RawFinding] = []

        # 1. Scan package.json
        pkg_json_path = os.path.join(workspace_path, "package.json")
        if os.path.exists(pkg_json_path):
            try:
                with open(pkg_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for dep_name, version in deps.items():
                    clean_name = dep_name.lower().strip()
                    if clean_name in KNOWN_VULNERABLE_PACKAGES:
                        info = KNOWN_VULNERABLE_PACKAGES[clean_name]
                        findings.append(
                            RawFinding(
                                rule_id=f"TRIVY_SCA_{clean_name.upper()}",
                                scanner="trivy",
                                title=f"Vulnerable Dependency: {dep_name} ({info['cve']})",
                                category="Vulnerable and Outdated Components",
                                owasp_id="A06:2021",
                                severity=info["severity"],
                                confidence="HIGH",
                                file_path="package.json",
                                line_start=1,
                                line_end=1,
                                evidence=f'"{dep_name}": "{version}"',
                                description=f"{info['desc']}. Affected library {dep_name} version {version} contains known security flaw {info['cve']}.",
                                impact="Exploitation of known CVE in third-party supply chain component.",
                                remediation=f"Upgrade {dep_name} to version {info['fixed']} or newer.",
                            )
                        )
            except Exception:
                pass

        # 2. Scan requirements.txt
        req_txt_path = os.path.join(workspace_path, "requirements.txt")
        if os.path.exists(req_txt_path):
            try:
                with open(req_txt_path, "r", encoding="utf-8") as f:
                    for line_num, line in enumerate(f, start=1):
                        parts = re.split(r"[=<>~]", line.strip())
                        if parts:
                            pkg_name = parts[0].strip().lower()
                            if pkg_name in KNOWN_VULNERABLE_PACKAGES:
                                info = KNOWN_VULNERABLE_PACKAGES[pkg_name]
                                findings.append(
                                    RawFinding(
                                        rule_id=f"TRIVY_SCA_{pkg_name.upper()}",
                                        scanner="trivy",
                                        title=f"Vulnerable Dependency: {pkg_name} ({info['cve']})",
                                        category="Vulnerable and Outdated Components",
                                        owasp_id="A06:2021",
                                        severity=info["severity"],
                                        confidence="HIGH",
                                        file_path="requirements.txt",
                                        line_start=line_num,
                                        line_end=line_num,
                                        evidence=line.strip(),
                                        description=f"{info['desc']} ({info['cve']}).",
                                        impact="Exploitation of known vulnerability in Python dependency.",
                                        remediation=f"Upgrade {pkg_name} to >= {info['fixed']}.",
                                    )
                                )
            except Exception:
                pass

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

        if not raw_output or not raw_output.strip().startswith(("{", "[")):
            return findings

        try:
            data = json.loads(raw_output)
            # Trivy JSON structure: { "Results": [ { "Target": ..., "Vulnerabilities": [...] } ] }
            results = data.get("Results", []) if isinstance(data, dict) else []
            for target_res in results:
                target_file = target_res.get("Target", "manifest")
                vulns = target_res.get("Vulnerabilities", [])
                for v in vulns:
                    cve_id = v.get("VulnerabilityID", "CVE-UNKNOWN")
                    pkg_name = v.get("PkgName", "dependency")
                    sev = v.get("Severity", "MEDIUM").upper()
                    findings.append(
                        RawFinding(
                            rule_id=f"TRIVY_{cve_id.replace('-', '_').upper()}",
                            scanner="trivy",
                            title=f"Dependency Vulnerability: {pkg_name} ({cve_id})",
                            category="Vulnerable and Outdated Components",
                            owasp_id="A06:2021",
                            severity=sev,
                            confidence="HIGH",
                            file_path=target_file,
                            line_start=1,
                            line_end=1,
                            evidence=f"Package: {pkg_name} Installed: {v.get('InstalledVersion')} Fixed: {v.get('FixedVersion')}",
                            description=v.get("Title", v.get("Description", "Known CVE in component")),
                            impact="Component contains known unpatched vulnerability.",
                            remediation=f"Upgrade {pkg_name} to {v.get('FixedVersion', 'latest safe release')}.",
                        )
                    )
        except Exception:
            pass

        return findings
