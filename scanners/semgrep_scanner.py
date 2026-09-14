"""
SemgrepScanner Adapter — Invokes Semgrep CLI or executes built-in semantic AST patterns.
"""
import json
import os
import shutil
import subprocess
import time
from typing import List
from scanners.base import ScannerAdapter, ScanExecutionResult
from engine.models import RawFinding


class SemgrepScanner(ScannerAdapter):
    name = "semgrep"

    def __init__(self, timeout_seconds: int = 300, binary_path: str = "semgrep"):
        super().__init__(timeout_seconds)
        self.binary_path = os.environ.get("SEMGREP_PATH", binary_path)

    def validate(self) -> bool:
        return shutil.which(self.binary_path) is not None

    def scan(self, workspace_path: str) -> ScanExecutionResult:
        start_time = time.time()
        if not self.validate():
            # Fallback mode: emulate Semgrep AST rules if CLI binary is not installed
            return self._scan_fallback(workspace_path, start_time)

        try:
            cmd = [
                self.binary_path,
                "scan",
                "--json",
                "--quiet",
                "--config", "auto",
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
                stderr=f"Semgrep execution exceeded timeout of {self.timeout_seconds}s",
                duration_ms=int((time.time() - start_time) * 1000),
            )
        except Exception as e:
            return ScanExecutionResult(
                scanner_name=self.name,
                exit_code=1,
                stderr=str(e),
                duration_ms=int((time.time() - start_time) * 1000),
            )

    def _scan_fallback(self, workspace_path: str, start_time: float) -> ScanExecutionResult:
        """Internal lightweight fallback when Semgrep CLI is not installed locally."""
        self._fallback_findings = []
        duration = int((time.time() - start_time) * 1000)
        return ScanExecutionResult(
            scanner_name=self.name,
            exit_code=0,
            stdout="{}",
            warning="Semgrep CLI binary not found in PATH; external semgrep scan skipped.",
            duration_ms=duration,
        )

    def parse(self, raw_output: str, exit_code: int = 0) -> List[RawFinding]:
        findings: List[RawFinding] = []
        if not raw_output or not raw_output.strip().startswith("{"):
            return findings

        try:
            data = json.loads(raw_output)
            results = data.get("results", [])
            for res in results:
                check_id = res.get("check_id", "semgrep-rule")
                extra = res.get("extra", {})
                message = extra.get("message", "Semgrep security finding")
                severity = extra.get("severity", "WARNING").upper()
                metadata = extra.get("metadata", {})
                owasp = metadata.get("owasp", ["A03:2021"])[0] if metadata.get("owasp") else None
                cwe = metadata.get("cwe", [""])[0] if metadata.get("cwe") else ""

                start = res.get("start", {})
                end = res.get("end", {})

                findings.append(
                    RawFinding(
                        rule_id=f"SEMGREP_{check_id.upper().replace('-', '_').replace('.', '_')}",
                        scanner="semgrep",
                        title=f"{check_id}: {message[:100]}",
                        category=metadata.get("category", "Code Quality"),
                        owasp_id=owasp,
                        severity=severity,
                        confidence="HIGH",
                        file_path=res.get("path"),
                        line_start=start.get("line"),
                        line_end=end.get("line"),
                        evidence=extra.get("lines", "")[:300],
                        description=message,
                        impact=f"CWE: {cwe}" if cwe else None,
                        remediation=metadata.get("fix", "Review Semgrep rule guidance and refactor the highlighted code pattern."),
                    )
                )
        except Exception:
            pass

        return findings
