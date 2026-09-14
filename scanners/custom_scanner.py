"""
CustomRuleScanner Adapter — Executes Audit Bench's deterministic OWASP Top 10 rule engine.
"""
import os
import time
from typing import List
from scanners.base import ScannerAdapter, ScanExecutionResult
from engine.models import RawFinding
from engine.rule_engine import RuleEngine

ALLOWED_EXTENSIONS = {
    ".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".rb", ".go", ".java",
    ".cs", ".sql", ".html", ".vue", ".svelte", ".json", ".yml", ".yaml",
    ".env", ".config", ".sh",
}

IGNORED_DIRS = {
    "node_modules", "vendor", ".git", "dist", "build", "__pycache__",
    "venv", ".venv", "target", ".idea", ".vscode",
}

MAX_FILE_BYTES = 500 * 1024  # 500 KB per file


class CustomRuleScanner(ScannerAdapter):
    name = "custom"

    def __init__(self, timeout_seconds: int = 120):
        super().__init__(timeout_seconds)
        self.engine = RuleEngine()

    def validate(self) -> bool:
        return True

    def scan(self, workspace_path: str) -> ScanExecutionResult:
        start_time = time.time()
        findings: List[RawFinding] = []

        if not os.path.exists(workspace_path):
            return ScanExecutionResult(
                scanner_name=self.name,
                exit_code=1,
                stderr=f"Workspace path does not exist: {workspace_path}",
                duration_ms=0,
            )

        try:
            for root, dirs, files in os.walk(workspace_path):
                # Filter out ignored directories in-place
                dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext not in ALLOWED_EXTENSIONS and file.lower() != ".env":
                        continue

                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, workspace_path)

                    try:
                        if os.path.getsize(full_path) > MAX_FILE_BYTES:
                            continue

                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        file_findings = self.engine.scan_content(content, file_path=rel_path)
                        findings.extend(file_findings)
                    except Exception as fe:
                        # Log and continue other files
                        continue

            duration = int((time.time() - start_time) * 1000)
            self._cached_findings = findings

            return ScanExecutionResult(
                scanner_name=self.name,
                exit_code=0,
                stdout=f"Scanned successfully. Found {len(findings)} issues.",
                duration_ms=duration,
            )
        except Exception as e:
            return ScanExecutionResult(
                scanner_name=self.name,
                exit_code=1,
                stderr=str(e),
                duration_ms=int((time.time() - start_time) * 1000),
            )

    def parse(self, raw_output: str, exit_code: int = 0) -> List[RawFinding]:
        if hasattr(self, "_cached_findings"):
            return self._cached_findings
        return []
