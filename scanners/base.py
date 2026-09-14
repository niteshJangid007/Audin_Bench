"""
Base class for all Scanner Adapters in Audit Bench.
Defines execution contract: scan(), parse(), normalize(), and validate().
"""
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from engine.models import RawFinding, Finding
from engine.normalizer import FindingNormalizer


class ScanExecutionResult(BaseModel):
    scanner_name: str
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_ms: int = 0
    warning: Optional[str] = None


class ScannerAdapter(ABC):
    name: str = "base"

    def __init__(self, timeout_seconds: int = 300):
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    def scan(self, workspace_path: str) -> ScanExecutionResult:
        """Executes the scanner against the target directory."""
        pass

    @abstractmethod
    def parse(self, raw_output: str, exit_code: int = 0) -> List[RawFinding]:
        """Parses the raw tool output into an intermediate list of RawFindings."""
        pass

    def normalize(self, raw_findings: List[RawFinding]) -> List[Finding]:
        """Converts raw findings into canonical Finding objects."""
        return FindingNormalizer.normalize_batch(raw_findings)

    @abstractmethod
    def validate(self) -> bool:
        """Checks if the scanner environment / dependencies are ready."""
        pass
