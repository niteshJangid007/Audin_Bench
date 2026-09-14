# Audit Bench — Scanner Adapters & Orchestration

## 1. Scanner Adapter Contract

Every scanner integrated into Audit Bench adheres to the `ScannerAdapter` abstract base interface. This enforces consistent execution, error trapping, output normalization, and validation across all engines.

```python
class ScannerAdapter(ABC):
    name: str  # "semgrep" | "trivy" | "gitleaks" | "custom"

    @abstractmethod
    def scan(self, workspace_path: str) -> ScanExecutionResult:
        """Executes the tool or engine in a contained environment."""

    @abstractmethod
    def parse(self, raw_output: str, exit_code: int) -> list[RawFinding]:
        """Parses native tool output into an intermediate RawFinding list."""

    @abstractmethod
    def normalize(self, raw_findings: list[RawFinding]) -> list[Finding]:
        """Normalizes raw findings into canonical Audit Bench Finding objects."""

    @abstractmethod
    def validate(self) -> bool:
        """Verifies tool availability and environment readiness."""
```

---

## 2. Integrated Scanners

| Scanner | Target Area | Detection Mechanism | Native Output |
|---|---|---|---|
| **CustomRuleScanner** | OWASP Top 10 | Deterministic regex and lexical pattern engine | Structured JSON |
| **SemgrepScanner** | Code Flaws & Anti-patterns | Abstract Syntax Tree (AST) pattern matching | SARIF / JSON |
| **GitleaksScanner** | Secrets & Tokens | Entropy analysis and regex pattern matching | JSON |
| **TrivyScanner** | Dependencies & Misconfigurations | Software Composition Analysis (SCA) | JSON |

---

## 3. Fault Isolation & Partial Failure Policy

- **No Single Point of Failure**: If an individual scanner crashes or times out (e.g., Trivy experiences an index lock or Semgrep encounters an unsupported syntax file), the orchestrator logs the incident in `error_detail.warnings`.
- **Continued Execution**: The remaining scanners complete their jobs, their findings are normalized and persisted, and the scan status transitions to `COMPLETED` with partial coverage noted in the scan report.
- A scan is marked `FAILED` only if repository acquisition fails or the database transaction cannot be committed.

---

## 4. Normalization Pipeline

```
[Raw Tool Output]
        │
        ▼
[parse() -> RawFinding]
        │
        ▼
[normalize() -> Finding]
   - Map severity to {CRITICAL, HIGH, MEDIUM, LOW}
   - Map confidence to {HIGH, MEDIUM, LOW}
   - Associate OWASP Top 10 Category (A01:2021 - A10:2021)
   - Compute deterministic SHA-256 fingerprint
   - Provide concrete remediation code / guidance
```
