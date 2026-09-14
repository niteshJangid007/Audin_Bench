# Audit Bench — Architecture

## 1. Purpose

Audit Bench is a production-grade DevSecOps security orchestration and verification platform. It audits code repositories for vulnerabilities, supply-chain risks, hardcoded secrets, and misconfigurations, enforcing policy merge gates before deployment. GitHub acts purely as an integration boundary — all security analysis, classification, risk scoring, and pass/fail gate decisions are executed deterministically inside Audit Bench.

---

## 2. Core Architectural Principles

- **Deterministic & Explainable**: Detection relies on established static analysis tooling (Semgrep, Trivy, Gitleaks) and a custom deterministic rule engine. No non-deterministic generative models participate in the security evaluation runtime.
- **Scanner Orchestration**: Scanners are wrapped behind a uniform adapter interface (`ScannerAdapter`). Scanner failures are isolated and never crash the orchestrator or API.
- **Zero Execution of Untrusted Code on API Server**: Repository files are acquired safely via archive tarballs and scanned in isolated worker processes/containers with strict timeouts, non-root privileges, and resource limits.
- **Defense in Depth**: API enforces strict input validation, SSRF DNS pinning and CIDR blocking, zip-slip defense, zip-bomb pre-decompression ratio checks, and HMAC-SHA256 signature verification for webhooks.
- **Clean Separation of Concerns**: Downstream engines and UI consume only the normalized `Finding` model. Scanner-native schemas (SARIF, JSON) never leak beyond the normalizer boundary.

---

## 3. High-Level System Topology

```
┌────────────────────────────────────────────────────────────────────────┐
│                          GitHub Ecosystem                              │
│   (Developer Commits / Pull Requests / App Installation / Check Runs)  │
└─────────────────────────────────┬──────────────────────────────────────┘
                                  │
                       Webhook (HMAC-SHA256)
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        apps/api (FastAPI Core)                         │
│  - GitHubIntegrationService (HMAC verification, installation auth)     │
│  - RepositoryService (Safe archive ingestion without git hooks)        │
│  - ScanService (Lifecycle state machine: QUEUED/RUNNING/COMPLETED)     │
│  - REST API Routes (/repositories, /scans, /findings, /policies)       │
└───────────────────┬───────────────────────────────┬────────────────────┘
                    │                               │
            Database Transaction           Dispatch / Run Task
                    │                               │
                    ▼                               ▼
┌───────────────────────────────┐   ┌────────────────────────────────────┐
│      database (PostgreSQL)    │   │       engine / ScanOrchestrator    │
│  - Organizations & Users      │   │  - Scanner Orchestration Pipeline  │
│  - Repositories & Branches    │   │  - FindingNormalizer               │
│  - Scans & Findings           │   │  - RuleEngine (13 OWASP Rules)     │
│  - ScanFindings & History     │   │  - OWASPMapper (A01-A10 2021)      │
│  - SecurityPolicies & Rules   │   │  - SeverityEngine & RiskEngine     │
└───────────────────────────────┘   │  - ScoreEngine (Base-100 Deduction)│
                                    │  - PolicyEngine (Gate Evaluation)  │
                                    │  - VerificationEngine (Re-scan)    │
                                    └─────────────────┬──────────────────┘
                                                      │
                                    ┌─────────────────┴──────────────────┐
                                    ▼                                    ▼
                         ┌────────────────────┐               ┌────────────────────┐
                         │      scanners      │               │     apps/web       │
                         │ - SemgrepScanner   │               │ Next.js + TS + TW  │
                         │ - TrivyScanner     │               │ Triage Dashboard   │
                         │ - GitleaksScanner  │               │ Scan Inspector     │
                         │ - CustomRuleScanner│               │ Policy Manager     │
                         └────────────────────┘               └────────────────────┘
```

---

## 4. Subsystems & Responsibilities

| Subsystem | Directory | Key Responsibility |
|---|---|---|
| **Web Frontend** | `apps/web/` | Next.js 14+ UI with Tailwind CSS. Visualizes repositories, real-time scans, findings drawer, interactive AST triage, policy configurations, and executive reports. |
| **API Backend** | `apps/api/` | FastAPI service exposing RESTful contracts, enforcing JWT auth, handling GitHub webhooks, validating payloads, and orchestrating scan requests. |
| **Core Engines** | `engine/` | Independent deterministic engines: RuleEngine, OWASPMapper, SeverityEngine, RiskEngine, ScoreEngine, PolicyEngine, VerificationEngine, FindingNormalizer. |
| **Scanner Adapters**| `scanners/` | Pluggable adapters (`SemgrepScanner`, `TrivyScanner`, `GitleaksScanner`, `CustomRuleScanner`) implementing `scan()`, `parse()`, `normalize()`, and `validate()`. |
| **GitHub Gatekeeper**| `github/` | GitHub App RS256 JWT auth, installation token manager, webhook handler, and Check Runs publisher with inline annotations. |
| **Database** | `database/` | PostgreSQL relational schema, SQLAlchemy 2.0 ORM models, migrations, and seed data. |
| **Testing** | `tests/` | Pytest unit tests, integration tests, and vulnerable sample fixture repositories. |

---

## 5. Security & Isolation Model

- **Safe Ingestion**: Untrusted repositories are never cloned with `git clone` because malicious repositories can execute arbitrary commands via `.git/hooks` or submodules. Audit Bench streams an archive tarball/zipball directly via the GitHub API.
- **Resource Constraints**: Scanners operate with strict memory caps (512MB default), CPU quotas, and execution timeouts (300s default).
- **Network Boundaries**: Scanners run air-gapped without unrestricted egress. Only authorized vulnerability database sync endpoints are permitted.
- **Finding Fingerprint Invariance**: `fingerprint = sha256(rule_id:file_path:line_start:evidence)` is immutable, enabling stable finding tracking across commits and branches.
