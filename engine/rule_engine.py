"""
RuleEngine — Deterministic OWASP Top 10 Static Analysis Rule Catalog and Evaluator.
Ports and expands the 13 core deterministic rules with line-accurate AST/regex inspection.
"""
import re
from typing import List, Optional, Dict, Any
from engine.models import RawFinding


class SecurityRule:
    def __init__(
        self,
        rule_id: str,
        owasp_id: str,
        category: str,
        severity: str,
        confidence: str,
        title: str,
        pattern: str,
        explanation: str,
        suggested_fix: str,
        impact: str,
        supported_languages: Optional[List[str]] = None,
    ):
        self.rule_id = rule_id
        self.owasp_id = owasp_id
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.title = title
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.explanation = explanation
        self.suggested_fix = suggested_fix
        self.impact = impact
        self.supported_languages = supported_languages or ["all"]


# 13 Deterministic OWASP Top 10 Core Rules
CORE_RULES: List[SecurityRule] = [
    # A01:2021 — Broken Access Control
    SecurityRule(
        rule_id="RULE_A01_IDOR_PARAM",
        owasp_id="A01:2021",
        category="Broken Access Control",
        severity="CRITICAL",
        confidence="HIGH",
        title="Direct Object Reference without Tenant/User Ownership Check",
        pattern=r"(?:findById|findOne|findUnique|delete|destroy)\s*\(\s*(?:req\.(?:params|query|body)\.\w+|[a-zA-Z0-9_]+Id)\s*\)(?!\s*\.where\s*\(\s*\{\s*userId)",
        explanation="Database query fetches or mutates records using user-supplied parameters without scoping to the authenticated user's tenant ID, allowing Insecure Direct Object References (IDOR).",
        impact="Unauthorized access, data exfiltration, or modification of other users' records.",
        suggested_fix="const record = await db.item.findOne({ where: { id: req.params.id, userId: req.user.id } });\nif (!record) return res.status(404).json({ error: 'Not found' });",
    ),
    SecurityRule(
        rule_id="RULE_A01_PATH_TRAVERSAL",
        owasp_id="A01:2021",
        category="Broken Access Control",
        severity="CRITICAL",
        confidence="HIGH",
        title="Path Traversal via Unsanitized File Access",
        pattern=r"(?:fs\.(?:readFile|readFileSync|createReadStream|unlink|writeFile)|open\s*\()\s*.*(?:req\.(?:params|query|body)|params\[|request\.args)",
        explanation="User-controlled input is passed directly to filesystem APIs. An attacker can use '../' sequences to traverse out of the intended directory and access sensitive server files.",
        impact="Arbitrary local file disclosure and source code exposure.",
        suggested_fix="const safePath = path.resolve(BASE_DIR, path.basename(req.query.filename));\nif (!safePath.startsWith(BASE_DIR)) throw new Error('Path traversal attempt');",
    ),

    # A02:2021 — Cryptographic Failures
    SecurityRule(
        rule_id="RULE_A02_WEAK_HASH",
        owasp_id="A02:2021",
        category="Cryptographic Failures",
        severity="CRITICAL",
        confidence="HIGH",
        title="Obsolete/Broken Hashing Algorithm (MD5 / SHA-1)",
        pattern=r"(?:createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)|hashlib\.(?:md5|sha1)\s*\(|md5\s*\(|sha1\s*\()",
        explanation="MD5 and SHA-1 suffer from collision and pre-image vulnerabilities. They must never be used for password hashing, integrity verification, or digital signatures.",
        impact="Cryptographic collision attacks and pre-image credential forgery.",
        suggested_fix="// For passwords: use Argon2id or bcrypt (cost >= 12)\n// For hashing/checksums: use SHA-256 or SHA-512\nconst digest = crypto.createHash('sha256').update(data).digest('hex');",
    ),
    SecurityRule(
        rule_id="RULE_A02_HARDCODED_KEY",
        owasp_id="A02:2021",
        category="Cryptographic Failures",
        severity="CRITICAL",
        confidence="HIGH",
        title="Hardcoded API Key, Secret Token, or Private Key",
        pattern=r"(?:(?:api_?key|secret|password|private_?key|token|auth_?token|jwt_?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-\.\/]{16,}['\"]|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)",
        explanation="Hardcoded secrets stored in source code are frequently leaked via version control, build artifacts, or client bundles.",
        impact="Complete compromise of cloud infrastructure, third-party integrations, or administrative credentials.",
        suggested_fix="const apiKey = process.env.API_SECRET_KEY;\nif (!apiKey) throw new Error('Missing API_SECRET_KEY in environment');",
    ),

    # A03:2021 — Injection
    SecurityRule(
        rule_id="RULE_A03_SQL_CONCAT",
        owasp_id="A03:2021",
        category="Injection",
        severity="CRITICAL",
        confidence="HIGH",
        title="SQL Query Built with String Concatenation / Interpolation",
        pattern=r"(?:(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+.*(?:\+\s*[a-zA-Z0-9_\.]+|\$\{[^\}]+\}))|(?:execute|query)\s*\(\s*[`'\"]\s*(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|f['\"]|\$\{)",
        explanation="Interpolating unescaped user input into raw SQL queries enables SQL injection (CWE-89), allowing attackers to bypass authentication or dump databases.",
        impact="Database compromise, unauthorized data extraction, data destruction, and potential RCE.",
        suggested_fix="// Use parameterized queries or prepared statements\nconst result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);",
    ),
    SecurityRule(
        rule_id="RULE_A03_XSS_INNERHTML",
        owasp_id="A03:2021",
        category="Injection",
        severity="CRITICAL",
        confidence="HIGH",
        title="Cross-Site Scripting (XSS) via innerHTML / Raw DOM Injection",
        pattern=r"(?:\.innerHTML\s*=\s*[^;]+|\.outerHTML\s*=\s*[^;]+|dangerouslySetInnerHTML\s*=\s*\{|document\.write\s*\()",
        explanation="Assigning untrusted data directly to innerHTML or dangerouslySetInnerHTML executes attacker-controlled JavaScript in the context of the user session (CWE-79).",
        impact="Session hijacking, sensitive cookie theft, and client-side credential theft.",
        suggested_fix="// Use safe textContent or DOMPurify\nelement.textContent = untrustedInput;\n// Or: element.innerHTML = DOMPurify.sanitize(untrustedHtml);",
    ),
    SecurityRule(
        rule_id="RULE_A03_EVAL_DYNAMIC_CODE",
        owasp_id="A03:2021",
        category="Injection",
        severity="CRITICAL",
        confidence="HIGH",
        title="Unsafe Dynamic Code Execution (eval / Function constructor)",
        pattern=r"(?:\beval\s*\([^\)]+\)|new\s+Function\s*\(|setTimeout\s*\(\s*['\"`][^'\"`]+['\"`]|setInterval\s*\(\s*['\"`][^'\"`]+['\"`])",
        explanation="eval() and new Function() execute arbitrary strings as code. Any user input reaching this construct leads directly to Remote Code Execution (RCE).",
        impact="Arbitrary code execution on the host server or client browser.",
        suggested_fix="// Parse structured data securely with JSON.parse\nconst parsed = JSON.parse(sanitizedJsonString);",
    ),

    # A04:2021 — Insecure Design
    SecurityRule(
        rule_id="RULE_A04_WEAK_PRNG",
        owasp_id="A04:2021",
        category="Insecure Design",
        severity="MEDIUM",
        confidence="HIGH",
        title="Cryptographically Weak Pseudo-Random Number Generator (Math.random)",
        pattern=r"(?:Math\.random\s*\(\s*\)|random\.random\s*\(\s*\)|rand\s*\(\s*\))",
        explanation="Math.random() is pseudo-random and predictable. It must never be used for security-critical contexts like password reset tokens, session IDs, or encryption keys (CWE-338).",
        impact="Prediction of reset tokens, session identifiers, and CSRF nonces.",
        suggested_fix="const crypto = require('crypto');\nconst secureToken = crypto.randomBytes(32).toString('hex');",
    ),

    # A05:2021 — Security Misconfiguration
    SecurityRule(
        rule_id="RULE_A05_CORS_WILDCARD",
        owasp_id="A05:2021",
        category="Security Misconfiguration",
        severity="MEDIUM",
        confidence="HIGH",
        title="Overly Permissive CORS Policy with Wildcard",
        pattern=r"(?:origin:\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\])",
        explanation="Allowing wildcard ('*') origins permits any arbitrary third-party site to send cross-origin requests, potentially exposing internal endpoints.",
        impact="Cross-origin data leakage and unauthorized API invocation.",
        suggested_fix="const allowedOrigins = ['https://app.auditbench.sec'];\napp.use(cors({ origin: allowedOrigins, credentials: true }));",
    ),
    SecurityRule(
        rule_id="RULE_A05_DEBUG_ENABLED",
        owasp_id="A05:2021",
        category="Security Misconfiguration",
        severity="MEDIUM",
        confidence="HIGH",
        title="Debug Mode / Verbose Diagnostic Mode Enabled in Production",
        pattern=r"(?:debug\s*:\s*true|DEBUG\s*=\s*True|app\.debug\s*=\s*True|app\.use\(errorhandler\(\)\))",
        explanation="Production services running with debug mode active expose internal stack traces, system paths, environment variables, and interactive consoles.",
        impact="Information disclosure of infrastructure topology, secrets, and system paths.",
        suggested_fix="const isProduction = process.env.NODE_ENV === 'production';\napp.use((err, req, res, next) => res.status(500).json({ error: 'Internal Error', id: req.id }));",
    ),

    # A07:2021 — Identification and Authentication Failures
    SecurityRule(
        rule_id="RULE_A07_WEAK_JWT_SECRET",
        owasp_id="A07:2021",
        category="Identification & Authentication Failures",
        severity="CRITICAL",
        confidence="HIGH",
        title="Weak or Default Hardcoded JWT Secret Key",
        pattern=r"(?:jwt\.sign\s*\([^,]+,\s*['\"](?:secret|123456|password|test|dev|admin|jwtsecret|mysecret)['\"]|algorithms\s*:\s*\[\s*['\"]none['\"]\s*\])",
        explanation="Signing JWTs with weak, trivial, or default dictionary keys allows attackers to easily brute-force the secret offline and forge administrative tokens.",
        impact="Complete authentication bypass and privilege escalation.",
        suggested_fix="const token = jwt.sign(payload, process.env.JWT_SIGNING_KEY, { algorithm: 'HS256', expiresIn: '1h' });",
    ),

    # A09:2021 — Security Logging and Monitoring Failures
    SecurityRule(
        rule_id="RULE_A09_SENSITIVE_LOGGING",
        owasp_id="A09:2021",
        category="Security Logging & Monitoring",
        severity="LOW",
        confidence="HIGH",
        title="Sensitive Credential or Token Written to Application Logs",
        pattern=r"(?:console\.(?:log|warn|error|info)|logger\.(?:info|debug))\s*\([^\)]*(?:password|token|secret|credit_?card|cvv|api_?key)",
        explanation="Writing sensitive authentication credentials, passwords, or secrets to stdout or log aggregators exposes them to log pipeline breaches (CWE-532).",
        impact="Credential exposure through logs and monitoring dashboards.",
        suggested_fix="const sanitized = { id: user.id, email: user.email };\nlogger.info('User authenticated', { user: sanitized });",
    ),

    # A10:2021 — Server-Side Request Forgery (SSRF)
    SecurityRule(
        rule_id="RULE_A10_UNVALIDATED_FETCH",
        owasp_id="A10:2021",
        category="Server-Side Request Forgery (SSRF)",
        severity="CRITICAL",
        confidence="HIGH",
        title="Outbound Request with Unvalidated User-Controlled URL",
        pattern=r"(?:(?:axios(?:\.get|\.post)?|fetch|http\.get|https\.get|urllib\.request|requests\.get)\s*\(\s*(?:req\.(?:query|body|params)\.\w+|[a-zA-Z0-9_]*url)\b)",
        explanation="Invoking HTTP client libraries using raw user-supplied URLs without resolving DNS, validating destination IP ranges, and blocking private CIDRs causes SSRF.",
        impact="Cloud metadata theft (169.254.169.254), internal port scanning, and internal network pivot.",
        suggested_fix="const safeUrl = await validateAndPinOutboundUrl(req.query.targetUrl);\nconst response = await fetchWithPinnedIp(safeUrl);",
    ),
]


class RuleEngine:
    """Executes deterministic static analysis rules across source files."""

    def __init__(self, rules: Optional[List[SecurityRule]] = None):
        self.rules = rules or CORE_RULES

    def scan_content(self, content: str, file_path: Optional[str] = None) -> List[RawFinding]:
        """Scans a text content string line-by-line and returns RawFinding objects."""
        if not content or not isinstance(content, str):
            return []

        findings: List[RawFinding] = []
        lines = content.splitlines()

        for line_idx, line_text in enumerate(lines):
            line_num = line_idx + 1
            trimmed_line = line_text.strip()
            if not trimmed_line or trimmed_line.startswith(("//", "#", "/*", "*")):
                continue

            for rule in self.rules:
                if rule.regex.search(line_text):
                    findings.append(
                        RawFinding(
                            rule_id=rule.rule_id,
                            scanner="custom",
                            title=rule.title,
                            category=rule.category,
                            owasp_id=rule.owasp_id,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            file_path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            evidence=trimmed_line[:300],
                            description=rule.explanation,
                            impact=rule.impact,
                            remediation=rule.suggested_fix,
                        )
                    )

        return findings

    @staticmethod
    def detect_language(content: str, file_path: Optional[str] = None) -> str:
        """Detects programming language from filename extension or content heuristics."""
        if file_path:
            lower = file_path.lower()
            if lower.endswith((".py", ".pyw")): return "python"
            if lower.endswith((".js", ".jsx", ".mjs")): return "javascript"
            if lower.endswith((".ts", ".tsx")): return "typescript"
            if lower.endswith(".go"): return "go"
            if lower.endswith((".java", ".jar")): return "java"
            if lower.endswith(".php"): return "php"
            if lower.endswith(".sql"): return "sql"
            if lower.endswith((".html", ".htm")): return "html"
            if lower.endswith((".json", ".yml", ".yaml")): return "config"

        sample = content[:2000] if content else ""
        if "<?php" in sample: return "php"
        if re.search(r"^\s*(?:import\s+\w+|from\s+\w+\s+import|def\s+\w+\s*\(|class\s+\w+:)", sample, re.MULTILINE):
            return "python"
        if re.search(r"\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", sample, re.IGNORECASE):
            return "sql"
        if re.search(r"(?:const|let|var|function|export\s+default)", sample):
            return "javascript"

        return "text"
