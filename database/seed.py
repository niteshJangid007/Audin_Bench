"""
Database Seeder for Audit Bench.
Populates standard OWASP Top 10 categories, rules, and baseline security policies.
"""
from sqlalchemy.orm import Session
from database.models import (
    OWASPCategory,
    Rule,
    Organization,
    SecurityPolicy,
    User,
)
from database.session import SessionLocal, init_db

OWASP_DATA = [
    {"id": "A01:2021", "name": "Broken Access Control"},
    {"id": "A02:2021", "name": "Cryptographic Failures"},
    {"id": "A03:2021", "name": "Injection"},
    {"id": "A04:2021", "name": "Insecure Design"},
    {"id": "A05:2021", "name": "Security Misconfiguration"},
    {"id": "A06:2021", "name": "Vulnerable and Outdated Components"},
    {"id": "A07:2021", "name": "Identification and Authentication Failures"},
    {"id": "A08:2021", "name": "Software and Data Integrity Failures"},
    {"id": "A09:2021", "name": "Security Logging and Monitoring Failures"},
    {"id": "A10:2021", "name": "Server-Side Request Forgery (SSRF)"},
]

RULES_DATA = [
    {
        "id": "RULE_A01_IDOR_PARAM",
        "title": "Direct Object Reference without Tenant/User Ownership Check",
        "category": "Broken Access Control",
        "owasp_id": "A01:2021",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "python"],
        "explanation": "Database query fetches or mutates records using user-supplied parameters without scoping to the authenticated user's tenant ID, allowing Insecure Direct Object References (IDOR).",
        "impact": "Unauthorized access, data exfiltration, or modification of other users' sensitive records.",
        "remediation_text": "Scope query by authenticated userId: db.item.findOne({ where: { id: req.params.id, userId: req.user.id } });",
    },
    {
        "id": "RULE_A01_PATH_TRAVERSAL",
        "title": "Path Traversal via Unsanitized File Access",
        "category": "Broken Access Control",
        "owasp_id": "A01:2021",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "python"],
        "explanation": "User-controlled input is passed directly to filesystem APIs. An attacker can use '../' sequences to traverse out of the intended directory and access sensitive server files.",
        "impact": "Arbitrary file disclosure, source code leak, or sensitive configuration exposure.",
        "remediation_text": "const safePath = path.resolve(BASE_DIR, path.basename(req.query.filename)); if (!safePath.startsWith(BASE_DIR)) throw new Error('Path traversal attempt');",
    },
    {
        "id": "RULE_A02_WEAK_HASH",
        "title": "Obsolete/Broken Hashing Algorithm (MD5 / SHA-1)",
        "category": "Cryptographic Failures",
        "owasp_id": "A02:2021",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "python", "java", "go"],
        "explanation": "MD5 and SHA-1 suffer from collision and pre-image vulnerabilities. They must never be used for password hashing, integrity verification, or digital signatures.",
        "impact": "Collision attacks, forged credentials, and compromised message integrity.",
        "remediation_text": "Use Argon2id or bcrypt for passwords (cost >= 12); use SHA-256 or SHA-512 for HMAC / hashing.",
    },
    {
        "id": "RULE_A02_HARDCODED_KEY",
        "title": "Hardcoded API Key, Secret Token, or Private Key",
        "category": "Cryptographic Failures",
        "owasp_id": "A02:2021",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
        "detection_method": "secret",
        "supported_languages": ["all"],
        "explanation": "Hardcoded secrets stored in source code are frequently leaked via version control, build artifacts, or client bundles.",
        "impact": "Complete compromise of backend APIs, cloud infrastructure, or private communication channels.",
        "remediation_text": "Store secrets in an external secrets manager or environment variables (e.g. process.env.API_KEY).",
    },
    {
        "id": "RULE_A03_SQL_CONCAT",
        "title": "SQL Query Built with String Concatenation / Interpolation",
        "category": "Injection",
        "owasp_id": "A03:2021",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "python", "php", "java"],
        "explanation": "Interpolating unescaped user input into raw SQL queries enables SQL injection (CWE-89), allowing attackers to bypass authentication or dump databases.",
        "impact": "Complete database dump, authentication bypass, data manipulation, or denial of service.",
        "remediation_text": "Use parameterized queries / prepared statements with placeholder variables ($1, $2 or ?).",
    },
    {
        "id": "RULE_A03_XSS_INNERHTML",
        "title": "Cross-Site Scripting (XSS) via innerHTML / Raw DOM Injection",
        "category": "Injection",
        "owasp_id": "A03:2021",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "html"],
        "explanation": "Assigning untrusted data directly to innerHTML or dangerouslySetInnerHTML executes attacker-controlled JavaScript in the context of the user session (CWE-79).",
        "impact": "Session hijacking, credential theft, keystroke logging, and DOM defacement.",
        "remediation_text": "Assign untrusted content to element.textContent, or sanitize with DOMPurify before setting innerHTML.",
    },
    {
        "id": "RULE_A03_EVAL_DYNAMIC_CODE",
        "title": "Unsafe Dynamic Code Execution (eval / Function constructor)",
        "category": "Injection",
        "owasp_id": "A03:2021",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "python"],
        "explanation": "eval() and new Function() execute arbitrary strings as code. Any user input reaching this construct leads directly to Remote Code Execution (RCE).",
        "impact": "Remote Code Execution (RCE) with host application privileges.",
        "remediation_text": "Avoid dynamic code execution entirely; parse structured data securely using JSON.parse().",
    },
    {
        "id": "RULE_A04_WEAK_PRNG",
        "title": "Cryptographically Weak Pseudo-Random Number Generator",
        "category": "Insecure Design",
        "owasp_id": "A04:2021",
        "default_severity": "MEDIUM",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "python"],
        "explanation": "Math.random() is predictable and pseudo-random. It must never be used for security-critical contexts such as password reset tokens, session IDs, or encryption keys.",
        "impact": "Token prediction, session hijacking, and cryptanalysis attacks.",
        "remediation_text": "Use crypto.randomBytes() in Node.js or secrets.token_bytes() in Python.",
    },
    {
        "id": "RULE_A05_CORS_WILDCARD",
        "title": "Overly Permissive CORS Policy with Wildcard Origin",
        "category": "Security Misconfiguration",
        "owasp_id": "A05:2021",
        "default_severity": "MEDIUM",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "python"],
        "explanation": "Allowing wildcard ('*') origins permits any arbitrary third-party site to send cross-origin requests, potentially exposing internal data.",
        "impact": "Data exposure across untrusted third-party origins.",
        "remediation_text": "Explicitly whitelist trusted origins array and deny wildcard origins.",
    },
    {
        "id": "RULE_A05_DEBUG_ENABLED",
        "title": "Debug Mode / Verbose Diagnostic Mode Enabled in Production",
        "category": "Security Misconfiguration",
        "owasp_id": "A05:2021",
        "default_severity": "MEDIUM",
        "default_confidence": "HIGH",
        "detection_method": "config",
        "supported_languages": ["javascript", "typescript", "python"],
        "explanation": "Production services running with debug mode active expose internal stack traces, system paths, environment variables, and interactive consoles.",
        "impact": "Reconnaissance data leakage, source code exposure via stack traces.",
        "remediation_text": "Disable debug flags in production: DEBUG=False; NODE_ENV=production.",
    },
    {
        "id": "RULE_A07_WEAK_JWT_SECRET",
        "title": "Weak or Default Hardcoded JWT Secret Key",
        "category": "Identification and Authentication Failures",
        "owasp_id": "A07:2021",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "python"],
        "explanation": "Signing JWTs with weak, trivial, or default dictionary keys allows attackers to brute-force the secret offline and forge administrative tokens.",
        "impact": "Complete privilege escalation and administrative authentication bypass.",
        "remediation_text": "Sign tokens with strong 256-bit+ cryptographically random keys loaded from environment variables.",
    },
    {
        "id": "RULE_A09_SENSITIVE_LOGGING",
        "title": "Sensitive Credential or Token Written to Application Logs",
        "category": "Security Logging and Monitoring Failures",
        "owasp_id": "A09:2021",
        "default_severity": "LOW",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "python"],
        "explanation": "Writing sensitive authentication credentials, passwords, or secrets to stdout or log aggregators exposes them to log pipeline breaches.",
        "impact": "Credential leakage through telemetry, SIEM, or support logs.",
        "remediation_text": "Scrub or mask sensitive fields (passwords, tokens) before outputting logs.",
    },
    {
        "id": "RULE_A10_UNVALIDATED_FETCH",
        "title": "Outbound Request with Unvalidated User-Controlled URL (SSRF)",
        "category": "Server-Side Request Forgery (SSRF)",
        "owasp_id": "A10:2021",
        "default_severity": "CRITICAL",
        "default_confidence": "HIGH",
        "detection_method": "regex",
        "supported_languages": ["javascript", "typescript", "python"],
        "explanation": "Invoking HTTP client libraries using raw user-supplied URLs without resolving DNS, validating destination IP ranges, and blocking private CIDRs causes SSRF.",
        "impact": "Internal network port scanning, cloud metadata compromise (169.254.169.254), and RCE via internal services.",
        "remediation_text": "Validate URL protocol, pre-resolve DNS, block private and metadata CIDRs, and pin the destination IP.",
    },
]

DEFAULT_POLICY = {
    "minimum_score": 75,
    "fail_on_critical": True,
    "max_high": 2,
    "max_medium": 10,
    "max_low": 20,
    "fail_on_secrets": True,
    "fail_on_new_findings": True,
}


def seed_database(db: Session) -> None:
    """Seeds default categories, rules, organization, and policy if not present."""
    # Seed OWASP categories
    for item in OWASP_DATA:
        existing = db.query(OWASPCategory).filter_by(id=item["id"]).first()
        if not existing:
            db.add(OWASPCategory(id=item["id"], name=item["name"]))

    # Seed Rules
    for r in RULES_DATA:
        existing_rule = db.query(Rule).filter_by(id=r["id"]).first()
        if not existing_rule:
            db.add(
                Rule(
                    id=r["id"],
                    title=r["title"],
                    category=r["category"],
                    owasp_id=r["owasp_id"],
                    default_severity=r["default_severity"],
                    default_confidence=r["default_confidence"],
                    detection_method=r["detection_method"],
                    supported_languages=r["supported_languages"],
                    explanation=r["explanation"],
                    impact=r["impact"],
                    remediation_text=r["remediation_text"],
                    is_active=True,
                )
            )

    # Seed default organization
    default_org = db.query(Organization).filter_by(name="Audit Bench Core").first()
    if not default_org:
        default_org = Organization(name="Audit Bench Core")
        db.add(default_org)
        db.flush()

        # Seed default admin user
        default_user = User(
            organization_id=default_org.id,
            email="secops-lead@auditbench.sec",
            role="admin",
        )
        db.add(default_user)

        # Seed default global policy
        default_pol = SecurityPolicy(
            organization_id=default_org.id,
            repository_id=None,
            name="Standard Security Gate Policy",
            definition=DEFAULT_POLICY,
            is_active=True,
        )
        db.add(default_pol)

    db.commit()


if __name__ == "__main__":
    init_db()
    with SessionLocal() as session:
        seed_database(session)
        print("Database initialized and seeded successfully.")
