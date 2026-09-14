# Audit Bench — Rule Catalog & Detection Specification

## 1. Catalog Architecture
Audit Bench maintains deterministic static analysis rules mapped to the OWASP Top 10 (2021) standard. Each rule defines severity, confidence, explanatory background, impact, vulnerable patterns, and safe remediation code.

---

## 2. Active OWASP Top 10 Core Rules

### A01:2021 — Broken Access Control
- **`RULE_A01_IDOR_PARAM`**
  - *Title*: Direct Object Reference without Tenant/User Ownership Check
  - *Severity*: `CRITICAL` | *Confidence*: `HIGH`
  - *Detection*: Query operations fetching by ID parameter without tenant/user scoping.
  - *Fix*: Bind queries to `userId` or authenticated tenant context.

- **`RULE_A01_PATH_TRAVERSAL`**
  - *Title*: Path Traversal via Unsanitized File Access
  - *Severity*: `CRITICAL` | *Confidence*: `HIGH`
  - *Detection*: Passing raw request parameters directly to filesystem APIs (`fs.readFile`, `open()`).
  - *Fix*: Normalize with `path.resolve()` and verify path starts with `BASE_DIR`.

---

### A02:2021 — Cryptographic Failures
- **`RULE_A02_WEAK_HASH`**
  - *Title*: Broken/Obsolete Hashing Algorithm (MD5 / SHA-1)
  - *Severity*: `CRITICAL` | *Confidence*: `HIGH`
  - *Detection*: Invocations of `createHash('md5')`, `hashlib.md5()`, `sha1()`.
  - *Fix*: Use Argon2id/bcrypt for passwords, and SHA-256/SHA-512 for cryptographic checksums.

- **`RULE_A02_HARDCODED_KEY`**
  - *Title*: Hardcoded Secret, Private Key, or API Token
  - *Severity*: `CRITICAL` | *Confidence*: `HIGH`
  - *Detection*: Static strings matching API tokens, AWS keys (`AKIA...`), or `BEGIN PRIVATE KEY`.
  - *Fix*: Inject credentials via protected environment variables or secrets manager.

---

### A03:2021 — Injection
- **`RULE_A03_SQL_CONCAT`**
  - *Title*: SQL Query Built with String Concatenation / Interpolation
  - *Severity*: `CRITICAL` | *Confidence*: `HIGH`
  - *Detection*: String concatenation (`+`) or template literals (`${...}`) inside SQL statements.
  - *Fix*: Use parameterized queries with prepared placeholders (`$1, $2` or `?`).

- **`RULE_A03_XSS_INNERHTML`**
  - *Title*: Cross-Site Scripting (XSS) via innerHTML / Raw DOM Injection
  - *Severity*: `CRITICAL` | *Confidence*: `HIGH`
  - *Detection*: Assignments to `.innerHTML`, `.outerHTML`, `dangerouslySetInnerHTML`, `document.write`.
  - *Fix*: Use `textContent` or sanitize input using DOMPurify.

- **`RULE_A03_EVAL_DYNAMIC_CODE`**
  - *Title*: Unsafe Dynamic Code Execution (eval / Function constructor)
  - *Severity*: `CRITICAL` | *Confidence*: `HIGH`
  - *Detection*: Calls to `eval()`, `new Function()`, or string-based `setTimeout`/`setInterval`.
  - *Fix*: Use `JSON.parse` for structured serialization and avoid dynamic code generation.

---

### A04:2021 — Insecure Design
- **`RULE_A04_WEAK_PRNG`**
  - *Title*: Cryptographically Weak Pseudo-Random Number Generator
  - *Severity*: `MEDIUM` | *Confidence*: `HIGH`
  - *Detection*: Invocations of `Math.random()`, `random.random()`, or `rand()`.
  - *Fix*: Use `crypto.randomBytes()` or `secrets.token_bytes()`.

---

### A05:2021 — Security Misconfiguration
- **`RULE_A05_CORS_WILDCARD`**
  - *Title*: Overly Permissive CORS Policy with Wildcard Origin
  - *Severity*: `MEDIUM` | *Confidence*: `HIGH`
  - *Detection*: `Access-Control-Allow-Origin: *` or `origin: '*'` with credentials allowed.
  - *Fix*: Specify explicit allowed origins list.

- **`RULE_A05_DEBUG_ENABLED`**
  - *Title*: Debug Mode / Diagnostic Traces Enabled in Production
  - *Severity*: `MEDIUM` | *Confidence*: `HIGH`
  - *Detection*: Flags such as `debug: true`, `DEBUG = True`, or error handler stack printers.
  - *Fix*: Disable debug flags in production and render generic error identifiers.

---

### A07:2021 — Identification and Authentication Failures
- **`RULE_A07_WEAK_JWT_SECRET`**
  - *Title*: Weak or Default Hardcoded JWT Secret Key
  - *Severity*: `CRITICAL` | *Confidence*: `HIGH`
  - *Detection*: Signing JWT tokens with dictionary words ('secret', '123456', 'test') or algorithm `none`.
  - *Fix*: Load high-entropy 256-bit+ random secret keys from environment variables.

---

### A09:2021 — Security Logging and Monitoring Failures
- **`RULE_A09_SENSITIVE_LOGGING`**
  - *Title*: Sensitive Credential or Token Written to Application Logs
  - *Severity*: `LOW` | *Confidence*: `HIGH`
  - *Detection*: Logging passwords, secrets, credit cards, or tokens to stdout or application loggers.
  - *Fix*: Mask or scrub sensitive identifiers before writing log lines.

---

### A10:2021 — Server-Side Request Forgery (SSRF)
- **`RULE_A10_UNVALIDATED_FETCH`**
  - *Title*: Outbound Request with Unvalidated User-Controlled URL
  - *Severity*: `CRITICAL` | *Confidence*: `HIGH`
  - *Detection*: Passing unvalidated URL parameters to HTTP clients (`axios`, `fetch`, `requests.get`).
  - *Fix*: Pre-resolve DNS, block private and cloud metadata CIDR ranges, and pin IP.
