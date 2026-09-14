# Audit Bench — Security Model

## 1. Threat Model Overview

Audit Bench ingests, analyzes, and evaluates potentially malicious source code submitted by untrusted third parties or compromised repositories. The security platform itself must resist attacks targeting:
1. Arbitrary code execution via build scripts, git hooks, or AST parsers.
2. Server-Side Request Forgery (SSRF) targeting internal cloud metadata or local microservices.
3. Path traversal attacks (Zip-Slip) extracting files outside sandbox directories.
4. Denial of Service via archive decompression bombs (Zip-Bomb) or catastrophic regex backtracking (ReDoS).
5. Information leakage of GitHub App private keys, installation tokens, or internal audit logs.
6. Webhook forgery or replay attacks.

---

## 2. Ingestion & Sandbox Isolation

### No Untrusted Git Execution
- `git clone` is strictly prohibited on the API server. Malicious repositories can execute arbitrary shell scripts through crafted `.git/hooks` or `.gitmodules`.
- Audit Bench acquires code exclusively via GitHub's tarball/zipball archive export endpoints (`/repos/{owner}/{repo}/tarball/{ref}`) or authenticated file uploads.

### Ephemeral Container / Subprocess Sandboxing
- Scanners run inside ephemeral worker sandboxes.
- The target repository is mounted **read-only** (`:ro`).
- Only `/tmp/scratch` is mounted as writable ephemeral storage.
- Non-root user execution (`nobody` or unprivileged UID 1000).
- Strict resource limits: CPU quota (max 2 cores), memory limits (max 512MB to 1GB), and wall-clock execution timeouts (300 seconds).
- Network isolation: Containers run with `--network none` (or allow-listed local loopback for internal tools only). Scanner processes are strictly forbidden from initiating outbound internet connections.

---

## 3. Webhook Authentication & Integrity

- Incoming GitHub webhooks are accepted only at `/api/v1/github/webhook`.
- Every payload must include the `X-Hub-Signature-256` header.
- The signature is verified using constant-time HMAC-SHA256 comparison against the configured `GITHUB_WEBHOOK_SECRET`.
- Requests with missing, malformed, or mismatched signatures are immediately rejected with `401 Unauthorized`.
- Webhook handlers do not perform blocking operations; they validate the payload, persist the scan trigger, and return HTTP `200` within 100ms.

---

## 4. Archive Ingestion Hardening

### Zip-Slip Defense
- Every archive entry is inspected before extraction.
- The target path is normalized and resolved:
  `resolved_path = os.path.abspath(os.path.join(target_dir, entry_name))`
- Assert that `resolved_path.startswith(os.path.abspath(target_dir) + os.sep)`.
- If an entry attempts to escape the root directory (e.g. `../../etc/passwd`), the entire archive is rejected with an error.

### Zip-Bomb & Resource Exhaustion Defense
- Maximum compressed size: 25 MB.
- Maximum uncompressed size: 500 MB.
- Maximum compression ratio: 100:1.
- Maximum total files: 2,000 files.
- Single file size limit: 1 MB.

---

## 5. SSRF Defense (URL Scanner & Webhook Targets)

For any feature fetching external URLs:
- Protocol restriction: Only `http:` and `https:` schemes.
- DNS pre-resolution: Hostnames are pre-resolved to all IPv4/IPv6 addresses before connection.
- Private CIDR blocking: Resolved IPs are checked against private, link-local, loopback, and cloud metadata ranges:
  - `127.0.0.0/8` (Loopback)
  - `10.0.0.0/8` (Private Class A)
  - `172.16.0.0/12` (Private Class B)
  - `192.168.0.0/16` (Private Class C)
  - `169.254.0.0/16` (Link-local & AWS/GCP/Azure Metadata `169.254.169.254`)
  - `::1/128`, `fc00::/7`, `fe80::/10` (IPv6 loopback, ULA, and link-local)
- IP Pinning: The HTTP client connects directly to the validated IP address to prevent Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.

---

## 6. Secrets & Credential Management

- Zero credentials in source code.
- GitHub App Private Key, Webhook Secret, Database Credentials, and JWT Signing Keys are injected via environment variables or secret volumes (`infra/secrets/.env`).
- Scanner sandbox environments never receive GitHub App credentials, access tokens, or database connection strings.
- Logging hygiene: Scan telemetry and audit logs record metadata (scan ID, counts, durations) and never log raw code snippets, tokens, or authorization headers.
