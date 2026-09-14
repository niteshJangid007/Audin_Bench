/**
 * Audit Bench API Client.
 * Thin typed client over the backend REST API — never makes security decisions itself.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "/api/v1";

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  owasp_distribution?: Record<string, number>;
  duration_ms?: number;
}

export interface Finding {
  finding_id: string;
  fingerprint: string;
  rule_id: string;
  scanner: "semgrep" | "trivy" | "gitleaks" | "custom";
  title: string;
  category: string;
  owasp_id: string | null;
  cwe_id: string | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  file_path: string;
  line_number: number | null;
  code_snippet: string | null;
  remediation_advice: string | null;
  risk_score: number;
  status: "OPEN" | "RESOLVED" | "REOPENED" | "IGNORED";
  first_seen_scan_id?: string;
  last_seen_scan_id?: string;
}

export interface SecurityPolicy {
  policy_id: string;
  name: string;
  enforcement_level: "BLOCKING" | "ADVISORY";
  min_security_score: number;
  max_critical_findings: number;
  max_high_findings: number;
  blocked_owasp_categories: string[];
  is_default: boolean;
}

export interface Scan {
  scan_id: string;
  repository_id: string;
  branch: string;
  commit_sha: string;
  scan_type: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  policy_gate_status: "PASSED" | "FAILED" | "PENDING";
  security_score: number;
  summary: ScanSummary;
  created_at: string;
  completed_at: string | null;
  findings?: Finding[];
}

export interface Repository {
  repository_id: string;
  name: string;
  owner: string;
  full_name: string;
  default_branch: string;
  is_active: boolean;
  active_policy_id: string | null;
  created_at: string;
  last_scan?: {
    scan_id: string;
    security_score: number;
    policy_gate_status: string;
    completed_at: string;
  } | null;
}

export interface SandboxScanRequest {
  code: string;
  language: string;
  policy_level?: "STRICT" | "STANDARD" | "PERMISSIVE";
}

export interface SandboxScanResponse {
  scan_id: string;
  security_score: number;
  policy_gate_status: "PASSED" | "FAILED";
  policy_applied: string;
  summary: ScanSummary;
  findings: Finding[];
}

class ApiClient {
  private base: string;

  constructor(baseUrl: string) {
    this.base = baseUrl.replace(/\/$/, "");
  }

  private async request<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const url = `${this.base}${endpoint}`;
    const res = await fetch(url, {
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
      ...options,
    });

    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(`API ${res.status}: ${errorText || res.statusText}`);
    }

    return res.json();
  }

  // Health
  async getHealth() {
    return this.request<{ status: string; version: string; service: string }>("/health");
  }

  // Repositories
  async getRepositories(): Promise<Repository[]> {
    return this.request<Repository[]>("/repositories");
  }

  async getRepository(id: string): Promise<Repository> {
    return this.request<Repository>(`/repositories/${id}`);
  }

  // Scans
  async getScans(repositoryId?: string): Promise<Scan[]> {
    const query = repositoryId ? `?repository_id=${repositoryId}` : "";
    return this.request<Scan[]>(`/scans${query}`);
  }

  async getScan(id: string): Promise<Scan> {
    return this.request<Scan>(`/scans/${id}`);
  }

  async triggerScan(repositoryId: string, branch = "main"): Promise<Scan> {
    return this.request<Scan>("/scans", {
      method: "POST",
      body: JSON.stringify({ repository_id: repositoryId, branch }),
    });
  }

  // Findings
  async getFindings(params?: {
    severity?: string;
    status?: string;
    owasp_id?: string;
    repository_id?: string;
  }): Promise<Finding[]> {
    const q = new URLSearchParams();
    if (params?.severity) q.set("severity", params.severity);
    if (params?.status) q.set("status", params.status);
    if (params?.owasp_id) q.set("owasp_id", params.owasp_id);
    if (params?.repository_id) q.set("repository_id", params.repository_id);
    const query = q.toString() ? `?${q.toString()}` : "";
    return this.request<Finding[]>(`/findings${query}`);
  }

  async getFinding(id: string): Promise<Finding> {
    return this.request<Finding>(`/findings/${id}`);
  }

  // Policies
  async getPolicies(): Promise<SecurityPolicy[]> {
    return this.request<SecurityPolicy[]>("/policies");
  }

  async updatePolicy(id: string, updates: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
    return this.request<SecurityPolicy>(`/policies/${id}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    });
  }

  // Sandbox Live Scan
  async runSandboxScan(payload: SandboxScanRequest): Promise<SandboxScanResponse> {
    return this.request<SandboxScanResponse>("/sandbox/scan", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  // GitHub status
  async getGitHubStatus() {
    return this.request<{
      app_id: string | null;
      configured: boolean;
      organizations: any[];
    }>("/github/status");
  }
}

export const api = new ApiClient(API_BASE);
