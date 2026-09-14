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
  owasp_name?: string | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  evidence: string | null;
  description: string | null;
  impact: string | null;
  remediation: string | null;
  status: "OPEN" | "RESOLVED" | "REOPENED";
  detected_at?: string;
  resolved_at?: string | null;
  history?: Array<{
    scan_id: string;
    from_status: string | null;
    to_status: string;
    changed_at: string;
  }>;
}

export interface Repository {
  id: string;
  full_name: string;
  default_branch: string;
  created_at: string;
  last_scan?: {
    id: string;
    status: string;
    security_score: number | null;
    policy_result: string | null;
    completed_at: string | null;
  } | null;
}

export interface Scan {
  id: string;
  repository_id: string;
  commit_sha: string;
  trigger: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
  security_score: number | null;
  policy_result: "PASS" | "FAIL" | null;
  summary?: ScanSummary | null;
  owasp_breakdown?: Record<string, number> | null;
  error_detail?: any;
  queued_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  findings_count?: number;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  organization_id: string;
  repository_id: string | null;
  definition: {
    minimum_score: number;
    fail_on_critical: boolean;
    max_high: number;
    max_medium: number;
    max_low: number;
    fail_on_secrets: boolean;
    fail_on_new_findings: boolean;
  };
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

async function fetchJson<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || errorData.message || `API error ${res.status}`);
  }

  return res.json();
}

export const api = {
  getHealth: () => fetchJson<any>("/health"),

  // Repositories
  getRepositories: () => fetchJson<Repository[]>("/repositories"),
  getRepository: (id: string) => fetchJson<any>(`/repositories/${id}`),
  triggerScan: (id: string, branch = "main", commitSha = "HEAD") =>
    fetchJson<any>(`/repositories/${id}/scans`, {
      method: "POST",
      body: JSON.stringify({ branch, commit_sha: commitSha }),
    }),

  // Scans
  getScans: (repositoryId?: string, status?: string) => {
    const params = new URLSearchParams();
    if (repositoryId) params.append("repository_id", repositoryId);
    if (status) params.append("status", status);
    return fetchJson<Scan[]>(`/scans?${params.toString()}`);
  },
  getScan: (id: string) => fetchJson<Scan>(`/scans/${id}`),
  cancelScan: (id: string) =>
    fetchJson<any>(`/scans/${id}/cancel`, { method: "POST" }),

  // Findings
  getFindings: (params?: { scan_id?: string; repository_id?: string; severity?: string; status?: string; owasp_id?: string }) => {
    const q = new URLSearchParams();
    if (params?.scan_id) q.append("scan_id", params.scan_id);
    if (params?.repository_id) q.append("repository_id", params.repository_id);
    if (params?.severity) q.append("severity", params.severity);
    if (params?.status) q.append("status", params.status);
    if (params?.owasp_id) q.append("owasp_id", params.owasp_id);
    return fetchJson<Finding[]>(`/findings?${q.toString()}`);
  },
  getFinding: (id: string) => fetchJson<Finding>(`/findings/${id}`),

  // Policies
  getPolicies: (repositoryId?: string) => {
    const q = repositoryId ? `?repository_id=${repositoryId}` : "";
    return fetchJson<SecurityPolicy[]>(`/policies${q}`);
  },
  createPolicy: (data: any) =>
    fetchJson<any>("/policies", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updatePolicy: (id: string, data: any) =>
    fetchJson<any>(`/policies/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  // GitHub
  getGitHubStatus: () => fetchJson<any>("/github/status"),
  installGitHubApp: (installationId: number, accountLogin: string) =>
    fetchJson<any>("/github/install", {
      method: "POST",
      body: JSON.stringify({ installation_id: installationId, account_login: accountLogin }),
    }),

  // Interactive Sandbox
  scanSnippet: (code: string, language = "auto") =>
    fetchJson<any>("/scan/snippet", {
      method: "POST",
      body: JSON.stringify({ code, language }),
    }),
};
