"use client";

import { useEffect, useState } from "react";
import { ShieldAlert, Search, Filter } from "lucide-react";
import { api, Finding } from "../../lib/api-client";
import { SeverityBadge, StatusBadge } from "../../components/SeverityBadge";
import FindingDrawer from "../../components/FindingDrawer";

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadFindings();
  }, [severityFilter, statusFilter]);

  async function loadFindings() {
    setLoading(true);
    try {
      const params: any = {};
      if (severityFilter !== "ALL") params.severity = severityFilter;
      if (statusFilter !== "ALL") params.status = statusFilter;

      const data = await api.getFindings(params);
      setFindings(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  const filtered = findings.filter((f) => {
    const q = searchQuery.toLowerCase();
    return (
      f.title.toLowerCase().includes(q) ||
      f.rule_id.toLowerCase().includes(q) ||
      (f.file_path && f.file_path.toLowerCase().includes(q))
    );
  });

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-bold font-mono text-white">Vulnerability Findings Explorer</h1>
        <p className="text-xs text-gray-400 mt-0.5 font-mono">
          Unified normalized findings mapped to OWASP Top 10 with deterministic remediation guidance.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-2 flex-1 max-w-md bg-surface px-3 py-2 rounded-lg border border-surfaceBorder">
          <Search className="w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search by title, rule ID, or filename..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-transparent text-xs font-mono text-white placeholder-gray-500 focus:outline-none w-full"
          />
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 font-mono text-xs">
            <span className="text-gray-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-surface border border-surfaceBorder rounded px-2.5 py-1 text-xs font-mono text-white focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 font-mono text-xs">
            <span className="text-gray-400">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-surface border border-surfaceBorder rounded px-2.5 py-1 text-xs font-mono text-white focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="OPEN">Open</option>
              <option value="RESOLVED">Resolved</option>
              <option value="REOPENED">Reopened</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      {loading ? (
        <div className="p-8 text-center font-mono text-xs text-gray-500">Loading findings...</div>
      ) : filtered.length === 0 ? (
        <div className="p-8 text-center font-mono text-xs text-gray-400 rounded-xl bg-cardBg border border-surfaceBorder">
          No findings match the selected filters.
        </div>
      ) : (
        <div className="rounded-xl bg-cardBg border border-surfaceBorder overflow-hidden shadow-xl">
          <table className="w-full text-left text-xs font-mono">
            <thead className="border-b border-surfaceBorder bg-surface text-gray-400 uppercase text-[10px]">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Title & Rule</th>
                <th className="py-3 px-4">OWASP Category</th>
                <th className="py-3 px-4">File Path</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {filtered.map((f) => (
                <tr
                  key={f.finding_id}
                  className="hover:bg-surfaceHover/50 transition-colors cursor-pointer"
                  onClick={() => setSelectedFinding(f)}
                >
                  <td className="py-3.5 px-4">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="font-bold text-white max-w-sm truncate">{f.title}</div>
                    <div className="text-[10px] text-gray-400 mt-0.5">{f.rule_id}</div>
                  </td>
                  <td className="py-3.5 px-4 text-primary font-mono">{f.owasp_id || "N/A"}</td>
                  <td className="py-3.5 px-4 text-gray-300 font-mono truncate max-w-[200px]">
                    {f.file_path ? `${f.file_path}:${f.line_start}` : "N/A"}
                  </td>
                  <td className="py-3.5 px-4">
                    <StatusBadge status={f.status} />
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button className="px-2.5 py-1 rounded bg-surfaceHover hover:bg-surfaceBorder text-primary border border-primary/20 text-[11px] font-mono">
                      Remediation
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
