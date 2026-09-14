"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Layers,
  FileCode,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { api, Scan, Finding } from "../../../lib/api-client";
import { SeverityBadge, StatusBadge } from "../../../components/SeverityBadge";
import { ScoreGauge } from "../../../components/ScoreGauge";
import FindingDrawer from "../../../components/FindingDrawer";

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadScanData() {
      try {
        const [scanData, findingsData] = await Promise.all([
          api.getScan(scanId),
          api.getFindings({ scan_id: scanId }),
        ]);
        setScan(scanData);
        setFindings(findingsData);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    if (scanId) {
      loadScanData();
    }
  }, [scanId]);

  if (loading) {
    return <div className="p-8 text-center font-mono text-xs text-gray-500">Loading scan forensic telemetry...</div>;
  }

  if (!scan) {
    return <div className="p-8 text-center font-mono text-xs text-critical">Scan not found.</div>;
  }

  const isPassed = scan.policy_result === "PASS";

  return (
    <div className="flex flex-col gap-6">
      <Link
        href="/scans"
        className="inline-flex items-center gap-1.5 text-xs font-mono text-gray-400 hover:text-white transition-colors"
      >
        <ArrowLeft className="w-3.5 h-3.5" /> Back to All Scans
      </Link>

      {/* Decision Banner */}
      <div
        className={`p-6 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl ${
          isPassed
            ? "bg-success/5 border-success/30 text-success"
            : "bg-critical/5 border-critical/30 text-critical"
        }`}
      >
        <div className="flex items-center gap-4">
          {isPassed ? (
            <CheckCircle2 className="w-10 h-10 text-success flex-shrink-0" />
          ) : (
            <XCircle className="w-10 h-10 text-critical flex-shrink-0" />
          )}
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase tracking-widest font-bold">
                GATE DECISION // {scan.policy_result || "PENDING"}
              </span>
              <StatusBadge status={scan.status} />
            </div>
            <h1 className="text-xl font-bold font-mono text-white mt-1">
              {isPassed
                ? "Merge Gate Passed: All Security Baseline Policies Satisfied"
                : "Merge Gate Failed: Critical Vulnerabilities or Policy Threshold Exceeded"}
            </h1>
            <p className="text-xs text-gray-400 font-mono mt-1">
              Commit: {scan.commit_sha} | Trigger: {scan.trigger.toUpperCase()}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <ScoreGauge score={scan.security_score} />
        </div>
      </div>

      {/* Summary Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col">
          <span className="text-[11px] font-mono text-gray-400 uppercase">Critical Severity</span>
          <span className="text-2xl font-bold font-mono text-critical mt-1">
            {scan.summary?.critical ?? 0}
          </span>
          <span className="text-[10px] text-gray-500 font-mono mt-0.5">Blocks PR merge</span>
        </div>

        <div className="p-4 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col">
          <span className="text-[11px] font-mono text-gray-400 uppercase">High Severity</span>
          <span className="text-2xl font-bold font-mono text-high mt-1">
            {scan.summary?.high ?? 0}
          </span>
          <span className="text-[10px] text-gray-500 font-mono mt-0.5">High exploitability risk</span>
        </div>

        <div className="p-4 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col">
          <span className="text-[11px] font-mono text-gray-400 uppercase">Medium Severity</span>
          <span className="text-2xl font-bold font-mono text-medium mt-1">
            {scan.summary?.medium ?? 0}
          </span>
          <span className="text-[10px] text-gray-500 font-mono mt-0.5">Moderate risk</span>
        </div>

        <div className="p-4 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col">
          <span className="text-[11px] font-mono text-gray-400 uppercase">Total Findings</span>
          <span className="text-2xl font-bold font-mono text-white mt-1">
            {findings.length}
          </span>
          <span className="text-[10px] text-gray-500 font-mono mt-0.5">
            Duration: {scan.summary?.duration_ms ?? 0}ms
          </span>
        </div>
      </div>

      {/* OWASP Category Breakdown */}
      {scan.owasp_breakdown && Object.keys(scan.owasp_breakdown).length > 0 && (
        <div className="p-5 rounded-xl bg-cardBg border border-surfaceBorder">
          <h2 className="text-xs font-mono uppercase text-gray-300 font-bold mb-3">
            OWASP Top 10 Category Distribution
          </h2>
          <div className="flex flex-wrap gap-2">
            {Object.entries(scan.owasp_breakdown).map(([cat, count]) => (
              <span
                key={cat}
                className="px-3 py-1.5 rounded-lg bg-surface border border-surfaceBorder font-mono text-xs text-primary flex items-center gap-2"
              >
                <span>{cat}</span>
                <span className="px-1.5 py-0.2 rounded bg-surfaceBorder text-white text-[10px] font-bold">
                  {count}
                </span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Findings Table */}
      <div className="p-5 rounded-xl bg-cardBg border border-surfaceBorder">
        <h2 className="text-xs font-mono uppercase text-gray-300 font-bold mb-3">
          Normalized Findings List ({findings.length})
        </h2>

        {findings.length === 0 ? (
          <div className="py-6 text-center font-mono text-xs text-success">
            ✨ Clean audit! No vulnerabilities detected in this scan.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="border-b border-surfaceBorder bg-surface text-gray-400 uppercase text-[10px]">
                <tr>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Rule & Title</th>
                  <th className="py-3 px-4">OWASP ID</th>
                  <th className="py-3 px-4">File Location</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surfaceBorder">
                {findings.map((f) => (
                  <tr
                    key={f.finding_id}
                    className="hover:bg-surfaceHover/50 transition-colors cursor-pointer"
                    onClick={() => setSelectedFinding(f)}
                  >
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="py-3.5 px-4 font-bold text-white max-w-xs truncate">
                      {f.title}
                    </td>
                    <td className="py-3.5 px-4 text-primary">{f.owasp_id || "N/A"}</td>
                    <td className="py-3.5 px-4 text-gray-400 truncate max-w-[200px]">
                      {f.file_path ? `${f.file_path}:${f.line_start}` : "N/A"}
                    </td>
                    <td className="py-3.5 px-4">
                      <StatusBadge status={f.status} />
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button className="px-2.5 py-1 rounded bg-surfaceHover hover:bg-surfaceBorder text-primary border border-primary/20 text-[11px] font-mono">
                        View Fix
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
