"use client";

import { useEffect, useState } from "react";
import { FileText, Download, Printer, ShieldCheck, ShieldAlert } from "lucide-react";
import { api, Scan } from "../../lib/api-client";
import { ScoreGauge } from "../../components/ScoreGauge";
import { StatusBadge } from "../../components/SeverityBadge";

export default function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadScans() {
      try {
        const data = await api.getScans();
        const completed = data.filter((s) => s.status === "COMPLETED");
        setScans(completed);
        if (completed.length > 0) {
          setSelectedScan(completed[0]);
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    loadScans();
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-white">Security & Compliance Reports</h1>
          <p className="text-xs text-gray-400 mt-0.5 font-mono">
            Auditable compliance documentation and executive security attestation reports.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surfaceHover hover:bg-surfaceBorder text-gray-200 border border-surfaceBorder text-xs font-mono transition-colors"
          >
            <Printer className="w-3.5 h-3.5" /> Print / Save PDF
          </button>
        </div>
      </div>

      {loading ? (
        <div className="p-8 text-center font-mono text-xs text-gray-500">Loading reports...</div>
      ) : scans.length === 0 ? (
        <div className="p-8 text-center font-mono text-xs text-gray-400 rounded-xl bg-cardBg border border-surfaceBorder">
          No completed scans found to generate compliance report.
        </div>
      ) : (
        <div className="flex flex-col gap-6">
          {/* Select Scan dropdown */}
          <div className="flex items-center gap-3 p-4 rounded-xl bg-cardBg border border-surfaceBorder font-mono text-xs">
            <span className="text-gray-400">Select Audit Run:</span>
            <select
              value={selectedScan?.id || ""}
              onChange={(e) => {
                const found = scans.find((s) => s.id === e.target.value);
                if (found) setSelectedScan(found);
              }}
              className="bg-surface border border-surfaceBorder rounded px-3 py-1 text-xs text-white focus:outline-none"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id.substring(0, 8)}... (Commit: {s.commit_sha.substring(0, 8)} | Result: {s.policy_result || "N/A"})
                </option>
              ))}
            </select>
          </div>

          {/* Printable Report Document */}
          {selectedScan && (
            <div className="p-8 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col gap-8 shadow-2xl print:bg-white print:text-black print:border-none">
              {/* Report Header */}
              <div className="border-b border-surfaceBorder pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <span className="text-[10px] font-mono text-primary uppercase tracking-widest">
                    ATTESTATION // OWASP TOP 10 2021 COMPLIANCE
                  </span>
                  <h2 className="text-2xl font-bold font-mono text-white mt-1">
                    Audit Bench Security Assessment Certificate
                  </h2>
                  <p className="text-xs text-gray-400 font-mono mt-1">
                    Scan Identifier: {selectedScan.id} | Timestamp: {selectedScan.completed_at ? new Date(selectedScan.completed_at).toUTCString() : "N/A"}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <ScoreGauge score={selectedScan.security_score} />
                  <StatusBadge status={selectedScan.policy_result || "PENDING"} />
                </div>
              </div>

              {/* Assessment Statement */}
              <div className="p-4 rounded-lg bg-surface border border-surfaceBorder text-xs text-gray-300 leading-relaxed font-mono">
                This document certifies that source code revision{" "}
                <span className="text-white font-bold">{selectedScan.commit_sha}</span> was audited
                using Audit Bench's deterministic multi-scanner orchestration pipeline (Custom OWASP Engine, Semgrep AST, Gitleaks Secrets, Trivy SCA).
                {selectedScan.policy_result === "PASS" ? (
                  <span className="text-success font-semibold">
                    {" "}The codebase satisfied all organizational baseline security policies and was approved for deployment.
                  </span>
                ) : (
                  <span className="text-critical font-semibold">
                    {" "}The codebase contained policy-violating security defects and was blocked by the security merge gate.
                  </span>
                )}
              </div>

              {/* Severity Metrics Summary */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
                <div className="p-4 rounded-lg bg-surface border border-surfaceBorder flex flex-col">
                  <span className="text-gray-400 uppercase text-[10px]">Critical Vulnerabilities</span>
                  <span className="text-2xl font-bold text-critical mt-1">
                    {selectedScan.summary?.critical ?? 0}
                  </span>
                </div>
                <div className="p-4 rounded-lg bg-surface border border-surfaceBorder flex flex-col">
                  <span className="text-gray-400 uppercase text-[10px]">High Severity</span>
                  <span className="text-2xl font-bold text-high mt-1">
                    {selectedScan.summary?.high ?? 0}
                  </span>
                </div>
                <div className="p-4 rounded-lg bg-surface border border-surfaceBorder flex flex-col">
                  <span className="text-gray-400 uppercase text-[10px]">Medium Severity</span>
                  <span className="text-2xl font-bold text-medium mt-1">
                    {selectedScan.summary?.medium ?? 0}
                  </span>
                </div>
                <div className="p-4 rounded-lg bg-surface border border-surfaceBorder flex flex-col">
                  <span className="text-gray-400 uppercase text-[10px]">Low Severity</span>
                  <span className="text-2xl font-bold text-low mt-1">
                    {selectedScan.summary?.low ?? 0}
                  </span>
                </div>
              </div>

              {/* OWASP Distribution */}
              {selectedScan.owasp_breakdown && (
                <div>
                  <h3 className="text-xs font-mono uppercase text-gray-400 font-bold mb-3">
                    OWASP Top 10 Coverage & Flaw Distribution
                  </h3>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 font-mono text-xs">
                    {Object.entries(selectedScan.owasp_breakdown).map(([cat, count]) => (
                      <div
                        key={cat}
                        className="p-3 rounded-lg bg-surface border border-surfaceBorder flex items-center justify-between"
                      >
                        <span className="text-gray-300">{cat}</span>
                        <span className="px-2 py-0.5 rounded bg-surfaceBorder text-primary font-bold">
                          {count}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
