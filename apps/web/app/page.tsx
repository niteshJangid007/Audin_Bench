"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  GitBranch,
  Terminal,
  ArrowRight,
  Clock,
  Play,
} from "lucide-react";
import { api, Repository, Scan, Finding } from "../lib/api-client";
import { SeverityBadge, StatusBadge } from "../components/SeverityBadge";
import { ScoreGauge } from "../components/ScoreGauge";

export default function DashboardPage() {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [repoData, scanData, findingData] = await Promise.all([
          api.getRepositories().catch(() => []),
          api.getScans().catch(() => []),
          api.getFindings({ status: "OPEN" }).catch(() => []),
        ]);
        setRepos(repoData);
        setScans(scanData);
        setFindings(findingData);
      } catch (err) {
        console.error("Failed to load dashboard data:", err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const mediumCount = findings.filter((f) => f.severity === "MEDIUM").length;
  const lowCount = findings.filter((f) => f.severity === "LOW").length;

  const passedScans = scans.filter((s) => s.policy_result === "PASS").length;
  const totalCompleted = scans.filter((s) => s.status === "COMPLETED").length;
  const passRate = totalCompleted > 0 ? Math.round((passedScans / totalCompleted) * 100) : 100;

  return (
    <div className="flex flex-col gap-8">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-xl bg-cardBg border border-surfaceBorder shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-success"></span>
            <span className="text-xs font-mono text-gray-400 uppercase tracking-wider">
              ENTERPRISE DEFENSE ENCLAVE
            </span>
          </div>
          <h1 className="text-2xl font-bold font-mono text-white mt-1">
            DevSecOps Gate Telemetry Dashboard
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Deterministic static analysis, supply chain auditing, and continuous verification.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/sandbox"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-surfaceHover hover:bg-surfaceBorder text-primary border border-primary/30 text-xs font-mono font-semibold transition-all shadow-sm"
          >
            <Terminal className="w-4 h-4" />
            Triage Workbench
          </Link>
          <Link
            href="/repositories"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-background text-xs font-mono font-bold transition-all shadow-lg shadow-primary/20"
          >
            <GitBranch className="w-4 h-4" />
            View Repositories
          </Link>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col justify-between">
          <span className="text-xs font-mono uppercase text-gray-400">Open Critical Flaws</span>
          <div className="flex items-baseline justify-between mt-3">
            <span className="text-3xl font-bold font-mono text-critical">{criticalCount}</span>
            <span className="text-xs font-mono text-critical bg-critical/10 px-2 py-0.5 rounded border border-critical/20">
              MERGE BLOCKER
            </span>
          </div>
          <span className="text-[11px] text-gray-500 font-mono mt-2">Requires immediate patch</span>
        </div>

        <div className="p-5 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col justify-between">
          <span className="text-xs font-mono uppercase text-gray-400">Total Active Findings</span>
          <div className="flex items-baseline justify-between mt-3">
            <span className="text-3xl font-bold font-mono text-white">{findings.length}</span>
            <div className="flex items-center gap-1">
              <span className="text-xs font-mono text-high">{highCount}H</span>
              <span className="text-xs text-gray-600">/</span>
              <span className="text-xs font-mono text-medium">{mediumCount}M</span>
            </div>
          </div>
          <span className="text-[11px] text-gray-500 font-mono mt-2">Tracked across repositories</span>
        </div>

        <div className="p-5 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col justify-between">
          <span className="text-xs font-mono uppercase text-gray-400">Policy Gate Pass Rate</span>
          <div className="flex items-baseline justify-between mt-3">
            <span className="text-3xl font-bold font-mono text-success">{passRate}%</span>
            <ShieldCheck className="w-6 h-6 text-success opacity-80" />
          </div>
          <span className="text-[11px] text-gray-500 font-mono mt-2">
            {passedScans} passed / {totalCompleted} completed
          </span>
        </div>

        <div className="p-5 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col justify-between">
          <span className="text-xs font-mono uppercase text-gray-400">Tracked Repositories</span>
          <div className="flex items-baseline justify-between mt-3">
            <span className="text-3xl font-bold font-mono text-primary">{repos.length}</span>
            <GitBranch className="w-6 h-6 text-primary opacity-80" />
          </div>
          <span className="text-[11px] text-gray-500 font-mono mt-2">Integrated via GitHub App</span>
        </div>
      </div>

      {/* Severity Breakdown Strip */}
      <div className="p-6 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col gap-4">
        <h2 className="text-sm font-mono uppercase text-gray-300 font-bold">
          Active Vulnerability Severity Breakdown
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="p-4 rounded-lg bg-surface border border-critical/20 flex flex-col">
            <span className="text-xs font-mono text-critical font-semibold uppercase">CRITICAL</span>
            <span className="text-2xl font-bold font-mono text-white mt-1">{criticalCount}</span>
            <span className="text-[10px] text-gray-500 mt-1">-25 pts deduction each</span>
          </div>
          <div className="p-4 rounded-lg bg-surface border border-high/20 flex flex-col">
            <span className="text-xs font-mono text-high font-semibold uppercase">HIGH</span>
            <span className="text-2xl font-bold font-mono text-white mt-1">{highCount}</span>
            <span className="text-[10px] text-gray-500 mt-1">-15 pts deduction each</span>
          </div>
          <div className="p-4 rounded-lg bg-surface border border-medium/20 flex flex-col">
            <span className="text-xs font-mono text-medium font-semibold uppercase">MEDIUM</span>
            <span className="text-2xl font-bold font-mono text-white mt-1">{mediumCount}</span>
            <span className="text-[10px] text-gray-500 mt-1">-5 pts deduction each</span>
          </div>
          <div className="p-4 rounded-lg bg-surface border border-low/20 flex flex-col">
            <span className="text-xs font-mono text-low font-semibold uppercase">LOW</span>
            <span className="text-2xl font-bold font-mono text-white mt-1">{lowCount}</span>
            <span className="text-[10px] text-gray-500 mt-1">-1 pt deduction each</span>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="p-6 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-mono uppercase text-gray-300 font-bold">
            Recent Audit & Security Gate Runs
          </h2>
          <Link
            href="/scans"
            className="text-xs font-mono text-primary hover:underline flex items-center gap-1"
          >
            All Runs <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {loading ? (
          <div className="py-8 text-center font-mono text-xs text-gray-500">Loading audit history...</div>
        ) : scans.length === 0 ? (
          <div className="py-8 text-center font-mono text-xs text-gray-500">
            No scans recorded yet. Trigger a scan from Repositories or Push via GitHub Webhook.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="border-b border-surfaceBorder text-gray-400 uppercase text-[10px]">
                <tr>
                  <th className="pb-3">Scan ID</th>
                  <th className="pb-3">Commit SHA</th>
                  <th className="pb-3">Trigger</th>
                  <th className="pb-3">Status</th>
                  <th className="pb-3">Score</th>
                  <th className="pb-3">Gate Policy</th>
                  <th className="pb-3">Completed At</th>
                  <th className="pb-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surfaceBorder">
                {scans.slice(0, 6).map((scan) => (
                  <tr key={scan.id} className="hover:bg-surfaceHover/50 transition-colors">
                    <td className="py-3.5 text-primary font-bold">{scan.id.substring(0, 8)}...</td>
                    <td className="py-3.5 text-gray-300">{scan.commit_sha.substring(0, 10)}</td>
                    <td className="py-3.5 uppercase text-gray-400">{scan.trigger}</td>
                    <td className="py-3.5">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="py-3.5">
                      <ScoreGauge score={scan.security_score} />
                    </td>
                    <td className="py-3.5">
                      <StatusBadge status={scan.policy_result || "PENDING"} />
                    </td>
                    <td className="py-3.5 text-gray-400">
                      {scan.completed_at ? new Date(scan.completed_at).toLocaleTimeString() : "In Progress"}
                    </td>
                    <td className="py-3.5 text-right">
                      <Link
                        href={`/scans/${scan.id}`}
                        className="px-2.5 py-1 rounded bg-surfaceHover hover:bg-surfaceBorder text-gray-200 border border-surfaceBorder hover:text-white transition-colors"
                      >
                        Details
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
