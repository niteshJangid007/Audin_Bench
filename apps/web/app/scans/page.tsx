"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { FileSearch, Clock, ArrowRight } from "lucide-react";
import { api, Scan } from "@/lib/api-client";
import { StatusBadge } from "@/components/SeverityBadge";
import { ScoreGauge } from "@/components/ScoreGauge";

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScans();
  }, []);

  async function loadScans() {
    try {
      const data = await api.getScans();
      setScans(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-bold font-mono text-white">Security Audit & Gate Runs</h1>
        <p className="text-xs text-gray-400 mt-0.5 font-mono">
          Historical log of all automated scans, policy gate evaluations, and verification runs.
        </p>
      </div>

      {loading ? (
        <div className="p-8 text-center font-mono text-xs text-gray-500">Loading scans...</div>
      ) : scans.length === 0 ? (
        <div className="p-8 text-center font-mono text-xs text-gray-400 rounded-xl bg-cardBg border border-surfaceBorder">
          No audit scans found. Trigger a scan from Repositories or Push via GitHub Webhook.
        </div>
      ) : (
        <div className="rounded-xl bg-cardBg border border-surfaceBorder overflow-hidden shadow-xl">
          <table className="w-full text-left text-xs font-mono">
            <thead className="border-b border-surfaceBorder bg-surface text-gray-400 uppercase text-[10px]">
              <tr>
                <th className="py-3 px-4">Scan Identifier</th>
                <th className="py-3 px-4">Commit SHA</th>
                <th className="py-3 px-4">Trigger</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Score</th>
                <th className="py-3 px-4">Policy Result</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {scans.map((s) => (
                <tr key={s.id} className="hover:bg-surfaceHover/50 transition-colors">
                  <td className="py-3.5 px-4 text-primary font-bold">{s.id.substring(0, 8)}...</td>
                  <td className="py-3.5 px-4 text-gray-300">{s.commit_sha.substring(0, 10)}</td>
                  <td className="py-3.5 px-4 uppercase text-gray-400">{s.trigger}</td>
                  <td className="py-3.5 px-4">
                    <StatusBadge status={s.status} />
                  </td>
                  <td className="py-3.5 px-4">
                    <ScoreGauge score={s.security_score} />
                  </td>
                  <td className="py-3.5 px-4">
                    <StatusBadge status={s.policy_result || "PENDING"} />
                  </td>
                  <td className="py-3.5 px-4 text-gray-400">
                    {s.completed_at ? new Date(s.completed_at).toLocaleString() : "Running..."}
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <Link
                      href={`/scans/${s.id}`}
                      className="px-2.5 py-1 rounded bg-surfaceHover hover:bg-surfaceBorder text-gray-200 border border-surfaceBorder hover:text-white transition-colors"
                    >
                      View Report
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
