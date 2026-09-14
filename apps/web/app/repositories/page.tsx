"use client";

import { useEffect, useState } from "react";
import { GitBranch, Play, ShieldAlert, CheckCircle, Clock } from "lucide-react";
import { api, Repository } from "@/lib/api-client";
import { StatusBadge } from "@/components/SeverityBadge";
import { ScoreGauge } from "@/components/ScoreGauge";

export default function RepositoriesPage() {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggeringId, setTriggeringId] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    loadRepositories();
  }, []);

  async function loadRepositories() {
    try {
      const data = await api.getRepositories();
      setRepos(data);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  async function handleTriggerScan(repoId: string) {
    setTriggeringId(repoId);
    setMsg(null);
    try {
      const res = await api.triggerScan(repoId);
      setMsg(`Scan enqueued successfully! (Scan ID: ${res.scan_id.substring(0, 8)})`);
      await loadRepositories();
    } catch (err: any) {
      setMsg(`Failed to trigger scan: ${err.message}`);
    } finally {
      setTriggeringId(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-white">Tracked Repositories</h1>
          <p className="text-xs text-gray-400 mt-0.5 font-mono">
            Connected repositories monitored by Audit Bench merge gate policies.
          </p>
        </div>
      </div>

      {msg && (
        <div className="p-3 rounded-lg bg-surfaceHover border border-primary/30 font-mono text-xs text-primary">
          {msg}
        </div>
      )}

      {loading ? (
        <div className="p-8 text-center font-mono text-xs text-gray-500">Loading repositories...</div>
      ) : repos.length === 0 ? (
        <div className="p-8 text-center font-mono text-xs text-gray-400 rounded-xl bg-cardBg border border-surfaceBorder">
          No repositories registered yet. Install the GitHub App or submit an event webhook to discover repositories.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {repos.map((repo) => (
            <div
              key={repo.id}
              className="p-5 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-surfaceBorder/80 transition-all shadow-md"
            >
              <div className="flex flex-col gap-1">
                <div className="flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-primary" />
                  <span className="font-mono font-bold text-sm text-white">{repo.full_name}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surfaceBorder text-gray-300">
                    {repo.default_branch}
                  </span>
                </div>
                <span className="text-[11px] font-mono text-gray-500">
                  Registered: {new Date(repo.created_at).toLocaleDateString()}
                </span>
              </div>

              <div className="flex items-center gap-6">
                <div className="flex flex-col items-start md:items-end">
                  <span className="text-[10px] font-mono uppercase text-gray-400">Security Gate</span>
                  <div className="flex items-center gap-2 mt-1">
                    <ScoreGauge score={repo.last_scan?.security_score ?? null} />
                    {repo.last_scan?.policy_result && (
                      <StatusBadge status={repo.last_scan.policy_result} />
                    )}
                  </div>
                </div>

                <button
                  onClick={() => handleTriggerScan(repo.id)}
                  disabled={triggeringId === repo.id}
                  className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-surfaceHover hover:bg-surfaceBorder text-primary border border-primary/30 text-xs font-mono font-semibold transition-all disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5" />
                  {triggeringId === repo.id ? "Auditing..." : "Trigger Audit"}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
