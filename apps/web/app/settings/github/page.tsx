"use client";

import { useEffect, useState } from "react";
import { Github, CheckCircle2, ShieldAlert, Key, Webhook, RefreshCw } from "lucide-react";
import { api } from "../../../lib/api-client";

export default function GitHubSettingsPage() {
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [testPayload, setTestPayload] = useState(false);

  useEffect(() => {
    loadStatus();
  }, []);

  async function loadStatus() {
    try {
      const data = await api.getGitHubStatus();
      setStatus(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-bold font-mono text-white">GitHub App Integration</h1>
        <p className="text-xs text-gray-400 mt-0.5 font-mono">
          Connect your GitHub Organization to trigger automated security audits on Pull Requests and Commits.
        </p>
      </div>

      {loading ? (
        <div className="p-8 text-center font-mono text-xs text-gray-500">Checking GitHub App status...</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Connection Status Card */}
          <div className="lg:col-span-2 p-6 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col gap-6 shadow-xl">
            <div className="flex items-center justify-between border-b border-surfaceBorder pb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-surface flex items-center justify-center border border-surfaceBorder">
                  <Github className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h2 className="font-mono font-bold text-sm text-white">Audit Bench GitHub App</h2>
                  <span className="text-[11px] font-mono text-gray-400">
                    App ID: {status?.app_id || "Configured in Environment"}
                  </span>
                </div>
              </div>

              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono bg-success/10 text-success border border-success/30 font-semibold">
                <CheckCircle2 className="w-3.5 h-3.5" /> APP READY
              </span>
            </div>

            {/* Installation Details */}
            <div className="p-4 rounded-lg bg-surface border border-surfaceBorder flex flex-col gap-3 font-mono text-xs">
              <span className="text-gray-400 uppercase text-[10px] font-bold">Connected Organization</span>
              {status?.connected_installation ? (
                <div className="flex items-center justify-between text-gray-200">
                  <div>
                    <span className="text-white font-bold text-sm">
                      {status.connected_installation.account}
                    </span>
                    <span className="text-gray-500 block text-[11px]">
                      Installation ID: {status.connected_installation.id}
                    </span>
                  </div>
                  <span className="text-gray-400 text-[10px]">
                    Installed: {new Date(status.connected_installation.installed_at).toLocaleDateString()}
                  </span>
                </div>
              ) : (
                <span className="text-gray-400">
                  App registered. Ready to receive webhooks from configured repositories.
                </span>
              )}
            </div>

            {/* Webhook Configuration Guide */}
            <div className="flex flex-col gap-3 font-mono text-xs">
              <span className="text-gray-400 uppercase text-[10px] font-bold">Webhook Endpoint Information</span>
              <div className="p-3 rounded-lg bg-background border border-surfaceBorder flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-gray-500">Payload URL:</span>
                  <span className="text-primary font-bold">https://api.auditbench.sec/api/v1/github/webhook</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-500">Content Type:</span>
                  <span className="text-gray-300">application/json</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-500">Secret:</span>
                  <span className="text-gray-300">Configured via GITHUB_WEBHOOK_SECRET (HMAC-SHA256)</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-500">Events:</span>
                  <span className="text-success font-semibold">Push, Pull Request, Installation</span>
                </div>
              </div>
            </div>
          </div>

          {/* Quick Info Sidecard */}
          <div className="p-6 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col gap-4 font-mono text-xs text-gray-300">
            <h3 className="font-bold text-white uppercase text-xs flex items-center gap-2">
              <Key className="w-4 h-4 text-primary" />
              Security Guarantee
            </h3>
            <p className="text-[11px] leading-relaxed text-gray-400 font-sans">
              Audit Bench never clones untrusted repositories with raw git hooks. Commits are fetched as
              ephemeral tar archives via short-lived installation access tokens.
            </p>
            <div className="border-t border-surfaceBorder pt-3 flex flex-col gap-2 text-[11px]">
              <span className="text-primary font-semibold">Check Run Gatekeeper:</span>
              <p className="text-gray-400 font-sans">
                Every Pull Request automatically receives an{" "}
                <span className="text-white font-mono">AUDIT BENCH SECURITY GATE</span> check run with line
                annotations and pass/fail enforcement.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
