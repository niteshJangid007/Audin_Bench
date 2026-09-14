"use client";

import { useState } from "react";
import { Terminal, Play, ShieldAlert, CheckCircle2, RotateCcw, AlertTriangle } from "lucide-react";
import { api, Finding } from "../../lib/api-client";
import { SeverityBadge, StatusBadge } from "../../components/SeverityBadge";
import { ScoreGauge } from "../../components/ScoreGauge";
import FindingDrawer from "../../components/FindingDrawer";

const SAMPLE_VULNERABLE_CODE = `// Sample High-Risk Payment Processing Service
const express = require("express");
const crypto = require("crypto");
const app = express();

app.post("/api/checkout", async (req, res) => {
  const { userId, targetWebhook, rawCode } = req.body;

  // A03: SQL Injection Concatenation
  const account = await db.query("SELECT * FROM accounts WHERE id = " + userId);

  // A02: Insecure MD5 Hashing
  const tokenHash = crypto.createHash("md5").update(account.secret).digest("hex");

  // A03: Cross-Site Scripting via innerHTML
  document.getElementById("receipt").innerHTML = "<h3>Order for: " + req.body.customerName + "</h3>";

  // A10: Server-Side Request Forgery (SSRF)
  await fetch(targetWebhook);

  // A03: Dynamic Code Evaluation (RCE)
  eval(rawCode);

  res.json({ status: "processed", hash: tokenHash });
});
`;

export default function SandboxPage() {
  const [code, setCode] = useState(SAMPLE_VULNERABLE_CODE);
  const [language, setLanguage] = useState("javascript");
  const [results, setResults] = useState<any | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleRunScan() {
    setScanning(true);
    setError(null);
    try {
      const res = await api.scanSnippet(code, language);
      setResults(res);
    } catch (err: any) {
      setError(err.message || "Failed to execute scan");
    } finally {
      setScanning(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-surfaceBorder text-primary border border-primary/20">
              DEVELOPER LAB
            </span>
            <span className="text-xs font-mono text-gray-400">SECONDARY DEMO WORKBENCH</span>
          </div>
          <h1 className="text-xl font-bold font-mono text-white mt-1">
            Interactive Code Triage & Rule Sandbox
          </h1>
          <p className="text-xs text-gray-400 mt-0.5 font-mono">
            Directly test deterministic static analysis patterns against snippets before commit.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setCode(SAMPLE_VULNERABLE_CODE)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surfaceHover hover:bg-surfaceBorder text-gray-300 border border-surfaceBorder text-xs font-mono transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Load High-Risk Sample
          </button>
          <button
            onClick={handleRunScan}
            disabled={scanning}
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-critical hover:bg-critical/90 text-white text-xs font-mono font-bold transition-all shadow-lg shadow-critical/20 disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5" />
            {scanning ? "Analyzing AST..." : "Execute Forensic Scan"}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-critical/10 border border-critical/30 font-mono text-xs text-critical">
          {error}
        </div>
      )}

      {/* Editor and Results Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Code Input (7 cols) */}
        <div className="lg:col-span-7 flex flex-col gap-2">
          <div className="flex items-center justify-between px-3 py-2 bg-cardBg border border-surfaceBorder rounded-t-xl font-mono text-xs text-gray-400">
            <span className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-primary" /> Source Code Snippet
            </span>
            <span>{code.split("\n").length} lines</span>
          </div>
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste source code snippet here to inspect for OWASP Top 10 vulnerabilities..."
            rows={18}
            className="w-full bg-cardBg border border-surfaceBorder rounded-b-xl p-4 font-mono text-xs text-gray-100 focus:outline-none focus:border-primary/50 resize-y leading-relaxed"
          />
        </div>

        {/* Real-Time Results Telemetry (5 cols) */}
        <div className="lg:col-span-5 flex flex-col gap-4">
          {results ? (
            <div className="p-6 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col gap-6 shadow-xl animate-in fade-in duration-200">
              {/* Gate Decision Header */}
              <div className="flex items-center justify-between border-b border-surfaceBorder pb-4">
                <div className="flex flex-col">
                  <span className="text-[10px] font-mono uppercase text-gray-400">Score & Policy Gate</span>
                  <div className="flex items-center gap-2 mt-1">
                    <ScoreGauge score={results.security_score} />
                    <StatusBadge status={results.policy_result} />
                  </div>
                </div>

                <div className="flex flex-col items-end">
                  <span className="text-[10px] font-mono uppercase text-gray-400">Total Findings</span>
                  <span className="text-xl font-bold font-mono text-white mt-1">
                    {results.summary.total}
                  </span>
                </div>
              </div>

              {/* Severity Breakdown */}
              <div className="grid grid-cols-4 gap-2 text-center font-mono text-xs">
                <div className="p-2 rounded bg-surface border border-critical/20">
                  <span className="text-[10px] text-critical font-bold block">CRIT</span>
                  <span className="text-base font-bold text-white">{results.summary.critical}</span>
                </div>
                <div className="p-2 rounded bg-surface border border-high/20">
                  <span className="text-[10px] text-high font-bold block">HIGH</span>
                  <span className="text-base font-bold text-white">{results.summary.high}</span>
                </div>
                <div className="p-2 rounded bg-surface border border-medium/20">
                  <span className="text-[10px] text-medium font-bold block">MED</span>
                  <span className="text-base font-bold text-white">{results.summary.medium}</span>
                </div>
                <div className="p-2 rounded bg-surface border border-low/20">
                  <span className="text-[10px] text-low font-bold block">LOW</span>
                  <span className="text-base font-bold text-white">{results.summary.low}</span>
                </div>
              </div>

              {/* Detected Findings List */}
              <div className="flex flex-col gap-2 max-h-[300px] overflow-y-auto pr-1">
                <span className="text-xs font-mono uppercase text-gray-400 font-bold">
                  Detected Vulnerabilities ({results.findings.length})
                </span>
                {results.findings.map((f: Finding) => (
                  <div
                    key={f.finding_id}
                    onClick={() => setSelectedFinding(f)}
                    className="p-3 rounded-lg bg-surface hover:bg-surfaceHover border border-surfaceBorder cursor-pointer transition-colors flex items-center justify-between gap-3"
                  >
                    <div className="flex flex-col min-w-0">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="text-[10px] font-mono text-primary">{f.owasp_id}</span>
                      </div>
                      <span className="text-xs font-mono font-semibold text-white mt-1 truncate">
                        {f.title}
                      </span>
                      {f.line_start && (
                        <span className="text-[10px] font-mono text-gray-500">Line {f.line_start}</span>
                      )}
                    </div>
                    <span className="text-[11px] font-mono text-primary flex-shrink-0">Inspect →</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-cardBg border border-surfaceBorder text-center font-mono text-xs text-gray-500 flex flex-col items-center justify-center h-full min-h-[300px]">
              <Terminal className="w-8 h-8 text-gray-600 mb-2" />
              <span>Paste or edit snippet and click "Execute Forensic Scan" to triage AST patterns.</span>
            </div>
          )}
        </div>
      </div>

      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
