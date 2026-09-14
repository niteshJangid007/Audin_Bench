"use client";

import { X, ShieldAlert, CheckCircle2, AlertTriangle, ArrowRight } from "lucide-react";
import { Finding } from "../lib/api-client";
import { SeverityBadge, StatusBadge } from "./SeverityBadge";

interface FindingDrawerProps {
  finding: Finding | null;
  onClose: () => void;
}

export default function FindingDrawer({ finding, onClose }: FindingDrawerProps) {
  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-2xl bg-surface border-l border-surfaceBorder h-full flex flex-col shadow-2xl overflow-hidden animate-in slide-in-from-right duration-200">
        {/* Drawer Header */}
        <div className="p-4 border-b border-surfaceBorder flex items-center justify-between bg-cardBg">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
            {finding.owasp_id && (
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-surfaceBorder text-primary border border-primary/20">
                {finding.owasp_id}
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white p-1 rounded hover:bg-surfaceBorder transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Drawer Content */}
        <div className="p-6 overflow-y-auto flex-1 flex flex-col gap-6">
          <div>
            <span className="text-xs font-mono uppercase text-gray-400">RULE ID: {finding.rule_id}</span>
            <h2 className="text-lg font-bold text-white font-mono mt-1">{finding.title}</h2>
            {finding.file_path && (
              <p className="text-xs font-mono text-primary mt-1">
                📍 {finding.file_path}:{finding.line_start}
              </p>
            )}
          </div>

          {/* Code Evidence */}
          {finding.evidence && (
            <div>
              <h3 className="text-xs font-mono uppercase text-gray-400 mb-2">Vulnerable Code Evidence</h3>
              <div className="bg-background border border-critical/30 rounded-lg p-3 font-mono text-xs text-critical overflow-x-auto">
                <code>{finding.evidence}</code>
              </div>
            </div>
          )}

          {/* Description & Impact */}
          <div className="grid grid-cols-1 gap-4">
            {finding.description && (
              <div className="bg-cardBg p-4 rounded-lg border border-surfaceBorder">
                <h3 className="text-xs font-mono uppercase text-gray-400 mb-1">Vulnerability Analysis</h3>
                <p className="text-xs text-gray-300 leading-relaxed font-sans">{finding.description}</p>
              </div>
            )}
            {finding.impact && (
              <div className="bg-cardBg p-4 rounded-lg border border-surfaceBorder">
                <h3 className="text-xs font-mono uppercase text-gray-400 mb-1">Security Impact</h3>
                <p className="text-xs text-gray-300 leading-relaxed font-sans">{finding.impact}</p>
              </div>
            )}
          </div>

          {/* Suggested Remediation */}
          {finding.remediation && (
            <div>
              <h3 className="text-xs font-mono uppercase text-success mb-2 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-success" />
                Deterministic Remediation Fix
              </h3>
              <div className="bg-background border border-success/30 rounded-lg p-4 font-mono text-xs text-success overflow-x-auto whitespace-pre-wrap">
                <code>{finding.remediation}</code>
              </div>
            </div>
          )}

          {/* Fingerprint & Metadata */}
          <div className="bg-cardBg p-4 rounded-lg border border-surfaceBorder flex flex-col gap-2 font-mono text-[11px] text-gray-400">
            <div>
              <span className="text-gray-500">Scanner Engine:</span> <span className="text-white uppercase">{finding.scanner}</span>
            </div>
            <div>
              <span className="text-gray-500">Confidence:</span> <span className="text-white uppercase">{finding.confidence}</span>
            </div>
            <div className="break-all">
              <span className="text-gray-500">Fingerprint (SHA-256):</span>{" "}
              <span className="text-primary">{finding.fingerprint}</span>
            </div>
          </div>

          {/* Finding History Lifecycle */}
          {finding.history && finding.history.length > 0 && (
            <div>
              <h3 className="text-xs font-mono uppercase text-gray-400 mb-2">Audit History Transitions</h3>
              <div className="flex flex-col gap-2">
                {finding.history.map((h, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 text-xs font-mono p-2 rounded bg-surfaceBorder/40 border border-surfaceBorder"
                  >
                    <span className="text-gray-400">{h.from_status || "NEW"}</span>
                    <ArrowRight className="w-3 h-3 text-primary" />
                    <span className="font-bold text-white">{h.to_status}</span>
                    <span className="text-[10px] text-gray-500 ml-auto">
                      {new Date(h.changed_at).toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
