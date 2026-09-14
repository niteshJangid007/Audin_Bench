"use client";

import { useEffect, useState } from "react";
import { Sliders, ShieldCheck, Save, Check } from "lucide-react";
import { api, SecurityPolicy } from "../../lib/api-client";

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<SecurityPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<string | null>(null);
  const [savedSuccess, setSavedSuccess] = useState<string | null>(null);

  useEffect(() => {
    loadPolicies();
  }, []);

  async function loadPolicies() {
    try {
      const data = await api.getPolicies();
      setPolicies(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  function handleDefinitionChange(policyId: string, field: string, value: any) {
    setPolicies((prev) =>
      prev.map((p) => {
        if (p.id === policyId) {
          return {
            ...p,
            definition: {
              ...p.definition,
              [field]: value,
            },
          };
        }
        return p;
      })
    );
  }

  async function handleSave(policy: SecurityPolicy) {
    setSavingId(policy.id);
    setSavedSuccess(null);
    try {
      await api.updatePolicy(policy.id, {
        name: policy.name,
        definition: policy.definition,
        is_active: policy.is_active,
      });
      setSavedSuccess(policy.id);
      setTimeout(() => setSavedSuccess(null), 3000);
    } catch (err) {
      console.error(err);
    } finally {
      setSavingId(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-bold font-mono text-white">Security Gate Policies</h1>
        <p className="text-xs text-gray-400 mt-0.5 font-mono">
          Configure deterministic merge gate rules enforced on GitHub pull requests and CI pipelines.
        </p>
      </div>

      {loading ? (
        <div className="p-8 text-center font-mono text-xs text-gray-500">Loading security policies...</div>
      ) : policies.length === 0 ? (
        <div className="p-8 text-center font-mono text-xs text-gray-400 rounded-xl bg-cardBg border border-surfaceBorder">
          No policies configured.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6">
          {policies.map((p) => (
            <div
              key={p.id}
              className="p-6 rounded-xl bg-cardBg border border-surfaceBorder flex flex-col gap-6 shadow-xl"
            >
              <div className="flex items-center justify-between border-b border-surfaceBorder pb-4">
                <div className="flex items-center gap-2">
                  <Sliders className="w-5 h-5 text-primary" />
                  <span className="font-mono font-bold text-base text-white">{p.name}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surfaceBorder text-success border border-success/30">
                    ACTIVE GATE
                  </span>
                </div>

                <button
                  onClick={() => handleSave(p)}
                  disabled={savingId === p.id}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-background text-xs font-mono font-bold transition-all shadow-md"
                >
                  {savedSuccess === p.id ? (
                    <>
                      <Check className="w-3.5 h-3.5" /> Saved!
                    </>
                  ) : (
                    <>
                      <Save className="w-3.5 h-3.5" /> {savingId === p.id ? "Saving..." : "Save Gate Policy"}
                    </>
                  )}
                </button>
              </div>

              {/* Threshold Controls */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
                <div className="p-4 rounded-lg bg-surface border border-surfaceBorder flex flex-col gap-2">
                  <label className="text-xs font-mono uppercase text-gray-300 font-semibold">
                    Minimum Security Score
                  </label>
                  <div className="flex items-center gap-3">
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={p.definition.minimum_score}
                      onChange={(e) =>
                        handleDefinitionChange(p.id, "minimum_score", parseInt(e.target.value))
                      }
                      className="w-full accent-primary cursor-pointer"
                    />
                    <span className="font-mono text-base font-bold text-primary w-12 text-right">
                      {p.definition.minimum_score}
                    </span>
                  </div>
                  <span className="text-[10px] text-gray-500 font-mono">
                    Scans below this score fail the GitHub Check Run.
                  </span>
                </div>

                <div className="p-4 rounded-lg bg-surface border border-surfaceBorder flex flex-col gap-2">
                  <label className="text-xs font-mono uppercase text-gray-300 font-semibold">
                    Max Allowed High Severity
                  </label>
                  <input
                    type="number"
                    min="0"
                    max="50"
                    value={p.definition.max_high}
                    onChange={(e) =>
                      handleDefinitionChange(p.id, "max_high", parseInt(e.target.value) || 0)
                    }
                    className="bg-background border border-surfaceBorder rounded px-3 py-1.5 font-mono text-sm text-white focus:outline-none focus:border-primary"
                  />
                  <span className="text-[10px] text-gray-500 font-mono">
                    Exceeding this count fails the gate.
                  </span>
                </div>

                <div className="p-4 rounded-lg bg-surface border border-surfaceBorder flex flex-col gap-3">
                  <label className="text-xs font-mono uppercase text-gray-300 font-semibold">
                    Strict Gate Rules
                  </label>
                  <div className="flex flex-col gap-2 font-mono text-xs text-gray-300">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={p.definition.fail_on_critical}
                        onChange={(e) =>
                          handleDefinitionChange(p.id, "fail_on_critical", e.target.checked)
                        }
                        className="rounded bg-surface border-surfaceBorder accent-critical w-4 h-4"
                      />
                      <span>Fail immediately on ANY Critical flaw</span>
                    </label>

                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={p.definition.fail_on_secrets}
                        onChange={(e) =>
                          handleDefinitionChange(p.id, "fail_on_secrets", e.target.checked)
                        }
                        className="rounded bg-surface border-surfaceBorder accent-critical w-4 h-4"
                      />
                      <span>Fail on Hardcoded Secrets (Gitleaks)</span>
                    </label>

                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={p.definition.fail_on_new_findings}
                        onChange={(e) =>
                          handleDefinitionChange(p.id, "fail_on_new_findings", e.target.checked)
                        }
                        className="rounded bg-surface border-surfaceBorder accent-high w-4 h-4"
                      />
                      <span>Fail if PR introduces new findings</span>
                    </label>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
