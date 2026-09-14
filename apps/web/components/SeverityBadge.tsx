export function SeverityBadge({ severity }: { severity: string }) {
  const sev = (severity || "").toUpperCase();

  const config: Record<string, { bg: string; text: string; border: string }> = {
    CRITICAL: { bg: "bg-critical/10", text: "text-critical", border: "border-critical/30" },
    HIGH: { bg: "bg-high/10", text: "text-high", border: "border-high/30" },
    MEDIUM: { bg: "bg-medium/10", text: "text-medium", border: "border-medium/30" },
    LOW: { bg: "bg-low/10", text: "text-low", border: "border-low/30" },
  };

  const style = config[sev] || config.MEDIUM;

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase border ${style.bg} ${style.text} ${style.border}`}
    >
      {sev}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const st = (status || "").toUpperCase();

  const config: Record<string, { bg: string; text: string; border: string }> = {
    OPEN: { bg: "bg-critical/10", text: "text-critical", border: "border-critical/30" },
    RESOLVED: { bg: "bg-success/10", text: "text-success", border: "border-success/30" },
    REOPENED: { bg: "bg-high/10", text: "text-high", border: "border-high/30" },
    COMPLETED: { bg: "bg-success/10", text: "text-success", border: "border-success/30" },
    QUEUED: { bg: "bg-gray-500/10", text: "text-gray-400", border: "border-gray-500/30" },
    RUNNING: { bg: "bg-primary/10", text: "text-primary", border: "border-primary/30" },
    FAILED: { bg: "bg-critical/10", text: "text-critical", border: "border-critical/30" },
    CANCELLED: { bg: "bg-gray-500/10", text: "text-gray-400", border: "border-gray-500/30" },
    PASS: { bg: "bg-success/10", text: "text-success", border: "border-success/30" },
    FAIL: { bg: "bg-critical/10", text: "text-critical", border: "border-critical/30" },
  };

  const style = config[st] || { bg: "bg-gray-800", text: "text-gray-300", border: "border-gray-700" };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase border ${style.bg} ${style.text} ${style.border}`}
    >
      {st}
    </span>
  );
}
