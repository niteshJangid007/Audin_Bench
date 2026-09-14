export function ScoreGauge({ score }: { score: number | null }) {
  if (score === null || score === undefined) {
    return (
      <div className="flex items-center gap-1 font-mono text-gray-400">
        <span>N/A</span>
      </div>
    );
  }

  const getColor = (val: number) => {
    if (val >= 80) return "text-success border-success/30 bg-success/10";
    if (val >= 60) return "text-medium border-medium/30 bg-medium/10";
    return "text-critical border-critical/30 bg-critical/10";
  };

  const getLabel = (val: number) => {
    if (val >= 80) return "LOW RISK";
    if (val >= 60) return "ELEVATED";
    return "HIGH RISK";
  };

  const colorClass = getColor(score);
  const label = getLabel(score);

  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-lg border font-mono ${colorClass}`}>
      <span className="text-xl font-bold">{score}</span>
      <div className="flex flex-col text-[9px] leading-tight opacity-90">
        <span className="font-semibold">/100</span>
        <span className="uppercase tracking-wider">{label}</span>
      </div>
    </div>
  );
}
