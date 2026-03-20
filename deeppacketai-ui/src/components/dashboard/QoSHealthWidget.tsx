interface QoSHealthWidgetProps {
  avgMos: number;
  qualityGood: number;
  qualityFair: number;
  qualityPoor: number;
  qualityFailed: number;
  totalCalls: number;
}

function mosStatus(mos: number) {
  if (mos >= 4.0) return { label: "Healthy", color: "bg-emerald-400", textColor: "text-emerald-400" };
  if (mos >= 3.5) return { label: "Degraded", color: "bg-amber-400", textColor: "text-amber-400" };
  return { label: "Critical", color: "bg-red-400", textColor: "text-red-400" };
}

export default function QoSHealthWidget({
  avgMos,
  qualityGood,
  qualityFair,
  qualityPoor,
  qualityFailed,
  totalCalls,
}: QoSHealthWidgetProps) {
  const status = mosStatus(avgMos);
  const segments = [
    { count: qualityGood, color: "bg-emerald-500", label: "Good" },
    { count: qualityFair, color: "bg-amber-400", label: "Fair" },
    { count: qualityPoor, color: "bg-orange-500", label: "Poor" },
    { count: qualityFailed, color: "bg-red-500", label: "Failed" },
  ];

  return (
    <div className="space-y-4">
      {/* Top row: status + MOS */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`w-2.5 h-2.5 rounded-full ${status.color}`} />
          <span className={`text-sm font-medium ${status.textColor}`}>
            {status.label}
          </span>
        </div>
        <div className="text-right">
          <span className={`text-3xl font-bold ${status.textColor}`}>
            {avgMos.toFixed(2)}
          </span>
          <span className="text-xs text-slate-400 ml-1">MOS</span>
        </div>
      </div>

      {/* Stacked bar */}
      {totalCalls > 0 && (
        <div className="w-full h-3 rounded-full overflow-hidden flex bg-slate-700">
          {segments.map(
            (seg) =>
              seg.count > 0 && (
                <div
                  key={seg.label}
                  className={`${seg.color} h-full`}
                  style={{ width: `${(seg.count / totalCalls) * 100}%` }}
                />
              ),
          )}
        </div>
      )}

      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-xs text-slate-400">
        {segments.map((seg) => (
          <div key={seg.label} className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${seg.color}`} />
            {seg.label}: <span className="text-slate-200">{seg.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
