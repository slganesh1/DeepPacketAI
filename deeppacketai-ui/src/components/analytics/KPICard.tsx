interface KPI {
  name: string;
  value: number;
  unit: string;
  description: string;
  status: string;
}

const statusColors: Record<string, { border: string; text: string; bg: string }> = {
  good: {
    border: "border-emerald-500/30",
    text: "text-emerald-400",
    bg: "bg-emerald-500/10",
  },
  warning: {
    border: "border-yellow-500/30",
    text: "text-yellow-400",
    bg: "bg-yellow-500/10",
  },
  critical: {
    border: "border-red-500/30",
    text: "text-red-400",
    bg: "bg-red-500/10",
  },
};

export default function KPICard({ kpi }: { kpi: KPI }) {
  const colors = statusColors[kpi.status] || statusColors.good;

  return (
    <div
      className={`${colors.bg} border ${colors.border} rounded-xl p-4 transition-all hover:scale-[1.02]`}
    >
      <div className="text-xs text-slate-400 mb-1 truncate">{kpi.name}</div>
      <div className={`text-2xl font-bold ${colors.text}`}>
        {kpi.value}
        {kpi.unit && (
          <span className="text-sm font-normal ml-1 text-slate-400">
            {kpi.unit}
          </span>
        )}
      </div>
      <div className="text-[10px] text-slate-500 mt-1 truncate">
        {kpi.description}
      </div>
      <div className="mt-2 flex items-center gap-1">
        <div
          className={`w-2 h-2 rounded-full ${
            kpi.status === "good"
              ? "bg-emerald-400"
              : kpi.status === "warning"
                ? "bg-yellow-400"
                : "bg-red-400"
          }`}
        />
        <span className="text-[10px] text-slate-500 capitalize">
          {kpi.status}
        </span>
      </div>
    </div>
  );
}
