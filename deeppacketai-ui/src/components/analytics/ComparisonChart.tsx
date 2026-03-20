import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface ProtocolStat {
  protocol: string;
  flow_count: number;
  success_rate: number;
  error_count: number;
}

const COLORS = [
  "#34d399", // emerald
  "#22d3ee", // cyan
  "#818cf8", // indigo
  "#f59e0b", // amber
  "#f472b6", // pink
  "#a78bfa", // violet
  "#fb923c", // orange
  "#38bdf8", // sky
  "#4ade80", // green
];

export default function ComparisonChart({
  stats,
}: {
  stats: ProtocolStat[];
}) {
  const data = stats.map((s) => ({
    name: s.protocol,
    flows: s.flow_count,
    successRate: s.success_rate,
    errors: s.error_count,
  }));

  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
      <h2 className="text-sm font-medium text-slate-300 mb-4">
        Protocol Flow Comparison
      </h2>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis
              dataKey="name"
              tick={{ fill: "#94a3b8", fontSize: 12 }}
              axisLine={{ stroke: "#475569" }}
            />
            <YAxis
              tick={{ fill: "#94a3b8", fontSize: 12 }}
              axisLine={{ stroke: "#475569" }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1e293b",
                border: "1px solid #475569",
                borderRadius: "8px",
                color: "#e2e8f0",
                fontSize: "12px",
              }}
              formatter={(value: number | undefined, name: string | undefined) => {
                const v = value ?? 0;
                const n = name ?? "";
                if (n === "flows") return [v, "Flows"] as [number, string];
                if (n === "errors") return [v, "Errors"] as [number, string];
                return [v, n] as [number, string];
              }}
            />
            <Bar dataKey="flows" radius={[4, 4, 0, 0]}>
              {data.map((_, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={COLORS[index % COLORS.length]}
                  opacity={0.8}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
