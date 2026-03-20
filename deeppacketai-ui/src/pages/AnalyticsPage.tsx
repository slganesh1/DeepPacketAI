import { useState, useEffect } from "react";
import { BarChart3, RefreshCw } from "lucide-react";
import { api } from "../api/client";
import KPICard from "../components/analytics/KPICard";
import ComparisonChart from "../components/analytics/ComparisonChart";
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

interface KPI {
  name: string;
  value: number;
  unit: string;
  description: string;
  status: string;
}

interface ProtocolStat {
  protocol: string;
  flow_count: number;
  success_rate: number;
  error_count: number;
}

interface CallSummary {
  total_calls: number;
  success_rate: number;
  avg_mos: number;
  avg_duration_sec: number;
  dropped_calls: number;
  quality_good: number;
  quality_fair: number;
  quality_poor: number;
  quality_failed: number;
}

interface Report {
  generated_at: string;
  duration_seconds: number;
  total_flows: number;
  total_calls: number;
  protocol_breakdown: Record<string, number>;
  kpis: { kpis: KPI[] };
  call_summary: CallSummary;
  protocol_stats: ProtocolStat[];
  root_cause_counts?: Record<string, number>;
}

const ROOT_CAUSE_COLORS = [
  "#ef4444", "#f97316", "#f59e0b", "#eab308",
  "#84cc16", "#22d3ee", "#6366f1", "#a855f7", "#ec4899",
];

export default function AnalyticsPage() {
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);

  const loadReport = async () => {
    setLoading(true);
    try {
      const { data } = await api.get("/analytics/report");
      setReport(data);
    } catch {
      // ignore
    }
    setLoading(false);
  };

  useEffect(() => {
    loadReport();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            Analytics & KPIs
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Telecom performance metrics and analysis
          </p>
        </div>
        <button
          onClick={loadReport}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-sm text-white rounded-lg transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {loading && !report ? (
        <div className="flex items-center justify-center py-20">
          <div className="text-slate-400 text-sm">Loading analytics...</div>
        </div>
      ) : !report ? (
        <div className="flex items-center justify-center py-20">
          <div className="text-slate-500 text-sm">
            No data available. Upload a PCAP or start a live capture first.
          </div>
        </div>
      ) : (
        <>
          {/* KPI Grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            {report.kpis?.kpis?.map((kpi) => (
              <KPICard key={kpi.name} kpi={kpi} />
            ))}
          </div>

          {/* Call Summary */}
          {report.call_summary && report.call_summary.total_calls > 0 && (
            <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
              <h2 className="text-sm font-medium text-slate-300 mb-4">
                Call Quality Distribution
              </h2>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-white">
                    {report.call_summary.total_calls}
                  </div>
                  <div className="text-xs text-slate-400">Total Calls</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-emerald-400">
                    {report.call_summary.quality_good}
                  </div>
                  <div className="text-xs text-slate-400">Good</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-400">
                    {report.call_summary.quality_fair}
                  </div>
                  <div className="text-xs text-slate-400">Fair</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-400">
                    {report.call_summary.quality_poor}
                  </div>
                  <div className="text-xs text-slate-400">Poor</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-400">
                    {report.call_summary.dropped_calls}
                  </div>
                  <div className="text-xs text-slate-400">Dropped</div>
                </div>
              </div>
            </div>
          )}

          {/* Root Cause Distribution */}
          {report.root_cause_counts &&
            Object.keys(report.root_cause_counts).length > 0 && (() => {
              const data = Object.entries(report.root_cause_counts)
                .map(([name, count]) => ({ name, count }))
                .sort((a, b) => b.count - a.count);
              return (
                <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
                  <h2 className="text-sm font-medium text-slate-300 mb-4">
                    Root Cause Distribution
                  </h2>
                  <ResponsiveContainer width="100%" height={Math.max(200, data.length * 40)}>
                    <BarChart layout="vertical" data={data} margin={{ left: 120, right: 20, top: 5, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 12 }} />
                      <YAxis
                        type="category"
                        dataKey="name"
                        tick={{ fill: "#cbd5e1", fontSize: 12 }}
                        width={110}
                      />
                      <Tooltip
                        contentStyle={{ backgroundColor: "#1e293b", border: "1px solid #334155", borderRadius: 8 }}
                        labelStyle={{ color: "#e2e8f0" }}
                        itemStyle={{ color: "#e2e8f0" }}
                      />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                        {data.map((_, idx) => (
                          <Cell key={idx} fill={ROOT_CAUSE_COLORS[idx % ROOT_CAUSE_COLORS.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              );
            })()}

          {/* Protocol Stats Comparison */}
          {report.protocol_stats && report.protocol_stats.length > 0 && (
            <ComparisonChart stats={report.protocol_stats} />
          )}

          {/* Protocol Breakdown Table */}
          {report.protocol_stats && report.protocol_stats.length > 0 && (
            <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-700/50">
                <h2 className="text-sm font-medium text-slate-300">
                  Protocol Breakdown
                </h2>
              </div>
              <table className="w-full">
                <thead>
                  <tr className="text-xs text-slate-400 border-b border-slate-700/30">
                    <th className="text-left px-6 py-3">Protocol</th>
                    <th className="text-right px-6 py-3">Flows</th>
                    <th className="text-right px-6 py-3">Success Rate</th>
                    <th className="text-right px-6 py-3">Errors</th>
                  </tr>
                </thead>
                <tbody>
                  {report.protocol_stats.map((ps) => (
                    <tr
                      key={ps.protocol}
                      className="border-b border-slate-700/20 hover:bg-slate-700/20"
                    >
                      <td className="px-6 py-3 text-sm text-white font-medium">
                        {ps.protocol}
                      </td>
                      <td className="px-6 py-3 text-sm text-slate-300 text-right">
                        {ps.flow_count}
                      </td>
                      <td className="px-6 py-3 text-sm text-right">
                        <span
                          className={
                            ps.success_rate >= 98
                              ? "text-emerald-400"
                              : ps.success_rate >= 95
                                ? "text-yellow-400"
                                : "text-red-400"
                          }
                        >
                          {ps.success_rate}%
                        </span>
                      </td>
                      <td className="px-6 py-3 text-sm text-right">
                        <span
                          className={
                            ps.error_count === 0
                              ? "text-slate-500"
                              : "text-red-400"
                          }
                        >
                          {ps.error_count}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Report Metadata */}
          <div className="text-xs text-slate-500 text-right">
            Report generated at{" "}
            {new Date(report.generated_at).toLocaleString()} | Duration:{" "}
            {report.duration_seconds.toFixed(1)}s | {report.total_flows} flows |{" "}
            {report.total_calls} calls
          </div>
        </>
      )}
    </div>
  );
}
