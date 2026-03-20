import { useEffect, useState } from "react";
import { api } from "../api/client";
import StatsRow from "../components/dashboard/StatsRow";
import BandwidthChart from "../components/dashboard/BandwidthChart";
import ProtocolPieChart from "../components/dashboard/ProtocolPieChart";
import TopTalkersTable from "../components/dashboard/TopTalkersTable";
import AlertsFeed from "../components/dashboard/AlertsFeed";
import QoSHealthWidget from "../components/dashboard/QoSHealthWidget";

export default function DashboardPage() {
  const [summary, setSummary] = useState<any>({});
  const [protocols, setProtocols] = useState<any[]>([]);
  const [topTalkers, setTopTalkers] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [bandwidth, setBandwidth] = useState<any[]>([]);
  const [report, setReport] = useState<any>(null);

  useEffect(() => {
    api.get("/stats/summary").then((r) => setSummary(r.data)).catch(() => {});
    api.get("/stats/protocols").then((r) => setProtocols(r.data ?? [])).catch(() => {});
    api.get("/stats/top-talkers").then((r) => setTopTalkers(r.data ?? [])).catch(() => {});
    api.get("/alerts?limit=10").then((r) => setAlerts(r.data ?? [])).catch(() => {});
    api.get("/stats/bandwidth").then((r) => setBandwidth(r.data ?? [])).catch(() => {});
    api.get("/analytics/report").then((r) => setReport(r.data ?? null)).catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-sm text-slate-400 mt-1">
          Network traffic overview and analysis
        </p>
      </div>

      <StatsRow
        totalPackets={summary.total_packets || 0}
        protocols={protocols.length}
        activeFlows={report?.total_flows ?? 0}
        alerts={summary.total_alerts || 0}
      />

      {report?.call_summary?.total_calls > 0 && (
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
          <h3 className="text-sm font-medium text-slate-300 mb-4">
            QoS Health
          </h3>
          <QoSHealthWidget
            avgMos={report.call_summary.avg_mos ?? 0}
            qualityGood={report.call_summary.quality_good ?? 0}
            qualityFair={report.call_summary.quality_fair ?? 0}
            qualityPoor={report.call_summary.quality_poor ?? 0}
            qualityFailed={report.call_summary.quality_failed ?? 0}
            totalCalls={report.call_summary.total_calls}
          />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
          <h3 className="text-sm font-medium text-slate-300 mb-4">
            Bandwidth Over Time
          </h3>
          <BandwidthChart data={bandwidth} />
        </div>

        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
          <h3 className="text-sm font-medium text-slate-300 mb-4">
            Protocol Distribution
          </h3>
          <ProtocolPieChart data={protocols} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
          <h3 className="text-sm font-medium text-slate-300 mb-4">
            Top Talkers
          </h3>
          <TopTalkersTable data={topTalkers} />
        </div>

        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
          <h3 className="text-sm font-medium text-slate-300 mb-4">
            Recent Alerts
          </h3>
          <AlertsFeed alerts={alerts} />
        </div>
      </div>
    </div>
  );
}
