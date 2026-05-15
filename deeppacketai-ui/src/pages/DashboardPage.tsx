import { useEffect, useState } from "react";
import { Trash2 } from "lucide-react";
import { api } from "../api/client";
import StatsRow from "../components/dashboard/StatsRow";
import BandwidthChart from "../components/dashboard/BandwidthChart";
import ProtocolPieChart from "../components/dashboard/ProtocolPieChart";
import TopTalkersTable from "../components/dashboard/TopTalkersTable";
import AlertsFeed from "../components/dashboard/AlertsFeed";
import QoSHealthWidget from "../components/dashboard/QoSHealthWidget";
import AgentsPanel from "../components/AgentsPanel";

export default function DashboardPage() {
  const [summary, setSummary] = useState<any>({});
  const [protocols, setProtocols] = useState<any[]>([]);
  const [topTalkers, setTopTalkers] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [bandwidth, setBandwidth] = useState<any[]>([]);
  const [report, setReport] = useState<any>(null);
  const [showPurgeConfirm, setShowPurgeConfirm] = useState(false);
  const [purging, setPurging] = useState(false);
  const [purgeMsg, setPurgeMsg] = useState<string | null>(null);

  useEffect(() => {
    loadStats();
  }, []);

  function loadStats() {
    api.get("/stats/summary").then((r) => setSummary(r.data)).catch(() => {});
    api.get("/stats/protocols").then((r) => setProtocols(r.data ?? [])).catch(() => {});
    api.get("/stats/top-talkers").then((r) => setTopTalkers(r.data ?? [])).catch(() => {});
    api.get("/alerts?limit=10").then((r) => setAlerts(r.data ?? [])).catch(() => {});
    api.get("/stats/bandwidth").then((r) => setBandwidth(r.data ?? [])).catch(() => {});
    api.get("/analytics/report").then((r) => setReport(r.data ?? null)).catch(() => {});
  }

  async function handlePurgePackets() {
    setPurging(true);
    setShowPurgeConfirm(false);
    try {
      await api.delete("/jobs/packets");
      setPurgeMsg("Raw packets purged. Flows, events, and job metadata are preserved.");
      loadStats();
    } catch {
      setPurgeMsg("Purge failed. Please try again.");
    } finally {
      setPurging(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-sm text-slate-400 mt-1">Network traffic overview and analysis</p>
        </div>
        <button
          onClick={() => setShowPurgeConfirm(true)}
          disabled={purging}
          className="flex items-center gap-2 px-3 py-2 text-xs text-slate-400 hover:text-red-400 border border-slate-700 hover:border-red-500/40 rounded-lg transition-colors disabled:opacity-40"
          title="Delete all raw packet data (keeps flows & events)"
        >
          <Trash2 className="w-3.5 h-3.5" />
          Purge Raw Packets
        </button>
      </div>

      {/* Purge confirm dialog */}
      {showPurgeConfirm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-sm shadow-xl">
            <h3 className="text-base font-semibold text-white mb-2">Purge Raw Packets?</h3>
            <p className="text-sm text-slate-400 mb-2">
              This deletes ALL raw packet rows from the database across every job.
            </p>
            <p className="text-sm text-emerald-400 mb-5">
              Jobs, flows, events, alerts, and telecom sessions are <strong>kept</strong>. Only packet-level frame data is removed.
            </p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setShowPurgeConfirm(false)}
                className="px-4 py-2 text-sm text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handlePurgePackets}
                className="px-4 py-2 text-sm text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors"
              >
                Purge Packets
              </button>
            </div>
          </div>
        </div>
      )}

      {purgeMsg && (
        <div className="text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-4 py-2 flex items-center justify-between">
          {purgeMsg}
          <button onClick={() => setPurgeMsg(null)} className="text-slate-500 hover:text-white ml-4">✕</button>
        </div>
      )}


      <AgentsPanel />

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
