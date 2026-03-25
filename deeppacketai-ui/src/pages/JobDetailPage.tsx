import { useParams, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { fetchJob, fetchJobSummary, fetchJobFlows, fetchJobEvents, reprocessJob } from "../api/jobs";
import { fetchJobEntities } from "../api/entities";
import { api } from "../api/client";
import type { Job, JobSummary, JobFlow, JobEvent } from "../api/jobs";
import type { Entity } from "../api/entities";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, ScatterChart, Scatter } from "recharts";

type Tab = "overview" | "flows" | "events" | "packets" | "reports";

export default function JobDetailPage() {
  const { jobId } = useParams();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("overview");
  const [job, setJob] = useState<Job | null>(null);
  const [summary, setSummary] = useState<JobSummary | null>(null);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [loading, setLoading] = useState(true);

  const numId = Number(jobId);

  const [rfc2544, setRfc2544] = useState<any>(null);
  const [y1564, setY1564] = useState<any>(null);
  const [loadingReports, setLoadingReports] = useState(false);

  useEffect(() => {
    if (!jobId) return;
    setLoading(true);
    Promise.all([
      fetchJob(numId).catch(() => null),
      fetchJobSummary(numId).catch(() => null),
      fetchJobEntities(jobId).catch(() => []),
    ]).then(([j, s, e]) => {
      setJob(j);
      setSummary(s);
      setEntities(e);
      setLoading(false);
    });
  }, [jobId, numId]);

  useEffect(() => {
    if (tab !== "reports" || !jobId) return;
    setLoadingReports(true);
    Promise.all([
      api.get(`/jobs/${jobId}/report/rfc2544`).then(r => r.data).catch(() => null),
      api.get(`/jobs/${jobId}/report/y1564`).then(r => r.data).catch(() => null),
    ]).then(([r, y]) => {
      setRfc2544(r);
      setY1564(y);
      setLoadingReports(false);
    });
  }, [tab, jobId]);

  if (loading) {
    return <div className="p-6 text-slate-400 animate-pulse">Loading job details...</div>;
  }

  const tabs: { key: Tab; label: string }[] = [
    { key: "overview", label: "Overview" },
    { key: "flows", label: "Flows" },
    { key: "events", label: "Events" },
    { key: "packets", label: "Packets" },
    { key: "reports", label: "Reports" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <button
            onClick={() => navigate("/jobs")}
            className="text-xs text-slate-500 hover:text-slate-300 mb-2 inline-flex items-center gap-1"
          >
            &larr; Back to Jobs
          </button>
          <h1 className="text-2xl font-bold text-white">
            {job ? pcapName(job.pcap_path) : `Job ${jobId}`}
          </h1>
          <div className="flex items-center gap-3 mt-1">
            {job && <StatusBadge status={job.status} />}
            {job && (
              <span className="text-sm text-slate-400">
                {formatDuration(job.started_at, job.completed_at)}
              </span>
            )}
            <span className="text-sm text-slate-500">Job #{jobId}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={async () => {
              if (!jobId) return;
              try {
                await reprocessJob(numId);
                setLoading(true);
                setTimeout(() => window.location.reload(), 2000);
              } catch { /* ignore */ }
            }}
            className="px-4 py-2 bg-slate-600 hover:bg-slate-500 text-white text-sm rounded-lg transition-colors"
          >
            Re-analyze
          </button>
          <button
            onClick={() => navigate(`/chat`, { state: { jobId: numId, jobName: job?.pcap_path } })}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg transition-colors"
          >
            Ask AI
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-700/50">
        <nav className="flex gap-1">
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`px-4 py-2.5 text-sm font-medium rounded-t-lg transition-colors ${
                tab === t.key
                  ? "bg-slate-800 text-white border-b-2 border-blue-500"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              {t.label}
              {t.key === "flows" && summary && (
                <span className="ml-1.5 text-xs text-slate-500">({summary.total_flows})</span>
              )}
              {t.key === "events" && summary && (
                <span className="ml-1.5 text-xs text-slate-500">({summary.total_events})</span>
              )}
              {t.key === "packets" && summary && (
                <span className="ml-1.5 text-xs text-slate-500">({summary.total_packets})</span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {tab === "overview" && <OverviewTab summary={summary} entities={entities} navigate={navigate} />}
      {tab === "flows" && <FlowsTab jobId={numId} />}
      {tab === "events" && <EventsTab jobId={numId} />}
      {tab === "packets" && <PacketsTab jobId={numId} />}
      {tab === "reports" && (
        <ReportsTab
          jobId={numId}
          rfc2544={rfc2544}
          y1564={y1564}
          loading={loadingReports}
        />
      )}
    </div>
  );
}

/* ============ Overview Tab ============ */
function OverviewTab({
  summary,
  entities,
  navigate,
}: {
  summary: JobSummary | null;
  entities: Entity[];
  navigate: (path: string) => void;
}) {
  if (!summary) {
    return <div className="text-slate-500 py-8 text-center">No summary data available.</div>;
  }

  const kpiCards = summary.kpis.filter(
    (k) => k.name !== "Active Protocols"
  );

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
        {kpiCards.map((kpi) => (
          <KpiCard key={kpi.name} name={kpi.name} value={kpi.value} unit={kpi.unit} status={kpi.status} />
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Protocol Breakdown */}
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-5">
          <h3 className="text-sm font-medium text-slate-300 mb-4">Protocol Distribution</h3>
          {Object.keys(summary.protocol_breakdown).length === 0 ? (
            <div className="text-slate-500 text-sm">No flows recorded.</div>
          ) : (
            <div className="space-y-2">
              {Object.entries(summary.protocol_breakdown)
                .sort(([, a], [, b]) => b - a)
                .map(([proto, count]) => {
                  const total = summary.total_flows || 1;
                  const pct = ((count / total) * 100).toFixed(1);
                  return (
                    <div key={proto} className="flex items-center gap-3">
                      <span className={`text-xs font-mono w-16 text-right ${protocolColor(proto)}`}>
                        {proto}
                      </span>
                      <div className="flex-1 bg-slate-700/50 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${protocolBg(proto)}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-400 w-16">
                        {count} ({pct}%)
                      </span>
                    </div>
                  );
                })}
            </div>
          )}
        </div>

        {/* Quality Breakdown */}
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-5">
          <h3 className="text-sm font-medium text-slate-300 mb-4">Call Quality Distribution</h3>
          {Object.keys(summary.quality_breakdown).length === 0 ? (
            <div className="text-slate-500 text-sm">No calls recorded.</div>
          ) : (
            <div className="space-y-3">
              {Object.entries(summary.quality_breakdown).map(([quality, count]) => (
                <div key={quality} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`w-3 h-3 rounded-full ${qualityDot(quality)}`} />
                    <span className="text-sm text-slate-300 capitalize">{quality}</span>
                  </div>
                  <span className="text-sm font-medium text-slate-200">{count}</span>
                </div>
              ))}
              <div className="border-t border-slate-700/50 pt-2 flex items-center justify-between">
                <span className="text-sm text-slate-400">Avg MOS</span>
                <span className={`text-lg font-bold ${mosColor(summary.avg_mos)}`}>
                  {summary.avg_mos > 0 ? summary.avg_mos.toFixed(2) : "-"}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Calls Table */}
      <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-5">
        <h3 className="text-sm font-medium text-slate-300 mb-4">
          Calls ({entities.length})
        </h3>
        {entities.length === 0 ? (
          <div className="text-slate-500 text-sm">No calls detected in this job.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 uppercase tracking-wider border-b border-slate-700/50">
                  <th className="pb-2 pr-4">Call ID</th>
                  <th className="pb-2 pr-4">MOS</th>
                  <th className="pb-2 pr-4">Quality</th>
                  <th className="pb-2 pr-4">Root Cause</th>
                  <th className="pb-2">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/30">
                {entities.map((e) => (
                  <tr
                    key={e.entity_id}
                    className="hover:bg-slate-700/30 cursor-pointer transition-colors"
                    onClick={() => navigate(`/entities/${e.entity_id}`)}
                  >
                    <td className="py-2.5 pr-4 font-mono text-xs text-slate-300">
                      {e.entity_id.replace("call:", "")}
                    </td>
                    <td className={`py-2.5 pr-4 font-medium ${mosColor(e.summary?.mos ?? 0)}`}>
                      {e.summary?.mos?.toFixed(2) ?? "-"}
                    </td>
                    <td className="py-2.5 pr-4">
                      <QualityBadge quality={e.summary?.quality} />
                    </td>
                    <td className="py-2.5 pr-4 text-slate-400">
                      {e.summary?.root_cause ?? "-"}
                    </td>
                    <td className="py-2.5 text-slate-400">
                      {e.summary?.confidence != null
                        ? `${(e.summary.confidence * 100).toFixed(0)}%`
                        : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/* ============ Flows Tab ============ */
function FlowsTab({ jobId }: { jobId: number }) {
  const [flows, setFlows] = useState<JobFlow[]>([]);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState("");
  const [expandedFlow, setExpandedFlow] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    fetchJobFlows(jobId, typeFilter || undefined)
      .then(setFlows)
      .catch(() => setFlows([]))
      .finally(() => setLoading(false));
  }, [jobId, typeFilter]);

  const types = ["", "SIP", "RTP", "DNS", "HTTP", "TLS", "TCP", "UDP", "Diameter", "GTP", "PFCP", "S1AP", "NGAP", "SCTP", "WebSocket"];

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-slate-500">Filter by protocol:</span>
        <div className="flex gap-1.5 flex-wrap">
          {types.map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-2.5 py-1 text-xs rounded-lg transition-colors ${
                typeFilter === t
                  ? "bg-blue-600 text-white"
                  : "bg-slate-700/50 text-slate-400 hover:text-slate-200"
              }`}
            >
              {t || "All"}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="text-slate-400 text-sm py-8 text-center animate-pulse">Loading flows...</div>
      ) : flows.length === 0 ? (
        <div className="text-slate-500 text-sm py-8 text-center">No flows found.</div>
      ) : (
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 uppercase tracking-wider border-b border-slate-700/50">
                  <th className="p-3">Type</th>
                  <th className="p-3">Source</th>
                  <th className="p-3">Destination</th>
                  <th className="p-3">Time</th>
                  <th className="p-3">Key Metric</th>
                  <th className="p-3">Subscriber</th>
                  <th className="p-3">SLA</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/30">
                {flows.map((f) => {
                  const isExpanded = expandedFlow === f.flow_id;
                  const m = f.metrics || {};
                  const slaVerdict = (m.sla_verdict as string) || "";
                  const slaScore = m.sla_score as number | undefined;

                  return (
                    <>
                      <tr
                        key={f.flow_id}
                        className="hover:bg-slate-700/30 transition-colors cursor-pointer"
                        onClick={() => setExpandedFlow(isExpanded ? null : f.flow_id)}
                      >
                        <td className="p-3">
                          <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${protocolBadge(f.type)}`}>
                            {f.type}
                          </span>
                        </td>
                        <td className="p-3 font-mono text-xs text-slate-300">
                          {f.src_ip}:{f.src_port}
                        </td>
                        <td className="p-3 font-mono text-xs text-slate-300">
                          {f.dst_ip}:{f.dst_port}
                        </td>
                        <td className="p-3 text-xs text-slate-400">
                          {formatTime(f.start_time)}
                        </td>
                        <td className="p-3 text-xs text-slate-400">
                          {flowKeyMetric(f)}
                        </td>
                        <td className="p-3 text-xs text-slate-400 font-mono">
                          {flowSubscriberInfo(f) || "-"}
                        </td>
                        <td className="p-3">
                          {slaVerdict ? (
                            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${slaColor(slaVerdict)}`}>
                              {slaVerdict}
                              {slaScore !== undefined && <span className="opacity-60">·{slaScore}</span>}
                            </span>
                          ) : "-"}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr key={`${f.flow_id}-detail`} className="bg-slate-900/60">
                          <td colSpan={7} className="p-4">
                            <FlowDetail flow={f} />
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

/* ============ Flow Detail Panel ============ */
function FlowDetail({ flow }: { flow: JobFlow }) {
  const m = flow.metrics || {};
  const throughputTrend = m.throughput_trend as {t:number,bps:number}[] | undefined;
  const rttSamples = m.rtt_samples as {t:number,ms:number}[] | undefined;
  const jitterTrend = m.jitter_trend as {i:number,ms:number}[] | undefined;
  const slaDetails = m.sla_details as string[] | undefined;

  const fmtBps = (v: number) => v >= 1_000_000 ? `${(v/1_000_000).toFixed(1)}Mbps` : v >= 1000 ? `${(v/1000).toFixed(1)}Kbps` : `${v}bps`;

  const keyMetrics: {label: string; value: string}[] = [];
  if (m.duration_ms !== undefined) keyMetrics.push({ label: "Duration", value: `${m.duration_ms}ms` });
  if (m.packets !== undefined) keyMetrics.push({ label: "Packets", value: String(m.packets) });
  if (m.bytes !== undefined) keyMetrics.push({ label: "Bytes", value: String(m.bytes) });
  if (m.throughput_bps !== undefined) keyMetrics.push({ label: "Throughput", value: fmtBps(m.throughput_bps as number) });
  if (m.rtt_ms !== undefined) keyMetrics.push({ label: "RTT", value: `${m.rtt_ms}ms` });
  if (m.handshake_rtt_ms !== undefined) keyMetrics.push({ label: "Handshake RTT", value: `${m.handshake_rtt_ms}ms` });
  if (m.retransmissions !== undefined) keyMetrics.push({ label: "Retransmissions", value: String(m.retransmissions) });
  if (m.packet_loss_pct !== undefined) keyMetrics.push({ label: "Packet Loss", value: `${m.packet_loss_pct}%` });
  if (m.close_reason !== undefined) keyMetrics.push({ label: "Close Reason", value: m.close_reason as string });
  if (m.jitter_ms !== undefined) keyMetrics.push({ label: "Jitter", value: `${(m.jitter_ms as number).toFixed(1)}ms` });
  if (m.loss_rate_pct !== undefined) keyMetrics.push({ label: "Loss Rate", value: `${m.loss_rate_pct}%` });
  if (m.packet_count !== undefined) keyMetrics.push({ label: "RTP Packets", value: String(m.packet_count) });
  if (m.tcp_flags !== undefined) keyMetrics.push({ label: "TCP Flags", value: m.tcp_flags as string });

  return (
    <div className="space-y-4">
      {/* Key metrics grid */}
      {keyMetrics.length > 0 && (
        <div className="grid grid-cols-3 md:grid-cols-5 gap-3">
          {keyMetrics.map(({ label, value }) => (
            <div key={label} className="bg-slate-800/60 rounded-lg p-2.5">
              <div className="text-[10px] text-slate-500 uppercase tracking-wide mb-0.5">{label}</div>
              <div className="text-xs font-mono text-slate-200">{value}</div>
            </div>
          ))}
        </div>
      )}

      {/* SLA details */}
      {slaDetails && slaDetails.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {slaDetails.map((d, i) => (
            <span key={i} className="text-xs text-slate-400 bg-slate-700/40 rounded px-2 py-1">{d}</span>
          ))}
        </div>
      )}

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

        {/* Throughput trend */}
        {throughputTrend && throughputTrend.length > 1 && (
          <div className="bg-slate-800/60 rounded-lg p-3">
            <div className="text-xs text-slate-400 mb-2 font-medium">Throughput Trend</div>
            <ResponsiveContainer width="100%" height={100}>
              <AreaChart data={throughputTrend} margin={{ top: 2, right: 4, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="tpGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#34d399" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#34d399" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" tick={{ fontSize: 9, fill: "#64748b" }} tickFormatter={v => `${v}s`} />
                <YAxis tick={{ fontSize: 9, fill: "#64748b" }} tickFormatter={v => v >= 1000 ? `${(v/1000).toFixed(0)}K` : v} width={36} />
                <Tooltip
                  contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 6, fontSize: 11 }}
                  formatter={(v: number | undefined) => [fmtBps(v ?? 0), "bps"]}
                  labelFormatter={l => `t=${l}s`}
                />
                <Area type="monotone" dataKey="bps" stroke="#34d399" strokeWidth={1.5} fill="url(#tpGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* RTT samples (TCP) */}
        {rttSamples && rttSamples.length > 1 && (
          <div className="bg-slate-800/60 rounded-lg p-3">
            <div className="text-xs text-slate-400 mb-2 font-medium">RTT Samples</div>
            <ResponsiveContainer width="100%" height={100}>
              <ScatterChart margin={{ top: 2, right: 4, left: 0, bottom: 0 }}>
                <XAxis dataKey="t" type="number" tick={{ fontSize: 9, fill: "#64748b" }} tickFormatter={v => `${v}s`} name="time" />
                <YAxis dataKey="ms" type="number" tick={{ fontSize: 9, fill: "#64748b" }} tickFormatter={v => `${v}`} width={36} name="ms" />
                <Tooltip
                  contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 6, fontSize: 11 }}
                  formatter={(v: number | undefined, name: string | undefined) => [name === "ms" ? `${v ?? 0}ms` : `${v ?? 0}s`, name === "ms" ? "RTT" : "Time"]}
                />
                <Scatter data={rttSamples} fill="#60a5fa" opacity={0.8} />
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Jitter trend (RTP) */}
        {jitterTrend && jitterTrend.length > 1 && (
          <div className="bg-slate-800/60 rounded-lg p-3">
            <div className="text-xs text-slate-400 mb-2 font-medium">Jitter Trend</div>
            <ResponsiveContainer width="100%" height={100}>
              <AreaChart data={jitterTrend} margin={{ top: 2, right: 4, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="jitGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="i" tick={{ fontSize: 9, fill: "#64748b" }} />
                <YAxis tick={{ fontSize: 9, fill: "#64748b" }} tickFormatter={v => `${v}`} width={36} />
                <Tooltip
                  contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 6, fontSize: 11 }}
                  formatter={(v: number | undefined) => [`${(v ?? 0).toFixed(1)}ms`, "Jitter"]}
                />
                <Area type="monotone" dataKey="ms" stroke="#f59e0b" strokeWidth={1.5} fill="url(#jitGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}

function slaColor(verdict: string) {
  switch (verdict) {
    case "good":       return "text-emerald-400 bg-emerald-500/10 border border-emerald-500/20";
    case "acceptable": return "text-yellow-400 bg-yellow-500/10 border border-yellow-500/20";
    case "poor":       return "text-orange-400 bg-orange-500/10 border border-orange-500/20";
    case "critical":   return "text-red-400 bg-red-500/10 border border-red-500/20";
    default:           return "text-slate-400 bg-slate-700/30";
  }
}

/* ============ Events Tab ============ */
function EventsTab({ jobId }: { jobId: number }) {
  const navigate = useNavigate();
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedEventId, setExpandedEventId] = useState<number | null>(null);

  useEffect(() => {
    setLoading(true);
    fetchJobEvents(jobId)
      .then(setEvents)
      .catch(() => setEvents([]))
      .finally(() => setLoading(false));
  }, [jobId]);

  return (
    <div>
      {loading ? (
        <div className="text-slate-400 text-sm py-8 text-center animate-pulse">Loading events...</div>
      ) : events.length === 0 ? (
        <div className="text-slate-500 text-sm py-8 text-center">No events found for this job.</div>
      ) : (
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 uppercase tracking-wider border-b border-slate-700/50">
                  <th className="p-3">Severity</th>
                  <th className="p-3">Protocol</th>
                  <th className="p-3">Title</th>
                  <th className="p-3">Description</th>
                  <th className="p-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/30">
                {events.map((e) => {
                  const isExpanded = expandedEventId === e.id;
                  return (
                    <tr
                      key={e.id}
                      className="hover:bg-slate-700/30 cursor-pointer transition-colors"
                      onClick={() => setExpandedEventId(isExpanded ? null : e.id)}
                    >
                      <td className="p-3 align-top">
                        <SeverityBadge severity={e.severity} />
                      </td>
                      <td className="p-3 align-top">
                        <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${protocolBadge(e.protocol)}`}>
                          {e.protocol}
                        </span>
                      </td>
                      <td className="p-3 text-slate-200 font-medium align-top">{e.title}</td>
                      <td className="p-3 text-slate-400 max-w-md align-top" title={e.description}>
                        {isExpanded ? (
                          <div className="space-y-2">
                            <p>{e.description}</p>

                            {e.metadata_json && (() => {
                              try {
                                const meta = typeof e.metadata_json === "string"
                                  ? JSON.parse(e.metadata_json)
                                  : e.metadata_json;
                                const entries = Object.entries(meta);
                                if (entries.length === 0) return null;
                                return (
                                  <div className="border-t border-slate-700/40 pt-2">
                                    <span className="text-xs font-medium text-slate-500">Metadata</span>
                                    <div className="mt-1 grid grid-cols-2 gap-x-4 gap-y-1">
                                      {entries.map(([key, val]) => (
                                        <div key={key} className="flex gap-2 text-xs">
                                          <span className="text-slate-500">{key}:</span>
                                          <span className="text-slate-300">{String(val)}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                );
                              } catch {
                                return null;
                              }
                            })()}

                            {e.packet_id && (
                              <div className="pt-1">
                                <button
                                  onClick={(ev) => { ev.stopPropagation(); navigate(`/packets?id=${e.packet_id}`); }}
                                  className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                                >
                                  View Packet #{e.packet_id}
                                </button>
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="truncate block">{e.description}</span>
                        )}
                      </td>
                      <td className="p-3 text-xs text-slate-500 whitespace-nowrap align-top">
                        {formatTime(e.timestamp)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

/* ============ Packets Tab ============ */
function PacketsTab({ jobId }: { jobId: number }) {
  const [packets, setPackets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [protocolFilter, setProtocolFilter] = useState("");

  useEffect(() => {
    setLoading(true);
    const params: Record<string, string> = { job_id: String(jobId), limit: "500" };
    if (protocolFilter) params.protocol = protocolFilter;

    api
      .get("/packets", { params })
      .then((r) => setPackets(r.data ?? []))
      .catch(() => setPackets([]))
      .finally(() => setLoading(false));
  }, [jobId, protocolFilter]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-xs text-slate-500">Filter by protocol:</span>
        <input
          type="text"
          placeholder="e.g. SIP, RTP, DNS..."
          value={protocolFilter}
          onChange={(e) => setProtocolFilter(e.target.value)}
          className="bg-slate-700/50 border border-slate-600/50 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-48"
        />
      </div>

      {loading ? (
        <div className="text-slate-400 text-sm py-8 text-center animate-pulse">Loading packets...</div>
      ) : packets.length === 0 ? (
        <div className="text-slate-500 text-sm py-8 text-center">No packets found.</div>
      ) : (
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 uppercase tracking-wider border-b border-slate-700/50">
                  <th className="p-3">#</th>
                  <th className="p-3">Time</th>
                  <th className="p-3">Source</th>
                  <th className="p-3">Destination</th>
                  <th className="p-3">Protocol</th>
                  <th className="p-3">Length</th>
                  <th className="p-3">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/30">
                {packets.map((p: any) => (
                  <tr key={p.id} className="hover:bg-slate-700/30 transition-colors">
                    <td className="p-3 text-xs text-slate-500">{p.frame_number}</td>
                    <td className="p-3 text-xs text-slate-400 whitespace-nowrap">
                      {formatTime(p.timestamp)}
                    </td>
                    <td className="p-3 font-mono text-xs text-slate-300">
                      {p.src_ip}:{p.src_port}
                    </td>
                    <td className="p-3 font-mono text-xs text-slate-300">
                      {p.dst_ip}:{p.dst_port}
                    </td>
                    <td className="p-3">
                      <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${protocolBadge(p.app_protocol || p.protocol)}`}>
                        {p.app_protocol || p.protocol}
                      </span>
                    </td>
                    <td className="p-3 text-xs text-slate-400">{p.length}</td>
                    <td className="p-3 text-xs text-slate-400 max-w-xs truncate" title={p.summary}>
                      {p.summary}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {packets.length >= 500 && (
            <div className="text-center text-xs text-slate-500 py-3 border-t border-slate-700/50">
              Showing first 500 packets.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ============ Shared Components & Helpers ============ */

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { bg: string; text: string }> = {
    completed: { bg: "bg-emerald-500/20", text: "text-emerald-400" },
    running: { bg: "bg-amber-500/20", text: "text-amber-400" },
    failed: { bg: "bg-red-500/20", text: "text-red-400" },
    pending: { bg: "bg-slate-500/20", text: "text-slate-400" },
  };
  const c = config[status] || config.pending;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${c.bg} ${c.text}`}>
      {status === "running" && (
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mr-1.5 animate-pulse" />
      )}
      {status}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const config: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400",
    error: "bg-orange-500/20 text-orange-400",
    warning: "bg-amber-500/20 text-amber-400",
    info: "bg-blue-500/20 text-blue-400",
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${config[severity] || config.info}`}>
      {severity}
    </span>
  );
}

function QualityBadge({ quality }: { quality?: string }) {
  if (!quality) return <span className="text-slate-500">-</span>;
  const config: Record<string, string> = {
    good: "bg-emerald-500/20 text-emerald-400",
    fair: "bg-amber-500/20 text-amber-400",
    poor: "bg-orange-500/20 text-orange-400",
    bad: "bg-red-500/20 text-red-400",
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium capitalize ${config[quality] || "bg-slate-500/20 text-slate-400"}`}>
      {quality}
    </span>
  );
}

function KpiCard({ name, value, unit, status }: { name: string; value: number; unit: string; status: string }) {
  const statusColor: Record<string, string> = {
    good: "text-emerald-400",
    warning: "text-amber-400",
    critical: "text-red-400",
  };
  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
      <div className="text-xs text-slate-500 truncate">{name}</div>
      <div className={`text-xl font-bold mt-1 ${statusColor[status] || "text-slate-200"}`}>
        {value > 0 ? value : "-"}
        {value > 0 && unit && <span className="text-xs ml-1 font-normal text-slate-500">{unit}</span>}
      </div>
    </div>
  );
}

function pcapName(path: string): string {
  if (!path) return "Unknown source";
  const parts = path.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || path;
}

function formatDuration(startedAt: string, completedAt?: string): string {
  if (!startedAt) return "-";
  const start = new Date(startedAt).getTime();
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  const diffMs = end - start;
  if (diffMs < 1000) return `${diffMs}ms`;
  if (diffMs < 60000) return `${(diffMs / 1000).toFixed(1)}s`;
  return `${(diffMs / 60000).toFixed(1)}m`;
}

function formatTime(ts: string): string {
  if (!ts) return "-";
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return ts;
  }
}

function protocolColor(proto: string): string {
  const colors: Record<string, string> = {
    SIP: "text-blue-400",
    RTP: "text-purple-400",
    DNS: "text-cyan-400",
    HTTP: "text-emerald-400",
    TLS: "text-lime-400",
    HTTPS: "text-lime-400",
    Diameter: "text-orange-400",
    GTP: "text-yellow-400",
    PFCP: "text-pink-400",
    S1AP: "text-teal-400",
    NGAP: "text-indigo-400",
    SCTP: "text-slate-400",
  };
  return colors[proto] || "text-slate-400";
}

function protocolBg(proto: string): string {
  const colors: Record<string, string> = {
    SIP: "bg-blue-500",
    RTP: "bg-purple-500",
    DNS: "bg-cyan-500",
    HTTP: "bg-emerald-500",
    TLS: "bg-lime-500",
    HTTPS: "bg-lime-500",
    Diameter: "bg-orange-500",
    GTP: "bg-yellow-500",
    PFCP: "bg-pink-500",
    S1AP: "bg-teal-500",
    NGAP: "bg-indigo-500",
    SCTP: "bg-slate-500",
  };
  return colors[proto] || "bg-slate-500";
}

function protocolBadge(proto: string): string {
  const colors: Record<string, string> = {
    SIP: "bg-blue-500/20 text-blue-400",
    RTP: "bg-purple-500/20 text-purple-400",
    DNS: "bg-cyan-500/20 text-cyan-400",
    HTTP: "bg-emerald-500/20 text-emerald-400",
    TLS: "bg-lime-500/20 text-lime-400",
    HTTPS: "bg-lime-500/20 text-lime-400",
    Diameter: "bg-orange-500/20 text-orange-400",
    GTP: "bg-yellow-500/20 text-yellow-400",
    PFCP: "bg-pink-500/20 text-pink-400",
    S1AP: "bg-teal-500/20 text-teal-400",
    NGAP: "bg-indigo-500/20 text-indigo-400",
    SCTP: "bg-slate-500/20 text-slate-400",
  };
  return colors[proto] || "bg-slate-500/20 text-slate-400";
}

function qualityDot(quality: string): string {
  const colors: Record<string, string> = {
    good: "bg-emerald-400",
    fair: "bg-amber-400",
    poor: "bg-orange-400",
    bad: "bg-red-400",
  };
  return colors[quality] || "bg-slate-400";
}

function mosColor(mos: number): string {
  if (mos >= 4.0) return "text-emerald-400";
  if (mos >= 3.5) return "text-amber-400";
  if (mos > 0) return "text-red-400";
  return "text-slate-500";
}

function flowSubscriberInfo(f: JobFlow): string {
  const m = f.metrics;
  if (!m) return "";
  const imsi = m.imsi as string || "";
  const msisdn = m.msisdn as string || "";
  const mei = m.mei as string || "";
  const parts = [imsi, msisdn].filter(Boolean);
  if (mei) parts.push(`IMEI:${mei}`);
  return parts.join(" / ");
}

function flowKeyMetric(f: JobFlow): string {
  const m = f.metrics;
  if (!m) return "-";

  switch (f.type) {
    case "SIP": {
      const method = m.method as string || "";
      const resp = m.response as string || "";
      let base = [method, resp].filter(Boolean).join(" ") || "-";
      const latency = m.setup_latency_ms as number | undefined;
      if (latency != null) {
        base += ` | setup: ${latency >= 1000 ? `${(latency / 1000).toFixed(1)}s` : `${Math.round(latency)}ms`}`;
      }
      return base;
    }
    case "RTP": {
      const jitter = m.jitter_ms;
      const pkts = m.packet_count;
      const parts: string[] = [];
      if (pkts != null) parts.push(`${pkts} pkts`);
      if (jitter != null) parts.push(`${jitter}ms jitter`);
      return parts.join(", ") || "-";
    }
    case "DNS": {
      const name = m.query_name as string || "";
      const rcode = m.reply_code as string || "";
      let base = [name, rcode].filter(Boolean).join(" ") || "-";
      const latency = m.latency_ms as number | undefined;
      if (latency != null) {
        base += ` | ${latency >= 1000 ? `${(latency / 1000).toFixed(1)}s` : `${latency.toFixed(1)}ms`}`;
      }
      return base;
    }
    case "HTTP": {
      const method = m.method as string || "";
      const status = m.status_code;
      const uri = m.uri as string || "";
      const host = m.host as string || "";
      const ct = m.content_type as string || "";
      const parts = [method, uri, status != null ? `(${status})` : ""];
      if (host) parts.push(`Host:${host}`);
      if (ct) parts.push(ct.split(";")[0]);
      return parts.filter(Boolean).join(" ") || "-";
    }
    case "TLS": {
      const sni = m.sni as string || "";
      const ver = m.tls_version as string || "";
      const cipher = m.cipher_suite as string || "";
      const alpn = m.alpn as string || "";
      const parts: string[] = [];
      if (sni) parts.push(sni);
      if (ver) parts.push(`[${ver}]`);
      if (cipher) parts.push(cipher);
      if (alpn) parts.push(`ALPN:${alpn}`);
      return parts.join(" ") || "-";
    }
    case "Diameter": {
      const cmd = m.command as string || "";
      const rc = m.result_code;
      const imsi = m.imsi as string || "";
      const msisdn = m.msisdn as string || "";
      return [cmd, rc != null ? `RC:${rc}` : "", imsi ? `IMSI:${imsi}` : "", msisdn ? `MSISDN:${msisdn}` : ""].filter(Boolean).join(" ") || "-";
    }
    case "GTP": {
      const msgType = m.message_type as string || "";
      const teid = m.teid;
      const imsi = m.imsi as string || "";
      const apn = m.apn as string || "";
      const rat = m.rat_type as string || "";
      const pdnType = m.pdn_type as string || "";
      const pdnAddr = m.pdn_address as string || "";
      const bearers = m.bearers as any[] | undefined;
      const parts = [msgType, teid != null ? `TEID:${teid}` : ""];
      if (imsi) parts.push(`IMSI:${imsi}`);
      if (apn) parts.push(`APN:${apn}`);
      if (rat) parts.push(`RAT:${rat}`);
      if (pdnType) parts.push(pdnType);
      if (pdnAddr) parts.push(`IP:${pdnAddr}`);
      if (bearers && bearers.length > 0) {
        const b = bearers[0];
        if (b.qci) parts.push(`QCI:${b.qci}`);
        if (b.qci_name) parts.push(`(${b.qci_name})`);
      }
      return parts.filter(Boolean).join(" ") || "-";
    }
    case "PFCP": {
      const msgType = m.message_type as string || "";
      return msgType || "-";
    }
    case "S1AP":
    case "NGAP": {
      const proc = m.procedure_name as string || "";
      const imsi = m.imsi as string || "";
      return [proc, imsi ? `IMSI:${imsi}` : ""].filter(Boolean).join(" ") || "-";
    }
    default:
      return "-";
  }
}

/* ============ Reports Tab ============ */

function ReportsTab({ jobId, rfc2544, y1564, loading }: { jobId: number; rfc2544: any; y1564: any; loading: boolean }) {
  const [thresholds, setThresholds] = useState({ latency_ms: '', jitter_ms: '', loss_pct: '' });
  const [customY1564, setCustomY1564] = useState<any>(null);
  const [applyingThresholds, setApplyingThresholds] = useState(false);
  const applyThresholds = async () => {
    setApplyingThresholds(true);
    try {
      const params = new URLSearchParams();
      if (thresholds.latency_ms) params.set('latency_ms', thresholds.latency_ms);
      if (thresholds.jitter_ms) params.set('jitter_ms', thresholds.jitter_ms);
      if (thresholds.loss_pct) params.set('loss_pct', thresholds.loss_pct);
      const { api } = await import('../api/client');
      const res = await api.get(`/jobs/${jobId}/report/y1564?${params.toString()}`);
      setCustomY1564(res.data);
    } catch { /* keep previous */ }
    setApplyingThresholds(false);
  };

  const downloadCDR = () => { window.open(`/api/v1/jobs/${jobId}/cdr`, '_blank'); };

  if (loading) {
    return <div className="p-8 text-slate-400 text-sm text-center animate-pulse">Generating reports...</div>;
  }

  const activeY1564 = customY1564 ?? y1564;

  return (
    <div className="p-6 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white">Test &amp; Measurement Reports</h2>
          <p className="text-xs text-slate-400 mt-0.5">RFC 2544 · Y.1564 SAT · CDR Export</p>
        </div>
        <button
          onClick={downloadCDR}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-400 text-sm font-medium transition-all"
        >
          ↓ Download CDR (CSV)
        </button>
      </div>

      {/* RFC 2544 */}
      {rfc2544 && <RFC2544Section data={rfc2544} />}

      {/* Y.1564 threshold editor */}
      <div className="bg-slate-800/40 border border-slate-700/40 rounded-xl p-4">
        <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
          Y.1564 Custom Thresholds <span className="normal-case text-slate-600">(leave blank to use ITU-T defaults)</span>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          {[
            { key: 'latency_ms', label: 'Max Latency (ms)', placeholder: 'e.g. 50' },
            { key: 'jitter_ms', label: 'Max Jitter (ms)', placeholder: 'e.g. 20' },
            { key: 'loss_pct', label: 'Max Loss (%)', placeholder: 'e.g. 0.1' },
          ].map(({ key, label, placeholder }) => (
            <div key={key}>
              <div className="text-[10px] text-slate-500 mb-1">{label}</div>
              <input
                type="number"
                min="0"
                step="any"
                placeholder={placeholder}
                value={thresholds[key as keyof typeof thresholds]}
                onChange={e => setThresholds(prev => ({ ...prev, [key]: e.target.value }))}
                className="w-32 px-3 py-1.5 bg-slate-900/60 border border-slate-700/50 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-violet-500/60"
              />
            </div>
          ))}
          <button
            onClick={applyThresholds}
            disabled={applyingThresholds}
            className="px-4 py-1.5 bg-violet-600/30 hover:bg-violet-600/50 border border-violet-500/30 text-violet-300 text-xs rounded-lg transition-all disabled:opacity-50"
          >
            {applyingThresholds ? 'Applying…' : 'Apply'}
          </button>
          {customY1564 && (
            <button
              onClick={() => { setCustomY1564(null); setThresholds({ latency_ms: '', jitter_ms: '', loss_pct: '' }); }}
              className="px-3 py-1.5 text-slate-500 hover:text-slate-300 text-xs"
            >
              Reset
            </button>
          )}
        </div>
      </div>

      {/* Y.1564 */}
      {activeY1564 && <Y1564Section data={activeY1564} />}
    </div>
  );
}

function RFC2544Section({ data }: { data: any }) {
  const fmt = (n: number, digits = 2) => n ? n.toFixed(digits) : '—';
  const fmtBps = (bps: number) => {
    if (!bps) return '—';
    if (bps >= 1e9) return `${(bps/1e9).toFixed(2)} Gbps`;
    if (bps >= 1e6) return `${(bps/1e6).toFixed(2)} Mbps`;
    if (bps >= 1e3) return `${(bps/1e3).toFixed(2)} Kbps`;
    return `${bps.toFixed(0)} bps`;
  };

  // Compute a visual bar width for load sweep loss column (max 100%)
  const maxSweepLoss = Math.max(...(data.load_sweep ?? []).map((r: any) => r.loss_rate_pct), 0.001);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <div className="w-1 h-5 bg-blue-500 rounded-full" />
        <h3 className="text-sm font-bold text-white">RFC 2544 Benchmarking</h3>
        <span className="text-[10px] text-slate-500 ml-1">Network performance baseline</span>
      </div>

      {/* Four KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <KPICard title="Max Throughput" value={fmtBps(data.throughput?.max_bps)} sub={`Avg: ${fmtBps(data.throughput?.avg_bps)}`} color="blue" />
        <KPICard title="Avg Latency" value={`${fmt(data.latency?.avg_ms)} ms`} sub={`P95: ${fmt(data.latency?.p95_ms)} ms`} color="cyan" />
        <KPICard title="Frame Loss" value={`${fmt(data.frame_loss?.loss_rate_pct)} %`} sub={`${data.frame_loss?.lost_packets ?? 0} lost pkts`} color={data.frame_loss?.loss_rate_pct > 1 ? "red" : "emerald"} />
        <KPICard title="Retransmissions" value={`${data.frame_loss?.retransmit_count ?? 0}`} sub={`of ${data.frame_loss?.total_packets ?? 0} pkts`} color="orange" />
      </div>

      {/* Latency distribution */}
      {data.latency?.min_ms > 0 && (
        <div className="bg-slate-800/60 border border-slate-700/40 rounded-xl p-4">
          <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-3">Latency Distribution</div>
          <div className="grid grid-cols-5 gap-2 text-center">
            {[
              { label: 'Min', val: data.latency.min_ms },
              { label: 'Avg', val: data.latency.avg_ms },
              { label: 'Max', val: data.latency.max_ms },
              { label: 'P95', val: data.latency.p95_ms },
              { label: 'P99', val: data.latency.p99_ms },
            ].map(({ label, val }) => (
              <div key={label} className="bg-slate-900/60 rounded-lg p-2">
                <div className="text-[10px] text-slate-500">{label}</div>
                <div className="text-sm font-mono font-bold text-cyan-300">{fmt(val)} ms</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* RFC 2544 Load Sweep — frame loss at different offered load levels */}
      {data.load_sweep?.length > 0 && (
        <div className="bg-slate-800/60 border border-slate-700/40 rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 border-b border-slate-700/40 flex items-center gap-2">
            <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Frame Loss vs. Offered Load</span>
            <span className="text-[10px] text-slate-600">(RFC 2544 §26.1 — flows bucketed by throughput percentile)</span>
          </div>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-500 text-[10px] uppercase tracking-wider border-b border-slate-700/30">
                <th className="text-left px-4 py-2">Load Level</th>
                <th className="text-right px-4 py-2">Flows</th>
                <th className="text-right px-4 py-2">Avg Throughput</th>
                <th className="text-right px-4 py-2">Avg Latency</th>
                <th className="text-left px-4 py-2" colSpan={2}>Frame Loss Rate</th>
              </tr>
            </thead>
            <tbody>
              {data.load_sweep.map((row: any) => {
                const lossPct = row.loss_rate_pct ?? 0;
                const barWidth = Math.min(100, (lossPct / maxSweepLoss) * 100);
                const lossColor = lossPct === 0 ? 'text-emerald-400' : lossPct < 1 ? 'text-yellow-400' : 'text-red-400';
                const barColor = lossPct === 0 ? 'bg-emerald-500' : lossPct < 1 ? 'bg-yellow-500' : 'bg-red-500';
                return (
                  <tr key={row.bucket_label} className="border-t border-slate-700/30 hover:bg-slate-700/20">
                    <td className="px-4 py-2.5">
                      <span className="font-medium text-slate-200">{row.bucket_label}</span>
                      <span className="text-[10px] text-slate-600 ml-2">offered load</span>
                    </td>
                    <td className="px-4 py-2.5 text-right text-slate-400">{row.flow_count}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-cyan-300">{fmtBps(row.avg_throughput_bps)}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-slate-300">
                      {row.avg_latency_ms > 0 ? `${fmt(row.avg_latency_ms)} ms` : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono w-20">
                      <span className={lossColor}>{lossPct.toFixed(3)}%</span>
                    </td>
                    <td className="px-4 py-2.5 w-32">
                      <div className="h-2 bg-slate-700/50 rounded-full overflow-hidden">
                        <div className={`h-2 rounded-full ${barColor} transition-all`} style={{ width: `${barWidth}%` }} />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Per-protocol breakdown */}
      {data.by_protocol?.length > 0 && (
        <div className="bg-slate-800/60 border border-slate-700/40 rounded-xl overflow-hidden">
          <div className="px-4 py-2 border-b border-slate-700/40">
            <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Per-Protocol Breakdown</span>
          </div>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-500 text-[10px] uppercase tracking-wider">
                <th className="text-left px-4 py-2">Protocol</th>
                <th className="text-right px-4 py-2">Flows</th>
                <th className="text-right px-4 py-2">Avg Throughput</th>
                <th className="text-right px-4 py-2">Avg RTT</th>
                <th className="text-right px-4 py-2">Avg Loss</th>
                <th className="text-right px-4 py-2">SLA</th>
              </tr>
            </thead>
            <tbody>
              {data.by_protocol.map((p: any) => {
                const verdicts = p.sla_verdicts || {};
                const dominantVerdict = ['good', 'acceptable', 'poor', 'critical'].find(v => verdicts[v] > 0) || 'good';
                const verdictColor = dominantVerdict === 'good' ? 'text-emerald-400' : dominantVerdict === 'acceptable' ? 'text-yellow-400' : dominantVerdict === 'poor' ? 'text-orange-400' : 'text-red-400';
                return (
                  <tr key={p.protocol} className="border-t border-slate-700/30 hover:bg-slate-700/20">
                    <td className="px-4 py-2 font-medium text-slate-200">{p.protocol}</td>
                    <td className="px-4 py-2 text-right text-slate-400">{p.flow_count}</td>
                    <td className="px-4 py-2 text-right text-cyan-300 font-mono">{fmtBps(p.avg_bps)}</td>
                    <td className="px-4 py-2 text-right text-slate-300 font-mono">{p.avg_rtt_ms ? `${fmt(p.avg_rtt_ms)} ms` : '—'}</td>
                    <td className="px-4 py-2 text-right font-mono" style={{ color: p.avg_loss_pct > 1 ? '#f87171' : '#94a3b8' }}>{fmt(p.avg_loss_pct)} %</td>
                    <td className={`px-4 py-2 text-right font-medium capitalize ${verdictColor}`}>{dominantVerdict}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Y1564Section({ data }: { data: any }) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const overallPass = data.overall === 'PASS';
  const fmt2 = (n: number) => n > 0 ? n.toFixed(2) : '—';

  const cellColor = (meas: number, thresh: number) =>
    meas <= thresh ? 'text-emerald-400' : 'text-red-400';

  const verdictBadge = (v: string) =>
    v === 'PASS' ? 'text-emerald-400 bg-emerald-500/10' :
    v === 'WARN' ? 'text-yellow-400 bg-yellow-500/10' :
    'text-red-400 bg-red-500/10';

  const dirLabel = (d: string) =>
    d === 'UL' ? 'text-sky-400' : 'text-violet-400';

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <div className="w-1 h-5 bg-violet-500 rounded-full" />
        <h3 className="text-sm font-bold text-white">Y.1564 Service Activation Test</h3>
        <span className="text-[10px] text-slate-600 ml-1">click a row to expand UL/DL split</span>
        <span className={`ml-auto px-3 py-1 rounded-full text-xs font-bold ${overallPass ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
          {data.overall}
        </span>
      </div>

      <div className="bg-slate-800/60 border border-slate-700/40 rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-slate-500 text-[10px] uppercase tracking-wider border-b border-slate-700/40">
              <th className="text-left px-4 py-2.5">Service</th>
              <th className="text-right px-3 py-2.5">Flows</th>
              <th className="text-right px-3 py-2.5">
                Latency<br/><span className="text-slate-600 normal-case">meas / threshold</span>
              </th>
              <th className="text-right px-3 py-2.5">
                Jitter<br/><span className="text-slate-600 normal-case">meas / threshold</span>
              </th>
              <th className="text-right px-3 py-2.5">
                Loss %<br/><span className="text-slate-600 normal-case">meas / threshold</span>
              </th>
              <th className="text-center px-4 py-2.5">Result</th>
            </tr>
          </thead>
          <tbody>
            {(data.services || []).map((svc: any) => {
              const isExpanded = expanded[svc.service];
              const hasDirs = svc.directions?.length > 0;
              return (
                <>
                  {/* Main service row */}
                  <tr
                    key={svc.service}
                    className={`border-t border-slate-700/30 transition-colors ${hasDirs ? 'cursor-pointer hover:bg-slate-700/20' : ''}`}
                    onClick={() => hasDirs && setExpanded(prev => ({ ...prev, [svc.service]: !prev[svc.service] }))}
                  >
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        {hasDirs && (
                          <span className="text-[10px] text-slate-600">{isExpanded ? '▾' : '▸'}</span>
                        )}
                        <div>
                          <div className="font-medium text-slate-200">{svc.service}</div>
                          <div className="text-[10px] text-slate-600">{svc.protocol} · {svc.flow_count} flows</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-3 py-2.5 text-right text-slate-400">{svc.flow_count}</td>
                    <td className="px-3 py-2.5 text-right font-mono">
                      <span className={cellColor(svc.meas_latency_ms, svc.max_latency_ms)}>
                        {fmt2(svc.meas_latency_ms)}
                      </span>
                      <span className="text-slate-600"> / </span>
                      <span className="text-slate-500">{svc.max_latency_ms} ms</span>
                    </td>
                    <td className="px-3 py-2.5 text-right font-mono">
                      {svc.max_jitter_ms > 0 ? (
                        <>
                          <span className={cellColor(svc.meas_jitter_ms, svc.max_jitter_ms)}>
                            {fmt2(svc.meas_jitter_ms)}
                          </span>
                          <span className="text-slate-600"> / </span>
                          <span className="text-slate-500">{svc.max_jitter_ms} ms</span>
                        </>
                      ) : <span className="text-slate-600">N/A</span>}
                    </td>
                    <td className="px-3 py-2.5 text-right font-mono">
                      <span className={cellColor(svc.meas_loss_pct, svc.max_loss_pct)}>
                        {fmt2(svc.meas_loss_pct)}
                      </span>
                      <span className="text-slate-600"> / </span>
                      <span className="text-slate-500">{svc.max_loss_pct}%</span>
                    </td>
                    <td className="px-4 py-2.5 text-center">
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${verdictBadge(svc.overall)}`}>
                        {svc.overall}
                      </span>
                      {svc.violations?.length > 0 && (
                        <div className="text-[10px] text-red-400/70 mt-0.5">{svc.violations.join(', ')}</div>
                      )}
                    </td>
                  </tr>

                  {/* Per-direction sub-rows (UL / DL) */}
                  {isExpanded && svc.directions?.map((dir: any) => (
                    <tr key={`${svc.service}-${dir.direction}`} className="bg-slate-900/40 border-t border-slate-700/20">
                      <td className="pl-10 pr-4 py-2">
                        <span className={`text-[10px] font-bold ${dirLabel(dir.direction)}`}>
                          {dir.direction}
                        </span>
                        <span className="text-[10px] text-slate-600 ml-1">{dir.flow_count} flows</span>
                      </td>
                      <td className="px-3 py-2 text-right text-slate-500 text-[11px]">{dir.flow_count}</td>
                      <td className="px-3 py-2 text-right font-mono text-[11px]">
                        <span className={cellColor(dir.meas_latency_ms, svc.max_latency_ms)}>
                          {fmt2(dir.meas_latency_ms)}
                        </span>
                        <span className="text-slate-600"> ms</span>
                      </td>
                      <td className="px-3 py-2 text-right font-mono text-[11px]">
                        {svc.max_jitter_ms > 0 ? (
                          <>
                            <span className={cellColor(dir.meas_jitter_ms, svc.max_jitter_ms)}>
                              {fmt2(dir.meas_jitter_ms)}
                            </span>
                            <span className="text-slate-600"> ms</span>
                          </>
                        ) : <span className="text-slate-700">—</span>}
                      </td>
                      <td className="px-3 py-2 text-right font-mono text-[11px]">
                        <span className={cellColor(dir.meas_loss_pct, svc.max_loss_pct)}>
                          {fmt2(dir.meas_loss_pct)}
                        </span>
                        <span className="text-slate-600">%</span>
                      </td>
                      <td className="px-4 py-2 text-center">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${verdictBadge(dir.overall)}`}>
                          {dir.overall}
                        </span>
                        {dir.violations?.length > 0 && (
                          <div className="text-[10px] text-red-400/60 mt-0.5">{dir.violations.join(', ')}</div>
                        )}
                      </td>
                    </tr>
                  ))}
                </>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function KPICard({ title, value, sub, color }: { title: string; value: string; sub: string; color: string }) {
  const colorMap: Record<string, string> = {
    blue: 'text-blue-400 border-blue-500/20 bg-blue-500/5',
    cyan: 'text-cyan-400 border-cyan-500/20 bg-cyan-500/5',
    emerald: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5',
    red: 'text-red-400 border-red-500/20 bg-red-500/5',
    orange: 'text-orange-400 border-orange-500/20 bg-orange-500/5',
  };
  return (
    <div className={`rounded-xl border p-4 ${colorMap[color] || colorMap.blue}`}>
      <div className="text-[10px] text-slate-500 uppercase tracking-wider">{title}</div>
      <div className={`text-xl font-bold font-mono mt-1 ${colorMap[color]?.split(' ')[0]}`}>{value}</div>
      <div className="text-[10px] text-slate-500 mt-0.5">{sub}</div>
    </div>
  );
}
