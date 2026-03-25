import { useEffect, useRef, useState, useCallback } from "react";
import { Activity, Package, Wifi, AlertTriangle, TrendingUp, Server, Clock, RefreshCw } from "lucide-react";
import { clsx } from "clsx";

// ── Prometheus text-format parser ─────────────────────────────────────────────
// Parses only the subset of metrics we care about; ignores histograms/summaries.
type MetricFamily = Record<string, number>; // label-set → value

function parsePromText(text: string): Record<string, MetricFamily> {
  const result: Record<string, MetricFamily> = {};
  for (const line of text.split("\n")) {
    if (line.startsWith("#") || line.trim() === "") continue;
    const spaceIdx = line.lastIndexOf(" ");
    if (spaceIdx === -1) continue;
    const nameAndLabels = line.slice(0, spaceIdx).trim();
    const value = parseFloat(line.slice(spaceIdx + 1));
    if (isNaN(value)) continue;

    const braceStart = nameAndLabels.indexOf("{");
    const name = braceStart === -1 ? nameAndLabels : nameAndLabels.slice(0, braceStart);
    const labelStr = braceStart === -1 ? "" : nameAndLabels.slice(braceStart + 1, -1);

    if (!result[name]) result[name] = {};
    result[name][labelStr] = value;
  }
  return result;
}

// Sum all label combinations for a metric family
function sum(family: MetricFamily | undefined): number {
  if (!family) return 0;
  return Object.values(family).reduce((a, b) => a + b, 0);
}

// Sum only entries whose label string contains a key=value match
function sumWhere(family: MetricFamily | undefined, key: string, val: string): number {
  if (!family) return 0;
  let total = 0;
  for (const [labels, v] of Object.entries(family)) {
    if (labels.includes(`${key}="${val}"`)) total += v;
  }
  return total;
}

// Get a single scalar gauge (no labels)
function scalar(family: MetricFamily | undefined): number {
  if (!family) return 0;
  return Object.values(family)[0] ?? 0;
}

function get(family: MetricFamily | undefined, labelStr: string): number {
  return family?.[labelStr] ?? 0;
}

// ── Sparkline component ────────────────────────────────────────────────────────
function Sparkline({ data, color = "#34d399", height = 36 }: { data: number[]; color?: string; height?: number }) {
  if (data.length < 2) return <div style={{ height }} />;
  const max = Math.max(...data, 1);
  const w = 160;
  const h = height;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - (v / max) * h;
    return `${x},${y}`;
  }).join(" ");

  return (
    <svg width={w} height={h} className="overflow-visible">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      {/* Area fill */}
      <polygon
        points={`0,${h} ${pts} ${w},${h}`}
        fill={color}
        fillOpacity="0.1"
      />
    </svg>
  );
}

// ── Metric card ────────────────────────────────────────────────────────────────
interface CardProps {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ElementType;
  color: string;
  history?: number[];
  sparkColor?: string;
}

function MetricCard({ label, value, sub, icon: Icon, color, history, sparkColor }: CardProps) {
  return (
    <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 p-4 flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-400">{label}</span>
        <Icon className={clsx("w-4 h-4", color)} />
      </div>
      <div className={clsx("text-2xl font-black", color)}>{value}</div>
      {sub && <div className="text-[10px] text-slate-500">{sub}</div>}
      {history && history.length > 1 && (
        <Sparkline data={history} color={sparkColor ?? "#34d399"} />
      )}
    </div>
  );
}

// ── Protocol table ─────────────────────────────────────────────────────────────
function ProtocolTable({ data }: { data: Array<{ proto: string; packets: number; bytes: number }> }) {
  const total = data.reduce((a, r) => a + r.packets, 0) || 1;
  return (
    <div className="space-y-1.5">
      {data.map(({ proto, packets, bytes }) => {
        const pct = (packets / total) * 100;
        return (
          <div key={proto}>
            <div className="flex justify-between text-xs mb-0.5">
              <span className="text-slate-300 font-medium">{proto}</span>
              <span className="text-slate-500">{packets.toLocaleString()} pkts · {fmtBytes(bytes)}</span>
            </div>
            <div className="h-1.5 bg-slate-700/50 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-emerald-500 to-cyan-500 rounded-full transition-all duration-500"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Decode errors table ────────────────────────────────────────────────────────
function ErrorTable({ data }: { data: Array<{ proto: string; errType: string; count: number }> }) {
  if (data.length === 0) {
    return <div className="text-slate-600 text-xs text-center py-4">No decode errors</div>;
  }
  return (
    <div className="space-y-1">
      {data.map(({ proto, errType, count }) => (
        <div key={`${proto}-${errType}`} className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="w-16 text-orange-400 font-medium">{proto}</span>
            <span className="text-slate-400 truncate max-w-[200px]">{errType}</span>
          </div>
          <span className="text-red-400 font-bold">{count}</span>
        </div>
      ))}
    </div>
  );
}

// ── HTTP latency table ─────────────────────────────────────────────────────────
function HTTPTable({ data }: { data: Array<{ method: string; path: string; status: string; count: number }> }) {
  if (data.length === 0) {
    return <div className="text-slate-600 text-xs text-center py-4">No requests recorded</div>;
  }
  const top = [...data].sort((a, b) => b.count - a.count).slice(0, 10);
  return (
    <div className="space-y-1">
      {top.map(({ method, path, status, count }) => (
        <div key={`${method}-${path}-${status}`} className="flex items-center gap-2 text-xs">
          <span className={clsx("w-12 font-bold text-center rounded px-1", method === "GET" ? "text-cyan-400" : "text-emerald-400")}>{method}</span>
          <span className="text-slate-400 flex-1 truncate font-mono">{path}</span>
          <span className={clsx("w-10 text-center rounded px-1 font-bold",
            status.startsWith("2") ? "text-emerald-400" : status.startsWith("4") ? "text-yellow-400" : "text-red-400"
          )}>{status}</span>
          <span className="text-slate-500 w-14 text-right">{count.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────────
function fmtBytes(b: number): string {
  if (b >= 1e9) return `${(b / 1e9).toFixed(1)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`;
  return `${b} B`;
}

function fmtNum(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return String(n);
}

const HISTORY_MAX = 60; // 60 samples = 1 minute at 1-second poll

// ── Main page ──────────────────────────────────────────────────────────────────
export default function ObservabilityPage() {
  const [raw, setRaw] = useState<Record<string, MetricFamily>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [refreshInterval, setRefreshInterval] = useState(5); // seconds

  // Rolling history for sparklines
  const ppsHistory = useRef<number[]>([]);
  const bpsHistory = useRef<number[]>([]);
  const errHistory = useRef<number[]>([]);

  const fetchMetrics = useCallback(async () => {
    try {
      // Prometheus text format — fetch directly (same origin, no auth needed)
      const res = await fetch("/metrics");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const parsed = parsePromText(text);
      setRaw(parsed);
      setLastUpdated(new Date());
      setError(null);

      // Update sparkline histories
      const pps = get(parsed["deeppacketai_packets_per_second"], 'source="live"');
      const bps = get(parsed["deeppacketai_bytes_per_second"], 'source="live"');
      const errs = sum(parsed["deeppacketai_decode_errors_total"]);

      ppsHistory.current = [...ppsHistory.current.slice(-HISTORY_MAX), pps];
      bpsHistory.current = [...bpsHistory.current.slice(-HISTORY_MAX), bps];
      errHistory.current = [...errHistory.current.slice(-HISTORY_MAX), errs];
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch metrics");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMetrics();
    const id = setInterval(fetchMetrics, refreshInterval * 1000);
    return () => clearInterval(id);
  }, [fetchMetrics, refreshInterval]);

  // ── Derived values ────────────────────────────────────────────────────────
  const totalPackets = sum(raw["deeppacketai_packets_total"]);
  const totalBytes = sum(raw["deeppacketai_bytes_total"]);
  const droppedPackets = sum(raw["deeppacketai_packets_dropped_total"]);
  const totalFlows = sum(raw["deeppacketai_flows_total"]);
  const activeFlows = scalar(raw["deeppacketai_flows_active"]);
  const pps = get(raw["deeppacketai_packets_per_second"], 'source="live"');
  const bps = get(raw["deeppacketai_bytes_per_second"], 'source="live"');
  const wsClients = scalar(raw["deeppacketai_websocket_clients"]);
  const pcapJobs = sum(raw["deeppacketai_pcap_jobs_total"]);
  const telecomTotal = sum(raw["deeppacketai_telecom_sessions_total"]);
  const totalDecodeErrors = sum(raw["deeppacketai_decode_errors_total"]);

  // Protocol breakdown from packets_total
  const protocolFamily = raw["deeppacketai_protocol_packets_total"];
  const protocolRows = Object.entries(protocolFamily ?? {})
    .map(([labels, count]) => {
      const proto = labels.match(/protocol="([^"]+)"/)?.[1] ?? labels;
      return { proto, packets: count, bytes: 0 };
    })
    .sort((a, b) => b.packets - a.packets)
    .slice(0, 10);

  // Decode errors breakdown
  const errFamily = raw["deeppacketai_decode_errors_total"];
  const errorRows = Object.entries(errFamily ?? {}).map(([labels, count]) => {
    const proto = labels.match(/protocol="([^"]+)"/)?.[1] ?? "unknown";
    const errType = labels.match(/error_type="([^"]+)"/)?.[1] ?? "unknown";
    return { proto, errType, count };
  }).sort((a, b) => b.count - a.count);

  // HTTP request count breakdown
  const httpFamily = raw["deeppacketai_http_request_duration_seconds_count"];
  const httpRows = Object.entries(httpFamily ?? {}).map(([labels, count]) => {
    const method = labels.match(/method="([^"]+)"/)?.[1] ?? "";
    const path = labels.match(/path="([^"]+)"/)?.[1] ?? "";
    const status = labels.match(/status="([^"]+)"/)?.[1] ?? "";
    return { method, path, status, count };
  });

  const pcapLive = sumWhere(raw["deeppacketai_packets_total"], "source", "live");
  const pcapFile = sumWhere(raw["deeppacketai_packets_total"], "source", "pcap");

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Observability</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Prometheus metrics · /metrics endpoint · auto-refresh every {refreshInterval}s
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdated && (
            <span className="text-[10px] text-slate-500">
              <Clock className="w-3 h-3 inline mr-1" />
              {lastUpdated.toLocaleTimeString()}
            </span>
          )}
          <select
            value={refreshInterval}
            onChange={(e) => setRefreshInterval(Number(e.target.value))}
            className="text-xs bg-slate-800 border border-slate-700/50 rounded px-2 py-1 text-slate-300"
          >
            <option value={2}>2s</option>
            <option value={5}>5s</option>
            <option value={10}>10s</option>
            <option value={30}>30s</option>
          </select>
          <button
            onClick={fetchMetrics}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700/50 text-xs text-slate-300 hover:bg-slate-700/60 transition-colors"
          >
            <RefreshCw className={clsx("w-3.5 h-3.5", loading && "animate-spin")} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-xl px-4 py-3 text-red-400 text-sm">
          {error} — make sure the backend is running at <code className="font-mono text-xs">:8080/metrics</code>
        </div>
      )}

      {/* ── Top metric cards ── */}
      <div className="grid grid-cols-4 gap-3">
        <MetricCard
          label="Packets/sec (live)"
          value={pps.toFixed(0)}
          sub="live capture rate"
          icon={Activity}
          color="text-emerald-400"
          history={ppsHistory.current}
          sparkColor="#34d399"
        />
        <MetricCard
          label="Throughput (live)"
          value={fmtBytes(bps) + "/s"}
          sub="live bytes/sec"
          icon={TrendingUp}
          color="text-cyan-400"
          history={bpsHistory.current}
          sparkColor="#22d3ee"
        />
        <MetricCard
          label="Dropped Packets"
          value={fmtNum(droppedPackets)}
          sub="parse errors before decode"
          icon={Package}
          color={droppedPackets > 0 ? "text-red-400" : "text-slate-400"}
          history={[]}
        />
        <MetricCard
          label="Decode Errors"
          value={fmtNum(totalDecodeErrors)}
          sub="protocol-level failures"
          icon={AlertTriangle}
          color={totalDecodeErrors > 0 ? "text-orange-400" : "text-slate-400"}
          history={errHistory.current}
          sparkColor="#fb923c"
        />
      </div>

      {/* ── Second row ── */}
      <div className="grid grid-cols-4 gap-3">
        <MetricCard
          label="Total Packets"
          value={fmtNum(totalPackets)}
          sub={`live ${fmtNum(pcapLive)} · pcap ${fmtNum(pcapFile)}`}
          icon={Package}
          color="text-slate-200"
        />
        <MetricCard
          label="Total Bytes"
          value={fmtBytes(totalBytes)}
          sub="all sources"
          icon={TrendingUp}
          color="text-slate-200"
        />
        <MetricCard
          label="Flows"
          value={`${fmtNum(activeFlows)} active`}
          sub={`${fmtNum(totalFlows)} total flushed`}
          icon={Wifi}
          color="text-violet-400"
        />
        <MetricCard
          label="Infrastructure"
          value={`${wsClients} WS`}
          sub={`${pcapJobs} PCAP jobs · ${telecomTotal} telecom sessions`}
          icon={Server}
          color="text-sky-400"
        />
      </div>

      {/* ── Details grid ── */}
      <div className="grid grid-cols-3 gap-4">
        {/* Protocol breakdown */}
        <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 p-4">
          <div className="text-xs font-semibold text-slate-400 mb-3 flex items-center gap-2">
            <Activity className="w-3.5 h-3.5" /> Protocol Packets
          </div>
          {protocolRows.length === 0
            ? <div className="text-slate-600 text-xs text-center py-4">No data yet</div>
            : <ProtocolTable data={protocolRows} />
          }
        </div>

        {/* Decode errors */}
        <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 p-4">
          <div className="text-xs font-semibold text-slate-400 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5" /> Decode Errors by Protocol
          </div>
          <ErrorTable data={errorRows} />
        </div>

        {/* HTTP API requests */}
        <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 p-4">
          <div className="text-xs font-semibold text-slate-400 mb-3 flex items-center gap-2">
            <Server className="w-3.5 h-3.5" /> HTTP API Requests
          </div>
          <HTTPTable data={httpRows} />
        </div>
      </div>

      {/* ── Prometheus info box ── */}
      {(() => {
        const metricsEndpoint = `${window.location.protocol}//${window.location.host}/metrics`;
        const scrapeTarget = window.location.host;
        const prometheusSnippet =
          `- job_name: deeppacketai\n  static_configs:\n  - targets: ['${scrapeTarget}']`;
        return (
          <div className="bg-slate-800/40 rounded-xl border border-slate-700/30 p-4">
            <div className="text-xs font-semibold text-slate-400 mb-2">Prometheus Scrape Endpoint</div>
            <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-xs">
              {[
                ["Endpoint", metricsEndpoint],
                ["Format", "OpenMetrics / Prometheus text"],
                ["Namespace", "deeppacketai_"],
                ["Scrape interval (recommended)", "15s"],
              ].map(([k, v]) => (
                <div key={k} className="flex gap-2">
                  <span className="text-slate-500 w-44">{k}</span>
                  <code className="text-emerald-400 font-mono">{v}</code>
                </div>
              ))}
            </div>
            <div className="mt-3 text-[10px] text-slate-600">
              Add to <code className="font-mono">prometheus.yml</code>:&nbsp;
              <code className="font-mono text-slate-400 whitespace-pre">{prometheusSnippet}</code>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
