import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Radio,
  Play,
  Square,
  AlertTriangle,
  X,
  ChevronRight,
  BarChart3,
} from "lucide-react";
import { fetchInterfaces, startCapture, stopCapture } from "../api/capture";
import type { NetworkInterface, StopCaptureResponse } from "../api/capture";
import { useWebSocket } from "../hooks/useWebSocket";
import type { WSMessage } from "../hooks/useWebSocket";
import LiveIndicator from "../components/dashboard/LiveIndicator";
import LiveInsightsFeed from "../components/LiveInsightsFeed";
import type { AIInsight } from "../components/LiveInsightsFeed";

interface PacketError {
  Code: string;
  Title: string;
  Description: string;
  Severity: string;
}

interface CapturePacket {
  frame: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  app_protocol: string;
  length: number;
  summary: string;
  metadata?: Record<string, any>;
  errors?: PacketError[];
}

interface CaptureAlert {
  frame: number;
  timestamp: string;
  severity: string;
  protocol: string;
  title: string;
  description: string;
  src_ip: string;
  dst_ip: string;
}

export default function CapturePage() {
  const navigate = useNavigate();
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedIface, setSelectedIface] = useState("");
  const [bpfFilter, setBpfFilter] = useState("");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [capturing, setCapturing] = useState(false);
  const [stats, setStats] = useState<any>(null);
  const [recentPackets, setRecentPackets] = useState<CapturePacket[]>([]);
  const [alerts, setAlerts] = useState<CaptureAlert[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<CapturePacket | null>(
    null
  );
  const [error, setError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<number | null>(null);
  const [sessionStatus, setSessionStatus] = useState<string | null>(null);
  const [insights, setInsights] = useState<AIInsight[]>([]);
  const [aiAnalyzing, setAIAnalyzing] = useState(false);

  useEffect(() => {
    fetchInterfaces()
      .then(setInterfaces)
      .catch(() => setError("Failed to load interfaces. Is Npcap installed?"));
  }, []);

  const handleMessage = useCallback((msg: WSMessage) => {
    if (msg.type === "stats") {
      setStats(msg.payload);
    } else if (msg.type === "packet") {
      setRecentPackets((prev) => [msg.payload, ...prev].slice(0, 200));
    } else if (msg.type === "alert") {
      setAlerts((prev) => [msg.payload, ...prev].slice(0, 100));
    } else if (msg.type === "capture_state") {
      const p = msg.payload;
      setSessionStatus(p.status);
      if (p.status === "stopped") {
        setCapturing(false);
        setAIAnalyzing(false);
      }
      if (p.job_id) {
        setJobId(p.job_id);
      }
    } else if (msg.type === "ai_insight") {
      setAIAnalyzing(false);
      setInsights((prev) => [...prev, msg.payload as AIInsight].slice(-50));
    }
  }, []);

  const { connected } = useWebSocket({ onMessage: handleMessage });

  const handleStart = async () => {
    if (!selectedIface) {
      setError("Please select a network interface");
      return;
    }
    try {
      setError(null);
      setRecentPackets([]);
      setAlerts([]);
      setInsights([]);
      setAIAnalyzing(false);
      setSelectedPacket(null);
      setJobId(null);
      setSessionStatus(null);
      const result = await startCapture(selectedIface, bpfFilter);
      // Show "Analyzing…" spinner 5s before the first AI insight arrives (~30s mark)
      setTimeout(() => setAIAnalyzing(true), 25000);
      setSessionId(result.session_id);
      setJobId(result.job_id);
      setCapturing(true);
    } catch (err: any) {
      setError(err.response?.data?.error || "Failed to start capture");
    }
  };

  const handleStop = async () => {
    if (sessionId) {
      try {
        const result: StopCaptureResponse = await stopCapture(sessionId);
        setCapturing(false);
        if (result.job_id) {
          setJobId(result.job_id);
        }
      } catch {
        setError("Failed to stop capture");
      }
    }
  };

  const errorCount = alerts.filter(
    (a) => a.severity === "error" || a.severity === "critical"
  ).length;
  const warningCount = alerts.filter(
    (a) => a.severity === "warning"
  ).length;

  const getRowClasses = (pkt: CapturePacket): string => {
    if (!pkt.errors || pkt.errors.length === 0) {
      return "border-b border-slate-700/20 hover:bg-slate-700/20 cursor-pointer";
    }
    const hasCritical = pkt.errors.some(
      (e) => e.Severity === "critical" || e.Severity === "error"
    );
    if (hasCritical) {
      return "border-b border-red-500/20 hover:bg-red-500/10 bg-red-500/5 cursor-pointer";
    }
    return "border-b border-yellow-500/20 hover:bg-yellow-500/10 bg-yellow-500/5 cursor-pointer";
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Live Capture</h1>
          <p className="text-sm text-slate-400 mt-1">
            Capture and analyze network traffic in real-time
          </p>
        </div>
        <div className="flex items-center gap-4">
          <LiveIndicator active={capturing} />
          <div className="text-xs text-slate-500">
            WS: {connected ? "Connected" : "Disconnected"}
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Capture Controls */}
      <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
        <div className="flex items-center gap-4 mb-4">
          <div className="flex-1">
            <label className="block text-xs text-slate-400 mb-1">
              Network Interface
            </label>
            <select
              value={selectedIface}
              onChange={(e) => setSelectedIface(e.target.value)}
              disabled={capturing}
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-emerald-500 disabled:opacity-50"
            >
              <option value="">Select interface...</option>
              {interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.description || iface.name}
                  {iface.addresses?.length
                    ? ` (${iface.addresses[0]})`
                    : ""}
                </option>
              ))}
            </select>
          </div>

          <div className="flex-1">
            <label className="block text-xs text-slate-400 mb-1">
              BPF Filter
              <span className="ml-2 text-slate-600 font-normal">
                — use <code className="text-slate-400">port 5060</code>, <code className="text-slate-400">udp</code>, <code className="text-slate-400">host 1.2.3.4</code>, etc.
              </span>
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={bpfFilter}
                onChange={(e) => setBpfFilter(e.target.value)}
                disabled={capturing}
                placeholder="e.g. port 5060 or udp port 53"
                className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 disabled:opacity-50"
              />
              <select
                disabled={capturing}
                value=""
                onChange={(e) => { if (e.target.value) setBpfFilter(e.target.value); }}
                className="bg-slate-700 border border-slate-600 rounded-lg px-2 py-2 text-sm text-slate-300 focus:outline-none focus:ring-2 focus:ring-emerald-500 disabled:opacity-50"
                title="Quick filter presets"
              >
                <option value="">Presets…</option>
                <optgroup label="VoIP / Telecom">
                  <option value="port 5060">SIP (port 5060)</option>
                  <option value="port 5060 or port 5061">SIP + TLS (5060/5061)</option>
                  <option value="udp portrange 16384-32767">RTP (16384-32767)</option>
                  <option value="port 2123 or port 2152">GTP (2123/2152)</option>
                  <option value="port 3868">Diameter (3868)</option>
                  <option value="port 36412">S1AP (36412)</option>
                </optgroup>
                <optgroup label="Common Protocols">
                  <option value="port 53">DNS (53)</option>
                  <option value="port 80">HTTP (80)</option>
                  <option value="port 443">HTTPS/TLS (443)</option>
                  <option value="port 22">SSH (22)</option>
                </optgroup>
                <optgroup label="Transport">
                  <option value="tcp">TCP only</option>
                  <option value="udp">UDP only</option>
                  <option value="icmp">ICMP only</option>
                </optgroup>
                <optgroup label="Clear">
                  <option value=" ">No filter (all traffic)</option>
                </optgroup>
              </select>
            </div>
          </div>

          <div className="pt-5">
            <button
              onClick={capturing ? handleStop : handleStart}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                capturing
                  ? "bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30"
                  : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30"
              }`}
            >
              {capturing ? (
                <>
                  <Square className="w-4 h-4" /> Stop
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" /> Start
                </>
              )}
            </button>
          </div>
        </div>

        {/* Stats */}
        {stats && capturing && (
          <div className="grid grid-cols-5 gap-4 pt-4 border-t border-slate-700/50">
            <div className="text-center">
              <div className="text-2xl font-bold text-white">
                {stats.total_packets?.toLocaleString() || 0}
              </div>
              <div className="text-xs text-slate-400">Total Packets</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-white">
                {stats.packets_per_sec || 0}
              </div>
              <div className="text-xs text-slate-400">Packets/sec</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-white">
                {formatBytes(stats.total_bytes || 0)}
              </div>
              <div className="text-xs text-slate-400">Total Bytes</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-white">
                {formatBytes(stats.bytes_per_sec || 0)}/s
              </div>
              <div className="text-xs text-slate-400">Throughput</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold">
                {errorCount > 0 ? (
                  <span className="text-red-400">{errorCount}</span>
                ) : (
                  <span className="text-white">0</span>
                )}
                {warningCount > 0 && (
                  <span className="text-yellow-400 text-lg ml-1">
                    +{warningCount}
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-400">Errors</div>
            </div>
          </div>
        )}
      </div>

      {/* AI Live Insights — shown during capture and after */}
      {(capturing || insights.length > 0) && (
        <LiveInsightsFeed insights={insights} analyzing={aiAnalyzing && insights.length === 0} />
      )}

      {/* Post-capture Navigation */}
      {!capturing && jobId && sessionStatus === "completed" && (
        <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-4 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-emerald-400">
              Capture analysis complete
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              {recentPackets.length} packets captured and analyzed.
              {alerts.length > 0 && ` ${alerts.length} alerts detected.`}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate(`/jobs/${jobId}`)}
              className="flex items-center gap-2 px-4 py-2 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg text-sm font-medium hover:bg-emerald-500/30 transition-colors"
            >
              <BarChart3 className="w-4 h-4" />
              View Analysis
              <ChevronRight className="w-4 h-4" />
            </button>
            <button
              onClick={() =>
                navigate("/chat", {
                  state: {
                    packets: recentPackets.slice(0, 50),
                    alerts,
                    jobId,
                  },
                })
              }
              className="flex items-center gap-2 px-4 py-2 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded-lg text-sm font-medium hover:bg-blue-500/30 transition-colors"
            >
              Ask AI
            </button>
          </div>
        </div>
      )}

      {!capturing && jobId && sessionStatus === "analyzing" && (
        <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4 flex items-center gap-3">
          <div className="animate-spin w-4 h-4 border-2 border-amber-400 border-t-transparent rounded-full" />
          <div>
            <h3 className="text-sm font-medium text-amber-400">
              Analyzing captured traffic...
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Running detection, correlation, and quality analysis.
            </p>
          </div>
        </div>
      )}

      {/* Alerts Panel */}
      {alerts.length > 0 && (
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
            <h3 className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Alerts ({alerts.length})
            </h3>
            <button
              onClick={() => setAlerts([])}
              className="text-xs text-slate-500 hover:text-slate-300"
            >
              Clear
            </button>
          </div>
          <div className="max-h-48 overflow-y-auto">
            {alerts.map((alert, i) => (
              <div
                key={i}
                className={`px-4 py-2 border-b border-slate-700/20 flex items-start gap-3 text-xs ${
                  alert.severity === "critical" || alert.severity === "error"
                    ? "text-red-400"
                    : alert.severity === "warning"
                    ? "text-yellow-400"
                    : "text-blue-400"
                }`}
              >
                <span
                  className={`mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                    alert.severity === "critical"
                      ? "bg-red-500/20 text-red-400"
                      : alert.severity === "error"
                      ? "bg-red-500/20 text-red-400"
                      : alert.severity === "warning"
                      ? "bg-yellow-500/20 text-yellow-400"
                      : "bg-blue-500/20 text-blue-400"
                  }`}
                >
                  {alert.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <span className="font-medium">{alert.protocol}: </span>
                  <span>{alert.title}</span>
                  {alert.description && (
                    <span className="text-slate-500">
                      {" "}
                      — {alert.description}
                    </span>
                  )}
                </div>
                <span className="text-slate-600 whitespace-nowrap">
                  {alert.src_ip} → {alert.dst_ip} (#{alert.frame})
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live Packet Stream + Detail Panel */}
      <div className="flex gap-4">
        {/* Packet Table */}
        <div
          className={`bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden ${
            selectedPacket ? "flex-1" : "w-full"
          }`}
        >
          <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
            <h3 className="text-sm font-medium text-slate-300">
              Packet Stream
            </h3>
            <span className="text-xs text-slate-500">
              {recentPackets.length} packets shown
            </span>
          </div>

          <div className="max-h-96 overflow-y-auto">
            {recentPackets.length === 0 ? (
              <div className="p-12 text-center text-slate-500 text-sm">
                <Radio className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                Start a capture to see live packets
              </div>
            ) : (
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-slate-800">
                  <tr className="border-b border-slate-700/50">
                    <th className="px-3 py-2 text-left text-slate-400">#</th>
                    <th className="px-3 py-2 text-left text-slate-400">
                      Source
                    </th>
                    <th className="px-3 py-2 text-left text-slate-400">
                      Dest
                    </th>
                    <th className="px-3 py-2 text-left text-slate-400">
                      Proto
                    </th>
                    <th className="px-3 py-2 text-left text-slate-400">Len</th>
                    <th className="px-3 py-2 text-left text-slate-400">
                      Info
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {recentPackets.map((pkt, i) => (
                    <tr
                      key={i}
                      className={`${getRowClasses(pkt)} ${
                        selectedPacket?.frame === pkt.frame
                          ? "!bg-emerald-500/10"
                          : ""
                      }`}
                      onClick={() => setSelectedPacket(pkt)}
                    >
                      <td className="px-3 py-1 text-slate-500 font-mono">
                        {pkt.frame}
                      </td>
                      <td className="px-3 py-1 text-slate-300 font-mono">
                        {pkt.src_ip}:{pkt.src_port}
                      </td>
                      <td className="px-3 py-1 text-slate-300 font-mono">
                        {pkt.dst_ip}:{pkt.dst_port}
                      </td>
                      <td
                        className={`px-3 py-1 ${
                          pkt.errors && pkt.errors.length > 0
                            ? pkt.errors.some(
                                (e) =>
                                  e.Severity === "error" ||
                                  e.Severity === "critical"
                              )
                              ? "text-red-400"
                              : "text-yellow-400"
                            : "text-emerald-400"
                        }`}
                      >
                        {pkt.app_protocol || pkt.protocol}
                      </td>
                      <td className="px-3 py-1 text-slate-400">
                        {pkt.length}
                      </td>
                      <td className="px-3 py-1 text-slate-300 truncate max-w-xs">
                        {pkt.summary || "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Packet Detail Panel */}
        {selectedPacket && (
          <div className="w-96 bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden flex-shrink-0">
            <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
              <h3 className="text-sm font-medium text-slate-300">
                Packet #{selectedPacket.frame}
              </h3>
              <button
                onClick={() => setSelectedPacket(null)}
                className="text-slate-500 hover:text-slate-300"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4 text-xs space-y-3 max-h-96 overflow-y-auto">
              {/* Basic Info */}
              <div className="space-y-1">
                <DetailRow
                  label="Timestamp"
                  value={formatTimestamp(selectedPacket.timestamp)}
                />
                <DetailRow
                  label="Source"
                  value={`${selectedPacket.src_ip}:${selectedPacket.src_port}`}
                />
                <DetailRow
                  label="Destination"
                  value={`${selectedPacket.dst_ip}:${selectedPacket.dst_port}`}
                />
                <DetailRow
                  label="Protocol"
                  value={`${
                    selectedPacket.app_protocol || selectedPacket.protocol
                  } (${selectedPacket.protocol})`}
                />
                <DetailRow
                  label="Length"
                  value={`${selectedPacket.length} bytes`}
                />
              </div>

              {/* Summary */}
              {selectedPacket.summary && (
                <div>
                  <div className="text-slate-500 mb-1">Summary</div>
                  <div className="text-slate-200 bg-slate-700/50 rounded px-2 py-1.5 font-mono break-all">
                    {selectedPacket.summary}
                  </div>
                </div>
              )}

              {/* Metadata */}
              {selectedPacket.metadata &&
                Object.keys(selectedPacket.metadata).length > 0 && (
                  <div>
                    <div className="text-slate-500 mb-1">Metadata</div>
                    <div className="bg-slate-700/50 rounded p-2 space-y-1">
                      {Object.entries(selectedPacket.metadata).map(
                        ([key, value]) => (
                          <DetailRow
                            key={key}
                            label={key}
                            value={
                              typeof value === "object"
                                ? JSON.stringify(value)
                                : String(value)
                            }
                          />
                        )
                      )}
                    </div>
                  </div>
                )}

              {/* Errors */}
              {selectedPacket.errors && selectedPacket.errors.length > 0 ? (
                <div>
                  <div className="text-slate-500 mb-1">
                    Errors ({selectedPacket.errors.length})
                  </div>
                  <div className="space-y-2">
                    {selectedPacket.errors.map((err, i) => (
                      <div
                        key={i}
                        className={`rounded p-2 text-xs ${
                          err.Severity === "critical" ||
                          err.Severity === "error"
                            ? "bg-red-500/10 border border-red-500/20 text-red-400"
                            : "bg-yellow-500/10 border border-yellow-500/20 text-yellow-400"
                        }`}
                      >
                        <div className="font-medium">{err.Title}</div>
                        <div className="text-slate-400 mt-0.5">
                          {err.Description}
                        </div>
                        <div className="text-slate-600 mt-0.5">
                          Code: {err.Code}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div>
                  <div className="text-slate-500 mb-1">Errors</div>
                  <div className="text-emerald-400 text-xs">None</div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-2">
      <span className="text-slate-500 whitespace-nowrap">{label}:</span>
      <span className="text-slate-200 text-right font-mono truncate">
        {value}
      </span>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString(undefined, {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      fractionalSecondDigits: 3,
    } as Intl.DateTimeFormatOptions);
  } catch {
    return ts;
  }
}
