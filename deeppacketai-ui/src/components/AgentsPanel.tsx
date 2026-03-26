import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useWebSocket } from "../hooks/useWebSocket";

interface AgentSession {
  id: string;
  interface_name: string;
  status: string;
  started_at: string;
  packet_count: number;
  byte_count: number;
  job_id: number;
}

interface AgentLiveStats {
  pps: number;
  bps: number;
}

function parseAgentId(sessionId: string, iface: string): string {
  // sessionId format: "agent-{agentId}-{iface}"
  const prefix = "agent-";
  const suffix = "-" + iface;
  let s = sessionId.startsWith(prefix) ? sessionId.slice(prefix.length) : sessionId;
  if (s.endsWith(suffix)) s = s.slice(0, s.length - suffix.length);
  return s || sessionId;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return (bytes / 1_000_000_000).toFixed(1) + " GB";
  if (bytes >= 1_000_000) return (bytes / 1_000_000).toFixed(1) + " MB";
  if (bytes >= 1_000) return (bytes / 1_000).toFixed(1) + " KB";
  return bytes + " B";
}

function formatBps(bps: number): string {
  if (bps >= 1_000_000) return (bps / 1_000_000).toFixed(1) + " Mbps";
  if (bps >= 1_000) return (bps / 1_000).toFixed(1) + " Kbps";
  return bps + " bps";
}

function formatDuration(startedAt: string): string {
  const secs = Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

const STATUS_DOT: Record<string, string> = {
  running:   "bg-emerald-400 animate-pulse",
  analyzing: "bg-yellow-400 animate-pulse",
  stopped:   "bg-slate-400",
  completed: "bg-slate-500",
};

const STATUS_LABEL: Record<string, string> = {
  running:   "text-emerald-400",
  analyzing: "text-yellow-400",
  stopped:   "text-slate-400",
  completed: "text-slate-500",
};

export default function AgentsPanel() {
  const navigate = useNavigate();
  const [sessions, setSessions] = useState<AgentSession[]>([]);
  const liveStats = useRef<Record<string, AgentLiveStats>>({});
  const [, forceRender] = useState(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchSessions = () => {
    api
      .get("/capture/sessions")
      .then((r) => {
        const all: AgentSession[] = r.data ?? [];
        setSessions(all.filter((s) => s.id.startsWith("agent-")));
      })
      .catch(() => {});
  };

  // Poll every 2 s for packet/byte counts
  useEffect(() => {
    fetchSessions();
    pollRef.current = setInterval(fetchSessions, 2000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  // WebSocket: instant notifications on connect/disconnect + per-agent bps/pps
  useWebSocket({
    onMessage(msg) {
      if (msg.type === "capture_state" && msg.payload?.agent_id) {
        // Agent connected or disconnected — refresh immediately
        fetchSessions();
      }
      if (msg.type === "stats" && msg.payload?.session_id?.startsWith("agent-")) {
        const sid: string = msg.payload.session_id;
        liveStats.current[sid] = {
          pps: msg.payload.packets_per_sec ?? 0,
          bps: msg.payload.bytes_per_sec ?? 0,
        };
        forceRender((n) => n + 1);
      }
    },
  });

  if (sessions.length === 0) return null;

  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-medium text-slate-300">Connected Agents</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Remote capture nodes streaming to this central server
          </p>
        </div>
        <span className="text-xs font-medium text-emerald-400 bg-emerald-400/10 px-2 py-1 rounded-full">
          {sessions.filter((s) => s.status === "running").length} live
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-slate-500 border-b border-slate-700/50">
              <th className="text-left pb-2 font-medium">Agent</th>
              <th className="text-left pb-2 font-medium">Interface</th>
              <th className="text-left pb-2 font-medium">Status</th>
              <th className="text-right pb-2 font-medium">Packets</th>
              <th className="text-right pb-2 font-medium">Data</th>
              <th className="text-right pb-2 font-medium">Rate</th>
              <th className="text-right pb-2 font-medium">Duration</th>
              <th className="text-right pb-2 font-medium"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/30">
            {sessions.map((s) => {
              const agentId = parseAgentId(s.id, s.interface_name);
              const live = liveStats.current[s.id];
              const dotClass = STATUS_DOT[s.status] ?? "bg-slate-400";
              const labelClass = STATUS_LABEL[s.status] ?? "text-slate-400";

              return (
                <tr key={s.id} className="hover:bg-slate-700/20 transition-colors">
                  <td className="py-2.5 pr-4">
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${dotClass}`} />
                      <span className="text-white font-mono text-xs">{agentId}</span>
                    </div>
                  </td>
                  <td className="py-2.5 pr-4 text-slate-300 font-mono text-xs">
                    {s.interface_name}
                  </td>
                  <td className="py-2.5 pr-4">
                    <span className={`text-xs font-medium capitalize ${labelClass}`}>
                      {s.status}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4 text-right text-slate-200 font-mono text-xs">
                    {s.packet_count.toLocaleString()}
                    {live && s.status === "running" && (
                      <span className="text-slate-500 ml-1">
                        +{live.pps}/s
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 pr-4 text-right text-slate-300 text-xs">
                    {formatBytes(s.byte_count)}
                  </td>
                  <td className="py-2.5 pr-4 text-right text-xs">
                    {live && s.status === "running" ? (
                      <span className="text-emerald-400">{formatBps(live.bps * 8)}</span>
                    ) : (
                      <span className="text-slate-600">-</span>
                    )}
                  </td>
                  <td className="py-2.5 pr-4 text-right text-slate-400 text-xs">
                    {formatDuration(s.started_at)}
                  </td>
                  <td className="py-2.5 text-right">
                    {s.job_id > 0 && (
                      <button
                        onClick={() => navigate(`/jobs/${s.job_id}`)}
                        className="text-xs text-sky-400 hover:text-sky-300 transition-colors"
                      >
                        View Job →
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
