import { useEffect, useState, useCallback } from "react";
import { api } from "../api/client";
import { Server, Wifi, WifiOff, RefreshCw, Filter, Check, AlertTriangle } from "lucide-react";

interface AgentStatus {
  agent_id: string;
  hostname: string;
  interface: string;
  remote_addr: string;
  session_id: string;
  connected_at: string;
  last_batch_at?: string;
  packets_rx: number;
  bytes_rx: number;
  batch_count: number;
  dropped_pkts: number;
  stale: boolean;
  current_filter?: string;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

function formatDuration(iso: string): string {
  const secs = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
}

function formatTime(iso?: string): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleTimeString();
}

function dropRate(agent: AgentStatus): string {
  const total = agent.packets_rx + agent.dropped_pkts;
  if (total === 0) return "0%";
  return `${((agent.dropped_pkts / total) * 100).toFixed(1)}%`;
}

function FilterEditor({ agent }: { agent: AgentStatus }) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(agent.current_filter ?? "");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  const submit = async () => {
    setSaving(true);
    setError("");
    try {
      await api.put(`/agents/${encodeURIComponent(agent.agent_id)}/filter`, {
        bpf_filter: value,
      });
      setSaved(true);
      setEditing(false);
      setTimeout(() => setSaved(false), 2500);
    } catch (e: any) {
      setError(e?.response?.data || "Failed to update filter");
    } finally {
      setSaving(false);
    }
  };

  if (!editing) {
    return (
      <div className="flex items-center gap-2">
        <span className="font-mono text-slate-400 text-xs">
          {agent.current_filter || <span className="text-slate-600 italic">none</span>}
        </span>
        {saved && <Check className="w-3.5 h-3.5 text-emerald-400" />}
        <button
          onClick={() => {
            setValue(agent.current_filter ?? "");
            setEditing(true);
          }}
          className="text-slate-600 hover:text-slate-300 transition-colors"
          title="Edit BPF filter"
        >
          <Filter className="w-3.5 h-3.5" />
        </button>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-1.5 min-w-0">
      <input
        autoFocus
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") submit();
          if (e.key === "Escape") setEditing(false);
        }}
        placeholder="e.g. port 5060"
        className="bg-slate-900 border border-slate-600 focus:border-emerald-500 rounded px-2 py-0.5 text-xs font-mono text-white w-36 outline-none"
      />
      <button
        onClick={submit}
        disabled={saving}
        className="px-2 py-0.5 text-xs bg-emerald-700 hover:bg-emerald-600 text-white rounded disabled:opacity-50 transition-colors"
      >
        {saving ? "…" : "Set"}
      </button>
      <button
        onClick={() => setEditing(false)}
        className="text-slate-600 hover:text-slate-300 text-xs transition-colors"
      >
        ✕
      </button>
      {error && (
        <span className="text-red-400 text-xs truncate" title={error}>
          {error}
        </span>
      )}
    </div>
  );
}

export default function AgentsPage() {
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  const fetchAgents = useCallback(async () => {
    try {
      const res = await api.get("/agents");
      setAgents(res.data || []);
      setLastRefresh(new Date());
    } catch {
      // returns [] in standalone mode
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 3000);
    return () => clearInterval(interval);
  }, [fetchAgents]);

  const staleCount = agents.filter((a) => a.stale).length;
  const liveCount = agents.length - staleCount;

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white flex items-center gap-2">
            <Server className="w-5 h-5 text-emerald-400" />
            Capture Agents
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Live-connected remote capture nodes — auto-refreshes every 3s
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500">
            Updated {lastRefresh.toLocaleTimeString()}
          </span>
          <button
            onClick={fetchAgents}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary bar */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4">
          <div className="text-2xl font-bold text-white">{liveCount}</div>
          <div className="text-xs text-slate-400 mt-0.5">Live Agents</div>
        </div>
        <div className={`rounded-xl p-4 border ${staleCount > 0 ? "bg-amber-900/20 border-amber-700/40" : "bg-slate-800/60 border-slate-700/50"}`}>
          <div className={`text-2xl font-bold ${staleCount > 0 ? "text-amber-400" : "text-slate-500"}`}>{staleCount}</div>
          <div className="text-xs text-slate-400 mt-0.5">Stale (no data &gt;30s)</div>
        </div>
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4">
          <div className="text-2xl font-bold text-emerald-400">
            {agents.reduce((s, a) => s + a.packets_rx, 0).toLocaleString()}
          </div>
          <div className="text-xs text-slate-400 mt-0.5">Total Packets Rx</div>
        </div>
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-4">
          <div className="text-2xl font-bold text-sky-400">
            {formatBytes(agents.reduce((s, a) => s + a.bytes_rx, 0))}
          </div>
          <div className="text-xs text-slate-400 mt-0.5">Total Bytes Rx</div>
        </div>
      </div>

      {/* Agent table */}
      {loading ? (
        <div className="text-slate-500 text-sm animate-pulse py-8 text-center">
          Loading agents…
        </div>
      ) : agents.length === 0 ? (
        <div className="bg-slate-800/40 border border-slate-700/50 rounded-xl p-12 text-center">
          <WifiOff className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400 font-medium">No agents connected</p>
          <p className="text-slate-500 text-xs mt-1 max-w-sm mx-auto">
            Start a capture node with{" "}
            <code className="bg-slate-900 px-1.5 py-0.5 rounded text-emerald-400">
              deeppacketai --mode=agent --iface=eth0 --central=&lt;this-ip&gt;:9090
            </code>
          </p>
          <p className="text-slate-600 text-xs mt-3">
            Note: In standalone mode this page is always empty — start with{" "}
            <code className="text-slate-400">--mode=central</code> to enable agent connections.
          </p>
        </div>
      ) : (
        <div className="bg-slate-800/40 border border-slate-700/50 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/60">
                <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Status</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Agent / Host</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Interface</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Remote IP</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Connected</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Pkts Rx</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Bytes Rx</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Drop%</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Last Batch</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">BPF Filter</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/40">
              {agents.map((agent) => (
                <tr
                  key={agent.agent_id}
                  className={`hover:bg-slate-700/20 transition-colors ${agent.stale ? "opacity-60" : ""}`}
                >
                  <td className="px-4 py-3">
                    {agent.stale ? (
                      <span className="flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        <span className="text-xs text-amber-400 font-medium">Stale</span>
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                        <span className="text-xs text-emerald-400 font-medium">Live</span>
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Wifi className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                      <div>
                        <div className="text-white font-medium text-xs">{agent.agent_id}</div>
                        <div className="text-slate-500 text-xs">{agent.hostname}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs bg-slate-900/60 border border-slate-700 px-2 py-0.5 rounded text-slate-300 font-mono">
                      {agent.interface}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-300 text-xs font-mono">
                    {agent.remote_addr}
                  </td>
                  <td className="px-4 py-3 text-slate-300 text-xs">
                    {formatDuration(agent.connected_at)}
                  </td>
                  <td className="px-4 py-3 text-right text-white font-mono text-xs">
                    {agent.packets_rx.toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-right text-sky-400 font-mono text-xs">
                    {formatBytes(agent.bytes_rx)}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <span className={agent.dropped_pkts === 0 ? "text-emerald-400 text-xs" : "text-amber-400 text-xs font-medium"}>
                      {dropRate(agent)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-400 text-xs">
                    {formatTime(agent.last_batch_at)}
                  </td>
                  <td className="px-4 py-3">
                    <FilterEditor agent={agent} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Session IDs (collapsed, for debugging) */}
      {agents.length > 0 && (
        <details className="group">
          <summary className="text-xs text-slate-600 cursor-pointer hover:text-slate-400 select-none">
            Session IDs (debug)
          </summary>
          <div className="mt-1 space-y-1">
            {agents.map((a) => (
              <div key={a.agent_id} className="flex items-center gap-2 text-xs">
                <span className="text-slate-400">{a.agent_id}</span>
                <span className="text-slate-600">→</span>
                <span className="font-mono text-slate-500">{a.session_id}</span>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
