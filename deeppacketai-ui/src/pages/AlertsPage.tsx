import { useEffect, useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import {
  AlertCircle, AlertTriangle, Info, Shield, Filter,
  ChevronDown, ChevronRight, ExternalLink, Wifi, Globe,
  Phone, Lock, Zap, Brain, RefreshCw,
} from "lucide-react";
import { clsx } from "clsx";

// ---- Severity config -------------------------------------------------------
const SEV: Record<string, { color: string; bg: string; border: string; icon: typeof AlertCircle }> = {
  critical: { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    icon: AlertCircle },
  error:    { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", icon: AlertCircle },
  warning:  { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", icon: AlertTriangle },
  info:     { color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   icon: Info },
};

// ---- Detection categories --------------------------------------------------
type Category = "Security" | "QoS / Voice" | "Protocol" | "Volume" | "Other";

function classifyAlert(alert: any): Category {
  const title: string = alert.title ?? "";
  const proto: string = alert.protocol ?? "";
  const attackType: string = alert.metadata_json?.attack_type ?? "";

  if (
    attackType ||
    /brute.?force|tunnel|downgrade|hijack|fraud|flood.*sip|sip.*flood|scan/i.test(title)
  ) return "Security";

  if (/packet.loss|jitter|mos|qos|call.drop|one.way|audio/i.test(title)) return "QoS / Voice";

  if (/mismatch|unusual.port|protocol/i.test(title)) return "Protocol";

  if (/flood|spike|burst|volume|concentrat/i.test(title)) return "Volume";

  if (proto === "RTP" || proto === "SIP") return "QoS / Voice";
  if (proto === "TLS" || proto === "DNS") return "Protocol";

  return "Other";
}

const CATEGORY_ICONS: Record<Category, typeof Shield> = {
  "Security":    Shield,
  "QoS / Voice": Phone,
  "Protocol":    Lock,
  "Volume":      Zap,
  "Other":       Globe,
};

const CATEGORY_COLORS: Record<Category, string> = {
  "Security":    "text-red-400 bg-red-900/20 border-red-500/30",
  "QoS / Voice": "text-green-400 bg-green-900/20 border-green-500/30",
  "Protocol":    "text-cyan-400 bg-cyan-900/20 border-cyan-500/30",
  "Volume":      "text-orange-400 bg-orange-900/20 border-orange-500/30",
  "Other":       "text-slate-400 bg-slate-800/40 border-slate-600/30",
};

// ---- Attack type badges ----------------------------------------------------
const ATTACK_BADGES: Record<string, string> = {
  sip_brute_force: "SIP Brute Force",
  dns_tunneling:   "DNS Tunneling",
  tls_downgrade:   "TLS Downgrade",
};

// ---- AI analysis state per alert ------------------------------------------
// result can be non-null while loading=true (streaming partial content)
type AIState = { loading: boolean; result: string | null };

// ---- Main component --------------------------------------------------------
export default function AlertsPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<Category | "">("");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [aiStates, setAIStates] = useState<Record<number, AIState>>({});

  const fetchAlerts = () => {
    setLoading(true);
    const params = new URLSearchParams({ limit: "500" });
    if (severityFilter) params.set("severity", severityFilter);

    api
      .get(`/alerts?${params}`)
      .then((r) => setAlerts(r.data ?? []))
      .catch(() => setAlerts([]))
      .finally(() => setLoading(false));
  };

  useEffect(fetchAlerts, [severityFilter]);

  // Parse metadata_json once
  const parsed = useMemo(
    () =>
      alerts.map((a) => {
        let meta: Record<string, unknown> = {};
        if (a.metadata_json) {
          try { meta = typeof a.metadata_json === "string" ? JSON.parse(a.metadata_json) : a.metadata_json; } catch { /* */ }
        }
        const category = classifyAlert({ ...a, metadata_json: meta });
        return { ...a, meta, category };
      }),
    [alerts]
  );

  // Available protocols for filter dropdown
  const protocols = useMemo(
    () => [...new Set(parsed.map((a) => a.protocol).filter(Boolean))].sort(),
    [parsed]
  );

  // Apply filters
  const filtered = useMemo(() => {
    return parsed.filter((a) => {
      if (protocolFilter && a.protocol !== protocolFilter) return false;
      if (categoryFilter && a.category !== categoryFilter) return false;
      return true;
    });
  }, [parsed, protocolFilter, categoryFilter]);

  // Stats
  const counts = useMemo(() => {
    const c: Record<string, number> = { critical: 0, error: 0, warning: 0, info: 0 };
    for (const a of filtered) c[a.severity] = (c[a.severity] ?? 0) + 1;
    return c;
  }, [filtered]);

  const catCounts = useMemo(() => {
    const c: Partial<Record<Category, number>> = {};
    for (const a of parsed) c[a.category as Category] = (c[a.category as Category] ?? 0) + 1;
    return c;
  }, [parsed]);

  // AI explain — streams SSE chunks from /chat/conversations/:id/messages
  const explainAlert = async (alert: any) => {
    setAIStates((s) => ({ ...s, [alert.id]: { loading: true, result: null } }));
    try {
      // 1. Create conversation
      const res = await api.post("/chat/conversations", { title: `Alert: ${alert.title}` });
      const convId = res.data?.id;
      if (!convId) throw new Error("no conversation id returned");

      const prompt =
        `Analyze this network security alert and explain clearly:\n\n` +
        `Title: ${alert.title}\n` +
        `Severity: ${alert.severity}\n` +
        `Protocol: ${alert.protocol}\n` +
        `Description: ${alert.description}\n\n` +
        `Please cover: 1) What caused this alert? 2) What is the potential impact? 3) What actions should be taken?`;

      // 2. Send message and read SSE stream
      const response = await fetch(`/api/v1/chat/conversations/${convId}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: prompt }),
      });

      if (!response.ok) throw new Error(`AI service error: HTTP ${response.status}`);
      if (!response.body) throw new Error("no response body from AI service");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let fullContent = "";
      let sseBuffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        sseBuffer += decoder.decode(value, { stream: true });
        const lines = sseBuffer.split("\n");
        sseBuffer = lines.pop() ?? ""; // keep last incomplete line

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const jsonStr = line.slice(6).trim();
          if (!jsonStr) continue;

          let parsed: any;
          try {
            parsed = JSON.parse(jsonStr);
          } catch {
            continue; // skip malformed SSE lines
          }

          // Protocol-level error from the AI service
          if (parsed.error) {
            throw new Error(parsed.error);
          }
          if (parsed.content) {
            fullContent += parsed.content;
            // Update UI progressively while still loading
            setAIStates((s) => ({ ...s, [alert.id]: { loading: true, result: fullContent } }));
          }
          if (parsed.done) {
            setAIStates((s) => ({ ...s, [alert.id]: { loading: false, result: fullContent || "No analysis returned." } }));
            return;
          }
        }
      }

      // Stream ended without a done event
      setAIStates((s) => ({ ...s, [alert.id]: { loading: false, result: fullContent || "No analysis returned." } }));
    } catch (e: any) {
      setAIStates((s) => ({ ...s, [alert.id]: { loading: false, result: `Error: ${e.message}` } }));
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Detection Alerts</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Rule-based + AI detection · {filtered.length} of {alerts.length} alerts
          </p>
        </div>
        <button
          onClick={fetchAlerts}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-700/60 hover:bg-slate-700 text-sm text-slate-300 transition-all"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Severity strip */}
      <div className="grid grid-cols-4 gap-3">
        {(["critical", "error", "warning", "info"] as const).map((sev) => {
          const cfg = SEV[sev];
          const Icon = cfg.icon;
          const n = counts[sev] ?? 0;
          const active = severityFilter === sev;
          return (
            <button
              key={sev}
              onClick={() => setSeverityFilter(active ? "" : sev)}
              className={clsx(
                "flex items-center gap-3 px-4 py-3 rounded-xl border transition-all text-left",
                active ? `${cfg.bg} ${cfg.border} ring-1 ring-current` : "bg-slate-800/50 border-slate-700/50 hover:bg-slate-800"
              )}
            >
              <Icon className={clsx("w-5 h-5", cfg.color)} />
              <div>
                <div className={clsx("text-xl font-black", cfg.color)}>{n}</div>
                <div className="text-xs text-slate-500 capitalize">{sev}</div>
              </div>
            </button>
          );
        })}
      </div>

      {/* Category pills */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-slate-500 mr-1">Category:</span>
        {(["Security", "QoS / Voice", "Protocol", "Volume", "Other"] as Category[]).map((cat) => {
          const n = catCounts[cat] ?? 0;
          if (n === 0) return null;
          const active = categoryFilter === cat;
          const Icon = CATEGORY_ICONS[cat];
          return (
            <button
              key={cat}
              onClick={() => setCategoryFilter(active ? "" : cat)}
              className={clsx(
                "flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-semibold transition-all",
                active ? CATEGORY_COLORS[cat] : "text-slate-400 bg-slate-800/40 border-slate-700/40 hover:bg-slate-800"
              )}
            >
              <Icon className="w-3 h-3" />
              {cat}
              <span className="ml-0.5 opacity-70">({n})</span>
            </button>
          );
        })}
      </div>

      {/* Protocol filter */}
      <div className="flex items-center gap-2">
        <Filter className="w-4 h-4 text-slate-500" />
        <select
          value={protocolFilter}
          onChange={(e) => setProtocolFilter(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:ring-1 focus:ring-emerald-500"
        >
          <option value="">All Protocols</option>
          {protocols.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        {(severityFilter || protocolFilter || categoryFilter) && (
          <button
            onClick={() => { setSeverityFilter(""); setProtocolFilter(""); setCategoryFilter(""); }}
            className="text-xs text-slate-400 hover:text-slate-200 underline"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Alert list */}
      {loading ? (
        <div className="flex items-center justify-center py-16 text-slate-400 text-sm">Loading alerts...</div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 gap-3 text-slate-500">
          <Shield className="w-10 h-10 opacity-20" />
          <div className="text-sm">No alerts match current filters</div>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((alert) => {
            const cfg = SEV[alert.severity] ?? SEV.info;
            const Icon = cfg.icon;
            const isExpanded = expandedId === alert.id;
            const CatIcon = CATEGORY_ICONS[alert.category as Category] ?? Globe;
            const aiState = aiStates[alert.id];
            const attackBadge = ATTACK_BADGES[alert.meta?.attack_type as string];

            return (
              <div
                key={alert.id}
                className={clsx("rounded-xl border transition-all", cfg.bg, cfg.border)}
              >
                {/* Row */}
                <div
                  className="flex items-start gap-3 px-4 py-3 cursor-pointer hover:brightness-110"
                  onClick={() => setExpandedId(isExpanded ? null : alert.id)}
                >
                  {isExpanded
                    ? <ChevronDown className="w-4 h-4 mt-0.5 text-slate-500 shrink-0" />
                    : <ChevronRight className="w-4 h-4 mt-0.5 text-slate-500 shrink-0" />
                  }
                  <Icon className={clsx("w-4 h-4 mt-0.5 shrink-0", cfg.color)} />

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold text-slate-100">{alert.title}</span>

                      {/* Protocol badge */}
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-700/60 text-slate-300 border border-slate-600/40">
                        {alert.protocol}
                      </span>

                      {/* Severity badge */}
                      <span className={clsx("px-1.5 py-0.5 rounded text-[10px] font-bold border", cfg.bg, cfg.color, cfg.border)}>
                        {alert.severity}
                      </span>

                      {/* Category badge */}
                      <span className={clsx("flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold border", CATEGORY_COLORS[alert.category as Category])}>
                        <CatIcon className="w-2.5 h-2.5" />
                        {alert.category}
                      </span>

                      {/* Attack type badge */}
                      {attackBadge && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-900/40 text-red-300 border border-red-500/40">
                          ⚠ {attackBadge}
                        </span>
                      )}

                      {/* AI indicator */}
                      {alert.meta?.tunnel_score && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-violet-900/30 text-violet-300 border border-violet-500/30">
                          Score: {alert.meta.tunnel_score}
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-slate-400 mt-0.5 truncate">{alert.description}</p>
                    <div className="text-[10px] text-slate-600 mt-1">{alert.timestamp}</div>
                  </div>
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="border-t border-slate-700/40 px-4 py-3 ml-7 space-y-3">
                    <p className="text-sm text-slate-300">{alert.description}</p>

                    {/* Metadata grid */}
                    {Object.keys(alert.meta).length > 0 && (
                      <div>
                        <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1.5">Details</div>
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-1">
                          {Object.entries(alert.meta).map(([key, val]) => (
                            <div key={key} className="flex gap-2 text-xs">
                              <span className="text-slate-500 shrink-0">{key}:</span>
                              <span className="text-slate-300 font-mono truncate">{String(val)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* AI analysis */}
                    <div className="border-t border-slate-700/40 pt-3">
                      {!aiState && (
                        <button
                          onClick={() => explainAlert(alert)}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-violet-900/30 hover:bg-violet-900/50 border border-violet-500/30 text-xs text-violet-300 transition-all"
                        >
                          <Brain className="w-3.5 h-3.5" />
                          Ask AI to Analyze
                        </button>
                      )}
                      {aiState && (
                        <div className="bg-violet-900/10 border border-violet-500/20 rounded-lg p-3">
                          <div className="flex items-center gap-1.5 text-[10px] font-semibold text-violet-400 mb-2">
                            <Brain className="w-3 h-3" />
                            AI Analysis
                            {aiState.loading && (
                              <Wifi className="w-3 h-3 animate-pulse ml-1" />
                            )}
                          </div>
                          {aiState.result ? (
                            <p className="text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">
                              {aiState.result}
                              {aiState.loading && (
                                <span className="inline-block w-1.5 h-3 bg-violet-400 animate-pulse ml-0.5 align-middle" />
                              )}
                            </p>
                          ) : (
                            <div className="flex items-center gap-2 text-xs text-violet-400">
                              <Wifi className="w-3.5 h-3.5 animate-pulse" /> Analyzing...
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Navigation links */}
                    <div className="flex items-center gap-3 pt-1">
                      {alert.job_id && (
                        <button
                          onClick={(e) => { e.stopPropagation(); navigate(`/jobs/${alert.job_id}`); }}
                          className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300"
                        >
                          <ExternalLink className="w-3 h-3" /> Job #{alert.job_id}
                        </button>
                      )}
                      {alert.packet_id && (
                        <button
                          onClick={(e) => { e.stopPropagation(); navigate(`/packets?id=${alert.packet_id}`); }}
                          className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300"
                        >
                          <ExternalLink className="w-3 h-3" /> Packet #{alert.packet_id}
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
