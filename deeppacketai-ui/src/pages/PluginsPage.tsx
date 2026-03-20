import { useEffect, useState, useCallback } from "react";
import { api } from "../api/client";
import {
  Puzzle,
  Radio,
  ShieldCheck,
  Bot,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Loader2,
} from "lucide-react";
import { clsx } from "clsx";

// ── Types ─────────────────────────────────────────────────────────────────────

interface PluginManifest {
  name: string;
  version: string;
  author: string;
  description: string;
  category: "protocol" | "detection" | "ai";
  tags?: string[];
  protocols?: string[];
  ports?: number[];
  severity?: string;
  cost_tier?: string;
  max_tokens?: number;
  capabilities?: string[];
}

interface PluginStatus extends PluginManifest {
  enabled: boolean;
  active?: boolean;
  loaded_at: string;
  error?: string;
}

interface AllPlugins {
  protocol: PluginStatus[];
  detection: PluginStatus[];
  ai: PluginStatus[];
}

// ── Severity badge ────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity?: string }) {
  if (!severity) return null;
  const cls: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    error: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    warning: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    info: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  };
  return (
    <span
      className={clsx(
        "text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded border",
        cls[severity] ?? "bg-slate-500/15 text-slate-400 border-slate-500/30"
      )}
    >
      {severity}
    </span>
  );
}

// ── Tag pill ──────────────────────────────────────────────────────────────────

function Tag({ label }: { label: string }) {
  return (
    <span className="text-[10px] bg-slate-700/60 text-slate-400 px-1.5 py-0.5 rounded">
      {label}
    </span>
  );
}

// ── Toggle switch ─────────────────────────────────────────────────────────────

interface ToggleProps {
  enabled: boolean;
  onToggle: () => void;
  disabled?: boolean;
}

function Toggle({ enabled, onToggle, disabled }: ToggleProps) {
  return (
    <button
      onClick={onToggle}
      disabled={disabled}
      className={clsx(
        "relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent",
        "transition-colors duration-200 ease-in-out focus:outline-none",
        enabled ? "bg-emerald-500" : "bg-slate-600",
        disabled && "opacity-50 cursor-not-allowed"
      )}
      aria-checked={enabled}
      role="switch"
    >
      <span
        className={clsx(
          "pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-sm",
          "transform transition duration-200 ease-in-out",
          enabled ? "translate-x-4" : "translate-x-0"
        )}
      />
    </button>
  );
}

// ── Protocol plugin card ──────────────────────────────────────────────────────

interface ProtocolCardProps {
  plugin: PluginStatus;
  onToggle: (name: string, enable: boolean) => Promise<void>;
}

function ProtocolCard({ plugin, onToggle }: ProtocolCardProps) {
  const [busy, setBusy] = useState(false);

  const handleToggle = async () => {
    setBusy(true);
    try {
      await onToggle(plugin.name, !plugin.enabled);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className={clsx(
        "bg-slate-800/50 border rounded-lg p-4 flex flex-col gap-2 transition-opacity",
        plugin.enabled ? "border-slate-700/50" : "border-slate-700/30 opacity-60"
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-white">{plugin.name}</span>
            <span className="text-[10px] text-slate-500">v{plugin.version}</span>
            {(plugin.protocols ?? []).map((p) => (
              <Tag key={p} label={p} />
            ))}
          </div>
          <p className="text-xs text-slate-400 mt-1 line-clamp-2">{plugin.description}</p>
        </div>
        <div className="shrink-0 flex items-center gap-2">
          {busy ? (
            <Loader2 className="w-4 h-4 text-emerald-400 animate-spin" />
          ) : (
            <Toggle enabled={plugin.enabled} onToggle={handleToggle} />
          )}
        </div>
      </div>

      {/* Tags and ports row */}
      <div className="flex flex-wrap gap-1 mt-1">
        {(plugin.tags ?? []).map((t) => (
          <Tag key={t} label={t} />
        ))}
        {(plugin.ports ?? []).length > 0 && (
          <Tag label={`ports: ${plugin.ports!.join(", ")}`} />
        )}
      </div>

      {plugin.error && (
        <p className="text-xs text-red-400 mt-1">{plugin.error}</p>
      )}
    </div>
  );
}

// ── Detection plugin card ─────────────────────────────────────────────────────

interface DetectionCardProps {
  plugin: PluginStatus;
  onToggle: (name: string, enable: boolean) => Promise<void>;
}

function DetectionCard({ plugin, onToggle }: DetectionCardProps) {
  const [busy, setBusy] = useState(false);

  const handleToggle = async () => {
    setBusy(true);
    try {
      await onToggle(plugin.name, !plugin.enabled);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className={clsx(
        "bg-slate-800/50 border rounded-lg p-4 flex flex-col gap-2 transition-opacity",
        plugin.enabled ? "border-slate-700/50" : "border-slate-700/30 opacity-60"
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-white">{plugin.name}</span>
            <SeverityBadge severity={plugin.severity} />
            {(plugin.protocols ?? []).map((p) => (
              <Tag key={p} label={p} />
            ))}
          </div>
          <p className="text-xs text-slate-400 mt-1">{plugin.description}</p>
        </div>
        <div className="shrink-0 flex items-center gap-2">
          {busy ? (
            <Loader2 className="w-4 h-4 text-emerald-400 animate-spin" />
          ) : (
            <Toggle enabled={plugin.enabled} onToggle={handleToggle} />
          )}
        </div>
      </div>

      <div className="flex flex-wrap gap-1 mt-1">
        {(plugin.tags ?? []).map((t) => (
          <Tag key={t} label={t} />
        ))}
      </div>
    </div>
  );
}

// ── AI plugin card ────────────────────────────────────────────────────────────

interface AICardProps {
  plugin: PluginStatus;
  onActivate: (name: string) => Promise<void>;
}

function AICard({ plugin, onActivate }: AICardProps) {
  const [busy, setBusy] = useState(false);

  const handleActivate = async () => {
    if (plugin.active || !plugin.enabled) return;
    setBusy(true);
    try {
      await onActivate(plugin.name);
    } finally {
      setBusy(false);
    }
  };

  const costColor: Record<string, string> = {
    free: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    paid: "bg-violet-500/15 text-violet-400 border-violet-500/30",
  };

  return (
    <div
      className={clsx(
        "bg-slate-800/50 border rounded-lg p-4 flex flex-col gap-3 transition-all",
        plugin.active
          ? "border-emerald-500/50 ring-1 ring-emerald-500/20"
          : "border-slate-700/50"
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-white capitalize">{plugin.name}</span>
            <span className="text-[10px] text-slate-500">v{plugin.version}</span>
            {plugin.cost_tier && (
              <span
                className={clsx(
                  "text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded border",
                  costColor[plugin.cost_tier] ??
                    "bg-slate-500/15 text-slate-400 border-slate-500/30"
                )}
              >
                {plugin.cost_tier}
              </span>
            )}
            {plugin.active && (
              <span className="flex items-center gap-1 text-[10px] text-emerald-400 font-semibold">
                <CheckCircle2 className="w-3 h-3" /> Active
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">{plugin.description}</p>
        </div>

        {/* Radio button to activate */}
        <button
          onClick={handleActivate}
          disabled={plugin.active || !plugin.enabled || busy}
          title={
            !plugin.enabled
              ? "Provider disabled"
              : plugin.active
              ? "Already active"
              : "Set as active provider"
          }
          className={clsx(
            "mt-0.5 w-5 h-5 rounded-full border-2 shrink-0 transition-all",
            plugin.active
              ? "border-emerald-500 bg-emerald-500"
              : "border-slate-500 bg-transparent hover:border-emerald-400",
            (plugin.active || !plugin.enabled) && "cursor-default"
          )}
        >
          {busy && <Loader2 className="w-3 h-3 text-white animate-spin m-auto" />}
        </button>
      </div>

      {/* Capabilities and limits */}
      <div className="flex flex-wrap gap-2">
        {(plugin.capabilities ?? []).map((c) => (
          <Tag key={c} label={c} />
        ))}
        {plugin.max_tokens && (
          <Tag label={`${(plugin.max_tokens / 1000).toFixed(0)}k ctx`} />
        )}
        {(plugin.tags ?? []).map((t) => (
          <Tag key={t} label={t} />
        ))}
      </div>

      {!plugin.enabled && (
        <div className="flex items-center gap-1.5 text-xs text-slate-500">
          <XCircle className="w-3.5 h-3.5" />
          No API key configured
        </div>
      )}
    </div>
  );
}

// ── Tabs ──────────────────────────────────────────────────────────────────────

type TabKey = "protocol" | "detection" | "ai";

interface Tab {
  key: TabKey;
  label: string;
  icon: React.ElementType;
  count: number;
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function PluginsPage() {
  const [data, setData] = useState<AllPlugins | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("protocol");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<AllPlugins>("/plugins");
      setData(res.data);
    } catch (e: any) {
      setError(e?.message ?? "Failed to load plugins");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // ── Mutation helpers ───────────────────────────────────────────────────────

  const toggleProtocol = useCallback(
    async (name: string, enable: boolean) => {
      const action = enable ? "enable" : "disable";
      await api.post(`/plugins/protocol/${encodeURIComponent(name)}/${action}`);
      setData((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          protocol: prev.protocol.map((p) =>
            p.name === name ? { ...p, enabled: enable } : p
          ),
        };
      });
    },
    []
  );

  const toggleDetection = useCallback(
    async (name: string, enable: boolean) => {
      const action = enable ? "enable" : "disable";
      await api.post(`/plugins/detection/${encodeURIComponent(name)}/${action}`);
      setData((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          detection: prev.detection.map((p) =>
            p.name === name ? { ...p, enabled: enable } : p
          ),
        };
      });
    },
    []
  );

  const activateAI = useCallback(async (name: string) => {
    await api.post(`/plugins/ai/${encodeURIComponent(name)}/activate`);
    setData((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        ai: prev.ai.map((p) => ({ ...p, active: p.name === name })),
      };
    });
  }, []);

  // ── Tab definitions ────────────────────────────────────────────────────────

  const tabs: Tab[] = [
    {
      key: "protocol",
      label: "Protocol Decoders",
      icon: Radio,
      count: data?.protocol.length ?? 0,
    },
    {
      key: "detection",
      label: "Detection Rules",
      icon: ShieldCheck,
      count: data?.detection.length ?? 0,
    },
    {
      key: "ai",
      label: "AI Providers",
      icon: Bot,
      count: data?.ai.length ?? 0,
    },
  ];

  const totalLoaded =
    (data?.protocol.length ?? 0) +
    (data?.detection.length ?? 0) +
    (data?.ai.length ?? 0);

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-full bg-slate-950 text-white overflow-hidden">
      {/* Header */}
      <div className="shrink-0 border-b border-slate-800 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-emerald-400 to-cyan-400 flex items-center justify-center">
              <Puzzle className="w-4 h-4 text-slate-900" />
            </div>
            <div>
              <h1 className="text-lg font-semibold">Plugins</h1>
              <p className="text-xs text-slate-400">
                {loading ? "Loading…" : `${totalLoaded} plugins loaded`}
              </p>
            </div>
          </div>

          {/* Summary badges */}
          {data && !loading && (
            <div className="hidden md:flex items-center gap-3">
              <SummaryBadge
                label="Protocol"
                enabled={data.protocol.filter((p) => p.enabled).length}
                total={data.protocol.length}
                color="emerald"
              />
              <SummaryBadge
                label="Detection"
                enabled={data.detection.filter((p) => p.enabled).length}
                total={data.detection.length}
                color="cyan"
              />
              <SummaryBadge
                label="AI"
                enabled={data.ai.filter((p) => p.enabled).length}
                total={data.ai.length}
                color="violet"
              />
            </div>
          )}

          <button
            onClick={load}
            disabled={loading}
            className="p-2 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            title="Refresh"
          >
            <RefreshCw className={clsx("w-4 h-4", loading && "animate-spin")} />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mt-4">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={clsx(
                "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all",
                activeTab === tab.key
                  ? "bg-slate-800 text-emerald-400"
                  : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
              )}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
              {tab.count > 0 && (
                <span
                  className={clsx(
                    "text-[10px] font-bold px-1.5 py-0.5 rounded-full",
                    activeTab === tab.key
                      ? "bg-emerald-500/20 text-emerald-400"
                      : "bg-slate-700 text-slate-400"
                  )}
                >
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
        {loading && (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-6 h-6 text-emerald-400 animate-spin" />
          </div>
        )}

        {error && !loading && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400 text-sm">
            {error}
          </div>
        )}

        {data && !loading && (
          <>
            {/* Protocol tab */}
            {activeTab === "protocol" && (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {data.protocol.map((p) => (
                  <ProtocolCard key={p.name} plugin={p} onToggle={toggleProtocol} />
                ))}
              </div>
            )}

            {/* Detection tab */}
            {activeTab === "detection" && (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {data.detection.map((p) => (
                  <DetectionCard key={p.name} plugin={p} onToggle={toggleDetection} />
                ))}
              </div>
            )}

            {/* AI tab */}
            {activeTab === "ai" && (
              <div>
                {data.ai.length === 0 ? (
                  <div className="text-center py-16 text-slate-500">
                    <Bot className="w-10 h-10 mx-auto mb-3 opacity-40" />
                    <p className="text-sm">No AI providers configured.</p>
                    <p className="text-xs mt-1">
                      Set <code className="bg-slate-800 px-1 py-0.5 rounded">ANTHROPIC_API_KEY</code>,{" "}
                      <code className="bg-slate-800 px-1 py-0.5 rounded">OPENAI_API_KEY</code>, or{" "}
                      <code className="bg-slate-800 px-1 py-0.5 rounded">GEMINI_API_KEY</code> environment
                      variables and restart the server.
                    </p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                    {data.ai.map((p) => (
                      <AICard key={p.name} plugin={p} onActivate={activateAI} />
                    ))}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ── Summary badge ─────────────────────────────────────────────────────────────

function SummaryBadge({
  label,
  enabled,
  total,
  color,
}: {
  label: string;
  enabled: number;
  total: number;
  color: "emerald" | "cyan" | "violet";
}) {
  const colorCls: Record<string, string> = {
    emerald: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    cyan: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
    violet: "bg-violet-500/10 text-violet-400 border-violet-500/20",
  };
  return (
    <div
      className={clsx(
        "flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border font-medium",
        colorCls[color]
      )}
    >
      <span>
        {enabled}/{total}
      </span>
      <span className="text-[10px] opacity-70">{label}</span>
    </div>
  );
}
