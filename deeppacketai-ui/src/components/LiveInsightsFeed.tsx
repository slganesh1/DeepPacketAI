import { useEffect, useRef, useState } from "react";
import { Brain, AlertTriangle, ShieldAlert, Info, ChevronDown, ChevronUp } from "lucide-react";

export interface AIInsight {
  session_id: string;
  timestamp: string;
  severity: "info" | "warning" | "critical";
  summary: string;
  anomalies: string[];
  threats: string[];
  frauds: string[];
  elapsed_secs: number;
  total_packets: number;
}

interface Props {
  insights: AIInsight[];
  analyzing?: boolean; // show spinner while waiting for first insight
}

function SeverityIcon({ severity }: { severity: AIInsight["severity"] }) {
  if (severity === "critical")
    return <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />;
  if (severity === "warning")
    return <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />;
  return <Info className="w-4 h-4 text-sky-400 flex-shrink-0 mt-0.5" />;
}

const SEVERITY_BORDER: Record<string, string> = {
  critical: "border-red-500/30 bg-red-500/5",
  warning:  "border-yellow-500/30 bg-yellow-500/5",
  info:     "border-sky-500/20 bg-sky-500/5",
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "text-red-400 bg-red-400/10",
  warning:  "text-yellow-400 bg-yellow-400/10",
  info:     "text-sky-400 bg-sky-400/10",
};

function InsightCard({ insight }: { insight: AIInsight }) {
  const [expanded, setExpanded] = useState(false);
  const hasDetails =
    (insight.anomalies?.length ?? 0) > 0 ||
    (insight.threats?.length ?? 0) > 0 ||
    (insight.frauds?.length ?? 0) > 0;

  return (
    <div
      className={`border rounded-lg p-3 transition-all ${SEVERITY_BORDER[insight.severity] ?? SEVERITY_BORDER.info}`}
    >
      <div className="flex items-start gap-2">
        <SeverityIcon severity={insight.severity} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2 mb-1">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">{insight.timestamp}</span>
              <span
                className={`text-[10px] font-medium px-1.5 py-0.5 rounded uppercase ${
                  SEVERITY_BADGE[insight.severity] ?? SEVERITY_BADGE.info
                }`}
              >
                {insight.severity}
              </span>
              <span className="text-xs text-slate-500">
                {insight.total_packets?.toLocaleString()} pkts · {insight.elapsed_secs}s elapsed
              </span>
            </div>
            {hasDetails && (
              <button
                onClick={() => setExpanded((v) => !v)}
                className="text-slate-500 hover:text-slate-300 flex-shrink-0"
              >
                {expanded ? (
                  <ChevronUp className="w-3.5 h-3.5" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5" />
                )}
              </button>
            )}
          </div>
          <p className="text-sm text-slate-200">{insight.summary}</p>

          {expanded && hasDetails && (
            <div className="mt-2 space-y-1.5 text-xs">
              {(insight.threats ?? []).map((t, i) => (
                <div key={i} className="flex gap-1.5 text-red-300">
                  <span className="text-red-500 flex-shrink-0">▲</span>
                  <span>{t}</span>
                </div>
              ))}
              {(insight.frauds ?? []).map((f, i) => (
                <div key={i} className="flex gap-1.5 text-orange-300">
                  <span className="text-orange-500 flex-shrink-0">●</span>
                  <span>{f}</span>
                </div>
              ))}
              {(insight.anomalies ?? []).map((a, i) => (
                <div key={i} className="flex gap-1.5 text-yellow-300">
                  <span className="text-yellow-500 flex-shrink-0">◆</span>
                  <span>{a}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function LiveInsightsFeed({ insights, analyzing }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to latest insight
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [insights.length]);

  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <Brain className="w-4 h-4 text-violet-400" />
        <h3 className="text-sm font-medium text-slate-300">AI Live Analysis</h3>
        {analyzing && (
          <span className="flex items-center gap-1 text-xs text-violet-400 ml-auto">
            <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />
            Analyzing…
          </span>
        )}
        {!analyzing && insights.length === 0 && (
          <span className="text-xs text-slate-500 ml-auto">
            First insight in ~30s
          </span>
        )}
        {insights.length > 0 && (
          <span className="text-xs text-slate-500 ml-auto">
            {insights.length} insight{insights.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {insights.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-6 text-slate-600">
          <Brain className="w-8 h-8 mb-2 opacity-30" />
          <p className="text-xs text-center">
            AI will analyze traffic every 30 seconds.
            <br />
            Make sure an AI provider is configured (ANTHROPIC_API_KEY etc.)
          </p>
        </div>
      ) : (
        <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
          {insights.map((insight, i) => (
            <InsightCard key={i} insight={insight} />
          ))}
          <div ref={bottomRef} />
        </div>
      )}
    </div>
  );
}
