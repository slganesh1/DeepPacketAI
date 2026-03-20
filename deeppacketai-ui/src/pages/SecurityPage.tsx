import { useEffect, useState, useMemo } from "react";
import { api } from "../api/client";
import {
  Shield, AlertTriangle, Radio, Globe, Lock,
  ChevronDown, ChevronRight, RefreshCw, ExternalLink,
} from "lucide-react";

interface SecurityAlert {
  id: string;
  timestamp: string;
  severity: string;
  protocol: string;
  title: string;
  description: string;
  flow_id?: string;
  job_id?: number;
  metadata?: Record<string, any>;
}

// ── Attack category classifier ──────────────────────────────────────────────

type AttackCategory = "voip" | "dns" | "tls" | "other";

function classifyAlert(a: SecurityAlert): AttackCategory {
  const t = (a.title + " " + a.description + " " + (a.metadata?.attack_type ?? "")).toLowerCase();
  if (a.protocol === "SIP" || a.protocol === "RTP" || t.includes("sip") || t.includes("voip")) return "voip";
  if (a.protocol === "DNS" || t.includes("dns")) return "dns";
  if (a.protocol === "TLS" || t.includes("tls") || t.includes("cipher") || t.includes("cert") || t.includes("ja3")) return "tls";
  return "other";
}

function isSecurityAlert(a: SecurityAlert): boolean {
  const securityKeywords = [
    "brute", "scan", "hijack", "flood", "fraud", "tunnel", "dga", "c2",
    "fast-flux", "weak", "broken", "downgrade", "self-signed", "ja3", "malicious",
    "attack", "suspicious", "exploit", "injection",
  ];
  const t = (a.title + " " + a.description).toLowerCase();
  return (
    a.severity === "critical" ||
    a.severity === "error" ||
    securityKeywords.some((kw) => t.includes(kw)) ||
    !!a.metadata?.attack_type
  );
}

// ── Severity helpers ────────────────────────────────────────────────────────

function severityColor(s: string) {
  switch (s) {
    case "critical": return "text-red-400 bg-red-500/10 border-red-500/30";
    case "error":    return "text-orange-400 bg-orange-500/10 border-orange-500/30";
    case "warning":  return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
    default:         return "text-slate-400 bg-slate-500/10 border-slate-500/30";
  }
}

function severityDot(s: string) {
  switch (s) {
    case "critical": return "bg-red-500";
    case "error":    return "bg-orange-500";
    case "warning":  return "bg-yellow-500";
    default:         return "bg-slate-500";
  }
}

// ── Category config ─────────────────────────────────────────────────────────

const CATEGORIES: { key: AttackCategory; label: string; icon: typeof Shield; color: string; border: string }[] = [
  { key: "voip", label: "VoIP / SIP",   icon: Radio,          color: "text-emerald-400", border: "border-emerald-500/30" },
  { key: "dns",  label: "DNS Threats",  icon: Globe,          color: "text-cyan-400",    border: "border-cyan-500/30"    },
  { key: "tls",  label: "TLS / Certs",  icon: Lock,           color: "text-violet-400",  border: "border-violet-500/30"  },
  { key: "other",label: "Other",        icon: AlertTriangle,  color: "text-slate-400",   border: "border-slate-500/30"   },
];

// ── Attack-type badge ───────────────────────────────────────────────────────

const ATTACK_BADGES: Record<string, { label: string; cls: string }> = {
  sip_brute_force:  { label: "Brute Force",   cls: "bg-red-500/20 text-red-400 border-red-500/30" },
  sip_scanning:     { label: "SIP Scan",      cls: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  sip_invite_flood: { label: "INVITE Flood",  cls: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  toll_fraud:       { label: "Toll Fraud",    cls: "bg-red-500/20 text-red-400 border-red-500/30" },
  sip_call_hijack:  { label: "Call Hijack",   cls: "bg-red-500/20 text-red-400 border-red-500/30" },
  dns_tunneling:    { label: "DNS Tunnel",    cls: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30" },
  dns_c2:           { label: "C2 Domain",     cls: "bg-red-500/20 text-red-400 border-red-500/30" },
  dns_fast_flux:    { label: "Fast-Flux",     cls: "bg-purple-500/20 text-purple-400 border-purple-500/30" },
  weak_cipher:      { label: "Weak Cipher",   cls: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  malicious_ja3:    { label: "Malicious JA3", cls: "bg-red-500/20 text-red-400 border-red-500/30" },
  self_signed_cert: { label: "Self-Signed",   cls: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  tls_downgrade:    { label: "TLS Downgrade", cls: "bg-red-500/20 text-red-400 border-red-500/30" },
};

// ── Main Page ───────────────────────────────────────────────────────────────

export default function SecurityPage() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeCategory, setActiveCategory] = useState<AttackCategory | "all">("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    setLoading(true);
    api
      .get("/alerts?limit=500")
      .then((r) => setAlerts(Array.isArray(r.data) ? r.data : []))
      .catch(() => setAlerts([]))
      .finally(() => setLoading(false));
  }, [refreshKey]);

  const secAlerts = useMemo(() => alerts.filter(isSecurityAlert), [alerts]);

  const byCategory = useMemo(() => {
    const m: Record<AttackCategory, SecurityAlert[]> = { voip: [], dns: [], tls: [], other: [] };
    for (const a of secAlerts) m[classifyAlert(a)].push(a);
    return m;
  }, [secAlerts]);

  const critical = secAlerts.filter((a) => a.severity === "critical").length;

  const displayed = useMemo(() => {
    if (activeCategory === "all") return secAlerts;
    return byCategory[activeCategory];
  }, [activeCategory, secAlerts, byCategory]);

  // ── JA3 table data ──────────────────────────────────────────────────────
  const ja3Rows = useMemo(() =>
    secAlerts
      .filter((a) => a.metadata?.ja3_hash)
      .map((a) => ({
        hash:    a.metadata!.ja3_hash as string,
        str:     a.metadata!.ja3_string as string,
        src:     a.metadata!.src_ip as string,
        dst:     a.metadata!.dst_ip as string,
        sni:     a.metadata!.sni as string ?? "",
        malware: a.metadata!.malware as string ?? "",
      })),
    [secAlerts]
  );

  // ── TLS cipher strength rows ─────────────────────────────────────────────
  const cipherRows = useMemo(() =>
    secAlerts
      .filter((a) => a.metadata?.cipher_suite)
      .map((a) => ({
        cipher:  a.metadata!.cipher_suite as string,
        noFS:    !(a.metadata!.has_forward_secrecy as boolean),
        weak:    (a.metadata!.weak_algorithms as string[] ?? []),
        src:     a.metadata!.src_ip as string,
        dst:     a.metadata!.dst_ip as string,
      })),
    [secAlerts]
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-red-400" />
            Security Analysis
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            VoIP attacks · DNS threats · TLS anomalies · JA3 fingerprints
          </p>
        </div>
        <button
          onClick={() => setRefreshKey((k) => k + 1)}
          className="flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-700 text-slate-400 hover:text-white hover:border-slate-500 transition-all text-sm"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <SummaryCard
          label="Total Security Alerts"
          value={secAlerts.length}
          sub={`${critical} critical`}
          color="text-white"
          icon={<Shield className="w-4 h-4 text-slate-400" />}
        />
        {CATEGORIES.map((cat) => (
          <SummaryCard
            key={cat.key}
            label={cat.label}
            value={byCategory[cat.key].length}
            sub={`${byCategory[cat.key].filter((a) => a.severity === "critical").length} critical`}
            color={cat.color}
            icon={<cat.icon className={`w-4 h-4 ${cat.color}`} />}
            onClick={() => setActiveCategory(cat.key === activeCategory ? "all" : cat.key)}
            active={activeCategory === cat.key}
          />
        ))}
      </div>

      {/* TLS Analysis panels — always visible if data exists */}
      {(ja3Rows.length > 0 || cipherRows.length > 0) && (
        <div className="grid grid-cols-2 gap-4">
          {ja3Rows.length > 0 && (
            <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-700/50 flex items-center gap-2">
                <Lock className="w-4 h-4 text-violet-400" />
                <h2 className="text-sm font-semibold text-white">JA3 Fingerprints</h2>
                <span className="ml-auto text-xs text-slate-500">{ja3Rows.length} records</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-700/50">
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">JA3 Hash</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">SNI</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Src → Dst</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ja3Rows.slice(0, 20).map((row, i) => (
                      <tr key={i} className="border-b border-slate-700/30 hover:bg-slate-700/20">
                        <td className="px-3 py-2 font-mono text-violet-300">{row.hash.slice(0, 12)}…</td>
                        <td className="px-3 py-2 text-slate-300 max-w-[120px] truncate">{row.sni || "—"}</td>
                        <td className="px-3 py-2 font-mono text-slate-400">{row.src} → {row.dst}</td>
                        <td className="px-3 py-2">
                          {row.malware
                            ? <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs">{row.malware}</span>
                            : <span className="text-slate-600">—</span>
                          }
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {cipherRows.length > 0 && (
            <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-700/50 flex items-center gap-2">
                <Lock className="w-4 h-4 text-orange-400" />
                <h2 className="text-sm font-semibold text-white">Weak Ciphers Detected</h2>
                <span className="ml-auto text-xs text-slate-500">{cipherRows.length} flows</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-700/50">
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Cipher Suite</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">FS</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Src → Dst</th>
                      <th className="px-3 py-2 text-left text-slate-500 font-medium">Issue</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cipherRows.slice(0, 20).map((row, i) => (
                      <tr key={i} className="border-b border-slate-700/30 hover:bg-slate-700/20">
                        <td className="px-3 py-2 font-mono text-slate-300 max-w-[180px] truncate" title={row.cipher}>{row.cipher}</td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${row.noFS ? "bg-red-500/20 text-red-400" : "bg-emerald-500/20 text-emerald-400"}`}>
                            {row.noFS ? "No" : "Yes"}
                          </span>
                        </td>
                        <td className="px-3 py-2 font-mono text-slate-400">{row.src} → {row.dst}</td>
                        <td className="px-3 py-2 text-orange-400">{row.weak.join(", ") || (row.noFS ? "No FS" : "—")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Category filter tabs */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={() => setActiveCategory("all")}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
            activeCategory === "all"
              ? "bg-slate-700 border-slate-500 text-white"
              : "border-slate-700 text-slate-400 hover:border-slate-500 hover:text-white"
          }`}
        >
          All ({secAlerts.length})
        </button>
        {CATEGORIES.map((cat) => (
          <button
            key={cat.key}
            onClick={() => setActiveCategory(cat.key === activeCategory ? "all" : cat.key)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
              activeCategory === cat.key
                ? `${cat.border} ${cat.color} bg-slate-800`
                : "border-slate-700 text-slate-400 hover:border-slate-500"
            }`}
          >
            <cat.icon className="w-3.5 h-3.5" />
            {cat.label} ({byCategory[cat.key].length})
          </button>
        ))}
      </div>

      {/* Alert list */}
      {loading ? (
        <div className="text-center py-16 text-slate-500 text-sm">Loading security events…</div>
      ) : displayed.length === 0 ? (
        <div className="text-center py-16 bg-slate-800/40 border border-slate-700/40 rounded-xl">
          <Shield className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400 text-sm font-medium">No security alerts detected</p>
          <p className="text-slate-600 text-xs mt-1">Upload a PCAP to run security analysis</p>
        </div>
      ) : (
        <div className="space-y-2">
          {displayed.map((alert) => (
            <AlertRow
              key={alert.id}
              alert={alert}
              expanded={expandedId === alert.id}
              onToggle={() => setExpandedId(expandedId === alert.id ? null : alert.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SummaryCard({
  label, value, sub, color, icon, onClick, active,
}: {
  label: string; value: number; sub: string; color: string;
  icon: React.ReactNode; onClick?: () => void; active?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={`bg-slate-800/80 border rounded-xl p-4 text-left transition-all ${
        active ? "border-slate-500 ring-1 ring-slate-500/40" : "border-slate-700/50 hover:border-slate-600"
      } ${onClick ? "cursor-pointer" : "cursor-default"}`}
    >
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <span className="text-xs text-slate-500">{label}</span>
      </div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-600 mt-0.5">{sub}</div>
    </button>
  );
}

function AlertRow({
  alert, expanded, onToggle,
}: { alert: SecurityAlert; expanded: boolean; onToggle: () => void }) {
  const attackType = alert.metadata?.attack_type as string | undefined;
  const badge = attackType ? ATTACK_BADGES[attackType] : null;

  return (
    <div className={`bg-slate-800/60 border rounded-xl transition-all ${severityColor(alert.severity).split(" ")[2]} border`}>
      {/* Header row */}
      <button
        onClick={onToggle}
        className="w-full flex items-start gap-3 px-4 py-3 text-left"
      >
        <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${severityDot(alert.severity)}`} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-white">{alert.title}</span>
            {badge && (
              <span className={`text-xs font-medium px-1.5 py-0.5 rounded border ${badge.cls}`}>
                {badge.label}
              </span>
            )}
            <span className={`text-xs font-medium px-1.5 py-0.5 rounded border ${severityColor(alert.severity)}`}>
              {alert.severity}
            </span>
            <span className="text-xs text-slate-600 ml-auto font-mono">{fmtTime(alert.timestamp)}</span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5 line-clamp-2">{alert.description}</p>
        </div>

        <div className="flex-shrink-0 text-slate-500 pt-0.5">
          {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </div>
      </button>

      {/* Expanded detail */}
      {expanded && alert.metadata && Object.keys(alert.metadata).length > 0 && (
        <div className="px-4 pb-4 pt-0 border-t border-slate-700/40">
          <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 mt-3 text-xs">
            {Object.entries(alert.metadata)
              .filter(([, v]) => typeof v !== "object" || Array.isArray(v))
              .map(([k, v]) => (
                <div key={k} className="flex gap-2">
                  <span className="text-slate-500 w-32 flex-shrink-0">{formatKey(k)}</span>
                  <span className="text-slate-200 font-mono break-all">
                    {Array.isArray(v) ? (v as string[]).join(", ") : String(v)}
                  </span>
                </div>
              ))}
          </div>
          {alert.flow_id && (
            <div className="mt-3 flex gap-2">
              <span className="text-xs text-slate-500">Flow</span>
              <span className="text-xs font-mono text-cyan-400">{alert.flow_id}</span>
            </div>
          )}
          {alert.job_id && (
            <a
              href={`/jobs/${alert.job_id}`}
              className="mt-2 inline-flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300"
              onClick={(e) => e.stopPropagation()}
            >
              <ExternalLink className="w-3 h-3" /> View Job
            </a>
          )}
        </div>
      )}
    </div>
  );
}

function fmtTime(ts: string): string {
  try {
    return new Date(ts).toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch { return ts; }
}

function formatKey(k: string): string {
  return k.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
    .replace(/Ip$/i, "IP").replace(/Src/i, "Src").replace(/Dst/i, "Dst")
    .replace(/Ja3/i, "JA3").replace(/Tls/i, "TLS").replace(/Sni/i, "SNI");
}
