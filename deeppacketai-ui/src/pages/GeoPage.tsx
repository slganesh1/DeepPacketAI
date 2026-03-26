import { useEffect, useState } from "react";
import { api } from "../api/client";
import {
  Globe, Shield, ShieldAlert, Wifi, RefreshCw,
  AlertTriangle, Server,
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import { clsx } from "clsx";

// ── Types ─────────────────────────────────────────────────────────────────────

interface GeoSummaryRow {
  country_code: string;
  country: string;
  count: number;
}

interface IPEnrichment {
  ip: string;
  country_code: string;
  country: string;
  city: string;
  isp: string;
  org: string;
  lat: number;
  lon: number;
  is_hosting: boolean;
  is_tor: boolean;
  is_proxy: boolean;
  abuse_score: number;
  is_abusive: boolean;
  last_checked: string;
}

interface GeoSummary {
  countries: GeoSummaryRow[];
  flagged: IPEnrichment[];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Convert ISO 3166-1 alpha-2 country code to emoji flag */
function flagEmoji(code: string): string {
  if (!code || code.length !== 2) return "🌐";
  const cp = (c: string) => 0x1f1e6 + c.toUpperCase().charCodeAt(0) - 65;
  return String.fromCodePoint(cp(code[0])) + String.fromCodePoint(cp(code[1]));
}

const BAR_COLORS = [
  "#34d399", "#60a5fa", "#f59e0b", "#f87171",
  "#a78bfa", "#fb923c", "#38bdf8", "#4ade80",
];

// ── IP Enrichment lookup panel ────────────────────────────────────────────────

function IPLookup() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<IPEnrichment | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function lookup() {
    const ip = query.trim();
    if (!ip) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await api.get<IPEnrichment>(`/geo/ip/${ip}`);
      setResult(res.data);
    } catch {
      setError("IP not found or lookup failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
      <h3 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
        <Globe className="w-4 h-4 text-sky-400" /> IP Lookup
      </h3>
      <div className="flex gap-2">
        <input
          className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:border-sky-500"
          placeholder="Enter IP address…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && lookup()}
        />
        <button
          onClick={lookup}
          disabled={loading}
          className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white text-sm rounded-lg transition-colors disabled:opacity-50"
        >
          {loading ? "…" : "Lookup"}
        </button>
      </div>

      {error && <p className="mt-2 text-xs text-red-400">{error}</p>}

      {result && (
        <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
          <Row label="IP" value={result.ip} mono />
          <Row label="Country" value={`${flagEmoji(result.country_code)} ${result.country} (${result.country_code})`} />
          <Row label="City" value={result.city || "—"} />
          <Row label="ISP" value={result.isp || "—"} />
          <Row label="Organisation" value={result.org || "—"} />
          <Row label="Coordinates" value={result.lat !== 0 ? `${result.lat.toFixed(3)}, ${result.lon.toFixed(3)}` : "—"} />
          <div className="col-span-2 mt-1 flex gap-3 flex-wrap text-xs">
            {result.is_tor     && <Badge color="red"    icon={<ShieldAlert className="w-3 h-3" />} label="Tor Exit Node" />}
            {result.is_proxy   && <Badge color="orange" icon={<Wifi className="w-3 h-3" />}       label="Proxy / VPN" />}
            {result.is_hosting && <Badge color="blue"   icon={<Server className="w-3 h-3" />}     label="Hosting / Cloud" />}
            {result.is_abusive && <Badge color="red"    icon={<AlertTriangle className="w-3 h-3" />} label={`Abuse Score ${result.abuse_score}`} />}
            {!result.is_tor && !result.is_proxy && !result.is_hosting && !result.is_abusive && (
              <span className="text-emerald-400 flex items-center gap-1">
                <Shield className="w-3 h-3" /> No flags
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <span className="text-slate-500 text-xs">{label}</span>
      <span className={clsx("text-slate-200 text-xs truncate", mono && "font-mono")}>{value}</span>
    </>
  );
}

function Badge({ color, icon, label }: { color: string; icon: React.ReactNode; label: string }) {
  const colors: Record<string, string> = {
    red:    "text-red-400 bg-red-400/10",
    orange: "text-orange-400 bg-orange-400/10",
    blue:   "text-sky-400 bg-sky-400/10",
  };
  return (
    <span className={clsx("flex items-center gap-1 px-2 py-0.5 rounded", colors[color] ?? colors.blue)}>
      {icon} {label}
    </span>
  );
}

// ── Flagged IPs table ─────────────────────────────────────────────────────────

function FlaggedTable({ items }: { items: IPEnrichment[] }) {
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-slate-600">
        <Shield className="w-8 h-8 mb-2 opacity-30" />
        <p className="text-xs">No flagged IPs detected yet.</p>
        <p className="text-xs mt-0.5 text-slate-700">Run a PCAP analysis or live capture to enrich IPs.</p>
      </div>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-slate-500 border-b border-slate-700/50">
            <th className="text-left pb-2 pr-3">IP</th>
            <th className="text-left pb-2 pr-3">Country</th>
            <th className="text-left pb-2 pr-3">ISP</th>
            <th className="text-left pb-2 pr-3">Flags</th>
            <th className="text-right pb-2">Abuse</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-700/30">
          {items.map((e) => (
            <tr key={e.ip} className="hover:bg-slate-700/20 transition-colors">
              <td className="py-1.5 pr-3 font-mono text-slate-300">{e.ip}</td>
              <td className="py-1.5 pr-3 text-slate-400">
                {flagEmoji(e.country_code)} {e.country}
              </td>
              <td className="py-1.5 pr-3 text-slate-500 max-w-[180px] truncate">{e.isp || e.org || "—"}</td>
              <td className="py-1.5 pr-3">
                <div className="flex gap-1 flex-wrap">
                  {e.is_tor     && <span className="text-red-400    bg-red-400/10    px-1 rounded">Tor</span>}
                  {e.is_proxy   && <span className="text-orange-400 bg-orange-400/10 px-1 rounded">Proxy</span>}
                  {e.is_hosting && <span className="text-sky-400    bg-sky-400/10    px-1 rounded">Hosting</span>}
                  {e.is_abusive && <span className="text-red-400    bg-red-400/10    px-1 rounded">Abuse</span>}
                </div>
              </td>
              <td className="py-1.5 text-right">
                <span className={clsx("font-medium", e.abuse_score > 75 ? "text-red-400" : e.abuse_score > 25 ? "text-yellow-400" : "text-slate-500")}>
                  {e.abuse_score > 0 ? `${e.abuse_score}%` : "—"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function GeoPage() {
  const [summary, setSummary] = useState<GeoSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  async function load(showSpinner = false) {
    if (showSpinner) setRefreshing(true);
    try {
      const res = await api.get<GeoSummary>("/geo/summary?limit=20");
      setSummary(res.data);
    } catch { /* silent */ }
    finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => { load(); }, []);

  const totalIPs = summary?.countries.reduce((s, r) => s + r.count, 0) ?? 0;

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-sky-400" />
          <h1 className="text-xl font-semibold text-slate-100">GeoIP & Reputation</h1>
          {totalIPs > 0 && (
            <span className="text-xs text-slate-500 ml-1">{totalIPs} enriched IPs</span>
          )}
        </div>
        <button
          onClick={() => load(true)}
          disabled={refreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-700/50 rounded-lg transition-colors"
        >
          <RefreshCw className={clsx("w-3.5 h-3.5", refreshing && "animate-spin")} />
          Refresh
        </button>
      </div>

      {/* IP Lookup */}
      <IPLookup />

      {loading ? (
        <div className="text-center py-16 text-slate-500 text-sm">Loading enrichment data…</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Country distribution chart */}
          <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
            <h3 className="text-sm font-medium text-slate-300 mb-4 flex items-center gap-2">
              <Globe className="w-4 h-4 text-sky-400" /> Top Countries
            </h3>
            {(summary?.countries ?? []).length === 0 ? (
              <div className="flex flex-col items-center py-8 text-slate-600">
                <Globe className="w-8 h-8 mb-2 opacity-30" />
                <p className="text-xs">No data yet — run a capture or PCAP analysis.</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart
                  data={(summary?.countries ?? []).slice(0, 10).map((r) => ({
                    name: `${flagEmoji(r.country_code)} ${r.country_code}`,
                    count: r.count,
                    fullName: r.country,
                  }))}
                  layout="vertical"
                  margin={{ left: 8, right: 16, top: 0, bottom: 0 }}
                >
                  <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis dataKey="name" type="category" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} width={52} />
                  <Tooltip
                    contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, fontSize: 12 }}
                    labelStyle={{ color: "#e2e8f0" }}
                    formatter={(v: any, _: any, p: any) => [v, p.payload.fullName]}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {(summary?.countries ?? []).slice(0, 10).map((_, i) => (
                      <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Stats tiles */}
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <Tile
                icon={<Globe className="w-4 h-4 text-sky-400" />}
                label="Countries"
                value={summary?.countries.length ?? 0}
              />
              <Tile
                icon={<ShieldAlert className="w-4 h-4 text-red-400" />}
                label="Flagged IPs"
                value={summary?.flagged.length ?? 0}
                highlight={(summary?.flagged.length ?? 0) > 0}
              />
              <Tile
                icon={<Wifi className="w-4 h-4 text-orange-400" />}
                label="Tor / Proxy"
                value={(summary?.flagged ?? []).filter((f) => f.is_tor || f.is_proxy).length}
                highlight={(summary?.flagged ?? []).some((f) => f.is_tor || f.is_proxy)}
              />
              <Tile
                icon={<Server className="w-4 h-4 text-blue-400" />}
                label="Hosting IPs"
                value={(summary?.flagged ?? []).filter((f) => f.is_hosting).length}
              />
            </div>

            {/* AbuseIPDB notice */}
            <div className="bg-slate-800/50 border border-slate-700/40 rounded-lg p-3 text-xs text-slate-500">
              <span className="text-slate-400 font-medium">Tip:</span> Set{" "}
              <code className="font-mono text-sky-400">ABUSEIPDB_API_KEY</code> in your{" "}
              <code className="font-mono text-slate-400">.env</code> file to enable abuse
              confidence scores. Geo data via ip-api.com is always active (no key needed).
            </div>
          </div>
        </div>
      )}

      {/* Flagged IPs table */}
      <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
        <h3 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400" /> Flagged IPs
          {(summary?.flagged.length ?? 0) > 0 && (
            <span className="ml-auto text-xs text-slate-500">{summary?.flagged.length} entries</span>
          )}
        </h3>
        <FlaggedTable items={summary?.flagged ?? []} />
      </div>
    </div>
  );
}

function Tile({ icon, label, value, highlight }: { icon: React.ReactNode; label: string; value: number; highlight?: boolean }) {
  return (
    <div className={clsx(
      "bg-slate-900/60 border rounded-lg p-3 text-center",
      highlight ? "border-red-500/30 bg-red-500/5" : "border-slate-700/50"
    )}>
      <div className="flex justify-center mb-1">{icon}</div>
      <div className={clsx("text-xl font-bold", highlight ? "text-red-400" : "text-slate-200")}>{value}</div>
      <div className="text-xs text-slate-500">{label}</div>
    </div>
  );
}
