import { useEffect, useState } from "react";
import {
  Phone, Wifi, CheckCircle, XCircle, ChevronDown, ChevronRight,
  Activity, Signal, Search, Tag, Network, Clock, Radio, MapPin,
} from "lucide-react";
import { clsx } from "clsx";
import { api } from "../api/client";

// ---- Types matching domain.TelecomSession ----
interface TraceEvent {
  timestamp: string;
  protocol: string;
  step: string;
  summary: string;
  src_ip: string;
  dst_ip: string;
  metadata?: Record<string, unknown>;
}

interface UELifecycleStep {
  step: string;
  protocol: string;
  timestamp: string;
  delta_ms: number;
  details: string;
}

interface TelecomSession {
  session_id: string;
  imsi?: string;
  msisdn?: string;
  apn?: string;
  ue_ip?: string;
  rat_type?: string;
  serving_network?: string;
  location?: string;
  pdn_type?: string;
  sip_call_id?: string;
  sip_from?: string;
  sip_to?: string;
  start_time: string;
  end_time: string;
  mos?: number;
  quality?: string;
  has_ngap: boolean;
  has_gtpc: boolean;
  has_pfcp: boolean;
  has_gtpu: boolean;
  has_sip: boolean;
  has_rtp: boolean;
  has_diameter: boolean;
  is_complete: boolean;
  ue_state?: string;
  teids?: string[];
  bearer_teids?: string[];
  seids?: string[];
  events?: TraceEvent[];
  lifecycle?: UELifecycleStep[];
}

const LAYER_ORDER = [
  { key: "has_ngap", label: "NGAP", color: "emerald", desc: "UE ↔ AMF" },
  { key: "has_gtpc", label: "GTP-C", color: "cyan", desc: "AMF/SMF ↔ UPF" },
  { key: "has_pfcp", label: "PFCP", color: "violet", desc: "SMF ↔ UPF" },
  { key: "has_gtpu", label: "GTP-U", color: "orange", desc: "UPF tunnel" },
  { key: "has_diameter", label: "Diameter", color: "pink", desc: "HSS/AAA" },
  { key: "has_sip", label: "SIP", color: "green", desc: "IMS signalling" },
  { key: "has_rtp", label: "RTP", color: "sky", desc: "Media stream" },
] as const;

const PROTOCOL_COLORS: Record<string, string> = {
  NGAP: "text-emerald-400 border-emerald-500/40 bg-emerald-900/20",
  "GTP-C": "text-cyan-400 border-cyan-500/40 bg-cyan-900/20",
  "GTP-U": "text-orange-400 border-orange-500/40 bg-orange-900/20",
  PFCP: "text-violet-400 border-violet-500/40 bg-violet-900/20",
  Diameter: "text-pink-400 border-pink-500/40 bg-pink-900/20",
  SIP: "text-green-400 border-green-500/40 bg-green-900/20",
  RTP: "text-sky-400 border-sky-500/40 bg-sky-900/20",
};

const LAYER_DOT: Record<string, string> = {
  NGAP: "bg-emerald-400",
  "GTP-C": "bg-cyan-400",
  "GTP-U": "bg-orange-400",
  PFCP: "bg-violet-400",
  Diameter: "bg-pink-400",
  SIP: "bg-green-400",
  RTP: "bg-sky-400",
};

const UE_STATE_STYLE: Record<string, string> = {
  idle: "text-slate-400 bg-slate-800/60 border-slate-600/40",
  attaching: "text-yellow-400 bg-yellow-900/20 border-yellow-500/40",
  registered: "text-cyan-400 bg-cyan-900/20 border-cyan-500/40",
  pdu_establishing: "text-violet-400 bg-violet-900/20 border-violet-500/40",
  active: "text-emerald-400 bg-emerald-900/20 border-emerald-500/40",
  releasing: "text-orange-400 bg-orange-900/20 border-orange-500/40",
};

function ueStateLabel(s?: string) {
  const map: Record<string, string> = {
    idle: "Idle",
    attaching: "Attaching",
    registered: "Registered",
    pdu_establishing: "PDU Establishing",
    active: "Active",
    releasing: "Releasing",
  };
  return s ? (map[s] ?? s) : "—";
}

function mosColor(mos: number) {
  if (mos >= 4.0) return "text-emerald-400";
  if (mos >= 3.5) return "text-yellow-400";
  if (mos >= 3.0) return "text-orange-400";
  return "text-red-400";
}

function formatTs(ts: string) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return ts;
  }
}

function duration(start: string, end: string) {
  try {
    const ms = new Date(end).getTime() - new Date(start).getTime();
    if (ms <= 0) return "—";
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  } catch {
    return "—";
  }
}

function formatDeltaMs(ms: number) {
  if (ms < 1000) return `+${ms}ms`;
  return `+${(ms / 1000).toFixed(2)}s`;
}

// ---- Layer Coverage Bar ----
function LayerBar({ session }: { session: TelecomSession }) {
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {LAYER_ORDER.map(({ key, label, color }) => {
        const active = session[key as keyof TelecomSession] as boolean;
        return (
          <span
            key={key}
            className={clsx(
              "px-2 py-0.5 rounded text-[10px] font-semibold border",
              active
                ? `text-${color}-300 bg-${color}-900/30 border-${color}-500/40`
                : "text-slate-600 bg-slate-800/40 border-slate-700/30"
            )}
          >
            {label}
          </span>
        );
      })}
    </div>
  );
}

// ---- Session Card ----
function SessionCard({ session, selected, onClick }: { session: TelecomSession; selected: boolean; onClick: () => void }) {
  const ueStyleKey = session.ue_state ?? "idle";
  const ueStyle = UE_STATE_STYLE[ueStyleKey] ?? UE_STATE_STYLE.idle;

  return (
    <button
      onClick={onClick}
      className={clsx(
        "w-full text-left px-4 py-3 rounded-xl border transition-all",
        selected
          ? "border-emerald-500/50 bg-emerald-900/10 shadow-md"
          : "border-slate-700/50 bg-slate-800/30 hover:bg-slate-800/60"
      )}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex items-center gap-2 min-w-0">
          {session.has_sip ? (
            <Phone className="w-4 h-4 text-green-400 shrink-0" />
          ) : (
            <Signal className="w-4 h-4 text-cyan-400 shrink-0" />
          )}
          <span className="text-sm font-semibold text-slate-200 truncate">
            {session.imsi || session.sip_call_id || session.session_id}
          </span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {session.is_complete ? (
            <CheckCircle className="w-4 h-4 text-emerald-400" />
          ) : (
            <XCircle className="w-4 h-4 text-slate-500" />
          )}
          {session.mos != null && session.mos > 0 && (
            <span className={clsx("text-xs font-bold", mosColor(session.mos))}>
              {session.mos.toFixed(2)}
            </span>
          )}
        </div>
      </div>

      <div className="text-xs text-slate-400 mb-2 space-y-0.5">
        {session.msisdn && <div>MSISDN: {session.msisdn}</div>}
        {session.ue_ip && <div>UE IP: {session.ue_ip}</div>}
        {session.apn && <div>APN: {session.apn}</div>}
        {session.rat_type && <div className="text-slate-500">RAT: {session.rat_type}</div>}
        {session.sip_from && <div className="truncate">{session.sip_from} → {session.sip_to}</div>}
      </div>

      <div className="flex items-center justify-between mb-1.5">
        <LayerBar session={session} />
        {session.ue_state && session.ue_state !== "idle" && (
          <span className={clsx("px-2 py-0.5 rounded text-[10px] font-semibold border ml-1 shrink-0", ueStyle)}>
            {ueStateLabel(session.ue_state)}
          </span>
        )}
      </div>

      <div className="text-[10px] text-slate-500">
        {formatTs(session.start_time)} · {duration(session.start_time, session.end_time)}
      </div>
    </button>
  );
}

// ---- TEID Panel ----
function TEIDPanel({ session }: { session: TelecomSession }) {
  const allTEIDs = session.teids ?? [];
  const bearerTEIDs = new Set(session.bearer_teids ?? []);
  const seids = session.seids ?? [];

  if (allTEIDs.length === 0 && seids.length === 0) return null;

  return (
    <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 p-4">
      <div className="text-xs font-semibold text-slate-400 mb-3 flex items-center gap-2">
        <Tag className="w-3.5 h-3.5" /> Tunnel Identifiers
      </div>
      <div className="space-y-3">
        {allTEIDs.length > 0 && (
          <div>
            <div className="text-[10px] text-slate-500 mb-1.5">GTP TEIDs ({allTEIDs.length})</div>
            <div className="flex flex-wrap gap-1.5">
              {allTEIDs.map((teid) => (
                <span
                  key={teid}
                  className={clsx(
                    "px-2 py-0.5 rounded font-mono text-[11px] border",
                    bearerTEIDs.has(teid)
                      ? "text-orange-300 bg-orange-900/20 border-orange-500/40"
                      : "text-cyan-300 bg-cyan-900/20 border-cyan-500/40"
                  )}
                  title={bearerTEIDs.has(teid) ? "Bearer F-TEID (GTP-U)" : "Control TEID (GTP-C)"}
                >
                  {teid}
                  {bearerTEIDs.has(teid) && <span className="ml-1 text-[9px] opacity-70">U</span>}
                </span>
              ))}
            </div>
            <div className="text-[9px] text-slate-600 mt-1">
              <span className="text-cyan-500">■</span> GTP-C control &nbsp;
              <span className="text-orange-500">■</span> GTP-U bearer (data-plane)
            </div>
          </div>
        )}
        {seids.length > 0 && (
          <div>
            <div className="text-[10px] text-slate-500 mb-1.5">PFCP SEIDs ({seids.length})</div>
            <div className="flex flex-wrap gap-1.5">
              {seids.map((seid) => (
                <span key={seid} className="px-2 py-0.5 rounded font-mono text-[11px] border text-violet-300 bg-violet-900/20 border-violet-500/40">
                  {seid}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ---- Network Context Panel ----
function NetworkContext({ session }: { session: TelecomSession }) {
  const fields = [
    { label: "RAT Type", value: session.rat_type, icon: Radio },
    { label: "Serving Network", value: session.serving_network, icon: Network },
    { label: "Location", value: session.location, icon: MapPin },
    { label: "PDN Type", value: session.pdn_type, icon: Network },
    { label: "UE IP", value: session.ue_ip, icon: Network },
    { label: "APN", value: session.apn, icon: Network },
  ].filter((f) => f.value);

  if (fields.length === 0) return null;

  return (
    <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 p-4">
      <div className="text-xs font-semibold text-slate-400 mb-3 flex items-center gap-2">
        <Signal className="w-3.5 h-3.5" /> Network Context
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
        {fields.map(({ label, value }) => (
          <div key={label} className="flex flex-col">
            <span className="text-[10px] text-slate-500">{label}</span>
            <span className="text-slate-300 font-mono text-[11px]">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---- UE Lifecycle Timeline ----
function LifecycleTimeline({ lifecycle }: { lifecycle: UELifecycleStep[] }) {
  if (!lifecycle || lifecycle.length === 0) return null;

  const STEP_ICONS: Record<string, string> = {
    UE_Registration: "📱",
    NAS_Uplink: "📡",
    Context_Setup: "🔧",
    HSS_Authenticate: "🔑",
    HSS_Location_Update: "📍",
    PDU_Session_Setup: "🌐",
    PDU_Session_Establish_Req: "→",
    PDU_Session_Establish_Resp: "←",
    PFCP_Establish_Req: "⚙",
    PFCP_Establish_Resp: "✓",
    Data_Tunnel: "🚇",
    IMS_Register: "📲",
    IMS_Call_Setup: "📞",
    IMS_Call_Connected: "✅",
    RTP_Media: "🎵",
    IMS_Call_Teardown: "📴",
    PDU_Session_Release_Req: "↩",
    UE_Context_Release: "🔒",
  };

  return (
    <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 p-4">
      <div className="text-xs font-semibold text-slate-400 mb-3 flex items-center gap-2">
        <Clock className="w-3.5 h-3.5" /> UE Lifecycle ({lifecycle.length} milestones)
      </div>
      <div className="space-y-0">
        {lifecycle.map((step, i) => {
          const protocolStyle = PROTOCOL_COLORS[step.protocol] || "text-slate-400 border-slate-600 bg-slate-800/40";
          const dot = LAYER_DOT[step.protocol] || "bg-slate-500";
          const icon = STEP_ICONS[step.step] ?? "·";

          return (
            <div key={i} className="flex gap-3 group">
              <div className="flex flex-col items-center">
                <div className={clsx("w-2.5 h-2.5 rounded-full mt-1.5 shrink-0", dot)} />
                {i < lifecycle.length - 1 && <div className="w-px flex-1 bg-slate-700/60 mt-0.5 mb-0.5 min-h-[12px]" />}
              </div>
              <div className="flex-1 pb-2 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm">{icon}</span>
                  <span className={clsx("px-1.5 py-0.5 rounded text-[10px] font-bold border", protocolStyle)}>
                    {step.protocol}
                  </span>
                  <span className="text-xs font-semibold text-slate-300">{step.step.replace(/_/g, " ")}</span>
                  <span className="text-[10px] text-emerald-500/80 ml-auto font-mono">
                    {formatDeltaMs(step.delta_ms)}
                  </span>
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5 truncate">{step.details}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---- Event Timeline ----
function EventTimeline({ events }: { events: TraceEvent[] }) {
  const [expanded, setExpanded] = useState<number | null>(null);

  if (!events || events.length === 0) {
    return (
      <div className="text-slate-500 text-sm py-6 text-center">No events recorded</div>
    );
  }

  return (
    <div className="space-y-1">
      {events.map((ev, i) => {
        const dot = LAYER_DOT[ev.protocol] || "bg-slate-500";
        const badge = PROTOCOL_COLORS[ev.protocol] || "text-slate-400 border-slate-600 bg-slate-800/40";
        const isOpen = expanded === i;

        return (
          <div key={i} className="flex gap-3 group">
            <div className="flex flex-col items-center">
              <div className={clsx("w-2.5 h-2.5 rounded-full mt-1.5 shrink-0", dot)} />
              {i < events.length - 1 && <div className="w-px flex-1 bg-slate-700/60 mt-1" />}
            </div>

            <div className="flex-1 pb-3 min-w-0">
              <button
                onClick={() => setExpanded(isOpen ? null : i)}
                className="w-full text-left"
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={clsx("px-1.5 py-0.5 rounded text-[10px] font-bold border", badge)}>
                    {ev.protocol}
                  </span>
                  <span className="text-xs font-semibold text-slate-300">{ev.step}</span>
                  <span className="text-[10px] text-slate-500 ml-auto">{formatTs(ev.timestamp)}</span>
                  {ev.metadata && (
                    isOpen ? <ChevronDown className="w-3 h-3 text-slate-500" /> : <ChevronRight className="w-3 h-3 text-slate-500" />
                  )}
                </div>
                <div className="text-xs text-slate-400 mt-0.5 truncate">{ev.summary}</div>
                {(ev.src_ip || ev.dst_ip) && (
                  <div className="text-[10px] text-slate-600 mt-0.5">
                    {ev.src_ip} → {ev.dst_ip}
                  </div>
                )}
              </button>

              {isOpen && ev.metadata && (
                <div className="mt-2 pl-2 border-l border-slate-700/50">
                  <pre className="text-[10px] text-slate-400 font-mono whitespace-pre-wrap break-all">
                    {JSON.stringify(ev.metadata, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ---- Session Detail Panel ----
type DetailTab = "lifecycle" | "events" | "layers";

function SessionDetail({ session }: { session: TelecomSession }) {
  const [tab, setTab] = useState<DetailTab>("lifecycle");
  const ueStyle = UE_STATE_STYLE[session.ue_state ?? "idle"] ?? UE_STATE_STYLE.idle;

  return (
    <div className="flex flex-col gap-4">
      {/* Header card */}
      <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 p-4">
        <div className="flex items-start justify-between gap-2 mb-3">
          <div>
            <div className="text-base font-bold text-slate-100">
              {session.imsi ? `IMSI: ${session.imsi}` : session.sip_call_id || session.session_id}
            </div>
            <div className="flex items-center gap-2 mt-1">
              {session.quality && (
                <span className={clsx(
                  "text-xs font-semibold",
                  session.quality === "good" ? "text-emerald-400" : session.quality === "fair" ? "text-yellow-400" : "text-red-400"
                )}>
                  Quality: {session.quality.toUpperCase()}
                </span>
              )}
              {session.ue_state && (
                <span className={clsx("px-2 py-0.5 rounded text-[10px] font-semibold border", ueStyle)}>
                  {ueStateLabel(session.ue_state)}
                </span>
              )}
            </div>
          </div>
          <div className="flex flex-col items-end gap-1">
            {session.mos != null && session.mos > 0 && (
              <div className={clsx("text-xl font-black", mosColor(session.mos))}>
                {session.mos.toFixed(2)}
                <span className="text-xs font-normal text-slate-400 ml-1">MOS</span>
              </div>
            )}
            <div className="flex items-center gap-1">
              {session.is_complete
                ? <><CheckCircle className="w-3.5 h-3.5 text-emerald-400" /><span className="text-xs text-emerald-400">Complete</span></>
                : <><XCircle className="w-3.5 h-3.5 text-slate-500" /><span className="text-xs text-slate-500">Partial</span></>
              }
            </div>
          </div>
        </div>

        {/* Subscriber identity row */}
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-slate-400">
          {session.msisdn && <><span className="text-slate-500">MSISDN</span><span>{session.msisdn}</span></>}
          {session.sip_from && <><span className="text-slate-500">From</span><span className="truncate">{session.sip_from}</span></>}
          {session.sip_to && <><span className="text-slate-500">To</span><span className="truncate">{session.sip_to}</span></>}
          <><span className="text-slate-500">Start</span><span>{formatTs(session.start_time)}</span></>
          <><span className="text-slate-500">Duration</span><span>{duration(session.start_time, session.end_time)}</span></>
        </div>
      </div>

      {/* Network context + TEIDs side by side */}
      <div className="grid grid-cols-2 gap-4">
        <NetworkContext session={session} />
        <TEIDPanel session={session} />
      </div>

      {/* Tab strip */}
      <div className="flex gap-1 border-b border-slate-700/50 pb-0">
        {([ ["lifecycle", "Lifecycle", Clock], ["events", "Events", Activity], ["layers", "Layers", Wifi] ] as const).map(([id, label, Icon]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={clsx(
              "flex items-center gap-1.5 px-3 py-2 text-xs font-semibold border-b-2 transition-colors",
              tab === id
                ? "border-emerald-400 text-emerald-400"
                : "border-transparent text-slate-500 hover:text-slate-300"
            )}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
            {id === "events" && session.events && (
              <span className="text-[10px] text-slate-600 ml-0.5">({session.events.length})</span>
            )}
            {id === "lifecycle" && session.lifecycle && (
              <span className="text-[10px] text-slate-600 ml-0.5">({session.lifecycle.length})</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "lifecycle" && (
        <>
          {session.lifecycle && session.lifecycle.length > 0
            ? <LifecycleTimeline lifecycle={session.lifecycle} />
            : <div className="text-slate-500 text-sm py-6 text-center">No lifecycle milestones recorded</div>
          }
        </>
      )}

      {tab === "events" && (
        <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 p-4">
          <EventTimeline events={session.events ?? []} />
        </div>
      )}

      {tab === "layers" && (
        <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 p-4">
          <div className="space-y-2">
            {LAYER_ORDER.map(({ key, label, desc }) => {
              const active = session[key as keyof TelecomSession] as boolean;
              return (
                <div key={key} className="flex items-center gap-2">
                  <div className={clsx("w-2 h-2 rounded-full", active ? "bg-emerald-400" : "bg-slate-600")} />
                  <span className={clsx("text-xs font-semibold w-16", active ? "text-slate-200" : "text-slate-600")}>{label}</span>
                  <span className="text-[10px] text-slate-500">{desc}</span>
                  {active && <span className="ml-auto text-[10px] text-emerald-500">✓</span>}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ---- Main Page ----
export default function TelecomTracePage() {
  const [sessions, setSessions] = useState<TelecomSession[]>([]);
  const [selected, setSelected] = useState<TelecomSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  useEffect(() => {
    setLoading(true);
    api.get("/telecom-sessions")
      .then(({ data }) => {
        const list: TelecomSession[] = data ?? [];
        setSessions(list);
        // Select first but lazy-load its detail
        if (list.length > 0) selectSession(list[0]);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  // Fetch full session detail (events + lifecycle) when a session is selected
  const selectSession = (s: TelecomSession) => {
    setSelected(s);
    if (s.events !== undefined) return; // already loaded
    setDetailLoading(true);
    api.get(`/telecom-sessions/${encodeURIComponent(s.session_id)}?job_id=0`)
      .then(({ data }) => setSelected(data))
      .catch(() => {/* keep metadata-only view */})
      .finally(() => setDetailLoading(false));
  };

  // Filter sessions by search term (IMSI, MSISDN, UE IP, SIP, TEID)
  const filtered = sessions.filter((s) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      s.imsi?.includes(q) ||
      s.msisdn?.includes(q) ||
      s.ue_ip?.includes(q) ||
      s.sip_from?.toLowerCase().includes(q) ||
      s.sip_to?.toLowerCase().includes(q) ||
      s.sip_call_id?.toLowerCase().includes(q) ||
      s.teids?.some((t) => t.includes(q)) ||
      s.apn?.toLowerCase().includes(q) ||
      s.serving_network?.includes(q)
    );
  });

  const complete = sessions.filter((s) => s.is_complete).length;
  const withVoice = sessions.filter((s) => s.has_sip).length;
  const activeCount = sessions.filter((s) => s.ue_state === "active").length;
  const uniqueIMSIs = new Set(sessions.map((s) => s.imsi).filter(Boolean)).size;

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Telecom Call Trace</h1>
        <p className="text-sm text-slate-400 mt-0.5">
          End-to-end 5G/4G session correlation · UE → NGAP → GTP-C → GTP-U → SIP → RTP
        </p>
      </div>

      {/* Summary strip */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: "Total Sessions", value: sessions.length, color: "text-slate-200" },
          { label: "Unique Subscribers", value: uniqueIMSIs, color: "text-cyan-400" },
          { label: "Active", value: activeCount, color: "text-emerald-400" },
          { label: "With Voice (SIP)", value: withVoice, color: "text-green-400" },
          { label: "Complete Traces", value: complete, color: "text-emerald-400" },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-slate-800/60 rounded-xl border border-slate-700/50 px-4 py-3">
            <div className={clsx("text-2xl font-black", color)}>{value}</div>
            <div className="text-xs text-slate-500 mt-0.5">{label}</div>
          </div>
        ))}
      </div>

      {loading && (
        <div className="flex items-center justify-center py-16 text-slate-400 text-sm">
          Loading sessions...
        </div>
      )}
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-xl px-4 py-3 text-red-400 text-sm">
          {error}
        </div>
      )}

      {!loading && !error && sessions.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 text-slate-500 gap-3">
          <Phone className="w-10 h-10 opacity-30" />
          <div className="text-sm">No telecom sessions found. Upload a PCAP containing 5G/4G traffic.</div>
        </div>
      )}

      {!loading && sessions.length > 0 && (
        <div className="flex gap-4 min-h-0">
          {/* Session list + search */}
          <div className="w-80 shrink-0 flex flex-col gap-2">
            {/* Search bar */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search IMSI, MSISDN, IP, TEID…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-2 rounded-lg bg-slate-800/60 border border-slate-700/50 text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-emerald-500/50"
              />
            </div>
            {/* Session cards */}
            <div className="space-y-2 max-h-[calc(100vh-300px)] overflow-y-auto pr-1">
              {filtered.length === 0 && (
                <div className="text-slate-500 text-xs text-center py-4">No sessions match</div>
              )}
              {filtered.map((s) => (
                <SessionCard
                  key={s.session_id}
                  session={s}
                  selected={selected?.session_id === s.session_id}
                  onClick={() => selectSession(s)}
                />
              ))}
            </div>
          </div>

          {/* Detail panel */}
          <div className="flex-1 min-w-0 max-h-[calc(100vh-300px)] overflow-y-auto">
            {detailLoading ? (
              <div className="flex items-center justify-center h-full text-slate-400 text-sm animate-pulse">
                Loading session detail…
              </div>
            ) : selected ? (
              <SessionDetail session={selected} />
            ) : (
              <div className="flex items-center justify-center h-full text-slate-500 text-sm">
                Select a session to view its call trace
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
