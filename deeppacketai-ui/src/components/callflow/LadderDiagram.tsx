import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";

interface CallFlowEvent {
  id: number;
  timestamp: string;
  protocol: string;
  event_type: string;
  summary: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
}

interface CallFlowData {
  entity_id: string;
  participants: string[];
  events: CallFlowEvent[];
}

// ── Colour palette ──────────────────────────────────────────────────────────
const PROTOCOL_COLORS: Record<string, string> = {
  SIP:      "#34d399",
  RTP:      "#22d3ee",
  DNS:      "#818cf8",
  HTTP:     "#f59e0b",
  Diameter: "#f472b6",
  GTP:      "#fb923c",
  "GTP-C":  "#fb923c",
  "GTP-U":  "#fbbf24",
  PFCP:     "#a78bfa",
  S1AP:     "#38bdf8",
  NGAP:     "#4ade80",
};

// ── Phase detection ─────────────────────────────────────────────────────────
interface Phase { label: string; startIdx: number; endIdx: number; color: string; }

function detectSIPPhases(events: CallFlowEvent[]): Phase[] {
  const phases: Phase[] = [];
  let setupStart = -1, setupEnd = -1;
  let mediaStart = -1, mediaEnd = -1;
  let teardownStart = -1, teardownEnd = -1;

  events.forEach((e, i) => {
    const s = e.summary.toUpperCase();
    if (e.protocol === "SIP") {
      if (s.includes("INVITE") && setupStart === -1) setupStart = i;
      if ((s.includes("200") || s.includes("ACK")) && setupStart !== -1 && setupEnd === -1) setupEnd = i;
      if (s.includes("BYE") || s.includes("CANCEL")) {
        if (teardownStart === -1) teardownStart = i;
      }
      if (s.includes("200") && teardownStart !== -1) teardownEnd = i;
    }
    if (e.protocol === "RTP") {
      if (mediaStart === -1) mediaStart = i;
      mediaEnd = i;
    }
  });

  if (setupStart !== -1)
    phases.push({ label: "Setup", startIdx: setupStart, endIdx: setupEnd === -1 ? setupStart : setupEnd, color: "rgba(52,211,153,0.06)" });
  if (mediaStart !== -1)
    phases.push({ label: "Media", startIdx: mediaStart, endIdx: mediaEnd, color: "rgba(34,211,238,0.06)" });
  if (teardownStart !== -1)
    phases.push({ label: "Teardown", startIdx: teardownStart, endIdx: teardownEnd === -1 ? events.length - 1 : teardownEnd, color: "rgba(248,113,113,0.07)" });

  return phases;
}

function detect5GPhases(events: CallFlowEvent[]): Phase[] {
  const phases: Phase[] = [];
  let regStart = -1, regEnd = -1, pduStart = -1, pduEnd = -1;
  events.forEach((e, i) => {
    const s = e.summary.toUpperCase();
    if (e.protocol === "NGAP" || e.protocol === "S1AP") {
      if ((s.includes("REGISTR") || s.includes("ATTACH")) && regStart === -1) regStart = i;
      if ((s.includes("ACCEPT") || s.includes("COMPLETE")) && regStart !== -1 && regEnd === -1) regEnd = i;
      if (s.includes("PDU SESSION") && pduStart === -1) pduStart = i;
      if (s.includes("ESTABLISH") && pduStart !== -1) pduEnd = i;
    }
  });
  if (regStart !== -1)
    phases.push({ label: "Registration", startIdx: regStart, endIdx: regEnd === -1 ? regStart : regEnd, color: "rgba(74,222,128,0.06)" });
  if (pduStart !== -1)
    phases.push({ label: "PDU Session", startIdx: pduStart, endIdx: pduEnd === -1 ? pduStart : pduEnd, color: "rgba(167,139,250,0.06)" });
  return phases;
}

// ── Message classification ──────────────────────────────────────────────────
function isResponse(event: CallFlowEvent): boolean {
  const s = event.summary.trim();
  // SIP responses start with 3-digit status code
  if (/^\d{3}\b/.test(s)) return true;
  // Diameter answers
  if (event.protocol === "Diameter") {
    const answers = ["CCA", "UAA", "MAA", "SAA", "AAA", "STA", "ASA", "DEA", "PEA", "DWA"];
    return answers.some((a) => s.toUpperCase().startsWith(a));
  }
  return false;
}

// Infer node role from port / protocol heuristics
function inferRole(ip: string, events: CallFlowEvent[]): string {
  const ports = new Set<number>();
  for (const e of events) {
    if (e.src_ip === ip) ports.add(e.src_port);
    if (e.dst_ip === ip) ports.add(e.dst_port);
  }
  if (ports.has(5060) || ports.has(5061)) return "SIP";
  if (ports.has(3868)) return "Diameter";
  if (ports.has(2123) || ports.has(2152)) return "GTP";
  if (ports.has(8805)) return "PFCP";
  if (ports.has(38412) || ports.has(36412)) return "NGAP";
  return "";
}

const ROLE_LABELS: Record<string, string> = {
  SIP: "SIP UA", Diameter: "HSS/AAA", GTP: "GTP Node", PFCP: "UPF/SMF", NGAP: "AMF/gNB",
};

// ── Main component ──────────────────────────────────────────────────────────
export default function LadderDiagram({ data }: { data: CallFlowData }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [filterProto, setFilterProto] = useState<string>("ALL");

  const protocols = Array.from(new Set(data.events.map((e) => e.protocol))).sort();

  const filteredEvents =
    filterProto === "ALL" ? data.events : data.events.filter((e) => e.protocol === filterProto);

  useEffect(() => {
    if (!svgRef.current || !data.participants.length) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    if (filteredEvents.length === 0) return;

    // ── Layout constants ────────────────────────────────────────────────────
    const margin        = { top: 80, right: 120, bottom: 40, left: 80 };
    const participantW  = 180;
    const rowH          = 52;
    const width = Math.max(700, data.participants.length * participantW + margin.left + margin.right);
    const height = filteredEvents.length * rowH + margin.top + margin.bottom + 40;

    svg.attr("width", width).attr("height", height);

    // ── Defs (arrowheads) ───────────────────────────────────────────────────
    const defs = svg.append("defs");
    const protocols_ = [...new Set(filteredEvents.map((e) => e.protocol)), "response"];
    protocols_.forEach((proto) => {
      const color = proto === "response" ? "#64748b" : (PROTOCOL_COLORS[proto] ?? "#94a3b8");
      defs.append("marker")
        .attr("id", `arrow-${proto.replace(/[^a-zA-Z0-9]/g, "_")}`)
        .attr("viewBox", "0 -4 8 8").attr("refX", 7).attr("refY", 0)
        .attr("markerWidth", 6).attr("markerHeight", 6).attr("orient", "auto")
        .append("path").attr("d", "M0,-4L8,0L0,4Z").attr("fill", color);
    });

    const g = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);

    // ── Participant positions ────────────────────────────────────────────────
    const pMap = new Map<string, number>();
    data.participants.forEach((p, i) => {
      pMap.set(p, i * participantW + participantW / 2);
    });

    // ── Phase background shading ─────────────────────────────────────────────
    const allProtocols = new Set(data.events.map((e) => e.protocol));
    const phases = allProtocols.has("NGAP") || allProtocols.has("S1AP")
      ? detect5GPhases(filteredEvents)
      : detectSIPPhases(filteredEvents);

    const drawWidth = (data.participants.length - 1) * participantW + participantW;

    phases.forEach((phase) => {
      const y0 = phase.startIdx * rowH - 10;
      const y1 = (phase.endIdx + 1) * rowH + 6;
      g.append("rect")
        .attr("x", -30).attr("y", y0)
        .attr("width", drawWidth + 60).attr("height", y1 - y0)
        .attr("fill", phase.color).attr("rx", 4);
      g.append("text")
        .attr("x", drawWidth + 35).attr("y", y0 + 14)
        .attr("fill", "#475569").attr("font-size", "9px").attr("font-style", "italic")
        .text(phase.label);
    });

    // ── Participant headers ──────────────────────────────────────────────────
    data.participants.forEach((p, i) => {
      const x = i * participantW + participantW / 2;
      const role = ROLE_LABELS[inferRole(p, data.events)] ?? "";

      g.append("rect")
        .attr("x", x - 72).attr("y", -60)
        .attr("width", 144).attr("height", 44)
        .attr("rx", 8).attr("fill", "#1e293b")
        .attr("stroke", "#334155").attr("stroke-width", 1.5);

      g.append("text")
        .attr("x", x).attr("y", -40)
        .attr("text-anchor", "middle")
        .attr("fill", "#e2e8f0").attr("font-size", "11px").attr("font-weight", "600")
        .text(p.length > 20 ? p.slice(0, 17) + "…" : p);

      if (role) {
        g.append("text")
          .attr("x", x).attr("y", -24)
          .attr("text-anchor", "middle")
          .attr("fill", "#64748b").attr("font-size", "9px")
          .text(role);
      }

      // Lifeline
      g.append("line")
        .attr("x1", x).attr("y1", -12)
        .attr("x2", x).attr("y2", filteredEvents.length * rowH + 20)
        .attr("stroke", "#1e3a5f").attr("stroke-width", 1.5)
        .attr("stroke-dasharray", "5,5");
    });

    // ── Time reference ───────────────────────────────────────────────────────
    const t0 = filteredEvents.length
      ? new Date(filteredEvents[0].timestamp).getTime()
      : 0;

    // ── Draw events ──────────────────────────────────────────────────────────
    filteredEvents.forEach((event, i) => {
      const y      = i * rowH + 26;
      const srcX   = pMap.get(event.src_ip);
      const dstX   = pMap.get(event.dst_ip);
      const resp   = isResponse(event);
      const color  = resp ? "#64748b" : (PROTOCOL_COLORS[event.protocol] ?? "#94a3b8");
      const markerId = `arrow-${(resp ? "response" : event.protocol).replace(/[^a-zA-Z0-9]/g, "_")}`;

      // ── Absolute timestamp (left gutter) ────────────────────────────────
      const tsMs   = new Date(event.timestamp).getTime();
      const delta  = tsMs - t0;
      const prevMs = i > 0 ? new Date(filteredEvents[i - 1].timestamp).getTime() : tsMs;
      const interDelta = tsMs - prevMs;

      g.append("text")
        .attr("x", -8).attr("y", y + 4)
        .attr("text-anchor", "end")
        .attr("fill", "#475569").attr("font-size", "9px").attr("font-family", "monospace")
        .text(fmtTimestamp(event.timestamp));

      // Δt from start (right gutter)
      g.append("text")
        .attr("x", (data.participants.length - 1) * participantW + participantW + 8)
        .attr("y", y + 4)
        .attr("text-anchor", "start")
        .attr("fill", "#334155").attr("font-size", "9px").attr("font-family", "monospace")
        .text(`+${fmtDelta(delta)}`);

      // inter-event delta (tiny, below)
      if (i > 0 && interDelta > 1) {
        g.append("text")
          .attr("x", (data.participants.length - 1) * participantW + participantW + 8)
          .attr("y", y + 14)
          .attr("text-anchor", "start")
          .attr("fill", "#1e3a5f").attr("font-size", "8px").attr("font-family", "monospace")
          .text(`Δ${fmtDelta(interDelta)}`);
      }

      // Self-loop (src == dst or dst not found)
      if (srcX === undefined || dstX === undefined || event.src_ip === event.dst_ip) {
        const x0 = srcX ?? (pMap.values().next().value as number);
        g.append("path")
          .attr("d", `M${x0},${y - 6} C${x0 + 40},${y - 16} ${x0 + 40},${y + 10} ${x0},${y + 4}`)
          .attr("fill", "none").attr("stroke", color).attr("stroke-width", 1.5)
          .attr("marker-end", `url(#${markerId})`);
        g.append("text")
          .attr("x", x0 + 44).attr("y", y - 2)
          .attr("fill", color).attr("font-size", "10px").attr("font-weight", "500")
          .text(truncate(event.summary, 28));
        return;
      }

      const isLR = srcX < dstX;

      // Arrow line (dashed for responses)
      g.append("line")
        .attr("x1", srcX).attr("y1", y)
        .attr("x2", dstX).attr("y2", y)
        .attr("stroke", color).attr("stroke-width", resp ? 1.5 : 2)
        .attr("stroke-dasharray", resp ? "5,3" : "none")
        .attr("marker-end", `url(#${markerId})`);

      // Activation box on source lifeline
      g.append("rect")
        .attr("x", srcX - 4).attr("y", y - 8)
        .attr("width", 8).attr("height", 16)
        .attr("rx", 2)
        .attr("fill", color).attr("opacity", 0.25);

      // Label above arrow
      const midX = (srcX + dstX) / 2;
      const labelY = y - 10;

      // Protocol pill badge
      const badgeW = 38;
      const protoLabel = event.protocol.length > 5 ? event.protocol.slice(0, 5) : event.protocol;
      g.append("rect")
        .attr("x", midX - badgeW / 2).attr("y", labelY - 14)
        .attr("width", badgeW).attr("height", 13)
        .attr("rx", 3)
        .attr("fill", color).attr("opacity", 0.18);
      g.append("text")
        .attr("x", midX).attr("y", labelY - 4)
        .attr("text-anchor", "middle")
        .attr("fill", color).attr("font-size", "8px").attr("font-weight", "700")
        .text(protoLabel);

      // Message label
      const maxLabelLen = Math.max(20, Math.floor(Math.abs(dstX - srcX) / 6));
      g.append("text")
        .attr("x", midX).attr("y", labelY + 2)
        .attr("text-anchor", "middle")
        .attr("fill", resp ? "#94a3b8" : "#e2e8f0")
        .attr("font-size", "10px")
        .attr("font-weight", resp ? "400" : "500")
        .attr("font-style", resp ? "italic" : "normal")
        .text(truncate(event.summary, maxLabelLen));

      // Port labels at arrow ends
      const portFontSz = "8px";
      g.append("text")
        .attr("x", isLR ? srcX + 6 : srcX - 6).attr("y", y + 12)
        .attr("text-anchor", isLR ? "start" : "end")
        .attr("fill", "#334155").attr("font-size", portFontSz).attr("font-family", "monospace")
        .text(`:${event.src_port}`);
      g.append("text")
        .attr("x", isLR ? dstX - 6 : dstX + 6).attr("y", y + 12)
        .attr("text-anchor", isLR ? "end" : "start")
        .attr("fill", "#334155").attr("font-size", portFontSz).attr("font-family", "monospace")
        .text(`:${event.dst_port}`);
    });
  }, [data, filteredEvents]);

  if (!data.participants.length || !data.events.length) {
    return (
      <div className="flex items-center justify-center py-12 text-slate-500 text-sm">
        No call flow data available
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Protocol filter pills */}
      <div className="flex flex-wrap gap-2 px-1">
        {["ALL", ...protocols].map((p) => {
          const color = PROTOCOL_COLORS[p] ?? "#94a3b8";
          const active = filterProto === p;
          return (
            <button
              key={p}
              onClick={() => setFilterProto(p)}
              className={`px-3 py-1 rounded-full text-xs font-medium border transition-all ${
                active
                  ? "text-white border-transparent"
                  : "text-slate-400 border-slate-700 hover:border-slate-500"
              }`}
              style={active ? { backgroundColor: p === "ALL" ? "#334155" : color + "33", borderColor: color, color } : {}}
            >
              {p}
            </button>
          );
        })}
        <span className="text-xs text-slate-600 self-center ml-2">
          {filteredEvents.length} messages
        </span>
      </div>

      {/* Legend */}
      <div className="flex gap-4 px-1 text-xs text-slate-500">
        <span className="flex items-center gap-1">
          <span className="inline-block w-6 border-t-2 border-slate-300" /> Request
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block w-6 border-t-2 border-dashed border-slate-500" /> Response
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-3 h-3 rounded-sm opacity-50" style={{ backgroundColor: "#34d399" }} />
          Setup phase
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-3 h-3 rounded-sm opacity-50" style={{ backgroundColor: "#22d3ee" }} />
          Media phase
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-3 h-3 rounded-sm opacity-50" style={{ backgroundColor: "#f87171" }} />
          Teardown
        </span>
      </div>

      {/* Diagram */}
      <div className="overflow-x-auto overflow-y-auto bg-slate-900/50 rounded-xl border border-slate-700/50 p-4 max-h-[80vh]">
        <svg ref={svgRef} />
      </div>
    </div>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

function fmtTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toISOString().slice(11, 23); // HH:MM:SS.mmm
  } catch {
    return ts;
  }
}

function fmtDelta(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
  return `${Math.floor(ms / 60000)}m${((ms % 60000) / 1000).toFixed(0)}s`;
}
