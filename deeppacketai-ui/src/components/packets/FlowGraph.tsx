import { useMemo, useState } from "react";
import { ArrowRight, ArrowLeft } from "lucide-react";

interface Packet {
  id: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  app_protocol?: string;
  length: number;
  timestamp: string;
}

interface FlowGraphProps {
  packets: Packet[];
}

interface FlowEntry {
  key: string;
  ipA: string;
  ipB: string;
  portA: number;
  portB: number;
  protocol: string;
  fwd: { packets: number; bytes: number };
  rev: { packets: number; bytes: number };
  firstTs: number;
  lastTs: number;
  protocols: string[];
}

const PROTO_COLOR: Record<string, string> = {
  SIP:      "text-emerald-400 border-emerald-500/40 bg-emerald-500/10",
  RTP:      "text-cyan-400 border-cyan-500/40 bg-cyan-500/10",
  DNS:      "text-indigo-400 border-indigo-500/40 bg-indigo-500/10",
  HTTP:     "text-amber-400 border-amber-500/40 bg-amber-500/10",
  TLS:      "text-lime-400 border-lime-500/40 bg-lime-500/10",
  HTTPS:    "text-lime-400 border-lime-500/40 bg-lime-500/10",
  Diameter: "text-pink-400 border-pink-500/40 bg-pink-500/10",
  GTP:      "text-orange-400 border-orange-500/40 bg-orange-500/10",
  "GTP-C":  "text-orange-400 border-orange-500/40 bg-orange-500/10",
  "GTP-U":  "text-yellow-400 border-yellow-500/40 bg-yellow-500/10",
  PFCP:     "text-violet-400 border-violet-500/40 bg-violet-500/10",
  S1AP:     "text-teal-400 border-teal-500/40 bg-teal-500/10",
  NGAP:     "text-green-400 border-green-500/40 bg-green-500/10",
  TCP:      "text-slate-400 border-slate-500/40 bg-slate-500/10",
  UDP:      "text-slate-400 border-slate-500/40 bg-slate-500/10",
};

const BAR_COLOR: Record<string, string> = {
  SIP: "#34d399", RTP: "#22d3ee", DNS: "#818cf8", HTTP: "#f59e0b",
  TLS: "#84cc16", HTTPS: "#84cc16", Diameter: "#f472b6",
  GTP: "#fb923c", "GTP-C": "#fb923c", "GTP-U": "#fbbf24",
  PFCP: "#a78bfa", S1AP: "#38bdf8", NGAP: "#4ade80",
};

function fmtBytes(b: number): string {
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)} MB`;
  if (b >= 1_000) return `${(b / 1_000).toFixed(1)} KB`;
  return `${b} B`;
}

function fmtRate(bytes: number, durationSec: number): string {
  if (durationSec <= 0) return "-";
  const bps = bytes / durationSec;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} MB/s`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} KB/s`;
  return `${bps.toFixed(0)} B/s`;
}

function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

export default function FlowGraph({ packets }: FlowGraphProps) {
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const flows = useMemo<FlowEntry[]>(() => {
    const map = new Map<string, FlowEntry>();

    for (const pkt of packets) {
      const ts = new Date(pkt.timestamp).getTime() || 0;
      const proto = pkt.app_protocol || pkt.protocol;

      // Normalise direction: smaller IP is always ipA
      const [ipA, portA, ipB, portB] =
        pkt.src_ip < pkt.dst_ip
          ? [pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port]
          : [pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port];

      const key = `${ipA}:${portA}↔${ipB}:${portB}:${proto}`;

      if (!map.has(key)) {
        map.set(key, {
          key, ipA, ipB, portA, portB, protocol: proto,
          fwd: { packets: 0, bytes: 0 },
          rev: { packets: 0, bytes: 0 },
          firstTs: ts, lastTs: ts,
          protocols: [proto],
        });
      }

      const f = map.get(key)!;
      const isFwd = pkt.src_ip === ipA;
      if (isFwd) {
        f.fwd.packets++;
        f.fwd.bytes += pkt.length;
      } else {
        f.rev.packets++;
        f.rev.bytes += pkt.length;
      }
      if (ts < f.firstTs) f.firstTs = ts;
      if (ts > f.lastTs) f.lastTs = ts;
    }

    return Array.from(map.values()).sort(
      (a, b) => (b.fwd.bytes + b.rev.bytes) - (a.fwd.bytes + a.rev.bytes)
    );
  }, [packets]);

  const maxBytes = useMemo(
    () => Math.max(1, ...flows.map((f) => f.fwd.bytes + f.rev.bytes)),
    [flows]
  );

  if (!flows.length) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500 text-sm">
        No flows to display
      </div>
    );
  }

  return (
    <div className="space-y-2 p-2">
      <div className="text-xs text-slate-500 px-2">
        {flows.length} unique flows — sorted by total bytes
      </div>

      {flows.map((flow) => {
        const durationSec = (flow.lastTs - flow.firstTs) / 1000;
        const totalBytes = flow.fwd.bytes + flow.rev.bytes;
        const barPct = (totalBytes / maxBytes) * 100;
        const color = BAR_COLOR[flow.protocol] ?? "#94a3b8";
        const badgeCls = PROTO_COLOR[flow.protocol] ?? "text-slate-400 border-slate-500/40 bg-slate-500/10";
        const isSelected = selectedKey === flow.key;

        return (
          <div
            key={flow.key}
            onClick={() => setSelectedKey(isSelected ? null : flow.key)}
            className={`rounded-xl border cursor-pointer transition-all ${
              isSelected
                ? "border-slate-500/60 bg-slate-800/80"
                : "border-slate-700/40 bg-slate-800/40 hover:border-slate-600/60 hover:bg-slate-800/60"
            }`}
          >
            {/* Main row */}
            <div className="flex items-center gap-3 px-4 py-3">
              {/* IP A */}
              <div className="flex flex-col items-center w-36 flex-shrink-0">
                <div className="bg-slate-700/60 border border-slate-600/40 rounded-lg px-3 py-1.5 text-center w-full">
                  <div className="text-xs font-mono text-white">{flow.ipA}</div>
                  <div className="text-xs text-slate-500">:{flow.portA}</div>
                </div>
              </div>

              {/* Arrow + Metrics */}
              <div className="flex-1 min-w-0">
                {/* Protocol badge */}
                <div className="flex justify-center mb-1.5">
                  <span className={`text-xs font-medium px-2 py-0.5 rounded border ${badgeCls}`}>
                    {flow.protocol}
                  </span>
                </div>

                {/* Bandwidth bar */}
                <div className="h-1.5 rounded-full bg-slate-700/60 mb-1.5">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{ width: `${barPct}%`, backgroundColor: color, opacity: 0.8 }}
                  />
                </div>

                {/* Fwd arrow */}
                <div className="flex items-center gap-1 justify-center text-xs text-slate-400">
                  <ArrowRight className="w-3 h-3 flex-shrink-0" style={{ color }} />
                  <span className="font-mono">{fmtBytes(flow.fwd.bytes)}</span>
                  <span className="text-slate-600">·</span>
                  <span className="font-mono">{flow.fwd.packets}p</span>
                  <span className="text-slate-600">·</span>
                  <span className="font-mono">{fmtRate(flow.fwd.bytes, durationSec)}</span>
                </div>

                {/* Rev arrow (if any) */}
                {flow.rev.packets > 0 && (
                  <div className="flex items-center gap-1 justify-center text-xs text-slate-400 mt-0.5">
                    <ArrowLeft className="w-3 h-3 flex-shrink-0" style={{ color }} />
                    <span className="font-mono">{fmtBytes(flow.rev.bytes)}</span>
                    <span className="text-slate-600">·</span>
                    <span className="font-mono">{flow.rev.packets}p</span>
                    <span className="text-slate-600">·</span>
                    <span className="font-mono">{fmtRate(flow.rev.bytes, durationSec)}</span>
                  </div>
                )}
              </div>

              {/* IP B */}
              <div className="flex flex-col items-center w-36 flex-shrink-0">
                <div className="bg-slate-700/60 border border-slate-600/40 rounded-lg px-3 py-1.5 text-center w-full">
                  <div className="text-xs font-mono text-white">{flow.ipB}</div>
                  <div className="text-xs text-slate-500">:{flow.portB}</div>
                </div>
              </div>

              {/* Duration */}
              <div className="w-20 text-right flex-shrink-0">
                <div className="text-xs text-slate-400 font-mono">{fmtDuration(flow.lastTs - flow.firstTs)}</div>
                <div className="text-xs text-slate-600">duration</div>
              </div>
            </div>

            {/* Expanded detail */}
            {isSelected && (
              <div className="px-4 pb-3 pt-0 border-t border-slate-700/40 grid grid-cols-4 gap-4 text-xs">
                <StatCell label="Total Bytes" value={fmtBytes(totalBytes)} />
                <StatCell label="Total Packets" value={(flow.fwd.packets + flow.rev.packets).toString()} />
                <StatCell label="Avg Rate" value={fmtRate(totalBytes, durationSec)} />
                <StatCell label="Duration" value={fmtDuration(flow.lastTs - flow.firstTs)} />
                <StatCell label="→ Bytes" value={fmtBytes(flow.fwd.bytes)} />
                <StatCell label="→ Packets" value={flow.fwd.packets.toString()} />
                <StatCell label="← Bytes" value={fmtBytes(flow.rev.bytes)} />
                <StatCell label="← Packets" value={flow.rev.packets.toString()} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function StatCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="pt-2">
      <div className="text-slate-500">{label}</div>
      <div className="text-slate-200 font-mono font-medium">{value}</div>
    </div>
  );
}
