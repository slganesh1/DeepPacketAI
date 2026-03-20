import { clsx } from "clsx";
import { AlertCircle } from "lucide-react";

interface Packet {
  id: number;
  frame_number: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  app_protocol: string;
  length: number;
  summary: string;
  errors_json?: string;
}

interface PacketTableProps {
  packets: Packet[];
  selectedId: number | null;
  onSelect: (packet: Packet) => void;
}

const protocolColors: Record<string, string> = {
  SIP: "text-blue-400",
  RTP: "text-green-400",
  DNS: "text-cyan-400",
  HTTP: "text-orange-400",
  TLS: "text-lime-400",
  HTTPS: "text-lime-400",
  Diameter: "text-purple-400",
  "GTP-C": "text-yellow-400",
  "GTP-U": "text-yellow-300",
  PFCP: "text-pink-400",
  S1AP: "text-teal-400",
  NGAP: "text-indigo-400",
  SCTP: "text-slate-400",
  TCP: "text-slate-400",
  UDP: "text-slate-400",
};

export default function PacketTable({
  packets,
  selectedId,
  onSelect,
}: PacketTableProps) {
  if (packets.length === 0) {
    return (
      <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-16 text-center text-slate-500 text-sm">
        No packets to display. Upload a PCAP or start a live capture.
      </div>
    );
  }

  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden">
      <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-slate-800 z-10">
            <tr className="border-b border-slate-700/50">
              <th className="px-3 py-2.5 text-left text-xs font-medium text-slate-400 uppercase tracking-wider w-12">
                #
              </th>
              <th className="px-3 py-2.5 text-left text-xs font-medium text-slate-400 uppercase tracking-wider w-40">
                Time
              </th>
              <th className="px-3 py-2.5 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Source
              </th>
              <th className="px-3 py-2.5 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Destination
              </th>
              <th className="px-3 py-2.5 text-left text-xs font-medium text-slate-400 uppercase tracking-wider w-24">
                Protocol
              </th>
              <th className="px-3 py-2.5 text-left text-xs font-medium text-slate-400 uppercase tracking-wider w-16">
                Len
              </th>
              <th className="px-3 py-2.5 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                Info
              </th>
            </tr>
          </thead>
          <tbody>
            {packets.map((pkt) => {
              const proto = pkt.app_protocol || pkt.protocol;
              const hasErrors =
                pkt.errors_json && pkt.errors_json !== "null" && pkt.errors_json !== "[]";

              return (
                <tr
                  key={pkt.id}
                  onClick={() => onSelect(pkt)}
                  className={clsx(
                    "border-b border-slate-700/30 cursor-pointer transition-colors",
                    selectedId === pkt.id
                      ? "bg-emerald-500/10"
                      : "hover:bg-slate-700/30"
                  )}
                >
                  <td className="px-3 py-1.5 text-slate-500 font-mono text-xs">
                    {pkt.frame_number}
                  </td>
                  <td className="px-3 py-1.5 text-slate-400 font-mono text-xs">
                    {formatTimestamp(pkt.timestamp)}
                  </td>
                  <td className="px-3 py-1.5 text-slate-300 font-mono text-xs">
                    {pkt.src_ip}:{pkt.src_port}
                  </td>
                  <td className="px-3 py-1.5 text-slate-300 font-mono text-xs">
                    {pkt.dst_ip}:{pkt.dst_port}
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={clsx(
                        "text-xs font-medium",
                        protocolColors[proto] || "text-slate-400"
                      )}
                    >
                      {proto}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-slate-400 text-xs">
                    {pkt.length}
                  </td>
                  <td className="px-3 py-1.5 text-slate-300 text-xs truncate max-w-xs">
                    <div className="flex items-center gap-1">
                      {hasErrors && (
                        <AlertCircle className="w-3 h-3 text-orange-400 flex-shrink-0" />
                      )}
                      {pkt.summary || "-"}
                    </div>
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

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toISOString().substring(11, 23);
  } catch {
    return ts;
  }
}
