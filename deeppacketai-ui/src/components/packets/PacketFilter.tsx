import { Search, Filter, X } from "lucide-react";
import { useState } from "react";

interface PacketFilterProps {
  onFilter: (filters: Record<string, string>) => void;
}

export default function PacketFilter({ onFilter }: PacketFilterProps) {
  const [search, setSearch] = useState("");
  const [protocol, setProtocol] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [srcIP, setSrcIP] = useState("");
  const [dstIP, setDstIP] = useState("");

  const apply = () => {
    const filters: Record<string, string> = {};
    if (protocol) filters.protocol = protocol;
    if (srcIP) filters.src_ip = srcIP;
    if (dstIP) filters.dst_ip = dstIP;
    onFilter(filters);
  };

  const clear = () => {
    setSearch("");
    setProtocol("");
    setSrcIP("");
    setDstIP("");
    onFilter({});
  };

  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4 space-y-3">
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by protocol, IP, port..."
            className="w-full bg-slate-700 border border-slate-600 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          />
        </div>

        <select
          value={protocol}
          onChange={(e) => {
            setProtocol(e.target.value);
            const f: Record<string, string> = {};
            if (e.target.value) f.protocol = e.target.value;
            if (srcIP) f.src_ip = srcIP;
            if (dstIP) f.dst_ip = dstIP;
            onFilter(f);
          }}
          className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-emerald-500"
        >
          <option value="">All Protocols</option>
          <option value="SIP">SIP</option>
          <option value="RTP">RTP</option>
          <option value="DNS">DNS</option>
          <option value="HTTP">HTTP</option>
          <option value="HTTPS">HTTPS</option>
          <option value="TLS">TLS</option>
          <option value="Diameter">Diameter</option>
          <option value="GTP-C">GTP-C</option>
          <option value="GTP-U">GTP-U</option>
          <option value="PFCP">PFCP</option>
          <option value="S1AP">S1AP</option>
          <option value="NGAP">NGAP</option>
        </select>

        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-2 px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-300 hover:bg-slate-600 transition-colors"
        >
          <Filter className="w-4 h-4" />
          Filters
        </button>

        {(protocol || srcIP || dstIP) && (
          <button
            onClick={clear}
            className="flex items-center gap-1 px-3 py-2 text-sm text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
            Clear
          </button>
        )}
      </div>

      {showAdvanced && (
        <div className="flex items-center gap-3 pt-2 border-t border-slate-700/50">
          <input
            type="text"
            value={srcIP}
            onChange={(e) => setSrcIP(e.target.value)}
            placeholder="Source IP"
            className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          />
          <input
            type="text"
            value={dstIP}
            onChange={(e) => setDstIP(e.target.value)}
            placeholder="Destination IP"
            className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          />
          <button
            onClick={apply}
            className="px-4 py-1.5 bg-emerald-500/20 border border-emerald-500/30 rounded-lg text-sm text-emerald-400 hover:bg-emerald-500/30 transition-colors"
          >
            Apply
          </button>
        </div>
      )}
    </div>
  );
}
