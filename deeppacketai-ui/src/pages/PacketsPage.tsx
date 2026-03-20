import { useEffect, useState, useCallback } from "react";
import { api } from "../api/client";
import PacketFilter from "../components/packets/PacketFilter";
import PacketTable from "../components/packets/PacketTable";
import PacketDetail from "../components/packets/PacketDetail";
import FlowGraph from "../components/packets/FlowGraph";

type ViewMode = "table" | "flow";

export default function PacketsPage() {
  const [packets, setPackets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<any>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [viewMode, setViewMode] = useState<ViewMode>("table");

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams(filters);
    params.set("limit", "1000");

    api
      .get(`/packets?${params.toString()}`)
      .then((r) => setPackets(r.data))
      .catch(() => setPackets([]))
      .finally(() => setLoading(false));
  }, [filters]);

  // Fetch full packet details when a row is selected
  const handleSelect = useCallback((pkt: any) => {
    // Show the row data immediately for instant feedback
    setSelected(pkt);

    // Then fetch the full record (with complete metadata_json)
    setLoadingDetail(true);
    api
      .get(`/packets/${pkt.id}`)
      .then((r) => setSelected(r.data))
      .catch(() => {
        // Keep the row data if the individual fetch fails
      })
      .finally(() => setLoadingDetail(false));
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Packets</h1>
          <p className="text-sm text-slate-400 mt-1">
            Browse and filter captured packets
          </p>
        </div>
        <div className="flex rounded-lg border border-slate-700/50 overflow-hidden">
          {(["table", "flow"] as ViewMode[]).map((m) => (
            <button
              key={m}
              onClick={() => { setViewMode(m); if (m === "flow") setSelected(null); }}
              className={`px-4 py-2 text-xs font-medium uppercase tracking-wider transition-colors ${
                viewMode === m
                  ? "bg-slate-700 text-white"
                  : "text-slate-500 hover:text-slate-300 hover:bg-slate-800"
              }`}
            >
              {m === "table" ? "Packet Table" : "Flow Graph"}
            </button>
          ))}
        </div>
      </div>

      <PacketFilter onFilter={setFilters} />

      {loading ? (
        <div className="text-slate-400 text-sm p-8 text-center">
          Loading packets...
        </div>
      ) : viewMode === "flow" ? (
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden">
          <FlowGraph packets={packets} />
        </div>
      ) : (
        <div className={`flex gap-4 ${selected ? "items-start" : ""}`}>
          {/* Packet table — shrinks when detail is open */}
          <div className={selected ? "flex-1 min-w-0" : "w-full"}>
            <PacketTable
              packets={packets}
              selectedId={selected?.id}
              onSelect={handleSelect}
            />
          </div>

          {/* Detail panel */}
          {selected && (
            <div className="w-[480px] flex-shrink-0 sticky top-4">
              {loadingDetail && (
                <div className="absolute inset-x-0 top-0 h-0.5 bg-emerald-500/60 rounded-full animate-pulse z-10" />
              )}
              <PacketDetail
                packet={selected}
                onClose={() => setSelected(null)}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
