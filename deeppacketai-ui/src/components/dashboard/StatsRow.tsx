import { Activity, Wifi, AlertTriangle, Database } from "lucide-react";
import StatCard from "../StatCard";

interface StatsRowProps {
  totalPackets: number;
  protocols: number;
  activeFlows: number;
  alerts: number;
}

export default function StatsRow({
  totalPackets,
  protocols,
  activeFlows,
  alerts,
}: StatsRowProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        label="Total Packets"
        value={totalPackets.toLocaleString()}
        icon={Activity}
        accent="emerald"
      />
      <StatCard
        label="Protocols"
        value={protocols}
        icon={Database}
        accent="cyan"
      />
      <StatCard
        label="Active Flows"
        value={activeFlows}
        icon={Wifi}
        accent="blue"
      />
      <StatCard
        label="Alerts"
        value={alerts}
        icon={AlertTriangle}
        accent={alerts > 0 ? "orange" : "emerald"}
      />
    </div>
  );
}
