import { useNavigate } from "react-router-dom";
import { AlertTriangle, AlertCircle, Info } from "lucide-react";
import { clsx } from "clsx";

interface AlertItem {
  id: number;
  timestamp: string;
  severity: string;
  protocol: string;
  title: string;
  description: string;
}

interface AlertsFeedProps {
  alerts: AlertItem[];
}

const severityConfig: Record<string, { icon: typeof AlertTriangle; color: string; bg: string }> = {
  critical: { icon: AlertCircle, color: "text-red-400", bg: "bg-red-500/10" },
  error: { icon: AlertCircle, color: "text-orange-400", bg: "bg-orange-500/10" },
  warning: { icon: AlertTriangle, color: "text-yellow-400", bg: "bg-yellow-500/10" },
  info: { icon: Info, color: "text-blue-400", bg: "bg-blue-500/10" },
};

export default function AlertsFeed({ alerts }: AlertsFeedProps) {
  const navigate = useNavigate();

  if (alerts.length === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-slate-500 text-sm">
        No alerts
      </div>
    );
  }

  return (
    <div className="space-y-2 max-h-48 overflow-y-auto">
      {alerts.slice(0, 10).map((alert) => {
        const config = severityConfig[alert.severity] || severityConfig.info;
        const Icon = config.icon;

        return (
          <div
            key={alert.id}
            className={clsx(
              "flex items-start gap-2 p-2 rounded-lg cursor-pointer hover:brightness-125 transition-all",
              config.bg
            )}
            onClick={() => navigate("/alerts")}
          >
            <Icon className={clsx("w-4 h-4 mt-0.5 flex-shrink-0", config.color)} />
            <div className="min-w-0">
              <div className="text-xs font-medium text-slate-200">
                <span className="text-slate-500">[{alert.protocol}]</span>{" "}
                {alert.title}
              </div>
              <div className="text-xs text-slate-400 truncate">
                {alert.description}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
