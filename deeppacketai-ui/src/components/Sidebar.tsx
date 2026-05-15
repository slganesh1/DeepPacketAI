import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Radio,
  List,
  Briefcase,
  MessageSquare,
  Upload,
  BarChart3,
  AlertTriangle,
  Bell,
  ShieldCheck,
  Globe,
  Phone,
  ShieldAlert,
  Gauge,
  Puzzle,
  Network,
} from "lucide-react";
import { clsx } from "clsx";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/capture", icon: Radio, label: "Live Capture" },
  { to: "/agents", icon: Network, label: "Capture Agents" },
  { to: "/packets", icon: List, label: "Packets" },
  { to: "/jobs", icon: Briefcase, label: "Jobs" },
  { to: "/alerts", icon: AlertTriangle, label: "Alerts" },
  { to: "/alerting", icon: Bell, label: "Notifications" },
  { to: "/detection-rules", icon: ShieldCheck, label: "Detection Rules" },
  { to: "/geo", icon: Globe, label: "GeoIP & Reputation" },
  { to: "/security", icon: ShieldAlert, label: "Security" },
  { to: "/observability", icon: Gauge, label: "Observability" },
  { to: "/analytics", icon: BarChart3, label: "Analytics" },
  { to: "/telecom", icon: Phone, label: "Call Trace" },
  { to: "/chat", icon: MessageSquare, label: "AI Chat" },
  { to: "/plugins", icon: Puzzle, label: "Plugins" },
];

export default function Sidebar() {
  const location = useLocation();

  return (
    <div className="w-64 bg-slate-900 text-white flex flex-col border-r border-slate-700">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-slate-700/50">
        <img src="/techtezlogo.svg" alt="Techtez" className="h-7 w-auto" />
        <div className="text-[10px] text-slate-500 mt-1.5 tracking-wide uppercase pl-0.5">
          DeepPacketAI · Telecom Analyzer
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-1">
        {navItems.map((item) => {
          const isActive =
            item.to === "/"
              ? location.pathname === "/"
              : location.pathname.startsWith(item.to);

          return (
            <Link
              key={item.to}
              to={item.to}
              className={clsx(
                "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all",
                isActive
                  ? "bg-slate-800 text-emerald-400 shadow-sm shadow-emerald-500/10"
                  : "text-slate-300 hover:bg-slate-800/60 hover:text-white"
              )}
            >
              <item.icon className="w-4 h-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Upload shortcut */}
      <div className="p-3 border-t border-slate-700/50">
        <Link
          to="/upload"
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-slate-300 hover:bg-slate-800/60 hover:text-emerald-400 transition-all"
        >
          <Upload className="w-4 h-4" />
          Upload PCAP
        </Link>
      </div>
    </div>
  );
}
