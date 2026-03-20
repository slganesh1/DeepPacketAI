import { clsx } from "clsx";
import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  label: string;
  value: string | number;
  icon?: LucideIcon;
  accent?: "emerald" | "cyan" | "orange" | "red" | "blue";
  subtitle?: string;
}

const accentColors = {
  emerald: "border-emerald-500/30 shadow-emerald-500/5",
  cyan: "border-cyan-500/30 shadow-cyan-500/5",
  orange: "border-orange-500/30 shadow-orange-500/5",
  red: "border-red-500/30 shadow-red-500/5",
  blue: "border-blue-500/30 shadow-blue-500/5",
};

const iconColors = {
  emerald: "text-emerald-400",
  cyan: "text-cyan-400",
  orange: "text-orange-400",
  red: "text-red-400",
  blue: "text-blue-400",
};

export default function StatCard({
  label,
  value,
  icon: Icon,
  accent = "emerald",
  subtitle,
}: StatCardProps) {
  return (
    <div
      className={clsx(
        "bg-slate-800/80 border rounded-xl p-4 shadow-lg",
        accentColors[accent]
      )}
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-slate-400 uppercase tracking-wider">
            {label}
          </div>
          <div className="text-2xl font-bold text-white mt-1">{value}</div>
          {subtitle && (
            <div className="text-xs text-slate-500 mt-0.5">{subtitle}</div>
          )}
        </div>
        {Icon && (
          <div
            className={clsx(
              "w-10 h-10 rounded-lg bg-slate-700/50 flex items-center justify-center",
              iconColors[accent]
            )}
          >
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
    </div>
  );
}
