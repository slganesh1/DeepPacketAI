import { clsx } from "clsx";

interface LiveIndicatorProps {
  active: boolean;
  label?: string;
}

export default function LiveIndicator({
  active,
  label = "Live",
}: LiveIndicatorProps) {
  return (
    <div className="flex items-center gap-2">
      <div className="relative">
        <div
          className={clsx(
            "w-2.5 h-2.5 rounded-full",
            active ? "bg-emerald-400" : "bg-slate-600"
          )}
        />
        {active && (
          <div className="absolute inset-0 w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping opacity-50" />
        )}
      </div>
      <span
        className={clsx(
          "text-xs font-medium",
          active ? "text-emerald-400" : "text-slate-500"
        )}
      >
        {active ? label : "Idle"}
      </span>
    </div>
  );
}
