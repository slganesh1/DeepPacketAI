interface TopTalker {
  ip: string;
  count: number;
}

interface TopTalkersTableProps {
  data: TopTalker[];
}

export default function TopTalkersTable({ data }: TopTalkersTableProps) {
  if (!data || data.length === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-slate-500 text-sm">
        No traffic data
      </div>
    );
  }

  const max = data[0]?.count || 1;

  return (
    <div className="space-y-2">
      {data.map((t, i) => (
        <div key={t.ip} className="flex items-center gap-3">
          <span className="text-xs text-slate-500 w-4">{i + 1}</span>
          <span className="text-sm text-slate-300 font-mono flex-1">
            {t.ip}
          </span>
          <div className="flex-1">
            <div
              className="h-2 rounded-full bg-emerald-500/30"
              style={{ width: `${(t.count / max) * 100}%` }}
            >
              <div
                className="h-full rounded-full bg-emerald-500"
                style={{ width: "100%" }}
              />
            </div>
          </div>
          <span className="text-xs text-slate-400 w-16 text-right">
            {t.count.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}
