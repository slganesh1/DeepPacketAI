import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchJobs, fetchJobSummary } from "../api/jobs";
import type { Job, JobSummary } from "../api/jobs";

export default function JobsPage() {
  const navigate = useNavigate();

  const [jobs, setJobs] = useState<Job[]>([]);
  const [summaries, setSummaries] = useState<Record<number, JobSummary>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchJobs()
      .then((data) => {
        setJobs(data);
        // Fetch summaries for each job in parallel
        const promises = data.map((job) =>
          fetchJobSummary(job.job_id)
            .then((summary) => ({ id: job.job_id, summary }))
            .catch(() => null)
        );
        Promise.all(promises).then((results) => {
          const map: Record<number, JobSummary> = {};
          for (const r of results) {
            if (r) map[r.id] = r.summary;
          }
          setSummaries(map);
        });
      })
      .catch(() => setError("Failed to load jobs"))
      .finally(() => setLoading(false));
  }, []);

  if (error) {
    return <div className="p-6 text-red-400">{error}</div>;
  }

  if (loading) {
    return (
      <div className="p-6 text-slate-400 animate-pulse">Loading jobs...</div>
    );
  }

  const completed = jobs.filter((j) => j.status === "completed").length;
  const failed = jobs.filter((j) => j.status === "failed").length;
  const active = jobs.filter((j) => j.status === "running").length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">PCAP Jobs</h1>
        <p className="text-sm text-slate-400 mt-1">
          Upload analysis results and capture sessions
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SummaryCard label="Total Jobs" value={jobs.length} color="text-blue-400" />
        <SummaryCard label="Completed" value={completed} color="text-emerald-400" />
        <SummaryCard label="Failed" value={failed} color="text-red-400" />
        <SummaryCard label="Active" value={active} color="text-amber-400" />
      </div>

      {/* Job Cards */}
      {jobs.length === 0 ? (
        <div className="text-slate-500 text-center py-12">
          No jobs found. Upload a PCAP to get started.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {jobs.map((job) => {
            const summary = summaries[job.job_id];
            return (
              <JobCard
                key={job.job_id}
                job={job}
                summary={summary}
                onClick={() => navigate(`/jobs/${job.job_id}`)}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}

function SummaryCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
      <div className="text-xs text-slate-400 uppercase tracking-wider">{label}</div>
      <div className={`text-2xl font-bold mt-1 ${color}`}>{value}</div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { bg: string; text: string }> = {
    completed: { bg: "bg-emerald-500/20", text: "text-emerald-400" },
    running: { bg: "bg-amber-500/20", text: "text-amber-400" },
    failed: { bg: "bg-red-500/20", text: "text-red-400" },
    pending: { bg: "bg-slate-500/20", text: "text-slate-400" },
  };
  const c = config[status] || config.pending;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${c.bg} ${c.text}`}>
      {status === "running" && (
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mr-1.5 animate-pulse" />
      )}
      {status}
    </span>
  );
}

function pcapName(path: string): string {
  if (!path) return "Unknown source";
  // Extract filename from path
  const parts = path.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || path;
}

function formatDuration(startedAt: string, completedAt?: string): string {
  if (!startedAt) return "-";
  const start = new Date(startedAt).getTime();
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  const diffMs = end - start;
  if (diffMs < 1000) return `${diffMs}ms`;
  if (diffMs < 60000) return `${(diffMs / 1000).toFixed(1)}s`;
  return `${(diffMs / 60000).toFixed(1)}m`;
}

function JobCard({
  job,
  summary,
  onClick,
}: {
  job: Job;
  summary?: JobSummary;
  onClick: () => void;
}) {
  return (
    <div
      className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-5 cursor-pointer hover:bg-slate-700/60 hover:border-slate-600/60 transition-all group"
      onClick={onClick}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-white truncate group-hover:text-blue-400 transition-colors">
            {pcapName(job.pcap_path)}
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">Job #{job.job_id}</p>
        </div>
        <StatusBadge status={job.status} />
      </div>

      {/* Time info */}
      <div className="flex items-center gap-3 text-xs text-slate-400 mb-4">
        <span>{new Date(job.started_at).toLocaleDateString()}</span>
        <span className="text-slate-600">|</span>
        <span>{formatDuration(job.started_at, job.completed_at)}</span>
      </div>

      {/* Stats grid */}
      {summary ? (
        <div className="grid grid-cols-4 gap-2">
          <MiniStat label="Flows" value={summary.total_flows} />
          <MiniStat label="Calls" value={summary.total_calls} />
          <MiniStat label="Events" value={summary.total_events} />
          <MiniStat
            label="Avg MOS"
            value={summary.avg_mos > 0 ? summary.avg_mos.toFixed(2) : "-"}
          />
        </div>
      ) : (
        <div className="grid grid-cols-4 gap-2">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="bg-slate-700/40 rounded-lg p-2 animate-pulse h-12" />
          ))}
        </div>
      )}

      {/* Error message */}
      {job.error && (
        <p className="text-xs text-red-400 mt-3 truncate" title={job.error}>
          {job.error}
        </p>
      )}
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-slate-700/40 rounded-lg p-2 text-center">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="text-sm font-semibold text-slate-200 mt-0.5">{value}</div>
    </div>
  );
}
