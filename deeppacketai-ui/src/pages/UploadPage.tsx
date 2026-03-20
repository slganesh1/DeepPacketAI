import { useState, useCallback, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Upload,
  FileUp,
  CheckCircle2,
  XCircle,
  Loader2,
  MessageSquare,
  File,
} from "lucide-react";
import { uploadPCAP } from "../api/upload";
import { fetchJob, fetchJobContext } from "../api/jobs";
import { createConversation, sendMessageStream } from "../api/chat";

type Stage = "select" | "uploading" | "processing" | "completed" | "failed";

export default function UploadPage() {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const [file, setFile] = useState<File | null>(null);
  const [stage, setStage] = useState<Stage>("select");
  const [jobId, setJobId] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [jobInfo, setJobInfo] = useState<{
    status: string;
    started_at: string;
    completed_at?: string;
  } | null>(null);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const handleFileSelect = useCallback((selected: File) => {
    const ext = selected.name.toLowerCase();
    if (!ext.endsWith(".pcap") && !ext.endsWith(".pcapng")) {
      setError("Please select a .pcap or .pcapng file");
      return;
    }
    setFile(selected);
    setError("");
    setStage("select");
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const dropped = e.dataTransfer.files[0];
      if (dropped) handleFileSelect(dropped);
    },
    [handleFileSelect]
  );

  const handleUpload = async () => {
    if (!file) return;

    setStage("uploading");
    setError("");

    try {
      const res = await uploadPCAP(file);
      setJobId(res.job_id);
      setStage("processing");

      // Poll for job completion
      pollRef.current = setInterval(async () => {
        try {
          const job = await fetchJob(res.job_id);
          setJobInfo({
            status: job.status,
            started_at: job.started_at,
            completed_at: job.completed_at,
          });

          if (job.status === "completed") {
            if (pollRef.current) clearInterval(pollRef.current);
            setStage("completed");
          } else if (job.status === "failed") {
            if (pollRef.current) clearInterval(pollRef.current);
            setStage("failed");
            setError(job.error || "Analysis failed");
          }
        } catch {
          // Keep polling on transient errors
        }
      }, 2000);
    } catch (err: unknown) {
      setStage("failed");
      setError(err instanceof Error ? err.message : "Upload failed");
    }
  };

  const handleAskAI = async () => {
    if (!jobId) {
      setError("No job ID available");
      return;
    }

    try {
      // Fetch detailed flow/call/event context for this specific job
      const context = await fetchJobContext(jobId);

      // Create a new conversation
      const conv = await createConversation(`PCAP Analysis - ${file?.name || "Upload"}`);

      // Send the analysis context as the first message
      sendMessageStream(
        conv.id,
        "I just uploaded and analyzed a PCAP file. Here is the detailed analysis data including all protocol flows, calls, and detected events. Please summarize the key findings, any issues detected, and recommendations.",
        context
      );

      // Navigate to chat page
      navigate("/chat");
    } catch {
      setError("Failed to start AI chat");
    }
  };

  const handleReset = () => {
    setFile(null);
    setStage("select");
    setJobId(null);
    setError("");
    setJobInfo(null);
    if (pollRef.current) clearInterval(pollRef.current);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="max-w-2xl mx-auto py-8 px-4">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center">
          <Upload className="w-5 h-5 text-emerald-400" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-white">Upload PCAP</h1>
          <p className="text-sm text-slate-400">
            Upload a packet capture file for analysis
          </p>
        </div>
      </div>

      <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
        {/* Drop zone - shown during select stage */}
        {stage === "select" && (
          <>
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all ${
                dragOver
                  ? "border-emerald-400 bg-emerald-500/10"
                  : "border-slate-600 hover:border-slate-500 hover:bg-slate-700/30"
              }`}
            >
              <FileUp
                className={`w-12 h-12 mx-auto mb-4 ${
                  dragOver ? "text-emerald-400" : "text-slate-500"
                }`}
              />
              <p className="text-sm text-slate-300 mb-1">
                Drag & drop your PCAP file here
              </p>
              <p className="text-xs text-slate-500">
                or click to browse (.pcap, .pcapng)
              </p>
            </div>

            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFileSelect(f);
              }}
              className="hidden"
            />

            {/* Selected file info */}
            {file && (
              <div className="mt-4 flex items-center justify-between bg-slate-700/50 rounded-lg px-4 py-3">
                <div className="flex items-center gap-3">
                  <File className="w-5 h-5 text-emerald-400" />
                  <div>
                    <p className="text-sm text-white">{file.name}</p>
                    <p className="text-xs text-slate-400">
                      {formatFileSize(file.size)}
                    </p>
                  </div>
                </div>
                <button
                  onClick={handleUpload}
                  className="px-4 py-2 bg-emerald-500/20 border border-emerald-500/30 rounded-lg text-sm text-emerald-400 hover:bg-emerald-500/30 transition-colors font-medium"
                >
                  Upload & Analyze
                </button>
              </div>
            )}
          </>
        )}

        {/* Uploading */}
        {stage === "uploading" && (
          <div className="text-center py-12">
            <Loader2 className="w-12 h-12 text-emerald-400 mx-auto mb-4 animate-spin" />
            <p className="text-sm text-white mb-1">Uploading {file?.name}...</p>
            <p className="text-xs text-slate-400">
              {formatFileSize(file?.size || 0)}
            </p>
          </div>
        )}

        {/* Processing */}
        {stage === "processing" && (
          <div className="text-center py-12">
            <Loader2 className="w-12 h-12 text-cyan-400 mx-auto mb-4 animate-spin" />
            <p className="text-sm text-white mb-1">Analyzing PCAP...</p>
            <p className="text-xs text-slate-400 mb-4">
              Decoding protocols, correlating flows, detecting anomalies
            </p>
            {jobId && (
              <p className="text-xs text-slate-500">Job ID: {jobId}</p>
            )}
          </div>
        )}

        {/* Completed */}
        {stage === "completed" && (
          <div className="text-center py-8">
            <CheckCircle2 className="w-14 h-14 text-emerald-400 mx-auto mb-4" />
            <p className="text-lg font-medium text-white mb-1">
              Analysis Complete
            </p>
            <p className="text-sm text-slate-400 mb-6">
              {file?.name} has been processed successfully
            </p>

            {jobInfo && (
              <div className="bg-slate-700/50 rounded-lg px-4 py-3 mb-6 text-left max-w-sm mx-auto">
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-400">Status</span>
                  <span className="text-emerald-400 font-medium">
                    Completed
                  </span>
                </div>
                {jobInfo.started_at && (
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-400">Started</span>
                    <span className="text-slate-300">
                      {new Date(jobInfo.started_at).toLocaleTimeString()}
                    </span>
                  </div>
                )}
                {jobInfo.completed_at && (
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">Completed</span>
                    <span className="text-slate-300">
                      {new Date(jobInfo.completed_at).toLocaleTimeString()}
                    </span>
                  </div>
                )}
              </div>
            )}

            <div className="flex items-center justify-center gap-3">
              <button
                onClick={handleAskAI}
                className="flex items-center gap-2 px-5 py-2.5 bg-emerald-500/20 border border-emerald-500/30 rounded-lg text-sm text-emerald-400 hover:bg-emerald-500/30 transition-colors font-medium"
              >
                <MessageSquare className="w-4 h-4" />
                Ask AI About This PCAP
              </button>
              <button
                onClick={handleReset}
                className="px-4 py-2.5 bg-slate-700/50 border border-slate-600/50 rounded-lg text-sm text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Upload Another
              </button>
            </div>
          </div>
        )}

        {/* Failed */}
        {stage === "failed" && (
          <div className="text-center py-12">
            <XCircle className="w-14 h-14 text-red-400 mx-auto mb-4" />
            <p className="text-lg font-medium text-white mb-1">
              Analysis Failed
            </p>
            <p className="text-sm text-red-400/80 mb-6">{error}</p>
            <button
              onClick={handleReset}
              className="px-4 py-2.5 bg-slate-700/50 border border-slate-600/50 rounded-lg text-sm text-slate-300 hover:bg-slate-700 transition-colors"
            >
              Try Again
            </button>
          </div>
        )}

        {/* Error message for validation */}
        {error && stage === "select" && (
          <p className="mt-3 text-sm text-red-400">{error}</p>
        )}
      </div>
    </div>
  );
}
