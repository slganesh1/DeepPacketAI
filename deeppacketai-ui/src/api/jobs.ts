import { api } from "./client";

export interface Job {
  job_id: number;
  status: string;
  pcap_path: string;
  started_at: string;
  completed_at?: string;
  error?: string;
}

export interface KPI {
  name: string;
  value: number;
  unit: string;
  description: string;
  status: string;
}

export interface JobSummary {
  job_id: number;
  total_flows: number;
  total_calls: number;
  total_packets: number;
  total_events: number;
  protocol_breakdown: Record<string, number>;
  quality_breakdown: Record<string, number>;
  avg_mos: number;
  kpis: KPI[];
}

export interface JobFlow {
  flow_id: string;
  type: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  start_time: string;
  end_time: string;
  metrics?: Record<string, unknown>;
}

export interface JobEvent {
  id: number;
  job_id?: number;
  session_id?: string;
  packet_id?: number;
  timestamp: string;
  severity: string;
  protocol: string;
  title: string;
  description: string;
  metadata_json?: string;
}

export async function fetchJobs(): Promise<Job[]> {
  const res = await api.get("/jobs");
  return res.data;
}

export async function fetchJob(jobID: number): Promise<Job> {
  const res = await api.get(`/jobs/${jobID}`);
  return res.data;
}

export async function fetchJobContext(jobID: number): Promise<string> {
  const res = await api.get(`/jobs/${jobID}/context`);
  return res.data.context;
}

export async function fetchJobSummary(jobID: number): Promise<JobSummary> {
  const res = await api.get(`/jobs/${jobID}/summary`);
  return res.data;
}

export async function fetchJobFlows(jobID: number, type?: string): Promise<JobFlow[]> {
  const params = type ? { type } : {};
  const res = await api.get(`/jobs/${jobID}/flows`, { params });
  return res.data;
}

export async function fetchJobEvents(jobID: number): Promise<JobEvent[]> {
  const res = await api.get(`/jobs/${jobID}/events`);
  return res.data;
}

export async function reprocessJob(jobID: number): Promise<void> {
  await api.post(`/jobs/${jobID}/reprocess`);
}
