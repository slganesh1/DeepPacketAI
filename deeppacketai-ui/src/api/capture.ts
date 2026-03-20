import { api } from "./client";

export interface NetworkInterface {
  name: string;
  description: string;
  addresses: string[];
}

export interface CaptureSession {
  id: string;
  interface_name: string;
  bpf_filter: string;
  status: string;
  started_at: string;
  stopped_at?: string;
  packet_count: number;
  byte_count: number;
  job_id?: number;
}

export interface StartCaptureResponse {
  session_id: string;
  status: string;
  job_id: number;
}

export interface StopCaptureResponse {
  status: string;
  session_id: string;
  job_id: number;
}

export async function fetchInterfaces(): Promise<NetworkInterface[]> {
  const { data } = await api.get("/capture/interfaces");
  return data;
}

export async function startCapture(
  iface: string,
  filter: string
): Promise<StartCaptureResponse> {
  const { data } = await api.post("/capture/start", {
    interface: iface,
    filter,
  });
  return data;
}

export async function stopCapture(
  sessionId: string
): Promise<StopCaptureResponse> {
  const { data } = await api.post("/capture/stop", {
    session_id: sessionId,
  });
  return data;
}

export async function fetchSessions(): Promise<CaptureSession[]> {
  const { data } = await api.get("/capture/sessions");
  return data;
}
