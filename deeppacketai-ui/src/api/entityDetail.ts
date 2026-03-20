import { api } from "./client";

export interface EntityDetail {
  entity: {
    entity_id: string;
    entity_type: string;
    start_time: string;
    end_time: string;
    summary: {
      mos: number;
      quality: string;
      root_cause: string;
      confidence: number;
    };
  };
  rtp_legs: any[];
  setup_latency_ms?: number;
}

export interface EntityEvent {
  timestamp: string;
  method?: string;
  response?: string;
  raw_line?: string;
}

export interface EntityMetrics {
  jitter: { timestamp: string; value: number }[];
  packet_count: { timestamp: string; value: number }[];
}

/* ---------- API CALLS ---------- */

export async function fetchEntityDetail(id: string) {
  const res = await api.get(`/entities/${id}`);
  return res.data;
}

export async function fetchEntityEvents(id: string) {
  const res = await api.get(`/entities/${id}/events`);
  return res.data;
}

export async function fetchEntityMetrics(id: string) {
  const res = await api.get(`/entities/${id}/metrics`);
  return res.data;
}

export interface CallFlowData {
  entity_id: string;
  participants: string[];
  events: {
    id: number;
    timestamp: string;
    protocol: string;
    event_type: string;
    summary: string;
    src_ip: string;
    dst_ip: string;
    src_port: number;
    dst_port: number;
  }[];
}

export async function fetchCallFlow(id: string): Promise<CallFlowData> {
  const res = await api.get(`/entities/${id}/callflow`);
  return res.data;
}