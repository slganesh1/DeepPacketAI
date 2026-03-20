import { api } from "./client";

export interface EntityMetrics {
  jitter: { timestamp: string; value: number }[];
  packet_count: { timestamp: string; value: number }[];
  mos: { timestamp: string; value: number }[];
}

export async function fetchEntityMetrics(
  entityId: string
): Promise<EntityMetrics> {
  const res = await api.get(`/entities/${entityId}/metrics`);
  return res.data;
}
