import { api } from "./client";

export type Entity = {
  entity_id: string;
  summary: {
    mos: number;
    quality: string;
    root_cause: string;
    confidence: number;
  };
};

export async function fetchJobEntities(jobId: string): Promise<Entity[]> {
  const res = await api.get(`/jobs/${jobId}/entities`);
  return res.data;
}
