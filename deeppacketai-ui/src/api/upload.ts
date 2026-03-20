import { api } from "./client";

export interface UploadResponse {
  job_id: number;
  filename: string;
  status: string;
  message: string;
}

export async function uploadPCAP(file: File): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append("pcap", file);

  const { data } = await api.post("/jobs/upload", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}
