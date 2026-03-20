import { api } from "./client";

export interface Conversation {
  id: string;
  title: string;
  provider: string;
  model: string;
  created_at: string;
  updated_at: string;
}

export interface ChatMessage {
  id: number;
  conversation_id: string;
  role: string;
  content: string;
  packet_context_json?: string;
  created_at: string;
}

export async function createConversation(
  title: string
): Promise<Conversation> {
  const { data } = await api.post("/chat/conversations", { title });
  return data;
}

export async function fetchConversations(): Promise<Conversation[]> {
  const { data } = await api.get("/chat/conversations");
  return data;
}

export async function fetchConversation(
  id: string
): Promise<{ conversation: Conversation; messages: ChatMessage[] }> {
  const { data } = await api.get(`/chat/conversations/${id}`);
  return data;
}

export async function deleteConversation(id: string): Promise<void> {
  await api.delete(`/chat/conversations/${id}`);
}

export async function fetchProviders(): Promise<{
  providers: string[];
  active: string;
}> {
  const { data } = await api.get("/chat/providers");
  return data;
}

export async function setActiveProvider(provider: string): Promise<void> {
  await api.put("/chat/settings", { provider });
}

// sendMessage uses SSE streaming
export function sendMessageStream(
  conversationId: string,
  content: string,
  packetContext?: string,
  onChunk?: (text: string) => void,
  onDone?: () => void,
  onError?: (err: string) => void
): AbortController {
  const controller = new AbortController();

  const apiBase = import.meta.env.PROD ? "/api/v1" : "http://localhost:8080/api/v1";
  fetch(`${apiBase}/chat/conversations/${conversationId}/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      content,
      packet_context: packetContext,
    }),
    signal: controller.signal,
  })
    .then(async (response) => {
      const reader = response.body?.getReader();
      if (!reader) return;

      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.content) {
                onChunk?.(data.content);
              }
              if (data.done) {
                onDone?.();
                return;
              }
              if (data.error) {
                onError?.(data.error);
                return;
              }
            } catch {
              // ignore parse errors
            }
          }
        }
      }
      onDone?.();
    })
    .catch((err) => {
      if (err.name !== "AbortError") {
        onError?.(err.message);
      }
    });

  return controller;
}
