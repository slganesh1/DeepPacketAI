import { useEffect, useRef, useState, useCallback } from "react";

export interface WSMessage {
  type: "packet" | "stats" | "alert" | "capture_state" | "chat_chunk" | "ai_insight";
  payload: any;
}

interface UseWebSocketOptions {
  url?: string;
  onMessage?: (msg: WSMessage) => void;
  reconnectInterval?: number;
}

// Build the WebSocket URL from the current page origin so it works in both
// local dev (ws://localhost:8080/ws) and production (wss://server/ws via Nginx).
function defaultWsUrl(): string {
  if (import.meta.env.DEV) return "ws://localhost:8080/ws";
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/ws`;
}

export function useWebSocket({
  url = defaultWsUrl(),
  onMessage,
  reconnectInterval = 3000,
}: UseWebSocketOptions = {}) {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(url);

    ws.onopen = () => {
      setConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data);
        onMessageRef.current?.(msg);
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      setConnected(false);
      reconnectTimer.current = setTimeout(connect, reconnectInterval);
    };

    ws.onerror = () => {
      ws.close();
    };

    wsRef.current = ws;
  }, [url, reconnectInterval]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const send = useCallback((data: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  return { connected, send };
}
