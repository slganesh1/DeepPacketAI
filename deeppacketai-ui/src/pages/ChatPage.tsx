import { useState, useEffect, useRef, useCallback } from "react";
import { useLocation } from "react-router-dom";
import { MessageSquare, Send, Plus, Trash2, Settings, Radio } from "lucide-react";
import {
  createConversation,
  fetchConversations,
  fetchConversation,
  deleteConversation,
  fetchProviders,
  setActiveProvider,
  sendMessageStream,
} from "../api/chat";
import type { Conversation, ChatMessage } from "../api/chat";
import { useWebSocket } from "../hooks/useWebSocket";
import { api } from "../api/client";

// Build a compact text summary of PCAP analysis results, safe for all AI token limits.
function buildPcapSummary(jobId: number, flows: any[], events: any[]): string {
  const lines: string[] = [`=== PCAP Analysis Summary — Job #${jobId} ===`];

  // Protocol distribution
  const byType: Record<string, number> = {};
  for (const f of flows) {
    const t = f.type ?? f.protocol ?? "unknown";
    byType[t] = (byType[t] ?? 0) + 1;
  }
  lines.push(`\nTotal flows: ${flows.length}`);
  lines.push("Protocols: " + Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `${k}(${v})`).join(", "));

  // Top source IPs
  const srcCount: Record<string, number> = {};
  const dstCount: Record<string, number> = {};
  for (const f of flows) {
    if (f.src_ip) srcCount[f.src_ip] = (srcCount[f.src_ip] ?? 0) + 1;
    if (f.dst_ip) dstCount[f.dst_ip] = (dstCount[f.dst_ip] ?? 0) + 1;
  }
  const topSrc = Object.entries(srcCount).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const topDst = Object.entries(dstCount).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (topSrc.length) lines.push("\nTop source IPs: " + topSrc.map(([ip, n]) => `${ip}(${n})`).join(", "));
  if (topDst.length) lines.push("Top dest IPs:   " + topDst.map(([ip, n]) => `${ip}(${n})`).join(", "));

  // Sample flows — 3 per protocol type
  lines.push("\n=== Sample flows (3 per protocol) ===");
  const seen: Record<string, number> = {};
  for (const f of flows) {
    const t = f.type ?? f.protocol ?? "unknown";
    if ((seen[t] ?? 0) >= 3) continue;
    seen[t] = (seen[t] ?? 0) + 1;
    const metrics = f.metrics ? " | " + Object.entries(f.metrics)
      .filter(([, v]) => v !== null && v !== "" && v !== 0)
      .slice(0, 6)
      .map(([k, v]) => `${k}=${v}`).join(", ") : "";
    lines.push(`[${t}] ${f.src_ip}:${f.src_port} → ${f.dst_ip}:${f.dst_port}${metrics}`);
  }

  // Events summary — group by type for compact representation
  if (events.length > 0) {
    lines.push(`\n=== Events/Alerts (${events.length} total) ===`);
    const eventGroups: Record<string, { severity: string; count: number }> = {};
    for (const e of events) {
      const key = e.title ?? e.type ?? e.message?.slice(0, 60) ?? "unknown";
      if (!eventGroups[key]) eventGroups[key] = { severity: e.severity ?? "info", count: 0 };
      eventGroups[key].count++;
    }
    const sorted = Object.entries(eventGroups).sort((a, b) => b[1].count - a[1].count);
    for (const [title, g] of sorted) {
      lines.push(`- [${g.severity}] ${title} (x${g.count})`);
    }
    lines.push(`\nFirst 5 event details:`);
    for (const e of events.slice(0, 5)) {
      lines.push(`  ${JSON.stringify(e).slice(0, 150)}`);
    }
  }

  return lines.join("\n").slice(0, 12000);
}

// Protocol keyword map for filter matching
const PROTOCOL_KEYWORDS: Record<string, string[]> = {
  tcp:   ["tcp", "FlowTCP"],
  udp:   ["udp", "FlowUDP"],
  dns:   ["dns", "FlowDNS"],
  rtp:   ["rtp", "FlowRTP"],
  sip:   ["sip", "FlowSIP"],
  http2: ["http2", "FlowHTTP2", "FlowSBI", "sbi"],
  pfcp:  ["pfcp", "FlowPFCP"],
  gtp:   ["gtp", "FlowGTP", "FlowGTPU", "gtpu", "gtpc"],
};

// Build a deep-dive context focused on a specific protocol or events
function buildFilteredContext(filter: string, flows: any[], events: any[], jobId: number): string {
  if (filter === "all") return buildPcapSummary(jobId, flows, events);

  if (filter === "events") {
    const lines = [`=== Events Deep Dive — Job #${jobId} (${events.length} total) ===`];
    const groups: Record<string, any[]> = {};
    for (const e of events) {
      const key = e.title ?? e.type ?? "unknown";
      if (!groups[key]) groups[key] = [];
      groups[key].push(e);
    }
    for (const [title, evts] of Object.entries(groups).sort((a, b) => b[1].length - a[1].length)) {
      lines.push(`\n[${evts[0].severity ?? "info"}] ${title} — ${evts.length} occurrences`);
      for (const e of evts.slice(0, 8)) {
        lines.push(`  ${JSON.stringify(e).slice(0, 200)}`);
      }
    }
    return lines.join("\n").slice(0, 12000);
  }

  const keywords = PROTOCOL_KEYWORDS[filter] ?? [filter];
  const filtered = flows.filter(f => {
    const t = (f.type ?? f.protocol ?? "").toLowerCase();
    return keywords.some(k => t.includes(k.toLowerCase()));
  });
  const filtEvents = events.filter(e => {
    const t = (e.type ?? e.title ?? e.message ?? "").toLowerCase();
    return keywords.some(k => t.includes(k.toLowerCase()));
  });

  const lines = [`=== ${filter.toUpperCase()} Deep Dive — Job #${jobId} ===`];
  lines.push(`Matching flows: ${filtered.length} of ${flows.length} total`);

  if (filtered.length === 0) {
    lines.push("No flows found for this protocol.");
    if (filtEvents.length > 0) {
      lines.push(`\n${filtEvents.length} events related to this protocol:`);
      for (const e of filtEvents.slice(0, 20)) {
        lines.push(`- [${e.severity ?? "info"}] ${e.title ?? e.message ?? JSON.stringify(e).slice(0, 150)}`);
      }
    }
    return lines.join("\n");
  }

  // Top IPs for this protocol
  const srcCount: Record<string, number> = {};
  const dstCount: Record<string, number> = {};
  for (const f of filtered) {
    if (f.src_ip) srcCount[f.src_ip] = (srcCount[f.src_ip] ?? 0) + 1;
    if (f.dst_ip) dstCount[f.dst_ip] = (dstCount[f.dst_ip] ?? 0) + 1;
  }
  const topSrc = Object.entries(srcCount).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const topDst = Object.entries(dstCount).sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (topSrc.length) lines.push("Top sources: " + topSrc.map(([ip, n]) => `${ip}(${n})`).join(", "));
  if (topDst.length) lines.push("Top dests:   " + topDst.map(([ip, n]) => `${ip}(${n})`).join(", "));

  // Up to 20 detailed flow samples
  lines.push(`\n=== Flow samples (up to 20) ===`);
  for (const f of filtered.slice(0, 20)) {
    const metrics = f.metrics ? " | " + Object.entries(f.metrics)
      .filter(([, v]) => v !== null && v !== "" && v !== 0)
      .slice(0, 8)
      .map(([k, v]) => `${k}=${v}`).join(", ") : "";
    lines.push(`${f.src_ip}:${f.src_port} → ${f.dst_ip}:${f.dst_port}${metrics}`);
  }

  // All related events
  if (filtEvents.length > 0) {
    lines.push(`\n=== ${filter.toUpperCase()} Events (${filtEvents.length}) ===`);
    for (const e of filtEvents.slice(0, 30)) {
      lines.push(`- [${e.severity ?? "info"}] ${e.title ?? e.message ?? JSON.stringify(e).slice(0, 150)}`);
    }
  }

  return lines.join("\n").slice(0, 12000);
}

// Detect protocol keywords in a user message for smart context injection
function detectContextFilter(text: string): string | null {
  const lower = text.toLowerCase();
  if (/\btcp\b|syn.?flood|rst\b|retransmit|handshake/.test(lower)) return "tcp";
  if (/\budp\b/.test(lower)) return "udp";
  if (/\bdns\b|domain.name|lookup|resolv|nxdomain/.test(lower)) return "dns";
  if (/\brtp\b|media.stream|jitter|mos\b/.test(lower)) return "rtp";
  if (/\bsip\b|voip|call.trace|invite\b/.test(lower)) return "sip";
  if (/http.?2|sbi\b|amf\b|smf\b|nrf\b|nf.regist/.test(lower)) return "http2";
  if (/\bpfcp\b|session.establish|pdr\b|far\b/.test(lower)) return "pfcp";
  if (/\bgtp/.test(lower)) return "gtp";
  if (/event|alert|detect|anomal|attack/.test(lower)) return "events";
  return null;
}

// Filter pills config
const FILTER_PILLS = [
  { key: "all",    label: "Overview" },
  { key: "tcp",    label: "TCP" },
  { key: "udp",    label: "UDP" },
  { key: "dns",    label: "DNS" },
  { key: "http2",  label: "HTTP/2" },
  { key: "rtp",    label: "RTP" },
  { key: "sip",    label: "SIP" },
  { key: "pfcp",   label: "PFCP" },
  { key: "gtp",    label: "GTP" },
  { key: "events", label: "Events" },
];

function getFilterCount(key: string, flows: any[], events: any[]): number {
  if (key === "all") return flows.length;
  if (key === "events") return events.length;
  const keywords = PROTOCOL_KEYWORDS[key] ?? [key];
  return flows.filter(f => {
    const t = (f.type ?? f.protocol ?? "").toLowerCase();
    return keywords.some(k => t.includes(k.toLowerCase()));
  }).length;
}

export default function ChatPage() {
  const location = useLocation();
  const captureState = location.state as {
    packets?: object[];
    alerts?: object[];
    jobId?: number;
    jobName?: string;
  } | null;

  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConv, setActiveConv] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [streamingText, setStreamingText] = useState("");
  const [providers, setProviders] = useState<string[]>([]);
  const [activeProvider, setActiveProviderState] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [livePackets, setLivePackets] = useState<object[]>([]);
  const [useLiveContext, setUseLiveContext] = useState(false);

  // Cached data for smart context injection
  const [cachedFlows, setCachedFlows] = useState<any[]>([]);
  const [cachedEvents, setCachedEvents] = useState<any[]>([]);
  const [currentJobId, setCurrentJobId] = useState<number | null>(null);
  const [activeFilter, setActiveFilter] = useState<string>("all");

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const sendingRef = useRef(false);
  const streamingTextRef = useRef("");
  const captureContextSentRef = useRef(false);

  const { connected: wsConnected } = useWebSocket({
    onMessage: (msg) => {
      if (msg.type === "packet") {
        setLivePackets((prev) => [...prev.slice(-49), msg.payload]);
      }
    },
  });

  useEffect(() => {
    fetchConversations().then(setConversations).catch(() => {});
    fetchProviders()
      .then((data) => {
        setProviders(data.providers || []);
        setActiveProviderState(data.active || "");
      })
      .catch(() => {});
  }, []);

  // Auto-create conversation when navigated from capture page or job detail page
  useEffect(() => {
    if (!captureState?.jobId || captureContextSentRef.current) return;
    captureContextSentRef.current = true;

    const autoStart = async () => {
      try {
        const jobId = captureState.jobId!;
        const label = captureState.jobName
          ? captureState.jobName.replace(/^live-capture:/, "")
          : `Job #${jobId}`;
        const conv = await createConversation(`Analysis: ${label}`);
        setConversations((prev) => [conv, ...prev]);
        setActiveConv(conv.id);
        setMessages([]);

        let flows: any[] = [];
        let events: any[] = [];

        if ((captureState.packets ?? []).length === 0) {
          const [eventsRes, flowsRes] = await Promise.all([
            api.get(`/jobs/${jobId}/events`).then(r => r.data).catch(() => []),
            api.get(`/jobs/${jobId}/flows`).then(r => r.data).catch(() => []),
          ]);
          flows = flowsRes ?? [];
          events = eventsRes ?? [];
        } else {
          flows = captureState.packets ?? [];
          events = captureState.alerts ?? [];
        }

        // Cache for filter buttons and smart context injection
        setCachedFlows(flows);
        setCachedEvents(events);
        setCurrentJobId(jobId);
        setActiveFilter("all");

        const context = buildPcapSummary(jobId, flows, events);
        const question = `Please analyze this network capture (Job #${jobId}) and explain what is happening on the network. Identify any issues, anomalies, or noteworthy patterns.`;

        setMessages([{
          id: Date.now(),
          conversation_id: conv.id,
          role: "user",
          content: question,
          created_at: new Date().toISOString(),
        }]);
        setStreaming(true);
        setStreamingText("");
        streamingTextRef.current = "";

        sendMessageStream(conv.id, question, context,
          (chunk) => { streamingTextRef.current += chunk; setStreamingText(streamingTextRef.current); },
          () => {
            setMessages((prev) => [...prev, {
              id: Date.now() + 1,
              conversation_id: conv.id,
              role: "assistant",
              content: streamingTextRef.current,
              created_at: new Date().toISOString(),
            }]);
            setStreamingText("");
            streamingTextRef.current = "";
            setStreaming(false);
          },
          (err) => {
            setStreaming(false);
            setStreamingText("");
            streamingTextRef.current = "";
            setMessages((prev) => [...prev, {
              id: Date.now() + 1,
              conversation_id: conv.id,
              role: "assistant",
              content: `Error: ${err}`,
              created_at: new Date().toISOString(),
            }]);
          }
        );
      } catch {
        // ignore
      }
    };

    autoStart();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, streamingText]);

  const loadConversation = useCallback(async (id: string) => {
    setActiveConv(id);
    try {
      const data = await fetchConversation(id);
      setMessages(data.messages || []);
    } catch {
      setMessages([]);
    }
  }, []);

  const handleNew = async () => {
    try {
      const conv = await createConversation("New Chat");
      setConversations((prev) => [conv, ...prev]);
      setActiveConv(conv.id);
      setMessages([]);
    } catch {
      // ignore
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteConversation(id);
      setConversations((prev) => prev.filter((c) => c.id !== id));
      if (activeConv === id) {
        setActiveConv(null);
        setMessages([]);
      }
    } catch {
      // ignore
    }
  };

  // Send a message with optional explicit context override
  const doSend = (convId: string, content: string, context?: string) => {
    const userMsg: ChatMessage = {
      id: Date.now(),
      conversation_id: convId,
      role: "user",
      content,
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setStreaming(true);
    setStreamingText("");
    streamingTextRef.current = "";

    abortRef.current = sendMessageStream(
      convId, content, context,
      (chunk) => { streamingTextRef.current += chunk; setStreamingText(streamingTextRef.current); },
      () => {
        setMessages((prev) => [...prev, {
          id: Date.now() + 1,
          conversation_id: convId,
          role: "assistant",
          content: streamingTextRef.current,
          created_at: new Date().toISOString(),
        }]);
        setStreamingText("");
        streamingTextRef.current = "";
        setStreaming(false);
        sendingRef.current = false;
      },
      (err) => {
        setStreaming(false);
        setStreamingText("");
        streamingTextRef.current = "";
        sendingRef.current = false;
        setMessages((prev) => [...prev, {
          id: Date.now() + 1,
          conversation_id: convId,
          role: "assistant",
          content: `Error: ${err}`,
          created_at: new Date().toISOString(),
        }]);
      }
    );
  };

  const handleSend = () => {
    if (!input.trim() || !activeConv || streaming || sendingRef.current) return;
    sendingRef.current = true;
    const userContent = input.trim();
    setInput("");

    // Option 1: Smart keyword detection — inject targeted context if keywords found
    let context: string | undefined;
    if (currentJobId !== null && cachedFlows.length > 0) {
      const detectedFilter = detectContextFilter(userContent);
      if (detectedFilter) {
        context = buildFilteredContext(detectedFilter, cachedFlows, cachedEvents, currentJobId);
      }
    } else if (useLiveContext && livePackets.length > 0) {
      context = buildPcapSummary(0, livePackets.slice(-100), []);
    }

    doSend(activeConv, userContent, context);
  };

  // Option 2: Filter pill clicked — re-analyze with protocol-specific deep dive
  const handleFilterAnalysis = (filter: string) => {
    if (!activeConv || streaming || !currentJobId || cachedFlows.length === 0) return;
    sendingRef.current = true;
    setActiveFilter(filter);

    const label = FILTER_PILLS.find(p => p.key === filter)?.label ?? filter;
    const question = filter === "all"
      ? `Give me a complete overview analysis of this PCAP (Job #${currentJobId}).`
      : filter === "events"
      ? `Analyze all ${cachedEvents.length} detected events/alerts in detail. What attacks or anomalies are present?`
      : `Do a deep dive analysis of all ${label} traffic in this PCAP. What patterns, anomalies, or issues do you see?`;

    const context = buildFilteredContext(filter, cachedFlows, cachedEvents, currentJobId);
    doSend(activeConv, question, context);
  };

  const handleProviderChange = async (provider: string) => {
    try {
      await setActiveProvider(provider);
      setActiveProviderState(provider);
    } catch {
      // ignore
    }
  };

  const hasJobContext = currentJobId !== null && cachedFlows.length > 0;

  return (
    <div className="flex h-full gap-4">
      {/* Sidebar */}
      <div className="w-64 flex-shrink-0 bg-slate-800/80 border border-slate-700/50 rounded-xl flex flex-col overflow-hidden">
        <div className="p-3 border-b border-slate-700/50 flex items-center justify-between">
          <h3 className="text-sm font-medium text-slate-300">Conversations</h3>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setShowSettings(!showSettings)}
              className="p-1.5 text-slate-400 hover:text-white transition-colors"
            >
              <Settings className="w-4 h-4" />
            </button>
            <button
              onClick={handleNew}
              className="p-1.5 text-emerald-400 hover:text-emerald-300 transition-colors"
            >
              <Plus className="w-4 h-4" />
            </button>
          </div>
        </div>

        {showSettings && (
          <div className="p-3 border-b border-slate-700/50">
            <label className="block text-xs text-slate-400 mb-1">AI Provider</label>
            <select
              value={activeProvider}
              onChange={(e) => handleProviderChange(e.target.value)}
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:ring-2 focus:ring-emerald-500"
            >
              {providers.length === 0 && <option value="">No providers configured</option>}
              {providers.map((p) => (
                <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
              ))}
            </select>
          </div>
        )}

        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {conversations.map((conv) => (
            <div
              key={conv.id}
              className={`flex items-center justify-between px-3 py-2 rounded-lg text-sm cursor-pointer transition-colors ${
                activeConv === conv.id
                  ? "bg-slate-700 text-white"
                  : "text-slate-400 hover:bg-slate-700/50 hover:text-white"
              }`}
              onClick={() => loadConversation(conv.id)}
            >
              <span className="truncate flex-1">{conv.title}</span>
              <button
                onClick={(e) => { e.stopPropagation(); handleDelete(conv.id); }}
                className="text-slate-500 hover:text-red-400 transition-colors ml-2"
              >
                <Trash2 className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Chat Area */}
      <div className="flex-1 bg-slate-800/80 border border-slate-700/50 rounded-xl flex flex-col overflow-hidden">
        {!activeConv ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <MessageSquare className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <p className="text-slate-400 text-sm">Select or create a conversation</p>
              <p className="text-slate-500 text-xs mt-1">Ask AI to explain network issues in plain language</p>
              <button
                onClick={handleNew}
                className="mt-4 px-4 py-2 bg-emerald-500/20 border border-emerald-500/30 rounded-lg text-sm text-emerald-400 hover:bg-emerald-500/30 transition-colors"
              >
                New Conversation
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {messages.map((msg) => (
                <div key={msg.id} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                  <div className={`max-w-[75%] rounded-xl px-4 py-2.5 text-sm ${
                    msg.role === "user"
                      ? "bg-emerald-500/20 text-emerald-100 border border-emerald-500/20"
                      : "bg-slate-700/50 text-slate-200 border border-slate-600/30"
                  }`}>
                    <div className="whitespace-pre-wrap">{msg.content}</div>
                  </div>
                </div>
              ))}

              {streaming && streamingText && (
                <div className="flex justify-start">
                  <div className="max-w-[75%] rounded-xl px-4 py-2.5 text-sm bg-slate-700/50 text-slate-200 border border-slate-600/30">
                    <div className="whitespace-pre-wrap">
                      {streamingText}
                      <span className="inline-block w-2 h-4 bg-emerald-400 animate-pulse ml-0.5" />
                    </div>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="border-t border-slate-700/50 p-4">

              {/* Option 2: Protocol filter pills — shown only when job context is loaded */}
              {hasJobContext && (
                <div className="flex items-center gap-1.5 mb-2.5 flex-wrap">
                  <span className="text-xs text-slate-500 mr-1">Deep dive:</span>
                  {FILTER_PILLS.map((pill) => {
                    const count = getFilterCount(pill.key, cachedFlows, cachedEvents);
                    if (count === 0 && pill.key !== "all") return null;
                    return (
                      <button
                        key={pill.key}
                        onClick={() => handleFilterAnalysis(pill.key)}
                        disabled={streaming}
                        className={`px-2.5 py-1 rounded-full text-xs border transition-colors disabled:opacity-40 ${
                          activeFilter === pill.key
                            ? "bg-emerald-500/30 border-emerald-500/60 text-emerald-300"
                            : "bg-slate-700/50 border-slate-600/50 text-slate-400 hover:text-white hover:border-slate-500"
                        }`}
                      >
                        {pill.label}
                        <span className="ml-1 text-slate-500">{count}</span>
                      </button>
                    );
                  })}
                </div>
              )}

              {/* Live context toggle */}
              <div className="flex items-center gap-2 mb-2">
                <button
                  onClick={() => setUseLiveContext((v) => !v)}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs border transition-colors ${
                    useLiveContext
                      ? "bg-emerald-500/20 border-emerald-500/40 text-emerald-400"
                      : "bg-slate-700/50 border-slate-600/50 text-slate-500 hover:text-slate-300"
                  }`}
                >
                  <Radio className="w-3 h-3" />
                  Live context {useLiveContext ? "ON" : "OFF"}
                </button>
                {wsConnected && (
                  <span className="text-xs text-slate-500">{livePackets.length} packets captured</span>
                )}
                {!wsConnected && (
                  <span className="text-xs text-slate-600">WS disconnected</span>
                )}
                {hasJobContext && (
                  <span className="text-xs text-slate-600 ml-auto">
                    Job #{currentJobId} · {cachedFlows.length} flows · {cachedEvents.length} events
                  </span>
                )}
              </div>

              <div className="flex items-center gap-3">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && handleSend()}
                  placeholder={hasJobContext ? "Ask about TCP, DNS, RTP, events… (auto-detects protocol)" : "Ask about packets, protocols, or network issues..."}
                  disabled={streaming}
                  className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 disabled:opacity-50"
                />
                <button
                  onClick={handleSend}
                  disabled={streaming || !input.trim()}
                  className="flex items-center justify-center w-10 h-10 bg-emerald-500/20 border border-emerald-500/30 rounded-lg text-emerald-400 hover:bg-emerald-500/30 transition-colors disabled:opacity-50"
                >
                  <Send className="w-4 h-4" />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
