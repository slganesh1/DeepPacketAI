import { useState, useEffect, useRef, useCallback } from "react";
import { MessageSquare, Send, Plus, Trash2, Settings } from "lucide-react";
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

export default function ChatPage() {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConv, setActiveConv] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [streamingText, setStreamingText] = useState("");
  const [providers, setProviders] = useState<string[]>([]);
  const [activeProvider, setActiveProviderState] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const sendingRef = useRef(false);
  const streamingTextRef = useRef("");

  useEffect(() => {
    fetchConversations().then(setConversations).catch(() => {});
    fetchProviders()
      .then((data) => {
        setProviders(data.providers || []);
        setActiveProviderState(data.active || "");
      })
      .catch(() => {});
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

  const handleSend = () => {
    if (!input.trim() || !activeConv || streaming || sendingRef.current) return;
    sendingRef.current = true;

    const userContent = input.trim();
    setInput("");

    // Add user message to UI immediately
    const userMsg: ChatMessage = {
      id: Date.now(),
      conversation_id: activeConv,
      role: "user",
      content: userContent,
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setStreaming(true);
    setStreamingText("");
    streamingTextRef.current = "";

    abortRef.current = sendMessageStream(
      activeConv,
      userContent,
      undefined,
      (chunk) => {
        streamingTextRef.current += chunk;
        setStreamingText(streamingTextRef.current);
      },
      () => {
        // Use ref to get final text — avoids nesting setMessages inside setStreamingText
        const finalText = streamingTextRef.current;
        const assistantMsg: ChatMessage = {
          id: Date.now() + 1,
          conversation_id: activeConv!,
          role: "assistant",
          content: finalText,
          created_at: new Date().toISOString(),
        };
        setMessages((prev) => [...prev, assistantMsg]);
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
        const errMsg: ChatMessage = {
          id: Date.now() + 1,
          conversation_id: activeConv!,
          role: "assistant",
          content: `Error: ${err}`,
          created_at: new Date().toISOString(),
        };
        setMessages((prev) => [...prev, errMsg]);
      }
    );
  };

  const handleProviderChange = async (provider: string) => {
    try {
      await setActiveProvider(provider);
      setActiveProviderState(provider);
    } catch {
      // ignore
    }
  };

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
            <label className="block text-xs text-slate-400 mb-1">
              AI Provider
            </label>
            <select
              value={activeProvider}
              onChange={(e) => handleProviderChange(e.target.value)}
              className="w-full bg-slate-700 border border-slate-600 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:ring-2 focus:ring-emerald-500"
            >
              {providers.length === 0 && (
                <option value="">No providers configured</option>
              )}
              {providers.map((p) => (
                <option key={p} value={p}>
                  {p.charAt(0).toUpperCase() + p.slice(1)}
                </option>
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
                onClick={(e) => {
                  e.stopPropagation();
                  handleDelete(conv.id);
                }}
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
              <p className="text-slate-400 text-sm">
                Select or create a conversation
              </p>
              <p className="text-slate-500 text-xs mt-1">
                Ask AI to explain network issues in plain language
              </p>
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
                <div
                  key={msg.id}
                  className={`flex ${
                    msg.role === "user" ? "justify-end" : "justify-start"
                  }`}
                >
                  <div
                    className={`max-w-[75%] rounded-xl px-4 py-2.5 text-sm ${
                      msg.role === "user"
                        ? "bg-emerald-500/20 text-emerald-100 border border-emerald-500/20"
                        : "bg-slate-700/50 text-slate-200 border border-slate-600/30"
                    }`}
                  >
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
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && handleSend()}
                  placeholder="Ask about packets, protocols, or network issues..."
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
