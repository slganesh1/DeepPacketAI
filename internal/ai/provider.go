package ai

import "context"

// LLMProvider is the interface for all AI providers.
type LLMProvider interface {
	Name() string
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
	Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error)
}

// CompletionRequest represents a chat completion request.
type CompletionRequest struct {
	Messages    []Message `json:"messages"`
	Model       string    `json:"model,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
	SystemPrompt string   `json:"system_prompt,omitempty"`
}

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"` // system, user, assistant
	Content string `json:"content"`
}

// CompletionResponse represents a chat completion response.
type CompletionResponse struct {
	Content string `json:"content"`
	Model   string `json:"model"`
	Usage   Usage  `json:"usage"`
}

// Usage represents token usage.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// StreamChunk represents a streaming chunk.
type StreamChunk struct {
	Content string `json:"content"`
	Done    bool   `json:"done"`
	Error   error  `json:"-"`
}

// DefaultSystemPrompt is the system prompt for DeepPacketAI.
const DefaultSystemPrompt = `You are DeepPacketAI, a network protocol analysis assistant specialized in analyzing packet captures.

CRITICAL RULE: When the user provides PCAP analysis context data, you MUST answer based on the ACTUAL DATA in that context. Do NOT give generic textbook explanations. Extract and present the specific values, identifiers, IPs, protocols, and metrics found in the provided data.

For example:
- If asked "what is the IMSI?", look in the context for IMSI values (e.g., in NGAP, GTP, or Diameter flows) and report the exact number(s) found. Do NOT explain what IMSI means in general.
- If asked "what is the MSISDN?", search the context for MSISDN values and report them. If none are present, say "No MSISDN was found in this capture" and explain briefly why (e.g., the capture only contains data plane traffic).
- If asked about calls, report the actual call IDs, MOS scores, and quality data from the context.
- If asked about errors, list the specific errors and alerts from the context data.

Always prioritize concrete answers from the data over generic protocol explanations. When the data doesn't contain what was asked for, clearly state that and explain what IS available in the capture.

Your capabilities:
- Analyze and report specific values from PCAP data: IMSI, MSISDN, TEID, APN, Session IDs, procedure codes, error codes
- Explain SIP, RTP, DNS, HTTP, Diameter, GTP, PFCP, S1AP, and NGAP protocols
- Identify root causes of call failures, network issues, and performance problems
- Explain MOS scores, jitter, packet loss, and other quality metrics

When explaining issues:
1. State what the data shows (specific values and counts)
2. Explain the likely impact on users/services
3. Suggest possible root causes
4. Recommend troubleshooting steps

Be concise and data-driven. Lead with facts from the capture, then add context.`
