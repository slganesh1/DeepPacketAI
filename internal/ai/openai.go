package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// OpenAIProvider implements LLMProvider for OpenAI.
type OpenAIProvider struct {
	apiKey string
	model  string
}

func NewOpenAIProvider(apiKey, model string) *OpenAIProvider {
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if model == "" {
		model = "gpt-4o"
	}
	return &OpenAIProvider{apiKey: apiKey, model: model}
}

func (p *OpenAIProvider) Name() string { return "openai" }

func (p *OpenAIProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	model := req.Model
	if model == "" {
		model = p.model
	}

	messages := buildOpenAIMessages(req)

	body := map[string]any{
		"model":    model,
		"messages": messages,
	}
	if req.MaxTokens > 0 {
		body["max_tokens"] = req.MaxTokens
	}

	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("openai API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	content := ""
	if len(result.Choices) > 0 {
		content = result.Choices[0].Message.Content
	}

	return &CompletionResponse{
		Content: content,
		Model:   result.Model,
		Usage:   Usage{InputTokens: result.Usage.PromptTokens, OutputTokens: result.Usage.CompletionTokens},
	}, nil
}

func (p *OpenAIProvider) Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error) {
	model := req.Model
	if model == "" {
		model = p.model
	}

	messages := buildOpenAIMessages(req)

	body := map[string]any{
		"model":    model,
		"messages": messages,
		"stream":   true,
	}

	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("openai API error %d: %s", resp.StatusCode, string(respBody))
	}

	ch := make(chan StreamChunk, 100)
	go func() {
		defer resp.Body.Close()
		defer close(ch)
		parseOpenAISSE(resp.Body, ch)
	}()

	return ch, nil
}

func buildOpenAIMessages(req CompletionRequest) []map[string]string {
	var messages []map[string]string

	systemPrompt := req.SystemPrompt
	if systemPrompt == "" {
		systemPrompt = DefaultSystemPrompt
	}
	messages = append(messages, map[string]string{"role": "system", "content": systemPrompt})

	for _, m := range req.Messages {
		if m.Role == "system" {
			continue
		}
		messages = append(messages, map[string]string{"role": m.Role, "content": m.Content})
	}

	return messages
}

func parseOpenAISSE(body io.Reader, ch chan<- StreamChunk) {
	data := make([]byte, 4096)
	remaining := ""

	for {
		n, err := body.Read(data)
		if n > 0 {
			remaining += string(data[:n])

			for {
				idx := indexOf(remaining, "\n")
				if idx == -1 {
					break
				}
				line := remaining[:idx]
				remaining = remaining[idx+1:]

				if len(line) > 6 && line[:6] == "data: " {
					jsonData := line[6:]
					if jsonData == "[DONE]" {
						ch <- StreamChunk{Done: true}
						return
					}

					var event struct {
						Choices []struct {
							Delta struct {
								Content string `json:"content"`
							} `json:"delta"`
						} `json:"choices"`
					}

					if json.Unmarshal([]byte(jsonData), &event) == nil {
						if len(event.Choices) > 0 && event.Choices[0].Delta.Content != "" {
							ch <- StreamChunk{Content: event.Choices[0].Delta.Content}
						}
					}
				}
			}
		}

		if err != nil {
			if err != io.EOF {
				ch <- StreamChunk{Error: err, Done: true}
			} else {
				ch <- StreamChunk{Done: true}
			}
			return
		}
	}
}
