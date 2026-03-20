package ai

import (
	"context"
	"fmt"
)

// ExplainAlert sends an alert to the LLM for a plain-English explanation.
func ExplainAlert(ctx context.Context, provider LLMProvider, alert AlertSummary) (string, error) {
	prompt := fmt.Sprintf(`Explain this network alert in plain language that a non-expert can understand:

Protocol: %s
Severity: %s
Title: %s
Description: %s

Please explain:
1. What happened (in simple terms)
2. What impact this might have on users or services
3. What likely caused this
4. What the recommended action is

Keep your response concise (3-5 sentences per section).`, alert.Protocol, alert.Severity, alert.Title, alert.Description)

	resp, err := provider.Complete(ctx, CompletionRequest{
		Messages: []Message{
			{Role: "user", Content: prompt},
		},
		MaxTokens: 1024,
	})
	if err != nil {
		return "", err
	}

	return resp.Content, nil
}
