// Package alerting delivers alert notifications to configured targets
// (Slack webhooks, generic HTTP webhooks, and SMTP email).
package alerting

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"DeepPacketAI/internal/storage"
)

// Dispatcher loads alert targets from the store and sends notifications.
type Dispatcher struct {
	store  storage.Store
	client *http.Client
}

// New creates a Dispatcher backed by the given store.
func New(store storage.Store) *Dispatcher {
	return &Dispatcher{
		store: store,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// severityLevel returns a numeric rank for severity comparison.
func severityLevel(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	default:
		return 1 // info
	}
}

// Dispatch sends notifications for each event that meets the target's
// minimum severity threshold. It loads targets fresh from the store on
// every call so configuration changes take effect immediately.
func (d *Dispatcher) Dispatch(ctx context.Context, events []storage.EventRecord) {
	if len(events) == 0 {
		return
	}

	targets, err := d.store.ListAlertTargets()
	if err != nil {
		log.Printf("alerting: failed to load targets: %v", err)
		return
	}

	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		// Filter events that meet the minimum severity
		var matching []storage.EventRecord
		minLevel := severityLevel(t.MinSeverity)
		for _, e := range events {
			if severityLevel(e.Severity) >= minLevel {
				matching = append(matching, e)
			}
		}
		if len(matching) == 0 {
			continue
		}

		go func(target storage.AlertTarget, evts []storage.EventRecord) {
			var sendErr error
			switch target.Type {
			case "slack":
				sendErr = d.sendSlack(ctx, target, evts)
			case "webhook":
				sendErr = d.sendWebhook(ctx, target, evts)
			case "email":
				sendErr = d.sendEmail(ctx, target, evts)
			}
			if sendErr != nil {
				log.Printf("alerting: target %q (%s) error: %v", target.Name, target.Type, sendErr)
			} else {
				log.Printf("alerting: sent %d event(s) to %q (%s)", len(evts), target.Name, target.Type)
			}
		}(t, matching)
	}
}

// ── Slack ────────────────────────────────────────────────────────────────────

func (d *Dispatcher) sendSlack(ctx context.Context, t storage.AlertTarget, events []storage.EventRecord) error {
	if t.URL == "" {
		return fmt.Errorf("slack target %q has no webhook URL", t.Name)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*DeepPacketAI Alert* — %d event(s)\n", len(events)))
	for _, e := range events {
		sb.WriteString(fmt.Sprintf("• [%s] *%s* (%s): %s\n", strings.ToUpper(e.Severity), e.Title, e.Protocol, e.Description))
	}

	payload := map[string]string{"text": sb.String()}
	return d.postJSON(ctx, t.URL, payload)
}

// ── Generic Webhook ──────────────────────────────────────────────────────────

// WebhookPayload is the JSON body sent to a generic webhook target.
type WebhookPayload struct {
	Source    string               `json:"source"`
	Timestamp string               `json:"timestamp"`
	Events    []storage.EventRecord `json:"events"`
}

func (d *Dispatcher) sendWebhook(ctx context.Context, t storage.AlertTarget, events []storage.EventRecord) error {
	if t.URL == "" {
		return fmt.Errorf("webhook target %q has no URL", t.Name)
	}

	payload := WebhookPayload{
		Source:    "DeepPacketAI",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Events:    events,
	}

	// Parse optional extra headers from config_json: {"headers": {"X-Token": "abc"}}
	var cfg struct {
		Headers map[string]string `json:"headers"`
	}
	if t.ConfigJSON != "" && t.ConfigJSON != "{}" {
		_ = json.Unmarshal([]byte(t.ConfigJSON), &cfg)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── Email / SMTP ─────────────────────────────────────────────────────────────

// EmailConfig holds SMTP configuration parsed from alert_targets.config_json.
type EmailConfig struct {
	Host     string `json:"smtp_host"`
	Port     int    `json:"smtp_port"` // 587 (STARTTLS) or 465 (TLS)
	Username string `json:"smtp_user"`
	Password string `json:"smtp_pass"`
	From     string `json:"from"`
	To       string `json:"to"` // comma-separated list
}

func (d *Dispatcher) sendEmail(_ context.Context, t storage.AlertTarget, events []storage.EventRecord) error {
	var cfg EmailConfig
	if err := json.Unmarshal([]byte(t.ConfigJSON), &cfg); err != nil {
		return fmt.Errorf("email config parse: %w", err)
	}
	if cfg.Host == "" || cfg.From == "" || cfg.To == "" {
		return fmt.Errorf("email target %q missing smtp_host/from/to in config_json", t.Name)
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}

	var body strings.Builder
	body.WriteString(fmt.Sprintf("DeepPacketAI detected %d alert(s):\r\n\r\n", len(events)))
	for _, e := range events {
		body.WriteString(fmt.Sprintf("[%s] %s (%s)\r\n%s\r\n\r\n",
			strings.ToUpper(e.Severity), e.Title, e.Protocol, e.Description))
	}

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: DeepPacketAI Alert — %d event(s)\r\n\r\n%s",
		cfg.From, cfg.To, len(events), body.String(),
	)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)

	if cfg.Port == 465 {
		// Implicit TLS
		tlsConf := &tls.Config{ServerName: cfg.Host}
		conn, err := tls.Dial("tcp", addr, tlsConf)
		if err != nil {
			return err
		}
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return err
		}
		defer client.Close()
		if err := client.Auth(auth); err != nil {
			return err
		}
		if err := client.Mail(cfg.From); err != nil {
			return err
		}
		for _, to := range strings.Split(cfg.To, ",") {
			to = strings.TrimSpace(to)
			if err := client.Rcpt(to); err != nil {
				return err
			}
		}
		w, err := client.Data()
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(w, msg)
		w.Close()
		return err
	}

	// STARTTLS (port 587) or plain (port 25)
	return smtp.SendMail(addr, auth, cfg.From, strings.Split(cfg.To, ","), []byte(msg))
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (d *Dispatcher) postJSON(ctx context.Context, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return nil
}
