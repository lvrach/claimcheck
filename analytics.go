package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Analytics is a fire-and-forget RudderStack HTTP client.
// All Track calls are non-blocking and discard errors so that telemetry
// never blocks or degrades the request path.
// A nil *Analytics is safe to use — all methods are no-ops when nil.
type Analytics struct {
	writeKey     string
	dataPlaneURL string
	client       *http.Client
	logger       *slog.Logger
}

// newAnalytics returns a configured Analytics client, or nil if either
// writeKey or dataPlaneURL is empty (analytics is opt-in via env vars).
func newAnalytics(writeKey, dataPlaneURL string, logger *slog.Logger) *Analytics {
	if writeKey == "" || dataPlaneURL == "" {
		return nil
	}
	return &Analytics{
		writeKey:     writeKey,
		dataPlaneURL: strings.TrimRight(dataPlaneURL, "/"),
		client:       &http.Client{Timeout: 5 * time.Second},
		logger:       logger,
	}
}

type trackPayload struct {
	AnonymousID string         `json:"anonymousId"`
	Event       string         `json:"event"`
	Properties  map[string]any `json:"properties,omitempty"`
	SentAt      time.Time      `json:"sentAt"`
}

// Track enqueues a RudderStack track event in a goroutine.
// It is safe to call on a nil *Analytics (no-op).
func (a *Analytics) Track(anonymousID, event string, properties map[string]any) {
	if a == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		body, err := json.Marshal(trackPayload{
			AnonymousID: anonymousID,
			Event:       event,
			Properties:  properties,
			SentAt:      time.Now().UTC(),
		})
		if err != nil {
			a.logger.Warn("analytics: marshal failed", "error", err)
			return
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.dataPlaneURL+"/v1/track", bytes.NewReader(body))
		if err != nil {
			a.logger.Warn("analytics: build request failed", "error", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(a.writeKey+":")))

		resp, err := a.client.Do(req)
		if err != nil {
			a.logger.Warn("analytics: send failed", "error", err)
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			a.logger.Warn("analytics: unexpected status", "status", resp.StatusCode, "event", event)
		}
	}()
}
