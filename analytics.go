package main

import (
	"log/slog"
	"time"

	analytics "github.com/rudderlabs/analytics-go/v4"
)

// Analytics wraps the RudderStack Go SDK client.
// A nil *Analytics is safe to use — all methods are no-ops when nil.
type Analytics struct {
	client analytics.Client
	logger *slog.Logger
}

// newAnalytics returns a configured Analytics client, or nil if either
// writeKey or dataPlaneURL is empty (analytics is opt-in via env vars).
func newAnalytics(writeKey, dataPlaneURL string, logger *slog.Logger) *Analytics {
	if writeKey == "" || dataPlaneURL == "" {
		return nil
	}
	client, err := analytics.NewWithConfig(writeKey, analytics.Config{
		DataPlaneUrl: dataPlaneURL,
		Interval:     5 * time.Second,
		BatchSize:    100,
	})
	if err != nil {
		logger.Warn("analytics: failed to create client", "error", err)
		return nil
	}
	return &Analytics{client: client, logger: logger}
}

// Track enqueues a RudderStack track event.
// It is safe to call on a nil *Analytics (no-op).
func (a *Analytics) Track(anonymousID, event string, properties map[string]any) {
	if a == nil {
		return
	}
	props := analytics.NewProperties()
	for k, v := range properties {
		props.Set(k, v)
	}
	if err := a.client.Enqueue(analytics.Track{
		AnonymousId: anonymousID,
		Event:       event,
		Properties:  props,
	}); err != nil {
		a.logger.Warn("analytics: enqueue failed", "error", err)
	}
}

// Close flushes any buffered events and shuts down the SDK client.
// It is safe to call on a nil *Analytics (no-op).
func (a *Analytics) Close() {
	if a == nil {
		return
	}
	if err := a.client.Close(); err != nil {
		a.logger.Warn("analytics: close failed", "error", err)
	}
}
