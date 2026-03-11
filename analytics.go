package main

import (
	"fmt"
	"log/slog"

	analytics "github.com/rudderlabs/analytics-go"
)

// Tracker wraps the RudderStack analytics client with domain-specific tracking
// methods. A zero-value Tracker (client == nil) silently no-ops all calls.
type Tracker struct {
	client analytics.Client
}

// newTracker creates a Tracker from config.
// If RUDDER_WRITE_KEY is unset, a no-op Tracker is returned.
func newTracker(cfg Config, logger *slog.Logger) (*Tracker, error) {
	if cfg.RudderWriteKey == "" {
		return &Tracker{}, nil
	}
	client, err := analytics.NewWithConfig(cfg.RudderWriteKey, analytics.Config{
		DataPlaneUrl: cfg.RudderDataPlaneURL,
		Logger:       &rudderLogger{log: logger},
	})
	if err != nil {
		return nil, fmt.Errorf("analytics client: %w", err)
	}
	return &Tracker{client: client}, nil
}

func (t *Tracker) enabled() bool {
	return t != nil && t.client != nil
}

// Close flushes buffered events and shuts down the analytics client.
func (t *Tracker) Close() {
	if t.enabled() {
		_ = t.client.Close()
	}
}

// TokenMinted records a successful token mint.
func (t *Tracker) TokenMinted(ip, providerID string, ttlSeconds int64, audienceCount, extraClaimCount int) {
	if !t.enabled() {
		return
	}
	_ = t.client.Enqueue(analytics.Track{
		AnonymousId: ip,
		Event:       "Token Minted",
		Properties: analytics.NewProperties().
			Set("provider", providerID).
			Set("ttl_seconds", ttlSeconds).
			Set("audience_count", audienceCount).
			Set("extra_claim_count", extraClaimCount),
	})
}

// TokenMintFailed records a failed token mint attempt.
func (t *Tracker) TokenMintFailed(ip, providerID, reason string) {
	if !t.enabled() {
		return
	}
	_ = t.client.Enqueue(analytics.Track{
		AnonymousId: ip,
		Event:       "Token Mint Failed",
		Properties: analytics.NewProperties().
			Set("provider", providerID).
			Set("reason", reason),
	})
}

// TokenReviewed records a token review outcome (authenticated or not).
func (t *Tracker) TokenReviewed(ip, providerID string, authenticated bool) {
	if !t.enabled() {
		return
	}
	_ = t.client.Enqueue(analytics.Track{
		AnonymousId: ip,
		Event:       "Token Reviewed",
		Properties: analytics.NewProperties().
			Set("provider", providerID).
			Set("authenticated", authenticated),
	})
}

// TokenReviewFailed records a processing error during token review.
// This is distinct from an unauthenticated result — use TokenReviewed for those.
func (t *Tracker) TokenReviewFailed(ip, providerID, reason string) {
	if !t.enabled() {
		return
	}
	_ = t.client.Enqueue(analytics.Track{
		AnonymousId: ip,
		Event:       "Token Review Failed",
		Properties: analytics.NewProperties().
			Set("provider", providerID).
			Set("reason", reason),
	})
}

// RateLimitExceeded records when a request is rejected by the rate limiter.
func (t *Tracker) RateLimitExceeded(ip, method, path string) {
	if !t.enabled() {
		return
	}
	_ = t.client.Enqueue(analytics.Track{
		AnonymousId: ip,
		Event:       "Rate Limit Exceeded",
		Properties: analytics.NewProperties().
			Set("method", method).
			Set("path", path),
	})
}

// rudderLogger adapts slog.Logger to the analytics.Logger interface.
type rudderLogger struct {
	log *slog.Logger
}

func (l *rudderLogger) Logf(format string, args ...interface{}) {
	l.log.Debug(fmt.Sprintf(format, args...))
}

func (l *rudderLogger) Errorf(format string, args ...interface{}) {
	l.log.Error(fmt.Sprintf(format, args...))
}
