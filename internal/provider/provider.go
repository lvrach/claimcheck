// Package provider defines the TokenProvider interface and shared types
// for token minting and review operations.
package provider

import (
	"context"
	"errors"
	"time"
)

// ErrUnauthenticatedToken is returned when a token fails authentication.
var ErrUnauthenticatedToken = errors.New("unauthenticated token")

// MintInput contains the parameters for minting a new token.
type MintInput struct {
	Namespace         string         `json:"namespace"`
	ServiceAccount    string         `json:"serviceAccount"`
	Audiences         []string       `json:"audiences"`
	ExpirationSeconds int64          `json:"expirationSeconds"`
	ExtraClaims       map[string]any `json:"extraClaims"`
}

// MintOutput contains the result of a token minting operation.
type MintOutput struct {
	Token               string    `json:"token"`
	ExpirationTimestamp time.Time `json:"expirationTimestamp"`
}

// ReviewInput contains the parameters for reviewing a token.
type ReviewInput struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences"`
}

// ReviewOutput contains the result of a token review operation.
type ReviewOutput struct {
	Authenticated bool                `json:"authenticated"`
	Username      string              `json:"username,omitempty"`
	UID           string              `json:"uid,omitempty"`
	Groups        []string            `json:"groups,omitempty"`
	Extra         map[string][]string `json:"extra,omitempty"`
	Claims        map[string]any      `json:"claims,omitempty"`
	Error         string              `json:"error,omitempty"`
}

// Schema describes a provider's capabilities and request format.
type Schema struct {
	Provider    string         `json:"provider"`
	DisplayName string         `json:"displayName"`
	Description string         `json:"description"`
	Fields      []SchemaField  `json:"fields"`
	MintJSON    map[string]any `json:"mintRequest"`
	ReviewJSON  map[string]any `json:"reviewRequest"`
	Limits      map[string]any `json:"limits"`
}

// SchemaField describes a single field in a provider schema.
type SchemaField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Default     any    `json:"default,omitempty"`
	Example     any    `json:"example,omitempty"`
}

// TokenProvider defines the interface for token minting and review providers.
type TokenProvider interface {
	ID() string
	Description() string
	Mint(ctx context.Context, in MintInput) (MintOutput, error)
	Review(ctx context.Context, in ReviewInput) (ReviewOutput, error)
	Schema() Schema
}
