// Package main provides an extensible token testing web service.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var errUnauthenticatedToken = errors.New("unauthenticated token")

type MintInput struct {
	Namespace         string         `json:"namespace"`
	ServiceAccount    string         `json:"serviceAccount"`
	Audiences         []string       `json:"audiences"`
	ExpirationSeconds int64          `json:"expirationSeconds"`
	ExtraClaims       map[string]any `json:"extraClaims"`
}

type MintOutput struct {
	Token               string    `json:"token"`
	ExpirationTimestamp time.Time `json:"expirationTimestamp"`
}

type ReviewInput struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences"`
}

type ReviewOutput struct {
	Authenticated bool                `json:"authenticated"`
	Username      string              `json:"username,omitempty"`
	UID           string              `json:"uid,omitempty"`
	Groups        []string            `json:"groups,omitempty"`
	Extra         map[string][]string `json:"extra,omitempty"`
	Claims        map[string]any      `json:"claims,omitempty"`
	Error         string              `json:"error,omitempty"`
}

type ProviderSchema struct {
	Provider    string         `json:"provider"`
	DisplayName string         `json:"displayName"`
	Description string         `json:"description"`
	Fields      []SchemaField  `json:"fields"`
	MintJSON    map[string]any `json:"mintRequest"`
	ReviewJSON  map[string]any `json:"reviewRequest"`
	Limits      map[string]any `json:"limits"`
}

type SchemaField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Default     any    `json:"default,omitempty"`
	Example     any    `json:"example,omitempty"`
}

type TokenProvider interface {
	ID() string
	Description() string
	Mint(ctx context.Context, in MintInput) (MintOutput, error)
	Review(ctx context.Context, in ReviewInput) (ReviewOutput, error)
	Schema() ProviderSchema
}

type K8sSAProvider struct {
	cfg  Config
	keys KeyMaterial
}

func NewK8sSAProvider(cfg Config, keys KeyMaterial) *K8sSAProvider {
	return &K8sSAProvider{cfg: cfg, keys: keys}
}

func (p *K8sSAProvider) ID() string { return "k8s-sa" }

func (p *K8sSAProvider) Description() string {
	return "High-fidelity Kubernetes service account token provider"
}

func (p *K8sSAProvider) Schema() ProviderSchema {
	return ProviderSchema{
		Provider:    p.ID(),
		DisplayName: "Kubernetes Service Account",
		Description: p.Description(),
		Fields: []SchemaField{
			{
				Name:        "namespace",
				Type:        "string",
				Required:    true,
				Description: "Kubernetes namespace for the service account.",
				Example:     "default",
			},
			{
				Name:        "serviceAccount",
				Type:        "string",
				Required:    true,
				Description: "Service account name.",
				Example:     "build-bot",
			},
			{
				Name:        "audiences",
				Type:        "string_array",
				Required:    false,
				Description: "Token audiences.",
				Default:     []string{p.cfg.DefaultAudience},
			},
			{
				Name:        "expirationSeconds",
				Type:        "integer",
				Required:    false,
				Description: "Requested token TTL in seconds.",
				Default:     int(p.cfg.MaxTTL.Seconds()),
			},
			{
				Name:        "extraClaims",
				Type:        "object",
				Required:    false,
				Description: "Additional custom claims as JSON object.",
				Default:     map[string]any{},
			},
		},
		MintJSON: map[string]any{
			"namespace":         "string (required)",
			"serviceAccount":    "string (required)",
			"audiences":         []string{"string"},
			"expirationSeconds": "integer",
			"extraClaims":       map[string]any{"extra.example": "value"},
		},
		ReviewJSON: map[string]any{
			"token":     "string (required)",
			"audiences": []string{"string"},
		},
		Limits: map[string]any{
			"minTTLSeconds":  int(p.cfg.MinTTL.Seconds()),
			"maxTTLSeconds":  int(p.cfg.MaxTTL.Seconds()),
			"maxClaimFields": p.cfg.MaxClaimFields,
			"maxClaimDepth":  p.cfg.MaxClaimDepth,
		},
	}
}

func (p *K8sSAProvider) Mint(_ context.Context, in MintInput) (MintOutput, error) {
	if in.Namespace == "" || in.ServiceAccount == "" {
		return MintOutput{}, errors.New("namespace and serviceAccount are required")
	}
	if err := validateClaims(in.ExtraClaims, p.cfg.MaxClaimFields, p.cfg.MaxClaimDepth, p.cfg.MaxClaimValueBytes); err != nil {
		return MintOutput{}, err
	}
	forbidden := []string{"iss", "iat", "exp", "nbf", "sub", "jti", "aud"}
	for _, k := range forbidden {
		if _, ok := in.ExtraClaims[k]; ok {
			return MintOutput{}, fmt.Errorf("extraClaims contains reserved key %q", k)
		}
	}

	now := time.Now().UTC()
	ttl := p.cfg.MaxTTL
	if in.ExpirationSeconds > 0 {
		reqTTL := time.Duration(in.ExpirationSeconds) * time.Second
		if reqTTL < p.cfg.MinTTL {
			ttl = p.cfg.MinTTL
		} else if reqTTL > p.cfg.MaxTTL {
			ttl = p.cfg.MaxTTL
		} else {
			ttl = reqTTL
		}
	}
	exp := now.Add(ttl)

	aud := in.Audiences
	if len(aud) == 0 {
		aud = []string{p.cfg.DefaultAudience}
	}
	for i := range aud {
		if len(aud[i]) == 0 || len(aud[i]) > 256 {
			return MintOutput{}, fmt.Errorf("invalid audience")
		}
	}
	if len(aud) > 8 {
		return MintOutput{}, fmt.Errorf("too many audiences")
	}

	sub := fmt.Sprintf("system:serviceaccount:%s:%s", in.Namespace, in.ServiceAccount)
	uid := fmt.Sprintf("%s:%s", in.Namespace, in.ServiceAccount)

	claims := jwt.MapClaims{
		"iss": p.cfg.IssuerURL,
		"sub": sub,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
		"jti": fmt.Sprintf("%d", now.UnixNano()),
		"aud": aud,
		"kubernetes.io": map[string]any{
			"namespace":        in.Namespace,
			"serviceaccount":   map[string]any{"name": in.ServiceAccount, "uid": uid},
			"warnafter":        now.Add(ttl * 8 / 10).Unix(),
			"pod":              map[string]any{},
			"node":             map[string]any{},
			"credential-id":    fmt.Sprintf("jti:%d", now.UnixNano()),
			"bound-object-ref": map[string]any{},
		},
	}

	maps.Copy(claims, in.ExtraClaims)

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = p.keys.Kid
	signed, err := token.SignedString(p.keys.PrivateKey)
	if err != nil {
		return MintOutput{}, fmt.Errorf("sign token: %w", err)
	}

	return MintOutput{Token: signed, ExpirationTimestamp: exp}, nil
}

func (p *K8sSAProvider) Review(_ context.Context, in ReviewInput) (ReviewOutput, error) {
	if in.Token == "" {
		return ReviewOutput{}, errors.New("token is required")
	}
	if len(in.Token) > 8192 {
		return ReviewOutput{}, errors.New("token too large")
	}

	parsed, parseErr := jwt.Parse(in.Token, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("unexpected signing method %s", t.Method.Alg())
		}
		if kid, _ := t.Header["kid"].(string); kid != "" && kid != p.keys.Kid {
			return nil, fmt.Errorf("unknown kid")
		}
		return p.keys.PublicKey, nil
	},
		jwt.WithIssuer(p.cfg.IssuerURL),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
	)
	if parseErr != nil {
		return ReviewOutput{Authenticated: false, Error: parseErr.Error()}, errUnauthenticatedToken
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return ReviewOutput{Authenticated: false, Error: "invalid claims"}, nil
	}

	if len(in.Audiences) > 0 {
		audClaim := parseAudience(claims["aud"])
		if !audIntersect(audClaim, in.Audiences) {
			return ReviewOutput{Authenticated: false, Error: "audience mismatch"}, nil
		}
	}

	sub, _ := claims["sub"].(string)
	uid := ""
	if kube, ok := claims["kubernetes.io"].(map[string]any); ok {
		if sa, ok := kube["serviceaccount"].(map[string]any); ok {
			uid, _ = sa["uid"].(string)
		}
	}

	groups := []string{"system:serviceaccounts", "system:authenticated"}
	extra := map[string][]string{}
	if ns, sa, ok := parseServiceAccountSub(sub); ok {
		groups = append(groups, "system:serviceaccounts:"+ns)
		extra["serviceaccount.name"] = []string{sa}
		extra["serviceaccount.namespace"] = []string{ns}
	}

	return ReviewOutput{
		Authenticated: true,
		Username:      sub,
		UID:           uid,
		Groups:        groups,
		Extra:         extra,
		Claims:        claims,
	}, nil
}

func jwkFromKey(keys KeyMaterial) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"use": "sig",
		"alg": "EdDSA",
		"crv": "Ed25519",
		"kid": keys.Kid,
		"x":   base64.RawURLEncoding.EncodeToString(keys.PublicKey),
	}
}

func parseAudience(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, i := range t {
			if s, ok := i.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

func audIntersect(a, b []string) bool {
	set := map[string]struct{}{}
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

func parseServiceAccountSub(sub string) (namespace, sa string, ok bool) {
	parts := splitN(sub, ':', 4)
	if len(parts) != 4 {
		return "", "", false
	}
	if parts[0] != "system" || parts[1] != "serviceaccount" {
		return "", "", false
	}
	return parts[2], parts[3], true
}

func splitN(s string, sep rune, n int) []string {
	parts := make([]string, 0, n)
	start := 0
	count := 1
	for i, r := range s {
		if r == sep && count < n {
			parts = append(parts, s[start:i])
			start = i + 1
			count++
		}
	}
	parts = append(parts, s[start:])
	return parts
}
