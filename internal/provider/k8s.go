package provider

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// K8sConfig holds the configuration needed by the K8s SA provider.
type K8sConfig struct {
	IssuerURL          string
	DefaultAudience    string
	MinTTL             time.Duration
	MaxTTL             time.Duration
	MaxClaimFields     int
	MaxClaimDepth      int
	MaxClaimValueBytes int
	Kid                string
	PrivateKey         ed25519.PrivateKey
	PublicKey          ed25519.PublicKey
}

// K8sSAProvider implements TokenProvider for Kubernetes service account tokens.
type K8sSAProvider struct {
	cfg K8sConfig
}

// NewK8sSAProvider creates a new Kubernetes service account token provider.
func NewK8sSAProvider(cfg K8sConfig) *K8sSAProvider {
	return &K8sSAProvider{cfg: cfg}
}

// ID returns the provider identifier.
func (p *K8sSAProvider) ID() string { return "k8s-sa" }

// Description returns a human-readable description of the provider.
func (p *K8sSAProvider) Description() string {
	return "High-fidelity Kubernetes service account token provider"
}

// Schema returns the provider's schema including fields and limits.
func (p *K8sSAProvider) Schema() Schema {
	return Schema{
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

// Mint creates a signed Kubernetes service account token from the given input.
func (p *K8sSAProvider) Mint(_ context.Context, in MintInput) (MintOutput, error) {
	if in.Namespace == "" || in.ServiceAccount == "" {
		return MintOutput{}, errors.New("namespace and serviceAccount are required")
	}
	if err := ValidateClaims(in.ExtraClaims, p.cfg.MaxClaimFields, p.cfg.MaxClaimDepth, p.cfg.MaxClaimValueBytes); err != nil {
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
	token.Header["kid"] = p.cfg.Kid
	signed, err := token.SignedString(p.cfg.PrivateKey)
	if err != nil {
		return MintOutput{}, fmt.Errorf("sign token: %w", err)
	}

	return MintOutput{Token: signed, ExpirationTimestamp: exp}, nil
}

// Review validates and extracts claims from a Kubernetes service account token.
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
		if kid, _ := t.Header["kid"].(string); kid != "" && kid != p.cfg.Kid {
			return nil, fmt.Errorf("unknown kid")
		}
		return p.cfg.PublicKey, nil
	},
		jwt.WithIssuer(p.cfg.IssuerURL),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
	)
	if parseErr != nil {
		return ReviewOutput{Authenticated: false, Error: parseErr.Error()}, ErrUnauthenticatedToken
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return ReviewOutput{Authenticated: false, Error: "invalid claims"}, nil
	}

	if len(in.Audiences) > 0 {
		audClaim := ParseAudience(claims["aud"])
		if !AudIntersect(audClaim, in.Audiences) {
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
	if ns, sa, ok := ParseServiceAccountSub(sub); ok {
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

// JWKFromKey converts Ed25519 key material into a JWK map for JWKS endpoints.
func JWKFromKey(kid string, pub ed25519.PublicKey) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"use": "sig",
		"alg": "EdDSA",
		"crv": "Ed25519",
		"kid": kid,
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// ParseAudience extracts audience strings from a JWT claim value.
func ParseAudience(v any) []string {
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

// AudIntersect returns true if the two audience lists share at least one entry.
func AudIntersect(a, b []string) bool {
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

// ParseServiceAccountSub parses a Kubernetes subject string like
// "system:serviceaccount:namespace:name" into its parts.
func ParseServiceAccountSub(sub string) (namespace, sa string, ok bool) {
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
