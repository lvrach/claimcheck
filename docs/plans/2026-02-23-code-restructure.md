# Code Restructure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extract provider abstraction and rate limiter into `internal/` packages to establish clean domain boundaries.

**Architecture:** Two new internal packages: `internal/provider` (interface, types, K8s implementation, claim validation) and `internal/ratelimit` (IP-based token bucket limiter). Everything else stays in `package main`. `K8sSAProvider` accepts key fields directly (ed25519 key + kid string) rather than importing `KeyMaterial` from main, avoiding circular imports.

**Tech Stack:** Go 1.23, github.com/golang-jwt/jwt/v5, standard library

---

### Task 1: Create `internal/provider/provider.go` — interface and shared types

**Files:**
- Create: `internal/provider/provider.go`

**Step 1: Write the file**

```go
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

// MintOutput contains the result of a mint operation.
type MintOutput struct {
	Token               string    `json:"token"`
	ExpirationTimestamp time.Time `json:"expirationTimestamp"`
}

// ReviewInput contains the parameters for reviewing a token.
type ReviewInput struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences"`
}

// ReviewOutput contains the result of a token review.
type ReviewOutput struct {
	Authenticated bool                `json:"authenticated"`
	Username      string              `json:"username,omitempty"`
	UID           string              `json:"uid,omitempty"`
	Groups        []string            `json:"groups,omitempty"`
	Extra         map[string][]string `json:"extra,omitempty"`
	Claims        map[string]any      `json:"claims,omitempty"`
	Error         string              `json:"error,omitempty"`
}

// ProviderSchema describes a provider's capabilities for agent consumption and UI rendering.
type ProviderSchema struct {
	Provider    string         `json:"provider"`
	DisplayName string         `json:"displayName"`
	Description string         `json:"description"`
	Fields      []SchemaField  `json:"fields"`
	MintJSON    map[string]any `json:"mintRequest"`
	ReviewJSON  map[string]any `json:"reviewRequest"`
	Limits      map[string]any `json:"limits"`
}

// SchemaField describes a single input field for a provider.
type SchemaField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Default     any    `json:"default,omitempty"`
	Example     any    `json:"example,omitempty"`
}

// TokenProvider is the interface that all token providers must implement.
type TokenProvider interface {
	ID() string
	Description() string
	Mint(ctx context.Context, in MintInput) (MintOutput, error)
	Review(ctx context.Context, in ReviewInput) (ReviewOutput, error)
	Schema() ProviderSchema
}
```

**Step 2: Verify it compiles**

Run: `go build ./internal/provider/`
Expected: success (no output)

**Step 3: Commit**

```bash
git add internal/provider/provider.go
git commit -m "refactor: extract provider interface and types into internal/provider"
```

---

### Task 2: Create `internal/provider/claims.go` — claim validation

**Files:**
- Create: `internal/provider/claims.go`
- Delete: `claims.go` (root)

**Step 1: Write the file**

```go
package provider

import (
	"fmt"
)

// ValidateClaims checks that extra claims don't exceed configured limits.
func ValidateClaims(claims map[string]any, maxFields, maxDepth, maxValueBytes int) error {
	if len(claims) > maxFields {
		return fmt.Errorf("too many claim fields")
	}
	for k, v := range claims {
		if len(k) > 128 {
			return fmt.Errorf("claim key too long: %s", k)
		}
		if err := validateClaimValue(v, 1, maxDepth, maxValueBytes); err != nil {
			return fmt.Errorf("claim %q: %w", k, err)
		}
	}
	return nil
}

func validateClaimValue(v any, depth, maxDepth, maxValueBytes int) error {
	if depth > maxDepth {
		return fmt.Errorf("claim nesting too deep")
	}
	switch x := v.(type) {
	case string:
		if len(x) > maxValueBytes {
			return fmt.Errorf("string value too large")
		}
	case float64, bool, int, int64, nil:
		return nil
	case []any:
		if len(x) > 64 {
			return fmt.Errorf("array too large")
		}
		for _, item := range x {
			if err := validateClaimValue(item, depth+1, maxDepth, maxValueBytes); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(x) > 64 {
			return fmt.Errorf("object too large")
		}
		for k, item := range x {
			if len(k) > 128 {
				return fmt.Errorf("nested key too long")
			}
			if err := validateClaimValue(item, depth+1, maxDepth, maxValueBytes); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported claim value type")
	}
	return nil
}
```

**Step 2: Delete old `claims.go`**

```bash
rm claims.go
```

**Step 3: Verify it compiles**

Run: `go build ./internal/provider/`
Expected: success

**Step 4: Commit**

```bash
git add internal/provider/claims.go
git rm claims.go
git commit -m "refactor: move claim validation into internal/provider"
```

---

### Task 3: Create `internal/provider/k8s.go` — K8s SA provider implementation

**Files:**
- Create: `internal/provider/k8s.go`
- Delete: `auth.go` (root)

**Step 1: Write the file**

The K8s provider needs key material but can't import `main.KeyMaterial`. Instead, define a `K8sConfig` struct that accepts the fields it needs.

```go
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
```

**Step 2: Delete old `auth.go`**

```bash
rm auth.go
```

**Step 3: Verify provider package compiles**

Run: `go build ./internal/provider/`
Expected: success

**Step 4: Commit**

```bash
git add internal/provider/k8s.go
git rm auth.go
git commit -m "refactor: move K8s SA provider into internal/provider"
```

---

### Task 4: Create `internal/ratelimit/ratelimit.go` — rate limiter

**Files:**
- Create: `internal/ratelimit/ratelimit.go`

**Step 1: Write the file**

```go
// Package ratelimit provides an IP-based token bucket rate limiter
// with amortized eviction of stale entries.
package ratelimit

import (
	"sync"
	"time"
)

const sweepInterval = 5 * time.Minute
const staleThreshold = 10 * time.Minute

// Limiter is an IP-based token bucket rate limiter.
type Limiter struct {
	mu        sync.Mutex
	clients   map[string]*bucket
	rps       float64
	burst     int
	calls     int
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter creates a rate limiter with the given requests-per-second and burst size.
func NewLimiter(rps float64, burst int) *Limiter {
	return &Limiter{
		clients: make(map[string]*bucket),
		rps:     rps,
		burst:   burst,
	}
}

// Allow reports whether a request from the given key should be allowed.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls++
	if l.calls%1000 == 0 && now.Sub(l.lastSweep) > sweepInterval {
		l.lastSweep = now
		for k, b := range l.clients {
			if now.Sub(b.last) > staleThreshold {
				delete(l.clients, k)
			}
		}
	}

	b, ok := l.clients[key]
	if !ok {
		l.clients[key] = &bucket{tokens: float64(l.burst - 1), last: now}
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rps
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
```

**Step 2: Verify it compiles**

Run: `go build ./internal/ratelimit/`
Expected: success

**Step 3: Commit**

```bash
git add internal/ratelimit/ratelimit.go
git commit -m "refactor: extract rate limiter into internal/ratelimit"
```

---

### Task 5: Update `server.go` — use new packages

**Files:**
- Modify: `server.go`

**Step 1: Rewrite server.go**

Replace the entire file. Key changes:
- Import `claimcheck/internal/provider` and `claimcheck/internal/ratelimit`
- Remove `IPLimiter`, `tokenBucket`, limiter constants (moved to ratelimit package)
- `Server.providers` becomes `map[string]provider.TokenProvider`
- `Server.limiter` becomes `*ratelimit.Limiter`
- `NewServer` creates `provider.K8sConfig` from `Config` + `KeyMaterial`, constructs provider
- `getProvider` returns `provider.TokenProvider`
- `jwkFromKey` call becomes `provider.JWKFromKey`

The full updated `server.go`:

```go
package main

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"claimcheck/internal/provider"
	"claimcheck/internal/ratelimit"
)

//go:embed static templates skills.md
var content embed.FS

type Server struct {
	cfg                Config
	logger             *slog.Logger
	keys               KeyMaterial
	providers          map[string]provider.TokenProvider
	tmpl               *template.Template
	limiter            *ratelimit.Limiter
	skillsMD           []byte
	skillsETag         string
	skillsLastModified time.Time
	startedAt          time.Time
}

func NewServer(logger *slog.Logger, cfg Config, keys KeyMaterial) (*Server, error) {
	tmpl, err := template.ParseFS(content, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	skillsMD, err := content.ReadFile("skills.md")
	if err != nil {
		return nil, fmt.Errorf("read skills.md: %w", err)
	}
	skillsHash := sha256.Sum256(skillsMD)
	skillsETag := `"` + base64.RawURLEncoding.EncodeToString(skillsHash[:12]) + `"`

	k8sCfg := provider.K8sConfig{
		IssuerURL:          cfg.IssuerURL,
		DefaultAudience:    cfg.DefaultAudience,
		MinTTL:             cfg.MinTTL,
		MaxTTL:             cfg.MaxTTL,
		MaxClaimFields:     cfg.MaxClaimFields,
		MaxClaimDepth:      cfg.MaxClaimDepth,
		MaxClaimValueBytes: cfg.MaxClaimValueBytes,
		Kid:                keys.Kid,
		PrivateKey:         keys.PrivateKey,
		PublicKey:          keys.PublicKey,
	}
	providers := map[string]provider.TokenProvider{}
	k8sProvider := provider.NewK8sSAProvider(k8sCfg)
	providers[k8sProvider.ID()] = k8sProvider

	return &Server{
		cfg:                cfg,
		logger:             logger,
		keys:               keys,
		providers:          providers,
		tmpl:               tmpl,
		limiter:            ratelimit.NewLimiter(cfg.RateLimitPerSecond, cfg.RateLimitBurst),
		skillsMD:           skillsMD,
		skillsETag:         skillsETag,
		skillsLastModified: time.Now().UTC().Truncate(time.Second),
		startedAt:          time.Now().UTC(),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /skills", s.handleSkillsJSON)
	mux.HandleFunc("GET /skills.md", s.handleSkills)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)

	mux.HandleFunc("GET /api/v1/providers", s.handleProviders)
	mux.HandleFunc("GET /api/v1/providers/{provider}/schema", s.handleProviderSchema)
	mux.HandleFunc("POST /api/v1/providers/{provider}/mint", s.handleProviderMint)
	mux.HandleFunc("POST /api/v1/providers/{provider}/review", s.handleProviderReview)

	mux.HandleFunc("POST /api/v1/namespaces/{namespace}/serviceaccounts/{name}/token", s.handleK8sTokenRequest)
	mux.HandleFunc("POST /api/v1/tokenreviews", s.handleK8sTokenReview)
	mux.HandleFunc("POST /apis/authentication.k8s.io/v1/tokenreviews", s.handleK8sTokenReview)

	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("GET /providers/{provider}", s.handleProviderPage)

	fs := http.FileServer(http.FS(content))
	mux.Handle("GET /static/", http.StripPrefix("/", fs))

	return s.withRecover(s.withLogging(mux))
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", clientIP(r),
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic recovered", "panic", rec)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowRequest(r *http.Request) bool {
	ip := clientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	return s.limiter.Allow(ip)
}

func getProvider(s *Server, id string) (provider.TokenProvider, bool) {
	p, ok := s.providers[id]
	return p, ok
}

func clientIP(r *http.Request) string {
	// Prefer Fly-Client-IP (set by Fly.io proxy, not spoofable).
	if fci := r.Header.Get("Fly-Client-IP"); fci != "" {
		return strings.TrimSpace(fci)
	}
	// Use the rightmost X-Forwarded-For entry: proxies append to XFF,
	// so the last value is the one added by the nearest trusted proxy.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) bool {
	return decodeJSONBodyOpts(w, r, maxBytes, dst, true)
}

func decodeJSONBodyOpts(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any, strict bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer func(body io.ReadCloser) { _ = body.Close() }(r.Body)
	dec := json.NewDecoder(r.Body)
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must contain a single JSON object"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if w.Header().Get("Link") == "" {
		w.Header().Set("Link", "</skills.md>; rel=\"describedby\"")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, nil))
}
```

**Step 2: Verify it compiles (will fail until handlers.go is updated)**

Expected: compile errors in handlers.go referencing old types — this is fine, Task 6 fixes it.

---

### Task 6: Update `handlers.go` — use `provider.*` types

**Files:**
- Modify: `handlers.go`

**Step 1: Update imports and type references**

Key changes:
- Add import `"claimcheck/internal/provider"`
- `MintInput` → `provider.MintInput`
- `ReviewInput` → `provider.ReviewInput`
- `ProviderSchema` → `provider.ProviderSchema`
- `errUnauthenticatedToken` → `provider.ErrUnauthenticatedToken`
- `jwkFromKey(s.keys)` → `provider.JWKFromKey(s.keys.Kid, s.keys.PublicKey)`

The full updated `handlers.go`:

```go
package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"claimcheck/internal/provider"
)

func (s *Server) handleSkillsJSON(w http.ResponseWriter, _ *http.Request) {
	providers := make([]map[string]any, 0, len(s.providers))
	for _, p := range s.providers {
		providers = append(providers, map[string]any{
			"id":           p.ID(),
			"description":  p.Description(),
			"capabilities": []string{"mint", "review", "jwks", "discovery"},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": "1.0.0",
		"auth": map[string]any{
			"mode": "anonymous",
		},
		"endpoints": map[string]string{
			"skills_markdown": "/skills.md",
			"providers":       "/api/v1/providers",
			"jwks":            "/.well-known/jwks.json",
			"discovery":       "/.well-known/openid-configuration",
		},
		"providers": providers,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"uptimeSec": int(time.Since(s.startedAt).Seconds()),
		"provider":  len(s.providers),
	})
}

func (s *Server) handleSkills(w http.ResponseWriter, r *http.Request) {
	if inm := r.Header.Get("If-None-Match"); inm != "" && inm == s.skillsETag {
		w.Header().Set("ETag", s.skillsETag)
		w.Header().Set("Last-Modified", s.skillsLastModified.Format(http.TimeFormat))
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("ETag", s.skillsETag)
	w.Header().Set("Last-Modified", s.skillsLastModified.Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.skillsMD)
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{provider.JWKFromKey(s.keys.Kid, s.keys.PublicKey)}})
}

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	issuer := strings.TrimRight(s.cfg.IssuerURL, "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"token_endpoint":                        issuer + "/api/v1/providers/k8s-sa/mint",
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"subject_types_supported":               []string{"public"},
	})
}

func (s *Server) handleProviders(w http.ResponseWriter, _ *http.Request) {
	type providerInfo struct {
		ID           string   `json:"id"`
		Description  string   `json:"description"`
		Capabilities []string `json:"capabilities"`
	}
	list := make([]providerInfo, 0, len(s.providers))
	for _, p := range s.providers {
		list = append(list, providerInfo{
			ID:           p.ID(),
			Description:  p.Description(),
			Capabilities: []string{"mint", "review", "jwks", "discovery"},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": list})
}

func (s *Server) handleProviderSchema(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	p, ok := getProvider(s, providerID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	writeJSON(w, http.StatusOK, p.Schema())
}

func (s *Server) handleProviderMint(w http.ResponseWriter, r *http.Request) {
	if !s.allowRequest(r) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}
	providerID := r.PathValue("provider")
	p, ok := getProvider(s, providerID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	var in provider.MintInput
	if !decodeJSONBody(w, r, s.cfg.MaxBodyBytes, &in) {
		return
	}
	out, err := p.Mint(r.Context(), in)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleProviderReview(w http.ResponseWriter, r *http.Request) {
	if !s.allowRequest(r) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}
	providerID := r.PathValue("provider")
	p, ok := getProvider(s, providerID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	var in provider.ReviewInput
	if !decodeJSONBody(w, r, s.cfg.MaxBodyBytes, &in) {
		return
	}
	out, err := p.Review(r.Context(), in)
	if err != nil {
		if errors.Is(err, provider.ErrUnauthenticatedToken) {
			writeJSON(w, http.StatusOK, out)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type tokenRequest struct {
	Spec struct {
		Audiences         []string       `json:"audiences"`
		ExpirationSeconds int64          `json:"expirationSeconds"`
		ExtraClaims       map[string]any `json:"extraClaims"`
	} `json:"spec"`
}

func (s *Server) handleK8sTokenRequest(w http.ResponseWriter, r *http.Request) {
	if !s.allowRequest(r) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}
	p, _ := getProvider(s, "k8s-sa")

	var req tokenRequest
	if !decodeJSONBodyOpts(w, r, s.cfg.MaxBodyBytes, &req, false) {
		return
	}

	in := provider.MintInput{
		Namespace:         r.PathValue("namespace"),
		ServiceAccount:    r.PathValue("name"),
		Audiences:         req.Spec.Audiences,
		ExpirationSeconds: req.Spec.ExpirationSeconds,
		ExtraClaims:       req.Spec.ExtraClaims,
	}
	if in.ExtraClaims == nil {
		in.ExtraClaims = map[string]any{}
	}

	out, err := p.Mint(r.Context(), in)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"status": map[string]any{
			"token":               out.Token,
			"expirationTimestamp": out.ExpirationTimestamp.Format(time.RFC3339),
		},
	})
}

type tokenReviewRequest struct {
	Spec struct {
		Token     string   `json:"token"`
		Audiences []string `json:"audiences"`
	} `json:"spec"`
}

func (s *Server) handleK8sTokenReview(w http.ResponseWriter, r *http.Request) {
	if !s.allowRequest(r) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}
	p, _ := getProvider(s, "k8s-sa")

	var req tokenReviewRequest
	if !decodeJSONBodyOpts(w, r, s.cfg.MaxBodyBytes, &req, false) {
		return
	}
	out, err := p.Review(r.Context(), provider.ReviewInput{Token: req.Spec.Token, Audiences: req.Spec.Audiences})
	if err != nil {
		if errors.Is(err, provider.ErrUnauthenticatedToken) {
			writeJSON(w, http.StatusOK, map[string]any{
				"apiVersion": "authentication.k8s.io/v1",
				"kind":       "TokenReview",
				"status": map[string]any{
					"authenticated": false,
					"error":         out.Error,
				},
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	status := map[string]any{
		"authenticated": out.Authenticated,
	}
	if out.Authenticated {
		status["user"] = map[string]any{
			"username": out.Username,
			"uid":      out.UID,
			"groups":   out.Groups,
			"extra":    out.Extra,
		}
	} else if out.Error != "" {
		status["error"] = out.Error
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"status":     status,
	})
}

func (s *Server) handleHome(w http.ResponseWriter, _ *http.Request) {
	providers := make([]provider.ProviderSchema, 0, len(s.providers))
	for _, p := range s.providers {
		providers = append(providers, p.Schema())
	}
	if err := s.tmpl.ExecuteTemplate(w, "layout.html", map[string]any{"providers": providers}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("render UI: %v", err)})
	}
}

func (s *Server) handleProviderPage(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	p, ok := getProvider(s, providerID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}
	if err := s.tmpl.ExecuteTemplate(w, "provider_form.html", p.Schema()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("render provider form: %v", err)})
	}
}
```

**Step 2: Verify full project compiles**

Run: `go build ./...`
Expected: success

**Step 3: Commit**

```bash
git add server.go handlers.go
git commit -m "refactor: update server and handlers to use internal packages"
```

---

### Task 7: Update `server_test.go` — fix imports

**Files:**
- Modify: `server_test.go`

**Step 1: Update test imports**

The test file references `clientIP` (still in main, no change needed) and uses types that are now in `provider.*`. The `newTestServer` function and most tests don't reference provider types directly — they go through HTTP handlers. Only `TestLimiterEvictsStaleEntries` references the old `IPLimiter` type which is now in `ratelimit`.

Replace `TestLimiterEvictsStaleEntries` to use `ratelimit.NewLimiter`:

```go
// Add to imports:
// "claimcheck/internal/ratelimit"

func TestLimiterEvictsStaleEntries(t *testing.T) {
	l := ratelimit.NewLimiter(10, 10)

	// We need to test the internal sweep. Since we can't inject stale entries
	// via the public API, we test that the limiter works correctly over time
	// by verifying it allows requests after a burst.
	for i := 0; i < 10; i++ {
		l.Allow("test-ip")
	}
	// 11th should be denied (burst exhausted).
	if l.Allow("test-ip") {
		t.Fatal("expected rate limit to deny request after burst")
	}
}
```

Note: The old test injected into `l.clients` directly which was possible when the limiter was in the same package. With the limiter in its own package, we test through the public API. To preserve the stale-eviction test, add a dedicated test file in the ratelimit package (see Task 8).

**Step 2: Run all tests**

Run: `go test ./...`
Expected: all pass

**Step 3: Commit**

```bash
git add server_test.go
git commit -m "refactor: update tests for new package structure"
```

---

### Task 8: Add `internal/ratelimit/ratelimit_test.go` — limiter unit test

**Files:**
- Create: `internal/ratelimit/ratelimit_test.go`

**Step 1: Write the test**

Since we're inside the `ratelimit` package, we can test internal state.

```go
package ratelimit

import (
	"testing"
	"time"
)

func TestAllow(t *testing.T) {
	l := NewLimiter(10, 10)

	// First 10 requests should be allowed.
	for i := 0; i < 10; i++ {
		if !l.Allow("ip1") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	// 11th should be denied.
	if l.Allow("ip1") {
		t.Fatal("expected denial after burst exhausted")
	}
	// Different IP should still be allowed.
	if !l.Allow("ip2") {
		t.Fatal("different IP should be allowed")
	}
}

func TestEvictsStaleEntries(t *testing.T) {
	l := NewLimiter(10, 10)

	// Inject a stale entry directly.
	staleTime := time.Now().Add(-15 * time.Minute)
	l.clients["stale-ip"] = &bucket{tokens: 10, last: staleTime}

	// Set up sweep trigger conditions.
	l.calls = 999
	l.lastSweep = time.Now().Add(-10 * time.Minute)

	// This call triggers a sweep.
	l.Allow("fresh-ip")

	if _, exists := l.clients["stale-ip"]; exists {
		t.Fatal("expected stale entry to be evicted")
	}
	if _, exists := l.clients["fresh-ip"]; !exists {
		t.Fatal("expected fresh entry to exist")
	}
}
```

**Step 2: Run the test**

Run: `go test ./internal/ratelimit/ -v`
Expected: PASS

**Step 3: Run full suite**

Run: `go test ./...`
Expected: all pass

**Step 4: Commit**

```bash
git add internal/ratelimit/ratelimit_test.go
git commit -m "test: add ratelimit package unit tests"
```

---

### Task 9: Clean up and verify

**Files:**
- Delete: `auth.go` (if not already deleted)
- Delete: `claims.go` (if not already deleted)

**Step 1: Verify deleted files are gone**

```bash
ls auth.go claims.go 2>&1
```
Expected: "No such file or directory" for both

**Step 2: Run full test suite**

Run: `go test ./...`
Expected: all pass

**Step 3: Run linter**

Run: `make lint`
Expected: pass (or only pre-existing warnings)

**Step 4: Final commit**

```bash
git add -A
git commit -m "refactor: complete package restructure — clean up"
```
