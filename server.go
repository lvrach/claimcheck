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
