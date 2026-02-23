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
	providers := make([]provider.Schema, 0, len(s.providers))
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
