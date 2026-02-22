package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	tempDir := t.TempDir()
	cfg := Config{
		Port:               "8080",
		IssuerURL:          "http://localhost:8080",
		KeysDir:            filepath.Join(tempDir, "keys"),
		DefaultAudience:    "kubernetes.default.svc",
		MinTTL:             60 * time.Second,
		MaxTTL:             3600 * time.Second,
		RateLimitPerSecond: 1000,
		RateLimitBurst:     1000,
		MaxBodyBytes:       64 * 1024,
		MaxClaimFields:     32,
		MaxClaimDepth:      4,
		MaxClaimValueBytes: 2048,
	}
	keys, err := loadOrCreateKeys(cfg.KeysDir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(newLogger(), cfg, keys)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSkillsEndpoint(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/skills.md", nil)
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if rr.Header().Get("ETag") == "" {
		t.Fatalf("expected ETag header")
	}
	if rr.Header().Get("Last-Modified") == "" {
		t.Fatalf("expected Last-Modified header")
	}
	if !strings.Contains(rr.Body.String(), "Agent Quickstart") {
		t.Fatalf("skills markdown missing expected section")
	}

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/skills.md", nil)
	req2.Header.Set("If-None-Match", rr.Header().Get("ETag"))
	s.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", rr2.Code)
	}
}

func TestSkillsJSONEndpoint(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/skills", nil)
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if rr.Header().Get("Link") == "" {
		t.Fatalf("expected Link describedby header")
	}
	if !strings.Contains(rr.Body.String(), "\"providers\"") {
		t.Fatalf("expected providers in JSON response")
	}
}

func TestRootProviderPages(t *testing.T) {
	s := newTestServer(t)
	h := s.Handler()

	rootRR := httptest.NewRecorder()
	rootReq := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rootRR, rootReq)
	if rootRR.Code != http.StatusOK {
		t.Fatalf("root status %d", rootRR.Code)
	}
	if !strings.Contains(rootRR.Body.String(), `href="/providers/k8s-sa"`) {
		t.Fatalf("root page missing provider link")
	}

	providerRR := httptest.NewRecorder()
	providerReq := httptest.NewRequest(http.MethodGet, "/providers/k8s-sa", nil)
	h.ServeHTTP(providerRR, providerReq)
	if providerRR.Code != http.StatusOK {
		t.Fatalf("provider status %d", providerRR.Code)
	}
	body := providerRR.Body.String()
	for _, needle := range []string{
		`name="namespace"`,
		`name="serviceAccount"`,
		`name="audiences"`,
		`name="expirationSeconds"`,
		`name="extraClaims"`,
		`id="copy-btn"`,
		`id="download-btn"`,
	} {
		if !strings.Contains(body, needle) {
			t.Fatalf("provider page missing %q", needle)
		}
	}
}

func TestLegacyUIRoutesRemoved(t *testing.T) {
	s := newTestServer(t)
	h := s.Handler()

	for _, path := range []string{"/ui", "/ui/providers/k8s-sa"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s expected 404, got %d", path, rr.Code)
		}
	}
}

func TestMintAndReviewFlow(t *testing.T) {
	s := newTestServer(t)
	h := s.Handler()

	mintBody := `{"namespace":"default","serviceAccount":"builder","audiences":["kubernetes.default.svc"],"expirationSeconds":600,"extraClaims":{"extra.env":"ci"}}`
	mintReq := httptest.NewRequest(http.MethodPost, "/api/v1/providers/k8s-sa/mint", strings.NewReader(mintBody))
	mintReq.Header.Set("Content-Type", "application/json")
	mintRR := httptest.NewRecorder()
	h.ServeHTTP(mintRR, mintReq)
	if mintRR.Code != http.StatusOK {
		t.Fatalf("mint status %d body=%s", mintRR.Code, mintRR.Body.String())
	}

	var mintResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(mintRR.Body.Bytes(), &mintResp); err != nil {
		t.Fatal(err)
	}
	if mintResp.Token == "" {
		t.Fatal("empty token")
	}

	reviewBody := `{"token":"` + mintResp.Token + `","audiences":["kubernetes.default.svc"]}`
	reviewReq := httptest.NewRequest(http.MethodPost, "/api/v1/providers/k8s-sa/review", strings.NewReader(reviewBody))
	reviewReq.Header.Set("Content-Type", "application/json")
	reviewRR := httptest.NewRecorder()
	h.ServeHTTP(reviewRR, reviewReq)
	if reviewRR.Code != http.StatusOK {
		t.Fatalf("review status %d body=%s", reviewRR.Code, reviewRR.Body.String())
	}

	var reviewResp map[string]any
	if err := json.Unmarshal(reviewRR.Body.Bytes(), &reviewResp); err != nil {
		t.Fatal(err)
	}
	if auth, _ := reviewResp["authenticated"].(bool); !auth {
		t.Fatalf("expected authenticated response: %s", reviewRR.Body.String())
	}
}

func TestJWTReviewTable(t *testing.T) {
	s := newTestServer(t)
	h := s.Handler()
	mintBody := `{"namespace":"ns","serviceAccount":"sa","audiences":["aud1"],"expirationSeconds":120}`

	mintReq := httptest.NewRequest(http.MethodPost, "/api/v1/providers/k8s-sa/mint", strings.NewReader(mintBody))
	mintReq.Header.Set("Content-Type", "application/json")
	mintRR := httptest.NewRecorder()
	h.ServeHTTP(mintRR, mintReq)
	if mintRR.Code != http.StatusOK {
		t.Fatalf("mint failed: %s", mintRR.Body.String())
	}
	var mintResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(mintRR.Body.Bytes(), &mintResp)

	tests := []struct {
		name   string
		body   string
		wantOK bool
	}{
		{"valid", `{"token":"` + mintResp.Token + `","audiences":["aud1"]}`, true},
		{"bad token", `{"token":"not.a.jwt","audiences":["aud1"]}`, false},
		{"aud mismatch", `{"token":"` + mintResp.Token + `","audiences":["other"]}`, false},
		{"missing token", `{"token":""}`, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/providers/k8s-sa/review", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
				t.Fatalf("unexpected status %d", rr.Code)
			}
			if rr.Code == http.StatusOK {
				var out map[string]any
				_ = json.Unmarshal(rr.Body.Bytes(), &out)
				auth, _ := out["authenticated"].(bool)
				if auth != tc.wantOK {
					t.Fatalf("got auth=%v want=%v body=%s", auth, tc.wantOK, rr.Body.String())
				}
			}
		})
	}
}

func TestK8sTokenReviewAcceptsExtraFields(t *testing.T) {
	s := newTestServer(t)
	h := s.Handler()

	// Mint a token first.
	mintBody := `{"namespace":"default","serviceAccount":"sa","audiences":["kubernetes.default.svc"],"expirationSeconds":120}`
	mintReq := httptest.NewRequest(http.MethodPost, "/api/v1/providers/k8s-sa/mint", strings.NewReader(mintBody))
	mintReq.Header.Set("Content-Type", "application/json")
	mintRR := httptest.NewRecorder()
	h.ServeHTTP(mintRR, mintReq)
	if mintRR.Code != http.StatusOK {
		t.Fatalf("mint failed: %s", mintRR.Body.String())
	}
	var mintResp struct{ Token string }
	_ = json.Unmarshal(mintRR.Body.Bytes(), &mintResp)

	// Send a TokenReview with apiVersion/kind (like a real K8s client would).
	reviewBody := `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"` + mintResp.Token + `","audiences":["kubernetes.default.svc"]}}`
	reviewReq := httptest.NewRequest(http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", strings.NewReader(reviewBody))
	reviewReq.Header.Set("Content-Type", "application/json")
	reviewRR := httptest.NewRecorder()
	h.ServeHTTP(reviewRR, reviewReq)
	if reviewRR.Code != http.StatusOK {
		t.Fatalf("expected 200 with extra K8s fields, got %d: %s", reviewRR.Code, reviewRR.Body.String())
	}
}

func TestClientIPUsesRightmostXFF(t *testing.T) {
	tests := []struct {
		name     string
		xff      string
		flyIP    string
		remote   string
		wantIP   string
	}{
		{"rightmost xff", "spoofed, real-client", "", "1.2.3.4:1234", "real-client"},
		{"fly-client-ip preferred", "spoofed", "fly-ip", "1.2.3.4:1234", "fly-ip"},
		{"no xff fallback", "", "", "1.2.3.4:1234", "1.2.3.4"},
		{"single xff", "only-one", "", "1.2.3.4:1234", "only-one"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.flyIP != "" {
				req.Header.Set("Fly-Client-IP", tc.flyIP)
			}
			got := clientIP(req)
			if got != tc.wantIP {
				t.Fatalf("clientIP()=%q want %q", got, tc.wantIP)
			}
		})
	}
}

func TestLimiterEvictsStaleEntries(t *testing.T) {
	l := &IPLimiter{
		clients: map[string]*tokenBucket{},
		rps:     10,
		burst:   10,
	}

	// Populate with a stale entry.
	staleTime := time.Now().Add(-15 * time.Minute)
	l.clients["stale-ip"] = &tokenBucket{tokens: 10, last: staleTime}

	// Force sweep by advancing the call counter to a multiple of 1000.
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

func TestMainRunConfigLoad(t *testing.T) {
	_ = os.Setenv("PORT", "18080")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "18080" {
		t.Fatalf("unexpected port %s", cfg.Port)
	}
}
