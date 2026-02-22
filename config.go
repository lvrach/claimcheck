package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port               string
	IssuerURL          string
	KeysDir            string
	DefaultAudience    string
	MinTTL             time.Duration
	MaxTTL             time.Duration
	RateLimitPerSecond float64
	RateLimitBurst     int
	MaxBodyBytes       int64
	MaxClaimFields     int
	MaxClaimDepth      int
	MaxClaimValueBytes int
}

func loadConfig() (Config, error) {
	cfg := Config{
		Port:               getEnv("PORT", "8080"),
		IssuerURL:          getEnv("ISSUER_URL", "http://localhost:8080"),
		KeysDir:            getEnv("KEYS_DIR", "/data/keys"),
		DefaultAudience:    getEnv("DEFAULT_AUDIENCE", "kubernetes.default.svc"),
		MinTTL:             time.Duration(getEnvInt("MIN_TTL_SECONDS", 60)) * time.Second,
		MaxTTL:             time.Duration(getEnvInt("MAX_TTL_SECONDS", 3600)) * time.Second,
		RateLimitPerSecond: getEnvFloat("RATE_LIMIT_RPS", 5.0),
		RateLimitBurst:     getEnvInt("RATE_LIMIT_BURST", 20),
		MaxBodyBytes:       int64(getEnvInt("MAX_BODY_BYTES", 64*1024)),
		MaxClaimFields:     getEnvInt("MAX_CLAIM_FIELDS", 32),
		MaxClaimDepth:      getEnvInt("MAX_CLAIM_DEPTH", 4),
		MaxClaimValueBytes: getEnvInt("MAX_CLAIM_VALUE_BYTES", 2048),
	}

	if cfg.MinTTL <= 0 || cfg.MaxTTL <= 0 || cfg.MaxTTL < cfg.MinTTL {
		return Config{}, fmt.Errorf("invalid TTL bounds")
	}
	if cfg.RateLimitPerSecond <= 0 || cfg.RateLimitBurst <= 0 {
		return Config{}, fmt.Errorf("invalid rate limit settings")
	}
	if cfg.MaxBodyBytes <= 0 {
		return Config{}, fmt.Errorf("invalid max body bytes")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return n
}
