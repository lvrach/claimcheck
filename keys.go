package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type KeyMaterial struct {
	Kid        string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

type keyMeta struct {
	Kid string `json:"kid"`
}

func loadOrCreateKeys(keysDir string) (KeyMaterial, error) {
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return KeyMaterial{}, fmt.Errorf("create keys dir: %w", err)
	}

	const keyPrefix = "ed25519"
	privPath := filepath.Join(keysDir, keyPrefix+"-private.pkcs8")
	pubPath := filepath.Join(keysDir, keyPrefix+"-public.der")
	metaPath := filepath.Join(keysDir, "meta.json")

	if fileExists(privPath) && fileExists(pubPath) && fileExists(metaPath) {
		// #nosec G304 -- Paths are derived from trusted config keysDir and fixed filenames.
		privBytes, err := os.ReadFile(privPath)
		if err != nil {
			return KeyMaterial{}, fmt.Errorf("read private key: %w", err)
		}
		pkAny, err := x509.ParsePKCS8PrivateKey(privBytes)
		if err != nil {
			return KeyMaterial{}, fmt.Errorf("parse private key: %w", err)
		}
		privateKey, ok := pkAny.(ed25519.PrivateKey)
		if !ok {
			return KeyMaterial{}, fmt.Errorf("private key is not ed25519")
		}

		// #nosec G304 -- Paths are derived from trusted config keysDir and fixed filenames.
		pubBytes, err := os.ReadFile(pubPath)
		if err != nil {
			return KeyMaterial{}, fmt.Errorf("read public key: %w", err)
		}
		pubAny, err := x509.ParsePKIXPublicKey(pubBytes)
		if err != nil {
			return KeyMaterial{}, fmt.Errorf("parse public key: %w", err)
		}
		publicKey, ok := pubAny.(ed25519.PublicKey)
		if !ok {
			return KeyMaterial{}, fmt.Errorf("public key is not ed25519")
		}

		// #nosec G304 -- Paths are derived from trusted config keysDir and fixed filenames.
		metaBytes, err := os.ReadFile(metaPath)
		if err != nil {
			return KeyMaterial{}, fmt.Errorf("read key meta: %w", err)
		}
		var m keyMeta
		if err := json.Unmarshal(metaBytes, &m); err != nil {
			return KeyMaterial{}, fmt.Errorf("parse key meta: %w", err)
		}
		if m.Kid == "" {
			m.Kid = makeKID(publicKey)
		}

		return KeyMaterial{Kid: m.Kid, PrivateKey: privateKey, PublicKey: publicKey}, nil
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("generate key: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("marshal private key: %w", err)
	}
	pubDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("marshal public key: %w", err)
	}
	kid := makeKID(publicKey)

	if err := os.WriteFile(privPath, pkcs8, 0o600); err != nil {
		return KeyMaterial{}, fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubDer, 0o600); err != nil {
		return KeyMaterial{}, fmt.Errorf("write public key: %w", err)
	}
	meta, _ := json.MarshalIndent(keyMeta{Kid: kid}, "", "  ")
	if err := os.WriteFile(metaPath, meta, 0o600); err != nil {
		return KeyMaterial{}, fmt.Errorf("write key meta: %w", err)
	}

	return KeyMaterial{Kid: kid, PrivateKey: privateKey, PublicKey: publicKey}, nil
}

func makeKID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
