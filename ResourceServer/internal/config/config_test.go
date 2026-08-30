package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	os.Clearenv()
	cfg := Load()

	if cfg.Port != 8082 {
		t.Errorf("expected default Port 8082, got %d", cfg.Port)
	}
	if cfg.Address() != "0.0.0.0:8082" {
		t.Errorf("expected Address '0.0.0.0:8082', got %s", cfg.Address())
	}
	if cfg.IssuerURL != "http://localhost:8080" {
		t.Errorf("expected IssuerURL 'http://localhost:8080', got %s", cfg.IssuerURL)
	}
	if cfg.JWKSURL != "http://localhost:8080/.well-known/jwks.json" {
		t.Errorf("expected JWKSURL 'http://localhost:8080/.well-known/jwks.json', got %s", cfg.JWKSURL)
	}
}

func TestLoadCustomEnv(t *testing.T) {
	os.Clearenv()
	os.Setenv("PORT", "8090")
	os.Setenv("ISSUER_URL", "https://auth.example.com")
	os.Setenv("JWKS_URL", "https://auth.example.com/.well-known/jwks.json")
	defer os.Clearenv()

	cfg := Load()

	if cfg.Port != 8090 {
		t.Errorf("expected Port 8090, got %d", cfg.Port)
	}
	if cfg.IssuerURL != "https://auth.example.com" {
		t.Errorf("expected IssuerURL 'https://auth.example.com', got %s", cfg.IssuerURL)
	}
	if cfg.JWKSURL != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("expected JWKSURL 'https://auth.example.com/.well-known/jwks.json', got %s", cfg.JWKSURL)
	}
}
