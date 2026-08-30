package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	os.Clearenv()
	cfg := Load()

	if cfg.Port != 9000 {
		t.Errorf("expected default Port 9000, got %d", cfg.Port)
	}
	if cfg.Address() != "0.0.0.0:9000" {
		t.Errorf("expected Address '0.0.0.0:9000', got %s", cfg.Address())
	}
	if cfg.AuthServerURL != "http://localhost:8080" {
		t.Errorf("expected AuthServerURL 'http://localhost:8080', got %s", cfg.AuthServerURL)
	}
	if cfg.ClientID != "client-id-001" {
		t.Errorf("expected ClientID 'client-id-001', got %s", cfg.ClientID)
	}
	if cfg.RedirectURI != "http://localhost:9000/oauth/callback" {
		t.Errorf("expected RedirectURI 'http://localhost:9000/oauth/callback', got %s", cfg.RedirectURI)
	}
}

func TestLoadCustomEnv(t *testing.T) {
	os.Clearenv()
	os.Setenv("PORT", "9001")
	os.Setenv("AUTH_SERVER_URL", "https://auth.example.com")
	os.Setenv("CLIENT_ID", "custom-client-app")
	os.Setenv("REDIRECT_URI", "https://app.example.com/oauth/callback")
	defer os.Clearenv()

	cfg := Load()

	if cfg.Port != 9001 {
		t.Errorf("expected Port 9001, got %d", cfg.Port)
	}
	if cfg.AuthServerURL != "https://auth.example.com" {
		t.Errorf("expected AuthServerURL 'https://auth.example.com', got %s", cfg.AuthServerURL)
	}
	if cfg.ClientID != "custom-client-app" {
		t.Errorf("expected ClientID 'custom-client-app', got %s", cfg.ClientID)
	}
	if cfg.RedirectURI != "https://app.example.com/oauth/callback" {
		t.Errorf("expected RedirectURI 'https://app.example.com/oauth/callback', got %s", cfg.RedirectURI)
	}
}
