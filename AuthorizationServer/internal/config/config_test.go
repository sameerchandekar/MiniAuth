package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	// Clear any existing env vars
	os.Clearenv()

	cfg := Load()

	if cfg.Port != 8080 {
		t.Errorf("expected default Port 8080, got %d", cfg.Port)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("expected default Host '0.0.0.0', got %s", cfg.Host)
	}
	if cfg.Environment != "development" {
		t.Errorf("expected default Environment 'development', got %s", cfg.Environment)
	}
	if cfg.Address() != "0.0.0.0:8080" {
		t.Errorf("expected Address '0.0.0.0:8080', got %s", cfg.Address())
	}
	if !cfg.IsDevelopment() {
		t.Errorf("expected IsDevelopment() to be true")
	}

	// Test DB defaults
	if cfg.DB.Host != "localhost" {
		t.Errorf("expected default DB Host 'localhost', got %s", cfg.DB.Host)
	}
	if cfg.DB.Port != 5432 {
		t.Errorf("expected default DB Port 5432, got %d", cfg.DB.Port)
	}
	if cfg.DB.User != "postgres" {
		t.Errorf("expected default DB User 'postgres', got %s", cfg.DB.User)
	}
	if cfg.DB.DBName != "miniauth" {
		t.Errorf("expected default DB Name 'miniauth', got %s", cfg.DB.DBName)
	}
	if !cfg.DB.AutoMigrate {
		t.Errorf("expected default DB AutoMigrate to be true")
	}

	expectedDSN := "postgres://postgres:postgres@localhost:5432/miniauth?sslmode=disable"
	if cfg.DB.DSN() != expectedDSN {
		t.Errorf("expected DSN %s, got %s", expectedDSN, cfg.DB.DSN())
	}
}

func TestLoadDatabaseURL(t *testing.T) {
	os.Clearenv()
	expectedURL := "postgresql://neondb_owner:secret@ep-bold-sound-ay01smo4.c-5.us-east-2.aws.neon.tech/neondb?sslmode=require"
	os.Setenv("DATABASE_URL", expectedURL)
	defer os.Clearenv()

	cfg := Load()

	if cfg.DB.DSN() != expectedURL {
		t.Errorf("expected DSN to match DATABASE_URL %s, got %s", expectedURL, cfg.DB.DSN())
	}
}

func TestLoadCustomEnv(t *testing.T) {
	os.Clearenv()
	os.Setenv("PORT", "9090")
	os.Setenv("HOST", "127.0.0.1")
	os.Setenv("APP_ENV", "production")
	os.Setenv("READ_TIMEOUT", "30s")
	os.Setenv("ISSUER_URL", "https://auth.example.com")
	os.Setenv("DB_HOST", "db.example.com")
	os.Setenv("DB_PORT", "5433")
	os.Setenv("DB_USER", "custom_user")
	os.Setenv("DB_PASSWORD", "secret#pass")
	os.Setenv("DB_NAME", "custom_auth")
	os.Setenv("DB_SSLMODE", "require")
	os.Setenv("DB_AUTO_MIGRATE", "false")
	defer os.Clearenv()

	cfg := Load()

	if cfg.Port != 9090 {
		t.Errorf("expected Port 9090, got %d", cfg.Port)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("expected Host '127.0.0.1', got %s", cfg.Host)
	}
	if cfg.Environment != "production" {
		t.Errorf("expected Environment 'production', got %s", cfg.Environment)
	}
	if cfg.ReadTimeout != 30*time.Second {
		t.Errorf("expected ReadTimeout 30s, got %v", cfg.ReadTimeout)
	}
	if cfg.IssuerURL != "https://auth.example.com" {
		t.Errorf("expected IssuerURL 'https://auth.example.com', got %s", cfg.IssuerURL)
	}
	if cfg.IsDevelopment() {
		t.Errorf("expected IsDevelopment() to be false for production")
	}

	// Test custom DB
	if cfg.DB.Host != "db.example.com" {
		t.Errorf("expected DB Host 'db.example.com', got %s", cfg.DB.Host)
	}
	if cfg.DB.Port != 5433 {
		t.Errorf("expected DB Port 5433, got %d", cfg.DB.Port)
	}
	if cfg.DB.AutoMigrate {
		t.Errorf("expected DB AutoMigrate to be false")
	}
	if cfg.DB.SSLMode != "require" {
		t.Errorf("expected DB SSLMode 'require', got %s", cfg.DB.SSLMode)
	}
}
