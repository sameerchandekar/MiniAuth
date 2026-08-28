package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	os.Clearenv()
	cfg := Load()

	if cfg.Port != 8081 {
		t.Errorf("expected default Port 8081, got %d", cfg.Port)
	}
	if cfg.Address() != "0.0.0.0:8081" {
		t.Errorf("expected Address '0.0.0.0:8081', got %s", cfg.Address())
	}
}

func TestLoadDatabaseURL(t *testing.T) {
	os.Clearenv()
	expectedURL := "postgresql://neondb_owner:secret@ep-bold.aws.neon.tech/neondb?sslmode=require"
	os.Setenv("DATABASE_URL", expectedURL)
	defer os.Clearenv()

	cfg := Load()
	if cfg.DB.DSN() != expectedURL {
		t.Errorf("expected %s, got %s", expectedURL, cfg.DB.DSN())
	}
}
