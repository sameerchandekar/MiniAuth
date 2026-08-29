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
	if cfg.Redis.Addr != "localhost:6379" {
		t.Errorf("expected Redis Addr 'localhost:6379', got %s", cfg.Redis.Addr)
	}
	if cfg.Redis.DB != 0 {
		t.Errorf("expected Redis DB 0, got %d", cfg.Redis.DB)
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

func TestLoadRedisURL(t *testing.T) {
	os.Clearenv()
	expectedURL := "redis://default:mFv3SaTNgsbycjmItIMKgpRbo3jEitxL@fulgent-jump-maroon-88822.db.redis.io:14418/0"
	os.Setenv("REDIS_URL", expectedURL)
	defer os.Clearenv()

	cfg := Load()
	if cfg.Redis.URL != expectedURL {
		t.Errorf("expected Redis URL %s, got %s", expectedURL, cfg.Redis.URL)
	}

	opts, err := cfg.Redis.ClientOptions()
	if err != nil {
		t.Fatalf("unexpected error parsing redis options: %v", err)
	}
	if opts.Addr != "fulgent-jump-maroon-88822.db.redis.io:14418" {
		t.Errorf("expected Redis Addr 'fulgent-jump-maroon-88822.db.redis.io:14418', got %s", opts.Addr)
	}
	if opts.Username != "default" {
		t.Errorf("expected Redis Username 'default', got %s", opts.Username)
	}
	if opts.Password != "mFv3SaTNgsbycjmItIMKgpRbo3jEitxL" {
		t.Errorf("expected Redis Password 'mFv3SaTNgsbycjmItIMKgpRbo3jEitxL', got %s", opts.Password)
	}
}
