package database

import (
	"testing"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
)

func TestNewRedisClient_Valid(t *testing.T) {
	cfg := config.RedisConfig{
		Addr:     "localhost:6379",
		Username: "default",
		Password: "secretpassword",
		DB:       1,
	}

	client, err := NewRedisClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating redis client: %v", err)
	}
	defer client.Close()

	opts := client.Options()
	if opts.Addr != "localhost:6379" {
		t.Errorf("expected Addr 'localhost:6379', got %s", opts.Addr)
	}
	if opts.Username != "default" {
		t.Errorf("expected Username 'default', got %s", opts.Username)
	}
	if opts.Password != "secretpassword" {
		t.Errorf("expected Password 'secretpassword', got %s", opts.Password)
	}
	if opts.DB != 1 {
		t.Errorf("expected DB 1, got %d", opts.DB)
	}
}

func TestNewRedisClient_FromURL(t *testing.T) {
	cfg := config.RedisConfig{
		URL: "redis://default:cloudpass@fulgent-jump-maroon-88822.db.redis.io:14418/2",
	}

	client, err := NewRedisClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating redis client from URL: %v", err)
	}
	defer client.Close()

	opts := client.Options()
	if opts.Addr != "fulgent-jump-maroon-88822.db.redis.io:14418" {
		t.Errorf("expected Addr 'fulgent-jump-maroon-88822.db.redis.io:14418', got %s", opts.Addr)
	}
	if opts.Username != "default" {
		t.Errorf("expected Username 'default', got %s", opts.Username)
	}
	if opts.Password != "cloudpass" {
		t.Errorf("expected Password 'cloudpass', got %s", opts.Password)
	}
	if opts.DB != 2 {
		t.Errorf("expected DB 2, got %d", opts.DB)
	}
}

func TestNewRedisClient_InvalidURL(t *testing.T) {
	cfg := config.RedisConfig{
		URL: "://invalid-redis-url",
	}

	_, err := NewRedisClient(cfg)
	if err == nil {
		t.Errorf("expected error with invalid URL, got nil")
	}
}
