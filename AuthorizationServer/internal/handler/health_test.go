package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
)

func TestHealthHandler_Healthz(t *testing.T) {
	cfg := &config.Config{Environment: "test"}
	h := NewHealthHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	h.Healthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("expected status 'healthy', got '%s'", resp.Status)
	}
	if resp.Environment != "test" {
		t.Errorf("expected environment 'test', got '%s'", resp.Environment)
	}
}

func TestHealthHandler_Readyz(t *testing.T) {
	cfg := &config.Config{Environment: "test"}
	h := NewHealthHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	h.Readyz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp ReadyResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "ready" {
		t.Errorf("expected status 'ready', got '%s'", resp.Status)
	}
	if resp.Checks["server"] != "up" {
		t.Errorf("expected check 'server' to be 'up', got '%s'", resp.Checks["server"])
	}
}

func TestHealthHandler_Root(t *testing.T) {
	cfg := &config.Config{Environment: "test"}
	h := NewHealthHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	h.Root(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["name"] != "MiniAuth Authorization Server" {
		t.Errorf("unexpected name: %v", resp["name"])
	}
}
