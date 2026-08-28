package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
)

// HealthHandler handles liveness and readiness probe requests.
type HealthHandler struct {
	cfg       *config.Config
	startTime time.Time
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(cfg *config.Config) *HealthHandler {
	return &HealthHandler{
		cfg:       cfg,
		startTime: time.Now(),
	}
}

// HealthResponse represents the health endpoint JSON payload.
type HealthResponse struct {
	Status      string `json:"status"`
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Timestamp   string `json:"timestamp"`
	Uptime      string `json:"uptime"`
}

// ReadyResponse represents the readiness probe payload.
type ReadyResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

// Healthz responds with a 200 OK and basic service health details.
func (h *HealthHandler) Healthz(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status:      "healthy",
		Service:     "MiniAuth-AuthorizationServer",
		Environment: h.cfg.Environment,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Uptime:      time.Since(h.startTime).Truncate(time.Millisecond).String(),
	}

	writeJSON(w, http.StatusOK, resp)
}

// Readyz responds with a 200 OK when ready to accept traffic.
func (h *HealthHandler) Readyz(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{
		"server": "up",
	}

	resp := ReadyResponse{
		Status: "ready",
		Checks: checks,
	}

	writeJSON(w, http.StatusOK, resp)
}

// Root provides basic service information.
func (h *HealthHandler) Root(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"name":        "MiniAuth Authorization Server",
		"version":     "0.1.0",
		"description": "OAuth 2.0 & OpenID Connect (OIDC) Identity Provider",
		"docs":        "/.well-known/openid-configuration",
		"status":      "running",
	}

	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
