package handler

import (
	"database/sql"
	"net/http"
	"time"
)

// HealthHandler handles health check probes.
type HealthHandler struct {
	db        *sql.DB
	startTime time.Time
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(db *sql.DB) *HealthHandler {
	return &HealthHandler{
		db:        db,
		startTime: time.Now(),
	}
}

// Healthz handles GET /healthz (liveness probe).
func (h *HealthHandler) Healthz(w http.ResponseWriter, r *http.Request) {
	renderJSON(w, http.StatusOK, map[string]any{
		"status":    "healthy",
		"service":   "MiniAuth-UserService",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(h.startTime).Truncate(time.Millisecond).String(),
	})
}

// Readyz handles GET /readyz (readiness probe).
func (h *HealthHandler) Readyz(w http.ResponseWriter, r *http.Request) {
	dbStatus := "up"
	if h.db != nil {
		if err := h.db.PingContext(r.Context()); err != nil {
			dbStatus = "down"
		}
	}

	status := http.StatusOK
	if dbStatus != "up" {
		status = http.StatusServiceUnavailable
	}

	renderJSON(w, status, map[string]any{
		"status": map[string]string{
			"database": dbStatus,
			"server":   "up",
		},
	})
}
