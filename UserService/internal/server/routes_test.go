package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/config"
)

func TestRouterRoutes(t *testing.T) {
	cfg := config.Load()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := SetupRouter(cfg, nil, logger)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"Swagger UI", http.MethodGet, "/swagger", http.StatusOK},
		{"Swagger doc.json", http.MethodGet, "/swagger/doc.json", http.StatusOK},
		{"Healthz", http.MethodGet, "/healthz", http.StatusOK},
		{"Readyz with nil DB", http.MethodGet, "/readyz", http.StatusOK},
		{"Root redirects to Swagger", http.MethodGet, "/", http.StatusMovedPermanently},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d for %s", tt.wantStatus, rec.Code, tt.path)
			}
		})
	}
}
