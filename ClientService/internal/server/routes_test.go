package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sameerchandekar/MiniAuth/ClientService/internal/config"
)

func TestRouterEndpoints(t *testing.T) {
	cfg := config.Load()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := SetupRouter(cfg, nil, logger)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"Landing Page", http.MethodGet, "/", http.StatusOK},
		{"Login Redirect", http.MethodGet, "/login", http.StatusFound},
		{"Healthz Probe", http.MethodGet, "/healthz", http.StatusOK},
		{"Not Found Route", http.MethodGet, "/unknown-route", http.StatusNotFound},
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
