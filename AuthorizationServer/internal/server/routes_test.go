package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
)

func TestRouterEndpoints(t *testing.T) {
	cfg := config.Load()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := SetupRouter(cfg, nil, nil, logger)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"Root endpoint", http.MethodGet, "/", http.StatusOK},
		{"Healthz endpoint", http.MethodGet, "/healthz", http.StatusOK},
		{"Readyz endpoint", http.MethodGet, "/readyz", http.StatusOK},
		{"Login page endpoint", http.MethodGet, "/login", http.StatusOK},
		{"Logout endpoint", http.MethodGet, "/logout", http.StatusFound},
		{"Authorize endpoint unauthenticated redirects to login", http.MethodGet, "/authorize?redirect_uri=https://myapp.com/callback&state=test", http.StatusFound},
		{"OAuth Authorize endpoint unauthenticated redirects to login", http.MethodGet, "/oauth/authorize?redirect_uri=https://myapp.com/callback&state=test", http.StatusFound},
		{"Token endpoint invalid grant", http.MethodPost, "/token", http.StatusBadRequest},
		{"OAuth Token endpoint invalid grant", http.MethodPost, "/oauth/token", http.StatusBadRequest},
		{"JWKS endpoint", http.MethodGet, "/.well-known/jwks.json", http.StatusOK},
		{"OAuth JWKS endpoint", http.MethodGet, "/oauth/.well-known/jwks.json", http.StatusOK},
		{"Not found endpoint", http.MethodGet, "/unknown-endpoint", http.StatusNotFound},
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
