package server

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/config"
	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/middleware"
)

func generateKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA test key: %v", err)
	}
	return privKey, &privKey.PublicKey
}

func createTestToken(t *testing.T, privKey *rsa.PrivateKey, sub, scope string) string {
	t.Helper()
	claims := middleware.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "http://localhost:8080",
			Subject:   sub,
			Audience:  jwt.ClaimStrings{"client-id-001"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		ClientID: "client-id-001",
		Scope:    scope,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"

	tokenStr, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenStr
}

func TestRouter_Endpoints(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	cfg := config.Load()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := SetupRouter(cfg, pubKey, logger)

	readOnlyToken := createTestToken(t, privKey, "user-001", "openid profile email read")
	writeToken := createTestToken(t, privKey, "user-001", "openid read write")

	tests := []struct {
		name       string
		method     string
		path       string
		token      string
		wantStatus int
	}{
		{"Healthz Probe", http.MethodGet, "/healthz", "", http.StatusOK},
		{"Swagger UI", http.MethodGet, "/swagger", "", http.StatusOK},
		{"OpenAPI Spec", http.MethodGet, "/swagger/openapi.yaml", "", http.StatusOK},
		{"GET Emails with No Auth -> 401", http.MethodGet, "/api/v1/emails", "", http.StatusUnauthorized},
		{"GET Emails with Read Scope -> 200", http.MethodGet, "/api/v1/emails", readOnlyToken, http.StatusOK},
		{"POST Emails with Read-Only Scope -> 403 Forbidden", http.MethodPost, "/api/v1/emails", readOnlyToken, http.StatusForbidden},
		{"POST Emails with Write Scope -> 400 (Bad payload but Authorized)", http.MethodPost, "/api/v1/emails", writeToken, http.StatusBadRequest},
		{"Userinfo with Valid Token -> 200", http.MethodGet, "/api/v1/userinfo", readOnlyToken, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d for %s %s", tt.wantStatus, rec.Code, tt.method, tt.path)
			}
		})
	}
}
