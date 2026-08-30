package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/config"
)

func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA test key: %v", err)
	}
	return privKey, &privKey.PublicKey
}

func signTestJWT(t *testing.T, privKey *rsa.PrivateKey, sub, scope string) string {
	t.Helper()
	claims := JWTClaims{
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
	token.Header["kid"] = "test-key-id"

	tokenStr, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}
	return tokenStr
}

func TestAuthMiddleware_ScopeReadAllowedWriteDenied(t *testing.T) {
	privKey, pubKey := generateTestKeyPair(t)
	cfg := &config.Config{
		IssuerURL: "http://localhost:8080",
	}

	authMw := NewAuthMiddleware(cfg, pubKey, nil)

	// Create test handlers
	readHandler := authMw.Authenticate(RequireScope("read", "email", "read:email")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"read_ok"}`))
	})))

	writeHandler := authMw.Authenticate(RequireScope("write", "write:email")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"status":"email_created"}`))
	})))

	// Token with only 'read' scope
	readOnlyToken := signTestJWT(t, privKey, "user-001", "openid profile email read")

	// 1. GET /emails with 'read' scope -> MUST SUCCEED (200 OK)
	reqRead := httptest.NewRequest(http.MethodGet, "/api/v1/emails", nil)
	reqRead.Header.Set("Authorization", "Bearer "+readOnlyToken)
	recRead := httptest.NewRecorder()

	readHandler.ServeHTTP(recRead, reqRead)

	if recRead.Code != http.StatusOK {
		t.Errorf("expected 200 OK for read endpoint with read scope, got %d", recRead.Code)
	}

	// 2. POST /emails with 'read' scope -> MUST BE DENIED (403 Forbidden)
	reqWrite := httptest.NewRequest(http.MethodPost, "/api/v1/emails", nil)
	reqWrite.Header.Set("Authorization", "Bearer "+readOnlyToken)
	recWrite := httptest.NewRecorder()

	writeHandler.ServeHTTP(recWrite, reqWrite)

	if recWrite.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for write endpoint with only read scope, got %d", recWrite.Code)
	}

	// 3. Token with 'write' scope -> MUST SUCCEED on write endpoint (201 Created)
	writeToken := signTestJWT(t, privKey, "user-001", "openid read write")
	reqWriteValid := httptest.NewRequest(http.MethodPost, "/api/v1/emails", nil)
	reqWriteValid.Header.Set("Authorization", "Bearer "+writeToken)
	recWriteValid := httptest.NewRecorder()

	writeHandler.ServeHTTP(recWriteValid, reqWriteValid)

	if recWriteValid.Code != http.StatusCreated {
		t.Errorf("expected 201 Created for write endpoint with write scope, got %d", recWriteValid.Code)
	}
}

func TestAuthMiddleware_MissingOrInvalidToken(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	cfg := &config.Config{
		IssuerURL: "http://localhost:8080",
	}

	authMw := NewAuthMiddleware(cfg, pubKey, nil)
	handler := authMw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Missing header -> 401 Unauthorized
	req := httptest.NewRequest(http.MethodGet, "/api/v1/emails", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for missing token, got %d", rec.Code)
	}

	// Invalid signature -> 401 Unauthorized
	reqInvalid := httptest.NewRequest(http.MethodGet, "/api/v1/emails", nil)
	reqInvalid.Header.Set("Authorization", "Bearer invalid.jwt.signature")
	recInvalid := httptest.NewRecorder()
	handler.ServeHTTP(recInvalid, reqInvalid)

	if recInvalid.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for invalid token, got %d", recInvalid.Code)
	}
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	privKey, pubKey := generateTestKeyPair(t)
	cfg := &config.Config{
		IssuerURL: "http://localhost:8080",
	}

	authMw := NewAuthMiddleware(cfg, pubKey, nil)
	handler := authMw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Generate an already-expired token (expired 10 minutes ago)
	claims := JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "http://localhost:8080",
			Subject:   "user-001",
			Audience:  jwt.ClaimStrings{"client-id-001"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-20 * time.Minute)),
		},
		ClientID: "client-id-001",
		Scope:    "read email",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	expiredTokenStr, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign expired token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/emails", nil)
	req.Header.Set("Authorization", "Bearer "+expiredTokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for expired token, got %d", rec.Code)
	}
}

