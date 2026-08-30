package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/repository"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/service"
)

func newTestOAuthHandler() (*OAuthHandler, service.AuthService, service.SessionStore) {
	clientRepo := repository.NewMemoryClientRepository()
	authCodeRepo := repository.NewMemoryAuthCodeRepository()
	refreshTokenRepo := repository.NewMemoryRefreshTokenRepository()
	sessionStore := service.NewMemorySessionStore()
	authService := service.NewAuthService(nil, sessionStore)
	svc := service.NewOAuthService(clientRepo, authCodeRepo, refreshTokenRepo, nil)
	return NewOAuthHandler(svc, authService), authService, sessionStore
}

func TestOAuthHandler_Authorize_UnauthenticatedRedirectsToLogin(t *testing.T) {
	h, _, _ := newTestOAuthHandler()

	params := url.Values{}
	params.Set("client_id", "my-client-123")
	params.Set("redirect_uri", "https://myapp.com/oauth/callback")
	params.Set("response_type", "code")
	params.Set("scope", "openid profile email")
	params.Set("state", "abc123")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	// Verify HTTP 302 Found redirect to /login
	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "/login?return_to=") {
		t.Errorf("expected redirect to /login?return_to=..., got '%s'", location)
	}
	if !strings.Contains(location, "client_id%3Dmy-client-123") && !strings.Contains(location, "client_id=my-client-123") {
		t.Errorf("expected original query params preserved in return_to")
	}
}

func TestOAuthHandler_Authorize_AuthenticatedWithCookie(t *testing.T) {
	h, authService, _ := newTestOAuthHandler()

	// Pre-create authenticated user session
	user := &service.UserInfo{ID: "user-001", Email: "user@example.com"}
	sess, err := authService.CreateSession(context.Background(), user, 0)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	params := url.Values{}
	params.Set("client_id", "my-client-123")
	params.Set("redirect_uri", "https://myapp.com/oauth/callback")
	params.Set("response_type", "code")
	params.Set("scope", "openid profile email")
	params.Set("state", "abc123")
	params.Set("code_challenge", "E9Melhoa2OwvFrGMTJguCH5ZwKRKg5UPn2dAwdDlvue")
	params.Set("code_challenge_method", "S256")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sess.SessionID})
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	// Verify HTTP 302 Found redirect to client callback
	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "https://myapp.com/oauth/callback") {
		t.Errorf("unexpected location: %s", location)
	}

	locURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect location: %v", err)
	}

	q := locURL.Query()
	if q.Get("state") != "abc123" {
		t.Errorf("expected state 'abc123', got '%s'", q.Get("state"))
	}
	if q.Get("code") == "" {
		t.Errorf("expected code to be present in redirect query")
	}
}

func TestOAuthHandler_Token_FormURLEncoded(t *testing.T) {
	clientRepo := repository.NewMemoryClientRepository()
	authCodeRepo := repository.NewMemoryAuthCodeRepository()
	refreshTokenRepo := repository.NewMemoryRefreshTokenRepository()
	svc := service.NewOAuthService(clientRepo, authCodeRepo, refreshTokenRepo, nil)
	sessionStore := service.NewMemorySessionStore()
	authService := service.NewAuthService(nil, sessionStore)
	h := NewOAuthHandler(svc, authService)

	// Pre-seed an auth code
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authRes, err := svc.Authorize(t.Context(), model.AuthorizeRequest{
		ClientID:            "my-client-123",
		RedirectURI:         "https://myapp.com/oauth/callback",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("failed to authorize: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", authRes.Code)
	form.Set("redirect_uri", "https://myapp.com/oauth/callback")
	form.Set("client_id", "my-client-123")
	form.Set("code_verifier", codeVerifier)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp model.TokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}

	if resp.AccessToken == "" {
		t.Errorf("expected non-empty access_token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token_type 'Bearer', got '%s'", resp.TokenType)
	}
	if resp.RefreshToken == "" {
		t.Errorf("expected non-empty refresh_token")
	}
}

func TestOAuthHandler_Token_JSON(t *testing.T) {
	clientRepo := repository.NewMemoryClientRepository()
	authCodeRepo := repository.NewMemoryAuthCodeRepository()
	refreshTokenRepo := repository.NewMemoryRefreshTokenRepository()
	svc := service.NewOAuthService(clientRepo, authCodeRepo, refreshTokenRepo, nil)
	sessionStore := service.NewMemorySessionStore()
	authService := service.NewAuthService(nil, sessionStore)
	h := NewOAuthHandler(svc, authService)

	authRes, err := svc.Authorize(t.Context(), model.AuthorizeRequest{
		ClientID:    "my-client-123",
		RedirectURI: "https://myapp.com/oauth/callback",
	})
	if err != nil {
		t.Fatalf("failed to authorize: %v", err)
	}

	payload := map[string]string{
		"grant_type":   "authorization_code",
		"code":         authRes.Code,
		"redirect_uri": "https://myapp.com/oauth/callback",
		"client_id":    "my-client-123",
	}
	jsonBody, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(string(jsonBody)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", rec.Code)
	}
}
