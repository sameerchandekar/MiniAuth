package handler

import (
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

func newTestOAuthHandler() *OAuthHandler {
	clientRepo := repository.NewMemoryClientRepository()
	authCodeRepo := repository.NewMemoryAuthCodeRepository()
	refreshTokenRepo := repository.NewMemoryRefreshTokenRepository()
	svc := service.NewOAuthService(clientRepo, authCodeRepo, refreshTokenRepo, nil)
	return NewOAuthHandler(svc)
}

func TestOAuthHandler_Authorize_RedirectWithParams(t *testing.T) {
	h := newTestOAuthHandler()

	params := url.Values{}
	params.Set("client_id", "my-client-123")
	params.Set("redirect_uri", "https://myapp.com/oauth/callback")
	params.Set("response_type", "code")
	params.Set("scope", "openid profile email")
	params.Set("state", "abc123")
	params.Set("code_challenge", "E9Melhoa2OwvFrGMTJguCH5ZwKRKg5UPn2dAwdDlvue")
	params.Set("code_challenge_method", "S256")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	// Verify HTTP 302 Found
	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}

	// Verify Location header
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

func TestOAuthHandler_Authorize_FallbackRedirect(t *testing.T) {
	h := newTestOAuthHandler()

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "https://myapp.com/oauth/callback") {
		t.Errorf("unexpected location: %s", location)
	}

	locURL, _ := url.Parse(location)
	q := locURL.Query()
	if q.Get("code") == "" {
		t.Errorf("expected code in redirect, got empty")
	}
}

func TestOAuthHandler_Token_FormURLEncoded(t *testing.T) {
	clientRepo := repository.NewMemoryClientRepository()
	authCodeRepo := repository.NewMemoryAuthCodeRepository()
	refreshTokenRepo := repository.NewMemoryRefreshTokenRepository()
	svc := service.NewOAuthService(clientRepo, authCodeRepo, refreshTokenRepo, nil)
	h := NewOAuthHandler(svc)

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
	h := NewOAuthHandler(svc)

	authRes, err := svc.Authorize(t.Context(), model.AuthorizeRequest{
		ClientID:    "my-client-123",
		RedirectURI: "https://myapp.com/oauth/callback",
	})
	if err != nil {
		t.Fatalf("failed to authorize: %v", err)
	}

	body := `{"grant_type":"authorization_code","code":"` + authRes.Code + `","redirect_uri":"https://myapp.com/oauth/callback","client_id":"my-client-123"}`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp model.TokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Errorf("expected access token to be present")
	}
}

func TestOAuthHandler_Token_InvalidGrant(t *testing.T) {
	h := newTestOAuthHandler()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "invalid-non-existent-code")
	form.Set("redirect_uri", "https://myapp.com/oauth/callback")
	form.Set("client_id", "my-client-123")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 Bad Request, got %d", rec.Code)
	}

	var errResp model.OAuthErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Error != "invalid_grant" {
		t.Errorf("expected error 'invalid_grant', got '%s'", errResp.Error)
	}
}
