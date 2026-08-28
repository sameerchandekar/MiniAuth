package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/repository"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/service"
)

func newTestOAuthHandler() *OAuthHandler {
	clientRepo := repository.NewMemoryClientRepository()
	authCodeRepo := repository.NewMemoryAuthCodeRepository()
	svc := service.NewOAuthService(clientRepo, authCodeRepo)
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
	params.Set("code_challenge", "E9Melhoa2OwvFrGMTJguCH5ZwKRKg5UPn2dAwdDlvue8j52hRqwc7z39P8w")
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
