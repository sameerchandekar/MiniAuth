package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sameerchandekar/MiniAuth/ClientService/internal/config"
	"github.com/sameerchandekar/MiniAuth/ClientService/internal/service"
)

func TestOAuthClientHandler_Index(t *testing.T) {
	cfg := &config.Config{
		AuthServerURL: "http://localhost:8080",
		ClientID:      "client-id-001",
		RedirectURI:   "http://localhost:9000/oauth/callback",
		Scopes:        "openid profile email",
	}
	svc := service.NewOAuthClientService(cfg, nil, nil)
	h := NewOAuthClientHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	h.Index(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Login with mini auth") {
		t.Errorf("expected index page to contain 'Login with mini auth'")
	}
	if !strings.Contains(body, "href=\"/login\"") {
		t.Errorf("expected index page to link to '/login'")
	}
}

func TestOAuthClientHandler_Login_Redirect(t *testing.T) {
	cfg := &config.Config{
		AuthServerURL: "http://localhost:8080",
		ClientID:      "client-id-001",
		RedirectURI:   "http://localhost:9000/oauth/callback",
		Scopes:        "openid profile email",
	}
	svc := service.NewOAuthClientService(cfg, nil, nil)
	h := NewOAuthClientHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 Found, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "http://localhost:8080/authorize") {
		t.Errorf("unexpected redirect location: %s", location)
	}
	if !strings.Contains(location, "client_id=client-id-001") {
		t.Errorf("expected redirect location to contain client_id")
	}
	if !strings.Contains(location, "code_challenge_method=S256") {
		t.Errorf("expected redirect location to contain code_challenge_method=S256")
	}
}

func TestOAuthClientHandler_Callback_JSON(t *testing.T) {
	// Mock AuthorizationServer /token endpoint
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(service.TokenResponse{
			AccessToken:  "at_test_callback_123",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "rt_test_callback_456",
		})
	}))
	defer mockServer.Close()

	cfg := &config.Config{
		AuthServerURL: mockServer.URL,
		ClientID:      "client-id-001",
		RedirectURI:   "http://localhost:9000/oauth/callback",
		Scopes:        "email",
	}
	stateStore := service.NewMemoryStateStore()
	svc := service.NewOAuthClientService(cfg, stateStore, mockServer.Client())
	h := NewOAuthClientHandler(svc)

	// Initiate login to set state in stateStore
	_, state, err := svc.BuildAuthorizeURL(context.Background())
	if err != nil {
		t.Fatalf("failed to build auth url: %v", err)
	}

	// Trigger callback with json format requested
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=mock_code_123&state="+state+"&format=json", nil)
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var resp service.TokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.AccessToken != "at_test_callback_123" {
		t.Errorf("expected access_token 'at_test_callback_123', got '%s'", resp.AccessToken)
	}
	if resp.RefreshToken != "rt_test_callback_456" {
		t.Errorf("expected refresh_token 'rt_test_callback_456', got '%s'", resp.RefreshToken)
	}
}
