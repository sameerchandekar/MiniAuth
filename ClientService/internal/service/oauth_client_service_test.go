package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sameerchandekar/MiniAuth/ClientService/internal/config"
)

func TestOAuthClientService_BuildAuthorizeURL(t *testing.T) {
	cfg := &config.Config{
		AuthServerURL: "http://localhost:8080",
		ClientID:      "client-id-001",
		RedirectURI:   "http://localhost:9000/oauth/callback",
		Scopes:        "openid profile email",
	}
	stateStore := NewMemoryStateStore()
	svc := NewOAuthClientService(cfg, stateStore, nil)

	authURL, state, err := svc.BuildAuthorizeURL(context.Background())
	if err != nil {
		t.Fatalf("unexpected error building authorize URL: %v", err)
	}

	if state == "" {
		t.Errorf("expected non-empty state")
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse generated auth URL: %v", err)
	}

	q := u.Query()
	if q.Get("client_id") != "client-id-001" {
		t.Errorf("expected client_id 'client-id-001', got '%s'", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "http://localhost:9000/oauth/callback" {
		t.Errorf("expected redirect_uri 'http://localhost:9000/oauth/callback', got '%s'", q.Get("redirect_uri"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("expected code_challenge_method 'S256', got '%s'", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" {
		t.Errorf("expected code_challenge to be present")
	}

	// Verify state was saved in stateStore
	saved, err := stateStore.GetAndDeleteState(context.Background(), state)
	if err != nil {
		t.Fatalf("expected state to be saved in store: %v", err)
	}
	if saved.CodeVerifier == "" {
		t.Errorf("expected code_verifier to be stored")
	}
}

func TestOAuthClientService_ExchangeCodeForToken_StateVerificationAndDeletion(t *testing.T) {
	// Mock AuthorizationServer /token endpoint
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()

		if r.FormValue("grant_type") != "authorization_code" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}
		if r.FormValue("code") != "valid_mock_code" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		if r.FormValue("code_verifier") == "" {
			http.Error(w, `{"error":"missing_verifier"}`, http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "at_test_12345",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "rt_test_67890",
		})
	}))
	defer mockServer.Close()

	cfg := &config.Config{
		AuthServerURL: mockServer.URL,
		ClientID:      "client-id-001",
		RedirectURI:   "http://localhost:9000/oauth/callback",
		Scopes:        "openid profile email",
	}
	stateStore := NewMemoryStateStore()
	svc := NewOAuthClientService(cfg, stateStore, mockServer.Client())

	// 1. Build auth URL which saves state to stateStore
	_, state, err := svc.BuildAuthorizeURL(context.Background())
	if err != nil {
		t.Fatalf("failed to build auth URL: %v", err)
	}

	// 2. Exchange code with valid state -> Should succeed
	tokenRes, err := svc.ExchangeCodeForToken(context.Background(), "valid_mock_code", state)
	if err != nil {
		t.Fatalf("unexpected error exchanging code: %v", err)
	}

	if tokenRes.AccessToken != "at_test_12345" {
		t.Errorf("expected access_token 'at_test_12345', got '%s'", tokenRes.AccessToken)
	}
	if tokenRes.RefreshToken != "rt_test_67890" {
		t.Errorf("expected refresh_token 'rt_test_67890', got '%s'", tokenRes.RefreshToken)
	}

	// 3. Re-using the same state -> MUST fail because state was deleted from store (single-use anti-replay)
	_, err = svc.ExchangeCodeForToken(context.Background(), "valid_mock_code", state)
	if err != ErrInvalidState {
		t.Errorf("expected ErrInvalidState when re-using state, got %v", err)
	}

	// 4. Using an unknown state -> MUST fail
	_, err = svc.ExchangeCodeForToken(context.Background(), "valid_mock_code", "completely_unknown_state_id")
	if err != ErrInvalidState {
		t.Errorf("expected ErrInvalidState for unknown state, got %v", err)
	}
}

func TestMemoryStateStore_Expiry(t *testing.T) {
	store := NewMemoryStateStore()
	ctx := context.Background()

	// Save with negative TTL to simulate expiration
	_ = store.SaveState(ctx, "expired_state", &StateData{
		State:        "expired_state",
		CodeVerifier: "some_verifier",
		CreatedAt:    time.Now().Add(-1 * time.Hour),
	}, -1*time.Minute)

	_, err := store.GetAndDeleteState(ctx, "expired_state")
	if err != ErrInvalidState {
		t.Errorf("expected ErrInvalidState for expired state, got %v", err)
	}
}
