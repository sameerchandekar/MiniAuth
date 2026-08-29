package service

import (
	"context"
	"testing"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/repository"
)

func TestOAuthService_Authorize_Success(t *testing.T) {
	clientRepo := repository.NewMemoryClientRepository()
	authCodeRepo := repository.NewMemoryAuthCodeRepository()
	svc := NewOAuthService(clientRepo, authCodeRepo)

	req := model.AuthorizeRequest{
		ClientID:            "my-client-123",
		RedirectURI:         "https://myapp.com/oauth/callback",
		ResponseType:        "code",
		Scope:               "openid profile email",
		State:               "xyz789",
		CodeChallenge:       "E9Melhoa2OwvFrGMTJguCH5ZwKRKg5UPn2dAwdDlvue8j52hRqwc7z39P8w",
		CodeChallengeMethod: "S256",
	}

	res, err := svc.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.State != "xyz789" {
		t.Errorf("expected state 'xyz789', got '%s'", res.State)
	}
	if res.Code == "" {
		t.Errorf("expected non-empty code")
	}

	// Verify code was stored in repository
	saved, err := authCodeRepo.Get(context.Background(), res.Code)
	if err != nil {
		t.Fatalf("failed to retrieve saved auth code: %v", err)
	}
	if saved.ClientID != "my-client-123" {
		t.Errorf("expected client_id 'my-client-123', got '%s'", saved.ClientID)
	}
	if saved.CodeChallengeMethod != "S256" {
		t.Errorf("expected code_challenge_method 'S256', got '%s'", saved.CodeChallengeMethod)
	}
}

func TestOAuthService_Authorize_ScopeValidation(t *testing.T) {
	clientRepo := repository.NewMemoryClientRepository()
	authCodeRepo := repository.NewMemoryAuthCodeRepository()
	svc := NewOAuthService(clientRepo, authCodeRepo)

	req := model.AuthorizeRequest{
		ClientID:    "my-client-123",
		RedirectURI: "https://myapp.com/oauth/callback",
		Scope:       "openid unauthorized_super_scope",
	}

	_, err := svc.Authorize(context.Background(), req)
	if err != ErrScopeNotAllowed {
		t.Errorf("expected ErrScopeNotAllowed, got %v", err)
	}
}

func TestOAuthService_Authorize_RedirectURIValidation(t *testing.T) {
	clientRepo := repository.NewMemoryClientRepository()
	authCodeRepo := repository.NewMemoryAuthCodeRepository()
	svc := NewOAuthService(clientRepo, authCodeRepo)

	t.Run("unregistered redirect URI returns error", func(t *testing.T) {
		req := model.AuthorizeRequest{
			ClientID:    "my-client-123",
			RedirectURI: "https://attacker.com/evil/callback",
			Scope:       "openid",
		}

		_, err := svc.Authorize(context.Background(), req)
		if err != ErrInvalidRedirectURI {
			t.Errorf("expected ErrInvalidRedirectURI, got %v", err)
		}
	})

	t.Run("valid registered redirect URI succeeds", func(t *testing.T) {
		req := model.AuthorizeRequest{
			ClientID:    "my-client-123",
			RedirectURI: "http://localhost:3000/callback",
			Scope:       "openid",
		}

		res, err := svc.Authorize(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error for valid redirect URI: %v", err)
		}
		if res.RedirectURI != "http://localhost:3000/callback" {
			t.Errorf("expected redirect URI 'http://localhost:3000/callback', got '%s'", res.RedirectURI)
		}
	})
}
