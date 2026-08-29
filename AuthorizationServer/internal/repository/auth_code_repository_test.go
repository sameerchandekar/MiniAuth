package repository

import (
	"context"
	"testing"
	"time"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
)

func TestMemoryAuthCodeRepository_CRUD(t *testing.T) {
	repo := NewMemoryAuthCodeRepository()
	ctx := context.Background()

	code := &model.AuthCode{
		Code:                "test-auth-code-123",
		ClientID:            "my-client",
		RedirectURI:         "https://myapp.com/callback",
		Scope:               "openid profile",
		CodeChallenge:       "challenge123",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	// 1. Save
	if err := repo.Save(ctx, code); err != nil {
		t.Fatalf("unexpected save error: %v", err)
	}

	// 2. Get
	fetched, err := repo.Get(ctx, "test-auth-code-123")
	if err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if fetched.ClientID != "my-client" {
		t.Errorf("expected client_id 'my-client', got '%s'", fetched.ClientID)
	}
	if fetched.RedirectURI != "https://myapp.com/callback" {
		t.Errorf("expected redirect_uri 'https://myapp.com/callback', got '%s'", fetched.RedirectURI)
	}

	// 3. Delete
	if err := repo.Delete(ctx, "test-auth-code-123"); err != nil {
		t.Fatalf("unexpected delete error: %v", err)
	}

	// 4. Verify gone
	_, err = repo.Get(ctx, "test-auth-code-123")
	if err != ErrAuthCodeNotFound {
		t.Errorf("expected ErrAuthCodeNotFound after deletion, got %v", err)
	}
}

func TestRedisAuthCodeRepository_Validation(t *testing.T) {
	repo := NewRedisAuthCodeRepository(nil)
	ctx := context.Background()

	// Invalid auth code
	err := repo.Save(ctx, nil)
	if err == nil {
		t.Errorf("expected error when saving nil auth code, got nil")
	}

	err = repo.Save(ctx, &model.AuthCode{Code: ""})
	if err == nil {
		t.Errorf("expected error when saving empty code, got nil")
	}

	// Get with empty code
	_, err = repo.Get(ctx, "")
	if err != ErrAuthCodeNotFound {
		t.Errorf("expected ErrAuthCodeNotFound for empty code, got %v", err)
	}
}
