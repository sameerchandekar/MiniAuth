package service

import (
	"context"
	"testing"
	"time"
)

func TestAuthService_Authenticate_DemoUsers(t *testing.T) {
	sessionStore := NewMemorySessionStore()
	authSvc := NewAuthService(nil, sessionStore)
	ctx := context.Background()

	t.Run("Valid demo user credentials succeed", func(t *testing.T) {
		user, err := authSvc.Authenticate(ctx, "user-001", "password")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if user.ID != "user-001" {
			t.Errorf("expected ID 'user-001', got '%s'", user.ID)
		}
	})

	t.Run("Wrong password returns ErrInvalidCredentials", func(t *testing.T) {
		_, err := authSvc.Authenticate(ctx, "user-001", "wrong_password")
		if err != ErrInvalidCredentials {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("Create and Validate Session", func(t *testing.T) {
		user := &UserInfo{
			ID:    "user-001",
			Email: "user001@example.com",
			Name:  "Demo User",
		}

		sess, err := authSvc.CreateSession(ctx, user, 1*time.Hour)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
		if sess.SessionID == "" {
			t.Errorf("expected non-empty session ID")
		}

		retrieved, err := authSvc.ValidateSession(ctx, sess.SessionID)
		if err != nil {
			t.Fatalf("failed to validate session: %v", err)
		}
		if retrieved.UserID != "user-001" {
			t.Errorf("expected user ID 'user-001', got '%s'", retrieved.UserID)
		}

		// Revoke session
		err = authSvc.RevokeSession(ctx, sess.SessionID)
		if err != nil {
			t.Fatalf("failed to revoke session: %v", err)
		}

		_, err = authSvc.ValidateSession(ctx, sess.SessionID)
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound after revocation, got %v", err)
		}
	})
}
