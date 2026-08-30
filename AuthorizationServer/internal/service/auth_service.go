package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid user identifier or password")
	ErrUserNotFound       = errors.New("user not found")
)

// UserInfo represents an authenticated identity.
type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// AuthService defines user authentication and session operations.
type AuthService interface {
	Authenticate(ctx context.Context, identifier, password string) (*UserInfo, error)
	CreateSession(ctx context.Context, user *UserInfo, ttl time.Duration) (*SessionData, error)
	ValidateSession(ctx context.Context, sessionID string) (*SessionData, error)
	RevokeSession(ctx context.Context, sessionID string) error
}

// DefaultAuthService implements AuthService.
type DefaultAuthService struct {
	db           *sql.DB
	sessionStore SessionStore
}

// NewAuthService creates a new DefaultAuthService.
func NewAuthService(db *sql.DB, sessionStore SessionStore) *DefaultAuthService {
	if sessionStore == nil {
		sessionStore = NewMemorySessionStore()
	}
	return &DefaultAuthService{
		db:           db,
		sessionStore: sessionStore,
	}
}

// Authenticate verifies user credentials against the PostgreSQL database or demo fallback users.
func (s *DefaultAuthService) Authenticate(ctx context.Context, identifier, password string) (*UserInfo, error) {
	ident := strings.TrimSpace(identifier)
	pwd := strings.TrimSpace(password)

	if ident == "" || pwd == "" {
		return nil, ErrInvalidCredentials
	}

	// 1. Try querying PostgreSQL database if available
	if s.db != nil {
		query := `
			SELECT id, name, email, password_hash 
			FROM users 
			WHERE email = $1 OR id::text = $1 
			LIMIT 1
		`
		var id, name, email, pwdHash string
		err := s.db.QueryRowContext(ctx, query, ident).Scan(&id, &name, &email, &pwdHash)
		if err == nil {
			if bcryptErr := bcrypt.CompareHashAndPassword([]byte(pwdHash), []byte(pwd)); bcryptErr == nil {
				return &UserInfo{
					ID:    id,
					Email: email,
					Name:  name,
				}, nil
			}
			// If password does not match hash, return error
			return nil, ErrInvalidCredentials
		}
	}

	// 2. Demo / Fallback authentication for quickstart & testing
	// Allows testing without pre-seeding the users table
	demoUsers := map[string]struct {
		ID       string
		Email    string
		Name     string
		Password string
	}{
		"user-001": {ID: "user-001", Email: "user001@example.com", Name: "Demo User 001", Password: "password"},
		"user":     {ID: "user-001", Email: "user@example.com", Name: "Standard User", Password: "password123"},
		"admin":    {ID: "admin-001", Email: "admin@example.com", Name: "Administrator", Password: "password123"},
	}

	if user, exists := demoUsers[ident]; exists {
		if user.Password == pwd {
			return &UserInfo{
				ID:    user.ID,
				Email: user.Email,
				Name:  user.Name,
			}, nil
		}
		return nil, ErrInvalidCredentials
	}

	// Accept any user ID if password is "password" or "password123" for dynamic demo testing
	if pwd == "password" || pwd == "password123" {
		return &UserInfo{
			ID:    ident,
			Email: fmt.Sprintf("%s@example.com", ident),
			Name:  strings.Title(ident),
		}, nil
	}

	return nil, ErrInvalidCredentials
}

// CreateSession generates a new session and returns the session metadata.
func (s *DefaultAuthService) CreateSession(ctx context.Context, user *UserInfo, ttl time.Duration) (*SessionData, error) {
	return s.sessionStore.CreateSession(ctx, user.ID, user.Email, user.Name, ttl)
}

// ValidateSession retrieves and validates an existing session ID.
func (s *DefaultAuthService) ValidateSession(ctx context.Context, sessionID string) (*SessionData, error) {
	return s.sessionStore.GetSession(ctx, sessionID)
}

// RevokeSession deletes a session.
func (s *DefaultAuthService) RevokeSession(ctx context.Context, sessionID string) error {
	return s.sessionStore.DeleteSession(ctx, sessionID)
}
