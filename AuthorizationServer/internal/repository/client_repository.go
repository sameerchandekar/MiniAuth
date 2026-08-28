package repository

import (
	"context"
	"errors"
	"time"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
)

var (
	ErrClientNotFound = errors.New("invalid_client: client not found")
)

// ClientRepository defines the interface for OAuth client lookup.
type ClientRepository interface {
	GetByClientID(ctx context.Context, clientID string) (*model.Client, error)
}

// MemoryClientRepository is a mock/hardcoded client repository implementation.
type MemoryClientRepository struct {
	clients map[string]*model.Client
}

// NewMemoryClientRepository creates a new client repository with initial mock data.
func NewMemoryClientRepository() *MemoryClientRepository {
	repo := &MemoryClientRepository{
		clients: make(map[string]*model.Client),
	}

	// Seed hardcoded demo client
	repo.clients["my-client-123"] = &model.Client{
		ID:           "c1234567-89ab-cdef-0123-456789abcdef",
		ClientID:     "my-client-123",
		ClientSecret: "mock_client_secret_xyz456",
		ClientName:   "Demo Application",
		RedirectURIs: []string{
			"https://myapp.com/oauth/callback",
			"http://localhost:3000/callback",
			"http://127.0.0.1:3000/callback",
		},
		AllowedScopes: []string{"openid", "profile", "email", "read:files", "offline_access"},
		CreatedAt:     time.Now(),
	}

	return repo
}

// GetByClientID finds a client by its client_id.
func (r *MemoryClientRepository) GetByClientID(ctx context.Context, clientID string) (*model.Client, error) {
	if client, exists := r.clients[clientID]; exists {
		return client, nil
	}

	// For flexible testing, return a default mock client if any client_id is passed
	if clientID != "" {
		return &model.Client{
			ID:            "mock-client-id",
			ClientID:      clientID,
			ClientSecret:  "mock-secret",
			ClientName:    "Generic Client: " + clientID,
			RedirectURIs:  []string{"https://myapp.com/oauth/callback"},
			AllowedScopes: []string{"openid", "profile", "email"},
			CreatedAt:     time.Now(),
		}, nil
	}

	return nil, ErrClientNotFound
}
