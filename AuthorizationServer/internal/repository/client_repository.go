package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// PostgresClientRepository queries OAuth clients from PostgreSQL tables (oauth_clients, client_redirect_uris, client_scopes).
type PostgresClientRepository struct {
	db *sql.DB
}

// NewPostgresClientRepository creates a new PostgresClientRepository.
func NewPostgresClientRepository(db *sql.DB) *PostgresClientRepository {
	return &PostgresClientRepository{db: db}
}

// GetByClientID reads client, redirect URIs, and scopes from the database tables.
func (r *PostgresClientRepository) GetByClientID(ctx context.Context, clientID string) (*model.Client, error) {
	if r.db == nil {
		return nil, ErrClientNotFound
	}

	query := `
		SELECT id, client_id, client_secret_hash, name, created_at
		FROM oauth_clients
		WHERE client_id = $1
	`
	var client model.Client
	var secretHash sql.NullString

	err := r.db.QueryRowContext(ctx, query, clientID).Scan(
		&client.ID,
		&client.ClientID,
		&secretHash,
		&client.ClientName,
		&client.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("failed to query oauth client by client_id: %w", err)
	}

	if secretHash.Valid {
		client.ClientSecret = secretHash.String
	}

	// 2. Fetch redirect URIs
	uriQuery := `SELECT redirect_uri FROM client_redirect_uris WHERE client_id = $1 ORDER BY redirect_uri ASC`
	uriRows, err := r.db.QueryContext(ctx, uriQuery, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to query client redirect uris: %w", err)
	}
	defer uriRows.Close()

	var uris []string
	for uriRows.Next() {
		var u string
		if err := uriRows.Scan(&u); err != nil {
			return nil, fmt.Errorf("failed to scan redirect uri: %w", err)
		}
		uris = append(uris, u)
	}
	if uris == nil {
		uris = []string{}
	}
	client.RedirectURIs = uris

	// 3. Fetch allowed scopes
	scopeQuery := `SELECT scope FROM client_scopes WHERE client_id = $1 ORDER BY scope ASC`
	scopeRows, err := r.db.QueryContext(ctx, scopeQuery, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to query client scopes: %w", err)
	}
	defer scopeRows.Close()

	var scopes []string
	for scopeRows.Next() {
		var s string
		if err := scopeRows.Scan(&s); err != nil {
			return nil, fmt.Errorf("failed to scan scope: %w", err)
		}
		scopes = append(scopes, s)
	}
	if scopes == nil {
		scopes = []string{}
	}
	client.AllowedScopes = scopes

	return &client, nil
}

// MemoryClientRepository is a mock/hardcoded client repository implementation for tests.
type MemoryClientRepository struct {
	clients map[string]*model.Client
}

// NewMemoryClientRepository creates a new client repository with initial mock data.
func NewMemoryClientRepository() *MemoryClientRepository {
	repo := &MemoryClientRepository{
		clients: make(map[string]*model.Client),
	}

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
