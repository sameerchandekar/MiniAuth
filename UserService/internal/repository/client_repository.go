package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
)

// ClientRepository handles SQL database operations for OAuth clients, scopes, and redirect URIs.
type ClientRepository struct {
	db *sql.DB
}

// NewClientRepository creates a new ClientRepository instance.
func NewClientRepository(db *sql.DB) *ClientRepository {
	return &ClientRepository{db: db}
}

// Create inserts a new client record into oauth_clients.
func (r *ClientRepository) Create(ctx context.Context, clientID string, clientSecretHash *string, name string, clientType model.ClientType) (*model.Client, error) {
	query := `
		INSERT INTO oauth_clients (client_id, client_secret_hash, name, client_type)
		VALUES ($1, $2, $3, $4)
		RETURNING id, client_id, client_secret_hash, name, client_type, created_at
	`
	var c model.Client
	var secretHash sql.NullString
	if clientSecretHash != nil {
		secretHash.String = *clientSecretHash
		secretHash.Valid = true
	}

	err := r.db.QueryRowContext(ctx, query, clientID, secretHash, name, string(clientType)).Scan(
		&c.ID, &c.ClientID, &secretHash, &c.Name, &c.ClientType, &c.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert oauth client: %w", err)
	}

	if secretHash.Valid {
		c.ClientSecretHash = &secretHash.String
	}

	return &c, nil
}

// GetByClientID finds a client by its unique client_id.
func (r *ClientRepository) GetByClientID(ctx context.Context, clientID string) (*model.Client, error) {
	query := `
		SELECT id, client_id, client_secret_hash, name, client_type, created_at
		FROM oauth_clients
		WHERE client_id = $1
	`
	var c model.Client
	var secretHash sql.NullString

	err := r.db.QueryRowContext(ctx, query, clientID).Scan(
		&c.ID, &c.ClientID, &secretHash, &c.Name, &c.ClientType, &c.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch client by client_id: %w", err)
	}

	if secretHash.Valid {
		c.ClientSecretHash = &secretHash.String
	}

	return &c, nil
}

// List fetches registered clients with pagination.
func (r *ClientRepository) List(ctx context.Context, limit, offset int) ([]model.Client, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, client_id, client_secret_hash, name, client_type, created_at
		FROM oauth_clients
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query oauth clients: %w", err)
	}
	defer rows.Close()

	var clients []model.Client
	for rows.Next() {
		var c model.Client
		var secretHash sql.NullString
		if err := rows.Scan(&c.ID, &c.ClientID, &secretHash, &c.Name, &c.ClientType, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan oauth client: %w", err)
		}
		if secretHash.Valid {
			c.ClientSecretHash = &secretHash.String
		}
		clients = append(clients, c)
	}

	if clients == nil {
		clients = []model.Client{}
	}

	return clients, rows.Err()
}

// Delete removes an OAuth client (cascades to redirect_uris and scopes).
func (r *ClientRepository) Delete(ctx context.Context, clientID string) error {
	query := `DELETE FROM oauth_clients WHERE client_id = $1`
	res, err := r.db.ExecContext(ctx, query, clientID)
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("client not found")
	}

	return nil
}

// GetRedirectURIs retrieves all redirect URIs configured for a client.
func (r *ClientRepository) GetRedirectURIs(ctx context.Context, clientID string) ([]string, error) {
	query := `SELECT redirect_uri FROM client_redirect_uris WHERE client_id = $1 ORDER BY redirect_uri ASC`
	rows, err := r.db.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to query client redirect uris: %w", err)
	}
	defer rows.Close()

	var uris []string
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			return nil, fmt.Errorf("failed to scan redirect uri: %w", err)
		}
		uris = append(uris, uri)
	}

	if uris == nil {
		uris = []string{}
	}

	return uris, rows.Err()
}

// AddRedirectURI associates a single redirect URI with a client.
func (r *ClientRepository) AddRedirectURI(ctx context.Context, clientID, uri string) error {
	query := `
		INSERT INTO client_redirect_uris (client_id, redirect_uri)
		VALUES ($1, $2)
		ON CONFLICT (client_id, redirect_uri) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, clientID, uri)
	if err != nil {
		return fmt.Errorf("failed to add redirect uri: %w", err)
	}
	return nil
}

// AddRedirectURIs associates multiple redirect URIs with a client.
func (r *ClientRepository) AddRedirectURIs(ctx context.Context, clientID string, uris []string) error {
	for _, uri := range uris {
		if err := r.AddRedirectURI(ctx, clientID, uri); err != nil {
			return err
		}
	}
	return nil
}

// RemoveRedirectURI removes a redirect URI from a client.
func (r *ClientRepository) RemoveRedirectURI(ctx context.Context, clientID, uri string) error {
	query := `DELETE FROM client_redirect_uris WHERE client_id = $1 AND redirect_uri = $2`
	res, err := r.db.ExecContext(ctx, query, clientID, uri)
	if err != nil {
		return fmt.Errorf("failed to remove redirect uri: %w", err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("redirect uri was not registered for this client")
	}

	return nil
}

// ReplaceRedirectURIs overwrites/replaces all redirect URIs for a client with the provided list in a transaction.
func (r *ClientRepository) ReplaceRedirectURIs(ctx context.Context, clientID string, uris []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `DELETE FROM client_redirect_uris WHERE client_id = $1`, clientID); err != nil {
		return fmt.Errorf("failed to clear existing redirect uris: %w", err)
	}

	for _, uri := range uris {
		if _, err := tx.ExecContext(ctx, `INSERT INTO client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2) ON CONFLICT (client_id, redirect_uri) DO NOTHING`, clientID, uri); err != nil {
			return fmt.Errorf("failed to insert redirect uri: %w", err)
		}
	}

	return tx.Commit()
}

// GetScopes retrieves all permitted scopes configured for a client.
func (r *ClientRepository) GetScopes(ctx context.Context, clientID string) ([]string, error) {
	query := `SELECT scope FROM client_scopes WHERE client_id = $1 ORDER BY scope ASC`
	rows, err := r.db.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to query client scopes: %w", err)
	}
	defer rows.Close()

	var scopes []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("failed to scan scope: %w", err)
		}
		scopes = append(scopes, s)
	}

	if scopes == nil {
		scopes = []string{}
	}

	return scopes, rows.Err()
}

// AddScope associates a single scope with a client.
func (r *ClientRepository) AddScope(ctx context.Context, clientID, scope string) error {
	query := `
		INSERT INTO client_scopes (client_id, scope)
		VALUES ($1, $2)
		ON CONFLICT (client_id, scope) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, clientID, scope)
	if err != nil {
		return fmt.Errorf("failed to add client scope: %w", err)
	}
	return nil
}

// AddScopes associates multiple scopes with a client.
func (r *ClientRepository) AddScopes(ctx context.Context, clientID string, scopes []string) error {
	for _, scope := range scopes {
		if err := r.AddScope(ctx, clientID, scope); err != nil {
			return err
		}
	}
	return nil
}

// RemoveScope removes a scope from a client.
func (r *ClientRepository) RemoveScope(ctx context.Context, clientID, scope string) error {
	query := `DELETE FROM client_scopes WHERE client_id = $1 AND scope = $2`
	res, err := r.db.ExecContext(ctx, query, clientID, scope)
	if err != nil {
		return fmt.Errorf("failed to remove client scope: %w", err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("scope was not registered for this client")
	}

	return nil
}

// ReplaceScopes overwrites/replaces all scopes for a client with the provided list in a transaction.
func (r *ClientRepository) ReplaceScopes(ctx context.Context, clientID string, scopes []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `DELETE FROM client_scopes WHERE client_id = $1`, clientID); err != nil {
		return fmt.Errorf("failed to clear existing scopes: %w", err)
	}

	for _, scope := range scopes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO client_scopes (client_id, scope) VALUES ($1, $2) ON CONFLICT (client_id, scope) DO NOTHING`, clientID, scope); err != nil {
			return fmt.Errorf("failed to insert scope: %w", err)
		}
	}

	return tx.Commit()
}

// GetFullClientDetail retrieves complete client metadata including redirect URIs and scopes.
func (r *ClientRepository) GetFullClientDetail(ctx context.Context, clientID string) (*model.ClientResponse, error) {
	c, err := r.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, nil
	}

	uris, err := r.GetRedirectURIs(ctx, clientID)
	if err != nil {
		return nil, err
	}

	scopes, err := r.GetScopes(ctx, clientID)
	if err != nil {
		return nil, err
	}

	return &model.ClientResponse{
		ID:           c.ID,
		ClientID:     c.ClientID,
		Name:         c.Name,
		ClientType:   c.ClientType,
		RedirectURIs: uris,
		Scopes:       scopes,
		CreatedAt:    c.CreatedAt,
	}, nil
}
