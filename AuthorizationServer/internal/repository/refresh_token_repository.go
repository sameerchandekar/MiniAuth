package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
)

var (
	ErrRefreshTokenNotFound = errors.New("refresh_token not found")
	ErrRefreshTokenExpired  = errors.New("refresh_token has expired")
	ErrRefreshTokenRevoked  = errors.New("refresh_token has been revoked")
)

// RefreshTokenRepository defines the interface for persisting and managing refresh tokens.
type RefreshTokenRepository interface {
	Create(ctx context.Context, token *model.RefreshToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error)
	Revoke(ctx context.Context, tokenHash string) error
	RevokeFamily(ctx context.Context, familyID string) error
}

// PostgresRefreshTokenRepository implements RefreshTokenRepository using PostgreSQL refresh_tokens table.
type PostgresRefreshTokenRepository struct {
	db *sql.DB
}

// NewPostgresRefreshTokenRepository creates a new PostgresRefreshTokenRepository.
func NewPostgresRefreshTokenRepository(db *sql.DB) *PostgresRefreshTokenRepository {
	return &PostgresRefreshTokenRepository{db: db}
}

// Create inserts a new refresh token record into the refresh_tokens table.
func (r *PostgresRefreshTokenRepository) Create(ctx context.Context, token *model.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (token_hash, user_id, client_id, family_id, created_at, expires_at, family_expires_at, revoked_at, replaced_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at
	`
	var uid sql.NullString
	if token.UserID != nil && *token.UserID != "" {
		uid.String = *token.UserID
		uid.Valid = true
	}

	var replaced sql.NullString
	if token.ReplacedBy != nil && *token.ReplacedBy != "" {
		replaced.String = *token.ReplacedBy
		replaced.Valid = true
	}

	createdAt := token.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	err := r.db.QueryRowContext(ctx, query,
		token.TokenHash,
		uid,
		token.ClientID,
		token.FamilyID,
		createdAt,
		token.ExpiresAt,
		token.FamilyExpiresAt,
		token.RevokedAt,
		replaced,
	).Scan(&token.ID, &token.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to insert refresh token: %w", err)
	}

	return nil
}

// GetByTokenHash retrieves a refresh token record by its unique SHA256 hash.
func (r *PostgresRefreshTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	query := `
		SELECT id, token_hash, user_id, client_id, family_id, created_at, expires_at, family_expires_at, revoked_at, replaced_by
		FROM refresh_tokens
		WHERE token_hash = $1
	`
	var rt model.RefreshToken
	var uid, replaced sql.NullString
	var revokedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&rt.ID,
		&rt.TokenHash,
		&uid,
		&rt.ClientID,
		&rt.FamilyID,
		&rt.CreatedAt,
		&rt.ExpiresAt,
		&rt.FamilyExpiresAt,
		&revokedAt,
		&replaced,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token by hash: %w", err)
	}

	if uid.Valid {
		rt.UserID = &uid.String
	}
	if replaced.Valid {
		rt.ReplacedBy = &replaced.String
	}
	if revokedAt.Valid {
		rt.RevokedAt = &revokedAt.Time
	}

	return &rt, nil
}

// Revoke marks a specific refresh token as revoked.
func (r *PostgresRefreshTokenRepository) Revoke(ctx context.Context, tokenHash string) error {
	query := `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = $1 AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, tokenHash)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	return nil
}

// RevokeFamily revokes all refresh tokens belonging to the specified family (rotation reuse breach mitigation).
func (r *PostgresRefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) error {
	query := `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE family_id = $1 AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, familyID)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token family: %w", err)
	}
	return nil
}

// MemoryRefreshTokenRepository is an in-memory mock implementation for tests or development.
type MemoryRefreshTokenRepository struct {
	mu     sync.RWMutex
	tokens map[string]*model.RefreshToken
}

// NewMemoryRefreshTokenRepository creates a new MemoryRefreshTokenRepository.
func NewMemoryRefreshTokenRepository() *MemoryRefreshTokenRepository {
	return &MemoryRefreshTokenRepository{
		tokens: make(map[string]*model.RefreshToken),
	}
}

func (r *MemoryRefreshTokenRepository) Create(ctx context.Context, token *model.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if token.ID == "" {
		token.ID = fmt.Sprintf("rt-id-%d", time.Now().UnixNano())
	}
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now()
	}

	r.tokens[token.TokenHash] = token
	return nil
}

func (r *MemoryRefreshTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, exists := r.tokens[tokenHash]
	if !exists {
		return nil, ErrRefreshTokenNotFound
	}
	return t, nil
}

func (r *MemoryRefreshTokenRepository) Revoke(ctx context.Context, tokenHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	t, exists := r.tokens[tokenHash]
	if !exists {
		return ErrRefreshTokenNotFound
	}
	now := time.Now()
	t.RevokedAt = &now
	return nil
}

func (r *MemoryRefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for _, t := range r.tokens {
		if t.FamilyID == familyID {
			t.RevokedAt = &now
		}
	}
	return nil
}
