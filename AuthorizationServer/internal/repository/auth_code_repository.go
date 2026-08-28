package repository

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
)

var (
	ErrAuthCodeNotFound = errors.New("invalid_grant: authorization code not found")
	ErrAuthCodeExpired  = errors.New("invalid_grant: authorization code has expired")
)

// AuthCodeRepository defines the interface for storing and retrieving authorization codes.
type AuthCodeRepository interface {
	Save(ctx context.Context, code *model.AuthCode) error
	Get(ctx context.Context, code string) (*model.AuthCode, error)
	Delete(ctx context.Context, code string) error
}

// MemoryAuthCodeRepository is an in-memory/mock implementation for authorization code storage.
type MemoryAuthCodeRepository struct {
	mu    sync.RWMutex
	codes map[string]*model.AuthCode
}

// NewMemoryAuthCodeRepository creates a new MemoryAuthCodeRepository.
func NewMemoryAuthCodeRepository() *MemoryAuthCodeRepository {
	return &MemoryAuthCodeRepository{
		codes: make(map[string]*model.AuthCode),
	}
}

// Save stores the authorization code with its associated metadata.
func (r *MemoryAuthCodeRepository) Save(ctx context.Context, code *model.AuthCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.codes[code.Code] = code
	return nil
}

// Get retrieves an authorization code by string.
func (r *MemoryAuthCodeRepository) Get(ctx context.Context, code string) (*model.AuthCode, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	authCode, exists := r.codes[code]
	if !exists {
		return nil, ErrAuthCodeNotFound
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrAuthCodeExpired
	}

	return authCode, nil
}

// Delete removes an authorization code (single-use semantics).
func (r *MemoryAuthCodeRepository) Delete(ctx context.Context, code string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.codes, code)
	return nil
}
