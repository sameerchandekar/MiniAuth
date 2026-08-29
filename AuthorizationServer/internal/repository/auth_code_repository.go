package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
)

var (
	ErrAuthCodeNotFound = errors.New("invalid_grant: authorization code not found")
	ErrAuthCodeExpired  = errors.New("invalid_grant: authorization code has expired")
)

const authCodeKeyPrefix = "auth_code:"

// AuthCodeRepository defines the interface for storing and retrieving authorization codes.
type AuthCodeRepository interface {
	Save(ctx context.Context, code *model.AuthCode) error
	Get(ctx context.Context, code string) (*model.AuthCode, error)
	Delete(ctx context.Context, code string) error
}

// RedisAuthCodeRepository stores and manages authorization codes in Redis.
type RedisAuthCodeRepository struct {
	rdb *redis.Client
}

// NewRedisAuthCodeRepository creates a new Redis-backed authorization code repository.
func NewRedisAuthCodeRepository(rdb *redis.Client) *RedisAuthCodeRepository {
	return &RedisAuthCodeRepository{
		rdb: rdb,
	}
}

// Save stores the authorization code as JSON in Redis with key "auth_code:<unique_authcode>" and TTL based on ExpiresAt.
func (r *RedisAuthCodeRepository) Save(ctx context.Context, code *model.AuthCode) error {
	if code == nil || code.Code == "" {
		return errors.New("invalid auth code")
	}

	key := authCodeKeyPrefix + code.Code

	data, err := json.Marshal(code)
	if err != nil {
		return fmt.Errorf("failed to marshal auth code to json: %w", err)
	}

	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	if err := r.rdb.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to save auth code in redis: %w", err)
	}

	return nil
}

// Get retrieves and deserializes an authorization code from Redis by its code string.
func (r *RedisAuthCodeRepository) Get(ctx context.Context, code string) (*model.AuthCode, error) {
	if code == "" {
		return nil, ErrAuthCodeNotFound
	}

	key := authCodeKeyPrefix + code

	val, err := r.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrAuthCodeNotFound
		}
		return nil, fmt.Errorf("failed to get auth code from redis: %w", err)
	}

	var authCode model.AuthCode
	if err := json.Unmarshal([]byte(val), &authCode); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth code json: %w", err)
	}

	if time.Now().After(authCode.ExpiresAt) {
		_ = r.Delete(ctx, code)
		return nil, ErrAuthCodeExpired
	}

	return &authCode, nil
}

// Delete removes an authorization code from Redis (single-use semantics).
func (r *RedisAuthCodeRepository) Delete(ctx context.Context, code string) error {
	if code == "" {
		return nil
	}

	key := authCodeKeyPrefix + code
	if err := r.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete auth code from redis: %w", err)
	}

	return nil
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
