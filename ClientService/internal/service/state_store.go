package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	stateKeyPrefix = "oauth_state:"
)

// StateData holds the PKCE code verifier and metadata associated with an OAuth state.
type StateData struct {
	State        string    `json:"state"`
	CodeVerifier string    `json:"code_verifier"`
	CreatedAt    time.Time `json:"created_at"`
}

// StateStore defines the interface for storing and single-use validating OAuth state IDs.
type StateStore interface {
	SaveState(ctx context.Context, state string, data *StateData, ttl time.Duration) error
	GetAndDeleteState(ctx context.Context, state string) (*StateData, error)
}

// RedisStateStore stores OAuth state IDs and PKCE verifiers in Redis with automatic TTL expiration.
type RedisStateStore struct {
	rdb *redis.Client
}

// NewRedisStateStore creates a new RedisStateStore.
func NewRedisStateStore(rdb *redis.Client) *RedisStateStore {
	return &RedisStateStore{rdb: rdb}
}

// SaveState saves the state ID and associated code verifier into Redis with the given TTL.
func (s *RedisStateStore) SaveState(ctx context.Context, state string, data *StateData, ttl time.Duration) error {
	if state == "" {
		return errors.New("state cannot be empty")
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal state data: %w", err)
	}

	key := stateKeyPrefix + state
	err = s.rdb.Set(ctx, key, payload, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to save state in redis: %w", err)
	}

	return nil
}

// GetAndDeleteState retrieves the state data from Redis and immediately deletes it (single-use / replay protection).
func (s *RedisStateStore) GetAndDeleteState(ctx context.Context, state string) (*StateData, error) {
	if state == "" {
		return nil, ErrInvalidState
	}

	key := stateKeyPrefix + state

	// Atomic Get and Delete from Redis (RFC 6749 anti-replay)
	val, err := s.rdb.GetDel(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrInvalidState
		}
		return nil, fmt.Errorf("failed to retrieve state from redis: %w", err)
	}

	var data StateData
	if err := json.Unmarshal([]byte(val), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state data: %w", err)
	}

	return &data, nil
}

// MemoryStateStore is an in-memory thread-safe fallback implementation for testing.
type MemoryStateStore struct {
	mu     sync.Mutex
	states map[string]memoryStateEntry
}

type memoryStateEntry struct {
	data      *StateData
	expiresAt time.Time
}

// NewMemoryStateStore creates a new MemoryStateStore.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		states: make(map[string]memoryStateEntry),
	}
}

func (s *MemoryStateStore) SaveState(ctx context.Context, state string, data *StateData, ttl time.Duration) error {
	if state == "" {
		return errors.New("state cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.states[state] = memoryStateEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *MemoryStateStore) GetAndDeleteState(ctx context.Context, state string) (*StateData, error) {
	if state == "" {
		return nil, ErrInvalidState
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.states[state]
	if !exists {
		return nil, ErrInvalidState
	}

	// Delete immediately to enforce single-use
	delete(s.states, state)

	if time.Now().After(entry.expiresAt) {
		return nil, ErrInvalidState
	}

	return entry.data, nil
}
