package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrSessionNotFound = errors.New("session not found or expired")
)

// SessionData holds session metadata for an authenticated user.
type SessionData struct {
	SessionID string    `json:"session_id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionStore defines the interface for storing and retrieving user login sessions.
type SessionStore interface {
	CreateSession(ctx context.Context, userID, email, name string, ttl time.Duration) (*SessionData, error)
	GetSession(ctx context.Context, sessionID string) (*SessionData, error)
	DeleteSession(ctx context.Context, sessionID string) error
}

// RedisSessionStore implements SessionStore using Redis.
type RedisSessionStore struct {
	client *redis.Client
}

// NewRedisSessionStore creates a new RedisSessionStore.
func NewRedisSessionStore(client *redis.Client) *RedisSessionStore {
	return &RedisSessionStore{client: client}
}

// CreateSession generates a new session and persists it in Redis with the given TTL.
func (s *RedisSessionStore) CreateSession(ctx context.Context, userID, email, name string, ttl time.Duration) (*SessionData, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	sessionID := generateSessionID()
	now := time.Now()
	data := &SessionData{
		SessionID: sessionID,
		UserID:    userID,
		Email:     email,
		Name:      name,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	rawJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session: %w", err)
	}

	key := fmt.Sprintf("auth_session:%s", sessionID)
	if err := s.client.Set(ctx, key, rawJSON, ttl).Err(); err != nil {
		return nil, fmt.Errorf("failed to save session in redis: %w", err)
	}

	return data, nil
}

// GetSession retrieves an active session from Redis.
func (s *RedisSessionStore) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	if sessionID == "" {
		return nil, ErrSessionNotFound
	}

	key := fmt.Sprintf("auth_session:%s", sessionID)
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session from redis: %w", err)
	}

	var data SessionData
	if err := json.Unmarshal([]byte(val), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	if time.Now().After(data.ExpiresAt) {
		_ = s.DeleteSession(ctx, sessionID)
		return nil, ErrSessionNotFound
	}

	return &data, nil
}

// DeleteSession removes a session from Redis.
func (s *RedisSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf("auth_session:%s", sessionID)
	return s.client.Del(ctx, key).Err()
}

// MemorySessionStore implements SessionStore in-memory for testing and local fallback.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionData
}

// NewMemorySessionStore creates a new in-memory SessionStore.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*SessionData),
	}
}

// CreateSession generates and stores a session in memory.
func (s *MemorySessionStore) CreateSession(ctx context.Context, userID, email, name string, ttl time.Duration) (*SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	sessionID := generateSessionID()
	now := time.Now()
	data := &SessionData{
		SessionID: sessionID,
		UserID:    userID,
		Email:     email,
		Name:      name,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	s.sessions[sessionID] = data
	return data, nil
}

// GetSession retrieves a session from memory.
func (s *MemorySessionStore) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(data.ExpiresAt) {
		delete(s.sessions, sessionID)
		return nil, ErrSessionNotFound
	}

	return data, nil
}

// DeleteSession removes a session from memory.
func (s *MemorySessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
	return nil
}

func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("sess_%d", time.Now().UnixNano())
	}
	return "sess_" + hex.EncodeToString(b)
}
