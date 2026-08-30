package repository

import (
	"context"
	"testing"
	"time"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
)

func TestMemoryRefreshTokenRepository_CRUD(t *testing.T) {
	repo := NewMemoryRefreshTokenRepository()
	ctx := context.Background()

	tokenHash := "mock_hash_123456789abcdef"
	familyID := "fam-001"
	userID := "user-123"

	rt := &model.RefreshToken{
		TokenHash:       tokenHash,
		UserID:          &userID,
		ClientID:        "client-001",
		FamilyID:        familyID,
		ExpiresAt:       time.Now().Add(30 * 24 * time.Hour),
		FamilyExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	}

	// 1. Create
	if err := repo.Create(ctx, rt); err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	// 2. GetByTokenHash
	fetched, err := repo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("failed to get refresh token: %v", err)
	}
	if fetched.ClientID != "client-001" {
		t.Errorf("expected client_id 'client-001', got '%s'", fetched.ClientID)
	}

	// 3. Revoke
	if err := repo.Revoke(ctx, tokenHash); err != nil {
		t.Fatalf("failed to revoke refresh token: %v", err)
	}
	revokedToken, _ := repo.GetByTokenHash(ctx, tokenHash)
	if revokedToken.RevokedAt == nil {
		t.Errorf("expected revoked_at to be set")
	}

	// 4. RevokeFamily
	tokenHash2 := "mock_hash_2"
	rt2 := &model.RefreshToken{
		TokenHash:       tokenHash2,
		ClientID:        "client-001",
		FamilyID:        familyID,
		ExpiresAt:       time.Now().Add(30 * 24 * time.Hour),
		FamilyExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	}
	_ = repo.Create(ctx, rt2)

	if err := repo.RevokeFamily(ctx, familyID); err != nil {
		t.Fatalf("failed to revoke family: %v", err)
	}
	revokedToken2, _ := repo.GetByTokenHash(ctx, tokenHash2)
	if revokedToken2.RevokedAt == nil {
		t.Errorf("expected family token revoked_at to be set")
	}
}
