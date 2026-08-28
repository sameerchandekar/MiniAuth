package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
)

// PermissionRepository defines database operations for permissions.
type PermissionRepository struct {
	db *sql.DB
}

// NewPermissionRepository creates a new PermissionRepository.
func NewPermissionRepository(db *sql.DB) *PermissionRepository {
	return &PermissionRepository{db: db}
}

// Create inserts a new permission.
func (r *PermissionRepository) Create(ctx context.Context, name string) (*model.Permission, error) {
	query := `
		INSERT INTO permissions (name)
		VALUES ($1)
		RETURNING id, name, created_at
	`
	var p model.Permission
	err := r.db.QueryRowContext(ctx, query, name).Scan(&p.ID, &p.Name, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert permission: %w", err)
	}
	return &p, nil
}

// GetByID fetches a permission by ID.
func (r *PermissionRepository) GetByID(ctx context.Context, id string) (*model.Permission, error) {
	query := `SELECT id, name, created_at FROM permissions WHERE id = $1`
	var p model.Permission
	err := r.db.QueryRowContext(ctx, query, id).Scan(&p.ID, &p.Name, &p.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch permission by id: %w", err)
	}
	return &p, nil
}

// GetByName fetches a permission by name.
func (r *PermissionRepository) GetByName(ctx context.Context, name string) (*model.Permission, error) {
	query := `SELECT id, name, created_at FROM permissions WHERE name = $1`
	var p model.Permission
	err := r.db.QueryRowContext(ctx, query, name).Scan(&p.ID, &p.Name, &p.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch permission by name: %w", err)
	}
	return &p, nil
}

// List returns all permissions.
func (r *PermissionRepository) List(ctx context.Context) ([]model.Permission, error) {
	query := `SELECT id, name, created_at FROM permissions ORDER BY name ASC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query permissions: %w", err)
	}
	defer rows.Close()

	var permissions []model.Permission
	for rows.Next() {
		var p model.Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, p)
	}

	if permissions == nil {
		permissions = []model.Permission{}
	}

	return permissions, rows.Err()
}
