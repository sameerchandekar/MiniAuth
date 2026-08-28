package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
)

// RoleRepository defines database operations for roles and role-permission relations.
type RoleRepository struct {
	db *sql.DB
}

// NewRoleRepository creates a new RoleRepository.
func NewRoleRepository(db *sql.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// Create inserts a new role.
func (r *RoleRepository) Create(ctx context.Context, name string) (*model.Role, error) {
	query := `
		INSERT INTO roles (name)
		VALUES ($1)
		RETURNING id, name, created_at
	`
	var role model.Role
	err := r.db.QueryRowContext(ctx, query, name).Scan(&role.ID, &role.Name, &role.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert role: %w", err)
	}
	role.Permissions = []model.Permission{}
	return &role, nil
}

// GetByID fetches a role by ID along with its permissions.
func (r *RoleRepository) GetByID(ctx context.Context, id string) (*model.Role, error) {
	query := `SELECT id, name, created_at FROM roles WHERE id = $1`
	var role model.Role
	err := r.db.QueryRowContext(ctx, query, id).Scan(&role.ID, &role.Name, &role.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch role by id: %w", err)
	}

	perms, err := r.GetPermissionsForRole(ctx, role.ID)
	if err != nil {
		return nil, err
	}
	role.Permissions = perms

	return &role, nil
}

// GetByName fetches a role by name.
func (r *RoleRepository) GetByName(ctx context.Context, name string) (*model.Role, error) {
	query := `SELECT id, name, created_at FROM roles WHERE name = $1`
	var role model.Role
	err := r.db.QueryRowContext(ctx, query, name).Scan(&role.ID, &role.Name, &role.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch role by name: %w", err)
	}
	return &role, nil
}

// List returns all roles with their assigned permissions.
func (r *RoleRepository) List(ctx context.Context) ([]model.Role, error) {
	query := `SELECT id, name, created_at FROM roles ORDER BY name ASC`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query roles: %w", err)
	}
	defer rows.Close()

	var roles []model.Role
	for rows.Next() {
		var role model.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if roles == nil {
		return []model.Role{}, nil
	}

	// Fetch permissions for each role
	for i := range roles {
		perms, err := r.GetPermissionsForRole(ctx, roles[i].ID)
		if err != nil {
			return nil, err
		}
		roles[i].Permissions = perms
	}

	return roles, rows.Err()
}

// AssignPermission links a permission to a role.
func (r *RoleRepository) AssignPermission(ctx context.Context, roleID, permissionID string) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to assign permission to role: %w", err)
	}
	return nil
}

// RemovePermission unlinks a permission from a role.
func (r *RoleRepository) RemovePermission(ctx context.Context, roleID, permissionID string) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`
	result, err := r.db.ExecContext(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to remove permission from role: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("permission was not assigned to this role")
	}
	return nil
}

// GetPermissionsForRole retrieves all permissions assigned to a given role.
func (r *RoleRepository) GetPermissionsForRole(ctx context.Context, roleID string) ([]model.Permission, error) {
	query := `
		SELECT p.id, p.name, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.name ASC
	`
	rows, err := r.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to query role permissions: %w", err)
	}
	defer rows.Close()

	var perms []model.Permission
	for rows.Next() {
		var p model.Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		perms = append(perms, p)
	}

	if perms == nil {
		perms = []model.Permission{}
	}

	return perms, rows.Err()
}
