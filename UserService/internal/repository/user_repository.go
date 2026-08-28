package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
)

// UserRepository defines database operations for users and user-role relations.
type UserRepository struct {
	db       *sql.DB
	roleRepo *RoleRepository
}

// NewUserRepository creates a new UserRepository.
func NewUserRepository(db *sql.DB, roleRepo *RoleRepository) *UserRepository {
	return &UserRepository{
		db:       db,
		roleRepo: roleRepo,
	}
}

// Create inserts a new user record.
func (r *UserRepository) Create(ctx context.Context, name, email, passwordHash string) (*model.User, error) {
	query := `
		INSERT INTO users (name, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, name, email, password_hash, created_at, updated_at
	`
	var u model.User
	err := r.db.QueryRowContext(ctx, query, name, email, passwordHash).Scan(
		&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert user: %w", err)
	}
	return &u, nil
}

// GetByID fetches a user by ID.
func (r *UserRepository) GetByID(ctx context.Context, id string) (*model.User, error) {
	query := `SELECT id, name, email, password_hash, created_at, updated_at FROM users WHERE id = $1`
	var u model.User
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch user by id: %w", err)
	}
	return &u, nil
}

// GetByEmail fetches a user by email address.
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `SELECT id, name, email, password_hash, created_at, updated_at FROM users WHERE email = $1`
	var u model.User
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch user by email: %w", err)
	}
	return &u, nil
}

// List fetches users with optional pagination.
func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]model.UserResponse, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, name, email, created_at, updated_at 
		FROM users 
		ORDER BY created_at DESC 
		LIMIT $1 OFFSET $2
	`
	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []model.UserResponse
	for rows.Next() {
		var u model.UserResponse
		if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, u)
	}

	if users == nil {
		users = []model.UserResponse{}
	}

	return users, rows.Err()
}

// AssignRole associates a role with a user.
func (r *UserRepository) AssignRole(ctx context.Context, userID, roleID string) error {
	query := `
		INSERT INTO user_roles (user_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to assign role to user: %w", err)
	}
	return nil
}

// RemoveRole removes a role from a user.
func (r *UserRepository) RemoveRole(ctx context.Context, userID, roleID string) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`
	result, err := r.db.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove role from user: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("role was not assigned to this user")
	}
	return nil
}

// GetRolesForUser retrieves all roles assigned to a user along with each role's permissions.
func (r *UserRepository) GetRolesForUser(ctx context.Context, userID string) ([]model.RoleSummary, error) {
	query := `
		SELECT r.id, r.name
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY r.name ASC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	var roleSummaries []model.RoleSummary
	for rows.Next() {
		var rs model.RoleSummary
		if err := rows.Scan(&rs.ID, &rs.Name); err != nil {
			return nil, fmt.Errorf("failed to scan role summary: %w", err)
		}
		roleSummaries = append(roleSummaries, rs)
	}

	if roleSummaries == nil {
		return []model.RoleSummary{}, nil
	}

	// Fetch permissions for each role
	for i := range roleSummaries {
		perms, err := r.roleRepo.GetPermissionsForRole(ctx, roleSummaries[i].ID)
		if err != nil {
			return nil, err
		}
		roleSummaries[i].Permissions = perms
	}

	return roleSummaries, rows.Err()
}

// GetFullUserDetail loads the complete user profile, assigned roles, and aggregated unique permissions.
func (r *UserRepository) GetFullUserDetail(ctx context.Context, userID string) (*model.UserDetailResponse, error) {
	user, err := r.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	roles, err := r.GetRolesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Collect unique permissions
	permMap := make(map[string]bool)
	for _, role := range roles {
		for _, perm := range role.Permissions {
			permMap[perm.Name] = true
		}
	}

	permissions := make([]string, 0, len(permMap))
	for permName := range permMap {
		permissions = append(permissions, permName)
	}

	return &model.UserDetailResponse{
		ID:          user.ID,
		Name:        user.Name,
		Email:       user.Email,
		Roles:       roles,
		Permissions: permissions,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}, nil
}
