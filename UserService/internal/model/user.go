package model

import "time"

// User represents a user entity in the database.
type User struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Role represents a role entity in the database.
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	CreatedAt   time.Time    `json:"created_at"`
	Permissions []Permission `json:"permissions,omitempty"`
}

// Permission represents a permission entity in the database.
type Permission struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// RoleSummary represents a lightweight role summary for user details.
type RoleSummary struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions,omitempty"`
}

// UserResponse represents the public user object without sensitive fields.
type UserResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserDetailResponse contains the full user profile, assigned roles, and resolved permissions.
type UserDetailResponse struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Email       string        `json:"email"`
	Roles       []RoleSummary `json:"roles"`
	Permissions []string      `json:"permissions"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// Request DTOs
type CreateUserRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CreateRoleRequest struct {
	Name string `json:"name"`
}

type AssignRoleRequest struct {
	RoleID string `json:"role_id"`
}

type CreatePermissionRequest struct {
	Name string `json:"name"`
}

type AssignPermissionRequest struct {
	PermissionID string `json:"permission_id"`
}
