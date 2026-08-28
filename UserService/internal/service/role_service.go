package service

import (
	"context"
	"errors"
	"strings"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/repository"
)

var (
	ErrRoleNameRequired = errors.New("role name is required")
	ErrRoleExists       = errors.New("role with this name already exists")
	ErrRoleNotFound     = errors.New("role not found")
)

// RoleService handles business logic for roles and role-permission bindings.
type RoleService struct {
	roleRepo *repository.RoleRepository
	permRepo *repository.PermissionRepository
}

// NewRoleService creates a new RoleService.
func NewRoleService(roleRepo *repository.RoleRepository, permRepo *repository.PermissionRepository) *RoleService {
	return &RoleService{
		roleRepo: roleRepo,
		permRepo: permRepo,
	}
}

// Create validates and creates a new role.
func (s *RoleService) Create(ctx context.Context, req model.CreateRoleRequest) (*model.Role, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, ErrRoleNameRequired
	}

	existing, err := s.roleRepo.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrRoleExists
	}

	return s.roleRepo.Create(ctx, name)
}

// GetByID fetches a role and its permissions.
func (s *RoleService) GetByID(ctx context.Context, id string) (*model.Role, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("invalid role id")
	}

	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, ErrRoleNotFound
	}
	return role, nil
}

// List returns all roles.
func (s *RoleService) List(ctx context.Context) ([]model.Role, error) {
	return s.roleRepo.List(ctx)
}

// AssignPermission assigns a permission to a role.
func (s *RoleService) AssignPermission(ctx context.Context, roleID, permissionID string) error {
	roleID = strings.TrimSpace(roleID)
	permissionID = strings.TrimSpace(permissionID)

	if roleID == "" || permissionID == "" {
		return errors.New("role_id and permission_id are required")
	}

	// Verify role exists
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return ErrRoleNotFound
	}

	// Verify permission exists
	perm, err := s.permRepo.GetByID(ctx, permissionID)
	if err != nil {
		return err
	}
	if perm == nil {
		return ErrPermissionNotFound
	}

	return s.roleRepo.AssignPermission(ctx, roleID, permissionID)
}

// RemovePermission removes a permission from a role.
func (s *RoleService) RemovePermission(ctx context.Context, roleID, permissionID string) error {
	roleID = strings.TrimSpace(roleID)
	permissionID = strings.TrimSpace(permissionID)

	if roleID == "" || permissionID == "" {
		return errors.New("role_id and permission_id are required")
	}

	return s.roleRepo.RemovePermission(ctx, roleID, permissionID)
}
