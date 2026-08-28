package service

import (
	"context"
	"errors"
	"strings"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/repository"
)

var (
	ErrPermissionNameRequired = errors.New("permission name is required")
	ErrPermissionExists       = errors.New("permission with this name already exists")
	ErrPermissionNotFound     = errors.New("permission not found")
)

// PermissionService handles business logic for permissions.
type PermissionService struct {
	repo *repository.PermissionRepository
}

// NewPermissionService creates a new PermissionService.
func NewPermissionService(repo *repository.PermissionRepository) *PermissionService {
	return &PermissionService{repo: repo}
}

// Create validates and creates a new permission.
func (s *PermissionService) Create(ctx context.Context, req model.CreatePermissionRequest) (*model.Permission, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, ErrPermissionNameRequired
	}

	existing, err := s.repo.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrPermissionExists
	}

	return s.repo.Create(ctx, name)
}

// GetByID retrieves a permission by ID.
func (s *PermissionService) GetByID(ctx context.Context, id string) (*model.Permission, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("invalid permission id")
	}

	p, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrPermissionNotFound
	}
	return p, nil
}

// List returns all permissions.
func (s *PermissionService) List(ctx context.Context) ([]model.Permission, error) {
	return s.repo.List(ctx)
}
