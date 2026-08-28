package service

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNameRequired     = errors.New("user name is required")
	ErrUserEmailInvalid     = errors.New("a valid email address is required")
	ErrUserPasswordTooShort = errors.New("password must be at least 8 characters long")
	ErrUserEmailExists      = errors.New("user with this email already exists")
	ErrUserNotFound         = errors.New("user not found")
)

// UserService handles user business logic, validation, and password cryptography.
type UserService struct {
	userRepo *repository.UserRepository
	roleRepo *repository.RoleRepository
}

// NewUserService creates a new UserService.
func NewUserService(userRepo *repository.UserRepository, roleRepo *repository.RoleRepository) *UserService {
	return &UserService{
		userRepo: userRepo,
		roleRepo: roleRepo,
	}
}

// CreateUser validates input, hashes password with bcrypt, and stores the user.
func (s *UserService) CreateUser(ctx context.Context, req model.CreateUserRequest) (*model.UserResponse, error) {
	name := strings.TrimSpace(req.Name)
	email := strings.ToLower(strings.TrimSpace(req.Email))
	password := req.Password

	if name == "" {
		return nil, ErrUserNameRequired
	}

	if _, err := mail.ParseAddress(email); err != nil || !strings.Contains(email, ".") {
		return nil, ErrUserEmailInvalid
	}

	if len(password) < 8 {
		return nil, ErrUserPasswordTooShort
	}

	// Check if email already exists
	existing, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserEmailExists
	}

	// Securely hash password with bcrypt
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.Create(ctx, name, email, string(hashedBytes))
	if err != nil {
		return nil, err
	}

	return &model.UserResponse{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

// GetUserDetail retrieves full user information including assigned roles and permissions.
func (s *UserService) GetUserDetail(ctx context.Context, id string) (*model.UserDetailResponse, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("invalid user id")
	}

	userDetail, err := s.userRepo.GetFullUserDetail(ctx, id)
	if err != nil {
		return nil, err
	}
	if userDetail == nil {
		return nil, ErrUserNotFound
	}

	return userDetail, nil
}

// ListUsers retrieves paginated user list.
func (s *UserService) ListUsers(ctx context.Context, limit, offset int) ([]model.UserResponse, error) {
	return s.userRepo.List(ctx, limit, offset)
}

// AssignRole links a role to a user.
func (s *UserService) AssignRole(ctx context.Context, userID, roleID string) error {
	userID = strings.TrimSpace(userID)
	roleID = strings.TrimSpace(roleID)

	if userID == "" || roleID == "" {
		return errors.New("user_id and role_id are required")
	}

	// Verify user exists
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Verify role exists
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return ErrRoleNotFound
	}

	return s.userRepo.AssignRole(ctx, userID, roleID)
}

// RemoveRole removes a role from a user.
func (s *UserService) RemoveRole(ctx context.Context, userID, roleID string) error {
	userID = strings.TrimSpace(userID)
	roleID = strings.TrimSpace(roleID)

	if userID == "" || roleID == "" {
		return errors.New("user_id and role_id are required")
	}

	return s.userRepo.RemoveRole(ctx, userID, roleID)
}
