package service

import (
	"context"
	"testing"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordHashing(t *testing.T) {
	password := "SuperSecretPassword123!"
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Verify valid password matches
	if err := bcrypt.CompareHashAndPassword(hashedBytes, []byte(password)); err != nil {
		t.Errorf("password verification failed: %v", err)
	}

	// Verify invalid password fails
	if err := bcrypt.CompareHashAndPassword(hashedBytes, []byte("WrongPassword")); err == nil {
		t.Errorf("expected error for wrong password, got nil")
	}
}

func TestValidationErrors(t *testing.T) {
	svc := &UserService{}

	// Test empty name
	_, err := svc.CreateUser(context.Background(), model.CreateUserRequest{
		Name:     "",
		Email:    "test@example.com",
		Password: "password123",
	})
	if err != ErrUserNameRequired {
		t.Errorf("expected ErrUserNameRequired, got %v", err)
	}

	// Test invalid email
	_, err = svc.CreateUser(context.Background(), model.CreateUserRequest{
		Name:     "Test",
		Email:    "invalid-email",
		Password: "password123",
	})
	if err != ErrUserEmailInvalid {
		t.Errorf("expected ErrUserEmailInvalid, got %v", err)
	}

	// Test short password
	_, err = svc.CreateUser(context.Background(), model.CreateUserRequest{
		Name:     "Test",
		Email:    "test@example.com",
		Password: "short",
	})
	if err != ErrUserPasswordTooShort {
		t.Errorf("expected ErrUserPasswordTooShort, got %v", err)
	}
}
