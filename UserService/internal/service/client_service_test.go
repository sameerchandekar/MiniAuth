package service

import (
	"context"
	"errors"
	"testing"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
)

func TestRegisterClientValidation(t *testing.T) {
	svc := NewClientService(nil)

	t.Run("empty name", func(t *testing.T) {
		_, err := svc.RegisterClient(context.Background(), model.RegisterClientRequest{
			Name: "",
		})
		if !errors.Is(err, ErrClientNameRequired) {
			t.Errorf("expected ErrClientNameRequired, got %v", err)
		}
	})

	t.Run("invalid client_type", func(t *testing.T) {
		_, err := svc.RegisterClient(context.Background(), model.RegisterClientRequest{
			Name:       "Test Client",
			ClientType: "unknown_type",
		})
		if !errors.Is(err, ErrInvalidClientType) {
			t.Errorf("expected ErrInvalidClientType, got %v", err)
		}
	})

	t.Run("invalid redirect_uri", func(t *testing.T) {
		_, err := svc.RegisterClient(context.Background(), model.RegisterClientRequest{
			Name:         "Test Client",
			RedirectURIs: []string{"not-a-valid-url"},
		})
		if !errors.Is(err, ErrInvalidRedirectURI) {
			t.Errorf("expected ErrInvalidRedirectURI, got %v", err)
		}
	})
}
