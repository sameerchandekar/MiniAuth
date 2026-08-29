package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrClientNotFound      = errors.New("client not found")
	ErrClientAlreadyExists  = errors.New("client with this client_id already exists")
	ErrClientNameRequired   = errors.New("client name is required")
	ErrInvalidClientType   = errors.New("client_type must be either 'confidential' or 'public'")
	ErrInvalidRedirectURI  = errors.New("invalid redirect uri format")
	ErrScopeRequired       = errors.New("scope cannot be empty")
	ErrRedirectURIRequired = errors.New("redirect_uri cannot be empty")
)

// ClientService encapsulates business logic and validation for OAuth clients.
type ClientService struct {
	clientRepo *repository.ClientRepository
}

// NewClientService creates a new ClientService instance.
func NewClientService(clientRepo *repository.ClientRepository) *ClientService {
	return &ClientService{clientRepo: clientRepo}
}

// RegisterClient validates input, auto-generates client_id and secret (if needed), and creates the client.
func (s *ClientService) RegisterClient(ctx context.Context, req model.RegisterClientRequest) (*model.ClientResponse, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, ErrClientNameRequired
	}

	// Validate / default client_type
	clientType := req.ClientType
	if clientType == "" {
		clientType = model.ClientTypeConfidential
	}
	if clientType != model.ClientTypeConfidential && clientType != model.ClientTypePublic {
		return nil, ErrInvalidClientType
	}

	// Validate / generate client_id
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		randomID, err := generateRandomHex(16)
		if err != nil {
			return nil, fmt.Errorf("failed to generate client_id: %w", err)
		}
		clientID = randomID
	} else {
		existing, err := s.clientRepo.GetByClientID(ctx, clientID)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, ErrClientAlreadyExists
		}
	}

	// Handle client secret for confidential clients
	var rawSecret string
	var secretHash *string

	if clientType == model.ClientTypeConfidential {
		rawSecret = strings.TrimSpace(req.ClientSecret)
		if rawSecret == "" {
			generatedSecret, err := generateRandomHex(32)
			if err != nil {
				return nil, fmt.Errorf("failed to generate client_secret: %w", err)
			}
			rawSecret = generatedSecret
		}

		hashBytes, err := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash client secret: %w", err)
		}
		hashStr := string(hashBytes)
		secretHash = &hashStr
	}

	// Validate redirect URIs if provided
	sanitizedURIs := make([]string, 0, len(req.RedirectURIs))
	for _, rawURI := range req.RedirectURIs {
		trimmed := strings.TrimSpace(rawURI)
		if trimmed == "" {
			continue
		}
		parsed, err := url.ParseRequestURI(trimmed)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("%w: %s", ErrInvalidRedirectURI, trimmed)
		}
		sanitizedURIs = append(sanitizedURIs, trimmed)
	}

	// Validate scopes if provided
	sanitizedScopes := make([]string, 0, len(req.Scopes))
	for _, rawScope := range req.Scopes {
		trimmed := strings.TrimSpace(rawScope)
		if trimmed != "" {
			sanitizedScopes = append(sanitizedScopes, trimmed)
		}
	}

	// Insert client
	client, err := s.clientRepo.Create(ctx, clientID, secretHash, name, clientType)
	if err != nil {
		return nil, err
	}

	// Insert redirect URIs
	if len(sanitizedURIs) > 0 {
		if err := s.clientRepo.AddRedirectURIs(ctx, clientID, sanitizedURIs); err != nil {
			return nil, err
		}
	}

	// Insert scopes
	if len(sanitizedScopes) > 0 {
		if err := s.clientRepo.AddScopes(ctx, clientID, sanitizedScopes); err != nil {
			return nil, err
		}
	}

	return &model.ClientResponse{
		ID:           client.ID,
		ClientID:     client.ClientID,
		ClientSecret: rawSecret,
		Name:         client.Name,
		ClientType:   client.ClientType,
		RedirectURIs: sanitizedURIs,
		Scopes:       sanitizedScopes,
		CreatedAt:    client.CreatedAt,
	}, nil
}

// GetClient retrieves full client metadata by client_id.
func (s *ClientService) GetClient(ctx context.Context, clientID string) (*model.ClientResponse, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}

	client, err := s.clientRepo.GetFullClientDetail(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, ErrClientNotFound
	}

	return client, nil
}

// ListClients retrieves paginated list of clients with their redirect URIs and scopes.
func (s *ClientService) ListClients(ctx context.Context, limit, offset int) ([]model.ClientResponse, error) {
	clients, err := s.clientRepo.List(ctx, limit, offset)
	if err != nil {
		return nil, err
	}

	results := make([]model.ClientResponse, 0, len(clients))
	for _, c := range clients {
		uris, err := s.clientRepo.GetRedirectURIs(ctx, c.ClientID)
		if err != nil {
			return nil, err
		}
		scopes, err := s.clientRepo.GetScopes(ctx, c.ClientID)
		if err != nil {
			return nil, err
		}

		results = append(results, model.ClientResponse{
			ID:           c.ID,
			ClientID:     c.ClientID,
			Name:         c.Name,
			ClientType:   c.ClientType,
			RedirectURIs: uris,
			Scopes:       scopes,
			CreatedAt:    c.CreatedAt,
		})
	}

	return results, nil
}

// DeleteClient deletes an OAuth client by client_id.
func (s *ClientService) DeleteClient(ctx context.Context, clientID string) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return errors.New("client_id is required")
	}

	// Verify client exists
	existing, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrClientNotFound
	}

	return s.clientRepo.Delete(ctx, clientID)
}

// AddScopes adds one or more scopes to an existing client.
func (s *ClientService) AddScopes(ctx context.Context, clientID string, scopes []string) ([]string, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}

	existing, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, ErrClientNotFound
	}

	for _, sc := range scopes {
		trimmed := strings.TrimSpace(sc)
		if trimmed == "" {
			return nil, ErrScopeRequired
		}
		if err := s.clientRepo.AddScope(ctx, clientID, trimmed); err != nil {
			return nil, err
		}
	}

	return s.clientRepo.GetScopes(ctx, clientID)
}

// RemoveScope removes a scope from a client.
func (s *ClientService) RemoveScope(ctx context.Context, clientID, scope string) error {
	clientID = strings.TrimSpace(clientID)
	scope = strings.TrimSpace(scope)
	if clientID == "" || scope == "" {
		return errors.New("client_id and scope are required")
	}

	existing, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrClientNotFound
	}

	return s.clientRepo.RemoveScope(ctx, clientID, scope)
}

// SetScopes replaces all scopes for an existing client (full overwrite / PUT).
func (s *ClientService) SetScopes(ctx context.Context, clientID string, scopes []string) ([]string, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}

	existing, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, ErrClientNotFound
	}

	sanitizedScopes := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		trimmed := strings.TrimSpace(sc)
		if trimmed != "" {
			sanitizedScopes = append(sanitizedScopes, trimmed)
		}
	}

	if err := s.clientRepo.ReplaceScopes(ctx, clientID, sanitizedScopes); err != nil {
		return nil, err
	}

	return s.clientRepo.GetScopes(ctx, clientID)
}

// AddRedirectURIs adds one or more redirect URIs to an existing client (incremental append / POST).
func (s *ClientService) AddRedirectURIs(ctx context.Context, clientID string, uris []string) ([]string, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}

	existing, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, ErrClientNotFound
	}

	for _, rawURI := range uris {
		trimmed := strings.TrimSpace(rawURI)
		if trimmed == "" {
			return nil, ErrRedirectURIRequired
		}
		parsed, err := url.ParseRequestURI(trimmed)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("%w: %s", ErrInvalidRedirectURI, trimmed)
		}
		if err := s.clientRepo.AddRedirectURI(ctx, clientID, trimmed); err != nil {
			return nil, err
		}
	}

	return s.clientRepo.GetRedirectURIs(ctx, clientID)
}

// SetRedirectURIs replaces all redirect URIs for an existing client (full overwrite / PUT).
func (s *ClientService) SetRedirectURIs(ctx context.Context, clientID string, uris []string) ([]string, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}

	existing, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, ErrClientNotFound
	}

	sanitizedURIs := make([]string, 0, len(uris))
	for _, rawURI := range uris {
		trimmed := strings.TrimSpace(rawURI)
		if trimmed == "" {
			continue
		}
		parsed, err := url.ParseRequestURI(trimmed)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("%w: %s", ErrInvalidRedirectURI, trimmed)
		}
		sanitizedURIs = append(sanitizedURIs, trimmed)
	}

	if err := s.clientRepo.ReplaceRedirectURIs(ctx, clientID, sanitizedURIs); err != nil {
		return nil, err
	}

	return s.clientRepo.GetRedirectURIs(ctx, clientID)
}

// RemoveRedirectURI removes a redirect URI from a client.
func (s *ClientService) RemoveRedirectURI(ctx context.Context, clientID, uri string) error {
	clientID = strings.TrimSpace(clientID)
	uri = strings.TrimSpace(uri)
	if clientID == "" || uri == "" {
		return errors.New("client_id and redirect_uri are required")
	}

	existing, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrClientNotFound
	}

	return s.clientRepo.RemoveRedirectURI(ctx, clientID, uri)
}

func generateRandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
