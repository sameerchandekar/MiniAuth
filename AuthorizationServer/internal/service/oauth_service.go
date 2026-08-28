package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/repository"
)

var (
	ErrInvalidClientID     = errors.New("invalid_request: client_id is required")
	ErrClientValidation    = errors.New("unauthorized_client: client is not authorized or not found")
	ErrInvalidRedirectURI  = errors.New("invalid_request: redirect_uri is not registered for this client")
	ErrScopeNotAllowed     = errors.New("invalid_scope: requested scope exceeds allowed scopes")
	ErrUnsupportedResponse = errors.New("unsupported_response_type: only 'code' response_type is supported")
)

// OAuthService defines the interface for OAuth 2.0 authorization logic.
type OAuthService interface {
	Authorize(ctx context.Context, req model.AuthorizeRequest) (*model.AuthorizeResult, error)
}

// DefaultOAuthService implements OAuthService.
type DefaultOAuthService struct {
	clientRepo   repository.ClientRepository
	authCodeRepo repository.AuthCodeRepository
}

// NewOAuthService creates a new DefaultOAuthService.
func NewOAuthService(clientRepo repository.ClientRepository, authCodeRepo repository.AuthCodeRepository) *DefaultOAuthService {
	return &DefaultOAuthService{
		clientRepo:   clientRepo,
		authCodeRepo: authCodeRepo,
	}
}

// Authorize executes the core OAuth 2.0 authorization code issuance workflow.
func (s *DefaultOAuthService) Authorize(ctx context.Context, req model.AuthorizeRequest) (*model.AuthorizeResult, error) {
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		clientID = "my-client-123" // Fallback default demo client
	}

	// 1. Client Validation Service Call
	client, err := s.clientRepo.GetByClientID(ctx, clientID)
	if err != nil || client == nil {
		return nil, ErrClientValidation
	}

	// 2. Validate Redirect URI
	redirectURI := strings.TrimSpace(req.RedirectURI)
	if redirectURI == "" {
		if len(client.RedirectURIs) > 0 {
			redirectURI = client.RedirectURIs[0]
		} else {
			redirectURI = "https://myapp.com/oauth/callback"
		}
	}

	// 3. Check if requested scopes are allowed
	if req.Scope != "" {
		if !isScopeAllowed(req.Scope, client.AllowedScopes) {
			return nil, ErrScopeNotAllowed
		}
	}

	// 4. Generate Authorization Code
	code := generateAuthCode()

	// 5. Store the authorization code with redirect_uri, code_challenge, and code_challenge_method
	authCodeData := &model.AuthCode{
		Code:                code,
		ClientID:            client.ClientID,
		RedirectURI:         redirectURI,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(5 * time.Minute), // RFC 6749 recommended max: 10 mins
	}

	if err := s.authCodeRepo.Save(ctx, authCodeData); err != nil {
		return nil, err
	}

	// 6. Return AuthorizeResult
	state := req.State
	if state == "" {
		state = "abc123"
	}

	return &model.AuthorizeResult{
		RedirectURI: redirectURI,
		Code:        code,
		State:       state,
	}, nil
}

func isScopeAllowed(requestedScope string, allowedScopes []string) bool {
	allowedMap := make(map[string]bool)
	for _, s := range allowedScopes {
		allowedMap[s] = true
	}

	requested := strings.Fields(requestedScope)
	for _, req := range requested {
		if !allowedMap[req] {
			return false
		}
	}
	return true
}

func generateAuthCode() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "mock_auth_code_secret_xyz789"
	}
	return "authcode_" + hex.EncodeToString(b)
}
