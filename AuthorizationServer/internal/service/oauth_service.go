package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/crypto"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/repository"
)

var (
	// Authorize errors
	ErrInvalidClientID     = errors.New("invalid_request: client_id is required")
	ErrClientValidation    = errors.New("unauthorized_client: client is not authorized or not found")
	ErrInvalidRedirectURI  = errors.New("invalid_request: redirect_uri is not registered for this client")
	ErrScopeNotAllowed     = errors.New("invalid_scope: requested scope exceeds allowed scopes")
	ErrUnsupportedResponse = errors.New("unsupported_response_type: only 'code' response_type is supported")

	// Token endpoint RFC 6749 Section 5.2 standard errors
	ErrInvalidRequest       = errors.New("invalid_request")
	ErrInvalidClient        = errors.New("invalid_client")
	ErrInvalidGrant         = errors.New("invalid_grant")
	ErrUnauthorizedClient   = errors.New("unauthorized_client")
	ErrUnsupportedGrantType = errors.New("unsupported_grant_type")
	ErrInvalidScope         = errors.New("invalid_scope")
)

// AccessTokenClaims defines the JWT claims payload for OAuth 2.0 access tokens (RFC 9068).
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

// IDTokenClaims defines the OpenID Connect Core 1.0 ID token claims payload.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	AuthTime          int64  `json:"auth_time,omitempty"`
	Name              string `json:"name,omitempty"`
	Email             string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

// OAuthService defines the interface for OAuth 2.0 authorization and token issuance logic.
type OAuthService interface {
	Authorize(ctx context.Context, req model.AuthorizeRequest) (*model.AuthorizeResult, error)
	Token(ctx context.Context, req model.TokenRequest) (*model.TokenResponse, error)
}

// DefaultOAuthService implements OAuthService.
type DefaultOAuthService struct {
	clientRepo       repository.ClientRepository
	authCodeRepo     repository.AuthCodeRepository
	refreshTokenRepo repository.RefreshTokenRepository
	jwtSigner        *crypto.JWTSigner
	db               *sql.DB
}

// NewOAuthService creates a new DefaultOAuthService.
func NewOAuthService(
	clientRepo repository.ClientRepository,
	authCodeRepo repository.AuthCodeRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	jwtSigner *crypto.JWTSigner,
) *DefaultOAuthService {
	if jwtSigner == nil {
		jwtSigner, _ = crypto.NewJWTSigner(config.JWTConfig{}, "http://localhost:8080", nil)
	}
	return &DefaultOAuthService{
		clientRepo:       clientRepo,
		authCodeRepo:     authCodeRepo,
		refreshTokenRepo: refreshTokenRepo,
		jwtSigner:        jwtSigner,
	}
}

// WithDB sets the database instance for user profile resolution in ID tokens.
func (s *DefaultOAuthService) WithDB(db *sql.DB) *DefaultOAuthService {
	s.db = db
	return s
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
			return nil, ErrInvalidRedirectURI
		}
	}
	if !isRedirectURIAllowed(redirectURI, client.RedirectURIs) {
		return nil, ErrInvalidRedirectURI
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
		UserID:              req.UserID,
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

// Token exchanges an authorization code for an RS256 signed JWT access token and refresh token,
// with scopes embedded directly into JWT claims.
func (s *DefaultOAuthService) Token(ctx context.Context, req model.TokenRequest) (*model.TokenResponse, error) {
	// 1. Validate grant_type
	if strings.TrimSpace(req.GrantType) != "authorization_code" {
		return nil, fmt.Errorf("%w: unsupported grant_type '%s', only 'authorization_code' is supported", ErrUnsupportedGrantType, req.GrantType)
	}

	codeStr := strings.TrimSpace(req.Code)
	if codeStr == "" {
		return nil, fmt.Errorf("%w: code parameter is required", ErrInvalidRequest)
	}

	// 2. Fetch and single-use invalidate authorization code from storage (Redis)
	authCode, err := s.authCodeRepo.Get(ctx, codeStr)
	if err != nil {
		return nil, fmt.Errorf("%w: authorization code is invalid or expired", ErrInvalidGrant)
	}

	// Delete immediately to enforce single-use semantics (RFC 6749 Section 4.1.2)
	_ = s.authCodeRepo.Delete(ctx, codeStr)

	if authCode == nil {
		return nil, fmt.Errorf("%w: authorization code not found", ErrInvalidGrant)
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("%w: authorization code has expired", ErrInvalidGrant)
	}

	// 3. Verify client_id match
	reqClientID := strings.TrimSpace(req.ClientID)
	if reqClientID != "" && authCode.ClientID != reqClientID {
		return nil, fmt.Errorf("%w: client_id mismatch", ErrInvalidGrant)
	}

	// Verify client is registered in database
	client, err := s.clientRepo.GetByClientID(ctx, authCode.ClientID)
	if err != nil || client == nil {
		return nil, fmt.Errorf("%w: registered client not found", ErrInvalidClient)
	}

	// 4. Verify redirect_uri match (RFC 6749 Section 4.1.3)
	reqRedirectURI := strings.TrimSpace(req.RedirectURI)
	if reqRedirectURI != "" && authCode.RedirectURI != reqRedirectURI {
		return nil, fmt.Errorf("%w: redirect_uri mismatch", ErrInvalidGrant)
	}

	// 5. PKCE Verification (RFC 7636 Section 4.6)
	if authCode.CodeChallenge != "" {
		codeVerifier := strings.TrimSpace(req.CodeVerifier)
		if codeVerifier == "" {
			return nil, fmt.Errorf("%w: code_verifier is required for PKCE-protected code", ErrInvalidGrant)
		}
		if !verifyCodeChallenge(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, fmt.Errorf("%w: code_verifier does not match code_challenge", ErrInvalidGrant)
		}
	}

	// 6. Generate signed JWT Access Token using RS256 with embedded scope claims (RFC 9068)
	now := time.Now()
	ttl := s.jwtSigner.TTL()
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	expiresAt := now.Add(ttl)
	sub := authCode.ClientID
	if authCode.UserID != nil && *authCode.UserID != "" {
		sub = *authCode.UserID
	}

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.jwtSigner.Issuer(),
			Subject:   sub,
			Audience:  jwt.ClaimStrings{authCode.ClientID},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        generateUUID(),
		},
		ClientID: authCode.ClientID,
		Scope:    authCode.Scope,
	}

	accessToken, err := s.jwtSigner.SignToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign jwt access token: %w", err)
	}

	// 7. Generate OpenID Connect ID Token (RS256) if openid scope requested or user authenticated
	var idToken string
	if strings.Contains(authCode.Scope, "openid") || authCode.UserID != nil {
		var userName, userEmail string

		// Lookup user in PostgreSQL database if available
		if s.db != nil && sub != "" {
			_ = s.db.QueryRowContext(ctx, "SELECT name, email FROM users WHERE id::text = $1 OR email = $1 LIMIT 1", sub).Scan(&userName, &userEmail)
		}

		if userName == "" {
			if sub == "user-001" {
				userName = "Demo User 001"
				userEmail = "user001@example.com"
			} else if strings.Contains(sub, "@") {
				userEmail = sub
				userName = strings.Title(strings.Split(sub, "@")[0])
			} else if len(sub) == 36 && strings.Count(sub, "-") == 4 { // UUID
				if userEmail != "" {
					userName = userEmail
				} else {
					userName = "User"
				}
			} else if strings.HasPrefix(sub, "user") {
				userName = "User " + strings.TrimPrefix(sub, "user")
				userEmail = fmt.Sprintf("%s@example.com", sub)
			} else {
				userName = strings.Title(sub)
				userEmail = fmt.Sprintf("%s@example.com", sub)
			}
		}

		if userEmail == "" {
			userEmail = fmt.Sprintf("%s@example.com", sub)
		}

		idClaims := IDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    s.jwtSigner.Issuer(),
				Subject:   sub,
				Audience:  jwt.ClaimStrings{authCode.ClientID},
				ExpiresAt: jwt.NewNumericDate(expiresAt),
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ID:        generateUUID(),
			},
			AuthTime:          now.Unix(),
			Name:              userName,
			Email:             userEmail,
			PreferredUsername: sub,
		}

		idToken, _ = s.jwtSigner.SignToken(idClaims)
	}

	// 8. Generate raw refresh token
	rawRefreshToken := "rt_" + generateSecureToken(32)

	// 9. Persist refresh token hash in refresh_tokens table
	tokenHash := hashToken(rawRefreshToken)
	familyID := generateUUID()
	familyExpiresAt := now.Add(90 * 24 * time.Hour) // 90 days

	rtRecord := &model.RefreshToken{
		TokenHash:       tokenHash,
		UserID:          authCode.UserID,
		ClientID:        authCode.ClientID,
		FamilyID:        familyID,
		CreatedAt:       now,
		ExpiresAt:       now.Add(30 * 24 * time.Hour), // 30 days
		FamilyExpiresAt: familyExpiresAt,
	}

	if s.refreshTokenRepo != nil {
		if err := s.refreshTokenRepo.Create(ctx, rtRecord); err != nil {
			return nil, fmt.Errorf("failed to persist refresh token: %w", err)
		}
	}

	// Note: Scope is conveyed inside JWT claims and omitted from response body per requirement
	return &model.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(ttl.Seconds()),
		RefreshToken: rawRefreshToken,
		IDToken:      idToken,
	}, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func verifyCodeChallenge(codeVerifier, expectedChallenge, method string) bool {
	switch strings.ToUpper(method) {
	case "S256":
		h := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return subtle.ConstantTimeCompare([]byte(computed), []byte(expectedChallenge)) == 1
	case "PLAIN", "":
		return subtle.ConstantTimeCompare([]byte(codeVerifier), []byte(expectedChallenge)) == 1
	default:
		return false
	}
}

func generateSecureToken(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return hex.EncodeToString(b)
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

func isRedirectURIAllowed(requestedURI string, registeredURIs []string) bool {
	for _, uri := range registeredURIs {
		if uri == requestedURI {
			return true
		}
	}
	return false
}
