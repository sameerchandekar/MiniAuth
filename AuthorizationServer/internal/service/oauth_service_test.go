package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/crypto"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/repository"
)

func newTestOAuthService() (*DefaultOAuthService, repository.ClientRepository, repository.AuthCodeRepository, repository.RefreshTokenRepository, *crypto.JWTSigner) {
	clientRepo := repository.NewMemoryClientRepository()
	authCodeRepo := repository.NewMemoryAuthCodeRepository()
	refreshTokenRepo := repository.NewMemoryRefreshTokenRepository()
	jwtSigner, _ := crypto.NewJWTSigner(config.JWTConfig{KeyID: "test-key-1"}, "http://localhost:8080", nil)
	svc := NewOAuthService(clientRepo, authCodeRepo, refreshTokenRepo, jwtSigner)
	return svc, clientRepo, authCodeRepo, refreshTokenRepo, jwtSigner
}

func TestOAuthService_Authorize_Success(t *testing.T) {
	svc, _, authCodeRepo, _, _ := newTestOAuthService()

	req := model.AuthorizeRequest{
		ClientID:            "my-client-123",
		RedirectURI:         "https://myapp.com/oauth/callback",
		ResponseType:        "code",
		Scope:               "openid profile email",
		State:               "xyz789",
		CodeChallenge:       "E9Melhoa2OwvFrGMTJguCH5ZwKRKg5UPn2dAwdDlvue",
		CodeChallengeMethod: "S256",
	}

	res, err := svc.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.State != "xyz789" {
		t.Errorf("expected state 'xyz789', got '%s'", res.State)
	}
	if res.Code == "" {
		t.Errorf("expected non-empty code")
	}

	// Verify code was stored in repository
	saved, err := authCodeRepo.Get(context.Background(), res.Code)
	if err != nil {
		t.Fatalf("failed to retrieve saved auth code: %v", err)
	}
	if saved.ClientID != "my-client-123" {
		t.Errorf("expected client_id 'my-client-123', got '%s'", saved.ClientID)
	}
	if saved.CodeChallengeMethod != "S256" {
		t.Errorf("expected code_challenge_method 'S256', got '%s'", saved.CodeChallengeMethod)
	}
}

func TestOAuthService_Authorize_ScopeValidation(t *testing.T) {
	svc, _, _, _, _ := newTestOAuthService()

	req := model.AuthorizeRequest{
		ClientID:    "my-client-123",
		RedirectURI: "https://myapp.com/oauth/callback",
		Scope:       "openid unauthorized_super_scope",
	}

	_, err := svc.Authorize(context.Background(), req)
	if err != ErrScopeNotAllowed {
		t.Errorf("expected ErrScopeNotAllowed, got %v", err)
	}
}

func TestOAuthService_Authorize_RedirectURIValidation(t *testing.T) {
	svc, _, _, _, _ := newTestOAuthService()

	t.Run("unregistered redirect URI returns error", func(t *testing.T) {
		req := model.AuthorizeRequest{
			ClientID:    "my-client-123",
			RedirectURI: "https://attacker.com/evil/callback",
			Scope:       "openid",
		}

		_, err := svc.Authorize(context.Background(), req)
		if err != ErrInvalidRedirectURI {
			t.Errorf("expected ErrInvalidRedirectURI, got %v", err)
		}
	})

	t.Run("valid registered redirect URI succeeds", func(t *testing.T) {
		req := model.AuthorizeRequest{
			ClientID:    "my-client-123",
			RedirectURI: "http://localhost:3000/callback",
			Scope:       "openid",
		}

		res, err := svc.Authorize(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error for valid redirect URI: %v", err)
		}
		if res.RedirectURI != "http://localhost:3000/callback" {
			t.Errorf("expected redirect URI 'http://localhost:3000/callback', got '%s'", res.RedirectURI)
		}
	})
}

func TestOAuthService_Token_Success(t *testing.T) {
	svc, _, _, refreshTokenRepo, jwtSigner := newTestOAuthService()
	ctx := context.Background()

	// 1. First obtain an authorization code with PKCE (S256)
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	authRes, err := svc.Authorize(ctx, model.AuthorizeRequest{
		ClientID:            "my-client-123",
		RedirectURI:         "https://myapp.com/oauth/callback",
		ResponseType:        "code",
		Scope:               "openid profile email",
		State:               "state123",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("failed to authorize: %v", err)
	}

	// 2. Exchange authorization code for token
	tokenRes, err := svc.Token(ctx, model.TokenRequest{
		GrantType:    "authorization_code",
		Code:         authRes.Code,
		RedirectURI:  "https://myapp.com/oauth/callback",
		ClientID:     "my-client-123",
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		t.Fatalf("unexpected error during token exchange: %v", err)
	}

	if tokenRes.AccessToken == "" {
		t.Errorf("expected access_token to be non-empty")
	}
	if tokenRes.TokenType != "Bearer" {
		t.Errorf("expected token_type 'Bearer', got '%s'", tokenRes.TokenType)
	}
	if tokenRes.ExpiresIn != 3600 {
		t.Errorf("expected expires_in 3600, got %d", tokenRes.ExpiresIn)
	}
	if tokenRes.RefreshToken == "" {
		t.Errorf("expected refresh_token to be non-empty")
	}

	// 3. Verify RS256 JWT Access Token claims contain Scope (RFC 9068) using Public Key
	var claims AccessTokenClaims
	parsedToken, err := jwt.ParseWithClaims(tokenRes.AccessToken, &claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			t.Fatalf("unexpected signing algorithm: %s", token.Method.Alg())
		}
		return jwtSigner.PublicKey(), nil
	})
	if err != nil || !parsedToken.Valid {
		t.Fatalf("failed to parse/validate generated RS256 JWT access token: %v", err)
	}
	if claims.Scope != "openid profile email" {
		t.Errorf("expected scope claim 'openid profile email', got '%s'", claims.Scope)
	}
	if claims.ClientID != "my-client-123" {
		t.Errorf("expected client_id claim 'my-client-123', got '%s'", claims.ClientID)
	}
	if claims.Issuer != "http://localhost:8080" {
		t.Errorf("expected issuer claim 'http://localhost:8080', got '%s'", claims.Issuer)
	}

	// 4. Verify that the refresh token was persisted in repository
	tokenHash := hashToken(tokenRes.RefreshToken)
	savedRT, err := refreshTokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("expected refresh token to be saved in refresh_token repository: %v", err)
	}
	if savedRT.ClientID != "my-client-123" {
		t.Errorf("expected refresh token client_id 'my-client-123', got '%s'", savedRT.ClientID)
	}
	if savedRT.FamilyID == "" {
		t.Errorf("expected family_id to be populated")
	}

	// 5. Single-use test: re-using the same code should fail immediately
	_, err = svc.Token(ctx, model.TokenRequest{
		GrantType:    "authorization_code",
		Code:         authRes.Code,
		RedirectURI:  "https://myapp.com/oauth/callback",
		ClientID:     "my-client-123",
		CodeVerifier: codeVerifier,
	})
	if err == nil {
		t.Errorf("expected error when re-using authorization code, got nil")
	}
}

func TestOAuthService_Token_PKCE_Mismatch(t *testing.T) {
	svc, _, _, _, _ := newTestOAuthService()
	ctx := context.Background()

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	authRes, err := svc.Authorize(ctx, model.AuthorizeRequest{
		ClientID:            "my-client-123",
		RedirectURI:         "https://myapp.com/oauth/callback",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("failed to authorize: %v", err)
	}

	// Exchange with wrong verifier
	_, err = svc.Token(ctx, model.TokenRequest{
		GrantType:    "authorization_code",
		Code:         authRes.Code,
		RedirectURI:  "https://myapp.com/oauth/callback",
		ClientID:     "my-client-123",
		CodeVerifier: "wrong_verifier_xyz_12345",
	})
	if err == nil {
		t.Errorf("expected error for invalid PKCE verifier, got nil")
	}
}

func TestOAuthService_Token_UnsupportedGrantType(t *testing.T) {
	svc, _, _, _, _ := newTestOAuthService()

	_, err := svc.Token(context.Background(), model.TokenRequest{
		GrantType: "client_credentials",
		Code:      "any_code",
	})
	if err == nil {
		t.Errorf("expected error for unsupported grant_type, got nil")
	}
}
