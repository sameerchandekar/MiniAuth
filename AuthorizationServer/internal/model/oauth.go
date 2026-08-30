package model

import (
	"net/url"
	"time"
)

// Client represents an OAuth 2.0 registered client application.
type Client struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret,omitempty"`
	ClientName    string    `json:"client_name"`
	RedirectURIs  []string  `json:"redirect_uris"`
	AllowedScopes []string  `json:"allowed_scopes"`
	CreatedAt     time.Time `json:"created_at"`
}

// AuthorizeRequest contains the incoming query parameters for /authorize.
type AuthorizeRequest struct {
	ClientID            string  `json:"client_id"`
	UserID              *string `json:"user_id,omitempty"`
	RedirectURI         string  `json:"redirect_uri"`
	ResponseType        string  `json:"response_type"`
	Scope               string  `json:"scope"`
	State               string  `json:"state"`
	CodeChallenge       string  `json:"code_challenge"`
	CodeChallengeMethod string  `json:"code_challenge_method"`
}

// AuthCode represents a stored authorization code with associated PKCE challenge and client metadata.
type AuthCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              *string   `json:"user_id,omitempty"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// AuthorizeResult represents the outcome of a successful authorization request.
type AuthorizeResult struct {
	RedirectURI string `json:"redirect_uri"`
	Code        string `json:"code"`
	State       string `json:"state"`
}

// RedirectURL constructs the full redirect URL with code and state parameters.
func (r *AuthorizeResult) RedirectURL() string {
	targetURL, err := url.Parse(r.RedirectURI)
	if err != nil {
		targetURL, _ = url.Parse("https://myapp.com/oauth/callback")
	}

	query := targetURL.Query()
	query.Set("code", r.Code)
	if r.State != "" {
		query.Set("state", r.State)
	}
	targetURL.RawQuery = query.Encode()

	return targetURL.String()
}

// TokenRequest represents the payload for POST /token.
type TokenRequest struct {
	GrantType    string `json:"grant_type" schema:"grant_type"`
	Code         string `json:"code" schema:"code"`
	RedirectURI  string `json:"redirect_uri" schema:"redirect_uri"`
	ClientID     string `json:"client_id" schema:"client_id"`
	ClientSecret string `json:"client_secret,omitempty" schema:"client_secret"`
	CodeVerifier string `json:"code_verifier" schema:"code_verifier"`
}

// TokenResponse represents the standard RFC 6749 OAuth 2.0 token response.
// Note: Scope is conveyed inside JWT access_token claims rather than top-level response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// RefreshToken represents a persisted refresh token entity in refresh_tokens table.
type RefreshToken struct {
	ID              string     `json:"id"`
	TokenHash       string     `json:"token_hash"`
	UserID          *string    `json:"user_id,omitempty"`
	ClientID        string     `json:"client_id"`
	FamilyID        string     `json:"family_id"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	FamilyExpiresAt time.Time  `json:"family_expires_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	ReplacedBy      *string    `json:"replaced_by,omitempty"`
}

// OAuthErrorResponse represents standard RFC 6749 Section 5.2 error JSON payload.
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}
