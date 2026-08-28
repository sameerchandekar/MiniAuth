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
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	ResponseType        string `json:"response_type"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// AuthCode represents a stored authorization code with associated PKCE challenge and client metadata.
type AuthCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
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
