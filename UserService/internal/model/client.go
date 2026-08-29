package model

import "time"

// ClientType defines OAuth 2.0 client types.
type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

// Client represents an OAuth 2.0 client database record.
type Client struct {
	ID               string     `json:"id"`
	ClientID         string     `json:"client_id"`
	ClientSecretHash *string    `json:"-"`
	Name             string     `json:"name"`
	ClientType       ClientType `json:"client_type"`
	CreatedAt        time.Time  `json:"created_at"`
}

// ClientResponse represents the complete OAuth 2.0 client metadata.
type ClientResponse struct {
	ID           string     `json:"id"`
	ClientID     string     `json:"client_id"`
	ClientSecret string     `json:"client_secret,omitempty"` // Only populated upon registration for confidential clients
	Name         string     `json:"name"`
	ClientType   ClientType `json:"client_type"`
	RedirectURIs []string   `json:"redirect_uris"`
	Scopes       []string   `json:"scopes"`
	CreatedAt    time.Time  `json:"created_at"`
}

// RegisterClientRequest contains parameters for creating a new OAuth 2.0 client.
type RegisterClientRequest struct {
	ClientID     string     `json:"client_id,omitempty"`     // Optional custom client_id; auto-generated if omitted
	ClientSecret string     `json:"client_secret,omitempty"` // Optional custom secret for confidential clients; auto-generated if omitted
	Name         string     `json:"name"`                    // Client application name (required)
	ClientType   ClientType `json:"client_type,omitempty"`   // "confidential" or "public" (default: "confidential")
	RedirectURIs []string   `json:"redirect_uris,omitempty"` // Allowed callback URLs
	Scopes       []string   `json:"scopes,omitempty"`        // Allowed OAuth scopes
}

// AddScopeRequest handles adding one or multiple scopes to a client.
type AddScopeRequest struct {
	Scope  string   `json:"scope,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

// AddRedirectURIRequest handles adding one or multiple redirect URIs to a client.
type AddRedirectURIRequest struct {
	RedirectURI  string   `json:"redirect_uri,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
}

// DeleteRedirectURIRequest handles removing a redirect URI via JSON payload.
type DeleteRedirectURIRequest struct {
	RedirectURI string `json:"redirect_uri"`
}
