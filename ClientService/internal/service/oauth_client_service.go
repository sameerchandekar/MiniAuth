package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sameerchandekar/MiniAuth/ClientService/internal/config"
)

var (
	ErrInvalidState = errors.New("invalid or expired oauth state parameter")
)

// TokenResponse represents the JSON response returned by AuthorizationServer /token.
// Note: Scope is conveyed inside JWT access_token claims.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// OAuthClientService handles PKCE challenge generation, authorization redirect URL building, and token exchange.
type OAuthClientService struct {
	cfg        *config.Config
	stateStore StateStore
	httpClient *http.Client
}

// NewOAuthClientService creates a new OAuthClientService.
func NewOAuthClientService(cfg *config.Config, stateStore StateStore, httpClient *http.Client) *OAuthClientService {
	if stateStore == nil {
		stateStore = NewMemoryStateStore()
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &OAuthClientService{
		cfg:        cfg,
		stateStore: stateStore,
		httpClient: httpClient,
	}
}

// BuildAuthorizeURL generates PKCE credentials and state, stores them in Redis/StateStore, and constructs the /authorize URL.
func (s *OAuthClientService) BuildAuthorizeURL(ctx context.Context) (string, string, error) {
	// 1. Generate random state ID
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random state: %w", err)
	}
	state := hex.EncodeToString(stateBytes)

	// 2. Generate PKCE code_verifier (32 random bytes -> 43 base64url chars)
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random code_verifier: %w", err)
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	// 3. Compute code_challenge = BASE64URL(SHA256(code_verifier))
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// 4. Save state ID and code_verifier in Redis with a 10-minute TTL
	err := s.stateStore.SaveState(ctx, state, &StateData{
		State:        state,
		CodeVerifier: codeVerifier,
		CreatedAt:    time.Now(),
	}, 10*time.Minute)
	if err != nil {
		return "", "", fmt.Errorf("failed to store state: %w", err)
	}

	// 5. Construct /authorize URL
	authEndpoint := strings.TrimRight(s.cfg.AuthServerURL, "/") + "/authorize"
	u, err := url.Parse(authEndpoint)
	if err != nil {
		return "", "", fmt.Errorf("invalid auth server url: %w", err)
	}

	q := u.Query()
	q.Set("client_id", s.cfg.ClientID)
	q.Set("redirect_uri", s.cfg.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", s.cfg.Scopes)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	return u.String(), state, nil
}

// ExchangeCodeForToken verifies and deletes the state ID from Redis, then calls AuthorizationServer /token.
func (s *OAuthClientService) ExchangeCodeForToken(ctx context.Context, code, state string) (*TokenResponse, error) {
	// 1. Verify presence in Redis and delete immediately (anti-replay single-use)
	stateData, err := s.stateStore.GetAndDeleteState(ctx, strings.TrimSpace(state))
	if err != nil || stateData == nil {
		return nil, ErrInvalidState
	}

	// 2. Prepare /token form payload using verified code_verifier
	internalURL := s.cfg.AuthServerInternalURL
	if internalURL == "" {
		internalURL = s.cfg.AuthServerURL
	}
	tokenEndpoint := strings.TrimRight(internalURL, "/") + "/token"
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.TrimSpace(code))
	form.Set("redirect_uri", s.cfg.RedirectURI)
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}
	if stateData.CodeVerifier != "" {
		form.Set("code_verifier", stateData.CodeVerifier)
	}

	// 3. Make POST request to AuthorizationServer
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute token request to auth server: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from auth server: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenRes TokenResponse
	if err := json.Unmarshal(bodyBytes, &tokenRes); err != nil {
		return nil, fmt.Errorf("failed to parse token response json: %w", err)
	}

	return &tokenRes, nil
}
