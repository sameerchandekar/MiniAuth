package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/config"
)

type contextKey string

const (
	claimsContextKey contextKey = "jwt_claims"
)

var (
	ErrMissingAuthHeader = errors.New("missing or malformed authorization header")
	ErrInvalidToken      = errors.New("invalid or expired access token")
	ErrInsufficientScope = errors.New("insufficient scope for requested resource")
)

// JWTClaims represents verified JWT access token claims (RFC 9068).
type JWTClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

// ScopesList returns the granted scopes as a slice of individual strings.
func (c *JWTClaims) ScopesList() []string {
	return strings.Fields(c.Scope)
}

// HasScope checks if the token has the exact given scope.
func (c *JWTClaims) HasScope(scope string) bool {
	for _, s := range c.ScopesList() {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the token has at least one of the required scopes.
func (c *JWTClaims) HasAnyScope(scopes ...string) bool {
	for _, required := range scopes {
		if c.HasScope(required) {
			return true
		}
	}
	return false
}

// AuthMiddleware verifies incoming JWT Bearer tokens and enforces scope permissions.
type AuthMiddleware struct {
	cfg        *config.Config
	logger     *slog.Logger
	httpClient *http.Client

	// Public Key Cache
	mu          sync.RWMutex
	cachedKeys  map[string]*rsa.PublicKey
	lastFetched time.Time
}

// NewAuthMiddleware creates a new AuthMiddleware instance.
func NewAuthMiddleware(cfg *config.Config, staticPubKey *rsa.PublicKey, logger *slog.Logger) *AuthMiddleware {
	m := &AuthMiddleware{
		cfg:        cfg,
		logger:     logger,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cachedKeys: make(map[string]*rsa.PublicKey),
	}

	if staticPubKey != nil {
		m.cachedKeys["default"] = staticPubKey
	} else {
		m.loadStaticPublicKey()
	}

	return m
}

func (m *AuthMiddleware) loadStaticPublicKey() {
	if m.cfg.PublicKeyPEM != "" {
		pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(m.cfg.PublicKeyPEM))
		if err == nil {
			m.cachedKeys["default"] = pubKey
			if m.logger != nil {
				m.logger.Info("loaded static RSA public key from JWT_PUBLIC_KEY environment variable")
			}
			return
		}
	}

	paths := []string{
		m.cfg.PublicKeyPath,
		"keys/public_key.pem",
		"../keys/public_key.pem",
		"AuthorizationServer/keys/public_key.pem",
	}

	for _, path := range paths {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err == nil {
			pubKey, err := jwt.ParseRSAPublicKeyFromPEM(data)
			if err == nil {
				m.cachedKeys["default"] = pubKey
				if m.logger != nil {
					m.logger.Info("loaded static RSA public key from file", slog.String("path", path))
				}
				return
			}
		}
	}
}

// Authenticate is an HTTP middleware that extracts and validates the Bearer token.
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Missing or malformed Authorization header"`)
			http.Error(w, `{"error":"unauthorized","error_description":"Authorization Bearer token required"}`, http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimSpace(authHeader[7:])
		if tokenStr == "" {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Empty bearer token"`)
			http.Error(w, `{"error":"unauthorized","error_description":"Bearer token cannot be empty"}`, http.StatusUnauthorized)
			return
		}

		claims, err := m.VerifyToken(r.Context(), tokenStr)
		if err != nil {
			if m.logger != nil {
				m.logger.Warn("token verification failed", slog.String("error", err.Error()))
			}
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", error_description="%s"`, err.Error()))
			http.Error(w, fmt.Sprintf(`{"error":"invalid_token","error_description":"%s"}`, err.Error()), http.StatusUnauthorized)
			return
		}

		// Inject verified claims into request context
		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireScope creates a middleware that ensures the token contains at least one of the allowed scopes.
func RequireScope(allowedScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				http.Error(w, `{"error":"unauthorized","error_description":"Authentication required"}`, http.StatusUnauthorized)
				return
			}

			if !claims.HasAnyScope(allowedScopes...) {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope="%s"`, strings.Join(allowedScopes, " ")))
				http.Error(w, fmt.Sprintf(`{"error":"insufficient_scope","error_description":"Access denied: requires one of the following scopes [%s]"}`, strings.Join(allowedScopes, ", ")), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// VerifyToken parses and verifies the signature and validity of the JWT token string.
func (m *AuthMiddleware) VerifyToken(ctx context.Context, tokenStr string) (*JWTClaims, error) {
	var claims JWTClaims

	parsedToken, err := jwt.ParseWithClaims(
		tokenStr,
		&claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing algorithm: %v", token.Header["alg"])
			}

			kid, _ := token.Header["kid"].(string)
			return m.resolvePublicKey(ctx, kid)
		},
		jwt.WithExpirationRequired(), // Ensures 'exp' claim is present and valid
	)

	if err != nil || !parsedToken.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: token has expired", ErrInvalidToken)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Explicit expiration check
	if claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("%w: token has expired", ErrInvalidToken)
	}

	// Validate Issuer if configured
	if m.cfg.IssuerURL != "" && claims.Issuer != "" && claims.Issuer != m.cfg.IssuerURL {
		return nil, fmt.Errorf("%w: issuer mismatch (expected %s, got %s)", ErrInvalidToken, m.cfg.IssuerURL, claims.Issuer)
	}

	// Validate Audience if configured
	if m.cfg.Audience != "" {
		audMatched := false
		for _, aud := range claims.Audience {
			if aud == m.cfg.Audience {
				audMatched = true
				break
			}
		}
		if !audMatched {
			return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
		}
	}

	return &claims, nil
}

func (m *AuthMiddleware) resolvePublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	m.mu.RLock()
	// Check cached keys
	if kid != "" {
		if key, exists := m.cachedKeys[kid]; exists {
			m.mu.RUnlock()
			return key, nil
		}
	}
	if defKey, exists := m.cachedKeys["default"]; exists {
		m.mu.RUnlock()
		return defKey, nil
	}
	m.mu.RUnlock()

	// Try fetching from JWKS endpoint if URL is provided
	if m.cfg.JWKSURL != "" {
		if err := m.fetchJWKS(ctx); err == nil {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if key, exists := m.cachedKeys[kid]; exists {
				return key, nil
			}
			if defKey, exists := m.cachedKeys["default"]; exists {
				return defKey, nil
			}
		}
	}

	return nil, errors.New("no matching RSA public key found to verify token signature")
}

type jwksDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (m *AuthMiddleware) fetchJWKS(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if time.Since(m.lastFetched) < 1*time.Minute && len(m.cachedKeys) > 0 {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.JWKSURL, nil)
	if err != nil {
		return err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}

	for _, k := range doc.Keys {
		if k.Kty == "RSA" && k.N != "" && k.E != "" {
			pubKey, err := parseRSAPublicKeyFromJWK(k.N, k.E)
			if err == nil {
				if k.Kid != "" {
					m.cachedKeys[k.Kid] = pubKey
				}
				m.cachedKeys["default"] = pubKey
			}
		}
	}

	m.lastFetched = time.Now()
	return nil
}

func parseRSAPublicKeyFromJWK(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// WithClaims injects JWTClaims into a context (useful for testing and internal calls).
func WithClaims(ctx context.Context, claims *JWTClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// GetClaims extracts JWT claims from context if present.
func GetClaims(ctx context.Context) *JWTClaims {
	val := ctx.Value(claimsContextKey)
	if val == nil {
		return nil
	}
	claims, ok := val.(*JWTClaims)
	if !ok {
		return nil
	}
	return claims
}
