package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
)

// JWKSResponse represents the RFC 7517 JSON Web Key Set structure.
type JWKSResponse struct {
	Keys []JWKKey `json:"keys"`
}

// JWKKey represents an individual RSA public key in RFC 7517 format.
type JWKKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWTSigner manages RSA key pairs, signs access tokens with RS256, and formats JWKS.
type JWTSigner struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	issuer     string
	ttl        time.Duration
}

// NewJWTSigner creates a new JWTSigner by loading RSA keys from environment, files, or generating a fallback pair.
func NewJWTSigner(cfg config.JWTConfig, issuerURL string, logger *slog.Logger) (*JWTSigner, error) {
	keyID := cfg.KeyID
	if keyID == "" {
		keyID = "miniauth-key-1"
	}
	if issuerURL == "" {
		issuerURL = "http://localhost:8080"
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	privKey, pubKey, err := loadOrGenerateKeys(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RSA keys: %w", err)
	}

	return &JWTSigner{
		privateKey: privKey,
		publicKey:  pubKey,
		keyID:      keyID,
		issuer:     issuerURL,
		ttl:        ttl,
	}, nil
}

func loadOrGenerateKeys(cfg config.JWTConfig, logger *slog.Logger) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// 1. Try loading from inline environment variable PEM string
	if cfg.PrivateKeyPEM != "" {
		privKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.PrivateKeyPEM))
		if err == nil {
			var pubKey *rsa.PublicKey
			if cfg.PublicKeyPEM != "" {
				pubKey, _ = jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.PublicKeyPEM))
			}
			if pubKey == nil {
				pubKey = &privKey.PublicKey
			}
			if logger != nil {
				logger.Info("loaded RSA signing key from JWT_PRIVATE_KEY environment variable")
			}
			return privKey, pubKey, nil
		}
	}

	// 2. Try loading from file path
	paths := []string{
		cfg.PrivateKeyPath,
		"keys/private_key.pem",
		"../keys/private_key.pem",
		"AuthorizationServer/keys/private_key.pem",
	}

	for _, path := range paths {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err == nil {
			privKey, err := jwt.ParseRSAPrivateKeyFromPEM(data)
			if err == nil {
				var pubKey *rsa.PublicKey
				if cfg.PublicKeyPath != "" {
					pubData, err := os.ReadFile(cfg.PublicKeyPath)
					if err == nil {
						pubKey, _ = jwt.ParseRSAPublicKeyFromPEM(pubData)
					}
				}
				if pubKey == nil {
					pubKey = &privKey.PublicKey
				}
				if logger != nil {
					logger.Info("loaded RSA signing key from file", slog.String("path", path))
				}
				return privKey, pubKey, nil
			}
		}
	}

	// 3. Fallback: Generate transient in-memory RSA 2048 key pair
	if logger != nil {
		logger.Warn("no RSA key file or environment variable found; generating transient in-memory RSA 2048-bit key pair")
	}
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate transient RSA key: %w", err)
	}

	return privKey, &privKey.PublicKey, nil
}

// SignToken signs the provided JWT claims using RSA SHA-256 (RS256) and attaches the Key ID (kid) in the header.
func (s *JWTSigner) SignToken(claims jwt.Claims) (string, error) {
	if s.privateKey == nil {
		return "", errors.New("rsa private key is not initialized")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID

	return token.SignedString(s.privateKey)
}

// JWKS returns the RFC 7517 JSON Web Key Set representation of the RSA public key.
func (s *JWTSigner) JWKS() *JWKSResponse {
	if s.publicKey == nil {
		return &JWKSResponse{Keys: []JWKKey{}}
	}

	n := base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.publicKey.E)).Bytes())

	return &JWKSResponse{
		Keys: []JWKKey{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: s.keyID,
				N:   n,
				E:   e,
			},
		},
	}
}

// KeyID returns the active key ID.
func (s *JWTSigner) KeyID() string {
	return s.keyID
}

// Issuer returns the configured token issuer.
func (s *JWTSigner) Issuer() string {
	return s.issuer
}

// PublicKey returns the RSA public key pointer.
func (s *JWTSigner) PublicKey() *rsa.PublicKey {
	return s.publicKey
}

// TTL returns the configured token lifetime duration.
func (s *JWTSigner) TTL() time.Duration {
	return s.ttl
}
