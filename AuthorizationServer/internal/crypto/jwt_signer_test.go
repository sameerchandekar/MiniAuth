package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/config"
)

func generateTestRSAPEMs(t *testing.T) (string, string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test RSA key: %v", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return string(privPEM), string(pubPEM)
}

func TestJWTSigner_SignAndVerifyWithJWKS(t *testing.T) {
	privPEM, pubPEM := generateTestRSAPEMs(t)

	cfg := config.JWTConfig{
		PrivateKeyPEM: privPEM,
		PublicKeyPEM:  pubPEM,
		KeyID:         "test-key-001",
	}

	signer, err := NewJWTSigner(cfg, "http://localhost:8080", nil)
	if err != nil {
		t.Fatalf("unexpected error creating JWTSigner: %v", err)
	}

	// 1. Sign a token
	claims := jwt.MapClaims{
		"sub":   "user-123",
		"scope": "openid profile email",
	}
	signedToken, err := signer.SignToken(claims)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// 2. Verify token with Public Key
	parsed, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			t.Fatalf("unexpected signing alg: %s", token.Method.Alg())
		}
		if token.Header["kid"] != "test-key-001" {
			t.Errorf("expected kid 'test-key-001', got %v", token.Header["kid"])
		}
		return signer.PublicKey(), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("failed to verify signed token with public key: %v", err)
	}

	// 3. Verify JWKS output
	jwks := signer.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	if key.Kty != "RSA" || key.Alg != "RS256" || key.Use != "sig" || key.Kid != "test-key-001" {
		t.Errorf("unexpected JWK fields: %+v", key)
	}
	if key.N == "" || key.E == "" {
		t.Errorf("expected non-empty N and E in JWK: %+v", key)
	}
}

func TestJWTSigner_FallbackTransientKey(t *testing.T) {
	// Empty config -> Should generate transient RSA key pair without errors
	cfg := config.JWTConfig{}
	signer, err := NewJWTSigner(cfg, "http://localhost:8080", nil)
	if err != nil {
		t.Fatalf("unexpected error creating fallback JWTSigner: %v", err)
	}

	jwks := signer.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key in fallback JWKS, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid == "" {
		t.Errorf("expected non-empty Kid in fallback key")
	}
}
