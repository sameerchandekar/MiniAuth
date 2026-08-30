package handler

import (
	"encoding/json"
	"net/http"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/crypto"
)

// JWKSHandler serves the RFC 7517 JSON Web Key Set containing public keys.
type JWKSHandler struct {
	jwtSigner *crypto.JWTSigner
}

// NewJWKSHandler creates a new JWKSHandler.
func NewJWKSHandler(jwtSigner *crypto.JWTSigner) *JWKSHandler {
	return &JWKSHandler{jwtSigner: jwtSigner}
}

// JWKS responds with the JSON Web Key Set (GET /.well-known/jwks.json).
func (h *JWKSHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.jwtSigner.JWKS()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(jwks)
}
