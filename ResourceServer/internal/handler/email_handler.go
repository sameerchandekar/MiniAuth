package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/middleware"
)

// EmailMessage represents a protected email resource.
type EmailMessage struct {
	ID         string    `json:"id"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	Subject    string    `json:"subject"`
	Snippet    string    `json:"snippet"`
	ReceivedAt time.Time `json:"received_at"`
}

// SendEmailRequest represents payload to send a new email.
type SendEmailRequest struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// EmailHandler provides protected email API endpoints.
type EmailHandler struct{}

// NewEmailHandler creates a new EmailHandler.
func NewEmailHandler() *EmailHandler {
	return &EmailHandler{}
}

// ListEmails handles GET /api/v1/emails (requires 'read' or 'email' scope).
func (h *EmailHandler) ListEmails(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	userID := "anonymous"
	clientID := ""
	scope := ""

	if claims != nil {
		userID = claims.Subject
		clientID = claims.ClientID
		scope = claims.Scope
	}

	messages := []EmailMessage{
		{
			ID:         "msg-001",
			From:       "security@miniauth.com",
			To:         "user@example.com",
			Subject:    "OAuth 2.0 Access Token Verified",
			Snippet:    "Your RS256 JWT access token was successfully validated against MiniAuth JWKS.",
			ReceivedAt: time.Now().Add(-15 * time.Minute),
		},
		{
			ID:         "msg-002",
			From:       "team@miniauth.com",
			To:         "user@example.com",
			Subject:    "Welcome to Protected Resource Server",
			Snippet:    "You have successfully authenticated with 'read' scope permissions.",
			ReceivedAt: time.Now().Add(-2 * time.Hour),
		},
	}

	response := map[string]interface{}{
		"status":    "success",
		"user_id":   userID,
		"client_id": clientID,
		"scope":     scope,
		"count":     len(messages),
		"emails":    messages,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// SendEmail handles POST /api/v1/emails (requires 'write' scope).
func (h *EmailHandler) SendEmail(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())

	var req SendEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	if req.To == "" || req.Subject == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"'to' and 'subject' fields are required"}`, http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"status":  "sent",
		"id":      "msg-new-" + time.Now().Format("20060102150405"),
		"from":    claims.Subject,
		"to":      req.To,
		"subject": req.Subject,
		"sent_at": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// UserInfo handles GET /api/v1/userinfo (returns caller identity and claims).
func (h *EmailHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":       claims.Subject,
		"client_id": claims.ClientID,
		"scope":     claims.Scope,
		"iss":       claims.Issuer,
		"aud":       claims.Audience,
		"exp":       claims.ExpiresAt.Unix(),
	})
}
