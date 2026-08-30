package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sameerchandekar/MiniAuth/ResourceServer/internal/middleware"
)

func TestEmailHandler_ListEmails(t *testing.T) {
	h := NewEmailHandler()

	claims := &middleware.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
		},
		ClientID: "client-id-001",
		Scope:    "openid profile email read",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/emails", nil)
	// Attach claims to context
	req = req.WithContext(middleware.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.ListEmails(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}

	if resp["status"] != "success" {
		t.Errorf("expected status 'success', got %v", resp["status"])
	}
	if resp["user_id"] != "user-123" {
		t.Errorf("expected user_id 'user-123', got %v", resp["user_id"])
	}
}

func TestEmailHandler_SendEmail(t *testing.T) {
	h := NewEmailHandler()

	claims := &middleware.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
		},
		ClientID: "client-id-001",
		Scope:    "write",
	}

	payload := `{"to":"friend@example.com","subject":"Hello","body":"Testing email"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/emails", strings.NewReader(payload))
	req = req.WithContext(middleware.WithClaims(req.Context(), claims))

	rec := httptest.NewRecorder()
	h.SendEmail(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d", rec.Code)
	}
}
