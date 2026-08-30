package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/service"
)

// OAuthHandler handles OAuth 2.0 and OIDC protocol endpoints.
type OAuthHandler struct {
	oauthService service.OAuthService
	authService  service.AuthService
}

// NewOAuthHandler creates a new OAuthHandler with OAuthService and AuthService.
func NewOAuthHandler(oauthService service.OAuthService, authService service.AuthService) *OAuthHandler {
	return &OAuthHandler{
		oauthService: oauthService,
		authService:  authService,
	}
}

// Authorize handles GET /authorize (OAuth 2.0 Authorization Endpoint).
// It checks for a valid authenticated session cookie (auth_session). If missing or expired,
// it redirects the user to the login page (/login) preserving the original authorization request.
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	// 1. Session verification: Check for auth_session cookie
	var session *service.SessionData
	cookie, err := r.Cookie("auth_session")
	if err == nil && cookie.Value != "" && h.authService != nil {
		session, _ = h.authService.ValidateSession(r.Context(), cookie.Value)
	}

	// 2. If unauthenticated, redirect to the login page with return_to
	if session == nil {
		returnTo := r.URL.RequestURI()
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}

	var userID *string
	if session.UserID != "" {
		userID = &session.UserID
	}

	req := model.AuthorizeRequest{
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		ResponseType:        r.URL.Query().Get("response_type"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		UserID:              userID,
	}

	result, err := h.oauthService.Authorize(r.Context(), req)
	if err != nil {
		// RFC 6749 Section 4.1.2.1: Error response via redirect if redirect_uri is available
		redirectURI := req.RedirectURI
		if redirectURI == "" {
			redirectURI = "https://myapp.com/oauth/callback"
		}

		targetURL, _ := url.Parse(redirectURI)
		q := targetURL.Query()
		q.Set("error", err.Error())
		if req.State != "" {
			q.Set("state", req.State)
		}
		targetURL.RawQuery = q.Encode()

		http.Redirect(w, r, targetURL.String(), http.StatusFound)
		return
	}

	// Issue HTTP 302 Found redirect with code and state
	http.Redirect(w, r, result.RedirectURL(), http.StatusFound)
}

// Token handles POST /token and POST /oauth/token (OAuth 2.0 Token Endpoint).
// Supports application/x-www-form-urlencoded, application/json, and HTTP Basic Auth credentials.
func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderTokenError(w, http.StatusMethodNotAllowed, "invalid_request", "only POST method is allowed")
		return
	}

	var req model.TokenRequest
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			renderTokenError(w, http.StatusBadRequest, "invalid_request", "invalid JSON request body")
			return
		}
	} else {
		// Parse form data (application/x-www-form-urlencoded or multipart/form-data)
		if err := r.ParseForm(); err != nil {
			renderTokenError(w, http.StatusBadRequest, "invalid_request", "failed to parse form data")
			return
		}
		req = model.TokenRequest{
			GrantType:    r.FormValue("grant_type"),
			Code:         r.FormValue("code"),
			RedirectURI:  r.FormValue("redirect_uri"),
			ClientID:     r.FormValue("client_id"),
			ClientSecret: r.FormValue("client_secret"),
			CodeVerifier: r.FormValue("code_verifier"),
		}
	}

	// Extract Client ID/Secret from HTTP Basic Auth if present in Authorization header
	if username, password, ok := r.BasicAuth(); ok {
		if req.ClientID == "" {
			req.ClientID = username
		}
		if req.ClientSecret == "" {
			req.ClientSecret = password
		}
	}

	res, err := h.oauthService.Token(r.Context(), req)
	if err != nil {
		statusCode := http.StatusBadRequest
		errCode := "invalid_request"

		if errors.Is(err, service.ErrUnsupportedGrantType) {
			errCode = "unsupported_grant_type"
		} else if errors.Is(err, service.ErrInvalidGrant) {
			errCode = "invalid_grant"
		} else if errors.Is(err, service.ErrInvalidClient) {
			errCode = "invalid_client"
			statusCode = http.StatusUnauthorized
		} else if errors.Is(err, service.ErrUnauthorizedClient) {
			errCode = "unauthorized_client"
			statusCode = http.StatusUnauthorized
		} else if errors.Is(err, service.ErrInvalidScope) {
			errCode = "invalid_scope"
		}

		renderTokenError(w, statusCode, errCode, err.Error())
		return
	}

	// Standard RFC 6749 Section 5.1 Success Response
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(res)
}

func renderTokenError(w http.ResponseWriter, statusCode int, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)

	resp := model.OAuthErrorResponse{
		Error:            errCode,
		ErrorDescription: errDesc,
	}
	_ = json.NewEncoder(w).Encode(resp)
}
