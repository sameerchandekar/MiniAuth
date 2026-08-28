package handler

import (
	"net/http"
	"net/url"

	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/model"
	"github.com/sameerchandekar/MiniAuth/AuthorizationServer/internal/service"
)

// OAuthHandler handles OAuth 2.0 and OIDC protocol endpoints.
type OAuthHandler struct {
	oauthService service.OAuthService
}

// NewOAuthHandler creates a new OAuthHandler with the required OAuthService.
func NewOAuthHandler(oauthService service.OAuthService) *OAuthHandler {
	return &OAuthHandler{
		oauthService: oauthService,
	}
}

// Authorize handles GET /authorize (OAuth 2.0 Authorization Endpoint).
// It accepts client_id, redirect_uri, response_type, scope, state, code_challenge, and code_challenge_method,
// delegates validation and code generation to the service layer, and issues an HTTP 302 Found redirect.
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	req := model.AuthorizeRequest{
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		ResponseType:        r.URL.Query().Get("response_type"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
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
