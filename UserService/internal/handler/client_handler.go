package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/service"
)

// ClientHandler handles HTTP requests for OAuth 2.0 client registration and management.
type ClientHandler struct {
	svc *service.ClientService
}

// NewClientHandler creates a new ClientHandler.
func NewClientHandler(svc *service.ClientService) *ClientHandler {
	return &ClientHandler{svc: svc}
}

// Register handles POST /api/v1/clients (Client Registration).
func (h *ClientHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	client, err := h.svc.RegisterClient(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrClientNameRequired) ||
			errors.Is(err, service.ErrInvalidClientType) ||
			errors.Is(err, service.ErrInvalidRedirectURI) {
			renderError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, service.ErrClientAlreadyExists) {
			renderError(w, http.StatusConflict, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to register oauth client")
		return
	}

	renderSuccess(w, http.StatusCreated, client, "client registered successfully")
}

// Get handles GET /api/v1/clients/{clientId}.
func (h *ClientHandler) Get(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")
	client, err := h.svc.GetClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, service.ErrClientNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to fetch client")
		return
	}

	renderSuccess(w, http.StatusOK, client, "")
}

// List handles GET /api/v1/clients.
func (h *ClientHandler) List(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	clients, err := h.svc.ListClients(r.Context(), limit, offset)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "failed to list clients")
		return
	}

	renderSuccess(w, http.StatusOK, clients, "")
}

// Delete handles DELETE /api/v1/clients/{clientId}.
func (h *ClientHandler) Delete(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")
	if err := h.svc.DeleteClient(r.Context(), clientID); err != nil {
		if errors.Is(err, service.ErrClientNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to delete client")
		return
	}

	renderSuccess(w, http.StatusOK, nil, "client deleted successfully")
}

// AddScope handles POST /api/v1/clients/{clientId}/scopes.
func (h *ClientHandler) AddScope(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")

	var req model.AddScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var scopes []string
	if req.Scope != "" {
		scopes = append(scopes, req.Scope)
	}
	if len(req.Scopes) > 0 {
		scopes = append(scopes, req.Scopes...)
	}

	if len(scopes) == 0 {
		renderError(w, http.StatusBadRequest, "at least one scope must be provided")
		return
	}

	updatedScopes, err := h.svc.AddScopes(r.Context(), clientID, scopes)
	if err != nil {
		if errors.Is(err, service.ErrClientNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, service.ErrScopeRequired) {
			renderError(w, http.StatusBadRequest, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to add scope to client")
		return
	}

	renderSuccess(w, http.StatusOK, updatedScopes, "scopes updated successfully")
}

// SetScopes handles PUT /api/v1/clients/{clientId}/scopes (full replacement of scopes).
func (h *ClientHandler) SetScopes(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")

	var req model.AddScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var scopes []string
	if req.Scope != "" {
		scopes = append(scopes, req.Scope)
	}
	if len(req.Scopes) > 0 {
		scopes = append(scopes, req.Scopes...)
	}

	updatedScopes, err := h.svc.SetScopes(r.Context(), clientID, scopes)
	if err != nil {
		if errors.Is(err, service.ErrClientNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to update client scopes")
		return
	}

	renderSuccess(w, http.StatusOK, updatedScopes, "scopes replaced successfully")
}

// RemoveScope handles DELETE /api/v1/clients/{clientId}/scopes/{scope}.
func (h *ClientHandler) RemoveScope(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")
	scope := chi.URLParam(r, "scope")

	if err := h.svc.RemoveScope(r.Context(), clientID, scope); err != nil {
		if errors.Is(err, service.ErrClientNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		renderError(w, http.StatusBadRequest, err.Error())
		return
	}

	renderSuccess(w, http.StatusOK, nil, "scope removed from client successfully")
}

// AddRedirectURI handles POST /api/v1/clients/{clientId}/redirect-uris (incremental append).
func (h *ClientHandler) AddRedirectURI(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")

	var req model.AddRedirectURIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var uris []string
	if req.RedirectURI != "" {
		uris = append(uris, req.RedirectURI)
	}
	if len(req.RedirectURIs) > 0 {
		uris = append(uris, req.RedirectURIs...)
	}

	if len(uris) == 0 {
		renderError(w, http.StatusBadRequest, "at least one redirect_uri must be provided")
		return
	}

	updatedURIs, err := h.svc.AddRedirectURIs(r.Context(), clientID, uris)
	if err != nil {
		if errors.Is(err, service.ErrClientNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, service.ErrInvalidRedirectURI) || errors.Is(err, service.ErrRedirectURIRequired) {
			renderError(w, http.StatusBadRequest, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to add redirect uri to client")
		return
	}

	renderSuccess(w, http.StatusOK, updatedURIs, "redirect URIs added successfully")
}

// SetRedirectURIs handles PUT /api/v1/clients/{clientId}/redirect-uris (full replacement / overwrite).
func (h *ClientHandler) SetRedirectURIs(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")

	var req model.AddRedirectURIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var uris []string
	if req.RedirectURI != "" {
		uris = append(uris, req.RedirectURI)
	}
	if len(req.RedirectURIs) > 0 {
		uris = append(uris, req.RedirectURIs...)
	}

	updatedURIs, err := h.svc.SetRedirectURIs(r.Context(), clientID, uris)
	if err != nil {
		if errors.Is(err, service.ErrClientNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, service.ErrInvalidRedirectURI) {
			renderError(w, http.StatusBadRequest, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to update redirect uris")
		return
	}

	renderSuccess(w, http.StatusOK, updatedURIs, "redirect URIs replaced successfully")
}

// RemoveRedirectURI handles DELETE /api/v1/clients/{clientId}/redirect-uris.
// Supports query param ?uri=... or ?redirect_uri=... as well as JSON body {"redirect_uri":"..."}.
func (h *ClientHandler) RemoveRedirectURI(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientId")

	targetURI := r.URL.Query().Get("redirect_uri")
	if targetURI == "" {
		targetURI = r.URL.Query().Get("uri")
	}

	if targetURI == "" && r.Body != nil {
		var req model.DeleteRedirectURIRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			targetURI = req.RedirectURI
		}
	}

	targetURI = strings.TrimSpace(targetURI)
	if targetURI == "" {
		renderError(w, http.StatusBadRequest, "redirect_uri parameter or JSON payload is required")
		return
	}

	if err := h.svc.RemoveRedirectURI(r.Context(), clientID, targetURI); err != nil {
		if errors.Is(err, service.ErrClientNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		renderError(w, http.StatusBadRequest, err.Error())
		return
	}

	renderSuccess(w, http.StatusOK, nil, "redirect uri removed from client successfully")
}
