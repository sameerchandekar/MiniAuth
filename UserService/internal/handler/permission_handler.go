package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/service"
)

// PermissionHandler handles HTTP requests for permissions.
type PermissionHandler struct {
	svc *service.PermissionService
}

// NewPermissionHandler creates a new PermissionHandler.
func NewPermissionHandler(svc *service.PermissionService) *PermissionHandler {
	return &PermissionHandler{svc: svc}
}

// Create handles POST /api/v1/permissions.
func (h *PermissionHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req model.CreatePermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	perm, err := h.svc.Create(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrPermissionNameRequired) {
			renderError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, service.ErrPermissionExists) {
			renderError(w, http.StatusConflict, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to create permission")
		return
	}

	renderSuccess(w, http.StatusCreated, perm, "permission created successfully")
}

// Get handles GET /api/v1/permissions/{id}.
func (h *PermissionHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	perm, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrPermissionNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to fetch permission")
		return
	}

	renderSuccess(w, http.StatusOK, perm, "")
}

// List handles GET /api/v1/permissions.
func (h *PermissionHandler) List(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.svc.List(r.Context())
	if err != nil {
		renderError(w, http.StatusInternalServerError, "failed to list permissions")
		return
	}

	renderSuccess(w, http.StatusOK, permissions, "")
}
