package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/service"
)

// RoleHandler handles HTTP requests for roles.
type RoleHandler struct {
	svc *service.RoleService
}

// NewRoleHandler creates a new RoleHandler.
func NewRoleHandler(svc *service.RoleService) *RoleHandler {
	return &RoleHandler{svc: svc}
}

// Create handles POST /api/v1/roles.
func (h *RoleHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req model.CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	role, err := h.svc.Create(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrRoleNameRequired) {
			renderError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, service.ErrRoleExists) {
			renderError(w, http.StatusConflict, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to create role")
		return
	}

	renderSuccess(w, http.StatusCreated, role, "role created successfully")
}

// Get handles GET /api/v1/roles/{id}.
func (h *RoleHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	role, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrRoleNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to fetch role")
		return
	}

	renderSuccess(w, http.StatusOK, role, "")
}

// List handles GET /api/v1/roles.
func (h *RoleHandler) List(w http.ResponseWriter, r *http.Request) {
	roles, err := h.svc.List(r.Context())
	if err != nil {
		renderError(w, http.StatusInternalServerError, "failed to list roles")
		return
	}

	renderSuccess(w, http.StatusOK, roles, "")
}

// AssignPermission handles POST /api/v1/roles/{id}/permissions.
func (h *RoleHandler) AssignPermission(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "id")

	var req model.AssignPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err := h.svc.AssignPermission(r.Context(), roleID, req.PermissionID)
	if err != nil {
		if errors.Is(err, service.ErrRoleNotFound) || errors.Is(err, service.ErrPermissionNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	renderSuccess(w, http.StatusOK, nil, "permission assigned to role successfully")
}

// RemovePermission handles DELETE /api/v1/roles/{id}/permissions/{permissionId}.
func (h *RoleHandler) RemovePermission(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "id")
	permissionID := chi.URLParam(r, "permissionId")

	err := h.svc.RemovePermission(r.Context(), roleID, permissionID)
	if err != nil {
		renderError(w, http.StatusBadRequest, err.Error())
		return
	}

	renderSuccess(w, http.StatusOK, nil, "permission removed from role successfully")
}
