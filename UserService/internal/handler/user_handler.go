package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
	"github.com/sameerchandekar/MiniAuth/UserService/internal/service"
)

// UserHandler handles HTTP requests for user lifecycle and details.
type UserHandler struct {
	svc *service.UserService
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(svc *service.UserService) *UserHandler {
	return &UserHandler{svc: svc}
}

// Create handles POST /api/v1/users.
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req model.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.svc.CreateUser(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrUserNameRequired) ||
			errors.Is(err, service.ErrUserEmailInvalid) ||
			errors.Is(err, service.ErrUserPasswordTooShort) {
			renderError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, service.ErrUserEmailExists) {
			renderError(w, http.StatusConflict, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	renderSuccess(w, http.StatusCreated, user, "user created successfully")
}

// Get handles GET /api/v1/users/{id} (fetching complete user data, roles, and permissions).
func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.svc.GetUserDetail(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, "failed to fetch user details")
		return
	}

	renderSuccess(w, http.StatusOK, user, "")
}

// List handles GET /api/v1/users.
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	users, err := h.svc.ListUsers(r.Context(), limit, offset)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	renderSuccess(w, http.StatusOK, users, "")
}

// AssignRole handles POST /api/v1/users/{id}/roles.
func (h *UserHandler) AssignRole(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	var req model.AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		renderError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err := h.svc.AssignRole(r.Context(), userID, req.RoleID)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) || errors.Is(err, service.ErrRoleNotFound) {
			renderError(w, http.StatusNotFound, err.Error())
			return
		}
		renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	renderSuccess(w, http.StatusOK, nil, "role assigned to user successfully")
}

// RemoveRole handles DELETE /api/v1/users/{id}/roles/{roleId}.
func (h *UserHandler) RemoveRole(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	roleID := chi.URLParam(r, "roleId")

	err := h.svc.RemoveRole(r.Context(), userID, roleID)
	if err != nil {
		renderError(w, http.StatusBadRequest, err.Error())
		return
	}

	renderSuccess(w, http.StatusOK, nil, "role removed from user successfully")
}
