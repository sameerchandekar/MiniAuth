package handler

import (
	"encoding/json"
	"net/http"

	"github.com/sameerchandekar/MiniAuth/UserService/internal/model"
)

func renderJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func renderSuccess(w http.ResponseWriter, status int, data any, message string) {
	renderJSON(w, status, model.SuccessResponse(data, message))
}

func renderError(w http.ResponseWriter, status int, errMessage string) {
	renderJSON(w, status, model.ErrorResponse(errMessage))
}
