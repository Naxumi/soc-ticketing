package response

import (
	"encoding/json"
	"net/http"
)

type Response struct {
	Success bool         `json:"success"`
	Message string       `json:"message,omitempty"`
	Data    interface{}  `json:"data,omitempty"`
	Error   *ErrorDetail `json:"error,omitempty"`
	Meta    *Meta        `json:"meta,omitempty"`
}

type ErrorDetail struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

type Meta struct {
	Page       int   `json:"page,omitempty"`
	Limit      int   `json:"limit,omitempty"`
	TotalItems int64 `json:"total_items,omitempty"`
	TotalPages int   `json:"total_pages,omitempty"`
}

func writeJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		fallback := Response{
			Success: false,
			Error: &ErrorDetail{
				Code:    "ENCODING_ERROR",
				Message: "Failed to encode response",
			},
		}
		_ = json.NewEncoder(w).Encode(fallback)
	}
}

// Success responses
func Success(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    data,
	})
}

func SuccessWithMessage(w http.ResponseWriter, message string, data interface{}) {
	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

func Created(w http.ResponseWriter, message string, data interface{}) {
	writeJSON(w, http.StatusCreated, Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

func SuccessWithMeta(w http.ResponseWriter, data interface{}, meta *Meta) {
	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Data:    data,
		Meta:    meta,
	})
}

// Error responses
func BadRequest(w http.ResponseWriter, message string, details map[string]string) {
	writeJSON(w, http.StatusBadRequest, Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    "BAD_REQUEST",
			Message: message,
			Details: details,
		},
	})
}

func ValidationError(w http.ResponseWriter, details map[string]string) {
	writeJSON(w, http.StatusUnprocessableEntity, Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    "VALIDATION_ERROR",
			Message: "Validation failed",
			Details: details,
		},
	})
}

func Unauthorized(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusUnauthorized, Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    "UNAUTHORIZED",
			Message: message,
		},
	})
}

func Forbidden(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusForbidden, Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    "FORBIDDEN",
			Message: message,
		},
	})
}

func NotFound(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusNotFound, Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    "NOT_FOUND",
			Message: message,
		},
	})
}

func InternalServerError(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusInternalServerError, Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    "INTERNAL_SERVER_ERROR",
			Message: message,
		},
	})
}

func Conflict(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusConflict, Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    "CONFLICT",
			Message: message,
		},
	})
}
