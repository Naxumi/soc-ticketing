package response

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	domainAuth "github.com/naxumi/soc-ticketing/internal/domain/auth"
	"github.com/naxumi/soc-ticketing/internal/domain/notification"
	"github.com/naxumi/soc-ticketing/internal/domain/ticket"
	"github.com/naxumi/soc-ticketing/internal/domain/user"
	"github.com/naxumi/soc-ticketing/internal/pkg/validator"
)

func TestHandleError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode int
		expectedMsg  string
	}{
		// 401 Unauthorized
		{
			name:         "invalid credentials",
			err:          domainAuth.ErrInvalidCredentials,
			expectedCode: http.StatusUnauthorized,
			expectedMsg:  "invalid username or password",
		},
		{
			name:         "invalid token",
			err:          domainAuth.ErrInvalidToken,
			expectedCode: http.StatusUnauthorized,
			expectedMsg:  "invalid or expired token",
		},
		{
			name:         "refresh token expired",
			err:          domainAuth.ErrRefreshTokenExpired,
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "refresh token revoked",
			err:          domainAuth.ErrRefreshTokenRevoked,
			expectedCode: http.StatusUnauthorized,
		},

		// 403 Forbidden
		{
			name:         "SOC manager required",
			err:          user.ErrSOCManagerRequired,
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "user update forbidden",
			err:          user.ErrUserUpdateForbidden,
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "ticket forbidden",
			err:          ticket.ErrTicketForbidden,
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "ticket terminal status",
			err:          ticket.ErrTicketStatusTerminal,
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "insufficient role for status",
			err:          ticket.ErrInsufficientRoleForStatus,
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "ticket locked by user",
			err:          ticket.ErrTicketLockedByUser,
			expectedCode: http.StatusForbidden,
		},

		// 404 Not Found
		{
			name:         "user not found",
			err:          user.ErrUserNotFound,
			expectedCode: http.StatusNotFound,
			expectedMsg:  "user not found",
		},
		{
			name:         "ticket not found",
			err:          ticket.ErrTicketNotFound,
			expectedCode: http.StatusNotFound,
			expectedMsg:  "ticket not found",
		},
		{
			name:         "notification not found",
			err:          notification.ErrNotificationNotFound,
			expectedCode: http.StatusNotFound,
			expectedMsg:  "notification not found",
		},

		// 409 Conflict
		{
			name:         "username exists",
			err:          user.ErrUsernameExists,
			expectedCode: http.StatusConflict,
			expectedMsg:  "username already exists",
		},

		// 422 Validation Error
		{
			name:         "validation errors",
			err:          validator.ValidationErrors{{Field: "name", Message: "is required"}},
			expectedCode: http.StatusUnprocessableEntity,
		},

		// 500 Internal Server Error
		{
			name:         "unknown error",
			err:          errors.New("something broke"),
			expectedCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			HandleError(w, tt.err)

			if w.Code != tt.expectedCode {
				t.Errorf("expected status %d, got %d", tt.expectedCode, w.Code)
			}

			var resp Response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp.Success {
				t.Error("expected success=false in error response")
			}
			if resp.Error == nil {
				t.Fatal("expected error detail in response, got nil")
			}
			if resp.Error.Code == "" {
				t.Error("expected non-empty error code")
			}

			if tt.expectedMsg != "" && resp.Error.Message != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, resp.Error.Message)
			}
		})
	}
}

func TestSuccessResponses(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		w := httptest.NewRecorder()
		Success(w, map[string]string{"hello": "world"})

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		var resp Response
		json.NewDecoder(w.Body).Decode(&resp)
		if !resp.Success {
			t.Error("expected success=true")
		}
	})

	t.Run("Created", func(t *testing.T) {
		w := httptest.NewRecorder()
		Created(w, "user created", map[string]string{"id": "1"})

		if w.Code != http.StatusCreated {
			t.Errorf("expected 201, got %d", w.Code)
		}
		var resp Response
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.Message != "user created" {
			t.Errorf("expected message 'user created', got %q", resp.Message)
		}
	})

	t.Run("SuccessWithMeta", func(t *testing.T) {
		w := httptest.NewRecorder()
		SuccessWithMeta(w, []string{"a"}, &Meta{Page: 1, Limit: 10, TotalItems: 100, TotalPages: 10})

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		var resp Response
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.Meta == nil {
			t.Fatal("expected meta in response")
		}
		if resp.Meta.TotalPages != 10 {
			t.Errorf("expected total_pages=10, got %d", resp.Meta.TotalPages)
		}
	})
}
