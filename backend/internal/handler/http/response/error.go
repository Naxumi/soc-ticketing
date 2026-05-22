package response

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/auth"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/notification"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/ticket"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/user"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/validator"
)

// HandleError maps domain errors to HTTP responses.
func HandleError(w http.ResponseWriter, err error) {
	var validationErrs validator.ValidationErrors
	if errors.As(err, &validationErrs) {
		ValidationError(w, validationErrs.ToMap())
		return
	}

	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		Unauthorized(w, err.Error())
	case errors.Is(err, auth.ErrInvalidToken), errors.Is(err, auth.ErrRefreshTokenExpired), errors.Is(err, auth.ErrRefreshTokenRevoked):
		Unauthorized(w, err.Error())
	case errors.Is(err, user.ErrSOCManagerRequired):
		Forbidden(w, err.Error())
	case errors.Is(err, user.ErrUserUpdateForbidden):
		Forbidden(w, err.Error())
	case errors.Is(err, user.ErrUsernameExists):
		Conflict(w, "username already exists")
	case errors.Is(err, user.ErrUserNotFound):
		NotFound(w, "user not found")
	case errors.Is(err, ticket.ErrTicketNotFound):
		NotFound(w, "ticket not found")
	case errors.Is(err, ticket.ErrTicketForbidden):
		Forbidden(w, err.Error())
	case errors.Is(err, ticket.ErrTicketStatusTerminal):
		Forbidden(w, err.Error())
	case errors.Is(err, ticket.ErrInsufficientRoleForStatus):
		Forbidden(w, err.Error())
	case errors.Is(err, ticket.ErrTicketLockedByUser):
		Forbidden(w, err.Error())
	case errors.Is(err, notification.ErrNotificationNotFound):
		NotFound(w, "notification not found")
	default:
		// Log the error
		fmt.Println(err.Error())
		InternalServerError(w, http.StatusText(http.StatusInternalServerError))
	}
}
