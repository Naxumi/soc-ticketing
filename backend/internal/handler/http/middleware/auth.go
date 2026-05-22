package middleware

import (
	"net/http"

	"github.com/go-chi/jwtauth/v5"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/auth"
	"github.com/pitik0x/Ai-Security-analyst/internal/handler/http/response"
)

func AuthRequired(ja *jwtauth.JWTAuth, sessionRepo auth.SessionRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, _, err := jwtauth.FromContext(r.Context())
			if err != nil {
				response.Unauthorized(w, err.Error())
				return
			}
			if token == nil {
				response.HandleError(w, auth.ErrInvalidToken)
				return
			}

			claims, err := token.AsMap(r.Context())
			if err != nil {
				response.HandleError(w, auth.ErrInvalidToken)
				return
			}
			typeVal, ok := claims["type"].(string)
			if !ok || typeVal != "access" {
				response.HandleError(w, auth.ErrInvalidToken)
				return
			}

			// Validate session is not revoked
			sessionID, ok := claims["session_id"].(string)
			if !ok || sessionID == "" {
				response.HandleError(w, auth.ErrInvalidToken)
				return
			}

			sess, err := sessionRepo.GetByID(r.Context(), sessionID)
			if err != nil {
				response.HandleError(w, auth.ErrInvalidToken)
				return
			}

			if sess.IsRevoked {
				response.HandleError(w, auth.ErrRefreshTokenRevoked)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
