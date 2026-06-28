package middleware

import (
	"crypto/subtle"
	"net/http"

	"github.com/naxumi/soc-ticketing/internal/handler/http/response"
)

func APIKeyRequired(expectedKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if expectedKey == "" {
				response.InternalServerError(w, "Webhook API key is not configured")
				return
			}

			provided := r.Header.Get("X-API-Key")
			if provided == "" {
				response.Unauthorized(w, "Missing X-API-Key")
				return
			}

			if subtle.ConstantTimeCompare([]byte(provided), []byte(expectedKey)) != 1 {
				response.Unauthorized(w, "Invalid X-API-Key")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
