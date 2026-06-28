package http

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/naxumi/soc-ticketing/internal/domain/auth"
	"github.com/naxumi/soc-ticketing/internal/domain/user"
	"github.com/naxumi/soc-ticketing/internal/handler/http/response"
	"github.com/naxumi/soc-ticketing/internal/pkg/jwt"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
)

type AuthHandler struct {
	authSvc auth.Service
	jwtSvc  jwt.Service
	users   user.Repository
}

func NewAuthHandler(authSvc auth.Service, jwtSvc jwt.Service, users user.Repository) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, jwtSvc: jwtSvc, users: users}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}
	creatorRole, _ := claims["role"].(string)

	var req auth.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON body", nil)
		return
	}

	res, err := h.authSvc.Register(r.Context(), creatorRole, req)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Created(w, "User created", res)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req auth.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON body", nil)
		return
	}

	track := auth.SessionTrackingFromRequest(r)
	res, err := h.authSvc.Login(r.Context(), req, track)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, res)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req auth.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON body", nil)
		return
	}

	track := auth.SessionTrackingFromRequest(r)
	res, err := h.authSvc.Refresh(r.Context(), req, track)
	if err != nil {
		response.HandleError(w, err)
		return
	}
	response.Success(w, res)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req auth.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON body", nil)
		return
	}

	if err := h.authSvc.Logout(r.Context(), req); err != nil {
		response.HandleError(w, err)
		return
	}
	response.SuccessWithMessage(w, "Logged out", nil)
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}

	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		response.Unauthorized(w, "Invalid token")
		return
	}

	u, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	// Never return password hash.
	response.Success(w, map[string]any{
		"id":         u.ID,
		"full_name":  u.FullName,
		"username":   u.Username,
		"role":       string(u.Role),
		"created_at": u.CreatedAt,
	})
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}

	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		response.Unauthorized(w, "Invalid token")
		return
	}

	var req auth.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON body", nil)
		return
	}

	if err := h.authSvc.ChangePassword(r.Context(), userID, req); err != nil {
		response.HandleError(w, err)
		return
	}
	response.SuccessWithMessage(w, "Password updated", nil)
}

func (h *AuthHandler) AdminUpdateAnalyst(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}

	actorUserID, ok := claims["sub"].(string)
	if !ok || actorUserID == "" {
		response.Unauthorized(w, "Invalid token")
		return
	}
	actorRole, _ := claims["role"].(string)

	targetUserID := chi.URLParam(r, "id")
	if targetUserID == "" {
		response.BadRequest(w, "Missing user id", nil)
		return
	}

	var req auth.AdminUpdateAnalystRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON body", nil)
		return
	}

	if err := h.authSvc.AdminUpdateAnalyst(r.Context(), actorUserID, actorRole, targetUserID, req); err != nil {
		response.HandleError(w, err)
		return
	}

	response.SuccessWithMessage(w, "User updated", nil)
}

func (h *AuthHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}
	actorRole, _ := claims["role"].(string)

	res, err := h.authSvc.ListUsers(r.Context(), actorRole)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.Success(w, res)
}

func (h *AuthHandler) GetUserDetail(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}
	actorRole, _ := claims["role"].(string)

	targetUserID := chi.URLParam(r, "id")
	if targetUserID == "" {
		response.BadRequest(w, "Missing user id", nil)
		return
	}

	res, err := h.authSvc.GetUserDetail(r.Context(), actorRole, targetUserID)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.Success(w, res)
}

func (h *AuthHandler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}
	actorRole, _ := claims["role"].(string)

	targetUserID := chi.URLParam(r, "id")
	if targetUserID == "" {
		response.BadRequest(w, "Missing user id", nil)
		return
	}

	var req auth.RevokeUserSessionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		response.BadRequest(w, "Invalid JSON body", nil)
		return
	}

	res, err := h.authSvc.RevokeUserSessions(r.Context(), actorRole, targetUserID, req)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	message := "User sessions revoked"
	if res.Scope == auth.RevokeScopeAll {
		if res.RevokedCnt == 0 {
			message = "No active sessions were revoked"
		} else {
			message = "All active sessions revoked"
		}
	} else if res.Scope == auth.RevokeScopeSingle {
		if res.RevokedCnt == 0 {
			message = "No active session was revoked for provided session_id"
		} else {
			message = "Session revoked"
		}
	}

	response.SuccessWithMessage(w, message, res)
}

func (h *AuthHandler) DeleteAnalyst(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}
	actorUserID, _ := claims["sub"].(string)
	if actorUserID == "" {
		response.Unauthorized(w, "Invalid token")
		return
	}
	actorRole, _ := claims["role"].(string)

	targetUserID := chi.URLParam(r, "id")
	if targetUserID == "" {
		response.BadRequest(w, "Missing user id", nil)
		return
	}

	if err := h.authSvc.DeleteAnalyst(r.Context(), actorUserID, actorRole, targetUserID); err != nil {
		response.HandleError(w, err)
		return
	}

	response.SuccessWithMessage(w, "User deleted", nil)
}

// Expose JWTAuth to router/middleware.
func (h *AuthHandler) JWTAuth() *jwtauth.JWTAuth { return h.jwtSvc.JWTAuth() }
