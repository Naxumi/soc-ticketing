package http

import (
	"net/http"
	"time"

	"github.com/go-chi/jwtauth/v5"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/dashboard"
	"github.com/pitik0x/Ai-Security-analyst/internal/handler/http/response"
)

type DashboardHandler struct {
	svc dashboard.Service
}

func NewDashboardHandler(svc dashboard.Service) *DashboardHandler {
	return &DashboardHandler{svc: svc}
}

func (h *DashboardHandler) Get(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}

	userID, _ := claims["sub"].(string)
	if userID == "" {
		response.Unauthorized(w, "Invalid token")
		return
	}
	role, _ := claims["role"].(string)

	q, err := dashboard.QueryFromStrings(
		r.URL.Query().Get("range"),
		r.URL.Query().Get("from"),
		r.URL.Query().Get("to"),
		r.URL.Query().Get("recent_limit"),
		time.Now().UTC(),
	)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	res, err := h.svc.Get(r.Context(), userID, role, q)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.Success(w, res)
}
