package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/ticket"
	"github.com/pitik0x/Ai-Security-analyst/internal/handler/http/response"
)

type TicketHandler struct {
	svc ticket.Service
}

func NewTicketHandler(svc ticket.Service) *TicketHandler {
	return &TicketHandler{svc: svc}
}

func (h *TicketHandler) List(w http.ResponseWriter, r *http.Request) {
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
	if actorRole == "" {
		response.Unauthorized(w, "Invalid token")
		return
	}

	q, err := ticket.ListTicketsQueryFromStrings(
		r.URL.Query().Get("page"),
		r.URL.Query().Get("limit"),
		r.URL.Query().Get("status"),
		r.URL.Query().Get("severity"),
		r.URL.Query().Get("assignee_id"),
		r.URL.Query().Get("tab"),
	)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	res, err := h.svc.List(r.Context(), actorUserID, actorRole, q)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.Success(w, res)
}

func (h *TicketHandler) GetDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		response.BadRequest(w, "missing id", map[string]string{"id": "id is required"})
		return
	}

	res, err := h.svc.GetDetail(r.Context(), id)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.Success(w, res)
}

func (h *TicketHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		response.BadRequest(w, "missing id", map[string]string{"id": "id is required"})
		return
	}

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
	if actorRole == "" {
		response.Unauthorized(w, "Invalid token")
		return
	}

	var req ticket.UpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.BadRequest(w, "Invalid JSON body", nil)
		return
	}
	if req.AssigneeID == nil {
		req.AssigneeID = &actorUserID
	}

	if err := h.svc.UpdateStatus(r.Context(), id, actorUserID, actorRole, req); err != nil {
		response.HandleError(w, err)
		return
	}

	response.SuccessWithMessage(w, "Status tiket berhasil diubah dan log tersimpan.", nil)
}

func (h *TicketHandler) Analyze(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		response.BadRequest(w, "missing id", map[string]string{"id": "id is required"})
		return
	}

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

	var req ticket.AnalyzeTicketRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	res, err := h.svc.Analyze(r.Context(), id, actorUserID, req)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.SuccessWithMessage(w, "Analisis external berhasil dipicu.", res)
}
