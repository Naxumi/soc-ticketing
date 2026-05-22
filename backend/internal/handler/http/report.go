package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth/v5"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/report"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/user"
	"github.com/pitik0x/Ai-Security-analyst/internal/handler/http/response"
)

type ReportService interface {
	ExportTicketsCSV(ctx context.Context, q report.ExportTicketsQuery, w io.Writer) error
	ExportTicketsPDF(ctx context.Context, q report.ExportTicketsQuery) ([]byte, error)
}

type ReportHandler struct {
	svc ReportService
}

func NewReportHandler(svc ReportService) *ReportHandler {
	return &ReportHandler{svc: svc}
}

func (h *ReportHandler) ExportTicketsCSV(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}
	role, _ := claims["role"].(string)
	if user.Role(role) != user.RoleSOCManager {
		response.HandleError(w, user.ErrSOCManagerRequired)
		return
	}

	q, err := report.ExportTicketsQueryFromStrings(
		r.URL.Query().Get("range"),
		r.URL.Query().Get("from"),
		r.URL.Query().Get("to"),
		r.URL.Query().Get("status"),
		r.URL.Query().Get("severity"),
		r.URL.Query().Get("assignee_id"),
		r.URL.Query().Get("limit"),
		time.Now().UTC(),
	)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	filename := fmt.Sprintf("tickets_%s_%s.csv", q.Window.From.Format("2006-01-02"), q.Window.To.Format("2006-01-02"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.WriteHeader(http.StatusOK)

	if err := h.svc.ExportTicketsCSV(r.Context(), q, w); err != nil {
		// Headers already written; best effort: log and abort.
		return
	}
}

func (h *ReportHandler) ExportTicketsPDF(w http.ResponseWriter, r *http.Request) {
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		response.Unauthorized(w, "Invalid token")
		return
	}
	role, _ := claims["role"].(string)
	if user.Role(role) != user.RoleSOCManager {
		response.HandleError(w, user.ErrSOCManagerRequired)
		return
	}

	q, err := report.ExportTicketsQueryFromStrings(
		r.URL.Query().Get("range"),
		r.URL.Query().Get("from"),
		r.URL.Query().Get("to"),
		r.URL.Query().Get("status"),
		r.URL.Query().Get("severity"),
		r.URL.Query().Get("assignee_id"),
		r.URL.Query().Get("limit"),
		time.Now().UTC(),
	)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	pdfBytes, err := h.svc.ExportTicketsPDF(r.Context(), q)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	filename := fmt.Sprintf("tickets_%s_%s.pdf", q.Window.From.Format("2006-01-02"), q.Window.To.Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdfBytes)
}
