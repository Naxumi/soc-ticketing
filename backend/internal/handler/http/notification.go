package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/notification"
	"github.com/pitik0x/Ai-Security-analyst/internal/handler/http/response"
	notificationSvc "github.com/pitik0x/Ai-Security-analyst/internal/service/notification"
)

type NotificationHandler struct {
	svc notification.Service
	hub *notificationSvc.Hub
}

func NewNotificationHandler(svc notification.Service, hub *notificationSvc.Hub) *NotificationHandler {
	return &NotificationHandler{svc: svc, hub: hub}
}

func (h *NotificationHandler) List(w http.ResponseWriter, r *http.Request) {
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

	q, err := notification.ListNotificationsQueryFromStrings(
		r.URL.Query().Get("page"),
		r.URL.Query().Get("limit"),
		r.URL.Query().Get("is_read"),
	)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	res, err := h.svc.List(r.Context(), userID, q)
	if err != nil {
		response.HandleError(w, err)
		return
	}

	response.Success(w, res)
}

func (h *NotificationHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
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
	userID, _ := claims["sub"].(string)
	if userID == "" {
		response.Unauthorized(w, "Invalid token")
		return
	}

	if err := h.svc.MarkRead(r.Context(), userID, id); err != nil {
		response.HandleError(w, err)
		return
	}

	response.SuccessWithMessage(w, "Notification marked as read", nil)
}

func (h *NotificationHandler) Stream(w http.ResponseWriter, r *http.Request) {
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

	flusher, ok := w.(http.Flusher)
	if !ok {
		response.InternalServerError(w, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ch, unsubscribe := h.hub.Subscribe(userID)
	defer unsubscribe()

	// Initial comment to open the stream.
	if _, err := w.Write([]byte(": connected\n\n")); err != nil {
		return
	}
	flusher.Flush()

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if _, err := w.Write([]byte("event: ping\ndata: {}\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case n, ok := <-ch:
			if !ok {
				return
			}

			payload := notification.NotificationListItem{
				ID:        n.ID,
				TicketID:  n.TicketID,
				Message:   n.Message,
				IsRead:    n.IsRead,
				CreatedAt: n.CreatedAt.UTC().Format(time.RFC3339),
			}
			b, _ := json.Marshal(payload)
			if _, err := w.Write([]byte("event: notification\n")); err != nil {
				return
			}
			if _, err := w.Write([]byte("data: ")); err != nil {
				return
			}
			if _, err := w.Write(b); err != nil {
				return
			}
			if _, err := w.Write([]byte("\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
