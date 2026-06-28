package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth/v5"

	"github.com/naxumi/soc-ticketing/internal/domain/ticket"
	"github.com/naxumi/soc-ticketing/internal/handler/http/response"
	"github.com/naxumi/soc-ticketing/internal/service/ticketstream"
)

type TicketStreamHandler struct {
	hub *ticketstream.Hub
}

func NewTicketStreamHandler(hub *ticketstream.Hub) *TicketStreamHandler {
	return &TicketStreamHandler{hub: hub}
}

func (h *TicketStreamHandler) Stream(w http.ResponseWriter, r *http.Request) {
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

	ch, unsubscribe := h.hub.Subscribe()
	defer unsubscribe()

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
		case ev, ok := <-ch:
			if !ok {
				return
			}

			payload := ticket.StreamEvent{
				Type:     ev.Type,
				Ticket:   ev.Ticket,
				WindowID: ev.WindowID,
				TicketID: ev.TicketID,
			}
			b, _ := json.Marshal(payload)
			if _, err := w.Write([]byte("event: ticket\n")); err != nil {
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
