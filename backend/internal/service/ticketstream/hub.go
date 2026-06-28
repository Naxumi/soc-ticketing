package ticketstream

import (
	"sync"

	"github.com/naxumi/soc-ticketing/internal/domain/ticket"
)

type Hub struct {
	mu      sync.RWMutex
	nextID  int64
	clients map[int64]chan ticket.StreamEvent
}

func NewHub() *Hub {
	return &Hub{clients: make(map[int64]chan ticket.StreamEvent)}
}

func (h *Hub) Subscribe() (ch <-chan ticket.StreamEvent, unsubscribe func()) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.nextID++
	clientID := h.nextID

	c := make(chan ticket.StreamEvent, 32)
	h.clients[clientID] = c

	return c, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if cc, ok := h.clients[clientID]; ok {
			delete(h.clients, clientID)
			close(cc)
		}
	}
}

func (h *Hub) Publish(ev ticket.StreamEvent) {
	h.mu.RLock()
	clients := make([]chan ticket.StreamEvent, 0, len(h.clients))
	for _, c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	for _, c := range clients {
		select {
		case c <- ev:
		default:
			// Drop if the client is slow.
		}
	}
}
