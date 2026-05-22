package notification

import (
	"sync"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/notification"
)

type Hub struct {
	mu      sync.RWMutex
	nextID  int64
	clients map[string]map[int64]chan notification.Notification // userID -> clientID -> ch
}

func NewHub() *Hub {
	return &Hub{clients: make(map[string]map[int64]chan notification.Notification)}
}

func (h *Hub) Subscribe(userID string) (ch <-chan notification.Notification, unsubscribe func()) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.nextID++
	clientID := h.nextID

	if h.clients[userID] == nil {
		h.clients[userID] = make(map[int64]chan notification.Notification)
	}

	c := make(chan notification.Notification, 16)
	h.clients[userID][clientID] = c

	return c, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		m := h.clients[userID]
		if m == nil {
			return
		}
		if cc, ok := m[clientID]; ok {
			delete(m, clientID)
			close(cc)
		}
		if len(m) == 0 {
			delete(h.clients, userID)
		}
	}
}

func (h *Hub) Publish(userID string, n notification.Notification) {
	h.mu.RLock()
	m := h.clients[userID]
	h.mu.RUnlock()
	if len(m) == 0 {
		return
	}

	for _, c := range m {
		select {
		case c <- n:
		default:
			// Drop if the client is slow.
		}
	}
}
