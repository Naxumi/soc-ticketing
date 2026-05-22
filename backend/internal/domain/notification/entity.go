package notification

import "time"

type Notification struct {
	ID        string
	UserID    string
	TicketID  *string
	Message   string
	IsRead    bool
	CreatedAt time.Time
}
