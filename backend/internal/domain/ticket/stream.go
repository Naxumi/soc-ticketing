package ticket

type StreamEventType string

const (
	StreamEventAggregatingCreated StreamEventType = "aggregating_created"
	StreamEventAggregatingUpdated StreamEventType = "aggregating_updated"
	StreamEventAggregatingClosed  StreamEventType = "aggregating_closed"
	StreamEventTicketCreated      StreamEventType = "ticket_created"
)

type StreamEvent struct {
	Type     StreamEventType `json:"type"`
	Ticket   *TicketListItem `json:"ticket,omitempty"`
	WindowID *string         `json:"window_id,omitempty"`
	TicketID *string         `json:"ticket_id,omitempty"`
}

type StreamPublisher interface {
	Publish(ev StreamEvent)
}
