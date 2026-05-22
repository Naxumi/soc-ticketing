package webhook

import "context"

type Service interface {
	IngestWazuh(ctx context.Context, req WazuhWebhookRequest) (IngestResponse, error)
	IngestRawLogs(ctx context.Context, req WazuhRawLogBatchRequest) (RawLogIngestResponse, error)
}

type IngestResponse struct {
	CreatedOrUpdatedTickets int      `json:"created_or_updated_tickets"`
	TicketIDs               []string `json:"ticket_ids"`
}

type RawLogIngestResponse struct {
	ProcessedLogs      int      `json:"processed_logs"`
	CreatedTickets     int      `json:"created_tickets"`
	CreatedTicketIDs   []string `json:"created_ticket_ids"`
	ActiveGroupingKeys int      `json:"active_grouping_keys"`
}
