package ticket

import "context"

type Service interface {
	List(ctx context.Context, actorUserID string, actorRole string, q ListTicketsQuery) (ListTicketsResponse, error)
	GetDetail(ctx context.Context, id string) (TicketDetailResponse, error)
	UpdateStatus(ctx context.Context, ticketID string, actorUserID string, actorRole string, req UpdateStatusRequest) error
	Analyze(ctx context.Context, ticketID string, actorUserID string, req AnalyzeTicketRequest) (AnalyzeTicketResponse, error)
}
