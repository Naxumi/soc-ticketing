package ticket

import (
	"context"
	"time"
)

type Repository interface {
	Count(ctx context.Context, q ListTicketsQuery) (int64, error)
	List(ctx context.Context, q ListTicketsQuery, limit, offset int) ([]Ticket, error)
	GetByID(ctx context.Context, id string) (Ticket, error)
	GetByIDForUpdate(ctx context.Context, id string) (Ticket, error)
	GetDetail(ctx context.Context, id string) (Detail, error)
	UpdateStatus(ctx context.Context, id string, status Status, assigneeID *string) error
	UpdateFromAnalysis(ctx context.Context, id string, in UpdateFromAnalysisInput) error
	UpsertAnalysis(ctx context.Context, ticketID string, in UpsertAnalysisInput) (analysisID string, err error)
	ReplaceRecommendations(ctx context.Context, analysisID string, recs []UpsertRecommendationInput) error
	ReplaceMitreTechniques(ctx context.Context, ticketID string, techniques []string) error
}

type UpdateFromAnalysisInput struct {
	Severity       *Severity
	ThreatCategory *string
	ThreatType     *string
	Status         *Status
}

type UpsertAnalysisInput struct {
	ModelName        string
	Summary          *string
	DetailedAnalysis *string
	AttackVector     *string
	PotentialImpact  *string
	ConfidenceScore  *float64
	ProcessingTimeMs *float64
	CreatedAt        time.Time
}

type UpsertRecommendationInput struct {
	Priority int
	Action   string
	Reason   *string
}

type RawLogRepository interface {
	ListByTicketID(ctx context.Context, ticketID string) ([]RawLog, error)
}

type AnalysisRepository interface {
	GetByTicketID(ctx context.Context, ticketID string) (*Analysis, error)
}

type RecommendationRepository interface {
	ListByAnalysisID(ctx context.Context, analysisID string) ([]Recommendation, error)
}

type IOCRepository interface {
	ListByTicketID(ctx context.Context, ticketID string) ([]IOC, error)
}

type AuditLogRepository interface {
	Create(ctx context.Context, l AuditLog) error
	ListByTicketID(ctx context.Context, ticketID string) ([]AuditLog, error)
	ListByUserID(ctx context.Context, userID string) ([]AuditLog, error)
	GetLastStatusUpdatedBy(ctx context.Context, ticketID string) (*string, error)
	GetUserFullNameAndRoleByID(ctx context.Context, userID string) (string, string, error)
}
