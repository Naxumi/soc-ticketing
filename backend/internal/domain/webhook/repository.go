package webhook

import (
	"context"
	"encoding/json"
	"time"

	"github.com/naxumi/soc-ticketing/internal/domain/ticket"
)

type Repository interface {
	UpsertTicketByAlertID(ctx context.Context, in UpsertTicketInput) (ticketID string, err error)
	UpsertRawLog(ctx context.Context, ticketID string, rawPayload json.RawMessage) error
	UpsertAnalysis(ctx context.Context, ticketID string, in UpsertAnalysisInput) (analysisID string, err error)
	ReplaceRecommendations(ctx context.Context, analysisID string, recs []UpsertRecommendationInput) error
	ReplaceIOCs(ctx context.Context, ticketID string, iocs []UpsertIOCInput) error

	GetWindowForUpdate(ctx context.Context, sourceIP string, attackRuleID string) (*IngestWindow, error)
	CreateWindow(ctx context.Context, in CreateWindowInput) (*IngestWindow, error)
	UpdateWindow(ctx context.Context, in UpdateWindowInput) error
	InsertWindowLog(ctx context.Context, in InsertWindowLogInput) error
	ListWindowLogPayloads(ctx context.Context, windowID string) ([]json.RawMessage, error)
	ListDueWindowsForUpdate(ctx context.Context, now time.Time) ([]IngestWindow, error)
	CreateTicketFromWindow(ctx context.Context, in CreateTicketFromWindowInput) (ticketID string, err error)
	MoveWindowLogsToTicket(ctx context.Context, windowID string, ticketID string) (moved int64, err error)
	DeleteWindow(ctx context.Context, windowID string) error
	CountActiveWindows(ctx context.Context) (int, error)
}

type UpsertTicketInput struct {
	WazuhAlertID   string
	ThreatCategory *string
	ThreatType     *string
	Severity       *ticket.Severity
	EventTimestamp time.Time
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

type UpsertIOCInput struct {
	IOCType  string
	IOCValue string
}

type IngestWindow struct {
	ID              string
	SourceIP        string
	AttackRuleID    string
	ThreatCategory  *string
	ThreatType      *string
	Severity        *ticket.Severity
	SampleScore     int
	FirstSeen       time.Time
	LastSeen        time.Time
	RawLogCount     int
	WindowSeconds   int
	WindowExpiresAt time.Time
	PayloadFirst    json.RawMessage
	PayloadLast     json.RawMessage
	PayloadSample   json.RawMessage
}

type CreateWindowInput struct {
	SourceIP        string
	AttackRuleID    string
	ThreatCategory  *string
	ThreatType      *string
	Severity        *ticket.Severity
	SampleScore     int
	FirstSeen       time.Time
	LastSeen        time.Time
	RawLogCount     int
	WindowSeconds   int
	WindowExpiresAt time.Time
	PayloadFirst    json.RawMessage
	PayloadLast     json.RawMessage
	PayloadSample   json.RawMessage
}

type UpdateWindowInput struct {
	WindowID        string
	ThreatCategory  *string
	ThreatType      *string
	Severity        *ticket.Severity
	SampleScore     int
	LastSeen        time.Time
	RawLogCount     int
	WindowSeconds   int
	WindowExpiresAt time.Time
	PayloadLast     json.RawMessage
	PayloadSample   json.RawMessage
}

type InsertWindowLogInput struct {
	WindowID     string
	WazuhEventID *string
	SourceIP     string
	AttackRuleID string
	EventTime    time.Time
	RawPayload   json.RawMessage
}

type CreateTicketFromWindowInput struct {
	SourceIP       string
	AttackRuleID   string
	ThreatCategory *string
	ThreatType     *string
	Severity       *ticket.Severity
	FirstSeen      time.Time
	LastSeen       time.Time
	RawLogCount    int
	PayloadFirst   json.RawMessage
	PayloadLast    json.RawMessage
	PayloadSample  json.RawMessage
}
