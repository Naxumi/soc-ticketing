package ticket

import (
	"encoding/json"
	"time"
)

type Severity string

type Status string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

const (
	StatusOpen          Status = "OPEN"
	StatusInProgress    Status = "IN_PROGRESS"
	StatusEscalated     Status = "ESCALATED"
	StatusInvestigating Status = "INVESTIGATING"
	StatusFalsePositive Status = "FALSE_POSITIVE"
	StatusResolved      Status = "RESOLVED"
	StatusAggregating   Status = "AGGREGATING"
)

type Ticket struct {
	ID              string
	TicketNumber    string
	SourceIP        string
	AttackRuleID    string
	ThreatCategory  *string
	ThreatType      *string
	Severity        *Severity
	Status          Status
	AssigneeID      *string
	AssigneeName    *string
	FirstSeen       time.Time
	LastSeen        time.Time
	RawLogCount     int
	PayloadFirst    json.RawMessage
	PayloadLast     json.RawMessage
	PayloadSample   json.RawMessage
	CreatedAt       time.Time
	UpdatedAt       time.Time
	IsAggregating   bool
	WindowExpiresAt *time.Time
	WindowSeconds   *int
}

type RawLog struct {
	ID           string
	TicketID     string
	WazuhEventID *string
	SourceIP     string
	AttackRuleID string
	EventTime    time.Time
	RawPayload   json.RawMessage
	CreatedAt    time.Time
}

type Analysis struct {
	ID               string
	TicketID         string
	ModelName        string
	Summary          *string
	DetailedAnalysis *string
	AttackVector     *string
	PotentialImpact  *string
	ConfidenceScore  *float64
	ProcessingTimeMs *float64
	CreatedAt        time.Time
}

type Recommendation struct {
	ID         string
	AnalysisID string
	Priority   int
	Action     string
	Reason     *string
	CreatedAt  time.Time
}

type IOC struct {
	ID        string
	TicketID  string
	IOCType   string
	IOCValue  string
	CreatedAt time.Time
}

type AuditLog struct {
	ID             string
	TicketID       string
	UserID         *string
	Action         string
	Note           *string
	CreatedAt      time.Time
	UserFullName   *string
	UserRole       *string
	TicketNumber   string
	SourceIP       string
	ThreatCategory *string
	ThreatType     *string
	Severity       *Severity
	FirstSeen      time.Time
	LastSeen       time.Time
}

// Detail is an aggregate of a ticket and all related tables.
type Detail struct {
	Ticket          Ticket
	RawLogs         []RawLog
	Analysis        *Analysis
	Recommendations []Recommendation
	IOCs            []IOC
	AuditLogs       []AuditLog
}
