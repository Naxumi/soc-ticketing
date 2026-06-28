package dashboard

import (
	"context"
	"time"

	"github.com/naxumi/soc-ticketing/internal/domain/ticket"
	"github.com/naxumi/soc-ticketing/internal/domain/user"
)

type StatusCount struct {
	Status ticket.Status
	Count  int64
}

type StringCount struct {
	Key   string
	Count int64
}

type RecentTicket struct {
	ID             string
	TicketNumber   string
	SourceIP       string
	AttackRuleID   string
	ThreatCategory *string
	ThreatType     *string
	Severity       *ticket.Severity
	Status         ticket.Status
	FirstSeen      time.Time
	LastSeen       time.Time
	RawLogCount    int
}

type TeamStatusCount struct {
	UserID   string
	FullName string
	Username string
	Role     user.Role
	Status   ticket.Status
	Count    int64
}

type TicketScopeFilter struct {
	Statuses             []ticket.Status
	UserID               *string
	AllowOpenForAll      bool
	AllowEscalatedForAll bool
}

type Repository interface {
	CountUnreadNotifications(ctx context.Context, userID string) (int64, error)

	CountTicketsByStatus(ctx context.Context, assigneeID *string) ([]StatusCount, error)
	CountTicketsBySeverity(ctx context.Context) ([]StringCount, error)
	CountTicketsByStatusAndSeverities(ctx context.Context, status ticket.Status, severities []ticket.Severity) (int64, error)
	CountTicketsByStatusScoped(ctx context.Context, filter TicketScopeFilter) ([]StatusCount, error)
	CountTicketsBySeverityScoped(ctx context.Context, filter TicketScopeFilter) ([]StringCount, error)

	CountTicketsCreatedInWindow(ctx context.Context, from, to time.Time) (int64, error)
	CountTicketsCreatedBySeverityInWindow(ctx context.Context, from, to time.Time) ([]StringCount, error)
	ListRecentTicketsInWindow(ctx context.Context, from, to time.Time, limit int) ([]RecentTicket, error)
	CountTicketsCreatedInWindowScoped(ctx context.Context, from, to time.Time, filter TicketScopeFilter) (int64, error)
	CountTicketsCreatedBySeverityInWindowScoped(ctx context.Context, from, to time.Time, filter TicketScopeFilter) ([]StringCount, error)
	ListRecentTicketsInWindowScoped(ctx context.Context, from, to time.Time, filter TicketScopeFilter, limit int) ([]RecentTicket, error)

	ListTeamActiveByAssigneeAndStatus(ctx context.Context, activeStatuses []ticket.Status) ([]TeamStatusCount, error)
	CountUnassignedActive(ctx context.Context, activeStatuses []ticket.Status) (int64, error)
	CountUnassignedActiveScoped(ctx context.Context, activeStatuses []ticket.Status, filter TicketScopeFilter) (int64, error)
}
