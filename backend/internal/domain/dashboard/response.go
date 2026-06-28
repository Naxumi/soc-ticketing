package dashboard

import (
	"time"

	"github.com/naxumi/soc-ticketing/internal/domain/ticket"
	"github.com/naxumi/soc-ticketing/internal/domain/user"
)

type Response struct {
	Window              TimeWindow     `json:"window"`
	Role                string         `json:"role"`
	UnreadNotifications int64          `json:"unread_notifications"`
	Tickets             TicketsSection `json:"tickets"`
	Focus               *FocusSection  `json:"focus,omitempty"`
	Team                *TeamSection   `json:"team,omitempty"`
	GeneratedAt         string         `json:"generated_at"`
	GeneratedAtUnix     int64          `json:"generated_at_unix"`
	GeneratedAtTime     time.Time      `json:"-"`
}

type TicketsSection struct {
	BacklogByStatus           map[ticket.Status]int64 `json:"backlog_by_status"`
	BacklogBySeverity         map[string]int64        `json:"backlog_by_severity"`
	MyByStatus                map[ticket.Status]int64 `json:"my_by_status"`
	CreatedInWindow           int64                   `json:"created_in_window"`
	CreatedBySeverityInWindow map[string]int64        `json:"created_by_severity_in_window"`
	RecentInWindow            []TicketListItem        `json:"recent_in_window"`
}

type TicketListItem struct {
	ID             string           `json:"id"`
	TicketNumber   string           `json:"ticket_number"`
	SourceIP       string           `json:"source_ip"`
	AttackRuleID   string           `json:"attack_rule_id"`
	ThreatCategory *string          `json:"threat_category,omitempty"`
	ThreatType     *string          `json:"threat_type,omitempty"`
	Severity       *ticket.Severity `json:"severity,omitempty"`
	Status         ticket.Status    `json:"status"`
	FirstSeen      string           `json:"first_seen"`
	LastSeen       string           `json:"last_seen"`
	RawLogCount    int              `json:"raw_log_count"`
}

type TeamSection struct {
	UnassignedActive int64              `json:"unassigned_active"`
	Assignees        []AssigneeWorkload `json:"assignees"`
}

// FocusSection contains role-specific widgets.
// Only one of L1/L2 is expected to be non-nil for analyst roles.
type FocusSection struct {
	L1 *L1Focus `json:"l1,omitempty"`
	L2 *L2Focus `json:"l2,omitempty"`
}

type L1Focus struct {
	UnassignedOpen   int64 `json:"unassigned_open"`
	OpenHighCritical int64 `json:"open_high_critical"`
	MyInProgress     int64 `json:"my_in_progress"`
}

type L2Focus struct {
	Escalated                          int64 `json:"escalated"`
	Investigating                      int64 `json:"investigating"`
	UnassignedEscalatedOrInvestigating int64 `json:"unassigned_escalated_or_investigating"`
	MyInvestigating                    int64 `json:"my_investigating"`
}

type AssigneeWorkload struct {
	UserID         string                  `json:"user_id"`
	FullName       string                  `json:"full_name"`
	Username       string                  `json:"username"`
	Role           user.Role               `json:"role"`
	ActiveByStatus map[ticket.Status]int64 `json:"active_by_status"`
	TotalActive    int64                   `json:"total_active"`
}
