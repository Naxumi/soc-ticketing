package ticket

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/naxumi/soc-ticketing/internal/pkg/validator"
)

type ListTicketsQuery struct {
	Page                   int
	Limit                  int
	Status                 *Status
	Statuses               []Status
	Severity               *Severity
	AssigneeID             *string
	ActivityUserID         *string
	Tab                    *TicketTab
	AllowOpenForAll        bool
	AllowEscalatedForAll   bool
	AllowAggregatingForAll bool
}

type TicketTab string

const (
	TicketTabActive  TicketTab = "active"
	TicketTabHistory TicketTab = "history"
)

func ListTicketsQueryFromStrings(pageStr, limitStr, statusStr, severityStr, assigneeIDStr, tabStr string) (ListTicketsQuery, error) {
	page := 1
	limit := 10

	if strings.TrimSpace(pageStr) != "" {
		p, err := strconv.Atoi(pageStr)
		if err != nil {
			return ListTicketsQuery{}, validator.ValidationErrors{{Field: "page", Message: "page must be an integer"}}
		}
		page = p
	}
	if strings.TrimSpace(limitStr) != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil {
			return ListTicketsQuery{}, validator.ValidationErrors{{Field: "limit", Message: "limit must be an integer"}}
		}
		limit = l
	}

	var status *Status
	if strings.TrimSpace(statusStr) != "" {
		s := Status(strings.TrimSpace(statusStr))
		status = &s
	}

	var severity *Severity
	if strings.TrimSpace(severityStr) != "" {
		sv := Severity(strings.TrimSpace(severityStr))
		severity = &sv
	}

	var assigneeID *string
	if strings.TrimSpace(assigneeIDStr) != "" {
		v := strings.TrimSpace(assigneeIDStr)
		assigneeID = &v
	}

	var tab *TicketTab
	if strings.TrimSpace(tabStr) != "" {
		v := TicketTab(strings.TrimSpace(tabStr))
		tab = &v
	}

	q := ListTicketsQuery{Page: page, Limit: limit, Status: status, Severity: severity, AssigneeID: assigneeID, Tab: tab}
	if err := q.Validate(); err != nil {
		return ListTicketsQuery{}, err
	}
	return q, nil
}

func (q ListTicketsQuery) Validate() error {
	var errs validator.ValidationErrors
	if q.Page < 1 {
		errs = append(errs, validator.ValidationError{Field: "page", Message: "page must be >= 1"})
	}
	if q.Limit < 1 {
		errs = append(errs, validator.ValidationError{Field: "limit", Message: "limit must be >= 1"})
	} else if q.Limit > 100 {
		errs = append(errs, validator.ValidationError{Field: "limit", Message: "limit must be <= 100"})
	}
	if q.Status != nil && !isValidStatusFilter(*q.Status) {
		errs = append(errs, validator.ValidationError{Field: "status", Message: "status must be one of: OPEN, IN_PROGRESS, ESCALATED, INVESTIGATING, FALSE_POSITIVE, RESOLVED, AGGREGATING"})
	}
	if len(q.Statuses) > 0 {
		seenAggregating := false
		for _, status := range q.Statuses {
			if !isValidStatusFilter(status) {
				errs = append(errs, validator.ValidationError{Field: "status", Message: "status must be one of: OPEN, IN_PROGRESS, ESCALATED, INVESTIGATING, FALSE_POSITIVE, RESOLVED, AGGREGATING"})
				break
			}
			if status == StatusAggregating {
				seenAggregating = true
			}
		}
		if seenAggregating && len(q.Statuses) > 1 {
			errs = append(errs, validator.ValidationError{Field: "status", Message: "AGGREGATING cannot be combined with other statuses"})
		}
	}
	if q.Severity != nil && !isValidSeverity(*q.Severity) {
		errs = append(errs, validator.ValidationError{Field: "severity", Message: "severity must be one of: low, medium, high, critical"})
	}
	if q.AssigneeID != nil {
		if !isValidUUID(*q.AssigneeID) {
			errs = append(errs, validator.ValidationError{Field: "assignee_id", Message: "assignee_id must be a valid UUID"})
		}
	}
	if q.ActivityUserID != nil {
		if !isValidUUID(*q.ActivityUserID) {
			errs = append(errs, validator.ValidationError{Field: "activity_user_id", Message: "activity_user_id must be a valid UUID"})
		}
	}
	if q.Tab != nil && !isValidTicketTab(*q.Tab) {
		errs = append(errs, validator.ValidationError{Field: "tab", Message: "tab must be one of: active, history"})
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

type UpdateStatusRequest struct {
	Status     Status  `json:"status"`
	AssigneeID *string `json:"assignee_id"`
	Note       string  `json:"note"`
}

type AnalyzeTicketRequest struct {
	// Optional note for auditing why analysis is triggered.
	Note *string `json:"note,omitempty"`
	// Optional model override forwarded to AI engine.
	ModelName *string `json:"model_name,omitempty"`
	// Optional language preference: id or en. Defaults to id.
	ResponseLanguage *string `json:"response_language,omitempty"`
}

type AnalyzeTicketResponse struct {
	ForwardedTo  string          `json:"forwarded_to"`
	StatusCode   int             `json:"status_code"`
	EngineStatus string          `json:"engine_status,omitempty"`
	RequestID    string          `json:"request_id,omitempty"`
	Saved        bool            `json:"saved"`
	Response     json.RawMessage `json:"response,omitempty"`
}

func (r UpdateStatusRequest) Validate() error {
	var errs validator.ValidationErrors
	if !isValidStatus(r.Status) {
		errs = append(errs, validator.ValidationError{Field: "status", Message: "invalid status"})
	}
	if r.AssigneeID == nil || validator.IsEmpty(*r.AssigneeID) {
		errs = append(errs, validator.ValidationError{Field: "assignee_id", Message: "assignee_id is required"})
	} else if !isValidUUID(*r.AssigneeID) {
		errs = append(errs, validator.ValidationError{Field: "assignee_id", Message: "assignee_id must be a valid UUID"})
	}
	if validator.IsEmpty(r.Note) {
		errs = append(errs, validator.ValidationError{Field: "note", Message: "note is required"})
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func isValidStatus(s Status) bool {
	switch s {
	case StatusOpen, StatusInProgress, StatusEscalated, StatusInvestigating, StatusFalsePositive, StatusResolved:
		return true
	default:
		return false
	}
}

func isValidStatusFilter(s Status) bool {
	if s == StatusAggregating {
		return true
	}
	return isValidStatus(s)
}

func isValidSeverity(s Severity) bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func isValidTicketTab(t TicketTab) bool {
	switch t {
	case TicketTabActive, TicketTabHistory:
		return true
	default:
		return false
	}
}

var uuidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isValidUUID(s string) bool {
	return uuidRe.MatchString(strings.TrimSpace(s))
}

// ========================================
// Ticket Response DTOs (returned by service)
// ========================================

type TicketListMetadata struct {
	TotalData  int64 `json:"total_data"`
	Page       int   `json:"page"`
	TotalPages int   `json:"total_pages"`
}

type TicketListItem struct {
	ID              string    `json:"id"`
	TicketNumber    string    `json:"ticket_number"`
	SourceIP        string    `json:"source_ip"`
	AttackRuleID    string    `json:"attack_rule_id"`
	ThreatCategory  *string   `json:"threat_category,omitempty"`
	ThreatType      *string   `json:"threat_type,omitempty"`
	Severity        *Severity `json:"severity,omitempty"`
	Status          Status    `json:"status"`
	AssigneeID      *string   `json:"assignee_id,omitempty"`
	AssigneeName    *string   `json:"assignee_name,omitempty"`
	FirstSeen       string    `json:"first_seen"`
	LastSeen        string    `json:"last_seen"`
	RawLogCount     int       `json:"raw_log_count"`
	IsAggregating   bool      `json:"is_aggregating"`
	WindowExpiresAt *string   `json:"window_expires_at,omitempty"`
	WindowSeconds   *int      `json:"window_seconds,omitempty"`
}

type ListTicketsResponse struct {
	Metadata TicketListMetadata `json:"metadata"`
	Data     []TicketListItem   `json:"data"`
}

type TicketHeader struct {
	ID             string          `json:"id"`
	TicketNumber   string          `json:"ticket_number"`
	SourceIP       string          `json:"source_ip"`
	AttackRuleID   string          `json:"attack_rule_id"`
	ThreatCategory *string         `json:"threat_category,omitempty"`
	ThreatType     *string         `json:"threat_type,omitempty"`
	Severity       *Severity       `json:"severity,omitempty"`
	Status         Status          `json:"status"`
	AssigneeID     *string         `json:"assignee_id,omitempty"`
	FirstSeen      string          `json:"first_seen"`
	LastSeen       string          `json:"last_seen"`
	RawLogCount    int             `json:"raw_log_count"`
	PayloadFirst   json.RawMessage `json:"payload_first,omitempty"`
	PayloadLast    json.RawMessage `json:"payload_last,omitempty"`
	PayloadSample  json.RawMessage `json:"payload_sample,omitempty"`
	CreatedAt      string          `json:"created_at"`
	UpdatedAt      string          `json:"updated_at"`
}

type TicketAnalysis struct {
	ModelName        string   `json:"model_name"`
	Summary          *string  `json:"summary,omitempty"`
	DetailedAnalysis *string  `json:"detailed_analysis,omitempty"`
	AttackVector     *string  `json:"attack_vector,omitempty"`
	PotentialImpact  *string  `json:"potential_impact,omitempty"`
	ConfidenceScore  *float64 `json:"confidence_score,omitempty"`
	ProcessingTimeMs *float64 `json:"processing_time_ms,omitempty"`
	CreatedAt        string   `json:"created_at"`
}

type TicketRecommendation struct {
	Priority int     `json:"priority"`
	Action   string  `json:"action"`
	Reason   *string `json:"reason,omitempty"`
}

type TicketIOC struct {
	IOCType  string `json:"ioc_type"`
	IOCValue string `json:"ioc_value"`
}

type TicketAuditLog struct {
	Action       string  `json:"action"`
	Note         *string `json:"note,omitempty"`
	CreatedAt    string  `json:"created_at"`
	UserFullName *string `json:"user_full_name,omitempty"`
	UserRole     *string `json:"user_role,omitempty"`
}

type TicketRawLogItem struct {
	WazuhEventID *string         `json:"wazuh_event_id,omitempty"`
	SourceIP     string          `json:"source_ip"`
	AttackRuleID string          `json:"attack_rule_id"`
	EventTime    string          `json:"event_timestamp"`
	RawPayload   json.RawMessage `json:"raw_payload"`
	CreatedAt    string          `json:"created_at"`
}

type TicketDetailResponse struct {
	Ticket          TicketHeader           `json:"ticket"`
	Analysis        *TicketAnalysis        `json:"analysis,omitempty"`
	Recommendations []TicketRecommendation `json:"recommendations"`
	IOCs            []TicketIOC            `json:"iocs"`
	AuditLogs       []TicketAuditLog       `json:"audit_logs"`
	RawLogs         []TicketRawLogItem     `json:"raw_logs"`
}
