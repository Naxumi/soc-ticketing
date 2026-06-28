package ticket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/naxumi/soc-ticketing/internal/domain/ticket"
	"github.com/naxumi/soc-ticketing/internal/domain/user"
	"github.com/naxumi/soc-ticketing/internal/pkg/database"
	"github.com/naxumi/soc-ticketing/internal/pkg/validator"
)

type Service struct {
	db             *database.DB
	tix            ticket.Repository
	logs           ticket.AuditLogRepository
	analyzeURL     string
	analyzeAPIKey  string
	analyzeTimeout time.Duration
	httpClient     *http.Client
}

func New(
	db *database.DB,
	tix ticket.Repository,
	logs ticket.AuditLogRepository,
	analyzeURL string,
	analyzeAPIKey string,
	analyzeTimeout time.Duration,
) *Service {
	if analyzeTimeout <= 0 {
		analyzeTimeout = 60 * time.Second
	}
	return &Service{
		db:             db,
		tix:            tix,
		logs:           logs,
		analyzeURL:     strings.TrimSpace(analyzeURL),
		analyzeAPIKey:  strings.TrimSpace(analyzeAPIKey),
		analyzeTimeout: analyzeTimeout,
		httpClient:     &http.Client{},
	}
}

func (s *Service) List(ctx context.Context, actorUserID string, actorRole string, q ticket.ListTicketsQuery) (ticket.ListTicketsResponse, error) {
	if err := q.Validate(); err != nil {
		return ticket.ListTicketsResponse{}, err
	}

	actor := strings.TrimSpace(actorUserID)
	role := user.Role(strings.TrimSpace(actorRole))
	if role == user.RoleL1Analyst || role == user.RoleL2Analyst {
		if q.Tab == nil {
			return ticket.ListTicketsResponse{}, validator.ValidationErrors{{Field: "tab", Message: "tab is required"}}
		}
		allowedStatuses := allowedStatusesForRoleTab(role, *q.Tab)
		if len(allowedStatuses) == 0 {
			return ticket.ListTicketsResponse{}, validator.ValidationErrors{{Field: "tab", Message: "tab must be one of: active, history"}}
		}
		if q.Status != nil && !statusInList(*q.Status, allowedStatuses) {
			return ticket.ListTicketsResponse{}, validator.ValidationErrors{{Field: "status", Message: "status is not allowed for this tab"}}
		}
		if q.AssigneeID != nil && *q.AssigneeID != actor {
			return ticket.ListTicketsResponse{}, validator.ValidationErrors{{Field: "assignee_id", Message: "assignee_id must match current user"}}
		}
		if q.Status != nil {
			q.Statuses = []ticket.Status{*q.Status}
		} else {
			q.Statuses = allowedStatuses
		}
		q.ActivityUserID = &actor
		q.AssigneeID = nil
		if role == user.RoleL1Analyst && *q.Tab == ticket.TicketTabActive {
			q.AllowOpenForAll = true
		}
		if role == user.RoleL1Analyst && *q.Tab == ticket.TicketTabActive {
			q.AllowAggregatingForAll = true
		}
		if role == user.RoleL2Analyst && *q.Tab == ticket.TicketTabActive {
			q.AllowEscalatedForAll = true
		}
	}

	total, err := s.tix.Count(ctx, q)
	if err != nil {
		return ticket.ListTicketsResponse{}, err
	}

	totalPages := 0
	if q.Limit > 0 {
		totalPages = int(math.Ceil(float64(total) / float64(q.Limit)))
	}
	if total == 0 {
		totalPages = 0
	}

	offset := (q.Page - 1) * q.Limit
	items, err := s.tix.List(ctx, q, q.Limit, offset)
	if err != nil {
		return ticket.ListTicketsResponse{}, err
	}

	outItems := make([]ticket.TicketListItem, 0, len(items))
	for _, t := range items {
		var windowExpiresAt *string
		if t.WindowExpiresAt != nil {
			v := t.WindowExpiresAt.UTC().Format(time.RFC3339)
			windowExpiresAt = &v
		}
		windowSeconds := t.WindowSeconds
		isAggregating := t.IsAggregating || t.Status == ticket.StatusAggregating

		outItems = append(outItems, ticket.TicketListItem{
			ID:              t.ID,
			TicketNumber:    t.TicketNumber,
			SourceIP:        t.SourceIP,
			AttackRuleID:    t.AttackRuleID,
			ThreatCategory:  t.ThreatCategory,
			ThreatType:      t.ThreatType,
			Severity:        t.Severity,
			Status:          t.Status,
			AssigneeID:      t.AssigneeID,
			AssigneeName:    t.AssigneeName,
			FirstSeen:       t.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:        t.LastSeen.UTC().Format(time.RFC3339),
			RawLogCount:     t.RawLogCount,
			IsAggregating:   isAggregating,
			WindowExpiresAt: windowExpiresAt,
			WindowSeconds:   windowSeconds,
		})
	}

	return ticket.ListTicketsResponse{
		Metadata: ticket.TicketListMetadata{
			TotalData:  total,
			Page:       q.Page,
			TotalPages: totalPages,
		},
		Data: outItems,
	}, nil
}

func allowedStatusesForRoleTab(role user.Role, tab ticket.TicketTab) []ticket.Status {
	switch role {
	case user.RoleL1Analyst:
		switch tab {
		case ticket.TicketTabActive:
			return []ticket.Status{ticket.StatusOpen, ticket.StatusInProgress}
		case ticket.TicketTabHistory:
			return []ticket.Status{ticket.StatusInProgress, ticket.StatusEscalated, ticket.StatusInvestigating, ticket.StatusFalsePositive, ticket.StatusResolved}
		}
	case user.RoleL2Analyst:
		switch tab {
		case ticket.TicketTabActive:
			return []ticket.Status{ticket.StatusEscalated, ticket.StatusInvestigating}
		case ticket.TicketTabHistory:
			return []ticket.Status{ticket.StatusInvestigating, ticket.StatusFalsePositive, ticket.StatusResolved}
		}
	}
	return nil
}

func statusInList(status ticket.Status, allowed []ticket.Status) bool {
	for _, s := range allowed {
		if s == status {
			return true
		}
	}
	return false
}

func (s *Service) GetDetail(ctx context.Context, id string) (ticket.TicketDetailResponse, error) {
	detail, err := s.tix.GetDetail(ctx, id)
	if err != nil {
		return ticket.TicketDetailResponse{}, err
	}

	head := ticket.TicketHeader{
		ID:             detail.Ticket.ID,
		TicketNumber:   detail.Ticket.TicketNumber,
		SourceIP:       detail.Ticket.SourceIP,
		AttackRuleID:   detail.Ticket.AttackRuleID,
		ThreatCategory: detail.Ticket.ThreatCategory,
		ThreatType:     detail.Ticket.ThreatType,
		Severity:       detail.Ticket.Severity,
		Status:         detail.Ticket.Status,
		AssigneeID:     detail.Ticket.AssigneeID,
		FirstSeen:      detail.Ticket.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:       detail.Ticket.LastSeen.UTC().Format(time.RFC3339),
		RawLogCount:    detail.Ticket.RawLogCount,
		PayloadFirst:   detail.Ticket.PayloadFirst,
		PayloadLast:    detail.Ticket.PayloadLast,
		PayloadSample:  detail.Ticket.PayloadSample,
		CreatedAt:      detail.Ticket.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      detail.Ticket.UpdatedAt.UTC().Format(time.RFC3339),
	}

	var anaOut *ticket.TicketAnalysis
	if detail.Analysis != nil {
		anaOut = &ticket.TicketAnalysis{
			ModelName:        detail.Analysis.ModelName,
			Summary:          detail.Analysis.Summary,
			DetailedAnalysis: detail.Analysis.DetailedAnalysis,
			AttackVector:     detail.Analysis.AttackVector,
			PotentialImpact:  detail.Analysis.PotentialImpact,
			ConfidenceScore:  detail.Analysis.ConfidenceScore,
			ProcessingTimeMs: detail.Analysis.ProcessingTimeMs,
			CreatedAt:        detail.Analysis.CreatedAt.UTC().Format(time.RFC3339),
		}
	}

	recOut := make([]ticket.TicketRecommendation, 0, len(detail.Recommendations))
	for _, r := range detail.Recommendations {
		recOut = append(recOut, ticket.TicketRecommendation{Priority: r.Priority, Action: r.Action, Reason: r.Reason})
	}

	iocOut := make([]ticket.TicketIOC, 0, len(detail.IOCs))
	for _, i := range detail.IOCs {
		iocOut = append(iocOut, ticket.TicketIOC{IOCType: i.IOCType, IOCValue: i.IOCValue})
	}

	logOut := make([]ticket.TicketAuditLog, 0, len(detail.AuditLogs))
	for _, l := range detail.AuditLogs {
		logOut = append(logOut, ticket.TicketAuditLog{
			Action:       l.Action,
			Note:         l.Note,
			CreatedAt:    l.CreatedAt.UTC().Format(time.RFC3339),
			UserFullName: l.UserFullName,
			UserRole:     l.UserRole,
		})
	}

	rawOut := make([]ticket.TicketRawLogItem, 0, len(detail.RawLogs))
	for _, rl := range detail.RawLogs {
		rawOut = append(rawOut, ticket.TicketRawLogItem{
			WazuhEventID: rl.WazuhEventID,
			SourceIP:     rl.SourceIP,
			AttackRuleID: rl.AttackRuleID,
			EventTime:    rl.EventTime.UTC().Format(time.RFC3339),
			RawPayload:   rl.RawPayload,
			CreatedAt:    rl.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	return ticket.TicketDetailResponse{
		Ticket:          head,
		Analysis:        anaOut,
		Recommendations: recOut,
		IOCs:            iocOut,
		AuditLogs:       logOut,
		RawLogs:         rawOut,
	}, nil
}

func (s *Service) UpdateStatus(ctx context.Context, ticketID string, actorUserID string, actorRole string, req ticket.UpdateStatusRequest) error {
	actor := strings.TrimSpace(actorUserID)
	if req.AssigneeID == nil || strings.TrimSpace(*req.AssigneeID) == "" {
		req.AssigneeID = &actor
	}

	if err := req.Validate(); err != nil {
		return err
	}

	role := user.Role(strings.TrimSpace(actorRole))
	return database.WithTransaction(ctx, s.db, func(txCtx context.Context) error {
		current, err := s.tix.GetByIDForUpdate(txCtx, ticketID)
		if err != nil {
			return err
		}

		if (current.Status == ticket.StatusFalsePositive || current.Status == ticket.StatusResolved) && role != user.RoleSOCManager {
			return ticket.ErrTicketStatusTerminal
		}

		if req.Status == ticket.StatusInvestigating || req.Status == ticket.StatusResolved {
			if role != user.RoleL2Analyst && role != user.RoleSOCManager {
				return ticket.ErrInsufficientRoleForStatus
			}
		}

		if err := validateTransition(current.Status, req.Status); err != nil {
			if !(role == user.RoleSOCManager && (current.Status == ticket.StatusFalsePositive || current.Status == ticket.StatusResolved)) {
				return err
			}
		}

		if current.Status == ticket.StatusInProgress || current.Status == ticket.StatusInvestigating {
			if current.AssigneeID != nil && *current.AssigneeID != actor && role != user.RoleSOCManager {
				return ticket.ErrTicketLockedByUser
			}
		}

		var assigneeName, assigneeRoleStr string
		if req.AssigneeID != nil {
			var err error
			assigneeName, assigneeRoleStr, err = s.logs.GetUserFullNameAndRoleByID(txCtx, *req.AssigneeID)
			if err != nil {
				return err
			}
			assigneeRole := user.Role(assigneeRoleStr)

			if req.Status == ticket.StatusInProgress {
				if assigneeRole != user.RoleL1Analyst && assigneeRole != user.RoleSOCManager {
					return ticket.ErrInsufficientRoleForStatus
				}
			}
			if req.Status == ticket.StatusInvestigating {
				if assigneeRole != user.RoleL2Analyst && assigneeRole != user.RoleSOCManager {
					return ticket.ErrInsufficientRoleForStatus
				}
			}
		}

		if err := s.tix.UpdateStatus(txCtx, ticketID, req.Status, req.AssigneeID); err != nil {
			return err
		}

		note := req.Note
		now := time.Now().UTC()

		if req.AssigneeID != nil && *req.AssigneeID != actor && role == user.RoleSOCManager {
			if assigneeName != "" {
				assignAction := fmt.Sprintf("DELEGATED_TO|%s|%s", assigneeName, assigneeRoleStr)
				_ = s.logs.Create(txCtx, ticket.AuditLog{
					TicketID:  ticketID,
					UserID:    &actor,
					Action:    assignAction,
					CreatedAt: now,
				})
			}
		}

		action := "STATUS_UPDATED_TO_" + string(req.Status)
		return s.logs.Create(txCtx, ticket.AuditLog{
			TicketID:  ticketID,
			UserID:    &actor,
			Action:    action,
			Note:      &note,
			CreatedAt: now,
		})
	})
}

func (s *Service) Analyze(ctx context.Context, ticketID string, actorUserID string, req ticket.AnalyzeTicketRequest) (ticket.AnalyzeTicketResponse, error) {
	endpointURL := buildAnalyzeGoURL(s.analyzeURL)
	if endpointURL == "" {
		return ticket.AnalyzeTicketResponse{}, validator.ValidationErrors{{Field: "analyze_api_url", Message: "analyze API URL is not configured"}}
	}

	detail, err := s.tix.GetDetail(ctx, ticketID)
	if err != nil {
		return ticket.AnalyzeTicketResponse{}, err
	}

	analyzeReq := buildAnalyzeGoRequest(detail, req)
	bodyBytes, err := json.Marshal(analyzeReq)
	if err != nil {
		return ticket.AnalyzeTicketResponse{}, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, s.analyzeTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpointURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return ticket.AnalyzeTicketResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if s.analyzeAPIKey != "" {
		httpReq.Header.Set("X-API-Key", s.analyzeAPIKey)
	}

	httpRes, err := s.httpClient.Do(httpReq)
	if err != nil {
		return ticket.AnalyzeTicketResponse{}, err
	}
	defer httpRes.Body.Close()

	resBody, err := io.ReadAll(httpRes.Body)
	if err != nil {
		return ticket.AnalyzeTicketResponse{}, err
	}
	if len(resBody) == 0 {
		resBody = []byte("{}")
	}

	var envelope analyzeGoEnvelope
	if err := json.Unmarshal(resBody, &envelope); err != nil {
		if httpRes.StatusCode < 200 || httpRes.StatusCode >= 300 {
			msg := strings.TrimSpace(string(resBody))
			if msg == "" {
				msg = "external analyze API returned non-success status"
			}
			return ticket.AnalyzeTicketResponse{}, validator.ValidationErrors{{Field: "analyze_api", Message: msg}}
		}
		return ticket.AnalyzeTicketResponse{}, validator.ValidationErrors{{Field: "analyze_api", Message: "invalid response format from analyze API"}}
	}

	now := time.Now().UTC()
	if httpRes.StatusCode < 200 || httpRes.StatusCode >= 300 || !strings.EqualFold(envelope.Status, "success") || envelope.Data == nil {
		message := "external analyze API returned non-success status"
		if envelope.Error != nil {
			if strings.TrimSpace(envelope.Error.Message) != "" {
				message = strings.TrimSpace(envelope.Error.Message)
			}
			if strings.TrimSpace(envelope.Error.Code) != "" {
				message = fmt.Sprintf("[%s] %s", strings.TrimSpace(envelope.Error.Code), message)
			}
		}
		return ticket.AnalyzeTicketResponse{}, validator.ValidationErrors{{Field: "analyze_api", Message: message}}
	}

	modelName := firstNonEmpty(
		strings.TrimSpace(envelope.Data.ModelUsed),
		strings.TrimSpace(envelope.Meta.ModelUsed),
		strings.TrimSpace(valueOrEmpty(req.ModelName)),
		"unknown",
	)

	var status *ticket.Status
	if envelope.Data.IsFalsePositive && envelope.Data.FalsePositiveConfidence != nil && *envelope.Data.FalsePositiveConfidence >= 0.8 {
		st := ticket.StatusFalsePositive
		status = &st
	}

	severity := parseSeverity(envelope.Data.Severity)
	threatCategory := stringPtrOrNil(envelope.Data.ThreatCategory)
	recommendations := buildRecommendationInputs(envelope.Data.RecommendedActions)
	mitreTechniques := extractMitreTechniqueIDs(envelope.Data.MitreAttacks)

	analysisCreatedAt := parseEngineTimestamp(envelope.Data.Timestamp, now)

	err = database.WithTransaction(ctx, s.db, func(txCtx context.Context) error {
		if err := s.tix.UpdateFromAnalysis(txCtx, ticketID, ticket.UpdateFromAnalysisInput{
			Severity:       severity,
			ThreatCategory: threatCategory,
			Status:         status,
		}); err != nil {
			return err
		}

		analysisID, err := s.tix.UpsertAnalysis(txCtx, ticketID, ticket.UpsertAnalysisInput{
			ModelName:        modelName,
			Summary:          stringPtrOrNil(envelope.Data.Summary),
			DetailedAnalysis: stringPtrOrNil(envelope.Data.DetailedAnalysis),
			AttackVector:     stringPtrOrNil(envelope.Data.AttackVector),
			PotentialImpact:  stringPtrOrNil(envelope.Data.PotentialImpact),
			ConfidenceScore:  envelope.Data.ConfidenceScore,
			ProcessingTimeMs: envelope.Data.ProcessingTimeMs,
			CreatedAt:        analysisCreatedAt,
		})
		if err != nil {
			return err
		}

		if err := s.tix.ReplaceRecommendations(txCtx, analysisID, recommendations); err != nil {
			return err
		}

		if err := s.tix.ReplaceMitreTechniques(txCtx, ticketID, mitreTechniques); err != nil {
			return err
		}

		note := "AI analysis completed"
		if req.Note != nil && strings.TrimSpace(*req.Note) != "" {
			note = strings.TrimSpace(*req.Note)
		}
		if strings.TrimSpace(envelope.Meta.RequestID) != "" {
			note = fmt.Sprintf("%s (request_id=%s)", note, strings.TrimSpace(envelope.Meta.RequestID))
		}

		var userID *string
		if actor := strings.TrimSpace(actorUserID); actor != "" {
			userID = &actor
		}

		return s.logs.Create(txCtx, ticket.AuditLog{
			TicketID:  ticketID,
			UserID:    userID,
			Action:    "ANALYZE_COMPLETED",
			Note:      &note,
			CreatedAt: now,
		})
	})
	if err != nil {
		return ticket.AnalyzeTicketResponse{}, err
	}

	return ticket.AnalyzeTicketResponse{
		ForwardedTo:  endpointURL,
		StatusCode:   httpRes.StatusCode,
		EngineStatus: envelope.Status,
		RequestID:    strings.TrimSpace(envelope.Meta.RequestID),
		Saved:        true,
		Response:     json.RawMessage(resBody),
	}, nil
}

func validateTransition(from, to ticket.Status) error {
	allowed := map[ticket.Status][]ticket.Status{
		ticket.StatusOpen:          {ticket.StatusInProgress},
		ticket.StatusInProgress:    {ticket.StatusEscalated, ticket.StatusFalsePositive},
		ticket.StatusEscalated:     {ticket.StatusInvestigating},
		ticket.StatusInvestigating: {ticket.StatusFalsePositive, ticket.StatusResolved},
	}

	nexts, ok := allowed[from]
	if !ok {
		return validator.ValidationErrors{{Field: "status", Message: "status transition is not allowed"}}
	}
	for _, n := range nexts {
		if n == to {
			return nil
		}
	}
	return validator.ValidationErrors{{Field: "status", Message: "status transition is not allowed"}}
}

type analyzeGoRequest struct {
	Alert   analyzeGoAlert   `json:"alert"`
	Options analyzeGoOptions `json:"options,omitempty"`
}

type analyzeGoAlert struct {
	RuleID          string   `json:"rule_id"`
	RuleLevel       int      `json:"rule_level"`
	RuleDescription string   `json:"rule_description"`
	FullLog         string   `json:"full_log"`
	AgentID         string   `json:"agent_id,omitempty"`
	AgentName       string   `json:"agent_name,omitempty"`
	AgentIP         string   `json:"agent_ip,omitempty"`
	Timestamp       string   `json:"timestamp,omitempty"`
	RuleMitreID     []string `json:"rule_mitre_id,omitempty"`
	RuleGroups      []string `json:"rule_groups,omitempty"`
	DecoderName     string   `json:"decoder_name,omitempty"`
	Location        string   `json:"location,omitempty"`
}

type analyzeGoOptions struct {
	ModelName        string `json:"model_name,omitempty"`
	ResponseLanguage string `json:"response_language,omitempty"`
}

type analyzeGoEnvelope struct {
	Status string          `json:"status"`
	Data   *analyzeGoData  `json:"data"`
	Error  *analyzeGoError `json:"error"`
	Meta   analyzeGoMeta   `json:"meta"`
}

type analyzeGoMeta struct {
	RequestID        string   `json:"request_id"`
	ModelUsed        string   `json:"model_used"`
	ResponseLanguage string   `json:"response_language"`
	ProcessingTimeMs *float64 `json:"processing_time_ms"`
}

type analyzeGoError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details"`
}

type analyzeGoData struct {
	AnalysisID              string                       `json:"analysis_id"`
	Timestamp               string                       `json:"timestamp"`
	ProcessingTimeMs        *float64                     `json:"processing_time_ms"`
	AlertID                 string                       `json:"alert_id"`
	AlertLevel              int                          `json:"alert_level"`
	Severity                string                       `json:"severity"`
	ThreatCategory          string                       `json:"threat_category"`
	IsFalsePositive         bool                         `json:"is_false_positive"`
	FalsePositiveConfidence *float64                     `json:"false_positive_confidence"`
	ConfidenceScore         *float64                     `json:"confidence_score"`
	Summary                 string                       `json:"summary"`
	DetailedAnalysis        string                       `json:"detailed_analysis"`
	AttackVector            string                       `json:"attack_vector"`
	PotentialImpact         string                       `json:"potential_impact"`
	MitreAttacks            []analyzeGoMitreAttack       `json:"mitre_attacks"`
	RecommendedActions      []analyzeGoRecommendedAction `json:"recommended_actions"`
	ModelUsed               string                       `json:"model_used"`
	ResponseLanguage        string                       `json:"response_language"`
}

type analyzeGoMitreAttack struct {
	TechniqueID string `json:"technique_id"`
}

type analyzeGoRecommendedAction struct {
	Priority int    `json:"priority"`
	Action   string `json:"action"`
	Reason   string `json:"reason"`
}

func buildAnalyzeGoRequest(detail ticket.Detail, req ticket.AnalyzeTicketRequest) analyzeGoRequest {
	rawMaps := collectAnalyzeRawMaps(detail)

	ruleID := firstNonEmpty(
		strings.TrimSpace(detail.Ticket.AttackRuleID),
		firstLookupString(rawMaps, []string{"alert", "rule", "id"}, []string{"rule_id"}),
	)
	if ruleID == "" {
		ruleID = "unknown"
	}

	ruleDescription := firstNonEmpty(
		firstLookupString(rawMaps, []string{"alert", "rule", "description"}, []string{"rule_description"}),
		buildRuleDescription(detail),
	)

	ruleLevel := maxRuleLevelFromPayloads(detail)
	if ruleLevel <= 0 {
		ruleLevel = severityToRuleLevel(detail.Ticket.Severity)
	}
	if ruleLevel < 7 {
		ruleLevel = 7
	}

	timestamp := firstNonEmpty(
		firstLookupString(rawMaps, []string{"timestamp"}, []string{"alert", "timestamp"}, []string{"alert", "data", "timestamp"}, []string{"event_timestamp"}),
		detail.Ticket.LastSeen.UTC().Format(time.RFC3339),
	)

	fullLog := firstNonEmpty(
		buildFullLogFromPayloads(detail),
		fmt.Sprintf("ticket_number=%s source_ip=%s rule_id=%s", detail.Ticket.TicketNumber, detail.Ticket.SourceIP, ruleID),
	)

	opts := analyzeGoOptions{ResponseLanguage: normalizeResponseLanguage(req.ResponseLanguage)}
	if req.ModelName != nil && strings.TrimSpace(*req.ModelName) != "" {
		opts.ModelName = strings.TrimSpace(*req.ModelName)
	}

	alert := analyzeGoAlert{
		RuleID:          ruleID,
		RuleLevel:       ruleLevel,
		RuleDescription: ruleDescription,
		FullLog:         fullLog,
		AgentID:         firstLookupString(rawMaps, []string{"agent", "id"}, []string{"agent_id"}),
		AgentName:       firstLookupString(rawMaps, []string{"agent", "name"}, []string{"agent_name"}),
		AgentIP:         firstLookupString(rawMaps, []string{"agent", "ip"}, []string{"agent_ip"}),
		Timestamp:       timestamp,
		RuleMitreID:     firstLookupStringSlice(rawMaps, []string{"alert", "rule", "mitre", "id"}, []string{"rule_mitre_id"}),
		RuleGroups:      firstLookupStringSlice(rawMaps, []string{"alert", "rule", "groups"}, []string{"rule_groups"}),
		DecoderName:     firstLookupString(rawMaps, []string{"decoder", "name"}, []string{"decoder_name"}),
		Location:        firstLookupString(rawMaps, []string{"location"}),
	}

	return analyzeGoRequest{
		Alert:   alert,
		Options: opts,
	}
}

func collectAnalyzeRawMaps(detail ticket.Detail) []map[string]any {
	out := make([]map[string]any, 0, 6)

	for i := len(detail.RawLogs) - 1; i >= 0; i-- {
		m := decodeRawMap(detail.RawLogs[i].RawPayload)
		if len(m) == 0 {
			continue
		}
		out = append(out, m)
		if len(out) >= 3 {
			break
		}
	}

	for _, payload := range []json.RawMessage{detail.Ticket.PayloadSample, detail.Ticket.PayloadLast, detail.Ticket.PayloadFirst} {
		m := decodeRawMap(payload)
		if len(m) == 0 {
			continue
		}
		out = append(out, m)
	}

	return out
}

func rawPayloadAsString(detail ticket.Detail) string {
	if n := len(detail.RawLogs); n > 0 {
		if raw := strings.TrimSpace(string(detail.RawLogs[n-1].RawPayload)); raw != "" {
			return raw
		}
	}
	for _, payload := range []json.RawMessage{detail.Ticket.PayloadSample, detail.Ticket.PayloadLast, detail.Ticket.PayloadFirst} {
		if raw := strings.TrimSpace(string(payload)); raw != "" {
			return raw
		}
	}
	return ""
}

func buildFullLogFromPayloads(detail ticket.Detail) string {
	parts := make([]string, 0, 3)
	for _, payload := range []json.RawMessage{detail.Ticket.PayloadFirst, detail.Ticket.PayloadLast, detail.Ticket.PayloadSample} {
		if raw := strings.TrimSpace(string(payload)); raw != "" {
			parts = append(parts, raw)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "\n")
}

func maxRuleLevelFromPayloads(detail ticket.Detail) int {
	maxLevel := 0
	for _, payload := range []json.RawMessage{detail.Ticket.PayloadFirst, detail.Ticket.PayloadLast, detail.Ticket.PayloadSample} {
		m := decodeRawMap(payload)
		if len(m) == 0 {
			continue
		}
		level := firstPositive(
			lookupIntMap(m, "llm_metadata", "severity_level"),
			lookupIntMap(m, "alert", "rule", "level"),
			lookupIntMap(m, "alert", "data", "alert", "severity"),
		)
		if level > maxLevel {
			maxLevel = level
		}
	}
	return maxLevel
}

func buildRuleDescription(detail ticket.Detail) string {
	threatType := strings.TrimSpace(valueOrEmpty(detail.Ticket.ThreatType))
	threatCategory := strings.TrimSpace(valueOrEmpty(detail.Ticket.ThreatCategory))

	if threatType != "" && threatCategory != "" {
		return fmt.Sprintf("%s - %s", threatCategory, threatType)
	}
	if threatType != "" {
		return threatType
	}
	if threatCategory != "" {
		return threatCategory
	}

	ruleID := strings.TrimSpace(detail.Ticket.AttackRuleID)
	if ruleID == "" {
		ruleID = "unknown"
	}
	return "Detected security alert for rule " + ruleID
}

func severityToRuleLevel(sev *ticket.Severity) int {
	if sev == nil {
		return 7
	}
	switch *sev {
	case ticket.SeverityCritical:
		return 12
	case ticket.SeverityHigh:
		return 10
	case ticket.SeverityMedium:
		return 8
	case ticket.SeverityLow:
		return 7
	default:
		return 7
	}
}

func buildAnalyzeGoURL(raw string) string {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	if base == "" {
		return ""
	}

	switch {
	case strings.HasSuffix(base, "/api/v1/analyze/go"):
		return base
	case strings.HasSuffix(base, "/api/v1/analyze"):
		return base + "/go"
	case strings.HasSuffix(base, "/api/v1"):
		return base + "/analyze/go"
	case strings.HasSuffix(base, "/analyze/go"):
		return base
	case strings.HasSuffix(base, "/analyze"):
		return base + "/go"
	default:
		return base + "/api/v1/analyze/go"
	}
}

func normalizeResponseLanguage(lang *string) string {
	v := strings.ToLower(strings.TrimSpace(valueOrEmpty(lang)))
	if v != "en" {
		return "id"
	}
	return "en"
}

func parseSeverity(raw string) *ticket.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "low":
		s := ticket.SeverityLow
		return &s
	case "medium":
		s := ticket.SeverityMedium
		return &s
	case "high":
		s := ticket.SeverityHigh
		return &s
	case "critical":
		s := ticket.SeverityCritical
		return &s
	default:
		return nil
	}
}

func parseEngineTimestamp(raw string, fallback time.Time) time.Time {
	v := strings.TrimSpace(raw)
	if v == "" {
		return fallback
	}

	layouts := []string{
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
		time.RFC3339,
		"2006-01-02T15:04:05.000-0700",
		"2006-01-02T15:04:05.000000-0700",
		"2006-01-02T15:04:05-0700",
	}

	for _, layout := range layouts {
		t, err := time.Parse(layout, v)
		if err == nil {
			return t.UTC()
		}
	}

	return fallback
}

func buildRecommendationInputs(actions []analyzeGoRecommendedAction) []ticket.UpsertRecommendationInput {
	out := make([]ticket.UpsertRecommendationInput, 0, len(actions))
	for idx, action := range actions {
		act := strings.TrimSpace(action.Action)
		if act == "" {
			continue
		}

		priority := action.Priority
		if priority <= 0 {
			priority = idx + 1
		}

		out = append(out, ticket.UpsertRecommendationInput{
			Priority: priority,
			Action:   act,
			Reason:   stringPtrOrNil(action.Reason),
		})
	}
	return out
}

func extractMitreTechniqueIDs(attacks []analyzeGoMitreAttack) []string {
	seen := make(map[string]struct{}, len(attacks))
	out := make([]string, 0, len(attacks))
	for _, attack := range attacks {
		techniqueID := strings.TrimSpace(attack.TechniqueID)
		if techniqueID == "" {
			continue
		}
		if _, ok := seen[techniqueID]; ok {
			continue
		}
		seen[techniqueID] = struct{}{}
		out = append(out, techniqueID)
	}
	return out
}

func decodeRawMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func firstLookupString(maps []map[string]any, paths ...[]string) string {
	for _, m := range maps {
		for _, p := range paths {
			if s := lookupStringMap(m, p...); s != "" {
				return s
			}
		}
	}
	return ""
}

func firstLookupInt(maps []map[string]any, paths ...[]string) int {
	for _, m := range maps {
		for _, p := range paths {
			if n := lookupIntMap(m, p...); n > 0 {
				return n
			}
		}
	}
	return 0
}

func firstLookupStringSlice(maps []map[string]any, paths ...[]string) []string {
	for _, m := range maps {
		for _, p := range paths {
			if v := lookupStringSliceMap(m, p...); len(v) > 0 {
				return v
			}
		}
	}
	return nil
}

func lookupStringMap(root map[string]any, keys ...string) string {
	v, ok := lookupAnyMap(root, keys...)
	if !ok || v == nil {
		return ""
	}

	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		return strings.TrimSpace(fmt.Sprint(x))
	}
}

func lookupIntMap(root map[string]any, keys ...string) int {
	v, ok := lookupAnyMap(root, keys...)
	if !ok || v == nil {
		return 0
	}

	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

func lookupStringSliceMap(root map[string]any, keys ...string) []string {
	v, ok := lookupAnyMap(root, keys...)
	if !ok || v == nil {
		return nil
	}

	seen := make(map[string]struct{})
	out := make([]string, 0)
	appendValue := func(item any) {
		s := strings.TrimSpace(fmt.Sprint(item))
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	switch x := v.(type) {
	case []any:
		for _, item := range x {
			appendValue(item)
		}
	case []string:
		for _, item := range x {
			appendValue(item)
		}
	default:
		appendValue(x)
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func lookupAnyMap(root map[string]any, keys ...string) (any, bool) {
	var cur any = root
	for _, key := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, exists := m[key]
		if !exists {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if s := strings.TrimSpace(value); s != "" {
			return s
		}
	}
	return ""
}

func stringPtrOrNil(raw string) *string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil
	}
	return &v
}

func valueOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
