package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pitik0x/Ai-Security-analyst/internal/domain/notification"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/ticket"
	"github.com/pitik0x/Ai-Security-analyst/internal/domain/webhook"
	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/database"
)

type Service struct {
	db        *database.DB
	repo      webhook.Repository
	notifRepo notification.Repository
	pub       notification.Publisher
	streamPub ticket.StreamPublisher
}

type WindowFlushResult struct {
	CreatedTicketIDs   []string
	ActiveGroupingKeys int
}

const (
	baseWindowSeconds = 30
	maxWindowSeconds  = 600
)

func New(db *database.DB, repo webhook.Repository, notifRepo notification.Repository, pub notification.Publisher, streamPub ticket.StreamPublisher) *Service {
	return &Service{db: db, repo: repo, notifRepo: notifRepo, pub: pub, streamPub: streamPub}
}

func (s *Service) IngestWazuh(ctx context.Context, req webhook.WazuhWebhookRequest) (webhook.IngestResponse, error) {
	if err := req.Validate(); err != nil {
		return webhook.IngestResponse{}, err
	}

	createdAt := time.Now().UTC()
	if ts := strings.TrimSpace(req.Metadata.Timestamp); ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			createdAt = t.UTC()
		}
	}

	out := webhook.IngestResponse{TicketIDs: make([]string, 0, len(req.Results))}
	streamEvents := make([]ticket.StreamEvent, 0, len(req.Results))

	err := database.WithTransaction(ctx, s.db, func(txCtx context.Context) error {
		for _, res := range req.Results {
			eventTS, _ := time.Parse(time.RFC3339, res.Timestamp)

			threatCategory := strings.TrimSpace(res.ThreatCategory)
			threatTypeStr := strings.TrimSpace(res.ThreatType)
			threatType := &threatTypeStr

			sev := parseSeverity(res.Severity)
			if sev == nil {
				// Backward-compat fallback if caller sends only alert_level.
				sev = mapAlertLevelToSeverity(res.AlertLevel)
			}

			ticketID, err := s.repo.UpsertTicketByAlertID(txCtx, webhook.UpsertTicketInput{
				WazuhAlertID:   strings.TrimSpace(res.AlertID),
				ThreatCategory: &threatCategory,
				ThreatType:     threatType,
				Severity:       sev,
				EventTimestamp: eventTS.UTC(),
			})
			if err != nil {
				return err
			}

			if len(res.RawLog) > 0 {
				if err := s.repo.UpsertRawLog(txCtx, ticketID, res.RawLog); err != nil {
					return err
				}
			}

			modelName, modelRes, ok := res.PickModelResult()
			if !ok {
				modelName = "unknown"
				modelRes = webhook.LLMModelResult{}
			}

			analysisID, err := s.repo.UpsertAnalysis(txCtx, ticketID, webhook.UpsertAnalysisInput{
				ModelName:        modelName,
				Summary:          modelRes.Summary,
				DetailedAnalysis: modelRes.DetailedAnalysis,
				AttackVector:     modelRes.AttackVector,
				PotentialImpact:  modelRes.PotentialImpact,
				ConfidenceScore:  nil,
				ProcessingTimeMs: nil,
				CreatedAt:        createdAt,
			})
			if err != nil {
				return err
			}

			recs := make([]webhook.UpsertRecommendationInput, 0, len(modelRes.RecommendedActions))
			for _, a := range modelRes.RecommendedActions {
				if strings.TrimSpace(a.Action) == "" {
					continue
				}
				recs = append(recs, webhook.UpsertRecommendationInput{
					Priority: a.Priority,
					Action:   strings.TrimSpace(a.Action),
					Reason:   a.Reason,
				})
			}
			if err := s.repo.ReplaceRecommendations(txCtx, analysisID, recs); err != nil {
				return err
			}

			iocs := make([]webhook.UpsertIOCInput, 0)
			for k, v := range res.Indicators {
				key := strings.TrimSpace(k)
				if key == "" {
					continue
				}
				val := strings.TrimSpace(fmt.Sprint(v))
				if val == "" {
					continue
				}
				iocs = append(iocs, webhook.UpsertIOCInput{IOCType: key, IOCValue: val})
			}
			if err := s.repo.ReplaceIOCs(txCtx, ticketID, iocs); err != nil {
				return err
			}

			msg := fmt.Sprintf("New ticket %s: %s", strings.TrimSpace(res.AlertID), strings.TrimSpace(res.AlertDescription))
			if strings.TrimSpace(res.AlertDescription) == "" {
				msg = fmt.Sprintf("New ticket %s", strings.TrimSpace(res.AlertID))
			}
			nots, err := s.notifRepo.CreateForAllUsers(txCtx, &ticketID, msg)
			if err != nil {
				return err
			}
			if s.pub != nil {
				for _, n := range nots {
					s.pub.Publish(n.UserID, n)
				}
			}

			ticketItem := buildTicketListItemFromAlert(ticketID, "legacy", strings.TrimSpace(res.AlertID), &threatCategory, threatType, sev, eventTS.UTC())
			streamEvents = append(streamEvents, ticket.StreamEvent{
				Type:     ticket.StreamEventTicketCreated,
				Ticket:   &ticketItem,
				TicketID: &ticketID,
			})

			out.TicketIDs = append(out.TicketIDs, ticketID)
			out.CreatedOrUpdatedTickets++
		}
		return nil
	})
	if err != nil {
		return webhook.IngestResponse{}, err
	}

	if s.streamPub != nil {
		for _, ev := range streamEvents {
			s.streamPub.Publish(ev)
		}
	}

	return out, nil
}

func (s *Service) IngestRawLogs(ctx context.Context, req webhook.WazuhRawLogBatchRequest) (webhook.RawLogIngestResponse, error) {
	if err := req.Validate(); err != nil {
		return webhook.RawLogIngestResponse{}, err
	}

	createdTicketIDs := make([]string, 0)
	createdSet := make(map[string]struct{})
	activeWindows := 0
	streamEvents := make([]ticket.StreamEvent, 0)

	err := database.WithTransaction(ctx, s.db, func(txCtx context.Context) error {
		// Always flush expired windows first so old groups become tickets promptly.
		initialCreated, initialEvents, err := s.finalizeExpiredWindows(txCtx, time.Now().UTC())
		if err != nil {
			return err
		}
		for _, id := range initialCreated {
			if _, ok := createdSet[id]; !ok {
				createdSet[id] = struct{}{}
				createdTicketIDs = append(createdTicketIDs, id)
			}
		}
		streamEvents = append(streamEvents, initialEvents...)

		for _, item := range req {
			parsed, err := parseRawLogEnvelope(item)
			if err != nil {
				return err
			}

			window, err := s.repo.GetWindowForUpdate(txCtx, parsed.SourceIP, parsed.AttackRuleID)
			if err != nil {
				return err
			}

			if window == nil {
				expiresAt := parsed.EventTime.Add(time.Duration(baseWindowSeconds) * time.Second)
				window, err = s.repo.CreateWindow(txCtx, webhook.CreateWindowInput{
					SourceIP:        parsed.SourceIP,
					AttackRuleID:    parsed.AttackRuleID,
					ThreatCategory:  parsed.ThreatCategory,
					ThreatType:      parsed.ThreatType,
					Severity:        parsed.Severity,
					SampleScore:     parsed.SampleScore,
					FirstSeen:       parsed.EventTime,
					LastSeen:        parsed.EventTime,
					RawLogCount:     1,
					WindowSeconds:   baseWindowSeconds,
					WindowExpiresAt: expiresAt,
					PayloadFirst:    parsed.RawPayload,
					PayloadLast:     parsed.RawPayload,
					PayloadSample:   parsed.RawPayload,
				})
				if err != nil {
					return err
				}

				msg := fmt.Sprintf("Aggregating logs from %s / rule %s", parsed.SourceIP, parsed.AttackRuleID)
				nots, err := s.notifRepo.CreateForAllUsers(txCtx, nil, msg)
				if err != nil {
					return err
				}
				if s.pub != nil {
					for _, n := range nots {
						s.pub.Publish(n.UserID, n)
					}
				}

				streamEvents = append(streamEvents, buildAggregatingEvent(ticket.StreamEventAggregatingCreated, *window))
			} else {
				nextWindow := window.WindowSeconds * 2
				if nextWindow > maxWindowSeconds {
					nextWindow = maxWindowSeconds
				}

				newSeverity := pickHigherSeverity(window.Severity, parsed.Severity)
				sampleScore := window.SampleScore
				payloadSample := window.PayloadSample
				if parsed.SampleScore >= sampleScore {
					sampleScore = parsed.SampleScore
					payloadSample = parsed.RawPayload
				}

				lastSeen := window.LastSeen
				if parsed.EventTime.After(lastSeen) {
					lastSeen = parsed.EventTime
				}

				updatedWindow := webhook.IngestWindow{
					ID:              window.ID,
					SourceIP:        window.SourceIP,
					AttackRuleID:    window.AttackRuleID,
					ThreatCategory:  coalesceStringPtr(window.ThreatCategory, parsed.ThreatCategory),
					ThreatType:      coalesceStringPtr(window.ThreatType, parsed.ThreatType),
					Severity:        newSeverity,
					SampleScore:     sampleScore,
					FirstSeen:       window.FirstSeen,
					LastSeen:        lastSeen,
					RawLogCount:     window.RawLogCount + 1,
					WindowSeconds:   nextWindow,
					WindowExpiresAt: parsed.EventTime.Add(time.Duration(nextWindow) * time.Second),
					PayloadFirst:    window.PayloadFirst,
					PayloadLast:     parsed.RawPayload,
					PayloadSample:   payloadSample,
				}

				if err := s.repo.UpdateWindow(txCtx, webhook.UpdateWindowInput{
					WindowID:        window.ID,
					ThreatCategory:  updatedWindow.ThreatCategory,
					ThreatType:      updatedWindow.ThreatType,
					Severity:        newSeverity,
					SampleScore:     sampleScore,
					LastSeen:        updatedWindow.LastSeen,
					RawLogCount:     updatedWindow.RawLogCount,
					WindowSeconds:   updatedWindow.WindowSeconds,
					WindowExpiresAt: updatedWindow.WindowExpiresAt,
					PayloadLast:     parsed.RawPayload,
					PayloadSample:   payloadSample,
				}); err != nil {
					return err
				}

				streamEvents = append(streamEvents, buildAggregatingEvent(ticket.StreamEventAggregatingUpdated, updatedWindow))
			}

			if err := s.repo.InsertWindowLog(txCtx, webhook.InsertWindowLogInput{
				WindowID:     window.ID,
				WazuhEventID: &parsed.EventID,
				SourceIP:     parsed.SourceIP,
				AttackRuleID: parsed.AttackRuleID,
				EventTime:    parsed.EventTime,
				RawPayload:   parsed.RawPayload,
			}); err != nil {
				return err
			}
		}

		createdNow, createdEvents, err := s.finalizeExpiredWindows(txCtx, time.Now().UTC())
		if err != nil {
			return err
		}
		for _, id := range createdNow {
			if _, ok := createdSet[id]; !ok {
				createdSet[id] = struct{}{}
				createdTicketIDs = append(createdTicketIDs, id)
			}
		}
		streamEvents = append(streamEvents, createdEvents...)

		activeWindows, err = s.repo.CountActiveWindows(txCtx)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return webhook.RawLogIngestResponse{}, err
	}

	if s.streamPub != nil {
		for _, ev := range streamEvents {
			s.streamPub.Publish(ev)
		}
	}

	return webhook.RawLogIngestResponse{
		ProcessedLogs:      len(req),
		CreatedTickets:     len(createdTicketIDs),
		CreatedTicketIDs:   createdTicketIDs,
		ActiveGroupingKeys: activeWindows,
	}, nil
}

func (s *Service) FlushExpiredWindows(ctx context.Context) (WindowFlushResult, error) {
	var out WindowFlushResult
	streamEvents := make([]ticket.StreamEvent, 0)

	err := database.WithTransaction(ctx, s.db, func(txCtx context.Context) error {
		created, events, err := s.finalizeExpiredWindows(txCtx, time.Now().UTC())
		if err != nil {
			return err
		}
		streamEvents = append(streamEvents, events...)

		activeWindows, err := s.repo.CountActiveWindows(txCtx)
		if err != nil {
			return err
		}

		out.CreatedTicketIDs = created
		out.ActiveGroupingKeys = activeWindows
		return nil
	})
	if err != nil {
		return WindowFlushResult{}, err
	}

	if s.streamPub != nil {
		for _, ev := range streamEvents {
			s.streamPub.Publish(ev)
		}
	}

	return out, nil
}

func (s *Service) finalizeExpiredWindows(ctx context.Context, now time.Time) ([]string, []ticket.StreamEvent, error) {
	windows, err := s.repo.ListDueWindowsForUpdate(ctx, now)
	if err != nil {
		return nil, nil, err
	}

	out := make([]string, 0, len(windows))
	streamEvents := make([]ticket.StreamEvent, 0, len(windows))
	for _, w := range windows {
		ticketID, err := s.repo.CreateTicketFromWindow(ctx, webhook.CreateTicketFromWindowInput{
			SourceIP:       w.SourceIP,
			AttackRuleID:   w.AttackRuleID,
			ThreatCategory: w.ThreatCategory,
			ThreatType:     w.ThreatType,
			Severity:       w.Severity,
			FirstSeen:      w.FirstSeen,
			LastSeen:       w.LastSeen,
			RawLogCount:    w.RawLogCount,
			PayloadFirst:   w.PayloadFirst,
			PayloadLast:    w.PayloadLast,
			PayloadSample:  w.PayloadSample,
		})
		if err != nil {
			return nil, nil, err
		}

		payloads, err := s.repo.ListWindowLogPayloads(ctx, w.ID)
		if err != nil {
			return nil, nil, err
		}
		iocs := extractIOCsFromRawPayloads(payloads)
		if len(iocs) > 0 {
			if err := s.repo.ReplaceIOCs(ctx, ticketID, iocs); err != nil {
				return nil, nil, err
			}
		}

		if _, err := s.repo.MoveWindowLogsToTicket(ctx, w.ID, ticketID); err != nil {
			return nil, nil, err
		}

		if err := s.repo.DeleteWindow(ctx, w.ID); err != nil {
			return nil, nil, err
		}

		msg := fmt.Sprintf("New ticket from %s / rule %s (%d raw logs)", w.SourceIP, w.AttackRuleID, w.RawLogCount)
		nots, err := s.notifRepo.CreateForAllUsers(ctx, &ticketID, msg)
		if err != nil {
			return nil, nil, err
		}
		if s.pub != nil {
			for _, n := range nots {
				s.pub.Publish(n.UserID, n)
			}
		}

		// event: aggregating_closed with mapping ticket_id
		closedEvent := ticket.StreamEvent{
			Type:     ticket.StreamEventAggregatingClosed,
			WindowID: &w.ID,
			TicketID: &ticketID,
			Ticket: &ticket.TicketListItem{
				ID:             ticketID,
				TicketNumber:   "",
				SourceIP:       w.SourceIP,
				AttackRuleID:   w.AttackRuleID,
				ThreatCategory: w.ThreatCategory,
				ThreatType:     w.ThreatType,
				Severity:       w.Severity,
				Status:         ticket.StatusOpen,
				FirstSeen:      w.FirstSeen.UTC().Format(time.RFC3339),
				LastSeen:       w.LastSeen.UTC().Format(time.RFC3339),
				RawLogCount:    w.RawLogCount,
			},
		}
		streamEvents = append(streamEvents, closedEvent)

		out = append(out, ticketID)
	}
	return out, streamEvents, nil
}

func extractIOCsFromRawPayloads(payloads []json.RawMessage) []webhook.UpsertIOCInput {
	seen := make(map[string]struct{})
	out := make([]webhook.UpsertIOCInput, 0)

	for _, payload := range payloads {
		if len(payload) == 0 {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal(payload, &raw); err != nil {
			continue
		}

		indicatorsRaw, ok := lookupAny(raw, "llm_metadata", "indicators")
		if !ok || indicatorsRaw == nil {
			continue
		}
		indicators, ok := indicatorsRaw.(map[string]any)
		if !ok {
			continue
		}

		for k, v := range indicators {
			key := strings.TrimSpace(k)
			if key == "" || v == nil {
				continue
			}
			val := strings.TrimSpace(fmt.Sprint(v))
			if val == "" {
				continue
			}
			fingerprint := key + "\x00" + val
			if _, exists := seen[fingerprint]; exists {
				continue
			}
			seen[fingerprint] = struct{}{}
			out = append(out, webhook.UpsertIOCInput{IOCType: key, IOCValue: val})
		}
	}

	return out
}

type parsedRawLogEnvelope struct {
	EventID        string
	SourceIP       string
	AttackRuleID   string
	ThreatCategory *string
	ThreatType     *string
	Severity       *ticket.Severity
	SampleScore    int
	EventTime      time.Time
	RawPayload     json.RawMessage
}

func parseRawLogEnvelope(item webhook.WazuhRawLogEnvelope) (parsedRawLogEnvelope, error) {
	out := parsedRawLogEnvelope{EventID: strings.TrimSpace(item.ID), RawPayload: item.RawLog}

	var raw map[string]any
	if err := json.Unmarshal(item.RawLog, &raw); err != nil {
		return parsedRawLogEnvelope{}, fmt.Errorf("invalid raw_log for event %s: %w", strings.TrimSpace(item.ID), err)
	}

	out.AttackRuleID = firstNonEmpty(
		lookupString(raw, "alert", "rule", "id"),
		lookupString(raw, "llm_metadata", "rule_id"),
	)
	if out.AttackRuleID == "" {
		return parsedRawLogEnvelope{}, fmt.Errorf("rule_id not found for event %s", out.EventID)
	}

	if s := strings.TrimSpace(lookupString(raw, "llm_metadata", "category")); s != "" {
		out.ThreatCategory = &s
	}
	if s := strings.TrimSpace(lookupString(raw, "llm_metadata", "attack_type")); s != "" {
		out.ThreatType = &s
	}

	out.SourceIP = firstNonEmpty(
		lookupString(raw, "llm_metadata", "indicators", "source_ip"),
		lookupString(raw, "alert", "data", "src_ip"),
		lookupString(raw, "alert", "data", "srcip"),
		strings.TrimSpace(item.SourceIP),
	)
	if out.SourceIP == "" {
		isMalware := out.ThreatCategory != nil && strings.ToLower(*out.ThreatCategory) == "malware"
		if !isMalware {
			return parsedRawLogEnvelope{}, fmt.Errorf("source_ip not found for event %s", out.EventID)
		}
	}

	out.Severity = parseSeverity(firstNonEmpty(
		lookupString(raw, "llm_metadata", "priority"),
		lookupString(raw, "llm_metadata", "severity"),
	))

	out.SampleScore = firstPositive(
		lookupInt(raw, "llm_metadata", "severity_level"),
		lookupInt(raw, "alert", "rule", "level"),
		lookupInt(raw, "alert", "data", "alert", "severity"),
	)

	if out.Severity == nil {
		out.Severity = mapAlertLevelToSeverity(out.SampleScore)
	}

	eventTS := firstNonEmpty(
		lookupString(raw, "alert", "data", "timestamp"),
		lookupString(raw, "alert", "timestamp"),
		strings.TrimSpace(item.ReceivedAt),
	)
	if parsed, ok := parseFlexibleTime(eventTS); ok {
		out.EventTime = parsed
	} else {
		out.EventTime = time.Now().UTC()
	}

	return out, nil
}

func parseFlexibleTime(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05.000-0700",
		"2006-01-02T15:04:05.000000-0700",
		"2006-01-02T15:04:05-0700",
	}
	for _, layout := range layouts {
		t, err := time.Parse(layout, v)
		if err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func buildAggregatingEvent(eventType ticket.StreamEventType, w webhook.IngestWindow) ticket.StreamEvent {
	ws := w.WindowSeconds

	winExpires := w.WindowExpiresAt.UTC().Format(time.RFC3339)
	item := ticket.TicketListItem{
		ID:              w.ID,
		TicketNumber:    "",
		SourceIP:        w.SourceIP,
		AttackRuleID:    w.AttackRuleID,
		ThreatCategory:  w.ThreatCategory,
		ThreatType:      w.ThreatType,
		Severity:        w.Severity,
		Status:          ticket.StatusAggregating,
		FirstSeen:       w.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:        w.LastSeen.UTC().Format(time.RFC3339),
		RawLogCount:     w.RawLogCount,
		IsAggregating:   true,
		WindowExpiresAt: &winExpires,
		WindowSeconds:   &ws,
	}
	return ticket.StreamEvent{
		Type:     eventType,
		WindowID: &w.ID,
		Ticket:   &item,
	}
}

func buildTicketListItemFromAlert(ticketID, modelName, alertID string, threatCategory, threatType *string, sev *ticket.Severity, eventTS time.Time) ticket.TicketListItem {
	return ticket.TicketListItem{
		ID:             ticketID,
		TicketNumber:   "",
		SourceIP:       "",
		AttackRuleID:   alertID,
		ThreatCategory: threatCategory,
		ThreatType:     threatType,
		Severity:       sev,
		Status:         ticket.StatusOpen,
		FirstSeen:      eventTS.UTC().Format(time.RFC3339),
		LastSeen:       eventTS.UTC().Format(time.RFC3339),
		RawLogCount:    0,
	}
}

func lookupString(root map[string]any, keys ...string) string {
	v, ok := lookupAny(root, keys...)
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

func lookupInt(root map[string]any, keys ...string) int {
	v, ok := lookupAny(root, keys...)
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

func lookupAny(root map[string]any, keys ...string) (any, bool) {
	var cur any = root
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, exists := m[k]
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
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func pickHigherSeverity(existing, incoming *ticket.Severity) *ticket.Severity {
	if existing == nil {
		return incoming
	}
	if incoming == nil {
		return existing
	}
	rank := map[ticket.Severity]int{
		ticket.SeverityLow:      1,
		ticket.SeverityMedium:   2,
		ticket.SeverityHigh:     3,
		ticket.SeverityCritical: 4,
	}
	if rank[*incoming] >= rank[*existing] {
		return incoming
	}
	return existing
}

func coalesceStringPtr(existing, incoming *string) *string {
	if existing != nil && strings.TrimSpace(*existing) != "" {
		return existing
	}
	if incoming != nil && strings.TrimSpace(*incoming) != "" {
		return incoming
	}
	return nil
}

func mapAlertLevelToSeverity(level int) *ticket.Severity {
	// Wazuh alert level is often 0-15. Use a simple threshold mapping.
	var sev ticket.Severity
	switch {
	case level >= 0 && level <= 3:
		sev = ticket.SeverityLow
	case level >= 4 && level <= 6:
		sev = ticket.SeverityMedium
	case level >= 7 && level <= 10:
		sev = ticket.SeverityHigh
	case level >= 11:
		sev = ticket.SeverityCritical
	default:
		return nil
	}
	return &sev
}

func parseSeverity(s string) *ticket.Severity {
	var sev ticket.Severity
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		sev = ticket.SeverityLow
	case "medium":
		sev = ticket.SeverityMedium
	case "high":
		sev = ticket.SeverityHigh
	case "critical":
		sev = ticket.SeverityCritical
	default:
		return nil
	}
	return &sev
}
