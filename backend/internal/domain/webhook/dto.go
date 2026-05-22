package webhook

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pitik0x/Ai-Security-analyst/internal/pkg/validator"
)

type WazuhWebhookRequest struct {
	Metadata WazuhWebhookMetadata `json:"metadata"`
	Results  []WazuhWebhookResult `json:"results"`
}

type WazuhWebhookMetadata struct {
	Timestamp   string `json:"timestamp"`
	TotalAlerts int    `json:"total_alerts"`
}

type WazuhWebhookResult struct {
	AlertID          string                    `json:"alert_id"`
	AlertDescription string                    `json:"alert_description"`
	AlertLevel       int                       `json:"alert_level"`
	ThreatCategory   string                    `json:"threat_category"`
	ThreatType       string                    `json:"threat_type"`
	Severity         string                    `json:"severity"`
	Timestamp        string                    `json:"timestamp"`
	DetailedResults  map[string]LLMModelResult `json:"detailed_results"`
	Indicators       map[string]any            `json:"indicators"`
	RawLog           json.RawMessage           `json:"raw_log"`
}

type LLMModelResult struct {
	Summary            *string             `json:"summary"`
	DetailedAnalysis   *string             `json:"detailed_analysis"`
	AttackVector       *string             `json:"attack_vector"`
	PotentialImpact    *string             `json:"potential_impact"`
	MitreAttacks       []MitreAttack       `json:"mitre_attacks"`
	RecommendedActions []RecommendedAction `json:"recommended_actions"`
}

type MitreAttack struct {
	TechniqueID string `json:"technique_id"`
}

type RecommendedAction struct {
	Priority int     `json:"priority"`
	Action   string  `json:"action"`
	Reason   *string `json:"reason"`
}

// ============================
// New raw-log batch ingestion
// ============================

type WazuhRawLogBatchRequest []WazuhRawLogEnvelope

type WazuhRawLogEnvelope struct {
	ID         string          `json:"id"`
	Customer   string          `json:"customer"`
	SourceIP   string          `json:"source_ip"`
	RawLog     json.RawMessage `json:"raw_log"`
	ReceivedAt string          `json:"received_at"`
}

func (r WazuhRawLogBatchRequest) Validate() error {
	var errs validator.ValidationErrors
	if len(r) == 0 {
		errs = append(errs, validator.ValidationError{Field: "body", Message: "request body cannot be empty"})
	}
	for i, item := range r {
		if strings.TrimSpace(item.ID) == "" {
			errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("[%d].id", i), Message: "id is required"})
		}
		if len(item.RawLog) == 0 {
			errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("[%d].raw_log", i), Message: "raw_log is required"})
		}
		if strings.TrimSpace(item.ReceivedAt) != "" {
			if _, err := time.Parse(time.RFC3339, strings.TrimSpace(item.ReceivedAt)); err != nil {
				errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("[%d].received_at", i), Message: "received_at must be RFC3339"})
			}
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (r WazuhWebhookRequest) Validate() error {
	var errs validator.ValidationErrors
	if len(r.Results) == 0 {
		errs = append(errs, validator.ValidationError{Field: "results", Message: "results is required"})
	}
	for i, res := range r.Results {
		if strings.TrimSpace(res.AlertID) == "" {
			errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("results[%d].alert_id", i), Message: "alert_id is required"})
		}
		if strings.TrimSpace(res.ThreatCategory) == "" {
			errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("results[%d].threat_category", i), Message: "threat_category is required"})
		}
		if strings.TrimSpace(res.ThreatType) == "" {
			errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("results[%d].threat_type", i), Message: "threat_type is required"})
		}
		if strings.TrimSpace(res.Severity) == "" {
			errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("results[%d].severity", i), Message: "severity is required"})
		} else if !isValidSeverity(res.Severity) {
			errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("results[%d].severity", i), Message: "severity must be one of: low, medium, high, critical"})
		}
		if strings.TrimSpace(res.Timestamp) == "" {
			errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("results[%d].timestamp", i), Message: "timestamp is required"})
		} else {
			if _, err := time.Parse(time.RFC3339, res.Timestamp); err != nil {
				errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("results[%d].timestamp", i), Message: "timestamp must be RFC3339"})
			}
		}
		if res.AlertLevel < 0 {
			errs = append(errs, validator.ValidationError{Field: fmt.Sprintf("results[%d].alert_level", i), Message: "alert_level must be >= 0"})
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func isValidSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// PickModelResult selects a deterministic model result from DetailedResults.
// If there are multiple models, keys are sorted lexicographically and the first is picked.
func (r WazuhWebhookResult) PickModelResult() (modelName string, model LLMModelResult, ok bool) {
	if len(r.DetailedResults) == 0 {
		return "", LLMModelResult{}, false
	}
	keys := make([]string, 0, len(r.DetailedResults))
	for k := range r.DetailedResults {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	k := keys[0]
	return k, r.DetailedResults[k], true
}
